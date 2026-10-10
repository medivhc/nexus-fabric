//! The Nexus Web Gateway: HTTPS/WSS server + node-side WebRTC endpoint.
//!
//! Threading model (std-only, no async runtime):
//! - An accept-loop thread accepts TCP connections and spawns one thread per
//!   connection (HTTP request serving or WSS signaling).
//! - A single event-loop thread owns every `Rtc` (str0m) session, drives time
//!   forward, reads the shared UDP socket, demultiplexes datagrams via
//!   `rtc.accepts`, and dispatches DataChannel protocol messages.
//! - Other threads interact with the event loop through an `mpsc` channel of
//!   [`GatewayEvent`]s.

use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, SyncSender, channel, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rustls::StreamOwned;
use str0m::channel::{ChannelData, ChannelId};
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, IceConnectionState, Input, Output, Rtc};

use crate::cert;
use crate::config::GatewayConfig;
use crate::error::GatewayError;
use crate::http;
use crate::mesh::{InMemoryMeshSignaler, MeshDataConnection, MeshSignaler, WssMeshSignaler};
use crate::protocol::{BrowserMessage, MeshMessage, NodeMessage, SdpPayload, SshAuth};
use crate::ssh_client::{self, SshInput};

/// Pick the IP address the shared WebRTC UDP socket binds to.
///
/// A concrete `listen_addr` binds the UDP socket to the same IP so the SDP
/// host candidate is reachable from browsers. An unspecified address
/// (`0.0.0.0` / `::`) has no single routable IP, so we derive the first
/// non-loopback address from the local interfaces; otherwise the socket would
/// only carry a loopback host candidate that real browsers never collect
/// (the `0.0.0.0` example-config dead end). When no non-loopback address
/// exists we fall back to loopback and warn loudly.
fn udp_bind_ip(listen_ip: std::net::IpAddr) -> std::net::IpAddr {
    if !listen_ip.is_unspecified() {
        return listen_ip;
    }
    let Ok(interfaces) = getifaddrs::getifaddrs() else {
        return loopback_for(listen_ip);
    };
    for iface in interfaces {
        if iface.flags.contains(getifaddrs::InterfaceFlags::LOOPBACK) {
            continue;
        }
        if let Some(ip) = iface.address.ip_addr() {
            if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
                continue;
            }
            let same_family = matches!(
                (listen_ip, ip),
                (std::net::IpAddr::V4(_), std::net::IpAddr::V4(_))
                    | (std::net::IpAddr::V6(_), std::net::IpAddr::V6(_))
            );
            if same_family {
                return ip;
            }
        }
    }
    loopback_for(listen_ip)
}

/// Loopback fallback for an unspecified `listen_addr` with no usable
/// non-loopback interface.
fn loopback_for(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V4(_) => std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        std::net::IpAddr::V6(_) => std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
    }
}

/// Maximum UDP datagram payload the gateway reads from the shared socket.
const UDP_BUF_SIZE: usize = 2048;

/// A command/notification delivered to the gateway event loop.
pub(crate) enum GatewayEvent {
    /// WSS thread: create a browser session from an SDP offer.
    CreateSession {
        session_id: String,
        peer_id: String,
        name: String,
        sdp: SdpPayload,
        reply: SyncSender<Result<SdpPayload, GatewayError>>,
    },
    /// WSS thread: close a browser session.
    CloseSession { session_id: String },
    /// Mesh handler: a relayed offer from another gateway.
    MeshOffer {
        session_id: String,
        sdp: SdpPayload,
        reply: SyncSender<Result<SdpPayload, GatewayError>>,
    },
    /// Relay worker: the answer (or error) for a browser's relay request.
    RelayResult {
        session_id: String,
        target: String,
        result: Result<SdpPayload, GatewayError>,
    },
    /// SSH bridge reader: bytes read from the local sshd.
    SshData {
        session_id: String,
        bridge_id: String,
        data: Vec<u8>,
    },
    /// SSH bridge reader: the bridge closed.
    SshClosed {
        session_id: String,
        bridge_id: String,
        reason: String,
    },
    /// SSH worker: the bridge opened (or failed to open).
    SshOpenAck {
        session_id: String,
        bridge_id: String,
        status: String,
        error: Option<String>,
    },
    /// Mesh relay reader: the target gateway accepted/rejected a relayed SSH
    /// terminal.
    RelaySshOpenAck {
        session_id: String,
        bridge_id: String,
        status: String,
        error: Option<String>,
    },
}

/// Shared, clone-able gateway state.
struct Shared {
    cfg: GatewayConfig,
    tls: Arc<rustls::ServerConfig>,
    mesh: Arc<dyn MeshSignaler>,
    event_tx: Sender<GatewayEvent>,
    udp: Arc<UdpSocket>,
    /// PEM-encoded self-signed certificate, served at `/cert`.
    cert_pem: String,
}

/// One browser session: the node-side WebRTC peer plus protocol state.
struct Session {
    id: String,
    peer_id: String,
    name: String,
    rtc: Rtc,
    channel: Option<ChannelId>,
    send_queue: VecDeque<Vec<u8>>,
    ssh_bridges: HashMap<String, SshBridge>,
    ssh_relays: HashMap<String, SshRelay>,
}

impl Session {
    fn new(id: String, peer_id: String, name: String, rtc: Rtc) -> Self {
        Self {
            id,
            peer_id,
            name,
            rtc,
            channel: None,
            send_queue: VecDeque::new(),
            ssh_bridges: HashMap::new(),
            ssh_relays: HashMap::new(),
        }
    }

    /// Queue a node->browser message for delivery over the control DataChannel.
    fn send(&mut self, msg: &NodeMessage) {
        let bytes = match serde_json::to_vec(msg) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("failed to serialize node message: {e}");
                return;
            }
        };
        self.send_queue.push_back(bytes);
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Stop every SSH worker thread and drop the bridge so no worker keeps a
        // clone of the event loop channels alive after the session is gone.
        for (_, bridge) in self.ssh_bridges.drain() {
            bridge.stop.store(true, Ordering::Relaxed);
            let _ = bridge.tx.send(SshInput::Close);
        }
        // Close every relayed terminal's mesh data connection.
        for (_, relay) in self.ssh_relays.drain() {
            relay.data.close();
        }
    }
}

/// An SSH terminal bridge to the local sshd, driven by a real SSH client.
struct SshBridge {
    /// Channel to the SSH worker thread (terminal bytes from the browser).
    tx: Sender<SshInput>,
    /// Set when the bridge must close; the worker thread checks it each loop.
    stop: Arc<AtomicBool>,
    /// Last activity (used for idle timeout).
    last_activity: Instant,
}

/// A data-plane peer-relayed SSH terminal: the browser's bytes travel over a
/// mesh data connection to the target gateway, which opens a local sshd bridge.
struct SshRelay {
    /// Persistent bidirectional mesh data connection to the target gateway.
    data: MeshDataConnection,
    /// Last activity (used for idle timeout).
    last_activity: Instant,
}

/// The running gateway handle.
pub struct GatewayHandle {
    /// Local address of the HTTPS listener (may be `0.0.0.0` when the config
    /// used an unspecified `listen_addr`).
    pub local_addr: std::net::SocketAddr,
    /// Address browsers should open in practice. When `listen_addr` is
    /// unspecified this is the derived routable IP plus the listener port,
    /// so the printed page URL is never an unusable `0.0.0.0`.
    pub page_addr: std::net::SocketAddr,
    /// Self-signed certificate DER presented by the HTTPS server (the local CA).
    pub cert_der: Vec<u8>,
}

/// The gateway server.
pub struct Gateway;

impl Gateway {
    /// Start a gateway on the given configuration, using the mesh backend
    /// declared in `cfg.mesh`.
    ///
    /// # Errors
    ///
    /// Returns `GatewayError::Config` for invalid config, `GatewayError::Tls`
    /// for TLS material problems, or `GatewayError::Io` for socket failures.
    pub fn start(cfg: GatewayConfig) -> Result<GatewayHandle, GatewayError> {
        let mesh: Arc<dyn MeshSignaler> = match &cfg.mesh {
            crate::config::MeshConfig::InMemory => Arc::new(InMemoryMeshSignaler::new()),
            crate::config::MeshConfig::Wss { peers, .. } => Arc::new(WssMeshSignaler::new(
                peers
                    .iter()
                    .map(|p| (p.peer_id.clone(), p.url.clone(), p.token.clone())),
            )),
        };
        Self::start_with_mesh(cfg, mesh)
    }

    /// Start a gateway with an explicitly injected mesh signaling backend.
    ///
    /// If `mesh` is an [`InMemoryMeshSignaler`], the gateway registers its
    /// offer handler under `cfg.node_id` so other gateways can relay offers to
    /// it.
    pub fn start_with_mesh(
        cfg: GatewayConfig,
        mesh: Arc<dyn MeshSignaler>,
    ) -> Result<GatewayHandle, GatewayError> {
        cfg.validate()?;

        let identity = match &cfg.tls {
            crate::config::TlsConfig::AutoGenerate {
                names,
                ips,
                cert_dir,
            } => {
                let default_dir;
                let dir: Option<&Path> = match cert_dir {
                    Some(d) => Some(Path::new(d)),
                    None => {
                        default_dir = cert::default_cert_dir(&cfg.node_id);
                        Some(default_dir.as_path())
                    }
                };
                cert::generate_or_load_identity(names, ips, dir)?
            }
            crate::config::TlsConfig::Files {
                cert_path,
                key_path,
            } => cert::load_identity(cert_path, key_path)?,
        };
        let tls = Arc::new(cert::server_config(&identity)?);

        let udp_ip = udp_bind_ip(cfg.listen_addr.ip());
        if cfg.listen_addr.ip().is_unspecified() {
            if udp_ip.is_loopback() {
                eprintln!(
                    "warning: no non-loopback network interface found; WebRTC UDP socket bound \
                     to {udp_ip} only. Browsers cannot reach a loopback ICE candidate — set \
                     `listen_addr` to a routable IP address."
                );
            } else {
                eprintln!(
                    "note: `listen_addr` is unspecified; binding the WebRTC UDP socket to \
                     {udp_ip} so browsers can reach the ICE host candidate."
                );
            }
        }
        let udp = Arc::new(UdpSocket::bind((udp_ip, 0)).map_err(GatewayError::Io)?);
        udp.set_read_timeout(Some(Duration::from_millis(50)))
            .map_err(GatewayError::Io)?;

        let (event_tx, event_rx) = channel::<GatewayEvent>();

        let listener = TcpListener::bind(cfg.listen_addr).map_err(GatewayError::Io)?;
        let local_addr = listener.local_addr().map_err(GatewayError::Io)?;
        // The address browsers should actually open (never `0.0.0.0`/`::`).
        // Use the actually bound port so `listen_addr: "0.0.0.0:0"` works.
        let page_addr = std::net::SocketAddr::new(udp_ip, local_addr.port());

        let shared = Arc::new(Shared {
            cfg: cfg.clone(),
            tls,
            mesh: mesh.clone(),
            event_tx: event_tx.clone(),
            udp: udp.clone(),
            cert_pem: identity.cert_pem()?,
        });

        // Register the local mesh offer handler (in-memory backend).
        let handler_shared = shared.clone();
        let handler = move |session_id: &str, sdp: &SdpPayload| {
            let (reply_tx, reply_rx) = sync_channel(1);
            handler_shared
                .event_tx
                .send(GatewayEvent::MeshOffer {
                    session_id: session_id.to_string(),
                    sdp: sdp.clone(),
                    reply: reply_tx,
                })
                .map_err(|e| GatewayError::Mesh(e.to_string()))?;
            reply_rx
                .recv_timeout(Duration::from_secs(30))
                .map_err(|e| GatewayError::Mesh(format!("mesh offer timeout: {e}")))?
        };
        let _ = mesh.register_offer_handler(cfg.node_id.clone(), Arc::new(handler));

        // Spawn the event loop.
        let event_loop_shared = shared.clone();
        thread::spawn(move || run_event_loop(event_loop_shared, event_rx));

        // Spawn the accept loop.
        let accept_shared = shared.clone();
        thread::spawn(move || accept_loop(accept_shared, listener));

        Ok(GatewayHandle {
            local_addr,
            page_addr,
            cert_der: identity.cert_der,
        })
    }
}

fn accept_loop(shared: Arc<Shared>, listener: TcpListener) -> Result<(), GatewayError> {
    for conn in listener.incoming() {
        match conn {
            Ok(tcp) => {
                let shared = shared.clone();
                thread::spawn(move || {
                    if let Err(e) = handle_connection(shared, tcp) {
                        tracing::debug!("connection error: {e}");
                    }
                });
            }
            Err(e) => {
                tracing::warn!("accept error: {e}");
            }
        }
    }
    Ok(())
}

fn handle_connection(shared: Arc<Shared>, tcp: TcpStream) -> Result<(), GatewayError> {
    let conn = rustls::ServerConnection::new(shared.tls.clone())
        .map_err(|e| GatewayError::Tls(e.to_string()))?;
    let mut tls = StreamOwned::new(conn, tcp);
    tls.get_mut()
        .set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(GatewayError::Io)?;

    let request = match http::read_request(&mut tls)? {
        Some(r) => r,
        None => return Ok(()),
    };

    // WebSocket upgrade paths.
    if request.is_websocket_upgrade() {
        // The /mesh endpoint is bearer-token protected; reject unauthorized
        // peers before upgrading.
        if request.path.starts_with("/mesh") {
            if let Some(expected) = shared.cfg.mesh.local_token() {
                let provided = request
                    .header("authorization")
                    .and_then(|v| v.strip_prefix("Bearer "))
                    .unwrap_or("");
                if !constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
                    http::write_http_401(&mut tls).map_err(GatewayError::Io)?;
                    return Ok(());
                }
            }
        }
        let key = request
            .header("sec-websocket-key")
            .ok_or_else(|| GatewayError::WebSocket("missing Sec-WebSocket-Key".into()))?;
        let accept = http::websocket_accept_key(key);
        http::write_websocket_101(&mut tls, &accept).map_err(GatewayError::Io)?;
        let ws = tungstenite::protocol::WebSocket::from_raw_socket(
            tls,
            tungstenite::protocol::Role::Server,
            None,
        );

        if request.path.starts_with("/mesh") {
            handle_mesh_connection(shared, ws)
        } else {
            handle_browser_ws(shared, ws)
        }
    } else {
        let result = serve_http(shared, &mut tls, &request);
        // Send TLS close_notify and flush so clients see a clean EOF.
        tls.conn.send_close_notify();
        let _ = tls.flush();
        result
    }
}

fn serve_http(
    shared: Arc<Shared>,
    tls: &mut http::TlsStream,
    request: &http::HttpRequest,
) -> Result<(), GatewayError> {
    if request.method != "GET" {
        http::write_http_405(tls).map_err(GatewayError::Io)?;
        return Ok(());
    }
    if request.path.starts_with("/api/config") {
        let body = serde_json::to_vec(&serde_json::json!({
            "node_id": shared.cfg.node_id,
            "node_name": shared.cfg.node_name,
            "node_list": shared.cfg.node_list,
            "ice_servers": shared.cfg.ice_servers,
        }))
        .map_err(|e| GatewayError::Protocol(e.to_string()))?;
        http::write_http_response(tls, "application/json", &body, &[]).map_err(GatewayError::Io)?;
        return Ok(());
    }
    if request.path.starts_with("/cert") {
        http::write_http_response(
            tls,
            "application/x-pem-file",
            shared.cert_pem.as_bytes(),
            &[(
                "Content-Disposition",
                "attachment; filename=\"nexus-ca.pem\"",
            )],
        )
        .map_err(GatewayError::Io)?;
        return Ok(());
    }
    if let Some(asset) = http::lookup_asset(&request.path) {
        http::write_http_response(tls, asset.content_type, asset.bytes, &[])
            .map_err(GatewayError::Io)?;
    } else {
        http::write_http_404(tls).map_err(GatewayError::Io)?;
    }
    Ok(())
}

fn handle_browser_ws(
    shared: Arc<Shared>,
    mut ws: tungstenite::WebSocket<http::TlsStream>,
) -> Result<(), GatewayError> {
    // The browser signaling WebSocket is a long-lived connection: the browser
    // sends one offer and then stays silent while the data plane runs over
    // WebRTC DataChannels. Keep the HTTP-read timeout (used only to bound the
    // initial request) OFF the upgraded socket; otherwise a healthy page dies
    // ~15s after joining and the frontend shows a bogus "Signaling closed"
    // error that also covers the first-node ICE guidance.
    ws.get_mut()
        .get_mut()
        .set_read_timeout(None)
        .map_err(GatewayError::Io)?;

    loop {
        let msg = match ws.read() {
            Ok(m) => m,
            Err(tungstenite::Error::Protocol(_) | tungstenite::Error::ConnectionClosed) => break,
            Err(e) => {
                tracing::debug!("browser ws read error: {e}");
                break;
            }
        };
        match msg {
            tungstenite::Message::Text(text) => {
                if let Err(e) = handle_browser_signaling_message(&shared, &mut ws, &text) {
                    let _ = ws.send(tungstenite::Message::Text(format!(
                        r#"{{"type":"error","error":"{}"}}"#,
                        e.to_string().replace('"', "\\\"")
                    )));
                }
            }
            tungstenite::Message::Close(_) => break,
            _ => {}
        }
    }
    Ok(())
}

fn handle_browser_signaling_message(
    shared: &Arc<Shared>,
    ws: &mut tungstenite::WebSocket<http::TlsStream>,
    text: &str,
) -> Result<(), GatewayError> {
    let value: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| GatewayError::Protocol(format!("bad signaling JSON: {e}")))?;
    let kind = value
        .get("type")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    match kind {
        "offer" => {
            let session_id = value
                .get("session_id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| GatewayError::Protocol("offer missing session_id".into()))?
                .to_string();
            let peer_id = value
                .get("peer_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string();
            let name = value
                .get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string();
            let sdp_value = value
                .get("sdp")
                .ok_or_else(|| GatewayError::Protocol("offer missing sdp".into()))?
                .clone();
            let sdp: SdpPayload = serde_json::from_value(sdp_value)
                .map_err(|e| GatewayError::Protocol(format!("bad offer sdp: {e}")))?;

            let answer = process_offer(shared, &session_id, &peer_id, &name, &sdp)?;
            ws.send(tungstenite::Message::Text(
                serde_json::to_string(&serde_json::json!({
                    "type": "answer",
                    "session_id": session_id,
                    "sdp": answer,
                }))
                .map_err(|e| GatewayError::Protocol(e.to_string()))?,
            ))
            .map_err(|e| GatewayError::WebSocket(e.to_string()))?;
            Ok(())
        }
        "ping" => {
            ws.send(tungstenite::Message::Text(r#"{"type":"pong"}"#.into()))
                .map_err(|e| GatewayError::WebSocket(e.to_string()))?;
            Ok(())
        }
        "close" => {
            if let Some(sid) = value.get("session_id").and_then(serde_json::Value::as_str) {
                let _ = shared.event_tx.send(GatewayEvent::CloseSession {
                    session_id: sid.to_string(),
                });
            }
            Ok(())
        }
        _ => Err(GatewayError::Protocol(format!(
            "unknown signaling message type {kind}"
        ))),
    }
}

/// Shared helper: send a CreateSession/MeshOffer event to the event loop and
/// return the SDP answer payload.
fn process_offer(
    shared: &Arc<Shared>,
    session_id: &str,
    peer_id: &str,
    name: &str,
    sdp: &SdpPayload,
) -> Result<SdpPayload, GatewayError> {
    let (reply_tx, reply_rx) = sync_channel(1);
    shared
        .event_tx
        .send(GatewayEvent::CreateSession {
            session_id: session_id.to_string(),
            peer_id: peer_id.to_string(),
            name: name.to_string(),
            sdp: sdp.clone(),
            reply: reply_tx,
        })
        .map_err(|e| GatewayError::Mesh(e.to_string()))?;
    reply_rx
        .recv_timeout(Duration::from_secs(30))
        .map_err(|e| GatewayError::Mesh(format!("offer timeout: {e}")))?
}

/// A relayed SSH bridge on the target gateway, fed by a peer gateway's mesh
/// data connection and driven by a real SSH client.
struct RelayBridge {
    /// Channel to the SSH worker thread (terminal bytes from the mesh).
    tx: Sender<SshInput>,
    /// Set when the bridge must close; the worker thread checks it each loop.
    stop: Arc<AtomicBool>,
    /// Last activity (used for idle timeout).
    last_activity: Instant,
}

fn handle_mesh_connection(
    shared: Arc<Shared>,
    ws: tungstenite::WebSocket<http::TlsStream>,
) -> Result<(), GatewayError> {
    // Very short read timeout so the WebSocket can be shared between the read
    // loop and relayed-bridge reader threads without deadlocking or starving
    // concurrent writers.
    let mut ws = ws;
    ws.get_mut()
        .get_mut()
        .set_read_timeout(Some(Duration::from_millis(1)))
        .map_err(GatewayError::Io)?;
    let ws = Arc::new(Mutex::new(ws));
    let mut bridges: HashMap<String, RelayBridge> = HashMap::new();

    loop {
        let read_result = {
            let mut ws = ws.lock().expect("mesh ws lock");
            ws.read()
        };
        let msg = match read_result {
            Ok(m) => m,
            Err(tungstenite::Error::Io(e))
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // No message pending: release the lock and yield so bridge
                // reader threads can send without being starved.
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(tungstenite::Error::Protocol(_) | tungstenite::Error::ConnectionClosed) => break,
            Err(e) => {
                tracing::debug!("mesh ws read error: {e}");
                break;
            }
        };
        match msg {
            tungstenite::Message::Text(text) => {
                let parsed: MeshMessage = match serde_json::from_str(&text) {
                    Ok(m) => m,
                    Err(e) => {
                        let _ = send_mesh(
                            &ws,
                            &MeshMessage::RelayError {
                                session_id: "".into(),
                                error: format!("bad mesh message: {e}"),
                            },
                        );
                        continue;
                    }
                };
                match parsed {
                    MeshMessage::RelayOffer { session_id, sdp } => {
                        handle_mesh_relay_offer(&shared, &ws, &session_id, &sdp);
                    }
                    MeshMessage::SshOpen { session_id, auth } => {
                        open_relayed_ssh_bridge(&shared, &ws, &mut bridges, &session_id, auth);
                    }
                    MeshMessage::SshData { session_id, data } => {
                        if let Some(bridge) = bridges.get_mut(&session_id) {
                            bridge.last_activity = Instant::now();
                            let Some(bytes) = base64_decode(&data) else {
                                continue;
                            };
                            if bridge.tx.send(SshInput::Data(bytes)).is_err() {
                                close_relayed_bridge(&ws, &mut bridges, &session_id, "worker gone");
                            }
                        } else {
                            // Never silently swallow terminal bytes for an
                            // unknown relayed session.
                            let _ = send_mesh(
                                &ws,
                                &MeshMessage::SshClose {
                                    session_id: session_id.clone(),
                                    reason: "unknown ssh session".into(),
                                },
                            );
                        }
                    }
                    MeshMessage::SshClose { session_id, reason } => {
                        close_relayed_bridge(&ws, &mut bridges, &session_id, &reason);
                    }
                    _ => {}
                }
            }
            tungstenite::Message::Close(_) => break,
            _ => {}
        }
    }

    // Close all remaining relayed bridges.
    for (_, bridge) in bridges.drain() {
        bridge.stop.store(true, Ordering::Relaxed);
        let _ = bridge.tx.send(SshInput::Close);
    }
    Ok(())
}

/// Send a mesh message over the shared mesh WebSocket.
fn send_mesh(
    ws: &Arc<Mutex<tungstenite::WebSocket<http::TlsStream>>>,
    msg: &MeshMessage,
) -> Result<(), GatewayError> {
    let mut ws = ws.lock().expect("mesh ws lock");
    ws.send(tungstenite::Message::Text(
        serde_json::to_string(msg)
            .map_err(|e| GatewayError::Protocol(format!("mesh send: {e}")))?,
    ))
    .map_err(|e| GatewayError::WebSocket(format!("mesh send: {e}")))
}

/// Handle a relayed SDP offer on the target gateway.
fn handle_mesh_relay_offer(
    shared: &Arc<Shared>,
    ws: &Arc<Mutex<tungstenite::WebSocket<http::TlsStream>>>,
    session_id: &str,
    sdp: &SdpPayload,
) {
    let (reply_tx, reply_rx) = sync_channel(1);
    match shared.event_tx.send(GatewayEvent::MeshOffer {
        session_id: session_id.to_string(),
        sdp: sdp.clone(),
        reply: reply_tx,
    }) {
        Ok(()) => match reply_rx.recv_timeout(Duration::from_secs(30)) {
            Ok(Ok(answer)) => {
                let _ = send_mesh(
                    ws,
                    &MeshMessage::RelayAnswer {
                        session_id: session_id.to_string(),
                        sdp: answer,
                    },
                );
            }
            Ok(Err(e)) => {
                let _ = send_mesh(
                    ws,
                    &MeshMessage::RelayError {
                        session_id: session_id.to_string(),
                        error: e.to_string(),
                    },
                );
            }
            Err(_) => {}
        },
        Err(e) => {
            let _ = send_mesh(
                ws,
                &MeshMessage::RelayError {
                    session_id: session_id.to_string(),
                    error: e.to_string(),
                },
            );
        }
    }
}

/// Open a local sshd bridge for a peer gateway's relayed SSH terminal.
fn open_relayed_ssh_bridge(
    shared: &Arc<Shared>,
    ws: &Arc<Mutex<tungstenite::WebSocket<http::TlsStream>>>,
    bridges: &mut HashMap<String, RelayBridge>,
    bridge_id: &str,
    auth: Option<SshAuth>,
) {
    if bridges.contains_key(bridge_id) {
        let _ = send_mesh(
            ws,
            &MeshMessage::SshOpenAck {
                session_id: bridge_id.to_string(),
                status: "error".into(),
                error: Some("bridge already open".into()),
            },
        );
        return;
    }

    let (tx, rx) = channel::<SshInput>();
    let stop = Arc::new(AtomicBool::new(false));
    let bridge = RelayBridge {
        tx,
        stop: stop.clone(),
        last_activity: Instant::now(),
    };
    bridges.insert(bridge_id.to_string(), bridge);

    // SSH worker thread: performs the real SSH handshake/authentication with
    // the target sshd, then bridges terminal bytes over the mesh connection.
    let data_ws = ws.clone();
    let close_ws = ws.clone();
    let ack_ws = ws.clone();
    let data_bridge_id = bridge_id.to_string();
    let close_bridge_id = bridge_id.to_string();
    let ack_bridge_id = bridge_id.to_string();
    let target = shared.cfg.ssh.target;
    thread::spawn(move || {
        ssh_client::run_ssh_client(
            target,
            auth,
            rx,
            stop,
            move |bytes| {
                let _ = send_mesh(
                    &data_ws,
                    &MeshMessage::SshData {
                        session_id: data_bridge_id.clone(),
                        data: base64_encode(bytes),
                    },
                );
            },
            move |reason| {
                let _ = send_mesh(
                    &close_ws,
                    &MeshMessage::SshClose {
                        session_id: close_bridge_id.clone(),
                        reason: reason.to_string(),
                    },
                );
            },
            move |result| {
                let (status, error) = match result {
                    Ok(()) => ("ok".to_string(), None),
                    Err(e) => ("error".to_string(), Some(e)),
                };
                let _ = send_mesh(
                    &ack_ws,
                    &MeshMessage::SshOpenAck {
                        session_id: ack_bridge_id.clone(),
                        status,
                        error,
                    },
                );
            },
        );
    });
}

/// Close a relayed SSH bridge on the target gateway.
fn close_relayed_bridge(
    ws: &Arc<Mutex<tungstenite::WebSocket<http::TlsStream>>>,
    bridges: &mut HashMap<String, RelayBridge>,
    bridge_id: &str,
    reason: &str,
) {
    if let Some(bridge) = bridges.remove(bridge_id) {
        bridge.stop.store(true, Ordering::Relaxed);
        let _ = bridge.tx.send(SshInput::Close);
        let _ = send_mesh(
            ws,
            &MeshMessage::SshClose {
                session_id: bridge_id.to_string(),
                reason: reason.to_string(),
            },
        );
    }
}

// ---------------------------------------------------------------------------
// Event loop
// ---------------------------------------------------------------------------
// Event loop
// ---------------------------------------------------------------------------

fn run_event_loop(shared: Arc<Shared>, rx: Receiver<GatewayEvent>) {
    let mut sessions: HashMap<String, Session> = HashMap::new();
    let mut buf = vec![0u8; UDP_BUF_SIZE];

    loop {
        // Drain command channel first.
        while let Ok(ev) = rx.try_recv() {
            handle_gateway_event(&shared, &mut sessions, ev);
        }

        // Drive each session's Rtc time forward and poll outputs.
        let now = Instant::now();
        let mut next_timeout = now + Duration::from_millis(200);

        for sess in sessions.values_mut() {
            if !sess.rtc.is_alive() {
                continue;
            }
            if let Err(e) = sess.rtc.handle_input(Input::Timeout(now)) {
                tracing::debug!("rtc timeout error: {e}");
                sess.rtc.disconnect();
            }
            next_timeout = next_timeout.min(poll_session_outputs(&shared, sess, now));
        }

        // Read UDP datagrams and demultiplex.
        let read_timeout = next_timeout
            .saturating_duration_since(now)
            .max(Duration::from_millis(1));
        if shared.udp.set_read_timeout(Some(read_timeout)).is_ok() {
            if let Ok((n, source)) = shared.udp.recv_from(&mut buf) {
                if let Ok(receive) = Receive::new(
                    Protocol::Udp,
                    source,
                    shared.udp.local_addr().unwrap(),
                    &buf[..n],
                ) {
                    let input = Input::Receive(now, receive);
                    for sess in sessions.values_mut() {
                        if sess.rtc.accepts(&input) {
                            if let Err(e) = sess.rtc.handle_input(input) {
                                tracing::debug!("rtc input error: {e}");
                                sess.rtc.disconnect();
                            }
                            break;
                        }
                    }
                }
            }
        }

        // Enforce SSH idle timeouts (configured, default 10 minutes).
        enforce_idle_timeouts(&shared, &mut sessions, Instant::now());

        // Clean up dead sessions.
        sessions.retain(|_, sess| sess.rtc.is_alive());

        if sessions.is_empty() {
            thread::sleep(Duration::from_millis(10));
        }
    }
}

/// Poll one session's Rtc output, returning the next timeout.
fn poll_session_outputs(shared: &Arc<Shared>, sess: &mut Session, now: Instant) -> Instant {
    let mut next_timeout = now + Duration::from_millis(200);
    loop {
        if !sess.rtc.is_alive() {
            return next_timeout;
        }
        match sess.rtc.poll_output() {
            Ok(Output::Timeout(t)) => {
                next_timeout = t;
                break;
            }
            Ok(Output::Transmit(t)) => {
                let _ = shared.udp.send_to(&t.contents, t.destination);
            }
            Ok(Output::Event(e)) => {
                handle_rtc_event(shared, sess, e, now);
            }
            Err(e) => {
                tracing::debug!("rtc poll error: {e}");
                sess.rtc.disconnect();
                break;
            }
        }
    }

    flush_send_queue(sess);
    next_timeout
}

fn flush_send_queue(sess: &mut Session) {
    let Some(cid) = sess.channel else {
        return;
    };
    while let Some(bytes) = sess.send_queue.front().cloned() {
        let Some(mut ch) = sess.rtc.channel(cid) else {
            break;
        };
        match ch.write(false, &bytes) {
            Ok(true) => {
                sess.send_queue.pop_front();
            }
            Ok(false) => break,
            Err(_) => {
                sess.send_queue.pop_front();
            }
        }
    }
}

fn handle_rtc_event(shared: &Arc<Shared>, sess: &mut Session, event: Event, now: Instant) {
    match event {
        Event::ChannelOpen(cid, _) => {
            sess.channel = Some(cid);
            flush_send_queue(sess);
        }
        Event::ChannelData(data) => {
            handle_channel_data(shared, sess, &data, now);
        }
        Event::IceConnectionStateChange(state) => {
            if state == IceConnectionState::Disconnected {
                sess.rtc.disconnect();
            }
        }
        Event::ChannelClose(cid) if sess.channel == Some(cid) => {
            sess.channel = None;
        }
        _ => {}
    }
}

fn handle_channel_data(shared: &Arc<Shared>, sess: &mut Session, data: &ChannelData, now: Instant) {
    if data.binary {
        return;
    }
    let text = match std::str::from_utf8(&data.data) {
        Ok(t) => t,
        Err(_) => return,
    };
    let msg: BrowserMessage = match serde_json::from_str(text) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!("bad browser message: {e}");
            return;
        }
    };
    match msg {
        BrowserMessage::Hello { peer_id, name } => {
            sess.peer_id = peer_id;
            sess.name = name;
        }
        BrowserMessage::RelayOffer {
            target,
            session_id,
            sdp,
        } => {
            let mesh = shared.mesh.clone();
            let event_tx = shared.event_tx.clone();
            thread::spawn(move || {
                let result = mesh.relay_offer(&target, &session_id, &sdp);
                let _ = event_tx.send(GatewayEvent::RelayResult {
                    session_id,
                    target,
                    result,
                });
            });
        }
        BrowserMessage::SshOpen {
            session_id,
            target,
            auth,
        } => {
            if target.is_empty() || target == shared.cfg.node_id {
                open_ssh_bridge(shared, sess, &session_id, auth, now);
            } else {
                open_ssh_relay(shared, sess, &session_id, &target, auth, now);
            }
        }
        BrowserMessage::SshData { session_id, data } => {
            let Some(bytes) = base64_decode(&data) else {
                return;
            };
            if let Some(bridge) = sess.ssh_bridges.get_mut(&session_id) {
                bridge.last_activity = now;
                if bridge.tx.send(SshInput::Data(bytes)).is_err() {
                    close_ssh_terminal(sess, &session_id, "worker gone");
                }
            } else if let Some(relay) = sess.ssh_relays.get_mut(&session_id) {
                relay.last_activity = now;
                let mesh_msg = MeshMessage::SshData {
                    session_id: session_id.clone(),
                    data: base64_encode(&bytes),
                };
                if relay.data.send(&mesh_msg).is_err() {
                    close_ssh_terminal(sess, &session_id, "write error");
                }
            } else {
                // Never silently swallow terminal bytes for an unknown session:
                // tell the browser the terminal is gone so it can surface an error.
                sess.send(&NodeMessage::SshClose {
                    session_id: session_id.clone(),
                    reason: "unknown ssh session".into(),
                });
            }
        }
        BrowserMessage::SshClose { session_id } => {
            close_ssh_terminal(sess, &session_id, "client closed");
        }
        BrowserMessage::Ping => {
            sess.send(&NodeMessage::Pong);
        }
    }
}

fn base64_decode(data: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(data.as_bytes())
        .ok()
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn open_ssh_bridge(
    shared: &Arc<Shared>,
    sess: &mut Session,
    bridge_id: &str,
    auth: Option<SshAuth>,
    now: Instant,
) {
    if sess.ssh_bridges.len() >= shared.cfg.ssh.max_terminals {
        sess.send(&NodeMessage::SshOpenAck {
            session_id: bridge_id.to_string(),
            status: "error".into(),
            error: Some("max terminals reached".into()),
        });
        return;
    }
    if sess.ssh_bridges.contains_key(bridge_id) {
        sess.send(&NodeMessage::SshOpenAck {
            session_id: bridge_id.to_string(),
            status: "error".into(),
            error: Some("bridge already open".into()),
        });
        return;
    }

    let (tx, rx) = channel::<SshInput>();
    let stop = Arc::new(AtomicBool::new(false));
    let bridge = SshBridge {
        tx,
        stop: stop.clone(),
        last_activity: now,
    };
    sess.ssh_bridges.insert(bridge_id.to_string(), bridge);

    // SSH worker thread: performs the real SSH handshake/authentication with
    // the target sshd, then bridges terminal bytes both ways.
    let data_tx = shared.event_tx.clone();
    let close_tx = shared.event_tx.clone();
    let ack_tx = shared.event_tx.clone();
    let data_session_id = sess.id.clone();
    let data_bridge_id = bridge_id.to_string();
    let close_session_id = sess.id.clone();
    let close_bridge_id = bridge_id.to_string();
    let ack_session_id = sess.id.clone();
    let ack_bridge_id = bridge_id.to_string();
    let target = shared.cfg.ssh.target;
    thread::spawn(move || {
        ssh_client::run_ssh_client(
            target,
            auth,
            rx,
            stop,
            move |bytes| {
                let _ = data_tx.send(GatewayEvent::SshData {
                    session_id: data_session_id.clone(),
                    bridge_id: data_bridge_id.clone(),
                    data: bytes.to_vec(),
                });
            },
            move |reason| {
                let _ = close_tx.send(GatewayEvent::SshClosed {
                    session_id: close_session_id.clone(),
                    bridge_id: close_bridge_id.clone(),
                    reason: reason.to_string(),
                });
            },
            move |result| {
                let (status, error) = match result {
                    Ok(()) => ("ok".to_string(), None),
                    Err(e) => ("error".to_string(), Some(e)),
                };
                let _ = ack_tx.send(GatewayEvent::SshOpenAck {
                    session_id: ack_session_id.clone(),
                    bridge_id: ack_bridge_id.clone(),
                    status,
                    error,
                });
            },
        );
    });
}

fn open_ssh_relay(
    shared: &Arc<Shared>,
    sess: &mut Session,
    bridge_id: &str,
    target: &str,
    auth: Option<SshAuth>,
    now: Instant,
) {
    if sess.ssh_bridges.len() + sess.ssh_relays.len() >= shared.cfg.ssh.max_terminals {
        sess.send(&NodeMessage::SshOpenAck {
            session_id: bridge_id.to_string(),
            status: "error".into(),
            error: Some("max terminals reached".into()),
        });
        return;
    }
    if sess.ssh_relays.contains_key(bridge_id) {
        sess.send(&NodeMessage::SshOpenAck {
            session_id: bridge_id.to_string(),
            status: "error".into(),
            error: Some("bridge already open".into()),
        });
        return;
    }

    let data = match shared.mesh.open_data_connection(target) {
        Ok(d) => d,
        Err(e) => {
            sess.send(&NodeMessage::SshOpenAck {
                session_id: bridge_id.to_string(),
                status: "error".into(),
                error: Some(format!("mesh relay to {target}: {e}")),
            });
            return;
        }
    };

    let mesh_msg = MeshMessage::SshOpen {
        session_id: bridge_id.to_string(),
        auth,
    };
    if let Err(e) = data.send(&mesh_msg) {
        data.close();
        sess.send(&NodeMessage::SshOpenAck {
            session_id: bridge_id.to_string(),
            status: "error".into(),
            error: Some(format!("mesh relay to {target}: {e}")),
        });
        return;
    }

    let relay = SshRelay {
        data: data.clone(),
        last_activity: now,
    };
    sess.ssh_relays.insert(bridge_id.to_string(), relay);

    // Reader thread: forward target-gateway messages (ack/data/close) to the
    // browser session via the event loop.
    let event_tx = shared.event_tx.clone();
    let session_id = sess.id.clone();
    let bridge_id = bridge_id.to_string();
    let target = target.to_string();
    thread::spawn(move || {
        loop {
            if data.is_stopped() {
                break;
            }
            match data.read() {
                Ok(MeshMessage::SshOpenAck {
                    session_id: sid,
                    status,
                    error,
                }) => {
                    let _ = event_tx.send(GatewayEvent::RelaySshOpenAck {
                        session_id: session_id.clone(),
                        bridge_id: sid,
                        status,
                        error,
                    });
                }
                Ok(MeshMessage::SshData {
                    session_id: sid,
                    data: encoded,
                }) => {
                    let bytes = base64_decode(&encoded).unwrap_or_default();
                    let _ = event_tx.send(GatewayEvent::SshData {
                        session_id: session_id.clone(),
                        bridge_id: sid,
                        data: bytes,
                    });
                }
                Ok(MeshMessage::SshClose {
                    session_id: sid,
                    reason,
                }) => {
                    let _ = event_tx.send(GatewayEvent::SshClosed {
                        session_id: session_id.clone(),
                        bridge_id: sid,
                        reason,
                    });
                }
                Ok(_) => continue,
                Err(e) => {
                    tracing::debug!("mesh relay reader {target}: {e}");
                    let _ = event_tx.send(GatewayEvent::SshClosed {
                        session_id: session_id.clone(),
                        bridge_id: bridge_id.clone(),
                        reason: format!("mesh relay: {e}"),
                    });
                    break;
                }
            }
        }
    });
}

fn close_ssh_bridge(sess: &mut Session, bridge_id: &str, reason: &str) {
    if let Some(bridge) = sess.ssh_bridges.remove(bridge_id) {
        bridge.stop.store(true, Ordering::Relaxed);
        let _ = bridge.tx.send(SshInput::Close);
        sess.send(&NodeMessage::SshClose {
            session_id: bridge_id.to_string(),
            reason: reason.to_string(),
        });
    }
}

fn close_ssh_relay(sess: &mut Session, bridge_id: &str, reason: &str) {
    if let Some(relay) = sess.ssh_relays.remove(bridge_id) {
        let _ = relay.data.send(&MeshMessage::SshClose {
            session_id: bridge_id.to_string(),
            reason: reason.to_string(),
        });
        relay.data.close();
        sess.send(&NodeMessage::SshClose {
            session_id: bridge_id.to_string(),
            reason: reason.to_string(),
        });
    }
}

/// Close an SSH terminal regardless of whether it is a local bridge or a
/// peer-relayed terminal.
fn close_ssh_terminal(sess: &mut Session, bridge_id: &str, reason: &str) {
    if sess.ssh_bridges.contains_key(bridge_id) {
        close_ssh_bridge(sess, bridge_id, reason);
    } else if sess.ssh_relays.contains_key(bridge_id) {
        close_ssh_relay(sess, bridge_id, reason);
    }
}

/// Close SSH bridges that have been idle for longer than the configured
/// timeout. Called once per event-loop iteration.
fn enforce_idle_timeouts(
    shared: &Arc<Shared>,
    sessions: &mut HashMap<String, Session>,
    now: Instant,
) {
    let timeout = shared.cfg.idle_timeout();
    for sess in sessions.values_mut() {
        let idle: Vec<String> = sess
            .ssh_bridges
            .iter()
            .filter(|(_, b)| now.duration_since(b.last_activity) >= timeout)
            .map(|(id, _)| id.clone())
            .chain(
                sess.ssh_relays
                    .iter()
                    .filter(|(_, b)| now.duration_since(b.last_activity) >= timeout)
                    .map(|(id, _)| id.clone()),
            )
            .collect();
        for bridge_id in idle {
            tracing::debug!("ssh terminal {bridge_id} idle timeout");
            close_ssh_terminal(sess, &bridge_id, "idle timeout");
        }
    }
}

/// Constant-time byte comparison for bearer-token checks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Gateway event handlers
// ---------------------------------------------------------------------------

fn handle_gateway_event(
    shared: &Arc<Shared>,
    sessions: &mut HashMap<String, Session>,
    event: GatewayEvent,
) {
    match event {
        GatewayEvent::CreateSession {
            session_id,
            peer_id,
            name,
            sdp,
            reply,
        } => {
            let result = create_session(shared, sessions, &session_id, &peer_id, &name, &sdp);
            let _ = reply.send(result);
        }
        GatewayEvent::CloseSession { session_id } => {
            sessions.remove(&session_id);
        }
        GatewayEvent::MeshOffer {
            session_id,
            sdp,
            reply,
        } => {
            let result = create_session(shared, sessions, &session_id, "", "relayed-browser", &sdp);
            let _ = reply.send(result);
        }
        GatewayEvent::RelayResult {
            session_id,
            target,
            result,
        } => {
            if let Some(sess) = sessions.get_mut(&session_id) {
                match result {
                    Ok(answer) => {
                        sess.send(&NodeMessage::RelayAnswer {
                            target,
                            session_id: session_id.clone(),
                            sdp: answer,
                        });
                    }
                    Err(e) => {
                        sess.send(&NodeMessage::RelayError {
                            target,
                            session_id: session_id.clone(),
                            error: e.to_string(),
                        });
                    }
                }
            }
        }
        GatewayEvent::SshData {
            session_id,
            bridge_id,
            data,
        } => {
            if let Some(sess) = sessions.get_mut(&session_id) {
                if let Some(bridge) = sess.ssh_bridges.get_mut(&bridge_id) {
                    bridge.last_activity = Instant::now();
                } else if let Some(relay) = sess.ssh_relays.get_mut(&bridge_id) {
                    relay.last_activity = Instant::now();
                }
                sess.send(&NodeMessage::SshData {
                    session_id: bridge_id,
                    data: base64_encode(&data),
                });
            }
        }
        GatewayEvent::SshClosed {
            session_id,
            bridge_id,
            reason,
        } => {
            if let Some(sess) = sessions.get_mut(&session_id) {
                close_ssh_terminal(sess, &bridge_id, &reason);
            }
        }
        GatewayEvent::SshOpenAck {
            session_id,
            bridge_id,
            status,
            error,
        } => {
            if let Some(sess) = sessions.get_mut(&session_id) {
                if status != "ok" {
                    // The SSH connection failed: remove the bridge so it does
                    // not linger until the idle timeout.
                    if let Some(bridge) = sess.ssh_bridges.remove(&bridge_id) {
                        bridge.stop.store(true, Ordering::Relaxed);
                        let _ = bridge.tx.send(SshInput::Close);
                    }
                }
                sess.send(&NodeMessage::SshOpenAck {
                    session_id: bridge_id,
                    status,
                    error,
                });
            }
        }
        GatewayEvent::RelaySshOpenAck {
            session_id,
            bridge_id,
            status,
            error,
        } => {
            if let Some(sess) = sessions.get_mut(&session_id) {
                if status != "ok" {
                    // The target gateway rejected the relayed terminal: drop
                    // the relay so it does not linger until the idle timeout.
                    if let Some(relay) = sess.ssh_relays.remove(&bridge_id) {
                        relay.data.close();
                    }
                }
                sess.send(&NodeMessage::SshOpenAck {
                    session_id: bridge_id,
                    status,
                    error,
                });
            }
        }
    }
}

/// Create (or reuse) a browser session and accept an SDP offer.
fn create_session(
    shared: &Arc<Shared>,
    sessions: &mut HashMap<String, Session>,
    session_id: &str,
    peer_id: &str,
    name: &str,
    sdp: &SdpPayload,
) -> Result<SdpPayload, GatewayError> {
    if let Some(_existing) = sessions.get(session_id) {
        // The browser already has this session. MVP does not support
        // renegotiation: accepting a re-offer on an existing Rtc produces an
        // answer whose mid does not match the new offer (the root cause of the
        // "answer failed" bug). Reject loudly so the browser never sees a bogus
        // answer and never reconnects in a loop.
        return Err(GatewayError::Protocol(
            "session already exists (re-offer not supported)".into(),
        ));
    }

    let now = Instant::now();
    let mut rtc = Rtc::builder().build(now);
    let udp_addr = shared.udp.local_addr().map_err(GatewayError::Io)?;
    let udp_port = udp_addr.port();
    // Advertise all non-loopback interface addresses as host candidates so
    // ICE can try each path (multi-homed hosts, mesh + LAN, etc.). The UDP
    // socket is bound to the selected IP, but candidates cover all interfaces.
    let mut added = 0;
    if let Ok(interfaces) = getifaddrs::getifaddrs() {
        for iface in interfaces {
            if iface.flags.contains(getifaddrs::InterfaceFlags::LOOPBACK) {
                continue;
            }
            if let Some(ip) = iface.address.ip_addr() {
                if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
                    continue;
                }
                // Match address family with the bound socket
                let same_family = matches!(
                    (udp_addr.ip(), ip),
                    (std::net::IpAddr::V4(_), std::net::IpAddr::V4(_))
                        | (std::net::IpAddr::V6(_), std::net::IpAddr::V6(_))
                );
                if !same_family {
                    continue;
                }
                let cand_addr = std::net::SocketAddr::new(ip, udp_port);
                if let Ok(candidate) = Candidate::host(cand_addr, "udp") {
                    rtc.add_local_candidate(candidate);
                    added += 1;
                }
            }
        }
    }
    // Fallback: if no interface candidates were added, use the bound address
    if added == 0 {
        let candidate = Candidate::host(udp_addr, "udp")
            .map_err(|e| GatewayError::Rtc(format!("host candidate: {e}")))?;
        rtc.add_local_candidate(candidate);
    }

    let offer = sdp.to_offer()?;
    let answer = rtc.sdp_api().accept_offer(offer)?;
    let payload = SdpPayload::from_answer(&answer)?;

    let mut session = Session::new(
        session_id.to_string(),
        peer_id.to_string(),
        name.to_string(),
        rtc,
    );
    session.send(&NodeMessage::HelloAck {
        node_id: shared.cfg.node_id.clone(),
        node_name: shared.cfg.node_name.clone(),
        node_list: shared.cfg.node_list.clone(),
        ice_servers: shared.cfg.ice_servers.clone(),
    });
    sessions.insert(session_id.to_string(), session);
    Ok(payload)
}

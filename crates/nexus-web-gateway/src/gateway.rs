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
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::mpsc::{Receiver, Sender, SyncSender, channel, sync_channel};
use std::sync::Arc;
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
use crate::mesh::{InMemoryMeshSignaler, MeshSignaler, WssMeshSignaler};
use crate::protocol::{BrowserMessage, MeshMessage, NodeMessage, SdpPayload, SshAuth};

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
}

/// Shared, clone-able gateway state.
struct Shared {
    cfg: GatewayConfig,
    tls: Arc<rustls::ServerConfig>,
    mesh: Arc<dyn MeshSignaler>,
    event_tx: Sender<GatewayEvent>,
    udp: Arc<UdpSocket>,
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

/// An SSH TCP-forward bridge.
struct SshBridge {
    /// Write end of the TCP connection to the local sshd.
    tcp_write: TcpStream,
    /// Last activity (used for idle timeout).
    last_activity: Instant,
}

/// The running gateway handle.
pub struct GatewayHandle {
    /// Local address of the HTTPS listener.
    pub local_addr: std::net::SocketAddr,
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
                peers.iter().map(|p| (p.peer_id.clone(), p.url.clone(), p.token.clone())),
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
            crate::config::TlsConfig::AutoGenerate { names, ips } => {
                cert::generate_identity(names, ips)?
            }
            crate::config::TlsConfig::Files {
                cert_path,
                key_path,
            } => cert::load_identity(cert_path, key_path)?,
        };
        let tls = Arc::new(cert::server_config(&identity)?);

        let udp_ip = if cfg.listen_addr.ip().is_unspecified() {
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        } else {
            cfg.listen_addr.ip()
        };
        let udp = Arc::new(UdpSocket::bind((udp_ip, 0)).map_err(GatewayError::Io)?);
        udp
            .set_read_timeout(Some(Duration::from_millis(50)))
            .map_err(GatewayError::Io)?;

        let (event_tx, event_rx) = channel::<GatewayEvent>();

        let listener = TcpListener::bind(cfg.listen_addr).map_err(GatewayError::Io)?;
        let local_addr = listener.local_addr().map_err(GatewayError::Io)?;

        let shared = Arc::new(Shared {
            cfg: cfg.clone(),
            tls,
            mesh: mesh.clone(),
            event_tx: event_tx.clone(),
            udp: udp.clone(),
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
        let _ = tls.conn.send_close_notify();
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
        "close" => {
            if let Some(sid) = value.get("session_id").and_then(serde_json::Value::as_str) {
                let _ = shared.event_tx.send(GatewayEvent::CloseSession {
                    session_id: sid.to_string(),
                });
            }
            Ok(())
        }
        _ => Err(GatewayError::Protocol(format!("unknown signaling message type {kind}"))),
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
        .map_err(GatewayError::from)
}

fn handle_mesh_connection(
    shared: Arc<Shared>,
    mut ws: tungstenite::WebSocket<http::TlsStream>,
) -> Result<(), GatewayError> {
    loop {
        let msg = match ws.read() {
            Ok(m) => m,
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
                        let _ = ws.send(tungstenite::Message::Text(format!(
                            r#"{{"type":"relay_error","session_id":"","error":"bad mesh message: {e}"}}"#
                        )));
                        continue;
                    }
                };
                if let MeshMessage::RelayOffer { session_id, sdp } = parsed {
                    let (reply_tx, reply_rx) = sync_channel(1);
                    match shared.event_tx.send(GatewayEvent::MeshOffer {
                        session_id: session_id.clone(),
                        sdp: sdp.clone(),
                        reply: reply_tx,
                    }) {
                        Ok(()) => match reply_rx.recv_timeout(Duration::from_secs(30)) {
                            Ok(Ok(answer)) => {
                                let _ = ws.send(tungstenite::Message::Text(
                                    serde_json::to_string(&MeshMessage::RelayAnswer {
                                        session_id,
                                        sdp: answer,
                                    })
                                    .expect("mesh answer serializable"),
                                ));
                            }
                            Ok(Err(e)) => {
                                let _ = ws.send(tungstenite::Message::Text(
                                    serde_json::to_string(&MeshMessage::RelayError {
                                        session_id,
                                        error: e.to_string(),
                                    })
                                    .expect("mesh error serializable"),
                                ));
                            }
                            Err(_) => {}
                        },
                        Err(e) => {
                            let _ = ws.send(tungstenite::Message::Text(
                                serde_json::to_string(&MeshMessage::RelayError {
                                    session_id,
                                    error: e.to_string(),
                                })
                                .expect("mesh error serializable"),
                            ));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

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
                if let Ok(receive) =
                    Receive::new(Protocol::Udp, source, shared.udp.local_addr().unwrap(), &buf[..n])
                {
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
    loop {
        let Some(bytes) = sess.send_queue.front().cloned() else {
            break;
        };
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
        Event::ChannelClose(cid) => {
            if sess.channel == Some(cid) {
                sess.channel = None;
            }
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
            target: _,
            auth,
        } => {
            open_ssh_bridge(shared, sess, &session_id, auth, now);
        }
        BrowserMessage::SshData { session_id, data } => {
            if let Some(bridge) = sess.ssh_bridges.get_mut(&session_id) {
                bridge.last_activity = now;
                let Some(bytes) = base64_decode(&data) else {
                    return;
                };
                if bridge.tcp_write.write_all(&bytes).is_err() {
                    close_ssh_bridge(sess, &session_id, "write error");
                }
            }
        }
        BrowserMessage::SshClose { session_id } => {
            close_ssh_bridge(sess, &session_id, "client closed");
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

    let mut tcp = match TcpStream::connect(shared.cfg.ssh.target) {
        Ok(t) => t,
        Err(e) => {
            sess.send(&NodeMessage::SshOpenAck {
                session_id: bridge_id.to_string(),
                status: "error".into(),
                error: Some(format!("connect to sshd: {e}")),
            });
            return;
        }
    };
    tcp.set_read_timeout(Some(Duration::from_millis(500))).ok();
    let mut read_end = match tcp.try_clone() {
        Ok(t) => t,
        Err(e) => {
            sess.send(&NodeMessage::SshOpenAck {
                session_id: bridge_id.to_string(),
                status: "error".into(),
                error: Some(format!("clone tcp: {e}")),
            });
            return;
        }
    };

    // Optional mock-sshd auth prologue (real sshd uses pure byte forwarding).
    if let Some(prologue) = &shared.cfg.ssh.auth_prologue {
        if let Some(line) = format_auth_prologue(prologue, &auth) {
            let _ = tcp.write_all(line.as_bytes());
        }
    }

    let bridge = SshBridge {
        tcp_write: tcp,
        last_activity: now,
    };
    sess.ssh_bridges.insert(bridge_id.to_string(), bridge);
    sess.send(&NodeMessage::SshOpenAck {
        session_id: bridge_id.to_string(),
        status: "ok".into(),
        error: None,
    });

    // Reader thread.
    let event_tx = shared.event_tx.clone();
    let bridge_id = bridge_id.to_string();
    let session_id = sess.id.clone();
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match read_end.read(&mut buf) {
                Ok(0) => {
                    let _ = event_tx.send(GatewayEvent::SshClosed {
                        session_id: session_id.clone(),
                        bridge_id: bridge_id.clone(),
                        reason: "sshd closed connection".into(),
                    });
                    break;
                }
                Ok(n) => {
                    let _ = event_tx.send(GatewayEvent::SshData {
                        session_id: session_id.clone(),
                        bridge_id: bridge_id.clone(),
                        data: buf[..n].to_vec(),
                    });
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    continue;
                }
                Err(_) => {
                    let _ = event_tx.send(GatewayEvent::SshClosed {
                        session_id: session_id.clone(),
                        bridge_id: bridge_id.clone(),
                        reason: "sshd read error".into(),
                    });
                    break;
                }
            }
        }
    });
}

fn format_auth_prologue(template: &str, auth: &Option<SshAuth>) -> Option<String> {
    let (username, password, private_key) = match auth {
        Some(SshAuth::Password { username, password }) => {
            (username.as_str(), Some(password.as_str()), None)
        }
        Some(SshAuth::Key {
            username,
            private_key,
        }) => (username.as_str(), None, Some(private_key.as_str())),
        None => ("", None, None),
    };
    Some(
        template
            .replace("{username}", username)
            .replace("{password}", password.unwrap_or(""))
            .replace("{private_key}", private_key.unwrap_or("")),
    )
}

fn close_ssh_bridge(sess: &mut Session, bridge_id: &str, reason: &str) {
    if let Some(bridge) = sess.ssh_bridges.remove(bridge_id) {
        let _ = bridge.tcp_write.shutdown(std::net::Shutdown::Both);
        sess.send(&NodeMessage::SshClose {
            session_id: bridge_id.to_string(),
            reason: reason.to_string(),
        });
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
            .collect();
        for bridge_id in idle {
            tracing::debug!("ssh bridge {bridge_id} idle timeout");
            close_ssh_bridge(sess, &bridge_id, "idle timeout");
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
                close_ssh_bridge(sess, &bridge_id, &reason);
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
    if let Some(existing) = sessions.get_mut(session_id) {
        // Re-offer: accept on the existing Rtc.
        let offer = sdp.to_offer()?;
        let answer = existing.rtc.sdp_api().accept_offer(offer)?;
        return SdpPayload::from_answer(&answer);
    }

    let now = Instant::now();
    let mut rtc = Rtc::builder().build(now);
    let udp_addr = shared.udp.local_addr().map_err(GatewayError::Io)?;
    let candidate = Candidate::host(udp_addr, "udp")
        .map_err(|e| GatewayError::Rtc(format!("host candidate: {e}")))?;
    rtc.add_local_candidate(candidate);

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
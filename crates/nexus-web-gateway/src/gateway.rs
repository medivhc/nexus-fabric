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
use crate::file::{
    self, FILE_CHANNEL_LABEL, FRAME_READ_CHUNK, FRAME_WRITE_CHUNK, FileBackend, FileCommand,
    FileLimits, FileReply, LocalSandbox, SftpBackend, decode_frame, encode_frame,
};
use crate::http;
use crate::mesh::{InMemoryMeshSignaler, MeshDataConnection, MeshSignaler, WssMeshSignaler};
use crate::protocol::{
    BrowserMessage, FileEntry, FileTarget, MeshMessage, NodeMessage, SdpPayload, SshAuth,
};
use crate::ssh_client::{self, SshInput};

/// Enumerate routable interface addresses of the same family as `for_ip`
/// (skipping loopback, unspecified and multicast), deduplicated.
fn routable_iface_ips(for_ip: std::net::IpAddr) -> Vec<std::net::IpAddr> {
    let Ok(interfaces) = getifaddrs::getifaddrs() else {
        return Vec::new();
    };
    let mut ips: Vec<std::net::IpAddr> = Vec::new();
    for iface in interfaces {
        if iface.flags.contains(getifaddrs::InterfaceFlags::LOOPBACK) {
            continue;
        }
        let Some(ip) = iface.address.ip_addr() else {
            continue;
        };
        if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
            continue;
        }
        let same_family = matches!(
            (for_ip, ip),
            (std::net::IpAddr::V4(_), std::net::IpAddr::V4(_))
                | (std::net::IpAddr::V6(_), std::net::IpAddr::V6(_))
        );
        if same_family && !ips.contains(&ip) {
            ips.push(ip);
        }
    }
    ips
}

/// How the shared WebRTC UDP socket is bound, and which addresses the SDP may
/// advertise as ICE host candidates.
///
/// **G11 (candidate/receive coherence)**: every advertised host candidate must
/// be an address the bound socket can actually receive on. A UDP socket bound to
/// a concrete IP only receives datagrams whose destination is that IP, so a
/// gateway listening on `127.0.0.1` must advertise the loopback address and
/// nothing else. Advertising the host's LAN/mesh IPs instead — which is what the
/// multi-homed fix used to do unconditionally — yields candidates that always
/// time out: ICE never connected, and every DataChannel test failed with
/// "no control channel open".
///
/// An unspecified `listen_addr` is therefore bound to the family's wildcard
/// address, which *does* receive on every interface. That is exactly the
/// configuration where advertising all non-loopback interface IPs (multi-homed
/// hosts: LAN + mesh) is both valid and necessary.
struct IceBindPlan {
    /// Address to bind the shared UDP socket to.
    bind_ip: std::net::IpAddr,
    /// Addresses the bound socket can receive on, in advertisement order.
    candidate_ips: Vec<std::net::IpAddr>,
    /// Browser-facing address for the page URL (never unspecified).
    page_ip: std::net::IpAddr,
    /// An unspecified `listen_addr` with no routable interface at all: ICE can
    /// only offer a loopback candidate, which no remote browser can reach.
    no_routable_interface: bool,
}

/// Derive the UDP bind address and the host-candidate set for a `listen_addr`.
fn ice_bind_plan(listen_ip: std::net::IpAddr) -> IceBindPlan {
    if !listen_ip.is_unspecified() {
        // Concrete bind: the socket receives on this address only, so this is
        // also the only candidate we may advertise.
        return IceBindPlan {
            bind_ip: listen_ip,
            candidate_ips: vec![listen_ip],
            page_ip: listen_ip,
            no_routable_interface: false,
        };
    }
    let ifaces = routable_iface_ips(listen_ip);
    let no_routable_interface = ifaces.is_empty();
    IceBindPlan {
        bind_ip: listen_ip,
        candidate_ips: ifaces.clone(),
        page_ip: ifaces
            .first()
            .copied()
            .unwrap_or_else(|| loopback_for(listen_ip)),
        no_routable_interface,
    }
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

/// Label of the JSON control DataChannel the browser opens first.
const CONTROL_CHANNEL_LABEL: &str = "control";

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
    /// File worker: the session opened (or failed to open).
    FileOpened {
        session_id: String,
        file_id: String,
        kind: String,
        error: Option<String>,
    },
    /// File worker: a directory listing.
    FileListed {
        session_id: String,
        file_id: String,
        path: String,
        entries: Vec<FileEntry>,
        error: Option<String>,
    },
    /// File worker: a single entry.
    FileStatted {
        session_id: String,
        file_id: String,
        entry: Option<FileEntry>,
        error: Option<String>,
    },
    /// File worker: bytes for a download, delivered as a binary frame (or an
    /// error message when `error` is set).
    FileChunk {
        session_id: String,
        file_id: String,
        stream_id: u32,
        offset: u64,
        data: Vec<u8>,
        final_block: bool,
        error: Option<String>,
    },
    /// File worker: upload progress.
    FileWriteAck {
        session_id: String,
        file_id: String,
        stream_id: u32,
        received: u64,
        error: Option<String>,
    },
    /// File worker: mkdir / remove / rename / write_end finished.
    FileOpDone {
        session_id: String,
        file_id: String,
        op: String,
        path: String,
        error: Option<String>,
    },
    /// File worker: the session closed.
    FileClosed {
        session_id: String,
        file_id: String,
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
    /// ICE host candidates to advertise: exactly the addresses the shared UDP
    /// socket can receive on (G11). Computed once at startup.
    host_candidate_ips: Vec<std::net::IpAddr>,
    /// PEM-encoded self-signed certificate, served at `/cert`.
    cert_pem: String,
    /// SHA256 fingerprint of the certificate, for /cert HTML page (REQ-001).
    cert_fingerprint: String,
}

/// One browser session: the node-side WebRTC peer plus protocol state.
struct Session {
    id: String,
    peer_id: String,
    name: String,
    rtc: Rtc,
    channel: Option<ChannelId>,
    send_queue: VecDeque<Vec<u8>>,
    /// Binary DataChannel carrying file chunks (label `nexus.file`).
    file_channel: Option<ChannelId>,
    file_send_queue: VecDeque<Vec<u8>>,
    ssh_bridges: HashMap<String, SshBridge>,
    ssh_relays: HashMap<String, SshRelay>,
    /// Open file sessions, keyed by the browser's `session_id`.
    file_sessions: HashMap<String, FileBridge>,
    /// Claimed chunk streams: stream id -> owning file session id. The binary
    /// frame header carries only the stream id, so this maps a chunk back to the
    /// session that must receive it.
    file_streams: HashMap<u32, String>,
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
            file_channel: None,
            file_send_queue: VecDeque::new(),
            ssh_bridges: HashMap::new(),
            ssh_relays: HashMap::new(),
            file_sessions: HashMap::new(),
            file_streams: HashMap::new(),
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

    /// Queue a binary frame for delivery over the file DataChannel (G15:
    /// file bytes never travel on the JSON control channel). Frames are dropped
    /// (never queued forever) while the file channel is closed.
    fn send_file(&mut self, bytes: Vec<u8>) {
        if self.file_channel.is_none() {
            tracing::debug!("file frame dropped: no file data channel open");
            return;
        }
        self.file_send_queue.push_back(bytes);
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
        // Stop every file worker the same way.
        for (_, bridge) in self.file_sessions.drain() {
            bridge.stop.store(true, Ordering::Relaxed);
            let _ = bridge.tx.send(FileCommand::Close {
                session_id: bridge.id.clone(),
                reason: "session closed".into(),
            });
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

/// A file session bridge to one backend, driven by a dedicated worker thread.
struct FileBridge {
    /// The file session id the browser assigned.
    id: String,
    /// Channel to the file worker thread.
    tx: Sender<FileCommand>,
    /// Set when the bridge must close; the worker checks it each loop.
    stop: Arc<AtomicBool>,
    /// Last activity (used for the file idle timeout).
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

        let plan = ice_bind_plan(cfg.listen_addr.ip());
        if plan.no_routable_interface {
            eprintln!(
                "warning: `listen_addr` is unspecified and no non-loopback network interface was \
                 found; ICE can only offer the loopback candidate {ip}, which remote browsers \
                 cannot reach — set `listen_addr` to a routable IP address.",
                ip = plan.page_ip
            );
        }
        // Wildcard bind (unspecified listen_addr) receives on every interface,
        // which is what makes the multi-candidate advertisement below valid.
        let udp = Arc::new(UdpSocket::bind((plan.bind_ip, 0)).map_err(GatewayError::Io)?);
        udp.set_read_timeout(Some(Duration::from_millis(50)))
            .map_err(GatewayError::Io)?;

        let (event_tx, event_rx) = channel::<GatewayEvent>();

        let listener = TcpListener::bind(cfg.listen_addr).map_err(GatewayError::Io)?;
        let local_addr = listener.local_addr().map_err(GatewayError::Io)?;
        // The address browsers should actually open (never `0.0.0.0`/`::`).
        // Use the actually bound port so `listen_addr: "0.0.0.0:0"` works.
        let page_addr = std::net::SocketAddr::new(plan.page_ip, local_addr.port());

        let shared = Arc::new(Shared {
            cfg: cfg.clone(),
            tls,
            mesh: mesh.clone(),
            event_tx: event_tx.clone(),
            udp: udp.clone(),
            host_candidate_ips: plan.candidate_ips,
            cert_pem: identity.cert_pem()?,
            cert_fingerprint: identity.fingerprint_sha256(),
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
            // File module capability discovery for the page: whether it is
            // enabled and which local roots exist. The bearer token is never
            // exposed here.
            "files": {
                "enabled": shared.cfg.files.enabled,
                "chunk_bytes": shared.cfg.files.chunk_bytes,
                "roots": shared.cfg.files.roots.iter().map(|r| serde_json::json!({
                    "name": r.name,
                    "read_only": r.read_only,
                })).collect::<Vec<_>>(),
            },
        }))
        .map_err(|e| GatewayError::Protocol(e.to_string()))?;
        http::write_http_response(tls, "application/json", &body, &[]).map_err(GatewayError::Io)?;
        return Ok(());
    }
    if request.path.starts_with("/cert") {
        // REQ-001: Browser gets HTML guidance page (A), direct download gets PEM (B).
        let accepts_html = request
            .header("accept")
            .map(|v| v.contains("text/html"))
            .unwrap_or(false);
        let force_pem = request.path.contains("format=pem");
        if accepts_html && !force_pem {
            let html = format!(
                "<!DOCTYPE html><html><head><meta charset=\"utf-8\">                <title>Install Nexus CA</title>                <style>body{{font-family:system-ui,sans-serif;max-width:640px;margin:40px auto;padding:0 16px;}}                code{{background:#f0f0f0;padding:2px 6px;border-radius:4px;word-break:break-all;}}                pre{{background:#f0f0f0;padding:12px;border-radius:8px;overflow-x:auto;}}                .btn{{display:inline-block;background:#0066cc;color:#fff;padding:10px 20px;                text-decoration:none;border-radius:6px;margin:10px 0;}}</style></head>                <body><h1>Install Nexus Local CA</h1>                <p>This gateway uses a self-signed certificate. Install the CA below.</p>                <h2>SHA256 Fingerprint</h2><p><code>{fp}</code></p>                <h2>Option A: Browser Download</h2>                <a class=\"btn\" href=\"/cert?format=pem\" download=\"nexus-ca.crt\">Download nexus-ca.crt</a>                <h2>Option B: Command Line</h2>                <pre>curl -k https://{host}/cert?format=pem -o nexus-ca.crt</pre>                </body></html>",
                fp = shared.cert_fingerprint,
                host = request.header("host").unwrap_or("this-gateway"),
            );
            http::write_http_response(tls, "text/html; charset=utf-8", html.as_bytes(), &[])
                .map_err(GatewayError::Io)?;
        } else {
            http::write_http_response(
                tls,
                "application/x-pem-file",
                shared.cert_pem.as_bytes(),
                &[(
                    "Content-Disposition",
                    "attachment; filename=\"nexus-ca.crt\"",
                )],
            )
            .map_err(GatewayError::Io)?;
        }
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
    if let Some(cid) = sess.channel {
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
    if let Some(cid) = sess.file_channel {
        while let Some(bytes) = sess.file_send_queue.front().cloned() {
            let Some(mut ch) = sess.rtc.channel(cid) else {
                break;
            };
            match ch.write(true, &bytes) {
                Ok(true) => {
                    sess.file_send_queue.pop_front();
                }
                // Backpressure: keep the frame queued and try again next tick.
                Ok(false) => break,
                Err(_) => {
                    sess.file_send_queue.pop_front();
                }
            }
        }
    }
}

fn handle_rtc_event(shared: &Arc<Shared>, sess: &mut Session, event: Event, now: Instant) {
    match event {
        Event::ChannelOpen(cid, label) => {
            if label == FILE_CHANNEL_LABEL {
                sess.file_channel = Some(cid);
            } else if sess.channel.is_none() || label == CONTROL_CHANNEL_LABEL {
                // The channel explicitly labeled `control` wins; otherwise the
                // first channel to open is the control channel (peers that open
                // a single unnamed channel keep working).
                sess.channel = Some(cid);
            }
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
            if sess.file_channel == Some(cid) {
                sess.file_channel = None;
                sess.file_send_queue.clear();
            }
        }
        _ => {}
    }
}

fn handle_channel_data(shared: &Arc<Shared>, sess: &mut Session, data: &ChannelData, now: Instant) {
    if data.binary {
        handle_file_frame(sess, data, now);
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
        BrowserMessage::FileOpen {
            session_id,
            token,
            target,
        } => {
            open_file_session(shared, sess, &session_id, &token, target, now);
        }
        BrowserMessage::FileList { session_id, path } => {
            let for_cmd = path.clone();
            forward_to_file(
                sess,
                now,
                &session_id,
                FileCommand::List {
                    session_id: session_id.clone(),
                    path: for_cmd,
                },
                |id| NodeMessage::FileListAck {
                    session_id: id,
                    path,
                    entries: Vec::new(),
                    error: Some(UNKNOWN_FILE_SESSION.into()),
                },
            );
        }
        BrowserMessage::FileStat { session_id, path } => {
            let for_cmd = path.clone();
            forward_to_file(
                sess,
                now,
                &session_id,
                FileCommand::Stat {
                    session_id: session_id.clone(),
                    path: for_cmd,
                },
                |id| NodeMessage::FileStatAck {
                    session_id: id,
                    entry: None,
                    error: Some(UNKNOWN_FILE_SESSION.into()),
                },
            );
        }
        BrowserMessage::FileRead {
            session_id,
            stream_id,
            path,
            offset,
            len,
        } => {
            if let Err(e) = claim_stream(sess, stream_id, &session_id) {
                sess.send(&NodeMessage::FileOpAck {
                    session_id,
                    op: "read".into(),
                    path,
                    ok: false,
                    error: Some(e),
                });
                return;
            }
            let for_cmd = path.clone();
            forward_to_file(
                sess,
                now,
                &session_id,
                FileCommand::Read {
                    session_id: session_id.clone(),
                    stream_id,
                    path: for_cmd,
                    offset,
                    len,
                },
                |id| NodeMessage::FileOpAck {
                    session_id: id,
                    op: "read".into(),
                    path,
                    ok: false,
                    error: Some(UNKNOWN_FILE_SESSION.into()),
                },
            );
        }
        BrowserMessage::FileWriteBegin {
            session_id,
            stream_id,
            path,
        } => {
            if let Err(e) = claim_stream(sess, stream_id, &session_id) {
                sess.send(&NodeMessage::FileWriteAck {
                    session_id,
                    stream_id,
                    received: 0,
                    error: Some(e),
                });
                return;
            }
            let for_cmd = path.clone();
            forward_to_file(
                sess,
                now,
                &session_id,
                FileCommand::WriteBegin {
                    session_id: session_id.clone(),
                    stream_id,
                    path: for_cmd,
                },
                |id| NodeMessage::FileWriteAck {
                    session_id: id,
                    stream_id,
                    received: 0,
                    error: Some(UNKNOWN_FILE_SESSION.into()),
                },
            );
        }
        BrowserMessage::FileWriteEnd {
            session_id,
            stream_id,
            path,
        } => {
            let for_cmd = path.clone();
            forward_to_file(
                sess,
                now,
                &session_id,
                FileCommand::WriteEnd {
                    session_id: session_id.clone(),
                    stream_id,
                    path: for_cmd,
                },
                |id| NodeMessage::FileOpAck {
                    session_id: id,
                    op: "write_end".into(),
                    path,
                    ok: false,
                    error: Some(UNKNOWN_FILE_SESSION.into()),
                },
            );
        }
        BrowserMessage::FileMkdir { session_id, path } => {
            let for_cmd = path.clone();
            forward_to_file(
                sess,
                now,
                &session_id,
                FileCommand::Mkdir {
                    session_id: session_id.clone(),
                    path: for_cmd,
                },
                |id| NodeMessage::FileOpAck {
                    session_id: id,
                    op: "mkdir".into(),
                    path,
                    ok: false,
                    error: Some(UNKNOWN_FILE_SESSION.into()),
                },
            );
        }
        BrowserMessage::FileRemove {
            session_id,
            path,
            recursive,
        } => {
            let for_cmd = path.clone();
            forward_to_file(
                sess,
                now,
                &session_id,
                FileCommand::Remove {
                    session_id: session_id.clone(),
                    path: for_cmd,
                    recursive,
                },
                |id| NodeMessage::FileOpAck {
                    session_id: id,
                    op: "remove".into(),
                    path,
                    ok: false,
                    error: Some(UNKNOWN_FILE_SESSION.into()),
                },
            );
        }
        BrowserMessage::FileRename {
            session_id,
            from,
            to,
        } => {
            let (for_cmd, to_cmd) = (from.clone(), to.clone());
            forward_to_file(
                sess,
                now,
                &session_id,
                FileCommand::Rename {
                    session_id: session_id.clone(),
                    from: for_cmd,
                    to: to_cmd,
                },
                |id| NodeMessage::FileOpAck {
                    session_id: id,
                    op: "rename".into(),
                    path: to,
                    ok: false,
                    error: Some(UNKNOWN_FILE_SESSION.into()),
                },
            );
        }
        BrowserMessage::FileClose { session_id } => {
            close_file_session(sess, &session_id, "client closed");
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

/// Reply text used when a file command names a session that is not open.
const UNKNOWN_FILE_SESSION: &str = "unknown file session";

/// Route an upload chunk from the binary file channel to its worker.
///
/// The frame header carries only the stream id, so [`Session::file_streams`]
/// resolves it back to the owning file session. Unknown streams are answered
/// explicitly (never dropped silently, per G9 and G16).
fn handle_file_frame(sess: &mut Session, data: &ChannelData, now: Instant) {
    let Some(file_cid) = sess.file_channel else {
        tracing::debug!("binary frame ignored: no file data channel");
        return;
    };
    if data.id != file_cid {
        tracing::debug!("binary frame on unexpected channel {:?}", data.id);
        return;
    }
    let frame = match decode_frame(&data.data) {
        Ok(frame) => frame,
        Err(e) => {
            tracing::debug!("malformed file frame: {e}");
            sess.send(&NodeMessage::FileWriteAck {
                session_id: String::new(),
                stream_id: 0,
                received: 0,
                error: Some(format!("malformed file frame: {e}")),
            });
            return;
        }
    };
    if frame.kind != FRAME_WRITE_CHUNK {
        tracing::debug!("unexpected file frame kind {:#04x}", frame.kind);
        return;
    }
    let Some(file_id) = sess.file_streams.get(&frame.stream_id).cloned() else {
        sess.send(&NodeMessage::FileWriteAck {
            session_id: String::new(),
            stream_id: frame.stream_id,
            received: 0,
            error: Some("unknown upload stream".into()),
        });
        return;
    };
    let Some(bridge) = sess.file_sessions.get_mut(&file_id) else {
        sess.file_streams.remove(&frame.stream_id);
        return;
    };
    bridge.last_activity = now;
    let cmd = FileCommand::WriteChunk {
        session_id: file_id.clone(),
        stream_id: frame.stream_id,
        offset: frame.offset,
        data: frame.data.to_vec(),
    };
    if bridge.tx.send(cmd).is_err() {
        close_file_session(sess, &file_id, "worker gone");
    }
}

/// Claim a stream id for a file session (reads and uploads share the space).
fn claim_stream(sess: &mut Session, stream_id: u32, file_id: &str) -> Result<(), String> {
    if let Some(owner) = sess.file_streams.get(&stream_id) {
        return if owner == file_id {
            Ok(())
        } else {
            Err(format!(
                "stream {stream_id} already used by session {owner}"
            ))
        };
    }
    if !sess.file_sessions.contains_key(file_id) {
        return Err(UNKNOWN_FILE_SESSION.into());
    }
    sess.file_streams.insert(stream_id, file_id.to_string());
    Ok(())
}

/// Forward one command to a file worker, replying explicitly when the session
/// is gone.
fn forward_to_file(
    sess: &mut Session,
    now: Instant,
    file_id: &str,
    cmd: FileCommand,
    on_missing: impl FnOnce(String) -> NodeMessage,
) {
    match sess.file_sessions.get_mut(file_id) {
        Some(bridge) => {
            bridge.last_activity = now;
            if bridge.tx.send(cmd).is_err() {
                close_file_session(sess, file_id, "worker gone");
            }
        }
        None => sess.send(&on_missing(file_id.to_string())),
    }
}

/// Open a file session.
///
/// The gate (module enabled, bearer token, limits) is checked here on the event
/// loop; the backend itself is built on the worker thread so a slow SFTP
/// handshake cannot stall every other session. G12: an enabled module without a
/// token is a configuration error, so this can only ever accept a matching token.
fn open_file_session(
    shared: &Arc<Shared>,
    sess: &mut Session,
    file_id: &str,
    token: &str,
    target: FileTarget,
    now: Instant,
) {
    let cfg = &shared.cfg.files;
    let reject = |reason: String| NodeMessage::FileOpenAck {
        session_id: file_id.to_string(),
        kind: String::new(),
        status: "error".into(),
        error: Some(reason),
        chunk_bytes: 0,
        roots: Vec::new(),
    };
    if !cfg.enabled {
        sess.send(&reject("file module disabled".into()));
        return;
    }
    if token.is_empty() || !constant_time_eq(token.as_bytes(), cfg.auth_token.as_bytes()) {
        tracing::debug!("file open refused for {file_id}: bearer token mismatch");
        sess.send(&reject("invalid file token".into()));
        return;
    }
    if sess.file_sessions.len() >= cfg.max_sessions {
        sess.send(&reject("max file sessions reached".into()));
        return;
    }
    if sess.file_sessions.contains_key(file_id) {
        sess.send(&reject("file session already open".into()));
        return;
    }

    let (tx, rx) = channel::<FileCommand>();
    let stop = Arc::new(AtomicBool::new(false));
    sess.file_sessions.insert(
        file_id.to_string(),
        FileBridge {
            id: file_id.to_string(),
            tx,
            stop: stop.clone(),
            last_activity: now,
        },
    );

    let limits = FileLimits::from(cfg);
    let roots = cfg.roots.clone();
    let ssh_target = shared.cfg.ssh.target;
    let event_tx = shared.event_tx.clone();
    let file_session_id = file_id.to_string();
    let rtc_session_id = sess.id.clone();
    thread::spawn(move || {
        let built: Result<Box<dyn FileBackend>, String> = match &target {
            FileTarget::Sftp { auth } => SftpBackend::connect(ssh_target, auth.clone(), limits)
                .map(|engine| Box::new(engine) as Box<dyn FileBackend>),
            FileTarget::Local { root } => match roots.iter().find(|r| &r.name == root) {
                Some(root_cfg) => {
                    LocalSandbox::new(root_cfg, limits).map(|engine| Box::new(engine) as _)
                }
                None => Err(format!("unknown local root: {root}")),
            },
        };
        let event_tx = event_tx.clone();
        file::run_file_worker(built, file_session_id, rx, stop, limits, move |reply| {
            let _ = event_tx.send(to_file_event(rtc_session_id.clone(), reply));
        });
    });
}

/// Close a file session, release its streams and tell the browser.
fn close_file_session(sess: &mut Session, file_id: &str, reason: &str) {
    if let Some(bridge) = sess.file_sessions.remove(file_id) {
        bridge.stop.store(true, Ordering::Relaxed);
        let _ = bridge.tx.send(FileCommand::Close {
            session_id: file_id.to_string(),
            reason: reason.to_string(),
        });
    }
    sess.file_streams.retain(|_, owner| owner != file_id);
    sess.send(&NodeMessage::FileClosed {
        session_id: file_id.to_string(),
        reason: reason.to_string(),
    });
}

/// Map a worker reply onto an event-loop event. `rtc_session_id` is the WebRTC
/// session the worker belongs to; the reply carries the file session id.
fn to_file_event(rtc_session_id: String, reply: FileReply) -> GatewayEvent {
    match reply {
        FileReply::Opened {
            session_id,
            kind,
            error,
        } => GatewayEvent::FileOpened {
            session_id: rtc_session_id,
            file_id: session_id,
            kind,
            error,
        },
        FileReply::Listed {
            session_id,
            path,
            entries,
            error,
        } => GatewayEvent::FileListed {
            session_id: rtc_session_id,
            file_id: session_id,
            path,
            entries,
            error,
        },
        FileReply::Statted {
            session_id,
            entry,
            error,
        } => GatewayEvent::FileStatted {
            session_id: rtc_session_id,
            file_id: session_id,
            entry,
            error,
        },
        FileReply::ReadChunk {
            session_id,
            stream_id,
            offset,
            data,
            final_block,
            error,
        } => GatewayEvent::FileChunk {
            session_id: rtc_session_id,
            file_id: session_id,
            stream_id,
            offset,
            data,
            final_block,
            error,
        },
        FileReply::WriteAck {
            session_id,
            stream_id,
            received,
            error,
        } => GatewayEvent::FileWriteAck {
            session_id: rtc_session_id,
            file_id: session_id,
            stream_id,
            received,
            error,
        },
        FileReply::OpDone {
            session_id,
            op,
            path,
            error,
        } => GatewayEvent::FileOpDone {
            session_id: rtc_session_id,
            file_id: session_id,
            op,
            path,
            error,
        },
        FileReply::Closed { session_id, reason } => GatewayEvent::FileClosed {
            session_id: rtc_session_id,
            file_id: session_id,
            reason,
        },
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
    // Then idle file sessions, on the file module's own timeout (REQ-005).
    let file_timeout = shared.cfg.files.idle_timeout();
    for sess in sessions.values_mut() {
        let idle: Vec<String> = sess
            .file_sessions
            .iter()
            .filter(|(_, b)| now.duration_since(b.last_activity) >= file_timeout)
            .map(|(id, _)| id.clone())
            .collect();
        for file_id in idle {
            tracing::debug!("file session {file_id} idle timeout");
            close_file_session(sess, &file_id, "idle timeout");
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
        GatewayEvent::FileOpened {
            session_id,
            file_id,
            kind,
            error,
        } => {
            if let Some(sess) = sessions.get_mut(&session_id) {
                if error.is_some() {
                    // The backend never came up: drop the bridge so it does not
                    // linger until the idle timeout.
                    sess.file_sessions.remove(&file_id);
                    sess.file_streams.retain(|_, owner| *owner != file_id);
                }
                let status = if error.is_none() { "ok" } else { "error" };
                sess.send(&NodeMessage::FileOpenAck {
                    session_id: file_id,
                    kind,
                    status: status.to_string(),
                    error,
                    chunk_bytes: shared.cfg.files.chunk_bytes as u32,
                    roots: shared
                        .cfg
                        .files
                        .roots
                        .iter()
                        .map(|r| r.name.clone())
                        .collect(),
                });
            }
        }
        GatewayEvent::FileListed {
            session_id,
            file_id,
            path,
            entries,
            error,
        } => {
            if let Some(sess) = sessions.get_mut(&session_id) {
                touch_file(sess, &file_id);
                sess.send(&NodeMessage::FileListAck {
                    session_id: file_id,
                    path,
                    entries,
                    error,
                });
            }
        }
        GatewayEvent::FileStatted {
            session_id,
            file_id,
            entry,
            error,
        } => {
            if let Some(sess) = sessions.get_mut(&session_id) {
                touch_file(sess, &file_id);
                sess.send(&NodeMessage::FileStatAck {
                    session_id: file_id,
                    entry,
                    error,
                });
            }
        }
        GatewayEvent::FileChunk {
            session_id,
            file_id,
            stream_id,
            offset,
            data,
            final_block,
            error,
        } => {
            if let Some(sess) = sessions.get_mut(&session_id) {
                touch_file(sess, &file_id);
                match error {
                    Some(e) => sess.send(&NodeMessage::FileOpAck {
                        session_id: file_id,
                        op: "read".into(),
                        path: String::new(),
                        ok: false,
                        error: Some(e),
                    }),
                    None => sess.send_file(encode_frame(
                        FRAME_READ_CHUNK,
                        stream_id,
                        offset,
                        final_block,
                        &data,
                    )),
                }
            }
        }
        GatewayEvent::FileWriteAck {
            session_id,
            file_id,
            stream_id,
            received,
            error,
        } => {
            if let Some(sess) = sessions.get_mut(&session_id) {
                touch_file(sess, &file_id);
                sess.send(&NodeMessage::FileWriteAck {
                    session_id: file_id,
                    stream_id,
                    received,
                    error,
                });
            }
        }
        GatewayEvent::FileOpDone {
            session_id,
            file_id,
            op,
            path,
            error,
        } => {
            if let Some(sess) = sessions.get_mut(&session_id) {
                touch_file(sess, &file_id);
                let ok = error.is_none();
                sess.send(&NodeMessage::FileOpAck {
                    session_id: file_id,
                    op,
                    path,
                    ok,
                    error,
                });
            }
        }
        GatewayEvent::FileClosed {
            session_id,
            file_id,
            reason,
        } => {
            if let Some(sess) = sessions.get_mut(&session_id) {
                // Only report a close the gateway has not already reported.
                if sess.file_sessions.remove(&file_id).is_some() {
                    sess.file_streams.retain(|_, owner| *owner != file_id);
                    sess.send(&NodeMessage::FileClosed {
                        session_id: file_id,
                        reason,
                    });
                }
            }
        }
    }
}

/// Keep a file session's idle timer fresh after worker activity.
fn touch_file(sess: &mut Session, file_id: &str) {
    if let Some(bridge) = sess.file_sessions.get_mut(file_id) {
        bridge.last_activity = Instant::now();
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
    // G11: advertise exactly the addresses the shared socket can receive on —
    // the single bound address for a concrete `listen_addr`, or every routable
    // interface address when it is unspecified (multi-homed hosts: LAN + mesh,
    // so ICE can try each path).
    let mut added = 0;
    for ip in &shared.host_candidate_ips {
        if let Ok(candidate) = Candidate::host(std::net::SocketAddr::new(*ip, udp_port), "udp") {
            rtc.add_local_candidate(candidate);
            added += 1;
        }
    }
    // Defensive fallback: never answer an offer with no host candidate at all.
    if added == 0 {
        let fallback = if udp_addr.ip().is_unspecified() {
            std::net::SocketAddr::new(loopback_for(udp_addr.ip()), udp_port)
        } else {
            udp_addr
        };
        let candidate = Candidate::host(fallback, "udp")
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

#[cfg(test)]
mod tests {
    use super::*;

    /// G11: a concrete `listen_addr` binds that address, so the socket can only
    /// receive datagrams addressed to it — it must be the only host candidate.
    /// Advertising this host's other interface IPs here is precisely the bug
    /// that made every ICE connection time out on loopback-bound gateways.
    #[test]
    fn concrete_listen_addr_advertises_only_the_bound_address() {
        for listen in ["127.0.0.1", "192.168.7.13", "10.144.144.4"] {
            let ip: std::net::IpAddr = listen.parse().expect("parse listen ip");
            let plan = ice_bind_plan(ip);
            assert_eq!(plan.bind_ip, ip, "{listen} must bind itself");
            assert_eq!(plan.candidate_ips, vec![ip], "{listen} candidate set");
            assert_eq!(plan.page_ip, ip, "{listen} page ip");
            assert!(!plan.no_routable_interface, "{listen} needs no warning");
        }
    }

    /// G11: an unspecified `listen_addr` is the one configuration where a socket
    /// receives on every interface, so it must bind the wildcard (not one derived
    /// interface IP) and advertise the routable interfaces rather than `0.0.0.0`
    /// itself. The page address stays concrete so browsers get a usable URL.
    #[test]
    fn unspecified_listen_addr_widens_bind_and_candidates() {
        let ip: std::net::IpAddr = "0.0.0.0".parse().expect("parse wildcard ip");
        let plan = ice_bind_plan(ip);

        assert!(
            plan.bind_ip.is_unspecified(),
            "wildcard bind is what makes multi-interface candidates reachable"
        );
        assert!(
            !plan.candidate_ips.is_empty(),
            "an offer must never be candidate-less"
        );
        assert!(
            !plan.candidate_ips.iter().any(|c| c.is_unspecified()),
            "0.0.0.0 leaked into candidates: {:?}",
            plan.candidate_ips
        );
        assert!(
            !plan.page_ip.is_unspecified(),
            "page_addr must be browser-openable, got {}",
            plan.page_ip
        );
        if !plan.no_routable_interface {
            assert!(
                plan.candidate_ips.iter().all(|c| !c.is_loopback()),
                "loopback candidate offered on a routable host: {:?}",
                plan.candidate_ips
            );
        }
    }
}

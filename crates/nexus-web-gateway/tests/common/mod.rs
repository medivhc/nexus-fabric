//! Test helpers: a browser-like WebRTC peer driven over a real UDP socket,
//! connecting to the gateway through WSS signaling (pinned to the gateway's
//! self-signed CA certificate), plus a real `sshd` subprocess for SSH tests.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use rustls::StreamOwned;
use rustls::pki_types::{CertificateDer, ServerName};
use str0m::channel::{ChannelData, ChannelId};
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, Input, Output, Rtc, RtcError};
use tungstenite::client::IntoClientRequest;
use tungstenite::protocol::WebSocketConfig;

use nexus_web_gateway::protocol::{BrowserMessage, NodeMessage, SdpPayload};

/// A WebSocket over a rustls client stream (WSS).
pub type WssClient = tungstenite::WebSocket<StreamOwned<rustls::ClientConnection, TcpStream>>;

/// Connect a WSS client to `url`, trusting `cert_der` as the only root.
pub fn connect_wss(cert_der: &[u8], url: &str) -> Result<WssClient, Box<dyn std::error::Error>> {
    let cert = CertificateDer::from(cert_der.to_vec());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();

    let request = url.into_client_request()?;
    let host = request.uri().host().ok_or("url has no host")?.to_string();
    let port = request.uri().port_u16().ok_or("url has no port")?;
    let tcp = TcpStream::connect((host.as_str(), port))?;
    let sni = ServerName::try_from(host)?;
    let conn = rustls::ClientConnection::new(Arc::new(config), sni)?;
    let tls = StreamOwned::new(conn, tcp);
    let (ws, _) =
        tungstenite::client::client_with_config(request, tls, Some(WebSocketConfig::default()))?;
    Ok(ws)
}

/// Read the next text message from a WSS client.
pub fn read_ws_json(ws: &mut WssClient) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    loop {
        match ws.read()? {
            tungstenite::Message::Text(t) => {
                return Ok(serde_json::from_str(&t)?);
            }
            tungstenite::Message::Close(_) => {
                return Err("websocket closed".into());
            }
            _ => continue,
        }
    }
}

static SSHD_COUNTER: AtomicUsize = AtomicUsize::new(0);
/// Serializes test-sshd spawns so the bind-drop-bind port reservation cannot
/// collide between concurrently running tests in the same process.
static SSHD_SPAWN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A real OpenSSH server running on a loopback high port with a generated host
/// key and an `authorized_keys` file for the caller's generated client key.
///
/// This lets the gateway's node-side SSH client be tested against a real sshd
/// (no mock): the full SSH handshake, authentication and pty/shell all run.
pub struct TestSshd {
    pub addr: SocketAddr,
    pub client_key_pem: String,
    dir: PathBuf,
    child: Child,
}

impl TestSshd {
    /// Spawn a real `sshd` on a loopback high port.
    pub fn spawn() -> Result<Self, Box<dyn std::error::Error>> {
        // Hold the lock for the whole spawn: the port is reserved by binding
        // then releasing a listener, so a concurrent spawner could otherwise
        // grab the same port before sshd binds it.
        let _guard = SSHD_SPAWN_LOCK.lock().expect("sshd spawn lock");
        let sshd_bin = which_sshd().ok_or_else(|| {
            "sshd binary not found; install openssh-server to run SSH gateway tests".to_string()
        })?;
        let ssh_keygen = which_ssh_keygen().ok_or_else(|| {
            "ssh-keygen binary not found; install openssh-client to run SSH gateway tests"
                .to_string()
        })?;

        let seq = SSHD_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "nexus-web-gateway-sshd-{}-{}",
            std::process::id(),
            seq
        ));
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }
        std::fs::create_dir_all(&dir)?;

        let host_key = dir.join("hostkey");
        run_command(
            ssh_keygen.to_str().unwrap(),
            &[
                "-t",
                "ed25519",
                "-f",
                host_key.to_str().unwrap(),
                "-N",
                "",
                "-q",
            ],
        )?;

        let client_key = dir.join("client_key");
        run_command(
            ssh_keygen.to_str().unwrap(),
            &[
                "-t",
                "ed25519",
                "-f",
                client_key.to_str().unwrap(),
                "-N",
                "",
                "-q",
            ],
        )?;

        let authorized_keys = dir.join("authorized_keys");
        std::fs::copy(client_key.with_extension("pub"), &authorized_keys)?;

        let port = reserve_loopback_port();
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;
        let user = whoami();
        let config_path = dir.join("sshd_config");
        let config = format!(
            "Port {port}\n\
             ListenAddress 127.0.0.1\n\
             HostKey {host_key}\n\
             PidFile {pid}\n\
             UsePAM no\n\
             PasswordAuthentication yes\n\
             KbdInteractiveAuthentication no\n\
             PubkeyAuthentication yes\n\
             StrictModes no\n\
             AuthorizedKeysFile {authorized_keys}\n\
             PermitRootLogin no\n\
             AllowUsers {user}\n\
             UseDNS no\n\
             Subsystem sftp internal-sftp\n\
             LogLevel VERBOSE\n",
            host_key = host_key.display(),
            pid = dir.join("sshd.pid").display(),
            authorized_keys = authorized_keys.display(),
        );
        std::fs::write(&config_path, config)?;

        let mut child = Command::new(&sshd_bin)
            .args(["-D", "-e", "-f", config_path.to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        // Wait for the port to accept connections.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
                break;
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                return Err("timed out waiting for test sshd to listen".into());
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        let client_key_pem = std::fs::read_to_string(&client_key)?;
        Ok(Self {
            addr,
            client_key_pem,
            dir,
            child,
        })
    }

    /// `SshAuth::Key` value for this sshd's generated client key.
    pub fn key_auth(&self) -> nexus_web_gateway::protocol::SshAuth {
        nexus_web_gateway::protocol::SshAuth::Key {
            username: whoami(),
            private_key: self.client_key_pem.clone(),
        }
    }
}

impl Drop for TestSshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn which_sshd() -> Option<PathBuf> {
    for p in std::env::split_paths(&std::env::var_os("PATH")?) {
        let cand = p.join("sshd");
        if cand.is_file() {
            return Some(cand);
        }
        let cand = p.join("sshd.exe");
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

fn which_ssh_keygen() -> Option<PathBuf> {
    for p in std::env::split_paths(&std::env::var_os("PATH")?) {
        let cand = p.join("ssh-keygen");
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

fn run_command(bin: &str, args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new(bin)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(format!("{bin} exited with {status:?}").into());
    }
    Ok(())
}

fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "root".to_string())
}

/// Reserve a loopback TCP port by binding then releasing a listener.
fn reserve_loopback_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = l.local_addr().expect("local addr").port();
    drop(l);
    port
}

/// A browser-side WebRTC peer (offerer) with its own UDP socket.
pub struct BrowserPeer {
    pub node_id: String,
    pub peer_id: String,
    pub rtc: Rtc,
    pub udp: UdpSocket,
    pub channel: Option<ChannelId>,
    /// The binary file DataChannel (`nexus.file`), when this peer offered one.
    pub file_channel: Option<ChannelId>,
    pub last: Instant,
    pub connected: bool,
    pub messages: Vec<NodeMessage>,
    /// Binary frames received on the file channel, in arrival order.
    pub binary_frames: Vec<Vec<u8>>,
    /// UDP packets received from the gateway but not yet fed to str0m.
    pending_recv: VecDeque<(SocketAddr, Vec<u8>)>,
}

impl BrowserPeer {
    pub fn new(node_id: String, peer_id: String, rtc: Rtc, udp: UdpSocket) -> Self {
        Self {
            node_id,
            peer_id,
            rtc,
            udp,
            channel: None,
            file_channel: None,
            last: Instant::now(),
            connected: false,
            messages: Vec::new(),
            binary_frames: Vec::new(),
            pending_recv: VecDeque::new(),
        }
    }

    /// Send a binary frame over the file DataChannel.
    pub fn send_file_frame(&mut self, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let cid = self
            .file_channel
            .ok_or_else(|| -> Box<dyn std::error::Error> { "no file channel open".into() })?;
        let mut ch = self
            .rtc
            .channel(cid)
            .ok_or_else(|| -> Box<dyn std::error::Error> { "file channel gone".into() })?;
        let _ = ch.write(true, bytes)?;
        Ok(())
    }

    /// Pop the first received binary frame satisfying `predicate`.
    pub fn take_binary_frame(&mut self, predicate: impl Fn(&[u8]) -> bool) -> Option<Vec<u8>> {
        let idx = self.binary_frames.iter().position(|f| predicate(f));
        idx.map(|i| self.binary_frames.remove(i))
    }

    /// Send a browser message over the control DataChannel.
    pub fn send(&mut self, msg: &BrowserMessage) -> Result<(), Box<dyn std::error::Error>> {
        let Some(cid) = self.channel else {
            return Err("no control channel open".into());
        };
        let bytes = serde_json::to_vec(msg)?;
        let mut ch = self
            .rtc
            .channel(cid)
            .ok_or_else(|| -> Box<dyn std::error::Error> { "channel gone".into() })?;
        let _ = ch.write(false, &bytes)?;
        Ok(())
    }

    /// Pop the next node message of the given variant kind from the inbox.
    pub fn take_message(
        &mut self,
        predicate: impl Fn(&NodeMessage) -> bool,
    ) -> Option<NodeMessage> {
        let idx = self.messages.iter().position(predicate);
        idx.map(|i| self.messages.remove(i))
    }

    /// Drive the peer: poll outputs, read UDP, advance time.
    pub fn progress(&mut self) -> Result<(), RtcError> {
        // Poll outputs until the next timeout.
        loop {
            if !self.rtc.is_alive() {
                return Ok(());
            }
            match self.rtc.poll_output()? {
                Output::Timeout(t) => {
                    self.last = t;
                    break;
                }
                Output::Transmit(t) => {
                    let _ = self.udp.send_to(&t.contents, t.destination);
                }
                Output::Event(e) => self.handle_event(e),
            }
        }

        // Read any pending UDP datagrams.
        self.udp
            .set_read_timeout(Some(Duration::from_millis(1)))
            .ok();
        let mut buf = [0u8; 2048];
        while let Ok((n, src)) = self.udp.recv_from(&mut buf) {
            self.pending_recv.push_back((src, buf[..n].to_vec()));
            self.udp
                .set_read_timeout(Some(Duration::from_millis(1)))
                .ok();
        }

        // Feed received datagrams to the Rtc.
        let now = Instant::now();
        while let Some((src, data)) = self.pending_recv.pop_front() {
            if let Ok(receive) =
                Receive::new(Protocol::Udp, src, self.udp.local_addr().unwrap(), &data)
            {
                let _ = self.rtc.handle_input(Input::Receive(now, receive));
            }
        }

        // Advance time.
        let _ = self.rtc.handle_input(Input::Timeout(now));
        Ok(())
    }

    fn handle_event(&mut self, event: Event) {
        match event {
            Event::ChannelOpen(cid, label) => {
                if label == nexus_web_gateway::file::FILE_CHANNEL_LABEL {
                    self.file_channel = Some(cid);
                } else {
                    self.channel = Some(cid);
                    // Announce the browser's temporary identity on the control
                    // channel only.
                    let _ = self.send(&BrowserMessage::Hello {
                        peer_id: self.peer_id.clone(),
                        name: "test-browser".into(),
                    });
                }
                self.connected = true;
            }
            Event::ChannelData(data) => self.handle_channel_data(&data),
            Event::IceConnectionStateChange(state) if state.is_connected() => {
                self.connected = true;
            }
            _ => {}
        }
    }

    fn handle_channel_data(&mut self, data: &ChannelData) {
        if data.binary {
            self.binary_frames.push(data.data.to_vec());
            return;
        }
        if let Ok(msg) = serde_json::from_slice::<NodeMessage>(&data.data) {
            self.messages.push(msg);
        }
    }
}

/// A minimal browser: one WSS signaling connection + one or more WebRTC peers.
pub struct Browser {
    pub session_id: String,
    pub peer_id: String,
    pub ws: WssClient,
    pub peers: Vec<BrowserPeer>,
    /// Raw SDP of the answer to the first offer, so tests can assert on the
    /// advertised ICE candidates.
    pub answer_sdp: String,
}

impl Browser {
    /// Create a browser and join `node_id` via WSS at `addr`.
    pub fn connect_first(
        cert_der: &[u8],
        addr: SocketAddr,
        node_id: &str,
        session_id: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let url = format!("wss://{addr}/ws");
        let mut ws = connect_wss(cert_der, &url)?;

        let peer_id = "test-browser-0123456789abcdef";
        let (mut rtc, udp, offer, pending) = create_rtc_with_channel()?;
        let sdp = SdpPayload {
            kind: "offer".into(),
            sdp: offer.to_sdp_string(),
        };
        ws.send(tungstenite::Message::Text(serde_json::to_string(
            &serde_json::json!({
                "type": "offer",
                "session_id": session_id,
                "peer_id": peer_id,
                "name": "test-browser",
                "sdp": sdp,
            }),
        )?))?;

        let answer_msg = read_ws_json(&mut ws)?;
        let answer_payload: SdpPayload =
            serde_json::from_value(answer_msg.get("sdp").ok_or("answer missing sdp")?.clone())?;
        let answer_sdp = answer_payload.sdp.clone();
        let answer = answer_payload.to_answer().map_err(|e| e.to_string())?;
        rtc.sdp_api().accept_answer(pending, answer)?;

        let peer = BrowserPeer::new(node_id.to_string(), peer_id.to_string(), rtc, udp);

        Ok(Self {
            session_id: session_id.to_string(),
            peer_id: peer_id.to_string(),
            ws,
            peers: vec![peer],
            answer_sdp,
        })
    }

    /// Connect to another node by relaying an offer through the first node.
    pub fn connect_node(
        &mut self,
        target_node_id: &str,
        node_id_for_peer: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut rtc, udp, offer, pending) = create_rtc_with_channel()?;
        let sdp = SdpPayload {
            kind: "offer".into(),
            sdp: offer.to_sdp_string(),
        };
        // Send the relay offer over the first peer's control channel.
        self.peers[0].send(&BrowserMessage::RelayOffer {
            target: target_node_id.to_string(),
            session_id: self.session_id.clone(),
            sdp,
        })?;

        // Drive until the relay answer arrives.
        let relay_answer = loop {
            self.drive_all(Duration::from_millis(50))?;
            if let Some(NodeMessage::RelayAnswer { sdp, .. }) =
                self.peers[0].take_message(|m| matches!(m, NodeMessage::RelayAnswer { .. }))
            {
                break sdp;
            }
        };

        let answer = relay_answer.to_answer().map_err(|e| e.to_string())?;
        rtc.sdp_api().accept_answer(pending, answer)?;
        self.peers.push(BrowserPeer::new(
            node_id_for_peer.to_string(),
            self.peer_id.clone(),
            rtc,
            udp,
        ));
        Ok(())
    }

    /// Drive all peers for `duration`.
    pub fn drive_all(&mut self, duration: Duration) -> Result<(), RtcError> {
        let start = Instant::now();
        while Instant::now().duration_since(start) < duration {
            for peer in &mut self.peers {
                peer.progress()?;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        Ok(())
    }
}

/// Create a browser-side Rtc with a control DataChannel, a file DataChannel and
/// a host candidate.
pub fn create_rtc_with_channel() -> Result<
    (
        Rtc,
        UdpSocket,
        str0m::change::SdpOffer,
        str0m::change::SdpPendingOffer,
    ),
    Box<dyn std::error::Error>,
> {
    let udp = UdpSocket::bind("127.0.0.1:0")?;
    let udp_addr = udp.local_addr()?;
    let now = Instant::now();
    let mut rtc = Rtc::builder().build(now);
    let candidate = Candidate::host(udp_addr, "udp").map_err(|e| format!("host candidate: {e}"))?;
    rtc.add_local_candidate(candidate);

    let mut changes = rtc.sdp_api();
    changes.add_channel("control".into());
    // The binary channel must be offered in the same SDP: the gateway does not
    // support renegotiation, so a second offer later would be rejected.
    changes.add_channel(nexus_web_gateway::file::FILE_CHANNEL_LABEL.into());
    let (offer, pending) = changes.apply().ok_or("failed to apply channel offer")?;
    Ok((rtc, udp, offer, pending))
}

//! Test helpers: a browser-like WebRTC peer driven over a real UDP socket,
//! connecting to the gateway through WSS signaling (pinned to the gateway's
//! self-signed CA certificate).

#![allow(dead_code)]

use std::collections::VecDeque;
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::StreamOwned;
use str0m::channel::{ChannelData, ChannelId};
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, Input, Output, Rtc, RtcError};
use tungstenite::client::IntoClientRequest;
use tungstenite::protocol::WebSocketConfig;

use nexus_web_gateway::protocol::{BrowserMessage, NodeMessage, SdpPayload};

/// A WebSocket over a rustls client stream (WSS).
pub type WssClient =
    tungstenite::WebSocket<StreamOwned<rustls::ClientConnection, TcpStream>>;

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
    let host = request
        .uri()
        .host()
        .ok_or("url has no host")?
        .to_string();
    let port = request.uri().port_u16().ok_or("url has no port")?;
    let tcp = TcpStream::connect((host.as_str(), port))?;
    let sni = ServerName::try_from(host)?;
    let conn = rustls::ClientConnection::new(Arc::new(config), sni)?;
    let tls = StreamOwned::new(conn, tcp);
    let (ws, _) = tungstenite::client::client_with_config(
        request,
        tls,
        Some(WebSocketConfig::default()),
    )?;
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

/// A browser-side WebRTC peer (offerer) with its own UDP socket.
pub struct BrowserPeer {
    pub node_id: String,
    pub peer_id: String,
    pub rtc: Rtc,
    pub udp: UdpSocket,
    pub channel: Option<ChannelId>,
    pub last: Instant,
    pub connected: bool,
    pub messages: Vec<NodeMessage>,
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
            last: Instant::now(),
            connected: false,
            messages: Vec::new(),
            pending_recv: VecDeque::new(),
        }
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
    pub fn take_message(&mut self, predicate: impl Fn(&NodeMessage) -> bool) -> Option<NodeMessage> {
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
            self.pending_recv
                .push_back((src, buf[..n].to_vec()));
            self.udp
                .set_read_timeout(Some(Duration::from_millis(1)))
                .ok();
        }

        // Feed received datagrams to the Rtc.
        let now = Instant::now();
        while let Some((src, data)) = self.pending_recv.pop_front() {
            if let Ok(receive) = Receive::new(
                Protocol::Udp,
                src,
                self.udp.local_addr().unwrap(),
                &data,
            ) {
                let _ = self.rtc.handle_input(Input::Receive(now, receive));
            }
        }

        // Advance time.
        let _ = self.rtc.handle_input(Input::Timeout(now));
        Ok(())
    }

    fn handle_event(&mut self, event: Event) {
        match event {
            Event::ChannelOpen(cid, _) => {
                self.channel = Some(cid);
                self.connected = true;
                // Announce the browser's temporary identity.
                let _ = self.send(&BrowserMessage::Hello {
                    peer_id: self.peer_id.clone(),
                    name: "test-browser".into(),
                });
            }
            Event::ChannelData(data) => self.handle_channel_data(&data),
            Event::IceConnectionStateChange(state) => {
                if state.is_connected() {
                    self.connected = true;
                }
            }
            _ => {}
        }
    }

    fn handle_channel_data(&mut self, data: &ChannelData) {
        if data.binary {
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
        ws.send(tungstenite::Message::Text(
            serde_json::to_string(&serde_json::json!({
                "type": "offer",
                "session_id": session_id,
                "peer_id": peer_id,
                "name": "test-browser",
                "sdp": sdp,
            }))?,
        ))?;

        let answer_msg = read_ws_json(&mut ws)?;
        let answer_sdp: SdpPayload = serde_json::from_value(
            answer_msg
                .get("sdp")
                .ok_or("answer missing sdp")?
                .clone(),
        )?;
        let answer = answer_sdp.to_answer().map_err(|e| e.to_string())?;
        rtc.sdp_api().accept_answer(pending, answer)?;

        let peer = BrowserPeer::new(node_id.to_string(), peer_id.to_string(), rtc, udp);

        Ok(Self {
            session_id: session_id.to_string(),
            peer_id: peer_id.to_string(),
            ws,
            peers: vec![peer],
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

/// Create a browser-side Rtc with a control DataChannel and a host candidate.
fn create_rtc_with_channel() -> Result<(Rtc, UdpSocket, str0m::change::SdpOffer, str0m::change::SdpPendingOffer), Box<dyn std::error::Error>> {
    let udp = UdpSocket::bind("127.0.0.1:0")?;
    let udp_addr = udp.local_addr()?;
    let now = Instant::now();
    let mut rtc = Rtc::builder().build(now);
    let candidate = Candidate::host(udp_addr, "udp")
        .map_err(|e| format!("host candidate: {e}"))?;
    rtc.add_local_candidate(candidate);

    let mut changes = rtc.sdp_api();
    changes.add_channel("control".into());
    let (offer, pending) = changes
        .apply()
        .ok_or("failed to apply channel offer")?;
    Ok((rtc, udp, offer, pending))
}
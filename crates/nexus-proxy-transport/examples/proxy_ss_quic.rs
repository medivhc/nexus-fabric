//! E4: product.proxy-transport-ss (T1/T3/T6).
//!
//! Minimal ss server S on 127.0.0.1:0. Like a real ss proxy, S *terminates*
//! the **SIP004** AEAD session: streaming `open` (Server role) →
//! `parse_request` → target; replies a sealed `b"ss-proxy-ok"` chunk (the
//! first write carries S's salt); then relays the decrypted framed bytes
//! A↔B (A→B: open+forward; B→A: seal+write).
//!
//! B listens on TCP 127.0.0.1:0, wraps accepted streams in the plain
//! [`FramedTransport`] (the S↔B leg is decrypted framed bytes), serves QUIC
//! via `bind_with_transport`. A does the ss handshake (via S) to B's TCP
//! port, builds QUIC via `connect_with_transport` with [`SsTransport`],
//! sends 64KB on a bi stream, B echoes. PASS requires full roundtrip **and**
//! `proxy_relayed_bytes > 0` (traffic really went through the proxy,
//! T1/T6) **and** `proxy_saw_plaintext_bytes == 0` (S only ever saw AEAD
//! records and QUIC ciphertext, T3/X2).
//!
//! TCP-only: no UDP involved, runs anywhere loopback TCP works.
//! B thread waits for A's confirmation before dropping its FabricConn
//! (4b lesson: premature drop shuts down the driver and loses echo data).

use nexus_fabric::{ConnConfig, FabricConn, FabricListener, PeerId};
use nexus_outbound_shadowsocks::{parse_request, Role, SsStream, SsTarget};
use nexus_proxy_transport::{
    FramedTransport, SsMethod, SsProxyConfig, SsTransport, MAX_SEALED_FRAME,
};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    mpsc, Arc, Mutex,
};
use std::thread;
use std::time::Duration;

const N: usize = 65536;
const SS_ACK: &[u8] = b"ss-proxy-ok";
const PASSWORD: &str = "e4-ss-password";

/// Distinctive 64-byte pattern from the payload (for the X2 plaintext scan).
fn marker() -> Vec<u8> {
    payload()[1000..1064].to_vec()
}

fn payload() -> Vec<u8> {
    (0..N as u32).map(|i| (i % 251) as u8).collect()
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Minimal ss server: handshake → relay decrypted framed bytes.
/// Counts relayed bytes and scans for plaintext payload (T3/X2).
struct SsServer {
    listener: TcpListener,
    relayed_bytes: Arc<AtomicU64>,
    saw_plaintext: Arc<AtomicU64>,
}

impl SsServer {
    fn bind() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        Ok(Self {
            listener,
            relayed_bytes: Arc::new(AtomicU64::new(0)),
            saw_plaintext: Arc::new(AtomicU64::new(0)),
        })
    }

    fn addr(&self) -> SocketAddr {
        self.listener.local_addr().unwrap()
    }

    /// Serve exactly one ss session then relay until EOF.
    fn serve_once(&self, marker: Vec<u8>) -> std::io::Result<()> {
        let (mut a, _) = self.listener.accept()?;
        a.set_read_timeout(Some(Duration::from_secs(30)))?;

        // Handshake: open the sealed target frame (Server role).
        let mut session = SsStream::new(PASSWORD, SsMethod::Chacha20IetfPoly1305, Role::Server)
            .map_err(|e| std::io::Error::other(format!("ss server session: {e}")))?;
        // Streaming handshake: one read may carry only part of the salt/chunk.
        let mut hs_buf = [0u8; 4096];
        let plain = loop {
            let n = a.read(&mut hs_buf)?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "ss handshake eof",
                ));
            }
            let plain = session.open(&hs_buf[..n]).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, format!("ss open: {e}"))
            })?;
            if !plain.is_empty() {
                break plain;
            }
        };
        let target = parse_request(&plain).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("ss target: {e}"))
        })?;
        let target_sa: SocketAddr = match target {
            SsTarget::Ipv4(oct, port) => SocketAddr::from((oct, port)),
            SsTarget::Domain(_, _) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "e4 ss server: domain target not supported",
                ))
            }
        };
        a.write_all(
            &session
                .seal(SS_ACK)
                .map_err(|e| std::io::Error::other(format!("ss seal ack: {e}")))?,
        )?;

        // Connect to target (B).
        let b = TcpStream::connect(target_sa)?;
        b.set_read_timeout(Some(Duration::from_secs(30)))?;

        // Relay: A→B decrypts records to framed bytes; B→A seals frames.
        // open/seal take &mut self → share the session behind a Mutex.
        let session = Arc::new(Mutex::new(session));
        let mut a2 = a.try_clone()?;
        let mut b2 = b.try_clone()?;
        // Shutdown handles: when either direction ends, tear down the whole
        // session promptly (don't leave the other thread parked in a 30s
        // read timeout — that stalls server_thread.join() and lets the QUIC
        // driver spin on EOF).
        let a_sd = a.try_clone()?;
        let b_sd = b.try_clone()?;
        let relayed = self.relayed_bytes.clone();
        let saw = self.saw_plaintext.clone();
        let m = marker.clone();
        let sess = session.clone();
        let t1 = thread::spawn(move || relay_a_to_b(&mut a2, &mut b2, &sess, &relayed, &saw, &m));
        let relayed2 = self.relayed_bytes.clone();
        let t2 = thread::spawn(move || {
            let mut a = a;
            let mut b = b;
            relay_b_to_a(&mut b, &mut a, &session, &relayed2)
        });
        // Wait for either direction to finish, then shut the session down.
        loop {
            if t1.is_finished() || t2.is_finished() {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        let _ = a_sd.shutdown(std::net::Shutdown::Both);
        let _ = b_sd.shutdown(std::net::Shutdown::Both);
        let _ = t1.join();
        let _ = t2.join();
        Ok(())
    }
}

/// A→B: read 2-byte-framed sealed datagram → open → scan marker (X2) →
/// forward the decrypted framed bytes.
/// NOTE: the handshake is streamed SIP004 (no u32 record header); the data
/// path layers the shared 2-byte framing (T4) on top of sealed chunks.
fn relay_a_to_b(
    a: &mut TcpStream,
    b: &mut TcpStream,
    session: &Mutex<SsStream>,
    relayed: &AtomicU64,
    saw: &AtomicU64,
    marker: &[u8],
) {
    let mut tail: Vec<u8> = Vec::new();
    while let Ok(sealed) = read_sealed(a) {
        let plain = match session.lock().unwrap().open(&sealed) {
            Ok(p) => p,
            Err(_) => break,
        };
        // Empty is legal for a streaming decoder (partial logical chunk);
        // never write a 0-length framed datagram downstream.
        if plain.is_empty() {
            continue;
        }
        relayed.fetch_add(plain.len() as u64, Ordering::Relaxed);
        let mut window = std::mem::take(&mut tail);
        window.extend_from_slice(&plain);
        if window.windows(marker.len()).any(|w| w == marker) {
            saw.fetch_add(1, Ordering::Relaxed);
        }
        let keep = window.len().saturating_sub(marker.len() - 1);
        tail = window[keep..].to_vec();
        // S terminates the ss session: re-frame the decrypted QUIC datagram
        // for the plain S<->B leg (B speaks 2-byte framing).
        if b.write_all(&(plain.len() as u16).to_be_bytes()).is_err() {
            break;
        }
        if b.write_all(&plain).is_err() {
            break;
        }
    }
}

/// Read one 2-byte-framed sealed datagram (the ss data path, T4).
fn read_sealed(r: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut hdr = [0u8; 2];
    r.read_exact(&mut hdr)?;
    let len = u16::from_be_bytes(hdr) as usize;
    if len > MAX_SEALED_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "sealed frame too large",
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Read one 2-byte-framed datagram (B speaks plain framing).
fn read_frame(r: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut hdr = [0u8; 2];
    r.read_exact(&mut hdr)?;
    let len = u16::from_be_bytes(hdr) as usize;
    if len > 1200 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// B→A: read framed datagram → seal → write 2-byte-framed sealed record.
fn relay_b_to_a(
    b: &mut TcpStream,
    a: &mut TcpStream,
    session: &Mutex<SsStream>,
    relayed: &AtomicU64,
) {
    while let Ok(frame) = read_frame(b) {
        let sealed = match session.lock().unwrap().seal(&frame) {
            Ok(s) => s,
            Err(_) => break,
        };
        relayed.fetch_add(frame.len() as u64, Ordering::Relaxed);
        if a.write_all(&(sealed.len() as u16).to_be_bytes()).is_err() {
            break;
        }
        if a.write_all(&sealed).is_err() {
            break;
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let _json = args.iter().any(|a| a == "--json");
    let (json, pass) = match run() {
        Ok(x) => x,
        Err(e) => (
            format!("{{\"verdict\":\"FAIL\",\"detail\":\"{}\"}}", esc(&e)),
            false,
        ),
    };
    println!("{json}");
    if !pass {
        std::process::exit(1);
    }
}

fn run() -> Result<(String, bool), String> {
    // 1. ss server.
    let server = SsServer::bind().map_err(|e| format!("ss bind: {e}"))?;
    let proxy_addr = server.addr();
    let relayed = server.relayed_bytes.clone();
    let saw = server.saw_plaintext.clone();
    let marker_bytes = marker();
    let server_thread = thread::spawn(move || server.serve_once(marker_bytes));

    // 2. B: TCP listener for the decrypted leg.
    let b_listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("B bind: {e}"))?;
    let b_tcp_addr = b_listener
        .local_addr()
        .map_err(|e| format!("B addr: {e}"))?;

    // B thread: TCP accept → plain FramedTransport → QUIC listener → echo → wait.
    let (peer_tx, peer_rx) = mpsc::channel::<PeerId>();
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let b_thread = thread::spawn(move || -> Result<(), String> {
        let (stream, _) = b_listener.accept().map_err(|e| format!("B accept: {e}"))?;
        // The S↔B leg carries decrypted framed bytes: plain framing, no ss.
        let transport = FramedTransport::new(stream, b_tcp_addr);
        let listener = FabricListener::bind_with_transport(Box::new(transport))
            .map_err(|e| format!("B bind_with_transport: {e}"))?;
        peer_tx
            .send(listener.peer_id())
            .map_err(|_| "B: peer_id send failed".to_string())?;
        let conn = listener
            .accept()
            .map_err(|e| format!("B accept QUIC: {e}"))?;
        let (mut send, mut recv) = conn.accept_bi().map_err(|e| format!("B accept_bi: {e}"))?;
        let mut got = vec![0u8; N];
        let mut off = 0;
        while off < N {
            let n = recv
                .read(&mut got[off..])
                .map_err(|e| format!("B read: {e}"))?;
            if n == 0 {
                return Err("B: unexpected EOF".into());
            }
            off += n;
        }
        if got != payload() {
            return Err("B: payload mismatch".into());
        }
        let mut woff = 0;
        while woff < N {
            let n = send
                .write(&got[woff..])
                .map_err(|e| format!("B echo write: {e}"))?;
            woff += n;
        }
        send.finish().map_err(|e| format!("B finish: {e}"))?;
        // 4b lesson: wait for A's confirmation before dropping FabricConn.
        done_rx
            .recv_timeout(Duration::from_secs(30))
            .map_err(|_| "B: timeout waiting for A".to_string())?;
        Ok(())
    });

    // 3. A: ss handshake (triggers S→B so B's accept returns), then QUIC.
    let config = SsProxyConfig::new(
        proxy_addr,
        SsMethod::Chacha20IetfPoly1305,
        PASSWORD.to_string(),
    );
    let transport =
        SsTransport::connect(&config, b_tcp_addr).map_err(|e| format!("A ss connect: {e}"))?;
    let peer_b = peer_rx
        .recv_timeout(Duration::from_secs(30))
        .map_err(|_| "A: timeout waiting for B peer_id".to_string())?;
    // Clone the counters handle BEFORE the transport is moved into the driver.
    let counters = transport.counters_handle();
    let conn_config = ConnConfig {
        addrs: vec![b_tcp_addr],
        handshake_timeout: Duration::from_secs(20),
    };
    let conn = FabricConn::connect_with_transport(peer_b, &conn_config, Box::new(transport))
        .map_err(|e| format!("A QUIC connect: {e}"))?;
    let (mut send, mut recv) = conn.open_bi().map_err(|e| format!("A open_bi: {e}"))?;
    let data = payload();
    let mut woff = 0;
    while woff < N {
        let n = send
            .write(&data[woff..])
            .map_err(|e| format!("A write: {e}"))?;
        woff += n;
    }
    send.finish().map_err(|e| format!("A finish: {e}"))?;
    let mut echo = vec![0u8; N];
    let mut off = 0;
    while off < N {
        let n = recv
            .read(&mut echo[off..])
            .map_err(|e| format!("A read: {e}"))?;
        if n == 0 {
            return Err("A: unexpected EOF".into());
        }
        off += n;
    }
    let roundtrip_ok = echo == data;
    // Signal B to exit (4b lesson), then join.
    let _ = done_tx.send(());
    let b_res = b_thread
        .join()
        .map_err(|_| "B thread panicked".to_string())?;
    b_res?;
    // Stop our driver before joining the server: otherwise it keeps polling
    // recv_from and spins on EOF once the server tears the session down.
    drop(conn);
    let _ = server_thread.join();

    let relayed_bytes = relayed.load(Ordering::Relaxed);
    let saw_plaintext = saw.load(Ordering::Relaxed);
    let (t_ok, t_err, t_framed) = counters.get();
    let pass = roundtrip_ok && relayed_bytes > 0 && saw_plaintext == 0;
    let json = format!(
        "{{\"verdict\":\"{}\",\"roundtrip_ok\":{},\"proxy_relayed_bytes\":{},\
         \"proxy_saw_plaintext_bytes\":{},\"transport_counters\":{{\"handshake_ok\":{},\
         \"handshake_err\":{},\"framed_bytes\":{}}}}}",
        if pass { "PASS" } else { "FAIL" },
        roundtrip_ok,
        relayed_bytes,
        saw_plaintext,
        t_ok,
        t_err,
        t_framed,
    );
    Ok((json, pass))
}

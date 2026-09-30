//! E4: product.proxy-transport
//!
//! Minimal SOCKS5 server S on 127.0.0.1:0. B listens on TCP 127.0.0.1:0,
//! wraps accepted streams in `ProxyTransport`, serves QUIC via
//! `bind_with_transport`. A does SOCKS5 CONNECT (via S) to B's TCP port,
//! builds QUIC via `connect_with_transport`, sends 64KB on a bi stream,
//! B echoes. PASS requires full roundtrip **and**
//! `proxy_relayed_bytes > 0` (traffic really went through the proxy,
//! X1/X6) **and** `proxy_saw_plaintext_bytes == 0` (proxy only saw
//! ciphertext, X2).
//!
//! TCP-only: no UDP involved, runs anywhere loopback TCP works.
//! B thread waits for A's confirmation before dropping its FabricConn
//! (4b lesson: premature drop shuts down the driver and loses echo data).

use nexus_fabric::{ConnConfig, FabricConn, FabricListener, PeerId};
use nexus_proxy_transport::{ProxyTransport, Socks5ProxyConfig};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    mpsc, Arc,
};
use std::thread;
use std::time::Duration;

const N: usize = 65536;

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

/// Minimal SOCKS5 server: greeting → CONNECT → bidirectional TCP relay.
/// Counts relayed bytes and scans for plaintext payload (X2).
struct Socks5Server {
    listener: TcpListener,
    relayed_bytes: Arc<AtomicU64>,
    saw_plaintext: Arc<AtomicU64>,
}

impl Socks5Server {
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

    /// Serve exactly one CONNECT then relay until EOF.
    fn serve_once(&self, marker: Vec<u8>) -> std::io::Result<()> {
        let (mut client, _) = self.listener.accept()?;
        client.set_read_timeout(Some(Duration::from_secs(30)))?;

        // Greeting: 05 NMETHODS METHODS — choose 0x00 (no auth).
        let mut g = [0u8; 2];
        client.read_exact(&mut g)?;
        if g[0] != 0x05 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bad SOCKS version",
            ));
        }
        let mut methods = vec![0u8; g[1] as usize];
        client.read_exact(&mut methods)?;
        client.write_all(&[0x05, 0x00])?;

        // CONNECT request.
        let mut head = [0u8; 4];
        client.read_exact(&mut head)?;
        if head[0] != 0x05 || head[1] != 0x01 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "not a CONNECT",
            ));
        }
        let target: SocketAddr = match head[3] {
            0x01 => {
                let mut ip = [0u8; 4];
                client.read_exact(&mut ip)?;
                let mut port = [0u8; 2];
                client.read_exact(&mut port)?;
                SocketAddr::from((ip, u16::from_be_bytes(port)))
            }
            0x04 => {
                let mut ip = [0u8; 16];
                client.read_exact(&mut ip)?;
                let mut port = [0u8; 2];
                client.read_exact(&mut port)?;
                SocketAddr::from((ip, u16::from_be_bytes(port)))
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unsupported ATYP",
                ))
            }
        };

        // Connect to target and reply success.
        let upstream = TcpStream::connect(target)?;
        upstream.set_read_timeout(Some(Duration::from_secs(30)))?;
        client.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?;

        // Bidirectional relay with byte counting + plaintext scan (X2).
        let mut up_clone = upstream.try_clone()?;
        let mut cl_clone = client.try_clone()?;
        let relayed = self.relayed_bytes.clone();
        let saw = self.saw_plaintext.clone();
        let m = marker.clone();
        let t1 = thread::spawn(move || relay_one(&mut cl_clone, &mut up_clone, &relayed, &saw, &m));
        let relayed2 = self.relayed_bytes.clone();
        let saw2 = self.saw_plaintext.clone();
        let t2 = thread::spawn(move || {
            let mut client = client;
            let mut upstream = upstream;
            relay_one(&mut upstream, &mut client, &relayed2, &saw2, &marker)
        });
        let _ = t1.join();
        let _ = t2.join();
        Ok(())
    }
}

/// Relay reader→writer, counting bytes and scanning for `marker`.
fn relay_one(
    reader: &mut TcpStream,
    writer: &mut TcpStream,
    relayed: &AtomicU64,
    saw: &AtomicU64,
    marker: &[u8],
) {
    let mut buf = [0u8; 8192];
    let mut tail: Vec<u8> = Vec::new(); // overlap so split markers are found
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        relayed.fetch_add(n as u64, Ordering::Relaxed);
        let mut window = std::mem::take(&mut tail);
        window.extend_from_slice(&buf[..n]);
        if window.windows(marker.len()).any(|w| w == marker) {
            saw.fetch_add(1, Ordering::Relaxed);
        }
        let keep = window.len().saturating_sub(marker.len() - 1);
        tail = window[keep..].to_vec();
        if writer.write_all(&buf[..n]).is_err() {
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
    // 1. SOCKS5 server.
    let server = Socks5Server::bind().map_err(|e| format!("proxy bind: {e}"))?;
    let proxy_addr = server.addr();
    let relayed = server.relayed_bytes.clone();
    let saw = server.saw_plaintext.clone();
    let marker_bytes = marker();
    let server_thread = thread::spawn(move || server.serve_once(marker_bytes));

    // 2. B: TCP listener for proxied QUIC.
    let b_listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("B bind: {e}"))?;
    let b_tcp_addr = b_listener
        .local_addr()
        .map_err(|e| format!("B addr: {e}"))?;

    // B thread: TCP accept → ProxyTransport → QUIC listener → echo → wait.
    let (peer_tx, peer_rx) = mpsc::channel::<PeerId>();
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let b_thread = thread::spawn(move || -> Result<(), String> {
        let (stream, _) = b_listener.accept().map_err(|e| format!("B accept: {e}"))?;
        let transport = ProxyTransport::new(stream, b_tcp_addr);
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

    // 3. A: two phases.
    //   Phase 1: SOCKS5 CONNECT (TCP). This triggers proxy→B, so B's TCP
    //            accept returns and B can create its QUIC listener.
    //   Phase 2: after receiving B's peer_id, wrap in ProxyTransport and
    //            do the QUIC handshake.
    let config = Socks5ProxyConfig::new(proxy_addr, None);
    let tcp_stream = nexus_proxy_transport::socks5_connect(&config, b_tcp_addr)
        .map_err(|e| format!("A proxy connect: {e}"))?;
    let peer_b = peer_rx
        .recv_timeout(Duration::from_secs(30))
        .map_err(|_| "A: timeout waiting for B peer_id".to_string())?;
    let transport = ProxyTransport::new(tcp_stream, b_tcp_addr);
    let (t_ok, t_err, t_framed) = transport.counters();
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
    let _ = server_thread.join();

    let relayed_bytes = relayed.load(Ordering::Relaxed);
    let saw_plaintext = saw.load(Ordering::Relaxed);
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

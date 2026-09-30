//! E4: product.proxy-transport-trojan (T2/T4/T6).
//!
//! Minimal trojan server S on 127.0.0.1:0 (plaintext handshake this phase):
//! read the request header → `parse_request` → `AuthDenied` closes the
//! connection; else TCP-connect to the target and relay plaintext both ways.
//!
//! B listens on TCP 127.0.0.1:0, wraps accepted streams in the plain
//! [`FramedTransport`], serves QUIC via `bind_with_transport`. A does the
//! trojan handshake (via S) to B's TCP port, builds QUIC via
//! `connect_with_transport` with [`TrojanTransport`], sends 64KB on a bi
//! stream, B echoes. PASS requires full roundtrip **and**
//! `proxy_relayed_bytes > 0` (T2/T6) **and** `proxy_saw_plaintext_bytes == 0`
//! (the QUIC payload stays E2E ciphertext — X2; only the trojan header and
//! the 2-byte length prefixes travel in the clear, TLS is postponed per T2).
//!
//! TCP-only: no UDP involved, runs anywhere loopback TCP works.
//! B thread waits for A's confirmation before dropping its FabricConn
//! (4b lesson: premature drop shuts down the driver and loses echo data).

use nexus_fabric::{ConnConfig, FabricConn, FabricListener, PeerId};
use nexus_outbound_trojan::{parse_request, TrojanError, TrojanTarget};
use nexus_proxy_transport::{FramedTransport, TrojanProxyConfig, TrojanTransport};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    mpsc, Arc,
};
use std::thread;
use std::time::Duration;

const N: usize = 65536;
const PASSWORD: &str = "e4-trojan-password";

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

/// Read exactly one trojan request header (bounded): 56 hex + CRLF,
/// CMD(0x01), ATYP, addr, port, CRLF.
fn read_header(s: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; 58]; // 56 hex + CRLF
    s.read_exact(&mut buf)?;
    let mut cmd = [0u8; 1];
    s.read_exact(&mut cmd)?;
    if cmd[0] != 0x01 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not a trojan CONNECT",
        ));
    }
    buf.push(cmd[0]);
    let mut atyp = [0u8; 1];
    s.read_exact(&mut atyp)?;
    buf.push(atyp[0]);
    match atyp[0] {
        0x01 => {
            let mut rest = [0u8; 6]; // 4B ip + 2B port
            s.read_exact(&mut rest)?;
            buf.extend_from_slice(&rest);
        }
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l)?;
            buf.push(l[0]);
            let mut rest = vec![0u8; l[0] as usize + 2];
            s.read_exact(&mut rest)?;
            buf.extend_from_slice(&rest);
        }
        b => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsupported ATYP {b:#04x}"),
            ))
        }
    }
    let mut crlf = [0u8; 2];
    s.read_exact(&mut crlf)?;
    if crlf != *b"\r\n" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "missing CRLF",
        ));
    }
    buf.extend_from_slice(&crlf);
    Ok(buf)
}

/// Minimal trojan server: header auth → plaintext bidirectional relay.
/// Counts relayed bytes and scans for plaintext payload (X2).
struct TrojanServer {
    listener: TcpListener,
    relayed_bytes: Arc<AtomicU64>,
    saw_plaintext: Arc<AtomicU64>,
}

impl TrojanServer {
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

    /// Serve exactly one trojan session then relay until EOF.
    /// `AuthDenied` → the connection is closed (real trojan semantic).
    fn serve_once(&self, marker: Vec<u8>) -> std::io::Result<()> {
        let (mut client, _) = self.listener.accept()?;
        client.set_read_timeout(Some(Duration::from_secs(30)))?;

        let raw = read_header(&mut client)?;
        let target = match parse_request(PASSWORD, &raw) {
            Ok(t) => t,
            Err(TrojanError::AuthDenied) => {
                // Real trojan semantic: reject by closing, no error reply.
                return Ok(());
            }
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("trojan header: {e}"),
                ))
            }
        };
        let target_sa: SocketAddr = match target {
            TrojanTarget::Ipv4(oct, port) => SocketAddr::from((oct, port)),
            TrojanTarget::Domain(_, _) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "e4 trojan server: domain target not supported",
                ))
            }
        };

        let upstream = TcpStream::connect(target_sa)?;
        upstream.set_read_timeout(Some(Duration::from_secs(30)))?;

        // Plaintext bidirectional relay with byte counting + marker scan.
        let mut up_clone = upstream.try_clone()?;
        let mut cl_clone = client.try_clone()?;
        // Shutdown handles for prompt session teardown (see ss example).
        let cl_sd = client.try_clone()?;
        let up_sd = upstream.try_clone()?;
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
        loop {
            if t1.is_finished() || t2.is_finished() {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        let _ = cl_sd.shutdown(std::net::Shutdown::Both);
        let _ = up_sd.shutdown(std::net::Shutdown::Both);
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
    // 1. trojan server.
    let server = TrojanServer::bind().map_err(|e| format!("trojan bind: {e}"))?;
    let proxy_addr = server.addr();
    let relayed = server.relayed_bytes.clone();
    let saw = server.saw_plaintext.clone();
    let marker_bytes = marker();
    let server_thread = thread::spawn(move || server.serve_once(marker_bytes));

    // 2. B: TCP listener for the relayed leg.
    let b_listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("B bind: {e}"))?;
    let b_tcp_addr = b_listener
        .local_addr()
        .map_err(|e| format!("B addr: {e}"))?;

    // B thread: TCP accept → plain FramedTransport → QUIC listener → echo → wait.
    let (peer_tx, peer_rx) = mpsc::channel::<PeerId>();
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let b_thread = thread::spawn(move || -> Result<(), String> {
        let (stream, _) = b_listener.accept().map_err(|e| format!("B accept: {e}"))?;
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

    // 3. A: trojan handshake (triggers S→B so B's accept returns), then QUIC.
    let config = TrojanProxyConfig::new(proxy_addr, PASSWORD.to_string());
    let transport = TrojanTransport::connect(&config, b_tcp_addr)
        .map_err(|e| format!("A trojan connect: {e}"))?;
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

//! E4 for `product.path-fallback`: automatic fallback Direct → Proxy.
//!
//! Topology (all on the test machine):
//! - B: TCP echo server on 127.0.0.1:0 (the "remote service").
//! - S: minimal SOCKS5 server on 127.0.0.1:0 (greeting → CONNECT → relay to
//!   B, counting relayed bytes).
//! - Chain: `FallbackConfig { proxy: Some(S), turn: None }` expands to
//!   `[Direct, Proxy]`; Turn is honestly skipped and counted (F4).
//! - The Direct candidate points at 192.0.2.1 (TEST-NET-1, unroutable),
//!   simulating a firewall DROP: packets vanish, no RST, connect never
//!   completes. This is NOT a real GFW (honest boundary, see scenario).
//!
//! The example's connector (composition-root pattern, F2) dials Direct via
//! cancel-cooperative `connect_timeout` slices (always fails) and dials Proxy
//! via a real SOCKS5 CONNECT handshake, then runs an N-byte echo roundtrip
//! through the relayed stream.
//!
//! PASS requires: winner is proxy, the echo roundtrip verifies, the proxy
//! really relayed bytes (> 0), Direct was attempted (stagger order), and
//! Turn was skipped.
//!
//! Outputs JSON; `--json` flag required (harness convention).

use nexus_path::{
    CandidatePath, FallbackChain, FallbackConfig, PathConnector, PathKind, ProxyEndpoint,
    RaceBudget, connect_with_fallback,
};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

/// Payload size for the echo roundtrip.
const N: usize = 65536;
/// Unroutable address simulating a firewall DROP for the Direct candidate.
const BLOCKED_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

fn payload() -> Vec<u8> {
    (0..N as u32).map(|i| (i % 251) as u8).collect()
}

/// Minimal SOCKS5 server: greeting → CONNECT → bidirectional TCP relay.
/// Counts relayed bytes in both directions.
struct Socks5Server {
    listener: TcpListener,
    relayed_bytes: Arc<AtomicU64>,
}

impl Socks5Server {
    fn bind() -> std::io::Result<Self> {
        Ok(Self {
            listener: TcpListener::bind("127.0.0.1:0")?,
            relayed_bytes: Arc::new(AtomicU64::new(0)),
        })
    }

    fn addr(&self) -> SocketAddr {
        self.listener.local_addr().unwrap()
    }

    /// Serve exactly one CONNECT session, then return.
    fn serve_one(&self) -> std::io::Result<()> {
        let (mut client, _) = self.listener.accept()?;
        // Greeting: VER=5, NMETHODS=1, METHOD=0 (no auth).
        let mut greet = [0u8; 3];
        client.read_exact(&mut greet)?;
        if greet[0] != 5 || greet[1] != 1 || greet[2] != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bad socks5 greeting",
            ));
        }
        client.write_all(&[5, 0])?;
        // Request: VER=5, CMD=1 (CONNECT), RSV=0, ATYP=1 (IPv4), addr, port.
        let mut req = [0u8; 10];
        client.read_exact(&mut req)?;
        if req[0] != 5 || req[1] != 1 || req[3] != 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bad socks5 request",
            ));
        }
        let target = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(req[4], req[5], req[6], req[7])),
            u16::from_be_bytes([req[8], req[9]]),
        );
        let upstream = TcpStream::connect(target)?;
        // Reply: success.
        client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;
        // Relay both directions, counting bytes. Split each stream so the two
        // directions own independent handles.
        let relayed = Arc::clone(&self.relayed_bytes);
        let mut up_write = upstream;
        let mut up_read = up_write.try_clone()?;
        let mut down_write = client;
        let mut down_read = down_write.try_clone()?;
        let r1 = Arc::clone(&relayed);
        let t1 = thread::spawn(move || -> std::io::Result<()> {
            let mut buf = [0u8; 8192];
            loop {
                let n = down_read.read(&mut buf)?;
                if n == 0 {
                    let _ = up_write.shutdown(std::net::Shutdown::Write);
                    break;
                }
                r1.fetch_add(n as u64, Ordering::SeqCst);
                up_write.write_all(&buf[..n])?;
            }
            Ok(())
        });
        let mut buf = [0u8; 8192];
        loop {
            let n = up_read.read(&mut buf)?;
            if n == 0 {
                break;
            }
            relayed.fetch_add(n as u64, Ordering::SeqCst);
            down_write.write_all(&buf[..n])?;
        }
        let _ = t1.join();
        Ok(())
    }
}

/// TCP echo server: echoes exactly N bytes, then waits for A's 1-byte "done"
/// before closing (4b lesson: the responder must not drop its side early).
fn serve_echo(listener: TcpListener) -> std::io::Result<()> {
    let (mut stream, _) = listener.accept()?;
    let mut received = vec![0u8; N];
    stream.read_exact(&mut received)?;
    stream.write_all(&received)?;
    // Wait for A's confirmation before dropping (else echo data can be lost).
    let mut done = [0u8; 1];
    stream.read_exact(&mut done)?;
    Ok(())
}

/// The composition-root connector (F2): knows how to dial each tier.
struct TierDialer {
    /// Ultimate peer address (the echo server B).
    peer: SocketAddr,
    direct_attempted: AtomicBool,
}

impl TierDialer {
    /// SOCKS5 CONNECT through `proxy` to `target`, returning the relayed stream.
    fn socks5_connect(proxy: SocketAddr, target: SocketAddr) -> std::io::Result<TcpStream> {
        let mut s = TcpStream::connect(proxy)?;
        s.write_all(&[5, 1, 0])?;
        let mut resp = [0u8; 2];
        s.read_exact(&mut resp)?;
        if resp != [5, 0] {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "socks5 auth failed",
            ));
        }
        let ip = match target.ip() {
            IpAddr::V4(v4) => v4.octets(),
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "ipv6 not supported in this E4",
                ));
            }
        };
        let port = target.port().to_be_bytes();
        s.write_all(&[5, 1, 0, 1, ip[0], ip[1], ip[2], ip[3], port[0], port[1]])?;
        let mut rep = [0u8; 10];
        s.read_exact(&mut rep)?;
        if rep[1] != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "socks5 connect refused",
            ));
        }
        Ok(s)
    }
}

impl PathConnector for TierDialer {
    fn connect(&self, path: &CandidatePath, cancel: &AtomicBool) -> std::io::Result<u64> {
        match path.kind {
            PathKind::Direct => {
                // Simulated firewall DROP: the address is unroutable, so the
                // connect never completes. Slice the wait so we stay
                // cancel-cooperative (R5); any fast failure also counts as
                // "attempted".
                self.direct_attempted.store(true, Ordering::SeqCst);
                let target = SocketAddr::new(IpAddr::V4(BLOCKED_IP), path.remote_addr.port());
                let deadline = Instant::now() + Duration::from_millis(4000);
                loop {
                    if cancel.load(Ordering::SeqCst) {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Interrupted,
                            "cancelled",
                        ));
                    }
                    if Instant::now() >= deadline {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "direct blocked (simulated DROP)",
                        ));
                    }
                    match TcpStream::connect_timeout(&target, Duration::from_millis(250)) {
                        Ok(_) => {
                            // Unexpected: the "blocked" address answered.
                            return Ok(0);
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
                        Err(e) => return Err(e), // fast fail (no route): still blocked
                    }
                }
            }
            PathKind::Proxy => {
                // Real SOCKS5 handshake, then the echo roundtrip through it.
                let mut stream = Self::socks5_connect(path.remote_addr, self.peer)?;
                let out = payload();
                stream.write_all(&out)?;
                let mut back = vec![0u8; N];
                stream.read_exact(&mut back)?;
                if back != out {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "echo mismatch through proxy",
                    ));
                }
                // Tell B we're done so it can close cleanly (4b lesson).
                stream.write_all(&[1])?;
                Ok((2 * N) as u64)
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "tier not used in this E4",
            )),
        }
    }
}

fn main() {
    let json = std::env::args().any(|a| a == "--json");

    // B: echo server. S: SOCKS5 proxy.
    let echo_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let peer = echo_listener.local_addr().unwrap();
    let proxy = Socks5Server::bind().unwrap();
    let proxy_addr = proxy.addr();

    let echo_handle = thread::spawn(move || serve_echo(echo_listener));
    let relayed_counter = Arc::clone(&proxy.relayed_bytes);
    let proxy_handle = thread::spawn(move || proxy.serve_one());

    // Chain: proxy configured, TURN not → [Direct, Proxy]; Turn skipped (F4).
    let config = FallbackConfig {
        proxy: Some(ProxyEndpoint { server: proxy_addr }),
        turn: None,
    };
    let mut chain = FallbackChain::expand(&config, "127.0.0.1:0".parse().unwrap(), peer);
    let turn_skipped = chain.skipped().contains(&PathKind::Turn);

    let dialer = TierDialer {
        peer,
        direct_attempted: AtomicBool::new(false),
    };
    let budget = RaceBudget {
        stagger_delay_ms: 200,
        max_parallel: 2,
        total_timeout_ms: 8000,
    };

    let mut verdict = "FAIL";
    let mut winner_kind = "none";
    let mut roundtrip_ok = false;

    match connect_with_fallback(&mut chain, &dialer, &budget) {
        Ok(outcome) => {
            winner_kind = match outcome.winner.kind {
                PathKind::Direct => "direct",
                PathKind::Mesh => "mesh",
                PathKind::Turn => "turn",
                PathKind::Proxy => "proxy",
            };
            // roundtrip_ok: proxy won AND the connector's echo verified
            // (connect() only returns Ok after a verified roundtrip).
            roundtrip_ok = winner_kind == "proxy";
            if roundtrip_ok {
                verdict = "PASS";
            }
        }
        Err(e) => {
            if !json {
                eprintln!("fallback race failed: {e}");
            }
        }
    }

    let direct_attempted = dialer.direct_attempted.load(Ordering::SeqCst);
    let relayed = relayed_counter.load(Ordering::SeqCst);
    // The proxy must really have relayed the echo bytes (2*N).
    if verdict == "PASS" && relayed < (2 * N) as u64 {
        verdict = "FAIL";
    }
    if verdict == "PASS" && !(direct_attempted && turn_skipped) {
        verdict = "FAIL";
    }

    let _ = proxy_handle.join();
    let _ = echo_handle.join();

    if json {
        println!(
            concat!(
                "{{\"verdict\":\"{verdict}\",",
                "\"fallback\":{{\"winner_kind\":\"{winner}\",",
                "\"roundtrip_ok\":{rt},",
                "\"proxy_relayed_bytes\":{relayed},",
                "\"direct_attempted\":{attempted},",
                "\"turn_skipped\":{skipped}}}}}"
            ),
            verdict = verdict,
            winner = winner_kind,
            rt = roundtrip_ok,
            relayed = relayed,
            attempted = direct_attempted,
            skipped = turn_skipped,
        );
    } else {
        println!(
            "verdict={verdict} winner={winner_kind} relayed={relayed}B direct_attempted={direct_attempted}"
        );
    }
    if verdict == "FAIL" {
        std::process::exit(1);
    }
}

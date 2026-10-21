//! E4: product.fabric-conn-basic
//!
//! Two endpoints over loopback UDP in one process: connect with peer-key
//! pinning, 1 MiB reliable stream echo (integrity + order), 100x200B
//! datagrams, measured RTT. Prints exactly one JSON line to stdout.

use nexus_fabric::{ConnConfig, FabricConn, FabricListener};
use std::net::SocketAddr;
use std::thread;
use std::time::Duration;

const STREAM_BYTES: usize = 1_048_576;
const DATAGRAMS: usize = 100;

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn payload() -> Vec<u8> {
    (0..STREAM_BYTES as u32).map(|i| (i % 251) as u8).collect()
}

fn main() {
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
    run_with_connect(
        |peer, config| FabricConn::connect(peer, config).map_err(|e| format!("connect: {e}")),
        || {},
    )
}

// Injection only: admission, client work and joining below are the actual
// example path. The default factory preserves the original connect behavior.
fn run_with_connect(
    connect: impl FnOnce(nexus_fabric::PeerId, &ConnConfig) -> Result<FabricConn, String>,
    server_exited: impl FnOnce() + Send + 'static,
) -> Result<(String, bool), String> {
    let listener =
        FabricListener::bind("127.0.0.1:0".parse().unwrap()).map_err(|e| format!("bind: {e}"))?;
    let server_peer = listener.peer_id();
    let server_addr: SocketAddr = listener
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?;
    let handshake_timeout = Duration::from_secs(10);
    // Queuing echo bytes and FIN does not confirm delivery. Keep the server
    // driver alive through the client's complete echo/EOF and worker join.
    let server_owner = listener.clone();

    // Server: accept -> echo the stream -> observe a valid datagram.
    let server = thread::spawn(move || -> Result<(usize, usize), String> {
        let _exit = WorkerExit(Some(server_exited));
        let conn = listener
            .accept_timeout(handshake_timeout)
            .map_err(|e| format!("accept: {e}"))?;
        let (mut send, mut recv) = conn.accept_bi().map_err(|e| format!("accept_bi: {e}"))?;
        let mut data = Vec::new();
        let mut buf = [0u8; 65536];
        loop {
            let n = recv.read(&mut buf).map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                break;
            }
            data.extend_from_slice(&buf[..n]);
        }
        let mut off = 0;
        while off < data.len() {
            off += send
                .write(&data[off..])
                .map_err(|e| format!("echo write: {e}"))?;
        }
        send.finish().map_err(|e| format!("echo finish: {e}"))?;
        let dcount = receive_example_datagrams(|| {
            conn.recv_datagram().map_err(|e| format!("dgram recv: {e}"))
        })?;
        Ok((dcount, data.len()))
    });

    // Enclose every client Result path, including failures before open_bi,
    // so the server handle is consumed before the example returns an error.
    let ((conn, echo, payload), (dcount, _slen)) = with_server_owner(server_owner, server, || {
        let config = ConnConfig {
            addrs: vec![server_addr],
            handshake_timeout,
        };
        let conn = connect(server_peer, &config)?;
        let (mut send, mut recv) = conn.open_bi().map_err(|e| format!("open_bi: {e}"))?;
        let payload = payload();
        let mut off = 0;
        while off < payload.len() {
            off += send
                .write(&payload[off..])
                .map_err(|e| format!("write: {e}"))?;
        }
        send.finish().map_err(|e| format!("finish: {e}"))?;
        for i in 0..DATAGRAMS as u8 {
            let mut d = vec![0u8; 200];
            d[0] = i;
            d[199] = i.wrapping_mul(7);
            conn.send_datagram(&d)
                .map_err(|e| format!("dgram send: {e}"))?;
        }
        let mut echo = Vec::new();
        let mut buf = [0u8; 65536];
        loop {
            let n = recv.read(&mut buf).map_err(|e| format!("echo read: {e}"))?;
            if n == 0 {
                break;
            }
            echo.extend_from_slice(&buf[..n]);
        }
        Ok((conn, echo, payload))
    })?;

    // Checks (match the frozen scenario fields).
    let echo_bytes_match = echo == payload;
    // A QUIC stream delivers bytes in order; byte-equality with the sent
    // buffer is the order check (any reordering would fail it).
    let in_order = echo_bytes_match;
    let received_at_least_one = dcount >= 1;
    let rtt = conn.stats().rtt_ms;
    let rtt_json = match rtt {
        Some(v) => v.to_string(),
        None => "null".to_string(),
    };
    // peer.authenticated: connect() pins the server's key; a successful
    // handshake means the peer was authenticated (else HandshakeFailed).
    let pass = echo_bytes_match && in_order && received_at_least_one && rtt.is_some();
    let verdict = if pass { "PASS" } else { "FAIL" };
    let detail = if pass {
        String::new()
    } else {
        format!(",\"detail\":\"echo_match={echo_bytes_match} dgrams={dcount} rtt={rtt_json}\"")
    };
    Ok((
        format!(
            "{{\"verdict\":\"{verdict}\",\"stream\":{{\"echo_bytes_match\":{echo_bytes_match},\"in_order\":{in_order}}},\"datagrams\":{{\"received_at_least_one\":{received_at_least_one}}},\"stats\":{{\"rtt_ms\":{rtt_json}}},\"peer\":{{\"authenticated\":true}}{detail}}}"
        ),
        pass,
    ))
}

// S5 permits loss: the example only needs to witness one valid arrival.
// The separate server owner keeps the driver alive through echo delivery.
fn receive_example_datagrams(
    mut receive: impl FnMut() -> Result<Vec<u8>, String>,
) -> Result<usize, String> {
    for _ in 0..DATAGRAMS {
        let datagram = receive()?;
        if datagram.len() == 200 {
            return Ok(1);
        }
    }
    Ok(0)
}

struct WorkerExit<F: FnOnce()>(Option<F>);

impl<F: FnOnce()> Drop for WorkerExit<F> {
    fn drop(&mut self) {
        if let Some(exited) = self.0.take() {
            exited();
        }
    }
}

fn with_server_owner<O, C, S>(
    owner: O,
    server: thread::JoinHandle<Result<S, String>>,
    client: impl FnOnce() -> Result<C, String>,
) -> Result<(C, S), String> {
    let client_result = client();
    let server_result = match server.join() {
        Ok(result) => result.map_err(|error| format!("server: {error}")),
        Err(_) => Err("server thread panicked".to_string()),
    };
    drop(owner);
    match (client_result, server_result) {
        (Ok(client), Ok(server)) => Ok((client, server)),
        (Err(client), Ok(_)) => Err(client),
        (Ok(_), Err(server)) => Err(server),
        (Err(client), Err(server)) => Err(format!("{client}; {server}")),
    }
}

#[cfg(test)]
#[path = "basic/owner_tests.rs"]
mod owner_tests;

#[cfg(test)]
#[path = "basic/datagram_tests.rs"]
mod datagram_tests;

//! S10/S11 regression tests for `nexus-fabric` driver connection lifecycle.
//!
//! These need real UDP (QUIC handshake + close). In environments without
//! UDP (e.g. the sandbox, where sendto is EPERM) they skip gracefully;
//! run them on xc-pc-linux for real evidence.

use nexus_fabric::{Cmd, Driver, PeerId};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// True when this machine can actually exchange UDP datagrams.
fn udp_available() -> bool {
    match std::net::UdpSocket::bind("127.0.0.1:0") {
        Ok(s) => s.send_to(&[0u8; 1], "127.0.0.1:9").is_ok(),
        Err(_) => false,
    }
}

fn require_udp() -> bool {
    if udp_available() {
        return true;
    }
    eprintln!("SKIP: no UDP in this environment — run on xc-pc-linux for real evidence");
    false
}

fn server_peer(server: &std::sync::Arc<Driver>) -> PeerId {
    server.shared().peer_id.expect("server has a peer id")
}

fn server_addr(server: &std::sync::Arc<Driver>) -> SocketAddr {
    *server.shared().local_addr.lock().unwrap()
}

/// S10: the reaper must remove closed connections from `shared.conns`,
/// otherwise their `accepted`/`dgrams` buffers accumulate forever.
#[test]
fn s10_reaped_conn_removed_from_shared_conns() {
    if !require_udp() {
        return;
    }
    let server = Driver::new_server("127.0.0.1:0".parse().unwrap()).unwrap();
    let (peer, addr) = (server_peer(&server), server_addr(&server));
    let client = Driver::new_client().unwrap();

    let c = client
        .connect(peer, addr, Duration::from_secs(10))
        .expect("client connects");
    let s = server.accept_conn().expect("server accepts");
    let id = s.id.0;

    // Close from the client side; the server observes ConnectionLost.
    client.send(Cmd::Close {
        conn: c.id.0,
        code: 0,
        reason: b"test done".to_vec(),
    });

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut gone = false;
    while Instant::now() < deadline {
        if !server.shared().conns.lock().unwrap().contains_key(&id) {
            gone = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        gone,
        "S10: reaped connection {id} must be removed from shared.conns"
    );
}

/// S10: `accept_conn` must skip ids whose connections were already reaped
/// instead of handing out (or erroring on) dead connections.
#[test]
fn s10_accept_skips_reaped_id() {
    if !require_udp() {
        return;
    }
    let server = Driver::new_server("127.0.0.1:0".parse().unwrap()).unwrap();
    let (peer, addr) = (server_peer(&server), server_addr(&server));
    let client = Driver::new_client().unwrap();

    // First connection: accept it, then close + wait for the reap.
    let c1 = client
        .connect(peer, addr, Duration::from_secs(10))
        .expect("client1 connects");
    let s1 = server.accept_conn().expect("server accepts c1");
    let dead_id = s1.id.0;
    client.send(Cmd::Close {
        conn: c1.id.0,
        code: 0,
        reason: b"test done".to_vec(),
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while server.shared().conns.lock().unwrap().contains_key(&dead_id) {
        assert!(
            Instant::now() < deadline,
            "S10: connection was never reaped"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    // A stale id sits in the accept queue (e.g. queued before the reap).
    server.shared().accept_q.lock().unwrap().push_back(dead_id);

    // Second connection; accept must skip the dead id and return the live one.
    let client2 = Driver::new_client().unwrap();
    let h = std::thread::spawn(move || {
        client2
            .connect(peer, addr, Duration::from_secs(10))
            .expect("client2 connects")
    });
    let got = server.accept_conn().expect("server accepts c2");
    let c2 = h.join().expect("client2 thread");
    // NOTE: client and server allocate conn ids from one process-global
    // counter, so the two ends of c2 have *different* ids — what matters
    // is that the reaped id was skipped, not returned.
    assert_ne!(
        got.id.0, dead_id,
        "S10: accept_conn must skip the reaped id {dead_id}"
    );
    assert!(
        server
            .shared()
            .conns
            .lock()
            .unwrap()
            .contains_key(&got.id.0),
        "S10: the accepted connection must be live"
    );
    let _ = c2;
}

/// S11: `Driver::connect` is bounded by a single total `handshake_timeout`
/// (command reply + QUIC handshake), never ~2x.
#[test]
fn s11_connect_timeout_is_single_deadline() {
    if !require_udp() {
        return;
    }
    let client = Driver::new_client().unwrap();
    let peer = PeerId([9u8; 32]);
    // TEST-NET-1 blackhole: packets go nowhere, no refusal, no handshake.
    let blackhole: SocketAddr = "192.0.2.1:9".parse().unwrap();
    let timeout = Duration::from_secs(2);
    let start = Instant::now();
    let r = client.connect(peer, blackhole, timeout);
    let elapsed = start.elapsed();
    assert!(r.is_err(), "connect to a blackhole must fail");
    assert!(
        elapsed < timeout + Duration::from_secs(1),
        "S11: connect must return within one handshake_timeout, took {elapsed:?}"
    );
}

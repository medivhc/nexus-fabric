//! WP1b / spec §19: the listener exposes how many inbound mTLS handshakes it
//! rejected, so the daemon can make the rejection observable without changing
//! `accept_timeout` semantics (rejections still surface as `Timeout`).
//!
//! Exactly-once is part of the contract: one rejected inbound connection must
//! bump the counter by exactly one, no matter how many driver events it emits.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use nexus_fabric::{ConnConfig, FabricConn, FabricError, FabricIdentity, FabricListener};

fn identity(seed: u8) -> FabricIdentity {
    FabricIdentity::from_ed25519_seed([seed; 32]).unwrap()
}

fn config(addr: SocketAddr) -> ConnConfig {
    ConnConfig {
        addrs: vec![addr],
        handshake_timeout: Duration::from_millis(700),
    }
}

/// Poll the counter until it reaches `at_least` or the deadline expires.
fn wait_for(listener: &FabricListener, at_least: u64, timeout: Duration) -> u64 {
    let deadline = Instant::now() + timeout;
    loop {
        let observed = listener.rejected_handshakes();
        if observed >= at_least || Instant::now() >= deadline {
            return observed;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Run one rejection attempt and require exactly one increment.
fn assert_single_increment(
    listener: &FabricListener,
    before: u64,
    label: &str,
    attempt: impl FnOnce(),
) {
    attempt();
    let observed = wait_for(listener, before + 1, Duration::from_secs(2));
    assert_eq!(
        observed,
        before + 1,
        "{label}: rejected handshake must bump the counter by exactly one"
    );
    // Retransmissions / late connection events for the same inbound
    // connection must not bump it again.
    std::thread::sleep(Duration::from_millis(150));
    assert_eq!(
        listener.rejected_handshakes(),
        observed,
        "{label}: a single rejected connection must be counted exactly once"
    );
}

#[test]
fn each_rejected_handshake_form_increments_exactly_once() {
    let server = identity(60);
    let client = identity(61);
    let listener =
        FabricListener::bind_mtls("127.0.0.1:0".parse().unwrap(), &server, &[client.peer_id()])
            .unwrap();
    let addr = listener.local_addr().unwrap();
    assert_eq!(
        listener.rejected_handshakes(),
        0,
        "fresh listener starts at 0"
    );

    // Form 1: anonymous legacy client (no client certificate).
    assert_single_increment(&listener, 0, "anonymous", || {
        if let Ok(anonymous) = FabricConn::connect(server.peer_id(), &config(addr)) {
            anonymous.close(0, b"anonymous");
        }
    });

    // Form 2: a client identity that is not in the allowlist.
    assert_single_increment(&listener, 1, "unlisted identity", || {
        assert!(
            FabricConn::connect_mtls(server.peer_id(), &identity(62), &config(addr)).is_err(),
            "unlisted identity must not connect"
        );
    });

    // Form 3: the client pins the wrong server key and aborts.
    assert_single_increment(&listener, 2, "wrong pin", || {
        assert!(
            FabricConn::connect_mtls(identity(63).peer_id(), &client, &config(addr)).is_err(),
            "wrongly pinned server must not connect"
        );
    });

    // Form 4: an empty allowlist rejects every client (fresh listener).
    let empty = FabricListener::bind_mtls("127.0.0.1:0".parse().unwrap(), &server, &[]).unwrap();
    let empty_addr = empty.local_addr().unwrap();
    assert_eq!(empty.rejected_handshakes(), 0);
    assert_single_increment(&empty, 0, "empty allowlist", || {
        assert!(
            FabricConn::connect_mtls(server.peer_id(), &client, &config(empty_addr)).is_err(),
            "empty allowlist must not connect"
        );
    });
}

#[test]
fn allowed_connection_and_idle_polling_do_not_increment() {
    let server = identity(64);
    let client = identity(65);
    let listener =
        FabricListener::bind_mtls("127.0.0.1:0".parse().unwrap(), &server, &[client.peer_id()])
            .unwrap();
    let addr = listener.local_addr().unwrap();

    // Pure idle: no inbound datagrams at all.
    assert!(
        matches!(
            listener.accept_timeout(Duration::from_millis(120)),
            Err(FabricError::Timeout)
        ),
        "idle listener still times out"
    );
    assert_eq!(
        listener.rejected_handshakes(),
        0,
        "idle polling must not bump the rejection counter"
    );

    // Successful allowlisted mTLS admission, then a clean close.
    let conn = FabricConn::connect_mtls(server.peer_id(), &client, &config(addr)).unwrap();
    let accepted = listener
        .accept_timeout(Duration::from_millis(700))
        .expect("allowlisted peer is accepted");
    assert_eq!(accepted.peer(), client.peer_id());
    conn.close(0, b"done");
    accepted.close(0, b"done");

    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        listener.rejected_handshakes(),
        0,
        "authenticated connections must never be counted as rejections"
    );
}

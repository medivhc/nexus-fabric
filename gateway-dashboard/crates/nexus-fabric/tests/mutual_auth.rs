use nexus_fabric::{ConnConfig, FabricConn, FabricError, FabricIdentity, FabricListener};
use std::time::{Duration, Instant};

fn identity(seed: u8) -> FabricIdentity {
    FabricIdentity::from_ed25519_seed([seed; 32]).unwrap()
}
fn config(listener: &FabricListener) -> ConnConfig {
    ConnConfig {
        addrs: vec![listener.local_addr().unwrap()],
        handshake_timeout: Duration::from_millis(700),
    }
}
#[test]
fn real_mutual_handshake_has_the_actual_keys_on_both_sides() {
    let server = identity(1);
    let client = identity(2);
    let listener =
        FabricListener::bind_mtls("127.0.0.1:0".parse().unwrap(), &server, &[client.peer_id()])
            .unwrap();
    let conn = FabricConn::connect_mtls(server.peer_id(), &client, &config(&listener)).unwrap();
    let accepted = listener.accept_timeout(Duration::from_millis(700)).unwrap();
    assert_eq!(conn.mutually_authenticated_peer(), Some(server.peer_id()));
    assert_eq!(
        accepted.mutually_authenticated_peer(),
        Some(client.peer_id())
    );
    assert_eq!(accepted.peer(), client.peer_id());
    let (mut send, _) = conn.open_bi().unwrap();
    send.write(b"verified TLS data").unwrap();
    send.finish().unwrap();
    let (_, mut recv) = accepted.accept_bi().unwrap();
    let mut bytes = Vec::new();
    loop {
        let mut buf = [0; 32];
        let n = recv.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        bytes.extend_from_slice(&buf[..n]);
    }
    assert_eq!(bytes, b"verified TLS data");
    conn.send_datagram(b"verified datagram").unwrap();
    assert_eq!(accepted.recv_datagram().unwrap(), b"verified datagram");
    conn.close(0, b"done");
    assert!(conn.open_bi().is_err());
    assert!(conn.send_datagram(b"after close").is_err());
    accepted.close(0, b"done");
}
#[test]
fn anonymous_unknown_wrong_pin_and_empty_allowlist_never_accept() {
    let server = identity(3);
    let client = identity(4);
    for allowed in [vec![client.peer_id()], vec![]] {
        let listener =
            FabricListener::bind_mtls("127.0.0.1:0".parse().unwrap(), &server, &allowed).unwrap();
        // Legacy clients may return before the server rejects the missing
        // certificate. Their one-way pin never claims mutual authentication.
        if let Ok(anonymous) = FabricConn::connect(server.peer_id(), &config(&listener)) {
            assert_eq!(anonymous.mutually_authenticated_peer(), None);
            if let Ok((mut stream, _)) = anonymous.open_bi() {
                let _ = stream.write(b"unauthenticated stream must not be delivered");
                let _ = stream.finish();
            }
            let _ = anonymous.send_datagram(b"unauthenticated datagram");
        }
        assert!(matches!(
            listener.accept_timeout(Duration::from_millis(40)),
            Err(FabricError::Timeout)
        ));
        assert!(
            FabricConn::connect_mtls(server.peer_id(), &identity(5), &config(&listener)).is_err()
        );
        assert!(matches!(
            listener.accept_timeout(Duration::from_millis(40)),
            Err(FabricError::Timeout)
        ));
        assert!(
            FabricConn::connect_mtls(identity(6).peer_id(), &client, &config(&listener)).is_err()
        );
        assert!(matches!(
            listener.accept_timeout(Duration::from_millis(40)),
            Err(FabricError::Timeout)
        ));
        if allowed.is_empty() {
            assert!(
                FabricConn::connect_mtls(server.peer_id(), &client, &config(&listener)).is_err()
            );
            assert!(matches!(
                listener.accept_timeout(Duration::from_millis(40)),
                Err(FabricError::Timeout)
            ));
        }
    }
}
#[test]
fn legacy_one_way_pin_never_claims_mutual_authentication() {
    let listener = FabricListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let conn = FabricConn::connect(listener.peer_id(), &config(&listener)).unwrap();
    let accepted = listener.accept_timeout(Duration::from_millis(700)).unwrap();
    assert_eq!(conn.mutually_authenticated_peer(), None);
    assert_eq!(accepted.mutually_authenticated_peer(), None);
    conn.close(0, b"done");
}
#[test]
fn seed_public_key_is_real_ed25519_and_debug_redacts_secrets() {
    use ring::signature::{Ed25519KeyPair, KeyPair};
    let seed = [11; 32];
    let id = FabricIdentity::from_ed25519_seed(seed).unwrap();
    let signer = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    assert_eq!(id.peer_id().0.as_slice(), signer.public_key().as_ref());
    let debug = format!("{id:?}");
    assert!(!debug.contains("key_der"));
    assert!(!debug.contains("cert_der"));
    assert!(!debug.contains(&format!("{seed:?}")));
}
#[test]
fn authenticated_timeout_has_one_budget_and_bounded_driver_drop() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let config = ConnConfig {
        addrs: vec![socket.local_addr().unwrap()],
        handshake_timeout: Duration::from_millis(120),
    };
    let start = Instant::now();
    assert!(matches!(
        FabricConn::connect_mtls(identity(7).peer_id(), &identity(8), &config),
        Err(FabricError::Timeout)
    ));
    assert!(start.elapsed() < Duration::from_millis(350));
}

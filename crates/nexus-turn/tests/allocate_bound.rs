use std::net::SocketAddr;

use nexus_turn::client::{TurnClient, TurnCredentials};
use nexus_turn::server::TurnServer;

fn creds() -> TurnCredentials {
    TurnCredentials {
        username: "nexus".into(),
        password: "test-secret".into(),
        realm: "nexus".into(),
    }
}

#[test]
fn g2_turn_bound_and_diagnostic() {
    let server: TurnServer = TurnServer::bind("127.0.0.1:0".parse().unwrap(), creds()).unwrap();
    let wildcard: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let client = TurnClient::allocate_bound(server.main_addr(), creds(), wildcard)
        .expect("allocate_bound on production bind must succeed");
    assert!(
        client.relayed_addr().port() > 0,
        "relayed address allocated"
    );
    assert!(
        client.mapped_addr().is_some(),
        "XOR-MAPPED available for diagnostics"
    );
    assert!(
        client.relayed_addr().ip().is_loopback(),
        "loopback test TURN"
    );
}

#[test]
fn allocate_defaults_to_loopback_bind() {
    let server = TurnServer::bind("127.0.0.1:0".parse().unwrap(), creds()).unwrap();
    let client = TurnClient::allocate(server.main_addr(), creds()).expect("compat allocate");
    assert!(client.relayed_addr().port() > 0);
}

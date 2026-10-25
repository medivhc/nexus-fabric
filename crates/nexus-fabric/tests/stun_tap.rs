use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nexus_fabric::{Driver, StunResponse, StunSink, StunTapError};

struct Recorder(Mutex<Vec<StunResponse>>);

impl StunSink for Recorder {
    fn on_stun_response(&self, response: StunResponse) {
        self.0.lock().unwrap().push(response);
    }
}

fn binding_request(txn: [u8; 12]) -> Vec<u8> {
    let mut b = vec![0u8, 1, 0, 0];
    b.extend_from_slice(&0x2112_A442u32.to_be_bytes());
    b.extend_from_slice(&txn);
    b
}

#[test]
fn g14_fabric_stun_tap_routes_response() {
    let driver = Driver::new_client().expect("client driver");
    let sink = Arc::new(Recorder(Mutex::new(Vec::new())));
    driver
        .install_stun_tap(sink.clone())
        .expect("first install");
    assert!(matches!(
        driver.install_stun_tap(sink.clone()),
        Err(StunTapError::AlreadyInstalled)
    ));

    let mut txn = [0u8; 12];
    for (i, b) in txn.iter_mut().enumerate() {
        *b = i as u8 + 1;
    }
    // Register the transaction (the destination does not need to be reachable).
    let dummy: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let id = driver
        .send_stun_request(dummy, binding_request(txn))
        .expect("send_stun_request");
    assert_eq!(id.0, txn);

    // Inject a matching STUN success response into the driver socket.
    let local = *driver.shared().local_addr.lock().unwrap();
    let from: SocketAddr = "127.0.0.1:40000".parse().unwrap();
    let injector = UdpSocket::bind(from).unwrap();
    let mut resp = vec![0u8, 1, 0, 0];
    resp.extend_from_slice(&0x2112_A442u32.to_be_bytes());
    resp.extend_from_slice(&txn);
    injector.send_to(&resp, local).unwrap();

    let deadline = std::time::Instant::now() + Duration::from_millis(1500);
    while sink.0.lock().unwrap().is_empty() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let got = sink.0.lock().unwrap().clone();
    assert_eq!(got.len(), 1, "registered txn routed to sink");
    assert_eq!(got[0].transaction_id.0, txn);

    // An unregistered STUN packet must not be hijacked.
    let mut other = [9u8; 12];
    other[0] = 0x42;
    let mut foreign = vec![0u8, 1, 0, 0];
    foreign.extend_from_slice(&0x2112_A442u32.to_be_bytes());
    foreign.extend_from_slice(&other);
    injector.send_to(&foreign, local).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        sink.0.lock().unwrap().len(),
        1,
        "unregistered STUN stays on QUIC path"
    );
}

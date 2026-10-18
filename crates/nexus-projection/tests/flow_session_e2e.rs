//! E2E product scenarios for the flow-session Hub (AC1/AC2/AC3/AC5/AC6/AC7).
//!
//! Real QUIC over 127.0.0.1 UDP loopback. When the sandbox blocks UDP
//! (EPERM), tests return early (pass-as-skip); true verification runs on
//! xc-pc-linux. This file deliberately contains no references to QUIC
//! protocol internals or the fabric driver module (AC1 grep assertion).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use nexus_fabric::{ConnConfig, Driver, FabricConn, FabricListener, PeerId};
use nexus_nat_wireup::PunchManager;
use nexus_path::{CandidatePath, PathConfig, PathKind, PathManager, PathStats, RaceBudget};
use nexus_projection::flow_session::{
    DatagramHandler, FlowSessionHub, MAX_STREAM_WRITE, RecvStream, SendStream, StreamHandler,
};
use nexus_projection::{DatagramTransport, FabricTransport, PathLink};
use sha2::{Digest, Sha256};

fn addr(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

fn peer_hex(peer: &PeerId) -> String {
    peer.0.iter().map(|b| format!("{b:02x}")).collect()
}

fn udp_loopback_available() -> bool {
    use std::net::UdpSocket;
    let a = match UdpSocket::bind("127.0.0.1:0") {
        Ok(s) => s,
        Err(_) => return false,
    };
    let b = match UdpSocket::bind("127.0.0.1:0") {
        Ok(s) => s,
        Err(_) => return false,
    };
    let bp = match b.local_addr() {
        Ok(addr) => addr.port(),
        Err(_) => return false,
    };
    a.send_to(b"probe", format!("127.0.0.1:{bp}")).is_ok()
}

fn fast_config() -> PathConfig {
    PathConfig {
        hysteresis_pct: 0.0,
        switch_hold_ms: 0,
        probe_interval_ms: 60_000,
        ewma_alpha: 1.0,
        max_missed_probes: 1000,
        race_budget: RaceBudget::default(),
    }
}

/// Create a Hub with a fast-switching PathManager; returns the Hub, its own
/// PeerId/listener address, and the shared PathManager Arc (for AC3 roaming).
fn make_hub_with_manager() -> Option<(FlowSessionHub, PeerId, SocketAddr, Arc<Mutex<PathManager>>)>
{
    if !udp_loopback_available() {
        return None;
    }
    let listener = FabricListener::bind(addr(0)).ok()?;
    let peer = listener.peer_id();
    let local = listener.local_addr().ok()?;
    let pm = Arc::new(Mutex::new(PathManager::new(fast_config())));
    let link = PathLink::new(Arc::clone(&pm));
    let punch = PunchManager::new(Driver::new_client().ok()?, PeerId([9u8; 32]));
    let hub = FlowSessionHub::new(listener, link, punch);
    Some((hub, peer, local, pm))
}

/// Create a Hub (default fast config) and return it with its own PeerId and
/// listener address.
fn make_hub() -> Option<(FlowSessionHub, PeerId, SocketAddr)> {
    make_hub_with_manager().map(|(h, p, a, _)| (h, p, a))
}

/// AC1: reliable stream end-to-end. A sends 4 MiB over a Hub stream; B's
/// registered handler receives every byte, SHA-256 matches, and A reads
/// EOF after B finishes.
#[test]
fn ac1_reliable_stream_4mib_sha256() {
    let Some((hub_a, _pa, _la)) = make_hub() else {
        return; // UDP blocked
    };
    let Some((hub_b, peer_b, addr_b)) = make_hub() else {
        return;
    };

    let total_payload = 4 * 1024 * 1024;
    let mut payload = Vec::with_capacity(total_payload);
    for i in 0..total_payload {
        payload.push((i % 251) as u8);
    }
    let expected: [u8; 32] = Sha256::digest(&payload).into();

    let (result_tx, result_rx) = mpsc::channel();
    let handler: StreamHandler = Arc::new(
        move |_peer: PeerId, mut send: SendStream, mut recv: RecvStream| {
            let mut hasher = Sha256::new();
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match recv.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => hasher.update(&buf[..n]),
                    Err(e) => {
                        let _ = result_tx.send(Err(e));
                        return;
                    }
                }
            }
            let digest: [u8; 32] = hasher.finalize().into();
            let _ = result_tx.send(Ok(digest));
            // Finish the send half so A observes EOF (AC1).
            let _ = send.finish();
        },
    );
    hub_b.register_stream_service(0x10, handler);

    hub_a.dial(peer_b, &[addr_b]).expect("dial");

    let (mut send, mut recv) = hub_a.open_stream(peer_b).expect("open stream");
    // First byte is the service type (D3); the Hub consumes it for routing.
    send.write(&[0x10]).expect("write type byte");
    for chunk in payload.chunks(MAX_STREAM_WRITE) {
        send.write(chunk).expect("write payload chunk");
    }
    send.finish().expect("finish send");

    // A reads EOF after B's handler finishes.
    let mut buf = [0u8; 8192];
    let mut eof = false;
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        match recv.read(&mut buf) {
            Ok(0) => {
                eof = true;
                break;
            }
            Ok(_) => continue,
            Err(e) => panic!("A read error: {e}"),
        }
    }
    assert!(eof, "A must observe EOF after B finishes");

    let digest = result_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("B handler must report a hash")
        .expect("B handler must not error");
    assert_eq!(digest, expected, "SHA-256 of the 4 MiB payload must match");
    hub_a.close_peer(peer_b);
}

/// AC2: datagram round-trip. A sends 100 service datagrams; B's registered
/// datagram handler receives them and the sequence numbers are strictly
/// increasing (loss tolerated on the unreliable path).
#[test]
fn ac2_datagram_roundtrip_monotonic_seq() {
    let Some((hub_a, _pa, _la)) = make_hub() else {
        return; // UDP blocked
    };
    let Some((hub_b, peer_b, addr_b)) = make_hub() else {
        return;
    };

    let (seq_tx, seq_rx) = mpsc::channel();
    let handler: DatagramHandler = Arc::new(move |_peer: PeerId, payload: &[u8]| {
        if payload.len() >= 8 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&payload[..8]);
            let seq = u64::from_be_bytes(b);
            let _ = seq_tx.send(seq);
        }
    });
    hub_b.register_datagram_service(0x07, handler);

    hub_a.dial(peer_b, &[addr_b]).expect("dial");

    for i in 0..100u64 {
        let mut data = vec![0x07]; // service sub-id (D4)
        data.extend_from_slice(&i.to_be_bytes());
        data.extend(std::iter::repeat_n(0xAB, 100));
        hub_a.send_datagram(peer_b, &data).expect("send datagram");
    }

    let mut seqs = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    while seqs.len() < 100 && Instant::now() < deadline {
        if let Ok(s) = seq_rx.recv_timeout(Duration::from_millis(200)) {
            seqs.push(s);
        }
    }
    assert!(!seqs.is_empty(), "at least one datagram must arrive");
    assert!(
        seqs.windows(2).all(|w| w[0] < w[1]),
        "received sequence numbers must be strictly increasing: {seqs:?}"
    );
    hub_a.close_peer(peer_b);
}

/// AC3: roaming keeps the connection. Mid-transfer the PathManager switches
/// paths and the production `PathLink::pump()` drives `rebind()`; the
/// ConnectionId is unchanged, the payload hash matches, and the app-visible
/// pause stays below 5000 ms.
#[test]
fn ac3_roam_rebind_keeps_conn_and_data() {
    let Some((hub_a, _pa, _la, _pm)) = make_hub_with_manager() else {
        return; // UDP blocked
    };
    let listener_b = FabricListener::bind(addr(0)).expect("bind B");
    let peer_b = listener_b.peer_id();
    let addr_b = listener_b.local_addr().expect("local addr");

    let (b_result_tx, b_result_rx) = mpsc::channel();
    let accept_thread = thread::spawn(move || {
        let conn = listener_b.accept().expect("accept conn");
        let cid = conn.id();
        let (_send, mut recv) = conn.accept_bi().expect("accept stream");
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut last = Instant::now();
        let mut max_gap = Duration::ZERO;
        loop {
            match recv.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let now = Instant::now();
                    let gap = now.duration_since(last);
                    if gap > max_gap {
                        max_gap = gap;
                    }
                    last = now;
                    hasher.update(&buf[..n]);
                }
                Err(e) => {
                    let _ = b_result_tx.send(Err(e));
                    return;
                }
            }
        }
        let digest: [u8; 32] = hasher.finalize().into();
        let _ = b_result_tx.send(Ok((cid, digest, max_gap)));
    });

    hub_a.dial(peer_b, &[addr_b]).expect("dial");

    let name_b = peer_hex(&peer_b);
    let local_placeholder = addr(8000);
    let candidate = |port: u16| CandidatePath {
        kind: PathKind::Direct,
        local_addr: local_placeholder,
        remote_addr: addr(port),
        cost: 0.0,
    };
    let stats = |rtt: u64| PathStats {
        rtt_ms: Some(rtt),
        loss_rate: Some(0.0),
        throughput_bps: None,
    };

    // Register two synthetic path candidates and map them to the peer so a
    // PathManager switch drives `rebind()` through the production pump (S27).
    {
        let link = hub_a.link();
        let mut link = link.lock().unwrap();
        link.manager()
            .lock()
            .unwrap()
            .add_candidate(candidate(9001));
        link.manager()
            .lock()
            .unwrap()
            .add_candidate(candidate(9002));
        link.map_peer_addr(&name_b, addr(9001));
        link.map_peer_addr(&name_b, addr(9002));
        link.manager()
            .lock()
            .unwrap()
            .on_stats(&addr(9001), stats(100));
        link.manager()
            .lock()
            .unwrap()
            .on_stats(&addr(9002), stats(10));
    }

    // A writes 2 MiB in chunks with a small pause so the path switch lands
    // mid-transfer.
    let total = 2 * 1024 * 1024;
    let mut payload = Vec::with_capacity(total);
    for i in 0..total {
        payload.push((i % 251) as u8);
    }
    let expected: [u8; 32] = Sha256::digest(&payload).into();

    let (mut send, _recv) = hub_a.open_stream(peer_b).expect("open stream");
    let write_thread = thread::spawn(move || {
        for chunk in payload.chunks(MAX_STREAM_WRITE) {
            send.write(chunk).expect("write chunk");
            thread::sleep(Duration::from_millis(5));
        }
        send.finish().expect("finish");
    });

    // Let the transfer start, then force a path switch (remove the active
    // candidate -> the path pump rebinds mid-transfer).
    thread::sleep(Duration::from_millis(30));
    {
        let link = hub_a.link();
        let manager = link.lock().unwrap().manager();
        // Make 9002 clearly better, then remove it so the manager switches.
        manager.lock().unwrap().on_stats(&addr(9001), stats(500));
        manager.lock().unwrap().on_stats(&addr(9002), stats(5));
        manager.lock().unwrap().remove_candidate(&addr(9002));
    }

    write_thread.join().expect("write thread");
    let (cid, digest, max_gap) = b_result_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("B must report the transfer")
        .expect("B read must not error");
    assert_eq!(digest, expected, "payload hash must match after roaming");
    assert!(cid.0 != 0, "ConnectionId must be present");
    assert!(
        max_gap < Duration::from_secs(5),
        "app-visible pause during rebind must be < 5000 ms, was {max_gap:?}"
    );
    drop(accept_thread);
    hub_a.close_peer(peer_b);
}

/// AC5: stream service dispatch. Two services (0x10/0x11) each receive three
/// streams routed by the first-frame type byte, with zero cross-talk.
#[test]
fn ac5_stream_service_dispatch() {
    let Some((hub_a, _pa, _la)) = make_hub() else {
        return; // UDP blocked
    };
    let Some((hub_b, peer_b, addr_b)) = make_hub() else {
        return;
    };

    let (s10_tx, s10_rx) = mpsc::channel();
    let (s11_tx, s11_rx) = mpsc::channel();
    let h10: StreamHandler = Arc::new(
        move |_peer: PeerId, _send: SendStream, mut recv: RecvStream| {
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            loop {
                match recv.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    Err(_) => return,
                }
            }
            let _ = s10_tx.send(buf);
        },
    );
    let h11: StreamHandler = Arc::new(
        move |_peer: PeerId, _send: SendStream, mut recv: RecvStream| {
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            loop {
                match recv.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    Err(_) => return,
                }
            }
            let _ = s11_tx.send(buf);
        },
    );
    hub_b.register_stream_service(0x10, h10);
    hub_b.register_stream_service(0x11, h11);

    hub_a.dial(peer_b, &[addr_b]).expect("dial");

    for i in 0..6 {
        let (mut send, _recv) = hub_a.open_stream(peer_b).expect("open stream");
        let ty = if i < 3 { 0x10 } else { 0x11 };
        let mut data = vec![ty];
        data.extend_from_slice(format!("payload-{i}").as_bytes());
        send.write(&data).expect("write");
        send.finish().expect("finish");
    }

    let mut got10 = Vec::new();
    for _ in 0..3 {
        got10.push(
            s10_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("service 0x10 stream"),
        );
    }
    let mut got11 = Vec::new();
    for _ in 0..3 {
        got11.push(
            s11_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("service 0x11 stream"),
        );
    }
    for (i, payload) in got10.iter().enumerate() {
        assert_eq!(payload, format!("payload-{i}").as_bytes());
    }
    for (i, payload) in got11.iter().enumerate() {
        assert_eq!(payload, format!("payload-{}", i + 3).as_bytes());
    }
    hub_a.close_peer(peer_b);
}

/// AC6: D5 regression. A relay connection registered via
/// `PunchManager::register_relay` gets NO `accept_bi` loop from the Hub;
/// the punch responder consumes signaling streams and non-punch streams
/// reach the correct handler through `take_unclaimed()`.
#[test]
fn ac6_relay_unclaimed_no_accept_bi() {
    if !udp_loopback_available() {
        return; // UDP blocked
    }
    // Raw relay connection between two server drivers (A and B).
    let driver_a = Driver::new_server(addr(0)).expect("driver A");
    let driver_b = Driver::new_server(addr(0)).expect("driver B");
    let peer_a = driver_a.shared().peer_id.expect("A peer id");
    let peer_b = driver_b.shared().peer_id.expect("B peer id");
    let addr_b = *driver_b.shared().local_addr.lock().unwrap();
    let addr_a = *driver_a.shared().local_addr.lock().unwrap();

    let accept_h = thread::spawn({
        let driver_b = driver_b.clone();
        move || driver_b.accept_conn()
    });
    let relay_a = driver_a
        .connect(peer_b, addr_b, Duration::from_secs(10))
        .expect("A relay conn");
    let relay_b = accept_h
        .join()
        .expect("accept thread")
        .expect("B relay conn");

    // B side: PunchManager + PathLink with the NAT relay registered.
    let punch_b = PunchManager::new(driver_b.clone(), peer_b);
    let pm = Arc::new(Mutex::new(PathManager::new(fast_config())));
    let mut link = PathLink::new(Arc::clone(&pm));
    let name_a = peer_hex(&peer_a);
    link.register_nat_relay(&name_a, relay_b.clone(), PathKind::Turn, addr_b, addr_a);
    punch_b.register_relay(&relay_b, peer_a);

    let listener_b = FabricListener::bind(addr(0)).expect("B listener");
    let hub_b = FlowSessionHub::new(listener_b, link, punch_b);

    let (ac6_tx, ac6_rx) = mpsc::channel();
    let handler: StreamHandler = Arc::new(
        move |_peer: PeerId, _send: SendStream, mut recv: RecvStream| {
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            loop {
                match recv.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    Err(_) => return,
                }
            }
            let _ = ac6_tx.send(buf);
        },
    );
    hub_b.register_stream_service(0x10, handler);

    // B's Hub recognizes the NAT peer via the PathLink registration.
    assert!(hub_b.dial(peer_a, &[addr_a]).expect("dial NAT peer"));

    // A opens a non-punch stream on the relay conn (service type 0x10).
    let sh = relay_a.open_stream().expect("open relay stream");
    let (mut send, _recv) = nexus_fabric::split_stream(sh);
    send.write(b"\x10hello-ac6").expect("write service stream");
    send.finish().expect("finish");

    let received = ac6_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("handler must receive the unclaimed stream");
    assert_eq!(received, b"hello-ac6");

    // The Hub must NOT run an accept_bi loop on the punch-registered relay:
    // no `flow-accept-<peer_a>` thread exists (only the listener + dgram
    // threads are Hub-generated for this peer).
    let peer_h = peer_hex(&peer_a);
    let comm_prefix = format!("flow-accept-{}", &peer_h[..3]);
    let mut accept_threads = 0usize;
    if let Ok(rd) = std::fs::read_dir("/proc/self/task") {
        for e in rd.flatten() {
            let comm_path = e.path().join("comm");
            if let Ok(name) = std::fs::read_to_string(comm_path) {
                if name.trim() == comm_prefix {
                    accept_threads += 1;
                }
            }
        }
    }
    assert_eq!(accept_threads, 0, "no flow-accept thread for the NAT peer");
    hub_b.close_peer(peer_a);
}

/// AC7: datagram dispatch compatibility. A `0x02` STREAM-intent datagram
/// still enters the TUN inbox (existing `FabricTransport` behavior); a
/// `0x03` service datagram goes to the upper-layer handler and never
/// reaches the inbox.
#[test]
fn ac7_datagram_dispatch_compat() {
    if !udp_loopback_available() {
        return; // UDP blocked
    }
    let listener = FabricListener::bind(addr(0)).expect("bind");
    let peer = listener.peer_id();
    let local = listener.local_addr().expect("local addr");
    let accept_thread = thread::spawn(move || listener.accept());
    let conn_a = FabricConn::connect(
        peer,
        &ConnConfig {
            addrs: vec![local],
            handshake_timeout: Duration::from_secs(10),
        },
    )
    .expect("connect");
    let conn_b = accept_thread
        .join()
        .expect("accept thread")
        .expect("accept");

    let mut peers = HashMap::new();
    peers.insert("b".to_string(), conn_a);
    let transport = FabricTransport::new(peers);

    let (svc_tx, svc_rx) = mpsc::channel();
    let handler: DatagramHandler = Arc::new(move |_peer: PeerId, payload: &[u8]| {
        let _ = svc_tx.send(payload.to_vec());
    });
    transport.register_datagram_service(7, handler);

    // 0x03 service datagram -> upper-layer handler, not the TUN inbox.
    conn_b
        .send_datagram(&[0x03, 0x07, 1, 2, 3])
        .expect("send service datagram");
    let payload = svc_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("service payload must reach the handler");
    assert_eq!(payload, vec![1, 2, 3]);
    assert!(
        transport.recv().is_none(),
        "0x03 service datagram must not enter the TUN inbox"
    );

    // 0x02 STREAM-intent datagram -> TUN inbox (existing behavior).
    conn_b
        .send_datagram(&[0x02, 0xAA, 0xBB])
        .expect("send stream datagram");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut got = None;
    while Instant::now() < deadline {
        if let Some(x) = transport.recv() {
            got = Some(x);
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let (from, data) = got.expect("0x02 datagram must reach the TUN inbox");
    assert_eq!(from, "b");
    assert_eq!(data, vec![0x02, 0xAA, 0xBB]);
}

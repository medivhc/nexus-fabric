//! Wireup Red tests: must FAIL on empty (`todo!()`) implementations.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::thread;
use std::time::{Duration, Instant};

use nexus_connectivity::nat::NatType;
use nexus_nat_traversal::PunchChannel;
use nexus_nat_traversal::{CandidateKind, PunchCandidate};
use nexus_nat_wireup::channel::{STREAM_TYPE_PUNCH, deframe, frame_msg};
use nexus_nat_wireup::responder::PreAnsweredChannel;
use nexus_nat_wireup::socket::first_finished;
use nexus_nat_wireup::tie_break_keep_local;

fn addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
}

/// Framing round-trips (type + payload), and deframe rejects truncated input.
#[test]
fn frame_roundtrip() {
    let payload = b"punch-offer-bytes";
    let framed = frame_msg(STREAM_TYPE_PUNCH, payload);
    let (ty, out, consumed) = deframe(&framed).expect("complete frame must parse");
    assert_eq!(ty, STREAM_TYPE_PUNCH);
    assert_eq!(out, payload);
    assert_eq!(consumed, framed.len());
    // Truncated: no frame.
    assert!(deframe(&framed[..4]).is_none());
    assert!(deframe(&[]).is_none());
}

/// Tie-break: larger PeerId keeps its initiated connection; smaller closes.
/// Both sides compute independently — determinism is the whole point.
#[test]
fn tie_break_larger_keeps() {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a[0] = 0x02;
    b[0] = 0x01;
    assert!(tie_break_keep_local(&a, &b));
    assert!(!tie_break_keep_local(&b, &a));
    // Must be antisymmetric for any distinct pair.
    let mut c = [7u8; 32];
    let mut d = [7u8; 32];
    d[31] = 8;
    c[31] = 9;
    assert!(tie_break_keep_local(&c, &d));
    assert!(!tie_break_keep_local(&d, &c));
}

/// First-wins: the earliest-finishing handle wins, even if a slower one was
/// pushed first.
#[test]
fn first_finished_picks_earliest() {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut handles = vec![
        (
            addr(9001),
            thread::spawn(|| {
                thread::sleep(Duration::from_millis(400));
                "slow"
            }),
        ),
        (
            addr(9002),
            thread::spawn(|| {
                thread::sleep(Duration::from_millis(50));
                "fast"
            }),
        ),
    ];
    let (winner_addr, join_res) = first_finished(&mut handles, deadline).expect("one must finish");
    assert_eq!(winner_addr, addr(9002));
    assert_eq!(join_res.unwrap(), "fast");
    // The slow handle is still pending.
    assert_eq!(handles.len(), 1);
    assert_eq!(handles[0].0, addr(9001));
}

/// first_finished: all handles gone / deadline passed -> None.
#[test]
fn first_finished_none_when_empty_or_timeout() {
    let mut empty: Vec<(SocketAddr, thread::JoinHandle<u32>)> = Vec::new();
    assert!(first_finished(&mut empty, Instant::now() + Duration::from_secs(1)).is_none());
    let mut pending = vec![(
        addr(9003),
        thread::spawn(|| {
            thread::sleep(Duration::from_secs(30));
            1u32
        }),
    )];
    let res = first_finished(&mut pending, Instant::now() + Duration::from_millis(100));
    assert!(res.is_none());
    assert_eq!(pending.len(), 1);
}

/// PreAnsweredChannel: send_offer captures the nonce; recv_answer replays
/// the prebuilt answer (initiator's candidates) with that nonce.
#[test]
fn preanswered_nonce_echo() {
    use nexus_nat_traversal::PunchOffer;
    let cands = vec![PunchCandidate {
        addr: addr(5001),
        kind: CandidateKind::Srflx,
    }];
    let ch = PreAnsweredChannel::new(cands.clone(), NatType::FullCone);
    let offer = PunchOffer {
        version: 1,
        nonce: 0xA11CE,
        candidates: vec![],
        nat_type: NatType::Symmetric,
        start_at_ms: 0,
    };
    ch.send_offer(&offer).unwrap();
    let answer = ch.recv_answer(Duration::from_secs(1)).unwrap();
    assert_eq!(answer.nonce, 0xA11CE);
    assert_eq!(answer.version, 1);
    assert_eq!(answer.candidates.len(), 1);
    assert_eq!(answer.candidates[0].addr, addr(5001));
    assert_eq!(answer.nat_type, NatType::FullCone);
}

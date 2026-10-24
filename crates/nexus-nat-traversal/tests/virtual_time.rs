mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};

use common::{FakeChannel, FakeSocket, ManualPunchClock};
use nexus_connectivity::nat::NatType;
use nexus_nat_traversal::{
    LocalCandidates, PortSample, PunchAnswer, PunchConfig, PunchFailReason, PunchPhase,
    PunchResult, PunchSession, PunchStats,
};

fn cands(nat: NatType, port: u16) -> LocalCandidates {
    LocalCandidates {
        host: vec![format!("10.0.0.2:{port}").parse().unwrap()],
        srflx: Some(format!("198.51.100.2:{port}").parse().unwrap()),
        srflx_stun: None,
        srflx_turn: None,
        nat_type: nat,
    }
}

fn answer(
    nonce: u64,
    nat: NatType,
    prediction: Option<nexus_nat_traversal::PredictionHint>,
) -> PunchAnswer {
    PunchAnswer {
        version: 2,
        nonce,
        candidates: vec![nexus_nat_traversal::PunchCandidate {
            addr: "198.51.100.9:40000".parse().unwrap(),
            kind: nexus_nat_traversal::CandidateKind::Srflx,
        }],
        nat_type: nat,
        prediction,
    }
}

fn samples() -> Vec<PortSample> {
    vec![
        PortSample {
            port: 40000,
            at_ms: 0,
            target: "192.0.2.1:3478".parse().unwrap(),
            observed_from: "10.0.0.2:5000".parse().unwrap(),
        },
        PortSample {
            port: 40001,
            at_ms: 100,
            target: "192.0.2.1:3478".parse().unwrap(),
            observed_from: "10.0.0.2:5000".parse().unwrap(),
        },
        PortSample {
            port: 40002,
            at_ms: 200,
            target: "192.0.2.2:3478".parse().unwrap(),
            observed_from: "10.0.0.2:5000".parse().unwrap(),
        },
    ]
}

fn direct() -> SocketAddr {
    "198.51.100.9:40000".parse().unwrap()
}

#[test]
fn coord_wait_uses_virtual_time() {
    let clock = ManualPunchClock::at(1_000);
    let mut a = answer(0, NatType::FullCone, None);
    a.nonce = 0; // replaced below from captured offer
    let ch = FakeChannel::new(clock.clone(), Vec::new());
    let sock = FakeSocket::new(clock.clone(), Some(direct()));
    let mut cfg = PunchConfig::default();
    cfg.coord_skew_ms = 200;
    let mut s = PunchSession::new(
        nexus_nat_traversal::PeerId([1; 32]),
        cands(NatType::FullCone, 5000),
        NatType::FullCone,
        Vec::new(),
        cfg,
        ch.clone(),
        sock.clone(),
        Arc::new(nexus_nat_traversal::NoopPredictor),
        clock.clone(),
    );
    *ch.auto_answer.lock().unwrap() = Some(answer(0, NatType::FullCone, None));
    let wall = Instant::now();
    let r = s.run();
    assert!(matches!(r, PunchResult::Migrated { .. }), "got {r:?}");
    assert!(
        wall.elapsed() < Duration::from_millis(100),
        "wall clock used"
    );
    let sends = sock.times();
    assert_eq!(
        sends.first().copied(),
        Some(1_200),
        "punch starts after coord skew"
    );
}

#[test]
fn punch_timeout_at_5000ms() {
    let clock = ManualPunchClock::at(0);
    let ch = FakeChannel::timeout_only(clock.clone());
    let sock = FakeSocket::new(clock.clone(), Some(direct()));
    let mut s = PunchSession::new(
        nexus_nat_traversal::PeerId([1; 32]),
        cands(NatType::FullCone, 5000),
        NatType::FullCone,
        Vec::new(),
        PunchConfig::default(),
        ch,
        sock,
        Arc::new(nexus_nat_traversal::NoopPredictor),
        clock.clone(),
    );
    let r = s.run();
    assert_eq!(
        r,
        PunchResult::StayedOnRelay {
            reason: PunchFailReason::Timeout
        }
    );
    assert_eq!(clock.now(), 5000, "budget must be exactly 5000ms");
}

#[test]
fn spray_pacing_50ms() {
    let clock = ManualPunchClock::at(0);
    let ch = FakeChannel::new(clock.clone(), Vec::new());
    let sock = FakeSocket::new(clock.clone(), Some(direct()));
    let mut cfg = PunchConfig::default();
    cfg.spray_k = 2;
    cfg.coord_skew_ms = 0;
    let hint = nexus_nat_traversal::PredictionHint {
        base_port: 40001,
        delta: 1,
        samples: 3,
    };
    let mut s = PunchSession::new(
        nexus_nat_traversal::PeerId([1; 32]),
        cands(NatType::FullCone, 5000),
        NatType::Symmetric,
        samples(),
        cfg,
        ch.clone(),
        sock.clone(),
        Arc::new(nexus_nat_traversal::DefaultPredictor),
        clock.clone(),
    );
    *ch.auto_answer.lock().unwrap() = Some(answer(0, NatType::Symmetric, Some(hint)));
    let _ = s.run();
    let t = sock.times();
    assert_eq!(t.len(), 5, "2K+1 spray targets");
    for w in t.windows(2) {
        assert_eq!(w[1] - w[0], 50, "spray pacing 50ms: {t:?}");
    }
}

#[test]
fn spray_budget_3s() {
    let clock = ManualPunchClock::at(0);
    let ch = FakeChannel::new(clock.clone(), Vec::new());
    let sock = FakeSocket::new(clock.clone(), Some(direct()));
    let mut cfg = PunchConfig::default();
    cfg.spray_k = 32;
    cfg.spray_interval_ms = 50;
    cfg.spray_time_budget = Duration::from_millis(100);
    cfg.coord_skew_ms = 0;
    let hint = nexus_nat_traversal::PredictionHint {
        base_port: 40001,
        delta: 1,
        samples: 3,
    };
    let mut s = PunchSession::new(
        nexus_nat_traversal::PeerId([1; 32]),
        cands(NatType::FullCone, 5000),
        NatType::Symmetric,
        samples(),
        cfg,
        ch.clone(),
        sock.clone(),
        Arc::new(nexus_nat_traversal::DefaultPredictor),
        clock.clone(),
    );
    *ch.auto_answer.lock().unwrap() = Some(answer(0, NatType::Symmetric, Some(hint)));
    let _ = s.run();
    let stats: PunchStats = s.stats();
    assert!(sock.send_count() < 65, "budget must stop spray");
    assert!(
        stats.spray_skipped > 0,
        "skipped targets counted: {stats:?}"
    );
}

#[test]
fn nonce_unique_without_wall_clock() {
    let clock = ManualPunchClock::at(777);
    let mk = || {
        let ch = FakeChannel::timeout_only(clock.clone());
        let sock = FakeSocket::new(clock.clone(), Some(direct()));
        let s = PunchSession::new(
            nexus_nat_traversal::PeerId([1; 32]),
            cands(NatType::FullCone, 5000),
            NatType::FullCone,
            Vec::new(),
            PunchConfig::default(),
            ch.clone(),
            sock,
            Arc::new(nexus_nat_traversal::NoopPredictor),
            clock.clone(),
        );
        (s, ch)
    };
    let (mut s1, c1) = mk();
    let (mut s2, c2) = mk();
    let _ = s1.run();
    clock.sleep_ms(0);
    let _ = s2.run();
    let n1 = c1.offers.lock().unwrap()[0].nonce;
    let n2 = c2.offers.lock().unwrap()[0].nonce;
    assert_ne!(n1, n2, "same virtual ms must still yield unique nonces");
}

#[test]
fn single_total_budget() {
    let clock = ManualPunchClock::at(0);
    let ch = FakeChannel::new(clock.clone(), Vec::new());
    ch.consume_before_answer_ms
        .store(4000, std::sync::atomic::Ordering::SeqCst);
    let sock = FakeSocket::new(clock.clone(), Some(direct()));
    sock.await_consume_ms
        .store(1000, std::sync::atomic::Ordering::SeqCst);
    let mut s = PunchSession::new(
        nexus_nat_traversal::PeerId([1; 32]),
        cands(NatType::FullCone, 5000),
        NatType::FullCone,
        Vec::new(),
        PunchConfig::default(),
        ch.clone(),
        sock,
        Arc::new(nexus_nat_traversal::NoopPredictor),
        clock.clone(),
    );
    *ch.auto_answer.lock().unwrap() = Some(answer(0, NatType::FullCone, None));
    let r = s.run();
    assert!(matches!(r, PunchResult::Migrated { .. }), "got {r:?}");
    assert_eq!(
        clock.now(),
        5000,
        "recv 4s + await 1s must share the 5s budget"
    );
}

#[test]
fn mapping_probe_count_bounded() {
    let clock = ManualPunchClock::at(0);
    let ch = FakeChannel::new(clock.clone(), Vec::new());
    let sock = FakeSocket::new(clock.clone(), Some(direct()));
    let mut cfg = PunchConfig::default();
    cfg.coord_skew_ms = 0;
    cfg.mapping_probe_count = 3;
    cfg.mapping_probe_interval_ms = 50;
    let mut s = PunchSession::new(
        nexus_nat_traversal::PeerId([1; 32]),
        cands(NatType::Symmetric, 5000),
        NatType::FullCone,
        samples(),
        cfg,
        ch.clone(),
        sock.clone(),
        Arc::new(nexus_nat_traversal::DefaultPredictor),
        clock.clone(),
    );
    *ch.auto_answer.lock().unwrap() = Some(answer(0, NatType::FullCone, None));
    let _ = s.run();
    let stats = s.stats();
    assert_eq!(sock.send_count(), 3, "mapping probes bounded to 3");
    assert_eq!(stats.mapping_probe_sends, 3);
    assert_eq!(stats.spray_sends, 0, "symmetric side must not spray");
    let t = sock.times();
    for w in t.windows(2) {
        assert_eq!(w[1] - w[0], 50);
    }
}

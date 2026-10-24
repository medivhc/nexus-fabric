mod common;

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use common::{FakeChannel, FakeSocket, ManualPunchClock};
use nexus_connectivity::nat::NatType;
use nexus_nat_traversal::{
    CandidateKind, DefaultPredictor, LocalCandidates, PortSample, Predictability, PunchAnswer,
    PunchCandidate, PunchConfig, PunchPredictor, PunchSession, SprayPlan,
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

fn answer(nat: NatType, prediction: Option<nexus_nat_traversal::PredictionHint>) -> PunchAnswer {
    PunchAnswer {
        version: 2,
        nonce: 0,
        candidates: vec![PunchCandidate {
            addr: "198.51.100.9:40000".parse().unwrap(),
            kind: CandidateKind::Srflx,
        }],
        nat_type: nat,
        prediction,
    }
}

fn samples() -> Vec<PortSample> {
    let obs: SocketAddr = "10.0.0.2:5000".parse().unwrap();
    vec![
        PortSample {
            port: 40000,
            at_ms: 0,
            target: "192.0.2.1:3478".parse().unwrap(),
            observed_from: obs,
        },
        PortSample {
            port: 40001,
            at_ms: 100,
            target: "192.0.2.1:3478".parse().unwrap(),
            observed_from: obs,
        },
        PortSample {
            port: 40002,
            at_ms: 200,
            target: "192.0.2.2:3478".parse().unwrap(),
            observed_from: obs,
        },
    ]
}

#[derive(Default)]
struct RecordingPredictor {
    seen: Mutex<Vec<Vec<PortSample>>>,
    inner: DefaultPredictor,
}

impl PunchPredictor for RecordingPredictor {
    fn assess(&self, samples: &[PortSample]) -> Predictability {
        self.seen.lock().unwrap().push(samples.to_vec());
        self.inner.assess(samples)
    }
    fn plan(&self, p: &Predictability, target_ip: IpAddr, k: u8) -> Option<SprayPlan> {
        self.inner.plan(p, target_ip, k)
    }
}

fn run_session(
    local_nat: NatType,
    remote_nat: NatType,
    prediction: Option<nexus_nat_traversal::PredictionHint>,
    predictor: Arc<dyn PunchPredictor>,
) -> (Arc<FakeSocket>, nexus_nat_traversal::PunchStats) {
    let clock = ManualPunchClock::at(0);
    let ch = FakeChannel::new(clock.clone(), Vec::new());
    *ch.auto_answer.lock().unwrap() = Some(answer(remote_nat, prediction));
    let sock = FakeSocket::new(clock.clone(), Some("198.51.100.9:40000".parse().unwrap()));
    let mut cfg = PunchConfig::default();
    cfg.coord_skew_ms = 0;
    cfg.spray_k = 2;
    let mut s = PunchSession::new(
        nexus_nat_traversal::PeerId([7; 32]),
        cands(local_nat, 5000),
        remote_nat,
        samples(),
        cfg,
        ch,
        sock.clone(),
        predictor,
        clock,
    );
    let _ = s.run();
    (sock, s.stats())
}

#[test]
fn g4_session_receives_samples_and_clock() {
    let rec = Arc::new(RecordingPredictor::default());
    let (_sock, _stats) = run_session(NatType::FullCone, NatType::FullCone, None, rec.clone());
    // Non-symmetric fast path still has to hand samples to the predictor so the
    // same session object can drive hints; at minimum assess must see the samples.
    let seen = rec.seen.lock().unwrap();
    assert!(!seen.is_empty(), "predictor must be consulted");
    assert_eq!(seen[0].len(), 3, "session passes its samples, not &[]");
}

#[test]
fn g7_cone_sprays_symmetric_ports() {
    let hint = nexus_nat_traversal::PredictionHint {
        base_port: 40002,
        delta: 1,
        samples: 3,
    };
    let (sock, stats) = run_session(
        NatType::FullCone,
        NatType::Symmetric,
        Some(hint),
        Arc::new(DefaultPredictor),
    );
    let targets = sock.targets();
    assert_eq!(stats.spray_sends as usize, targets.len());
    assert!(stats.spray_sends > 0, "cone side sprays");
    assert_eq!(stats.mapping_probe_sends, 0, "cone side must not probe");
    let ips: std::collections::HashSet<_> = targets.iter().map(|t| t.ip()).collect();
    assert_eq!(ips.len(), 1, "single reflexive IP");
    // window center = base + delta = 40003, K=2 -> [40001..=40005]
    for t in &targets {
        assert!(
            (40001..=40005).contains(&t.port()),
            "port {t} outside predicted window"
        );
    }
}

#[test]
fn g7_symmetric_side_probes_and_never_sprays() {
    let (sock, stats) = run_session(
        NatType::Symmetric,
        NatType::FullCone,
        None,
        Arc::new(DefaultPredictor),
    );
    assert_eq!(stats.spray_sends, 0, "symmetric side never sprays");
    assert!(
        (1..=5).contains(&stats.mapping_probe_sends),
        "probe bounded 1..5"
    );
    assert_eq!(stats.mapping_probe_sends as usize, sock.send_count());
}

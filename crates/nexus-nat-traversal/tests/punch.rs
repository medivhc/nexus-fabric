//! Track A Red Evidence 测试（冻结合同 §Red Evidence）。
//!
//! 先在空实现上运行确认 FAIL（exit != 0），再实现。

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nexus_connectivity::nat::NatType;
use nexus_nat_traversal::*;

// ---------------------------------------------------------------------------
// 测试替身
// ---------------------------------------------------------------------------

fn timed_out(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, msg)
}

/// 内存信令通道：预置 answer 队列。
struct FakeChannel {
    sent: Mutex<Vec<PunchOffer>>,
    answers: Mutex<VecDeque<io::Result<PunchAnswer>>>,
}

impl FakeChannel {
    fn new(answers: Vec<io::Result<PunchAnswer>>) -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
            answers: Mutex::new(answers.into()),
        }
    }

    fn sent_count(&self) -> usize {
        self.sent.lock().unwrap().len()
    }
}

impl PunchChannel for FakeChannel {
    fn send_offer(&self, offer: &PunchOffer) -> io::Result<()> {
        self.sent.lock().unwrap().push(offer.clone());
        Ok(())
    }

    fn recv_answer(&self, _timeout: Duration) -> io::Result<PunchAnswer> {
        self.answers
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Err(timed_out("no more answers")))
    }
}

/// 内存打洞 socket：记录 send_punch 目标，预置 await_direct 结果。
struct FakeSocket {
    punched: Mutex<Vec<(SocketAddr, Vec<u8>)>>,
    direct: Mutex<VecDeque<io::Result<SocketAddr>>>,
}

impl FakeSocket {
    fn new(direct: Vec<io::Result<SocketAddr>>) -> Self {
        Self {
            punched: Mutex::new(Vec::new()),
            direct: Mutex::new(direct.into()),
        }
    }

    fn punched_targets(&self) -> Vec<SocketAddr> {
        self.punched
            .lock()
            .unwrap()
            .iter()
            .map(|(a, _)| *a)
            .collect()
    }
}

impl PunchSocket for FakeSocket {
    fn send_punch(&self, target: SocketAddr, payload: &[u8]) -> io::Result<()> {
        self.punched
            .lock()
            .unwrap()
            .push((target, payload.to_vec()));
        Ok(())
    }

    fn await_direct(&self, _timeout: Duration) -> io::Result<SocketAddr> {
        self.direct
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Err(timed_out("no direct")))
    }
}

fn test_addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn local_fullcone() -> LocalCandidates {
    LocalCandidates {
        host: vec![test_addr("192.168.1.10:5000")],
        srflx: Some(test_addr("203.0.113.7:40001")),
        srflx_stun: None,
        nat_type: NatType::FullCone,
    }
}

fn answer_for(nonce: u64, nat: NatType) -> PunchAnswer {
    PunchAnswer {
        version: SIGNAL_VERSION,
        nonce,
        candidates: vec![PunchCandidate {
            addr: test_addr("198.51.100.9:41002"),
            kind: CandidateKind::Srflx,
        }],
        nat_type: nat,
    }
}

fn test_config() -> PunchConfig {
    PunchConfig {
        punch_timeout: Duration::from_secs(2),
        coord_skew_ms: 0, // 测试不等待协同时间窗
        spray_k: 16,
        spray_interval_ms: 0,
        repunch_interval: Duration::from_secs(300),
    }
}

fn new_session(
    channel: FakeChannel,
    socket: FakeSocket,
    local: LocalCandidates,
    remote_nat: NatType,
) -> (PunchSession, Arc<FakeChannel>, Arc<FakeSocket>) {
    let ch = Arc::new(channel);
    let so = Arc::new(socket);
    let s = PunchSession::new(
        PeerId([7u8; 32]),
        local,
        remote_nat,
        test_config(),
        ch.clone(),
        so.clone(),
        Arc::new(NoopPredictor),
    );
    (s, ch, so)
}

// ---------------------------------------------------------------------------
// 1. signal_codec_roundtrip
// ---------------------------------------------------------------------------

#[test]
fn signal_codec_roundtrip() {
    let offer = PunchOffer {
        version: SIGNAL_VERSION,
        nonce: 0x1234_5678_9ABC_DEF0,
        candidates: vec![
            PunchCandidate {
                addr: test_addr("192.0.2.1:5000"),
                kind: CandidateKind::Srflx,
            },
            PunchCandidate {
                addr: test_addr("[2001:db8::1]:6000"),
                kind: CandidateKind::Host,
            },
            PunchCandidate {
                addr: test_addr("203.0.113.9:3478"),
                kind: CandidateKind::Relay,
            },
        ],
        nat_type: NatType::PortRestrictedCone,
        start_at_ms: 1_700_000_000_123,
    };
    let rt = decode_offer(&encode_offer(&offer)).expect("offer roundtrip");
    assert_eq!(rt, offer, "offer 往返必须一致（含候选顺序）");

    let answer = PunchAnswer {
        version: SIGNAL_VERSION,
        nonce: offer.nonce,
        candidates: offer.candidates.clone(),
        nat_type: NatType::Symmetric,
    };
    let rt = decode_answer(&encode_answer(&answer)).expect("answer roundtrip");
    assert_eq!(rt, answer, "answer 往返必须一致");

    // version != 1 → Err(Version)
    let mut bad = encode_offer(&offer);
    bad[0] = 2;
    assert_eq!(decode_offer(&bad).unwrap_err(), SignalError::Version);

    // 候选超 16 → Err(TooMany)
    let many_cands = vec![
        PunchCandidate {
            addr: test_addr("192.0.2.1:5000"),
            kind: CandidateKind::Host,
        };
        17
    ];
    let many = PunchOffer {
        candidates: many_cands,
        ..offer.clone()
    };
    assert_eq!(
        decode_offer(&encode_offer(&many)).unwrap_err(),
        SignalError::TooMany
    );

    // 截断 → Err(Truncated)
    let mut trunc = encode_offer(&offer);
    trunc.truncate(5);
    assert_eq!(decode_offer(&trunc).unwrap_err(), SignalError::Truncated);
}

// ---------------------------------------------------------------------------
// 2. nonce_mismatch_drops_answer
// ---------------------------------------------------------------------------

#[test]
fn nonce_mismatch_drops_answer() {
    // EchoChannel：在 offer 发出后，先塞一个 nonce 错误的 answer，
    // 再塞 nonce 正确的 answer。状态机必须丢弃前者、用后者推进。
    struct EchoChannel {
        inner: FakeChannel,
    }
    impl PunchChannel for EchoChannel {
        fn send_offer(&self, offer: &PunchOffer) -> io::Result<()> {
            self.inner.send_offer(offer)?;
            let mut q = self.inner.answers.lock().unwrap();
            q.push_back(Ok(PunchAnswer {
                version: SIGNAL_VERSION,
                nonce: offer.nonce.wrapping_add(1), // 错误 nonce
                candidates: vec![PunchCandidate {
                    addr: test_addr("10.9.9.9:1111"), // 诱饵地址
                    kind: CandidateKind::Srflx,
                }],
                nat_type: NatType::FullCone,
            }));
            q.push_back(Ok(answer_for(offer.nonce, NatType::FullCone)));
            Ok(())
        }
        fn recv_answer(&self, timeout: Duration) -> io::Result<PunchAnswer> {
            self.inner.recv_answer(timeout)
        }
    }
    let echo = Arc::new(EchoChannel {
        inner: FakeChannel::new(vec![]),
    });
    let direct_addr = test_addr("198.51.100.9:41002");
    let sock = Arc::new(FakeSocket::new(vec![Ok(direct_addr)]));
    let mut s = PunchSession::new(
        PeerId([7u8; 32]),
        local_fullcone(),
        NatType::FullCone,
        test_config(),
        echo.clone(),
        sock.clone(),
        Arc::new(NoopPredictor),
    );
    let r = s.run();
    assert!(
        matches!(r, PunchResult::Migrated { addr } if addr == direct_addr),
        "丢弃 wrong-nonce 后必须用正确 answer 推进到 Migrated，实际: {r:?}"
    );
    assert_eq!(s.phase(), PunchPhase::Migrated);
    // 错误 answer 的诱饵地址绝不能成为打洞目标。
    let targets = sock.punched_targets();
    assert!(
        !targets.contains(&test_addr("10.9.9.9:1111")),
        "wrong-nonce answer 的候选必须被丢弃，实际打洞目标: {targets:?}"
    );
    assert!(targets.contains(&direct_addr));

    // 只有 wrong-nonce（无正确 answer）→ 超时失败，不推进。
    let ch2 = Arc::new(FakeChannel::new(vec![Ok(PunchAnswer {
        version: SIGNAL_VERSION,
        nonce: 0xDEAD_BEEF,
        candidates: vec![],
        nat_type: NatType::FullCone,
    })]));
    let mut s2 = PunchSession::new(
        PeerId([7u8; 32]),
        local_fullcone(),
        NatType::FullCone,
        test_config(),
        ch2.clone(),
        Arc::new(FakeSocket::new(vec![])),
        Arc::new(NoopPredictor),
    );
    let r2 = s2.run();
    assert_eq!(
        r2,
        PunchResult::StayedOnRelay {
            reason: PunchFailReason::Timeout
        }
    );
    assert_eq!(s2.phase(), PunchPhase::Failed(PunchFailReason::Timeout));
}

// ---------------------------------------------------------------------------
// 3. state_machine_happy_path
// ---------------------------------------------------------------------------

#[test]
fn state_machine_happy_path() {
    struct EchoOnce {
        inner: FakeChannel,
    }
    impl PunchChannel for EchoOnce {
        fn send_offer(&self, offer: &PunchOffer) -> io::Result<()> {
            self.inner.send_offer(offer)?;
            self.inner
                .answers
                .lock()
                .unwrap()
                .push_back(Ok(answer_for(offer.nonce, NatType::FullCone)));
            Ok(())
        }
        fn recv_answer(&self, timeout: Duration) -> io::Result<PunchAnswer> {
            self.inner.recv_answer(timeout)
        }
    }
    let ch = Arc::new(EchoOnce {
        inner: FakeChannel::new(vec![]),
    });
    let direct_addr = test_addr("198.51.100.9:41002");
    let so = Arc::new(FakeSocket::new(vec![Ok(direct_addr)]));
    let mut s = PunchSession::new(
        PeerId([7u8; 32]),
        local_fullcone(),
        NatType::FullCone,
        test_config(),
        ch.clone(),
        so.clone(),
        Arc::new(NoopPredictor),
    );
    assert_eq!(s.phase(), PunchPhase::Idle);

    let r = s.run();
    assert_eq!(r, PunchResult::Migrated { addr: direct_addr });
    assert_eq!(s.phase(), PunchPhase::Migrated);

    // 状态机确实驱动了打洞：同一 socket 向对端候选发了包。
    let targets = so.punched_targets();
    assert!(
        targets.contains(&direct_addr),
        "必须向对端 Srflx 候选发打洞包，实际: {targets:?}"
    );

    let st = s.stats();
    assert_eq!(st.attempts, 1);
    assert_eq!(st.migrated, 1);
    assert_eq!(st.last_phase, PunchPhase::Migrated);
}

// ---------------------------------------------------------------------------
// 4. no_candidates_fails
// ---------------------------------------------------------------------------

#[test]
fn no_candidates_fails() {
    let empty = LocalCandidates {
        host: vec![],
        srflx: None,
        srflx_stun: None,
        nat_type: NatType::Unknown,
    };
    let (mut s, ch, so) = new_session(
        FakeChannel::new(vec![]),
        FakeSocket::new(vec![]),
        empty,
        NatType::FullCone,
    );
    let r = s.run();
    assert_eq!(
        r,
        PunchResult::StayedOnRelay {
            reason: PunchFailReason::NoCandidates
        }
    );
    assert_eq!(s.phase(), PunchPhase::Failed(PunchFailReason::NoCandidates));
    // 无候选 → 不应发 offer、不应打洞。
    assert_eq!(ch.sent_count(), 0);
    assert!(so.punched_targets().is_empty());
}

// ---------------------------------------------------------------------------
// 额外：symmetric + NoopPredictor → StayedOnRelay(UnpredictableSymmetric)
// ---------------------------------------------------------------------------

#[test]
fn symmetric_unpredictable_stays_on_relay() {
    struct EchoOnce {
        inner: FakeChannel,
    }
    impl PunchChannel for EchoOnce {
        fn send_offer(&self, offer: &PunchOffer) -> io::Result<()> {
            self.inner.send_offer(offer)?;
            self.inner
                .answers
                .lock()
                .unwrap()
                .push_back(Ok(answer_for(offer.nonce, NatType::FullCone)));
            Ok(())
        }
        fn recv_answer(&self, timeout: Duration) -> io::Result<PunchAnswer> {
            self.inner.recv_answer(timeout)
        }
    }
    let ch = Arc::new(EchoOnce {
        inner: FakeChannel::new(vec![]),
    });
    let so = Arc::new(FakeSocket::new(vec![Ok(test_addr("198.51.100.9:41002"))]));
    let mut local = local_fullcone();
    local.nat_type = NatType::Symmetric;
    let mut s = PunchSession::new(
        PeerId([7u8; 32]),
        local,
        NatType::FullCone,
        test_config(),
        ch.clone(),
        so.clone(),
        Arc::new(NoopPredictor),
    );
    let r = s.run();
    assert_eq!(
        r,
        PunchResult::StayedOnRelay {
            reason: PunchFailReason::UnpredictableSymmetric
        }
    );
    assert_eq!(
        s.phase(),
        PunchPhase::Failed(PunchFailReason::UnpredictableSymmetric)
    );
    // 不可预测 → 一个打洞包都不发。
    assert!(so.punched_targets().is_empty());
    assert_eq!(s.stats().failed_unpredictable, 1);
}

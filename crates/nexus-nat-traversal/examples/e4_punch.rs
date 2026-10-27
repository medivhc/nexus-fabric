//! E4 机制验证：`product.nat-punch-relay-first` 的编排部分。
//!
//! 用真实 UDP socket 实现 `PunchChannel` / `PunchSocket` 替身，
//! 在 netns 双节点（或回环）上证明状态机能驱动完整流程：
//! offer → answer → 协同开打 → Migrated，以及 NoCandidates 失败分支。
//!
//! 不需要真实 TURN：信令通道在此即为"已建连的中继控制流"的替身；
//! TURN/真实中继接线由 coordinator 在合并时做。
//!
//! ```sh
//! # responder（netns punch-b）
//! e4_punch --role responder --sig 10.200.77.2:9000 --punch 10.200.77.2:9001
//! # initiator（netns punch-a）
//! e4_punch --role initiator --sig 10.200.77.2:9000 --punch-bind 10.200.77.1:0
//! # NoCandidates 分支（无需 responder）
//! e4_punch --role initiator --empty-candidates
//! ```
//!
//! initiator 退出码：0 = 得到预期结果；非 0 = 异常。
//! 预期结果由 `--expect migrated|stayed:<reason>` 指定，默认 `migrated`。

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nexus_domain::nat::NatType;
use nexus_nat_traversal::*;

struct SystemClock(Instant);
impl PunchClock for SystemClock {
    fn now_ms(&self) -> u64 {
        self.0.elapsed().as_millis() as u64
    }
    fn wall_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
    fn sleep_until_ms(&self, deadline_ms: u64) {
        let now = self.now_ms();
        if deadline_ms > now {
            std::thread::sleep(Duration::from_millis(deadline_ms - now));
        }
    }
    fn sleep_ms(&self, ms: u64) {
        std::thread::sleep(Duration::from_millis(ms));
    }
}

const ACK_MAGIC: &[u8; 10] = b"NXPNCH-ACK";
const PUNCH_MAGIC: &[u8; 8] = b"NXPNCH01";

fn usage() -> ! {
    eprintln!("usage: e4_punch --role responder --sig <addr> --punch <addr>");
    eprintln!(
        "       e4_punch --role initiator --sig <addr> --punch-bind <addr> [--empty-candidates] [--expect migrated|stayed:<reason>]"
    );
    std::process::exit(2);
}

fn arg_val(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone())
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let role = arg_val(&args, "--role").unwrap_or_else(|| usage());
    match role.as_str() {
        "responder" => responder(&args),
        "initiator" => initiator(&args),
        _ => usage(),
    }
}

// ---------------------------------------------------------------------------
// responder：收 offer → 回 answer；收打洞包 → 回 ack
// ---------------------------------------------------------------------------

fn responder(args: &[String]) {
    let sig_addr: SocketAddr = arg_val(args, "--sig")
        .unwrap_or_else(|| usage())
        .parse()
        .unwrap();
    let punch_addr: SocketAddr = arg_val(args, "--punch")
        .unwrap_or_else(|| usage())
        .parse()
        .unwrap();

    let punch_sock = UdpSocket::bind(punch_addr).expect("bind punch");
    let punch_local = punch_sock.local_addr().unwrap();
    let sig_sock = UdpSocket::bind(sig_addr).expect("bind sig");
    sig_sock
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    punch_sock
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    eprintln!("[responder] sig={sig_addr} punch={punch_local}");

    let deadline = Instant::now() + Duration::from_secs(25);
    let mut buf = [0u8; 2048];
    let mut acked = 0u32;
    while Instant::now() < deadline {
        // 信令：offer → answer
        if let Ok((n, from)) = sig_sock.recv_from(&mut buf) {
            if let Ok(offer) = decode_offer(&buf[..n]) {
                let answer = PunchAnswer {
                    version: SIGNAL_VERSION,
                    nonce: offer.nonce, // 回显 nonce
                    candidates: vec![PunchCandidate {
                        addr: punch_local,
                        kind: CandidateKind::Srflx,
                    }],
                    nat_type: NatType::FullCone,
                    prediction: None,
                };
                let _ = sig_sock.send_to(&encode_answer(&answer), from);
                eprintln!("[responder] answered offer nonce={}", offer.nonce);
            }
        }
        // 打洞：收 punch 包 → 回 ack（带 nonce）
        if let Ok((n, from)) = punch_sock.recv_from(&mut buf) {
            if n >= 16 && &buf[..8] == PUNCH_MAGIC {
                let mut ack = [0u8; 18];
                ack[..10].copy_from_slice(ACK_MAGIC);
                ack[10..].copy_from_slice(&buf[8..16]);
                let _ = punch_sock.send_to(&ack, from);
                acked += 1;
            }
        }
        if acked >= 3 {
            break;
        }
    }
    eprintln!("[responder] done acked={acked}");
}

// ---------------------------------------------------------------------------
// initiator：PunchSession + 真实 UDP 替身
// ---------------------------------------------------------------------------

struct UdpChannel {
    sock: UdpSocket,
    peer_sig: SocketAddr,
}

impl PunchChannel for UdpChannel {
    fn send_offer(&self, offer: &PunchOffer) -> io::Result<()> {
        let b = encode_offer(offer);
        self.sock.send_to(&b, self.peer_sig)?;
        Ok(())
    }

    fn recv_answer(&self, timeout: Duration) -> io::Result<PunchAnswer> {
        self.sock.set_read_timeout(Some(timeout))?;
        let mut buf = [0u8; 2048];
        loop {
            let (n, _) = self.sock.recv_from(&mut buf).map_err(|e| {
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut {
                    io::Error::new(io::ErrorKind::TimedOut, "answer timeout")
                } else {
                    e
                }
            })?;
            match decode_answer(&buf[..n]) {
                Ok(a) => return Ok(a),
                Err(_) => continue, // 坏包跳过
            }
        }
    }
}

struct UdpPunchSocket {
    sock: UdpSocket, // 与 QUIC 同一 socket 的替身：单 socket 收发
}

impl PunchSocket for UdpPunchSocket {
    fn send_punch(&self, target: SocketAddr, payload: &[u8]) -> io::Result<()> {
        self.sock.send_to(payload, target)?;
        Ok(())
    }

    fn await_direct(&self, timeout: Duration) -> io::Result<SocketAddr> {
        self.sock.set_read_timeout(Some(timeout))?;
        let mut buf = [0u8; 2048];
        loop {
            let (n, from) = self.sock.recv_from(&mut buf).map_err(|e| {
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut {
                    io::Error::new(io::ErrorKind::TimedOut, "direct timeout")
                } else {
                    e
                }
            })?;
            // 只校验 ACK 魔数；nonce 防串扰由状态机层保证（已单测）。
            if n == 18 && &buf[..10] == ACK_MAGIC {
                return Ok(from);
            }
            // 非 ack 包继续等（整体超时内）
        }
    }
}

fn initiator(args: &[String]) {
    let empty = has_flag(args, "--empty-candidates");
    let expect = arg_val(args, "--expect").unwrap_or_else(|| "migrated".to_string());

    let local = if empty {
        LocalCandidates {
            host: vec![],
            srflx: None,
            srflx_stun: None,
            srflx_turn: None,
            nat_type: NatType::Unknown,
        }
    } else {
        let peer_sig: SocketAddr = arg_val(args, "--sig")
            .unwrap_or_else(|| usage())
            .parse()
            .unwrap();
        let punch_bind: SocketAddr = arg_val(args, "--punch-bind")
            .unwrap_or_else(|| usage())
            .parse()
            .unwrap();
        // 信令 socket（模拟"已建连的中继控制流"）与打洞 socket 分开；
        // 关键是打洞收发共用**同一个** UDP socket。
        let sig_sock = UdpSocket::bind("0.0.0.0:0").expect("bind sig");
        let punch_sock = UdpSocket::bind(punch_bind).expect("bind punch");
        let punch_local = punch_sock.local_addr().unwrap();

        let channel = Arc::new(UdpChannel {
            sock: sig_sock,
            peer_sig,
        });
        let socket: Arc<dyn PunchSocket> = Arc::new(UdpPunchSocket { sock: punch_sock });
        let mut s = PunchSession::new(
            PeerId([1u8; 32]),
            LocalCandidates {
                host: vec![],
                srflx: Some(punch_local),
                srflx_stun: None,
                srflx_turn: None,
                nat_type: NatType::FullCone,
            },
            NatType::FullCone,
            Vec::new(),
            PunchConfig {
                punch_timeout: Duration::from_secs(8),
                coord_skew_ms: 200,
                ..PunchConfig::default()
            },
            channel,
            socket,
            Arc::new(NoopPredictor),
            Arc::new(SystemClock(Instant::now())),
        );
        finish(s.run(), s.phase(), &expect);
    };

    // empty-candidates：不需要网络
    let mut s = PunchSession::new(
        PeerId([1u8; 32]),
        local,
        NatType::FullCone,
        Vec::new(),
        PunchConfig::default(),
        Arc::new(UdpChannel {
            sock: UdpSocket::bind("0.0.0.0:0").unwrap(),
            peer_sig: "127.0.0.1:9".parse().unwrap(),
        }),
        Arc::new(UdpPunchSocket {
            sock: UdpSocket::bind("0.0.0.0:0").unwrap(),
        }),
        Arc::new(NoopPredictor),
        Arc::new(SystemClock(Instant::now())),
    );
    finish(s.run(), s.phase(), &expect);
}

fn finish(result: PunchResult, phase: PunchPhase, expect: &str) -> ! {
    println!("PUNCH_RESULT={result:?}");
    println!("PUNCH_PHASE={phase:?}");
    let ok = match expect {
        "migrated" => matches!(result, PunchResult::Migrated { .. }),
        e if e.starts_with("stayed:") => {
            let want = &e["stayed:".len()..];
            match &result {
                PunchResult::StayedOnRelay { reason } => format!("{reason:?}") == want,
                _ => false,
            }
        }
        _ => false,
    };
    if ok {
        println!("E4_EXPECT=met");
        std::process::exit(0);
    } else {
        println!("E4_EXPECT=NOT-met (expect {expect})");
        std::process::exit(1);
    }
}

//! E3 回归场景 `regression.session-outcome-exactly-once` 的可执行驱动。
//!
//! 由 `scenarios/regression/session_outcome_exactly_once.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus-session --example session_outcome_exactly_once -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出，供 harness 按路径求值）；
//! 不带 `--json` 时打印人类可读摘要。
//!
//! 语义（与场景 [given]/[when] 对应）：多次竞争运行——每轮三个竞争源
//! （worker_success / cancel_requested / network_disconnect）以轮换顺序尝试
//! 提交 `TerminalOutcome`。`SessionOwner` 的 commit-once 守卫保证恰一次成功，
//! 其余源得到 `AlreadyTerminated`；随后 Owner 清理到 `Disposed`。

#![forbid(unsafe_code)]

use nexus_domain::{LifecyclePhase, NexusError, ProviderId, SessionId, TerminalOutcome};
use nexus_session::{SessionError, SessionOwner};

/// 竞争轮数（足够暴露任何违反 commit-once 的状态泄漏）。
const RACES: u64 = 10_000;

/// 竞争源：与场景 [given].race 一一对应。
enum RaceSource {
    /// worker 成功：提交 `Completed`。
    WorkerSuccess,
    /// 用户/外部取消：记录取消事件后提交 `Cancelled`。
    CancelRequested,
    /// 网络断链：提交 `Failed(ConnectivityEstablishmentFailed)`。
    NetworkDisconnect,
}

impl RaceSource {
    fn attempt(self, owner: &mut SessionOwner) -> Result<(), SessionError> {
        match self {
            Self::WorkerSuccess => owner.commit_outcome(TerminalOutcome::Completed),
            Self::CancelRequested => {
                let _ = owner.request_cancellation("user abort".into());
                owner.commit_outcome(TerminalOutcome::Cancelled)
            }
            Self::NetworkDisconnect => owner.commit_outcome(TerminalOutcome::Failed(
                NexusError::ConnectivityEstablishmentFailed {
                    provider: ProviderId("p1".into()),
                    reason: "network disconnect".into(),
                },
            )),
        }
    }
}

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match run_races() {
        Ok((commit_count, phase)) => {
            let json = format!(
                "{{\"verdict\":\"PASS\",\"terminal_outcome_commit_count\":{},\
\"lifecycle_phase\":{},\"races_run\":{},\"commit_success_total\":{}}}",
                commit_count,
                json_str(&phase),
                RACES,
                commit_count * RACES,
            );
            if as_json {
                println!("{json}");
            } else {
                println!("Session outcome exactly-once flow OK: {json}");
            }
        }
        Err(err) => {
            eprintln!("session_outcome_exactly_once failed: {err}");
            std::process::exit(1);
        }
    }
}

/// 每轮竞争都断言：恰一次提交 + 最终 `Disposed`。返回每轮提交次数（=1）
/// 与最终 phase（=Disposed）。
fn run_races() -> Result<(u64, String), String> {
    let mut total_success = 0u64;
    let mut final_phase = String::new();
    for round in 0..RACES {
        let mut owner = SessionOwner::new(SessionId(format!("race-{round}")));
        owner
            .transition_phase(LifecyclePhase::Active)
            .map_err(|e| e.to_string())?;

        // 三个竞争源以轮换顺序尝试提交；恰一次成功，其余均被 commit-once 拒绝。
        let mut sources = vec![
            RaceSource::WorkerSuccess,
            RaceSource::CancelRequested,
            RaceSource::NetworkDisconnect,
        ];
        sources.rotate_left((round % 3) as usize);

        let mut success = 0u64;
        for source in sources {
            match source.attempt(&mut owner) {
                Ok(()) => success += 1,
                Err(SessionError::AlreadyTerminated { .. }) => {}
                Err(other) => return Err(format!("unexpected session error: {other}")),
            }
        }
        if success != 1 {
            return Err(format!(
                "round {round}: expected exactly one terminal outcome, got {success}"
            ));
        }
        if owner.committed_outcome().is_none() {
            return Err(format!("round {round}: no terminal outcome committed"));
        }

        // 竞争结束后 Owner 清理到 Disposed（Outcome 确定后仍可执行 cleanup）。
        owner
            .transition_phase(LifecyclePhase::Draining)
            .map_err(|e| e.to_string())?;
        owner
            .transition_phase(LifecyclePhase::Disposed)
            .map_err(|e| e.to_string())?;
        if owner.phase() != LifecyclePhase::Disposed {
            return Err(format!("round {round}: phase not Disposed"));
        }

        total_success += success;
        final_phase = format!("{:?}", owner.phase());
    }
    // 每轮恰一次 → 每轮计数为 1。
    Ok((total_success / RACES, final_phase))
}

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

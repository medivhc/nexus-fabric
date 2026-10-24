//! SessionManager：流→会话映射的 Owner（AGENTS.md §13/§14）。
//!
//! - 后台建连任务：`CancellationToken` + `JoinSet`（此处为 `Vec<JoinHandle>`）+ Reaper（`Drop`）。
//! - Exactly-One Outcome：`SessionOwner::commit_outcome` 是 TerminalOutcome 唯一写入者。
//! - `process_one()` 永不阻塞：建连在后台线程，`pump()` 非阻塞回填事件。

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use nexus_domain::{FlowContext, FlowOrigin, LifecyclePhase, ResourceId, SessionId};
use nexus_planner::Planned;
use nexus_policy::PolicyTraceEntry;
use nexus_session::{CancelToken, SessionOwner};

use crate::chain::{ChainDeps, ChainError, run_first_packet_chain};
use crate::flow::{FlowDecision, FlowKey, FlowPhase, FlowTable, IpProto};

/// 建连器：Composition Root 实现（生产接 domain-runtime 的建连路径；测试用 fake）。
///
/// 在后台线程调用；实现必须是快速可取消的（检查点轮询建议）。
pub trait ConnectivityEstablisher: Send {
    /// 建立连接；Ok(locator) / Err(reason)。
    fn establish(&mut self, session_id: &SessionId, planned: &Planned) -> Result<String, String>;
}

/// 后台建连事件（worker → Owner，`pump()` 非阻塞消费）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EstablishEvent {
    Established {
        session_id: SessionId,
        locator: String,
    },
    Failed {
        session_id: SessionId,
        reason: String,
    },
}

/// 发往 dataplane 的信号（`drain_signals()` 取走）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowSignal {
    /// TCP 建连失败：对该流发 RST（不静默黑洞）。
    TcpReset { key: FlowKey },
    /// 流进 Draining：dataplane 终结本地传输会话（smoltcp/UDP 状态）。
    TearDown { key: FlowKey, session_id: SessionId },
}

/// SessionManager 配置。
#[derive(Debug, Clone)]
pub struct SessionManagerConfig {
    /// 空闲超时（流进 Draining）。
    pub idle_timeout: Duration,
}

impl Default for SessionManagerConfig {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(300),
        }
    }
}

/// 流→会话映射的 Owner。
///
/// 单线程使用（dataplane 包线程）；后台建连线程只经 channel 发事件。
pub struct SessionManager {
    config: SessionManagerConfig,
    table: FlowTable,
    sessions: HashMap<SessionId, SessionOwner>,
    plans: HashMap<SessionId, Planned>,
    session_to_key: HashMap<SessionId, FlowKey>,
    /// 每个会话的首包链 policy trace（E4 `decision_trace_non_empty` 证明）。
    policy_traces: HashMap<SessionId, Vec<PolicyTraceEntry>>,
    cancel: CancelToken,
    event_tx: mpsc::Sender<EstablishEvent>,
    event_rx: mpsc::Receiver<EstablishEvent>,
    workers: Vec<JoinHandle<()>>,
    establisher: Arc<Mutex<Box<dyn ConnectivityEstablisher>>>,
    signals: VecDeque<FlowSignal>,
    next_id: u64,
    /// 首包链总运行次数（E4 `no_planner_in_hot_path` 证明：快路径不得增加此计数）。
    pub planner_calls: u64,
}

impl SessionManager {
    /// 创建 Owner；`establisher` 由 Composition Root 注入。
    #[must_use]
    pub fn new(
        config: SessionManagerConfig,
        establisher: Box<dyn ConnectivityEstablisher>,
    ) -> Self {
        let (event_tx, event_rx) = mpsc::channel();
        Self {
            config,
            table: FlowTable::new(),
            sessions: HashMap::new(),
            plans: HashMap::new(),
            session_to_key: HashMap::new(),
            policy_traces: HashMap::new(),
            cancel: CancelToken::new(),
            event_tx,
            event_rx,
            workers: Vec::new(),
            establisher: Arc::new(Mutex::new(establisher)),
            signals: VecDeque::new(),
            next_id: 0,
            planner_calls: 0,
        }
    }

    #[must_use]
    pub fn flow_count(&self) -> usize {
        self.table.len()
    }

    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    #[must_use]
    pub fn get_phase(&self, key: &FlowKey) -> Option<FlowPhase> {
        self.table.get(key).map(|e| e.phase)
    }

    /// 包入口（dataplane `process_one()` 调用，永不阻塞）。
    ///
    /// - `is_syn`：TCP SYN 标志（UDP 忽略）。
    /// - `packet`：完整 IPv4 包（UDP Allocating 期入缓冲时需要）。
    pub fn on_packet(
        &mut self,
        key: FlowKey,
        packet: &[u8],
        is_syn: bool,
        deps: &ChainDeps,
        now: Instant,
    ) -> FlowDecision {
        self.on_packet_with_hint(key, packet, is_syn, deps, now, None)
    }

    /// 同 [`Self::on_packet`]，额外带上规则引擎选出的出站 tag（Q3 `egress_hint`）。
    pub fn on_packet_with_hint(
        &mut self,
        key: FlowKey,
        packet: &[u8],
        is_syn: bool,
        deps: &ChainDeps,
        now: Instant,
        egress_hint: Option<&str>,
    ) -> FlowDecision {
        // 快路径：已建流。
        if let Some(entry) = self.table.get_mut(&key) {
            entry.last_seen = now;
            match entry.phase {
                FlowPhase::Active => {
                    // 已建流：不再调 Planner（hot path 纯洁性由 planner_calls 计数证明）。
                    return FlowDecision::Forward {
                        session_id: entry.session_id.clone(),
                    };
                }
                FlowPhase::Allocating => {
                    // 建连期：TCP 由 smoltcp 缓冲（继续本地流程）；UDP 入有界缓冲。
                    if key.proto == IpProto::Udp {
                        let sid = entry.session_id.clone();
                        let buffered = entry
                            .udp_buffer
                            .as_mut()
                            .map(|b| b.push(packet.to_vec()))
                            .unwrap_or(false);
                        if buffered {
                            return FlowDecision::Buffered { session_id: sid };
                        }
                        return FlowDecision::Drop {
                            reason: "udp buffer over bound",
                        };
                    }
                    return FlowDecision::Forward {
                        session_id: entry.session_id.clone(),
                    };
                }
                FlowPhase::Draining | FlowPhase::Disposed => {
                    return FlowDecision::Drop {
                        reason: "flow draining",
                    };
                }
            }
        }

        // 新流：TCP 非 SYN 包无流表项 → 丢弃（与现状一致，不为它建会话）。
        if key.proto == IpProto::Tcp && !is_syn {
            return FlowDecision::Drop {
                reason: "tcp non-syn without flow",
            };
        }

        // 首包链（同步纯函数）。
        let flow = FlowContext {
            origin: FlowOrigin::VirtualPacketInterface,
            resource: ResourceId("internet-access".into()),
            destination: format!(
                "{}.{}.{}.{}:{}",
                key.dst_ip[0], key.dst_ip[1], key.dst_ip[2], key.dst_ip[3], key.dst_port
            ),
            profile: "Balanced".into(),
            egress_hint: egress_hint.map(str::to_string),
        };
        let outcome = match run_first_packet_chain(&flow, deps) {
            Ok(o) => o,
            Err(ChainError::PolicyRejected { .. }) => {
                return FlowDecision::Drop {
                    reason: "policy rejected",
                };
            }
            Err(ChainError::PlanFailed { .. }) => {
                return FlowDecision::Drop {
                    reason: "no provider",
                };
            }
        };
        self.planner_calls += 1;

        // 创建 Session（Owner 唯一写入者），phase=Allocating。
        let session_id = self.alloc_session_id();
        let owner = SessionOwner::new(session_id.clone());
        // SessionOwner::new 初始 phase 即 Allocating（不断言，由 nexus-session 保证）。
        self.sessions.insert(session_id.clone(), owner);
        self.plans
            .insert(session_id.clone(), outcome.planned.clone());
        self.policy_traces
            .insert(session_id.clone(), outcome.policy_trace);

        // 流表项（幂等：重传 SYN 走上面的快路径，不会重复建）。
        let entry = self.table.insert(key, session_id.clone(), now);
        self.session_to_key.insert(session_id.clone(), key);
        debug_assert_eq!(entry.chain_runs, 1);

        // UDP 首包入缓冲。
        if key.proto == IpProto::Udp {
            let ok = entry
                .udp_buffer
                .as_mut()
                .map(|b| b.push(packet.to_vec()))
                .unwrap_or(false);
            if !ok {
                return FlowDecision::Drop {
                    reason: "udp buffer over bound",
                };
            }
        }

        // 后台建连（D5）。
        self.spawn_establish(session_id.clone(), outcome.planned);

        if key.proto == IpProto::Udp {
            FlowDecision::Buffered {
                session_id: session_id.clone(),
            }
        } else {
            FlowDecision::NewSession { session_id }
        }
    }

    /// 非阻塞回填后台建连事件（每轮 `process_one()` 后调用）。
    pub fn pump(&mut self) {
        while let Ok(ev) = self.event_rx.try_recv() {
            match ev {
                EstablishEvent::Established {
                    session_id,
                    locator,
                } => {
                    if let Some(key) = self.key_of_session(&session_id) {
                        if let Some(entry) = self.table.get_mut(&key) {
                            entry.phase = FlowPhase::Active;
                        }
                    }
                    if let Some(owner) = self.sessions.get_mut(&session_id) {
                        let _ = owner.record_connectivity_established(locator);
                        let _ = owner.transition_phase(LifecyclePhase::Active);
                    }
                }
                EstablishEvent::Failed { session_id, reason } => {
                    let _ = reason;
                    if let Some(key) = self.key_of_session(&session_id) {
                        if let Some(entry) = self.table.get_mut(&key) {
                            entry.phase = FlowPhase::Draining;
                        }
                        let sig = if self.proto_of(&key) == Some(IpProto::Tcp) {
                            FlowSignal::TcpReset { key }
                        } else {
                            FlowSignal::TearDown {
                                key,
                                session_id: session_id.clone(),
                            }
                        };
                        self.signals.push_back(sig);
                    }
                    if let Some(owner) = self.sessions.get_mut(&session_id) {
                        let _ = owner.record_connectivity_failed(
                            String::new(),
                            "establish failed".to_string(),
                        );
                    }
                }
            }
        }
    }

    /// 取走待 dataplane 执行的信号。
    pub fn drain_signals(&mut self) -> Vec<FlowSignal> {
        self.signals.drain(..).collect()
    }

    /// 空闲扫描：超时流进 Draining，对应 Session 也进 Draining。
    /// 返回进入 Draining 的 session 数量。
    pub fn sweep_idle(&mut self, now: Instant) -> usize {
        let drained = self.table.sweep_idle(self.config.idle_timeout, now);
        for sid in &drained {
            if let Some(owner) = self.sessions.get_mut(sid) {
                let _ = owner.transition_phase(LifecyclePhase::Draining);
            }
            if let Some(key) = self.key_of_session(sid) {
                self.signals.push_back(FlowSignal::TearDown {
                    key,
                    session_id: sid.clone(),
                });
            }
        }
        // Draining 的流标记 Disposed，等待 GC（dataplane 执行 TearDown 后调 dispose_flow）。
        drained.len()
    }

    /// dataplane 执行完 TearDown 后调用：流进 Disposed。
    pub fn dispose_flow(&mut self, key: &FlowKey) {
        // 找到 session_id，清理所有相关 map。
        let session_id = self.table.get(key).map(|e| e.session_id.clone());
        if let Some(sid) = session_id {
            self.sessions.remove(&sid);
            self.plans.remove(&sid);
            self.session_to_key.remove(&sid);
            self.policy_traces.remove(&sid);
        }
        if let Some(entry) = self.table.get_mut(key) {
            entry.phase = FlowPhase::Disposed;
        }
        self.table.gc_disposed();
    }

    /// 取出 UDP 缓冲（会话 Active 后 flush 用）。
    pub fn take_udp_buffer(&mut self, key: &FlowKey) -> Vec<Vec<u8>> {
        self.table
            .get_mut(key)
            .and_then(|e| e.udp_buffer.as_mut())
            .map(|b| b.drain())
            .unwrap_or_default()
    }

    /// 取出所有 Active 流的 UDP 缓冲（dataplane flush 用）。
    pub fn take_udp_buffers_for_active(&mut self) -> Vec<(FlowKey, Vec<Vec<u8>>)> {
        self.table.drain_udp_buffers_for_active()
    }

    #[must_use]
    pub fn udp_dropped(&self, key: &FlowKey) -> u64 {
        self.table
            .get(key)
            .and_then(|e| e.udp_buffer.as_ref())
            .map(|b| b.dropped_over_bound())
            .unwrap_or(0)
    }

    /// 该会话的首包链 policy trace 长度（E4 证明用）。
    #[must_use]
    pub fn policy_trace_len(&self, session_id: &SessionId) -> usize {
        self.policy_traces
            .get(session_id)
            .map(|t| t.len())
            .unwrap_or(0)
    }

    /// 流绑定的 session id（dataplane 门控用）。
    #[must_use]
    pub fn session_for_key(&self, key: &FlowKey) -> Option<SessionId> {
        self.table.get(key).map(|e| e.session_id.clone())
    }

    /// 设置空闲超时（E4/测试用）。
    pub fn set_idle_timeout(&mut self, timeout: Duration) {
        self.config.idle_timeout = timeout;
    }

    /// 路径切换事件（D6）：底层 direct→relay 切换时，会话记录新 locator，
    /// 流表项不变、不断流、不重跑 Planner。
    ///
    /// 返回 false = 会话不存在。
    pub fn on_path_switch(&mut self, session_id: &SessionId, new_locator: String) -> bool {
        match self.sessions.get_mut(session_id) {
            Some(owner) => owner.record_connectivity_established(new_locator).is_ok(),
            None => false,
        }
    }

    fn alloc_session_id(&mut self) -> SessionId {
        let id = SessionId(format!("flow-sess-{:016x}", self.next_id));
        self.next_id += 1;
        id
    }

    fn key_of_session(&self, session_id: &SessionId) -> Option<FlowKey> {
        self.session_to_key.get(session_id).copied()
    }

    fn proto_of(&self, key: &FlowKey) -> Option<IpProto> {
        self.table.get(key).map(|e| e.key.proto)
    }

    fn spawn_establish(&mut self, session_id: SessionId, planned: Planned) {
        let tx = self.event_tx.clone();
        let cancel = self.cancel.clone();
        let establisher = Arc::clone(&self.establisher);
        let handle = thread::spawn(move || {
            if cancel.is_cancelled() {
                return;
            }
            let result = establisher
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .establish(&session_id, &planned);
            if cancel.is_cancelled() {
                return;
            }
            let ev = match result {
                Ok(locator) => EstablishEvent::Established {
                    session_id,
                    locator,
                },
                Err(reason) => EstablishEvent::Failed { session_id, reason },
            };
            let _ = tx.send(ev);
        });
        self.workers.push(handle);
    }
}

impl Drop for SessionManager {
    /// Reaper：取消所有建连任务并回收线程（AGENTS.md §13）。
    fn drop(&mut self) {
        self.cancel.cancel();
        for h in self.workers.drain(..) {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use nexus_domain::ProviderId;
    use nexus_planner::PlanningSnapshot;
    use nexus_policy::PolicyEngine;
    use nexus_registry::{ProviderRecord, Registry};

    use super::*;
    use crate::chain::ChainDeps;

    struct OkEstablisher;
    impl ConnectivityEstablisher for OkEstablisher {
        fn establish(&mut self, _sid: &SessionId, _p: &Planned) -> Result<String, String> {
            Ok("edge-a.exit".into())
        }
    }

    struct FailEstablisher;
    impl ConnectivityEstablisher for FailEstablisher {
        fn establish(&mut self, _sid: &SessionId, _p: &Planned) -> Result<String, String> {
            Err("no route".into())
        }
    }

    fn test_deps() -> ChainDeps {
        ChainDeps {
            policy: PolicyEngine::default_network(),
            build_snapshot: Box::new(|flow: &FlowContext| {
                let mut registry = Registry::new();
                registry.register(ProviderRecord {
                    id: ProviderId("provider-edge-a".into()),
                    resource: flow.resource.clone(),
                    placement: "local-edge".into(),
                    locator: "edge-a.exit".into(),
                    capabilities: vec!["internet-access".into()],
                    present: true,
                });
                let probe = PolicyEngine::default_network().evaluate(flow);
                PlanningSnapshot::new(
                    registry.candidates(&flow.resource),
                    probe.decision.constraints,
                )
            }),
            measure: Box::new(|_| None),
        }
    }

    fn tcp_key() -> FlowKey {
        FlowKey {
            src_ip: [192, 168, 1, 2],
            src_port: 54321,
            dst_ip: [93, 184, 216, 34],
            dst_port: 443,
            proto: IpProto::Tcp,
        }
    }

    fn udp_key() -> FlowKey {
        FlowKey {
            proto: IpProto::Udp,
            dst_port: 53,
            ..tcp_key()
        }
    }

    fn tcp_syn_packet() -> Vec<u8> {
        // IPv4(20) + TCP(20)，SYN 置位。
        let mut pkt = vec![0x45u8, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0];
        pkt.extend_from_slice(&[192, 168, 1, 2, 93, 184, 216, 34]);
        pkt.extend_from_slice(&[0xd4, 0x31, 0x01, 0xbb]); // ports
        pkt.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0, 0]); // SYN
        pkt.extend_from_slice(&[0u8; 8]);
        pkt
    }

    fn wait_pump(mgr: &mut SessionManager) {
        // 给后台线程一点时间完成 establish（fake 极快，50ms 足够）。
        for _ in 0..100 {
            mgr.pump();
            if mgr.get_phase(&tcp_key()) == Some(FlowPhase::Active)
                || !mgr.drain_signals().is_empty()
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        mgr.pump();
    }

    #[test]
    fn syn_creates_session_exactly_once() {
        let t0 = Instant::now();
        let mut mgr = SessionManager::new(SessionManagerConfig::default(), Box::new(OkEstablisher));
        let deps = test_deps();
        let pkt = tcp_syn_packet();
        let d1 = mgr.on_packet(tcp_key(), &pkt, true, &deps, t0);
        let sid = match d1 {
            FlowDecision::NewSession { session_id } => session_id,
            other => panic!("expected NewSession, got {other:?}"),
        };
        assert_eq!(mgr.planner_calls, 1);
        // 重传 SYN：走快路径（Allocating），不重复建会话、不重复调链。
        let d2 = mgr.on_packet(tcp_key(), &pkt, true, &deps, t0);
        assert!(
            matches!(&d2, FlowDecision::Forward { session_id } if session_id == &sid),
            "{d2:?}"
        );
        assert_eq!(mgr.planner_calls, 1, "重传 SYN 不得重复跑首包链");
        assert_eq!(mgr.session_count(), 1);
    }

    #[test]
    fn tcp_non_syn_without_flow_is_dropped() {
        let t0 = Instant::now();
        let mut mgr = SessionManager::new(SessionManagerConfig::default(), Box::new(OkEstablisher));
        let deps = test_deps();
        let d = mgr.on_packet(tcp_key(), &tcp_syn_packet(), false, &deps, t0);
        assert!(matches!(d, FlowDecision::Drop { .. }), "{d:?}");
        assert_eq!(mgr.session_count(), 0);
    }

    #[test]
    fn establish_success_activates_flow() {
        let t0 = Instant::now();
        let mut mgr = SessionManager::new(SessionManagerConfig::default(), Box::new(OkEstablisher));
        let deps = test_deps();
        let pkt = tcp_syn_packet();
        let sid = match mgr.on_packet(tcp_key(), &pkt, true, &deps, t0) {
            FlowDecision::NewSession { session_id } => session_id,
            other => panic!("{other:?}"),
        };
        wait_pump(&mut mgr);
        // pump 后应为 Active（fake 建立极快）。
        // 注意：wait_pump 内已 pump；这里再确认。
        assert_eq!(mgr.get_phase(&tcp_key()), Some(FlowPhase::Active));
        // Active 后后续包走快路径，planner_calls 不变。
        let calls = mgr.planner_calls;
        let d = mgr.on_packet(tcp_key(), &pkt, false, &deps, t0);
        assert!(
            matches!(&d, FlowDecision::Forward { session_id } if session_id == &sid),
            "{d:?}"
        );
        assert_eq!(mgr.planner_calls, calls, "快路径不得调 Planner");
    }

    #[test]
    fn establish_failure_drains_and_signals_reset() {
        let t0 = Instant::now();
        let mut mgr =
            SessionManager::new(SessionManagerConfig::default(), Box::new(FailEstablisher));
        let deps = test_deps();
        let pkt = tcp_syn_packet();
        mgr.on_packet(tcp_key(), &pkt, true, &deps, t0);
        // 等待失败事件回填（不提前 drain 信号）。
        for _ in 0..200 {
            mgr.pump();
            if mgr.get_phase(&tcp_key()) == Some(FlowPhase::Draining) {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        mgr.pump();
        let signals = mgr.drain_signals();
        assert_eq!(mgr.get_phase(&tcp_key()), Some(FlowPhase::Draining));
        assert!(
            signals
                .iter()
                .any(|s| matches!(s, FlowSignal::TcpReset { key } if *key == tcp_key())),
            "TCP 建连失败必须发 RST 信号：{signals:?}"
        );
    }

    #[test]
    fn udp_first_packet_buffered_and_bounded() {
        let t0 = Instant::now();
        let mut mgr = SessionManager::new(SessionManagerConfig::default(), Box::new(OkEstablisher));
        let deps = test_deps();
        let pkt = vec![0u8; 32];
        // 首包 → Buffered（会话创建）。
        let d = mgr.on_packet(udp_key(), &pkt, false, &deps, t0);
        let sid = match d {
            FlowDecision::Buffered { session_id } => session_id,
            other => panic!("{other:?}"),
        };
        assert_eq!(mgr.session_count(), 1);
        // 继续塞包直到超 bound。
        let mut got_drop = false;
        for _ in 0..40 {
            match mgr.on_packet(udp_key(), &pkt, false, &deps, t0) {
                FlowDecision::Buffered { .. } => {}
                FlowDecision::Drop { .. } => {
                    got_drop = true;
                    break;
                }
                other => panic!("{other:?}"),
            }
        }
        assert!(got_drop, "超 bound 必须丢弃");
        assert!(mgr.udp_dropped(&udp_key()) > 0);
        // 会话仍在（Allocating），不因丢包而死。
        assert!(mgr.get_phase(&udp_key()).is_some());
        let _ = sid;
    }

    #[test]
    fn sweep_idle_drains_stale_flows() {
        let config = SessionManagerConfig {
            idle_timeout: Duration::from_millis(1),
        };
        let mut mgr = SessionManager::new(config, Box::new(OkEstablisher));
        let deps = test_deps();
        let t0 = Instant::now();
        mgr.on_packet(tcp_key(), &tcp_syn_packet(), true, &deps, t0);
        // 虚拟时间：只随传入的 now 老化，不依赖墙钟。
        assert_eq!(mgr.sweep_idle(t0), 0);
        let n = mgr.sweep_idle(t0 + Duration::from_millis(5));
        assert_eq!(n, 1);
        assert_eq!(mgr.get_phase(&tcp_key()), Some(FlowPhase::Draining));
        // TearDown 信号发出。
        let signals = mgr.drain_signals();
        assert!(
            signals
                .iter()
                .any(|s| matches!(s, FlowSignal::TearDown { .. })),
            "{signals:?}"
        );
        // dataplane 执行完 TearDown 后 dispose。
        mgr.dispose_flow(&tcp_key());
        assert_eq!(mgr.flow_count(), 0);
    }

    /// 性能基线（R4）：快路径与首包链的耗时分布。
    ///
    /// `#[ignore]`：不进常规 CI；`cargo test -p nexus-flow-session -- --ignored --nocapture` 手动跑。
    #[test]
    #[ignore]
    fn perf_baseline_fast_path_and_chain() {
        let mut mgr = SessionManager::new(SessionManagerConfig::default(), Box::new(OkEstablisher));
        let deps = test_deps();
        let pkt = tcp_syn_packet();
        let t0 = Instant::now();
        // 预热：建流并等 Active。
        mgr.on_packet(tcp_key(), &pkt, true, &deps, t0);
        for _ in 0..200 {
            mgr.pump();
            if mgr.get_phase(&tcp_key()) == Some(FlowPhase::Active) {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }

        // 快路径：已建流 on_packet（查表+Forward 决策）。
        const N: usize = 20_000;
        let mut times = Vec::with_capacity(N);
        for _ in 0..N {
            let t = Instant::now();
            let d = mgr.on_packet(tcp_key(), &pkt, false, &deps, t0);
            times.push(t.elapsed());
            assert!(matches!(d, FlowDecision::Forward { .. }));
        }
        times.sort();
        let p50 = times[N / 2].as_nanos();
        let p99 = times[N * 99 / 100].as_nanos();
        println!("fast_path on_packet: p50={p50}ns p99={p99}ns (target p99 < 2000ns)");

        // 首包链：Policy+Planner 同步部分（直接调 run_first_packet_chain）。
        let flow = FlowContext {
            origin: FlowOrigin::VirtualPacketInterface,
            resource: ResourceId("internet-access".into()),
            destination: "93.184.216.34:443".into(),
            profile: "Balanced".into(),
            egress_hint: None,
        };
        let mut chain_times = Vec::with_capacity(1000);
        for _ in 0..1000 {
            let t = Instant::now();
            let _ = run_first_packet_chain(&flow, &deps).expect("ok");
            chain_times.push(t.elapsed());
        }
        chain_times.sort();
        let cp50 = chain_times[500].as_nanos();
        let cp99 = chain_times[990].as_nanos();
        println!("first_packet_chain: p50={cp50}ns p99={cp99}ns (target p99 < 500000ns)");
    }
}

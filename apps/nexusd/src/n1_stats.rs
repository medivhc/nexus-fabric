//! N1 计数面与 `/localapi/v0/n1/stats`（spec §5.6/§7，WP6）。
//!
//! 沿 `nat_chunk_stats.rs` 的既有模式：`AtomicU64` 计数 + `OnceLock` 发布 +
//! 纯 JSON 构建函数（便于精确值单测）。冻结口径（§5.6/§11.4）：
//!
//! - `recv_chunks` 仍是 direct-only（ERRATA-1）：本模块不触碰
//!   `nat_chunk_stats`，N1 投递只看 `n1.rx.*` / `n1.egress.*`；
//! - `egress.connect_ok` 只计「本地 socket 已产出证据」的连接（静默连接
//!   少计、不多计）；`egress.bytes_to_local` 计 DATA 载荷进入 relay 写路径
//!   的字节（正常缓冲下等于写入本地 socket）——按 WP5 §5.3 的可观测边界
//!   原样表述，不冒充逐字节严格语义。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use nexus_network::n1::N1PeerId;
use serde_json::{Value, json};

/// 入站拒绝分类（spec §6.1/§7；reason 进日志，计数只分大类）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum N1InboundReject {
    EmptyDatagram,
    AmbiguousKind { first: u8 },
    QueueFull,
    BadFrame { len: usize },
    UnknownStream { stream_id: u32 },
    AdmissionDenied { peer: N1PeerId },
    DuplicatePeer { peer: N1PeerId },
    ConnClosed,
}

/// egress relay 计数事件（spec §5.6/§7 `egress.*`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum N1EgressEvent {
    /// SYN 帧交给 relay（含重复 SYN / 短 SYN；机制侧另有 `short_syn_dropped`）。
    Syn,
    /// 已观测到本地连接建立成功的证据（本地 socket 读出字节或 FIN）。
    ConnectOk,
    /// relay 的 connect worker 报告失败（机制侧 `TcpRelayStats::connect_failed`）。
    ConnectFailed,
    /// 进入本地 socket 写路径的字节（§5.6 口径；边界见模块文档）。
    BytesToLocal(usize),
    /// 从本地 socket 读出并交给回程的字节（§5.6 口径）。
    BytesFromLocal(usize),
    /// `conns + pending >= MAX_TCP_CONNS`（1024）；该 SYN 已回 RST。
    TableFull,
}

/// 消费侧分派目标（spec §5.6/§7）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum N1DispatchTarget {
    /// 本节点发起的流：回程帧注入 TCP 终结器。
    Terminator,
    /// 对端发起的流：本节点是 egress，交 relay。
    Relay,
    /// terminator 与 relay 都不认识该流。
    Unknown,
}

/// listener 运行状态（spec §7；`/n1/stats` 的 `runtime`/`listener` 由此派生）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum N1ListenerState {
    Disabled { reason: &'static str },
    BindFailed { reason: String },
    Listening { addr: std::net::SocketAddr },
}

/// N1 计数（spec §5.6/§7）。
///
/// `rx_rejected_admission` / `rx_conn_closed` / `rx_transient_errors` 是 §6.1
/// 分类的细分观测（不进 §5.6 JSON 的固定形状）；其余字段与 JSON 一一对应。
#[derive(Debug, Default)]
pub struct N1Stats {
    rx_datagrams: AtomicU64,
    rx_bytes: AtomicU64,
    rx_raw_ip: AtomicU64,
    rx_stream_frames: AtomicU64,
    rx_rejected: AtomicU64,
    rx_rejected_admission: AtomicU64,
    rx_queue_full: AtomicU64,
    rx_ambiguous: AtomicU64,
    rx_conn_closed: AtomicU64,
    rx_transient_errors: AtomicU64,
    dispatch_to_terminator: AtomicU64,
    dispatch_to_relay: AtomicU64,
    dispatch_bad_frame: AtomicU64,
    dispatch_unknown_stream: AtomicU64,
    egress_syn: AtomicU64,
    egress_connect_ok: AtomicU64,
    egress_connect_failed: AtomicU64,
    egress_bytes_to_local: AtomicU64,
    egress_bytes_from_local: AtomicU64,
    egress_table_full: AtomicU64,
    tx_frames: AtomicU64,
    tx_errors: AtomicU64,
}

/// `N1Stats` 的快照（字段名与 §5.6 的 `n1.*` 点路径对齐）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct N1StatsSnapshot {
    pub rx_datagrams: u64,
    pub rx_bytes: u64,
    pub rx_raw_ip: u64,
    pub rx_stream_frames: u64,
    pub rx_rejected: u64,
    pub rx_rejected_admission: u64,
    pub rx_queue_full: u64,
    pub rx_ambiguous: u64,
    pub rx_conn_closed: u64,
    pub rx_transient_errors: u64,
    pub dispatch_to_terminator: u64,
    pub dispatch_to_relay: u64,
    pub dispatch_bad_frame: u64,
    pub dispatch_unknown_stream: u64,
    pub egress_syn: u64,
    pub egress_connect_ok: u64,
    pub egress_connect_failed: u64,
    pub egress_bytes_to_local: u64,
    pub egress_bytes_from_local: u64,
    pub egress_table_full: u64,
    pub tx_frames: u64,
    pub tx_errors: u64,
}

impl N1Stats {
    #[must_use]
    pub fn snapshot(&self) -> N1StatsSnapshot {
        N1StatsSnapshot {
            rx_datagrams: self.rx_datagrams.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            rx_raw_ip: self.rx_raw_ip.load(Ordering::Relaxed),
            rx_stream_frames: self.rx_stream_frames.load(Ordering::Relaxed),
            rx_rejected: self.rx_rejected.load(Ordering::Relaxed),
            rx_rejected_admission: self.rx_rejected_admission.load(Ordering::Relaxed),
            rx_queue_full: self.rx_queue_full.load(Ordering::Relaxed),
            rx_ambiguous: self.rx_ambiguous.load(Ordering::Relaxed),
            rx_conn_closed: self.rx_conn_closed.load(Ordering::Relaxed),
            rx_transient_errors: self.rx_transient_errors.load(Ordering::Relaxed),
            dispatch_to_terminator: self.dispatch_to_terminator.load(Ordering::Relaxed),
            dispatch_to_relay: self.dispatch_to_relay.load(Ordering::Relaxed),
            dispatch_bad_frame: self.dispatch_bad_frame.load(Ordering::Relaxed),
            dispatch_unknown_stream: self.dispatch_unknown_stream.load(Ordering::Relaxed),
            egress_syn: self.egress_syn.load(Ordering::Relaxed),
            egress_connect_ok: self.egress_connect_ok.load(Ordering::Relaxed),
            egress_connect_failed: self.egress_connect_failed.load(Ordering::Relaxed),
            egress_bytes_to_local: self.egress_bytes_to_local.load(Ordering::Relaxed),
            egress_bytes_from_local: self.egress_bytes_from_local.load(Ordering::Relaxed),
            egress_table_full: self.egress_table_full.load(Ordering::Relaxed),
            tx_frames: self.tx_frames.load(Ordering::Relaxed),
            tx_errors: self.tx_errors.load(Ordering::Relaxed),
        }
    }

    /// 计入 `rx.rejected{reason}`（reason 进日志；计数只分大类，spec §5.6）。
    pub fn record_rx_rejected(&self, reason: N1InboundReject) {
        self.rx_rejected.fetch_add(1, Ordering::Relaxed);
        if matches!(reason, N1InboundReject::AdmissionDenied { .. }) {
            self.rx_rejected_admission.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// `rx.datagrams` + `rx.bytes`：reader 从 `recv_datagram` 读到的（§5.6）。
    pub fn record_rx_datagram(&self, len: usize) {
        self.rx_datagrams.fetch_add(1, Ordering::Relaxed);
        self.rx_bytes
            .fetch_add(u64::try_from(len).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// `rx.raw_ip`：demux 判为 raw IPv4/IPv6。
    pub fn record_rx_raw_ip(&self) {
        self.rx_raw_ip.fetch_add(1, Ordering::Relaxed);
    }

    /// `rx.stream_frames`：demux 判为 STREAM 帧。
    pub fn record_rx_stream_frame(&self) {
        self.rx_stream_frames.fetch_add(1, Ordering::Relaxed);
    }

    /// `rx.queue_full`：入站队列满事件（含 ConnUp/ConnDown 重投；是否同时
    /// 计 `rx.rejected{queue_full}` 由调用方按 §6.1 决定——只有被丢弃的
    /// **数据报**才算 rejected）。
    pub fn record_rx_queue_full(&self) {
        self.rx_queue_full.fetch_add(1, Ordering::Relaxed);
    }

    /// `rx.ambiguous`（`rx.rejected` 由 `record_rx_rejected` 单独累计）。
    pub fn record_rx_ambiguous(&self) {
        self.rx_ambiguous.fetch_add(1, Ordering::Relaxed);
    }

    /// `rx.conn_closed`：不算 rejected（§6.1 ConnClosed 行）。
    pub fn record_rx_conn_closed(&self) {
        self.rx_conn_closed.fetch_add(1, Ordering::Relaxed);
    }

    /// reader 侧 transient 读取错误（10ms 续读，不算 rejected）。
    pub fn record_rx_transient_error(&self) {
        self.rx_transient_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// `dispatch.to_terminator / to_relay / unknown_stream`（§5.6 消费侧）。
    pub fn record_dispatch(&self, target: N1DispatchTarget) {
        let counter = match target {
            N1DispatchTarget::Terminator => &self.dispatch_to_terminator,
            N1DispatchTarget::Relay => &self.dispatch_to_relay,
            N1DispatchTarget::Unknown => &self.dispatch_unknown_stream,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// `dispatch.bad_frame`：`decode_stream_frame` 失败（§6.1 `BadFrame`）。
    ///
    /// 与 `dispatch.to_*` 互斥：坏帧不进任何一路，也不计 `rx.rejected`
    ///（§6.1 只要求 `dispatch.bad_frame`）。
    pub fn record_dispatch_bad_frame(&self) {
        self.dispatch_bad_frame.fetch_add(1, Ordering::Relaxed);
    }

    /// `egress.*`：egress relay 计数（spec §5.6/§7）。
    pub fn record_egress(&self, ev: N1EgressEvent) {
        let counter = match ev {
            N1EgressEvent::Syn => &self.egress_syn,
            N1EgressEvent::ConnectOk => &self.egress_connect_ok,
            N1EgressEvent::ConnectFailed => &self.egress_connect_failed,
            N1EgressEvent::BytesToLocal(_) => &self.egress_bytes_to_local,
            N1EgressEvent::BytesFromLocal(_) => &self.egress_bytes_from_local,
            N1EgressEvent::TableFull => &self.egress_table_full,
        };
        match ev {
            N1EgressEvent::BytesToLocal(n) | N1EgressEvent::BytesFromLocal(n) => {
                counter.fetch_add(u64::try_from(n).unwrap_or(u64::MAX), Ordering::Relaxed);
            }
            _ => {
                counter.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// `tx.frames / tx.errors`：回程 STREAM 帧（§5.6）。
    ///
    /// `bytes` 只作日志/未来扩展用；§5.6 不定义 `tx.bytes` 字段。
    pub fn record_tx(&self, bytes: usize, ok: bool) {
        let _ = bytes;
        if ok {
            self.tx_frames.fetch_add(1, Ordering::Relaxed);
        } else {
            self.tx_errors.fetch_add(1, Ordering::Relaxed);
        }
    }
}

static N1_STATS: OnceLock<Arc<N1Stats>> = OnceLock::new();
static N1_LISTENER_STATE: OnceLock<N1ListenerState> = OnceLock::new();

/// 发布进程级 stats 句柄（组合根/`assemble_n1_runtime`，一次）。
pub fn publish_n1_stats(stats: Arc<N1Stats>) {
    let _ = N1_STATS.set(stats);
}

/// 发布 listener 状态（`assemble_n1_runtime`，一次）；未发布 = disabled。
pub fn publish_n1_listener_state(state: N1ListenerState) {
    let _ = N1_LISTENER_STATE.set(state);
}

/// `None` before the composition root publishes the handle.
#[must_use]
pub fn n1_stats_snapshot() -> Option<N1StatsSnapshot> {
    N1_STATS.get().map(|s| s.snapshot())
}

fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Build the `/localapi/v0/n1/stats` body from published state.
#[must_use]
pub fn n1_status() -> Value {
    build_n1_status_json_from(N1_LISTENER_STATE.get(), n1_stats_snapshot(), now_epoch_ms())
}

/// `None` listener（未装配 N1，例如 `serve` 形态）= disabled。
fn build_n1_status_json_from(
    listener_state: Option<&N1ListenerState>,
    snapshot: Option<N1StatsSnapshot>,
    generated_at_ms: u64,
) -> Value {
    let state = listener_state
        .cloned()
        .unwrap_or(N1ListenerState::Disabled {
            reason: "no_listen_addr",
        });
    build_n1_status_json(state, snapshot.unwrap_or_default(), generated_at_ms)
}

/// Pure JSON builder（§5.6 形状逐字；单测精确值）。
///
/// `disabled` 时强制全 0（与 `/nat/chunks` 的冻结行为一致）；`bind_failed`
/// 属于 `runtime=enabled`（listener 已尝试启动），`addr` 为空串。
#[must_use]
pub fn build_n1_status_json(
    listener_state: N1ListenerState,
    snapshot: N1StatsSnapshot,
    generated_at_ms: u64,
) -> Value {
    let (runtime, state_text, addr) = match &listener_state {
        N1ListenerState::Disabled { .. } => ("disabled", "disabled", String::new()),
        N1ListenerState::BindFailed { .. } => ("enabled", "bind_failed", String::new()),
        N1ListenerState::Listening { addr } => ("enabled", "listening", addr.to_string()),
    };
    let snapshot = if runtime == "disabled" {
        N1StatsSnapshot::default()
    } else {
        snapshot
    };
    json!({
        "verdict": "PASS",
        "runtime": runtime,
        "listener": { "state": state_text, "addr": addr },
        "rx": {
            "datagrams": snapshot.rx_datagrams,
            "bytes": snapshot.rx_bytes,
            "raw_ip": snapshot.rx_raw_ip,
            "stream_frames": snapshot.rx_stream_frames,
            "rejected": snapshot.rx_rejected,
            "queue_full": snapshot.rx_queue_full,
            "ambiguous": snapshot.rx_ambiguous,
        },
        "dispatch": {
            "to_terminator": snapshot.dispatch_to_terminator,
            "to_relay": snapshot.dispatch_to_relay,
            "bad_frame": snapshot.dispatch_bad_frame,
            "unknown_stream": snapshot.dispatch_unknown_stream,
        },
        "egress": {
            "syn": snapshot.egress_syn,
            "connect_ok": snapshot.egress_connect_ok,
            "connect_failed": snapshot.egress_connect_failed,
            "bytes_to_local": snapshot.egress_bytes_to_local,
            "bytes_from_local": snapshot.egress_bytes_from_local,
            "table_full": snapshot.egress_table_full,
        },
        "tx": {
            "frames": snapshot.tx_frames,
            "errors": snapshot.tx_errors,
        },
        "generated_at_ms": generated_at_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::net::SocketAddr;

    use nexus_network::n1::N1PeerId;

    fn keys(value: &serde_json::Value) -> BTreeSet<String> {
        value.as_object().expect("object").keys().cloned().collect()
    }

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn rx_counters_record_each_source() {
        let stats = N1Stats::default();
        stats.record_rx_datagram(100);
        stats.record_rx_datagram(50);
        stats.record_rx_raw_ip();
        stats.record_rx_stream_frame();
        stats.record_rx_rejected(N1InboundReject::EmptyDatagram);
        stats.record_rx_rejected(N1InboundReject::AdmissionDenied {
            peer: N1PeerId([7; 32]),
        });
        stats.record_rx_queue_full();
        stats.record_rx_ambiguous();
        stats.record_rx_conn_closed();
        stats.record_rx_transient_error();

        let snap = stats.snapshot();
        assert_eq!(snap.rx_datagrams, 2);
        assert_eq!(snap.rx_bytes, 150);
        assert_eq!(snap.rx_raw_ip, 1);
        assert_eq!(snap.rx_stream_frames, 1);
        assert_eq!(snap.rx_rejected, 2);
        assert_eq!(snap.rx_rejected_admission, 1);
        assert_eq!(snap.rx_queue_full, 1);
        assert_eq!(snap.rx_ambiguous, 1);
        assert_eq!(snap.rx_conn_closed, 1);
        assert_eq!(snap.rx_transient_errors, 1);
    }

    #[test]
    fn dispatch_counters_record_each_target() {
        let stats = N1Stats::default();
        stats.record_dispatch(N1DispatchTarget::Terminator);
        stats.record_dispatch(N1DispatchTarget::Relay);
        stats.record_dispatch(N1DispatchTarget::Relay);
        stats.record_dispatch(N1DispatchTarget::Unknown);
        stats.record_dispatch_bad_frame();

        let snap = stats.snapshot();
        assert_eq!(snap.dispatch_to_terminator, 1);
        assert_eq!(snap.dispatch_to_relay, 2);
        assert_eq!(snap.dispatch_unknown_stream, 1);
        assert_eq!(snap.dispatch_bad_frame, 1);
    }

    #[test]
    fn egress_counters_record_each_event() {
        let stats = N1Stats::default();
        stats.record_egress(N1EgressEvent::Syn);
        stats.record_egress(N1EgressEvent::ConnectOk);
        stats.record_egress(N1EgressEvent::ConnectFailed);
        stats.record_egress(N1EgressEvent::BytesToLocal(4096));
        stats.record_egress(N1EgressEvent::BytesFromLocal(1024));
        stats.record_egress(N1EgressEvent::TableFull);

        let snap = stats.snapshot();
        assert_eq!(snap.egress_syn, 1);
        assert_eq!(snap.egress_connect_ok, 1);
        assert_eq!(snap.egress_connect_failed, 1);
        assert_eq!(snap.egress_bytes_to_local, 4096);
        assert_eq!(snap.egress_bytes_from_local, 1024);
        assert_eq!(snap.egress_table_full, 1);
    }

    #[test]
    fn tx_counters_split_frames_and_errors() {
        let stats = N1Stats::default();
        stats.record_tx(10, true);
        stats.record_tx(20, true);
        stats.record_tx(30, false);

        let snap = stats.snapshot();
        assert_eq!(snap.tx_frames, 2);
        assert_eq!(snap.tx_errors, 1);
    }

    #[test]
    fn json_shape_matches_spec_5_6_exactly() {
        let stats = N1Stats::default();
        let value = build_n1_status_json(
            N1ListenerState::Listening {
                addr: "127.0.0.1:9000".parse::<SocketAddr>().unwrap(),
            },
            stats.snapshot(),
            7,
        );

        assert_eq!(
            keys(&value),
            set(&[
                "verdict",
                "runtime",
                "listener",
                "rx",
                "dispatch",
                "egress",
                "tx",
                "generated_at_ms",
            ])
        );
        assert_eq!(keys(&value["listener"]), set(&["state", "addr"]));
        assert_eq!(
            keys(&value["rx"]),
            set(&[
                "datagrams",
                "bytes",
                "raw_ip",
                "stream_frames",
                "rejected",
                "queue_full",
                "ambiguous",
            ])
        );
        assert_eq!(
            keys(&value["dispatch"]),
            set(&["to_terminator", "to_relay", "bad_frame", "unknown_stream",])
        );
        assert_eq!(
            keys(&value["egress"]),
            set(&[
                "syn",
                "connect_ok",
                "connect_failed",
                "bytes_to_local",
                "bytes_from_local",
                "table_full",
            ])
        );
        assert_eq!(keys(&value["tx"]), set(&["frames", "errors"]));
        // AC-N1-6：不引入送达/确认语义。
        let text = value.to_string();
        assert!(!text.contains("delivered"));
        assert!(!text.contains("acked"));
    }

    #[test]
    fn json_enabled_reports_listening_state_and_exact_counters() {
        let stats = N1Stats::default();
        stats.record_rx_datagram(1200);
        stats.record_rx_stream_frame();
        stats.record_dispatch(N1DispatchTarget::Relay);
        stats.record_egress(N1EgressEvent::BytesToLocal(512));
        stats.record_tx(64, true);

        let value = build_n1_status_json(
            N1ListenerState::Listening {
                addr: "0.0.0.0:9000".parse::<SocketAddr>().unwrap(),
            },
            stats.snapshot(),
            42,
        );
        assert_eq!(value["verdict"], "PASS");
        assert_eq!(value["runtime"], "enabled");
        assert_eq!(value["listener"]["state"], "listening");
        assert_eq!(value["listener"]["addr"], "0.0.0.0:9000");
        assert_eq!(value["rx"]["datagrams"], 1);
        assert_eq!(value["rx"]["bytes"], 1200);
        assert_eq!(value["rx"]["stream_frames"], 1);
        assert_eq!(value["dispatch"]["to_relay"], 1);
        assert_eq!(value["egress"]["bytes_to_local"], 512);
        assert_eq!(value["tx"]["frames"], 1);
        assert_eq!(value["generated_at_ms"], 42);
    }

    #[test]
    fn json_disabled_is_all_zero_even_with_live_counters() {
        // §5.6：disabled 时全 0（与 `/nat/chunks` 的冻结行为一致）。
        let stats = N1Stats::default();
        stats.record_rx_datagram(99);
        stats.record_egress(N1EgressEvent::BytesToLocal(99));
        let value = build_n1_status_json(
            N1ListenerState::Disabled {
                reason: "no_listen_addr",
            },
            stats.snapshot(),
            1,
        );
        assert_eq!(value["runtime"], "disabled");
        assert_eq!(value["listener"]["state"], "disabled");
        assert_eq!(value["listener"]["addr"], "");
        assert_eq!(value["rx"]["datagrams"], 0);
        assert_eq!(value["rx"]["bytes"], 0);
        assert_eq!(value["egress"]["bytes_to_local"], 0);
        assert_eq!(value["tx"]["frames"], 0);
    }

    #[test]
    fn json_bind_failed_is_enabled_with_zero_counters() {
        let value = build_n1_status_json(
            N1ListenerState::BindFailed {
                reason: "address in use".to_string(),
            },
            N1StatsSnapshot::default(),
            3,
        );
        assert_eq!(value["runtime"], "enabled");
        assert_eq!(value["listener"]["state"], "bind_failed");
        assert_eq!(value["listener"]["addr"], "");
    }

    #[test]
    fn unpublished_status_is_disabled_and_all_zero() {
        // `serve` 形态（不装配 N1）没有发布句柄：默认 disabled 全 0。
        let value = build_n1_status_json_from(
            None,
            Some(N1StatsSnapshot {
                rx_datagrams: 5,
                ..N1StatsSnapshot::default()
            }),
            9,
        );
        assert_eq!(value["runtime"], "disabled");
        assert_eq!(value["rx"]["datagrams"], 0);
    }
}

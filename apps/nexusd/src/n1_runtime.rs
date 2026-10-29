//! N1 runtime 组合函数（spec §5.8/§7，WP1）。
//!
//! `assemble_n1_runtime` 是 `run_daemon` 与组合路径测试**共用**的生产装配函数：
//! listener（mTLS）→ accept 线程（复用 `N1SessionManager::accept_loop`）→
//! inbound channel/stats 句柄。`run_daemon` 只负责把返回的 `inbound_rx` 交给
//! dataplane（WP3/WP4 落地后接线）。
//!
//! 本段（WP1）只落 listener/accept 与生命周期底座；inbound reader（WP3）、
//! dataplane 注入（WP4）、`/n1/stats`（WP6）在后续 WP 增补。

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};

use nexus_fabric::FabricIdentity;
use nexus_network::n1::{N1Connection, N1PeerId};

use crate::config::N1Section;
use crate::n1_listener::FabricN1Listener;

/// 入站队列容量（spec §8.1 `N1_INBOUND_QUEUE_CAP`）。
pub const N1_INBOUND_QUEUE_CAP: usize = 4096;

/// N1 入站消息（spec §7；WP3/WP4 的 reader/dispatch 消费）。
pub enum N1Inbound {
    ConnUp {
        peer: N1PeerId,
        conn: Arc<dyn N1Connection>,
    },
    ConnDown {
        peer: N1PeerId,
    },
    RawIp {
        peer: N1PeerId,
        packet: Vec<u8>,
    },
    Stream {
        peer: N1PeerId,
        conn: Arc<dyn N1Connection>,
        frame: Vec<u8>,
    },
}

/// 入站拒绝分类（spec §6.1；本段只落计数所需子集，WP3/WP4 增补消费者）。
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

/// N1 计数（spec §5.6/§7）。WP1 只落 rejected 大类；WP4/WP6 增补其余字段
/// 与 `/localapi/v0/n1/stats` 序列化。
#[derive(Debug, Default)]
pub struct N1Stats {
    rx_rejected: AtomicU64,
    rx_rejected_admission: AtomicU64,
}

/// `N1Stats` 的快照（WP1 子集；字段名与 §5.6 的 `rx.rejected` 对齐）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct N1StatsSnapshot {
    pub rx_rejected: u64,
    pub rx_rejected_admission: u64,
}

impl N1Stats {
    pub fn snapshot(&self) -> N1StatsSnapshot {
        N1StatsSnapshot {
            rx_rejected: self.rx_rejected.load(Ordering::Relaxed),
            rx_rejected_admission: self.rx_rejected_admission.load(Ordering::Relaxed),
        }
    }

    /// 计入 `rx.rejected{reason}`（reason 进日志；计数只分大类，spec §5.6）。
    pub fn record_rx_rejected(&self, reason: N1InboundReject) {
        self.rx_rejected.fetch_add(1, Ordering::Relaxed);
        if matches!(reason, N1InboundReject::AdmissionDenied { .. }) {
            self.rx_rejected_admission.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// listener 运行状态（spec §7）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum N1ListenerState {
    Disabled { reason: &'static str },
    BindFailed { reason: String },
    Listening { addr: std::net::SocketAddr },
}

/// `assemble_n1_runtime` 的返回值（spec §7）。
pub struct N1RuntimeHandles {
    pub accept: Option<std::thread::JoinHandle<()>>,
    pub rx: Option<std::thread::JoinHandle<()>>,
    pub inbound_rx: Receiver<N1Inbound>,
    pub stats: Arc<N1Stats>,
    pub listener_state: N1ListenerState,
    /// 保持 inbound channel 存活直到 WP3 的 rx supervisor 接管发送端。
    pub(crate) _inbound_tx: Option<SyncSender<N1Inbound>>,
}

fn handles(
    accept: Option<std::thread::JoinHandle<()>>,
    listener_state: N1ListenerState,
    tx: SyncSender<N1Inbound>,
    inbound_rx: Receiver<N1Inbound>,
    stats: Arc<N1Stats>,
) -> N1RuntimeHandles {
    N1RuntimeHandles {
        accept,
        rx: None,
        inbound_rx,
        stats,
        listener_state,
        _inbound_tx: Some(tx),
    }
}

/// 生产装配函数：listener + accept 线程（`run_daemon` 与组合路径测试共用）。
///
/// - `section.enabled == false` 或 `listen_addr` 缺省 → 不 bind、不 spawn，
///   状态 `Disabled{reason: "no_listen_addr"}`；
/// - `identity == None`（listen enabled）→ 不 bind，状态 `BindFailed`；
/// - `bind_mtls` 失败 → `BindFailed`（daemon 继续，WARN）；
/// - 成功 → 启动 `nexusd-n1-accept` 线程，状态 `Listening{addr}`。
pub fn assemble_n1_runtime(
    assembly: &crate::assembly::N1Assembly,
    section: &N1Section,
    identity: Option<FabricIdentity>,
    shutdown: Arc<AtomicBool>,
) -> N1RuntimeHandles {
    let (tx, inbound_rx) = sync_channel(N1_INBOUND_QUEUE_CAP);
    let stats = Arc::new(N1Stats::default());

    if !section.enabled || section.listen_addr.is_none() {
        eprintln!("[n1-listener] listener disabled reason=no_listen_addr");
        return handles(
            None,
            N1ListenerState::Disabled {
                reason: "no_listen_addr",
            },
            tx,
            inbound_rx,
            stats,
        );
    }

    let addr_text = section
        .listen_addr
        .as_deref()
        .expect("listen_addr checked above");
    let addr = match addr_text.parse::<std::net::SocketAddr>() {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("[n1-listener] WARN: bind failed addr={addr_text} reason={e}");
            return handles(
                None,
                N1ListenerState::BindFailed {
                    reason: format!("invalid listen_addr: {e}"),
                },
                tx,
                inbound_rx,
                stats,
            );
        }
    };

    let Some(identity) = identity else {
        eprintln!("[n1-listener] ERROR: identity unavailable; refusing to listen");
        return handles(
            None,
            N1ListenerState::BindFailed {
                reason: "identity unavailable".to_string(),
            },
            tx,
            inbound_rx,
            stats,
        );
    };

    let allowed: Vec<N1PeerId> = assembly.config.peers.iter().map(|p| p.id).collect();
    let allowed_count = allowed.len();
    let stop = Arc::clone(&shutdown);
    let listener = match FabricN1Listener::bind(addr, &identity, allowed, stop) {
        Ok(listener) => listener.with_stats(Arc::clone(&stats)),
        Err(e) => {
            eprintln!("[n1-listener] WARN: bind failed addr={addr} reason={e}");
            return handles(
                None,
                N1ListenerState::BindFailed {
                    reason: e.to_string(),
                },
                tx,
                inbound_rx,
                stats,
            );
        }
    };
    let bound = match listener.local_addr() {
        Ok(bound) => bound,
        Err(e) => {
            eprintln!("[n1-listener] WARN: bind failed addr={addr} reason={e}");
            return handles(
                None,
                N1ListenerState::BindFailed {
                    reason: e.to_string(),
                },
                tx,
                inbound_rx,
                stats,
            );
        }
    };
    eprintln!("[n1-listener] listening addr={bound} peers={allowed_count}");

    let sessions = Arc::clone(&assembly.sessions);
    let accept_stop = Arc::clone(&shutdown);
    let accept = std::thread::Builder::new()
        .name("nexusd-n1-accept".to_string())
        .spawn(move || sessions.accept_loop(&listener, &accept_stop))
        .map_err(|e| format!("spawn n1 accept thread: {e}"));
    match accept {
        Ok(handle) => handles(
            Some(handle),
            N1ListenerState::Listening { addr: bound },
            tx,
            inbound_rx,
            stats,
        ),
        Err(reason) => {
            eprintln!("[n1-listener] WARN: bind failed addr={bound} reason={reason}");
            handles(
                None,
                N1ListenerState::BindFailed { reason },
                tx,
                inbound_rx,
                stats,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    use nexus_fabric::{ConnConfig, FabricConn, FabricIdentity};

    fn identity(seed: u8) -> FabricIdentity {
        FabricIdentity::from_ed25519_seed([seed; 32]).unwrap()
    }

    fn hex32(bytes: &[u8; 32]) -> String {
        let mut out = String::with_capacity(64);
        for b in bytes {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }

    fn assembly(server: &FabricIdentity, client: &FabricIdentity) -> crate::assembly::N1Assembly {
        let server_hex = hex32(&server.peer_id().0);
        let client_hex = hex32(&client.peer_id().0);
        let text = format!(
            "peer_id = \"{server_hex}\"\n\
             [[peers]]\n\
             id = \"{client_hex}\"\n\
             addrs = [\"127.0.0.1:1\"]\n\
             [vpi]\n\
             interface = \"nexus0\"\n\
             address = \"10.200.0.1\"\n\
             mtu = 1200\n"
        );
        crate::assembly::assemble_n1_with_discovery(
            &text,
            None,
            Arc::new(AtomicBool::new(false)),
            nexus::network::DiscoveryParams::static_only(),
        )
        .expect("assembly")
    }

    #[test]
    fn absent_section_is_disabled_without_threads() {
        let server = identity(41);
        let client = identity(42);
        let asm = assembly(&server, &client);
        let handles = assemble_n1_runtime(
            &asm,
            &N1Section::default(),
            Some(server),
            Arc::new(AtomicBool::new(false)),
        );
        assert_eq!(
            handles.listener_state,
            N1ListenerState::Disabled {
                reason: "no_listen_addr"
            }
        );
        assert!(handles.accept.is_none());
        assert!(handles.rx.is_none());
        assert_eq!(handles.stats.snapshot(), N1StatsSnapshot::default());
    }

    #[test]
    fn enabled_without_addr_degrades_to_disabled() {
        let server = identity(43);
        let client = identity(44);
        let asm = assembly(&server, &client);
        let section = N1Section {
            enabled: true,
            listen_addr: None,
        };
        let handles = assemble_n1_runtime(
            &asm,
            &section,
            Some(server),
            Arc::new(AtomicBool::new(false)),
        );
        assert_eq!(
            handles.listener_state,
            N1ListenerState::Disabled {
                reason: "no_listen_addr"
            }
        );
        assert!(handles.accept.is_none());
    }

    #[test]
    fn enabled_without_identity_fails_closed_without_threads() {
        let server = identity(45);
        let client = identity(46);
        let asm = assembly(&server, &client);
        let section = N1Section {
            enabled: true,
            listen_addr: Some("127.0.0.1:0".to_string()),
        };
        let handles = assemble_n1_runtime(&asm, &section, None, Arc::new(AtomicBool::new(false)));
        assert!(matches!(
            handles.listener_state,
            N1ListenerState::BindFailed { .. }
        ));
        assert!(handles.accept.is_none());
    }

    #[test]
    fn enabled_listener_spawns_accept_thread_and_registers_peer() {
        let server = identity(47);
        let server_id = server.peer_id();
        let client = identity(48);
        let asm = assembly(&server, &client);
        let shutdown = Arc::new(AtomicBool::new(false));
        let section = N1Section {
            enabled: true,
            listen_addr: Some("127.0.0.1:0".to_string()),
        };
        let handles = assemble_n1_runtime(&asm, &section, Some(server), Arc::clone(&shutdown));
        let N1ListenerState::Listening { addr } = handles.listener_state else {
            panic!("expected listening, got {:?}", handles.listener_state);
        };
        assert!(handles.accept.is_some());

        let cfg = ConnConfig {
            addrs: vec![addr],
            handshake_timeout: Duration::from_millis(700),
        };
        let dialer = FabricConn::connect_mtls(server_id, &client, &cfg).unwrap();
        let client_peer = N1PeerId(client.peer_id().0);
        let deadline = Instant::now() + Duration::from_secs(3);
        while asm.sessions.connection_for(&client_peer).is_none() {
            assert!(Instant::now() < deadline, "accepted peer never registered");
            std::thread::sleep(Duration::from_millis(10));
        }
        dialer.close(0, b"done");
        shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = handles.accept {
            handle.join().expect("accept thread joins");
        }
    }
}

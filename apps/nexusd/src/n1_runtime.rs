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
use std::sync::mpsc::{Receiver, sync_channel};

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

/// N1 计数（spec §5.6/§7）。WP1 落 rejected 大类，WP3 增补 rx 侧字段；
/// WP4/WP6 增补 dispatch/egress/tx 与 `/localapi/v0/n1/stats` 序列化。
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
}

/// `N1Stats` 的快照（字段名与 §5.6 的 rx 侧点路径对齐）。
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
}

impl N1Stats {
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

    /// `rx.queue_full` 且 `rx.rejected{queue_full}`（§6.1 QueueFull 行）。
    pub fn record_rx_queue_full(&self) {
        self.rx_queue_full.fetch_add(1, Ordering::Relaxed);
        self.rx_rejected.fetch_add(1, Ordering::Relaxed);
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
}

fn handles(
    accept: Option<std::thread::JoinHandle<()>>,
    rx: Option<std::thread::JoinHandle<()>>,
    listener_state: N1ListenerState,
    inbound_rx: Receiver<N1Inbound>,
    stats: Arc<N1Stats>,
) -> N1RuntimeHandles {
    N1RuntimeHandles {
        accept,
        rx,
        inbound_rx,
        stats,
        listener_state,
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
            None,
            N1ListenerState::Disabled {
                reason: "no_listen_addr",
            },
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
                None,
                N1ListenerState::BindFailed {
                    reason: format!("invalid listen_addr: {e}"),
                },
                inbound_rx,
                stats,
            );
        }
    };

    let Some(identity) = identity else {
        eprintln!("[n1-listener] ERROR: identity unavailable; refusing to listen");
        return handles(
            None,
            None,
            N1ListenerState::BindFailed {
                reason: "identity unavailable".to_string(),
            },
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
                None,
                N1ListenerState::BindFailed {
                    reason: e.to_string(),
                },
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
                None,
                N1ListenerState::BindFailed {
                    reason: e.to_string(),
                },
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
        Ok(handle) => {
            let rx = match crate::n1_rx::spawn_n1_receiver(
                Arc::clone(&assembly.sessions),
                tx,
                Arc::clone(&stats),
                Arc::clone(&shutdown),
            ) {
                Ok(rx) => Some(rx),
                Err(error) => {
                    eprintln!("[n1-rx] WARN: supervisor spawn failed reason={error}");
                    None
                }
            };
            handles(
                Some(handle),
                rx,
                N1ListenerState::Listening { addr: bound },
                inbound_rx,
                stats,
            )
        }
        Err(reason) => {
            eprintln!("[n1-listener] WARN: bind failed addr={bound} reason={reason}");
            handles(
                None,
                None,
                N1ListenerState::BindFailed { reason },
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

    fn assembly(
        server: &FabricIdentity,
        client: &FabricIdentity,
        shutdown: Arc<AtomicBool>,
    ) -> crate::assembly::N1Assembly {
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
            shutdown,
            nexus::network::DiscoveryParams::static_only(),
            None,
        )
        .expect("assembly")
    }

    #[test]
    fn absent_section_is_disabled_without_threads() {
        let server = identity(41);
        let client = identity(42);
        let dial_shutdown = Arc::new(AtomicBool::new(false));
        let asm = assembly(&server, &client, Arc::clone(&dial_shutdown));
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
        dial_shutdown.store(true, Ordering::SeqCst);
    }

    #[test]
    fn enabled_without_addr_degrades_to_disabled() {
        let server = identity(43);
        let client = identity(44);
        let dial_shutdown = Arc::new(AtomicBool::new(false));
        let asm = assembly(&server, &client, Arc::clone(&dial_shutdown));
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
        dial_shutdown.store(true, Ordering::SeqCst);
    }

    #[test]
    fn enabled_without_identity_fails_closed_without_threads() {
        let server = identity(45);
        let client = identity(46);
        let dial_shutdown = Arc::new(AtomicBool::new(false));
        let asm = assembly(&server, &client, Arc::clone(&dial_shutdown));
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
        dial_shutdown.store(true, Ordering::SeqCst);
    }

    #[test]
    fn enabled_listener_spawns_accept_thread_and_registers_peer() {
        let server = identity(47);
        let server_id = server.peer_id();
        let client = identity(48);
        let shutdown = Arc::new(AtomicBool::new(false));
        let asm = assembly(&server, &client, Arc::clone(&shutdown));
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

    #[test]
    fn larger_id_listens_and_smaller_id_dials_over_mtls() {
        // 生成一对身份，确保 listener 是大 id、dialer 是小 id（tie-break 所有权）。
        let mut listener_seed = 0x71u8;
        let mut dialer_seed = 0x72u8;
        let (listener, dialer) = loop {
            let listener = identity(listener_seed);
            let dialer = identity(dialer_seed);
            if listener.peer_id().0 > dialer.peer_id().0 {
                break (listener, dialer);
            }
            std::mem::swap(&mut listener_seed, &mut dialer_seed);
        };
        let listener_peer = listener.peer_id();
        let dialer_peer = dialer.peer_id();

        let listener_text = format!(
            "peer_id = \"{}\"\n\
             [[peers]]\n\
             id = \"{}\"\n\
             addrs = [\"127.0.0.1:1\"]\n\
             [vpi]\n\
             interface = \"nexus0\"\n\
             address = \"10.200.0.1\"\n\
             mtu = 1200\n",
            hex32(&listener_peer.0),
            hex32(&dialer_peer.0),
        );
        let shutdown = Arc::new(AtomicBool::new(false));
        let listener_assembly = crate::assembly::assemble_n1_with_discovery(
            &listener_text,
            None,
            Arc::clone(&shutdown),
            nexus::network::DiscoveryParams::static_only(),
            Some(listener),
        )
        .expect("listener assembly");
        let section = N1Section {
            enabled: true,
            listen_addr: Some("127.0.0.1:0".to_string()),
        };
        let listener_identity = identity(listener_seed);
        let handles = assemble_n1_runtime(
            &listener_assembly,
            &section,
            Some(listener_identity),
            Arc::clone(&shutdown),
        );
        let N1ListenerState::Listening { addr } = handles.listener_state else {
            panic!("expected listening, got {:?}", handles.listener_state);
        };

        let dialer_text = format!(
            "peer_id = \"{}\"\n\
             [[peers]]\n\
             id = \"{}\"\n\
             addrs = [\"{addr}\"]\n\
             [vpi]\n\
             interface = \"nexus0\"\n\
             address = \"10.200.0.2\"\n\
             mtu = 1200\n",
            hex32(&dialer_peer.0),
            hex32(&listener_peer.0),
        );
        let dialer_assembly = crate::assembly::assemble_n1_with_discovery(
            &dialer_text,
            None,
            Arc::clone(&shutdown),
            nexus::network::DiscoveryParams::static_only(),
            Some(dialer),
        )
        .expect("dialer assembly");

        let listener_key = N1PeerId(listener_peer.0);
        let dialer_key = N1PeerId(dialer_peer.0);
        let deadline = Instant::now() + Duration::from_secs(5);
        while dialer_assembly
            .sessions
            .connection_for(&listener_key)
            .is_none()
            || listener_assembly
                .sessions
                .connection_for(&dialer_key)
                .is_none()
        {
            assert!(
                Instant::now() < deadline,
                "smaller id never completed mTLS dial to larger id"
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = handles.accept {
            handle.join().expect("accept thread joins");
        }
    }
}

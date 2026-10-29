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
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{Receiver, sync_channel};

use nexus_fabric::FabricIdentity;
use nexus_network::n1::{N1Connection, N1PeerId};

use crate::config::N1Section;
use crate::n1_listener::FabricN1Listener;
use crate::n1_stats::{N1ListenerState, N1Stats, publish_n1_listener_state, publish_n1_stats};

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
    // WP6（§5.6）：`/localapi/v0/n1/stats` 读的是进程级发布面；生产装配
    // （`run_daemon`）与组合路径测试共用本函数，故发布点只此一处。
    publish_n1_stats(Arc::clone(&stats));
    publish_n1_listener_state(listener_state.clone());
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
            // M-4（review-r1）：§9 要求 `listen_addr` 格式非法时
            // `CONFIG_INVALID` + exit 1，而本分支只降级为 `BindFailed`。
            // **生产不可达**（防御性口径）：`parse_n1_section`（config.rs）
            // 在启用时先校验该字段格式，解析失败 daemon 在装配前已 exit 1；
            // 保留本分支只为非配置来源（测试/复用装配函数）的兜底，
            // 不得读作第二条配置错误口径。
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
        Ok(listener) => listener
            .with_stats(Arc::clone(&stats))
            // M-5：接入会话表（只读）以便在 accept 侧发
            // `[n1-listener] rejected peer=… reason=duplicate`；机制零改动。
            .with_sessions(Arc::clone(&assembly.sessions)),
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
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    use crate::n1_stats::N1StatsSnapshot;

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
    fn listening_runtime_wires_rx_supervisor_into_the_inbound_queue() {
        // WP3 接线证据：生产装配函数在 listening 路径上起 supervisor，
        // 真实 mTLS 入向连接经 reader 以 ConnUp 形式出现在 inbound 队列。
        let server = identity(49);
        let server_id = server.peer_id();
        let client = identity(50);
        let client_peer = N1PeerId(client.peer_id().0);
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
        assert!(
            handles.rx.is_some(),
            "listening runtime must spawn the rx supervisor"
        );

        let cfg = ConnConfig {
            addrs: vec![addr],
            handshake_timeout: Duration::from_millis(700),
        };
        let dialer = FabricConn::connect_mtls(server_id, &client, &cfg).unwrap();
        match handles
            .inbound_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("ConnUp must reach the inbound queue")
        {
            N1Inbound::ConnUp { peer, conn } => {
                assert_eq!(peer, client_peer);
                assert!(conn.connection_id() > 0);
            }
            _ => panic!("expected ConnUp as the first inbound message"),
        }

        dialer.close(0, b"done");
        shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = handles.accept {
            handle.join().expect("accept thread joins");
        }
        if let Some(handle) = handles.rx {
            handle.join().expect("rx supervisor joins");
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

//! E3 集成测试：策略热加载文件 watcher（§12.58 扩展）。
//!
//! Red Evidence：本文件先于实现编写，初始运行必须失败
//! （`nexus::strategy_watcher` 模块不存在 → 编译失败）。
//! 实现后全部测试必须通过；任一失败即阻塞。

use nexus::strategy_watcher::{ReloadEventKind, StrategyWatcher, WatcherConfig};
use nexus_discovery::PeerId;
use nexus_discovery::lsa::{LinkAdvert, LinkMetrics, Lsa, Lsdb};
use nexus_discovery::routing::{RoutingStrategy, SharedFibManager};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

fn peer(id: &str) -> PeerId {
    PeerId(id.to_string())
}

fn link(to: &str, latency_ms: u32) -> LinkAdvert {
    LinkAdvert {
        neighbor: peer(to),
        metrics: LinkMetrics {
            latency_ms,
            loss_pct: 0,
            bandwidth_kbps: 100_000,
        },
    }
}

/// Diamond 拓扑：A-B(10ms), B-D(10ms), A-C(10ms), C-D(10ms)。
/// Shortest: A->D 1 条下一跳；Ecmp: A->D 2 条下一跳。
fn diamond_lsdb() -> (SharedFibManager<RoutingStrategy>, Arc<RwLock<Lsdb>>) {
    let (id_a, id_b, id_c, id_d) = (peer("a"), peer("b"), peer("c"), peer("d"));
    let mut lsdb = Lsdb::new(id_a.clone());
    lsdb.update_local(Lsa {
        node_id: id_a.clone(),
        vip: "10.99.0.1".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link("b", 10), link("c", 10)],
    });
    lsdb.update(Lsa {
        node_id: id_b.clone(),
        vip: "10.99.0.2".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link("a", 10), link("d", 10)],
    });
    lsdb.update(Lsa {
        node_id: id_c.clone(),
        vip: "10.99.0.3".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link("a", 10), link("d", 10)],
    });
    lsdb.update(Lsa {
        node_id: id_d.clone(),
        vip: "10.99.0.4".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: None,
        neighbors: vec![link("b", 10), link("c", 10)],
    });
    let fib = SharedFibManager::new(id_a.clone(), RoutingStrategy::Shortest, &lsdb);
    (fib, Arc::new(RwLock::new(lsdb)))
}

fn temp_config_path() -> PathBuf {
    let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!(
        "nexus-watcher-test-{}-{}.toml",
        std::process::id(),
        n
    ))
}

fn write_strategy(path: &std::path::Path, strategy: &str) {
    let content = format!(
        "[subnet]\ncidr = \"10.99.0.0/24\"\n[routing]\nstrategy = \"{}\"\n",
        strategy
    );
    std::fs::write(path, content).expect("write test config");
}

fn next_hop_count(fib: &SharedFibManager<RoutingStrategy>) -> usize {
    fib.read()
        .fib()
        .lookup("10.99.0.4")
        .map(|hops| hops.len())
        .unwrap_or(0)
}

/// 等待 watcher 事件数达到期望，超时返回 false（避免 flaky 用轮询而非固定 sleep）。
fn wait_for_events(watcher: &StrategyWatcher, want: usize, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if watcher.events().len() >= want {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    watcher.events().len() >= want
}

/// 等待最大 seq 达到目标（用于有界缓冲测试：缓冲长度有上限，seq 单调递增）。
fn wait_for_seq(watcher: &StrategyWatcher, want_seq: u64, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let max_seq = watcher.events().iter().map(|e| e.seq).max();
        if max_seq.is_some_and(|s| s >= want_seq) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    watcher
        .events()
        .iter()
        .map(|e| e.seq)
        .max()
        .is_some_and(|s| s >= want_seq)
}

fn start_watcher(
    path: &std::path::Path,
    fib: SharedFibManager<RoutingStrategy>,
    lsdb: Arc<RwLock<Lsdb>>,
) -> StrategyWatcher {
    let config = WatcherConfig {
        config_path: path.to_path_buf(),
        poll_interval: Duration::from_millis(50),
        max_events: 64,
    };
    StrategyWatcher::start(config, fib, lsdb).expect("watcher start")
}

#[test]
fn watcher_detects_strategy_change() {
    let path = temp_config_path();
    write_strategy(&path, "shortest");
    let (fib, lsdb) = diamond_lsdb();
    assert_eq!(next_hop_count(&fib), 1, "initial shortest: 1 next-hop");

    let watcher = start_watcher(&path, fib.clone(), lsdb);
    assert!(watcher.is_running());

    // 修改文件：shortest -> ecmp
    write_strategy(&path, "ecmp");
    assert!(
        wait_for_events(&watcher, 1, Duration::from_secs(5)),
        "watcher should detect change within 5s"
    );

    // FIB 已重算为 ECMP
    assert_eq!(
        next_hop_count(&fib),
        2,
        "after reload: ecmp gives 2 next-hops"
    );
    assert_eq!(fib.read().generation(), 2, "generation should advance");

    // 事件记录：Applied{strategy: "ecmp"}
    let events = watcher.events();
    let applied = events
        .iter()
        .find(|e| matches!(&e.kind, ReloadEventKind::Applied { .. }));
    assert!(applied.is_some(), "should have Applied event");
    if let Some(e) = applied {
        match &e.kind {
            ReloadEventKind::Applied {
                strategy,
                generation,
            } => {
                assert_eq!(strategy, "ecmp");
                assert_eq!(*generation, 2);
            }
            _ => unreachable!(),
        }
    }

    let mut watcher = watcher;
    watcher.stop();
    assert!(!watcher.is_running(), "stopped watcher not running");
    std::fs::remove_file(&path).ok();
}

#[test]
fn watcher_keeps_old_strategy_on_parse_failure() {
    let path = temp_config_path();
    write_strategy(&path, "ecmp");
    let (fib, lsdb) = diamond_lsdb();
    // 手动先切到 ecmp，建立"旧策略"
    {
        let db = lsdb.read().unwrap();
        fib.set_strategy(RoutingStrategy::Ecmp, &db);
    }
    assert_eq!(next_hop_count(&fib), 2);
    let gen_before = fib.read().generation();

    let watcher = start_watcher(&path, fib.clone(), lsdb);
    // 写入非法策略
    write_strategy(&path, "not-a-real-strategy");
    assert!(
        wait_for_events(&watcher, 1, Duration::from_secs(5)),
        "watcher should record failure within 5s"
    );

    // 旧策略与旧 FIB 原样保留
    assert_eq!(
        next_hop_count(&fib),
        2,
        "FIB must remain ecmp after parse failure"
    );
    assert_eq!(
        fib.read().generation(),
        gen_before,
        "generation must not advance on failure"
    );

    // 事件记录：ParseFailed
    let events = watcher.events();
    assert!(
        events
            .iter()
            .any(|e| matches!(&e.kind, ReloadEventKind::ParseFailed { .. })),
        "should have ParseFailed event"
    );
    // 没有 Applied 事件
    assert!(
        !events
            .iter()
            .any(|e| matches!(&e.kind, ReloadEventKind::Applied { .. })),
        "must not Apply on parse failure"
    );

    let mut watcher = watcher;
    watcher.stop();
    std::fs::remove_file(&path).ok();
}

#[test]
fn watcher_stop_joins_thread() {
    let path = temp_config_path();
    write_strategy(&path, "shortest");
    let (fib, lsdb) = diamond_lsdb();

    let mut watcher = start_watcher(&path, fib, lsdb);
    assert!(watcher.is_running());
    watcher.stop();
    assert!(
        !watcher.is_running(),
        "after stop(), is_running must be false"
    );
    // stop() 已 join：事件缓冲仍可查询（无 use-after-join）
    let _ = watcher.events();
    // 重复 stop() 安全（幂等）
    watcher.stop();
    std::fs::remove_file(&path).ok();
}

#[test]
fn watcher_event_log_bounded() {
    let path = temp_config_path();
    write_strategy(&path, "shortest");
    let (fib, lsdb) = diamond_lsdb();

    let config = WatcherConfig {
        config_path: path.to_path_buf(),
        poll_interval: Duration::from_millis(50),
        max_events: 3,
    };
    let watcher = StrategyWatcher::start(config, fib.clone(), lsdb).expect("watcher start");

    // 触发多次 reload：shortest -> ecmp -> shortest -> ecmp -> shortest
    // 注意：max_events=3 有界，等待按 seq（第 i 次 reload 产生 seq=i 的事件）。
    for (i, s) in ["ecmp", "shortest", "ecmp", "shortest"].iter().enumerate() {
        write_strategy(&path, s);
        assert!(
            wait_for_seq(&watcher, i as u64, Duration::from_secs(5)),
            "reload {} should be detected",
            i
        );
    }

    let events = watcher.events();
    assert!(
        events.len() <= 3,
        "event log must be bounded by max_events=3, got {}",
        events.len()
    );
    // seq 单调递增（环形缓冲保留最新的）
    let seqs: Vec<u64> = events.iter().map(|e| e.seq).collect();
    let mut sorted = seqs.clone();
    sorted.sort_unstable();
    assert_eq!(seqs, sorted, "seq must be monotonic");

    let mut watcher = watcher;
    watcher.stop();
    std::fs::remove_file(&path).ok();
}

#[test]
fn watcher_ignores_content_unchanged_rewrite() {
    let path = temp_config_path();
    write_strategy(&path, "shortest");
    let (fib, lsdb) = diamond_lsdb();

    let watcher = start_watcher(&path, fib.clone(), lsdb);
    // 等 watcher 完成初始基线读取
    std::thread::sleep(Duration::from_millis(200));
    let baseline = watcher.events().len();

    // 重写相同内容（mtime 变，哈希不变）→ 不应产生事件
    write_strategy(&path, "shortest");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        watcher.events().len(),
        baseline,
        "rewriting identical content must not produce events"
    );
    assert_eq!(
        fib.read().generation(),
        1,
        "no recompute on identical content"
    );

    let mut watcher = watcher;
    watcher.stop();
    std::fs::remove_file(&path).ok();
}

#[test]
fn deletion_test_no_watcher_still_works() {
    // Deletion Test：不启动 watcher，系统退化为"无热加载"——
    // 手动 set_strategy() 仍可用，无 panic、无挂起。
    let (fib, lsdb) = diamond_lsdb();
    assert_eq!(next_hop_count(&fib), 1);
    {
        let db = lsdb.read().unwrap();
        let generation = fib.set_strategy(RoutingStrategy::Ecmp, &db);
        assert_eq!(generation, 2);
    }
    assert_eq!(next_hop_count(&fib), 2);
    // 无 watcher 线程被创建：本测试结束时进程干净退出即通过
}

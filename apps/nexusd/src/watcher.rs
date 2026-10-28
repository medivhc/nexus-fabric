//! 配置文件夹热加载 watcher（轮询实现，零新依赖）。
//!
//! 设计：
//! - 每 2 秒轮询一次配置文件夹内已知文件的 mtime+size（见 `config::FileMeta`）。
//! - 检测到变更 → 重载 → 校验 → 分类 → 应用/拒绝。
//! - 校验失败：拒绝应用，保留旧配置，记 error 日志，**不 crash**（进程继续跑旧配置）。
//! - `ChangeKind::NeedsRestart`：记 warning，提示用户重启 daemon，不自动重启。
//!
//! 热加载分级（与 `config.rs` 文档一致）：
//! | 变更类型 | 行为 |
//! |---|----|
//! | proxy.yaml 内容变更 | 需重启（engine 只在启动构造） |
//! | dns.toml 内容变更 | 需重启（dns service owns sockets/cache） |
//! | network.toml 内容变更 | 热生效（peer 列表等；端口类变更由 N1 侧自行决定） |
//! | daemon.toml localapi_addr 变更 | 需重启（warning，不自动重启） |
//! | 任一文件新增/删除 | 需重启（子系统启停需重新装配，warning） |
//! | 任一文件校验失败 | 拒绝，沿用旧配置，error 日志，不 crash |
//!
//! 并发模型（AGENTS.md §13）：watcher 线程由 daemon 主线程拥有；
//! 通过 `mpsc::Sender<ReloadEvent>` 向主线程报告事件，不直接改共享状态。
//! 主线程是唯一的配置应用者（single writer）。

use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::time::Duration;

use super::config::{self, ChangeKind, ConfigDir, LoadedConfig};

/// 轮询间隔（config 热加载 2 秒延迟可接受；低于 inotify 实时性，但零依赖）。
pub const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Watcher 发给主线程的重载事件。
#[derive(Debug)]
pub enum ReloadEvent {
    /// 热加载成功（已应用新配置）。
    Applied {
        /// 变更的文件名列表。
        files: Vec<String>,
    },
    /// 需要重启 daemon（配置已校验但需重启才生效）。
    NeedsRestart {
        /// 触发本次事件的变更文件。
        files: Vec<String>,
        /// 原因描述。
        reason: String,
    },
    /// 重载被拒绝（校验失败），沿用旧配置。
    Rejected {
        /// 错误描述。
        error: String,
    },
}

/// 启动 watcher 线程。返回 JoinHandle（daemon 主线程拥有，退出时 join）。
///
/// `current` 为启动时已加载的配置（watcher 以此为基准做变更检测）。
pub fn spawn(
    dir: ConfigDir,
    current: LoadedConfig,
    tx: Sender<ReloadEvent>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("nexusd-cfg-watch".to_string())
        .spawn(move || watch_loop(dir, current, tx))
        .expect("spawn config watcher")
}

fn watch_loop(dir: ConfigDir, mut current: LoadedConfig, tx: Sender<ReloadEvent>) {
    // 已知文件列表（固定集合，避免遍历目录引入意外文件）。
    let files = [
        config::DAEMON_TOML,
        config::NETWORK_TOML,
        config::PROXY_YAML,
        config::DNS_TOML,
        config::WORKSPACE_TOML,
    ];
    loop {
        std::thread::sleep(POLL_INTERVAL);

        // 检测任一文件元信息变化（新增/删除/修改）。
        let mut changed: Vec<String> = Vec::new();
        for f in files {
            let path: PathBuf = dir.file(f);
            let old_meta = current.meta.get(f).copied();
            let new_meta = config::FileMeta::of(&path);
            if old_meta != new_meta {
                changed.push(f.to_string());
            }
        }
        if changed.is_empty() {
            continue;
        }

        // 重载 + 校验。失败 → 拒绝，保留旧配置内容，
        // 但更新 meta 基准避免对同一坏文件重复刷屏。
        let new_cfg = match config::load(&dir) {
            Ok(c) => c,
            Err(e) => {
                for f in changed.iter() {
                    let path: PathBuf = dir.file(f);
                    if let Some(m) = config::FileMeta::of(&path) {
                        current.meta.insert(f.clone(), m);
                    } else {
                        current.meta.remove(f);
                    }
                }
                // 写点 2（spec §9.1）：构造点即脱敏（口令不落 stderr）。
                let _ = tx.send(ReloadEvent::Rejected {
                    error: nexus::redact::redact_secrets(&format!("files {changed:?}: {e}")),
                });
                continue;
            }
        };

        // 分类。
        match config::classify_change(&current, &new_cfg) {
            ChangeKind::Hot => {
                current = new_cfg;
                let _ = tx.send(ReloadEvent::Applied { files: changed });
            }
            ChangeKind::NeedsRestart => {
                // 不更新 current（旧配置继续生效），提示重启。
                // 注意：若用户后续又改回，meta 对比会再次触发，这是预期的。
                let reason = if changed.iter().any(|f| f == config::PROXY_YAML) {
                    // Q-7=B：proxy.yaml 固定句式（§7.6.1）。
                    "proxy.yaml changed: outbound engine requires daemon restart".to_string()
                } else if changed.iter().any(|f| f == config::DNS_TOML) {
                    // AC14(3)：dns.toml 固定句式（Q8）。
                    "config change requires restart: dns.toml (dns service owns sockets/cache)"
                        .to_string()
                } else {
                    format!(
                        "files {changed:?} require daemon restart to take effect; \
                         current config remains active"
                    )
                };
                let _ = tx.send(ReloadEvent::NeedsRestart {
                    files: changed,
                    reason,
                });
                // 更新 meta 基准，避免对同一变更重复 warning。
                // 但保留旧配置内容（current 的各字段不动，只换 meta）。
                current.meta = new_cfg.meta;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::channel;

    fn write(dir: &std::path::Path, name: &str, content: &str) {
        std::fs::write(dir.join(name), content).unwrap();
        // 确保 mtime 变化（某些文件系统粒度粗）。
        std::thread::sleep(Duration::from_millis(1100));
    }

    #[test]
    fn hot_reload_applies_and_rejects_bad() {
        let d = std::env::temp_dir().join(format!(
            "nexusd-watch-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let yaml_v1 = "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: d\n    kind: direct\n";
        let yaml_v2 = "schema_version: 1\nrules:\n  - tag: r2\n    kind: domain\n    match: x.com\n    action:\n      - kind: select_outbound\n        tag: d\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: d\noutbounds:\n  - tag: d\n    kind: direct\n";
        write(&d, config::PROXY_YAML, yaml_v1);
        write(&d, config::DNS_TOML, "[dns]\nupstream = [\"1.1.1.1\"]\n");
        let dir = ConfigDir::new(&d).unwrap();
        let current = config::load(&dir).unwrap();
        let (tx, rx) = channel();
        let _h = spawn(dir.clone(), current, tx);

        // Q8/AC14(3)：已有 dns.toml 的**内容**变更 → NeedsRestart + 固定日志原文。
        write(&d, config::DNS_TOML, "[dns]\nupstream = [\"8.8.8.8\"]\n");
        let ev = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("expected NeedsRestart event for dns.toml");
        match ev {
            ReloadEvent::NeedsRestart { files, reason } => {
                assert_eq!(files, vec![config::DNS_TOML.to_string()]);
                assert_eq!(
                    reason,
                    "config change requires restart: dns.toml (dns service owns sockets/cache)"
                );
            }
            other => panic!("got {other:?}"),
        }

        // proxy.yaml 内容变更 → NeedsRestart（Q-7=B：engine 只在启动构造）
        write(&d, config::PROXY_YAML, yaml_v2);
        let ev = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("expected NeedsRestart event");
        assert!(matches!(ev, ReloadEvent::NeedsRestart { .. }), "got {ev:?}");

        // 无效变更 → Rejected（TOML 语法错误）
        write(&d, config::NETWORK_TOML, "[[[broken");
        let ev = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("expected Rejected event");
        assert!(matches!(ev, ReloadEvent::Rejected { .. }), "got {ev:?}");

        // 清理坏文件（否则后续重载一直失败）
        std::fs::remove_file(d.join(config::NETWORK_TOML)).unwrap();
        std::thread::sleep(Duration::from_millis(1100));
        // 等 watcher 消化删除事件（会是 NeedsRestart，因为文件删除；消费掉它）
        let _ = rx.recv_timeout(Duration::from_secs(10));

        // daemon addr 变更 → NeedsRestart
        write(
            &d,
            config::DAEMON_TOML,
            "[localapi]\naddr = \"127.0.0.1:18888\"\n",
        );
        let ev = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("expected NeedsRestart event");
        assert!(matches!(ev, ReloadEvent::NeedsRestart { .. }), "got {ev:?}");

        let _ = std::fs::remove_dir_all(&d);
    }
}

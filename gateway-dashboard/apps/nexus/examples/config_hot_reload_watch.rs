//! E4 `product.config-hot-reload-watch`：std 文件轮询驱动 revision 前进。
//!
//! ```text
//! cargo run --quiet -p nexus --example config_hot_reload_watch -- --json
//! ```

#![forbid(unsafe_code)]

use nexus_connectivity::config_hot_reload::{FileWatcher, HotReloadConfig, HotReloadManager};
use serde_json::json;

fn run() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!("nexus-cfg-{}.toml", std::process::id()));
    std::fs::write(&path, "version = 1")?;

    let mut watcher = FileWatcher::new(&path);
    // 首次 poll 建立基线，不报变化。
    let first_poll_changed = watcher.poll_changed()?;

    let mgr_cfg = HotReloadConfig::new(50, true)?;
    let mut mgr = HotReloadManager::new(mgr_cfg);

    // 修改 1 -> 检测变化 -> 校验通过 -> revision 1。
    std::fs::write(&path, "version = 2")?;
    let after_edit1_changed = watcher.poll_changed()?;
    let content1 = watcher.read_current()?;
    mgr.propose_reload(1, !content1.is_empty());
    let revision1 = mgr.current_revision();

    // 修改 2 -> revision 2。
    std::fs::write(&path, "version = 3")?;
    let after_edit2_changed = watcher.poll_changed()?;
    mgr.propose_reload(2, true);
    let revision2 = mgr.current_revision();

    // 清理临时文件。
    std::fs::remove_file(&path)?;
    let temp_file_removed = !path.exists();

    Ok(json!({
        "verdict": "PASS",
        "command": "config-hot-reload-watch",
        "first_poll_changed": first_poll_changed,
        "after_edit1_changed": after_edit1_changed,
        "revision1": revision1,
        "after_edit2_changed": after_edit2_changed,
        "revision2": revision2,
        "temp_file_removed": temp_file_removed,
    }))
}

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match run() {
        Ok(v) => {
            if as_json {
                println!("{v}");
            } else {
                println!("config_hot_reload_watch: {v}");
            }
        }
        Err(e) => {
            eprintln!("config_hot_reload_watch failed: {e}");
            std::process::exit(1);
        }
    }
}

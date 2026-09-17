//! E4 产品场景 `product.remote-workspace-rejected-rollback` 的可执行驱动（Composition Root）。
//!
//! 由 `scenarios/product/remote_workspace_rejected_rollback.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example remote_workspace_rejected_rollback -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出，供 harness 按路径求值）；
//! 不带 `--json` 时打印人类可读摘要。

#![forbid(unsafe_code)]

use nexus::remote_workspace_rejected_rollback;

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match remote_workspace_rejected_rollback() {
        Ok(json) => {
            if as_json {
                println!("{json}");
            } else {
                println!("remote workspace rejected rollback OK: {json}");
            }
        }
        Err(err) => {
            eprintln!("remote_workspace_rejected_rollback failed: {err}");
            std::process::exit(1);
        }
    }
}

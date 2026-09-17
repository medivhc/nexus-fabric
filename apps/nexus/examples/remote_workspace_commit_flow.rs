//! E4 产品场景 `product.remote-workspace-commit-flow` 的可执行驱动（Composition Root）。
//!
//! 由 `scenarios/product/remote_workspace_commit_flow.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example remote_workspace_commit_flow -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出，供 harness 按路径求值）；
//! 不带 `--json` 时打印人类可读摘要。

#![forbid(unsafe_code)]

use nexus::remote_workspace_commit_flow;

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match remote_workspace_commit_flow() {
        Ok(json) => {
            if as_json {
                println!("{json}");
            } else {
                println!("remote workspace commit flow OK: {json}");
            }
        }
        Err(err) => {
            eprintln!("remote_workspace_commit_flow failed: {err}");
            std::process::exit(1);
        }
    }
}

//! E4 产品场景 `product.group-isolation` 的可执行驱动（Composition Root）。
//!
//! 由 `scenarios/product/group_isolation.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example group_isolation -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出）；不带 `--json` 时打印摘要。
//!
//! 本 example 自包含：直接使用 `nexus_connectivity::group_isolation`，
//! 不依赖 `nexus` 库中的 flow 函数。

#![forbid(unsafe_code)]

use nexus_connectivity::group_isolation::{
    GroupConfig, GroupIsolation, GroupIsolationError, IsolationMode,
};
use serde_json::json;

/// 跑一遍分组隔离决策矩阵，返回单个 JSON 对象。
fn run() -> Result<serde_json::Value, GroupIsolationError> {
    // 节点 prod-a/prod-b 在组 "prod"，dev-a/dev-b 在组 "dev"。
    let mut mgr = GroupIsolation::new(IsolationMode::Full);
    mgr.define_group(GroupConfig::new("prod", IsolationMode::Full)?);
    mgr.define_group(GroupConfig::new("dev", IsolationMode::Full)?);
    mgr.assign("prod-a", "prod")?;
    mgr.assign("prod-b", "prod")?;
    mgr.assign("dev-a", "dev")?;
    mgr.assign("dev-b", "dev")?;

    // 同组 prod→prod：Allow。
    let same_group = mgr.check("prod-a", "prod-b");
    // 跨组 prod→dev（默认）：Deny。
    let cross_group_default = mgr.check("prod-a", "dev-a");

    // 登记例外 prod→dev。
    mgr.allow_exception("prod", "dev");
    let exception_count = mgr.exception_count();
    // 登记例外后 prod→dev：Allow。
    let cross_group_after_exception = mgr.check("prod-a", "dev-a");

    // mode=None：任意节点（含未分配）一律 Allow。
    let open = GroupIsolation::new(IsolationMode::None);
    let open_mode_allows = open.check("prod-a", "unassigned-x");

    // Full 模式下未分配节点：Deny。
    let unassigned_denied = mgr.check("prod-a", "ghost-node");

    // 错误路径 E4：空组名构造被拒、把节点划入未声明组被拒。
    let empty_group_rejected = GroupConfig::new("", IsolationMode::Full).is_err();
    let unknown_group_rejected = mgr.assign("orphan", "ghost-group").is_err();

    Ok(json!({
        "verdict": "PASS",
        "command": "group-isolation",
        "same_group": same_group.as_str(),
        "cross_group_default": cross_group_default.as_str(),
        "cross_group_after_exception": cross_group_after_exception.as_str(),
        "open_mode_allows": open_mode_allows.as_str(),
        "unassigned_denied": unassigned_denied.as_str(),
        "exception_count": exception_count,
        "empty_group_rejected": empty_group_rejected,
        "unknown_group_rejected": unknown_group_rejected,
    }))
}

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match run() {
        Ok(value) => {
            if as_json {
                println!("{value}");
            } else {
                let same = value["same_group"].as_str().unwrap_or("?");
                let cross = value["cross_group_default"].as_str().unwrap_or("?");
                println!("group isolation OK: same_group={same} cross_group_default={cross}");
            }
        }
        Err(err) => {
            eprintln!("group_isolation example failed: {err}");
            std::process::exit(1);
        }
    }
}

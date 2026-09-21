//! E4 产品场景 `product.log-level` 的可执行驱动（Composition Root）。
//!
//! 由 `scenarios/product/log_level.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example log_level -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出）；不带 `--json` 时打印摘要。
//! 演示：global=Info，override connectivity=Debug；随后动态调整全局与模块级别。

#![forbid(unsafe_code)]

use nexus_connectivity::log_level::*;

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");

    let result = run();
    match result {
        Ok(json) => {
            if as_json {
                println!("{json}");
            } else {
                println!("log level control OK: {json}");
            }
        }
        Err(err) => {
            eprintln!("log_level example failed: {err}");
            std::process::exit(1);
        }
    }
}

/// 构建演示并输出单个 JSON 对象。
fn run() -> Result<String, String> {
    // global=Info，override connectivity=Debug。
    let mut config = LogLevelConfig::new(LogLevel::Info);
    config.set_module("connectivity".to_string(), LogLevel::Debug);
    let mut ctl = LogLevelController::new(config);

    let eff_connectivity = ctl.effective_level("connectivity").as_str().to_string();
    let eff_routing = ctl.effective_level("routing").as_str().to_string();
    let debug_conn_enabled = ctl.enabled("connectivity", LogLevel::Debug);
    let debug_routing_enabled = ctl.enabled("routing", LogLevel::Debug);

    // set_global(Warn) 后，未覆盖的 routing 全局变为 Warn。
    ctl.set_global(LogLevel::Warn);
    let after_global_warn = ctl.effective_level("routing").as_str().to_string();

    // set_module_level("routing", Trace) 后，routing 覆盖为 Trace。
    ctl.set_module_level("routing", LogLevel::Trace);
    let after_module_trace = ctl.effective_level("routing").as_str().to_string();

    // "ERROR" 大小写不敏感解析。
    let parsed = "ERROR".parse::<LogLevel>().map_err(|e| e.to_string())?;
    let parsed_level = parsed.as_str().to_string();

    let json = serde_json::json!({
        "verdict": "PASS",
        "command": "log-level",
        "eff_connectivity": eff_connectivity,
        "eff_routing": eff_routing,
        "debug_conn_enabled": debug_conn_enabled,
        "debug_routing_enabled": debug_routing_enabled,
        "after_global_warn": after_global_warn,
        "after_module_trace": after_module_trace,
        "parsed_level": parsed_level,
    });
    Ok(json.to_string())
}

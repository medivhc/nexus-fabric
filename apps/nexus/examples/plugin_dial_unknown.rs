//! E4 `product.plugin-dial-unknown`：未知插件名 → dial 直接失败。
//!
//! 协议：
//! 1. `dial_with_obfs(addr, Some("no-such-plugin"), params)` 必须返回 Err，
//!    且 `err.kind() == ErrorKind::NotFound`（P2 硬校验）；
//! 2. 关键：不得静默回退到 plain——回退意味着 Ok，此处 Ok 即 FAIL（P3）；
//! 3. 断言可观测 `dial_err_count("no-such-plugin", UnknownPlugin)` +1（P5）。
//!
//! 只用公开 API + 可观测输出。TCP loopback 不可用 → SKIP（exit 0）。

use nexus_plugin::{
    DialFailReason, ObfsParams, dial_err_count, dial_with_obfs, init_builtin_plugins,
};
use std::io;
use std::net::TcpListener;

enum Outcome {
    Skip(String),
    Fail(String),
}

fn run() -> Result<String, Outcome> {
    init_builtin_plugins();

    let listener =
        TcpListener::bind("127.0.0.1:0").map_err(|e| Outcome::Skip(format!("bind: {e}")))?;
    let addr = listener
        .local_addr()
        .map_err(|e| Outcome::Fail(format!("local_addr: {e}")))?;

    let params = ObfsParams { key: b"" };
    let before = dial_err_count("no-such-plugin", DialFailReason::UnknownPlugin);

    // 1+2. 未知插件名 → dial 必须失败（不回退）。
    match dial_with_obfs(addr, Some("no-such-plugin"), &params) {
        Ok(_) => {
            return Err(Outcome::Fail(
                "dial with unknown plugin succeeded: silent fallback to plain (P3 violated)"
                    .into(),
            ));
        }
        Err(e) => {
            if e.kind() != io::ErrorKind::NotFound {
                return Err(Outcome::Fail(format!(
                    "wrong error kind: {:?}, want NotFound",
                    e.kind()
                )));
            }
        }
    }

    // 3. P5 可观测。
    let after = dial_err_count("no-such-plugin", DialFailReason::UnknownPlugin);
    if after != before + 1 {
        return Err(Outcome::Fail(format!(
            "obfs_dial_err{{no-such-plugin,unknown_plugin}} = {after}, want {}",
            before + 1
        )));
    }

    Ok(format!(
        "{{\"verdict\":\"PASS\",\"hard_fail\":true,\"dial_err_unknown_plugin\":{after}}}"
    ))
}

fn main() {
    let json = std::env::args().any(|a| a == "--json");
    match run() {
        Ok(out) => {
            if json {
                println!("{out}");
            } else {
                println!("plugin-dial-unknown E4: PASS");
            }
        }
        Err(Outcome::Skip(reason)) => {
            if json {
                println!("{{\"verdict\":\"SKIP\",\"reason\":{reason:?}}}");
            } else {
                println!("plugin-dial-unknown E4: SKIP ({reason})");
            }
        }
        Err(Outcome::Fail(reason)) => {
            if json {
                println!("{{\"verdict\":\"FAIL\",\"reason\":{reason:?}}}");
            } else {
                eprintln!("plugin-dial-unknown E4: FAIL ({reason})");
            }
            std::process::exit(1);
        }
    }
}

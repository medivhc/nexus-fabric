//! `nexus provider` 命令族（N2 P0-5）：提供方侧常驻准入服务。
//!
//! - `nexus provider serve --bind <addr:port> [--once]`
//!
//! 在 B 机运行：TCP 监听准入连接（`n2_admission::serve_forever`），执行
//! D6 提供方侧 grant 判定（每次建 Session、每次写审计）＋D1 租约落盘。
//! 连接计数经 stderr 日志可观测（`nexus plan` 只读断言：plan 期间提供方侧
//! 不得有新连接）。

use crate::n2_admission::serve_forever;

/// `nexus provider serve --bind <addr:port> [--once]`
fn run_serve(args: &[String]) -> i32 {
    const USAGE: &str = "usage: nexus provider serve --bind <addr:port> [--once]";
    let mut bind: Option<String> = None;
    let mut once = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--bind" => {
                i += 1;
                bind = args.get(i).cloned();
            }
            "--once" => {
                once = true;
            }
            other => {
                eprintln!("error: unexpected argument for provider serve: {other}");
                eprintln!("{USAGE}");
                return 2;
            }
        }
        i += 1;
    }
    let Some(bind) = bind else {
        eprintln!("error: provider serve requires --bind <addr:port>");
        eprintln!("{USAGE}");
        return 2;
    };
    let node_dir = crate::node_cli::node_dir();
    match serve_forever(&bind, &node_dir, once) {
        Ok(()) => 0,
        Err(e) => {
            // bind 失败等人为错误：stderr＋exit 1（非 JSON silencioso 失败）。
            eprintln!("error: provider serve: {e}");
            1
        }
    }
}

/// `nexus provider` 命令族入口（`--json` 在此命令族无意义：serve 为长驻进程）。
pub fn run_provider(args: &[String], _json_mode: bool) -> i32 {
    const USAGE: &str = "usage: nexus provider <serve> ...";
    let Some(sub) = args.first() else {
        eprintln!("error: missing subcommand for provider");
        eprintln!("{USAGE}");
        return 2;
    };
    match sub.as_str() {
        "serve" => run_serve(&args[1..]),
        other => {
            eprintln!("error: unknown provider subcommand: {other}");
            eprintln!("{USAGE}");
            2
        }
    }
}

#![forbid(unsafe_code)]

mod code_intel;
mod commands;
mod config;
mod env;
mod evidence;
mod gates;
mod run_scenario;
mod scenario;
mod scenario_cmd;

use serde_json::{Value, json};
use std::process::ExitCode;

const SCHEMA_VERSION: u32 = 1;

/// Dispatch result: (verdict, message, extra JSON fields).
type Outcome = (String, String, Vec<(String, Value)>);

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let machine = args.iter().any(|a| a == "--json");
    let filtered: Vec<String> = args.iter().filter(|a| *a != "--json").cloned().collect();
    let command = filtered
        .first()
        .cloned()
        .unwrap_or_else(|| "help".to_string());

    let rest = &filtered[1..];
    let outcome = dispatch(&command, rest);

    let mut obj = serde_json::Map::new();
    obj.insert("schema_version".to_string(), json!(SCHEMA_VERSION));
    obj.insert("command".to_string(), json!(command));
    obj.insert("verdict".to_string(), json!(outcome.0));
    obj.insert("message".to_string(), json!(outcome.1));
    for (k, v) in &outcome.2 {
        obj.insert(k.clone(), v.clone());
    }

    // `mcp serve` 的 stdout **就是 MCP 协议通道**：往它上面追加一段裸 JSON，严格客户端会把
    // 会话结尾读成畸形帧（独立 Review round 2 的 N5；修前实测 Red 见
    // `.agents/red-evidence-mcp-round2.txt`：`printf '' | mcp serve --json` 的 stdout 是
    // 194 字节裸 JSON，一帧响应后裸 JSON 直接粘在帧尾、没有分隔）。
    // 因此只有这一条命令的退出 envelope 走 stderr；退出码仍由 verdict 决定，其余命令不变
    // （场景与 Evidence 都从 stdout 读 JSON，改它们会造成无关的契约漂移）。
    let protocol_channel_is_stdout =
        command == "mcp" && rest.first().map(String::as_str) == Some("serve");
    let emit = |line: String| {
        if protocol_channel_is_stdout {
            eprintln!("{line}");
        } else {
            println!("{line}");
        }
    };

    if machine {
        emit(
            serde_json::to_string(&Value::Object(obj))
                .unwrap_or_else(|e| format!("{{\"verdict\":\"FAIL\",\"message\":\"{e}\"}}")),
        );
    } else {
        emit(format!(
            "nexus-harness {command}: {} - {}",
            outcome.0, outcome.1
        ));
        for (k, v) in &outcome.2 {
            emit(format!("  {k}: {v}"));
        }
    }

    match outcome.0.as_str() {
        "FAIL" => ExitCode::from(1),
        "BLOCKED" => ExitCode::from(2),
        _ => ExitCode::SUCCESS,
    }
}

fn dispatch(command: &str, rest: &[String]) -> Outcome {
    match command {
        "status" => commands::status(),
        "context" => commands::context(rest),
        "check" => commands::check(),
        "test" => commands::test_affected(),
        "verify" => commands::verify(rest.first().map(String::as_str).unwrap_or("")),
        "explain" => commands::explain(),
        "run" => run_scenario::run_scenario(rest),
        "scenario" => scenario_cmd::dispatch(rest),
        "code" => code_intel::run(rest),
        "mcp" => code_intel::mcp::dispatch(rest),
        "bench" => commands::bench(),
        "replay" => (
            "UNKNOWN".to_string(),
            "replay gate is not implemented in the MVP harness (recorded UNKNOWN, not silently passed)"
                .to_string(),
            Vec::new(),
        ),
        _ => (
            "BLOCKED".to_string(),
            "supported commands: status, context, check, test, verify, explain, bench, replay, scenario, code"
                .to_string(),
            Vec::new(),
        ),
    }
}

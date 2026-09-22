#![forbid(unsafe_code)]

mod commands;
mod config;
mod env;
mod evidence;
mod gates;
mod run_scenario;
mod scenario;

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

    let outcome = dispatch(&command, &filtered[1..]);

    let mut obj = serde_json::Map::new();
    obj.insert("schema_version".to_string(), json!(SCHEMA_VERSION));
    obj.insert("command".to_string(), json!(command));
    obj.insert("verdict".to_string(), json!(outcome.0));
    obj.insert("message".to_string(), json!(outcome.1));
    for (k, v) in &outcome.2 {
        obj.insert(k.clone(), v.clone());
    }

    if machine {
        println!(
            "{}",
            serde_json::to_string(&Value::Object(obj))
                .unwrap_or_else(|e| format!("{{\"verdict\":\"FAIL\",\"message\":\"{e}\"}}"))
        );
    } else {
        println!("nexus-harness {command}: {} - {}", outcome.0, outcome.1);
        for (k, v) in &outcome.2 {
            println!("  {k}: {v}");
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
        "context" => commands::context(rest.first().map(String::as_str).unwrap_or("")),
        "check" => commands::check(),
        "test" => commands::test_affected(),
        "verify" => commands::verify(rest.first().map(String::as_str).unwrap_or("")),
        "explain" => commands::explain(),
        "run" => run_scenario::run_scenario(rest),
        "bench" => commands::bench(),
        "replay" => (
            "UNKNOWN".to_string(),
            "replay gate is not implemented in the MVP harness (recorded UNKNOWN, not silently passed)"
                .to_string(),
            Vec::new(),
        ),
        _ => (
            "BLOCKED".to_string(),
            "supported commands: status, context, check, test, verify, explain, bench, replay"
                .to_string(),
            Vec::new(),
        ),
    }
}

#![forbid(unsafe_code)]

use std::env;

const SCHEMA_VERSION: u32 = 1;

fn json(command: &str, verdict: &str, message: &str) -> String {
    format!(
        "{{\"schema_version\":{SCHEMA_VERSION},\"command\":\"{command}\",\"verdict\":\"{verdict}\",\"message\":\"{message}\"}}"
    )
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let machine = args.iter().any(|a| a == "--json");
    let filtered: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|a| *a != "--json")
        .collect();

    let command = filtered.first().copied().unwrap_or("help");
    let supported = matches!(
        command,
        "status" | "context" | "check" | "test" | "verify" | "explain" | "bench" | "replay"
    );

    let (verdict, message) = if supported {
        (
            "UNKNOWN",
            "bootstrap harness contract is present; production gate adapters are not implemented in this skeleton",
        )
    } else {
        (
            "BLOCKED",
            "supported commands: status, context, check, test, verify, explain, bench, replay",
        )
    };

    if machine {
        println!("{}", json(command, verdict, message));
    } else {
        println!("nexus-harness {command}: {verdict} - {message}");
    }
}

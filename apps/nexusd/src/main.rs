#![forbid(unsafe_code)]

use std::process::ExitCode;

use serde_json::Value;

/// nexusd：桌面/服务端主 Runtime Composition Root。
///
/// 用法：
///   nexusd run <service|internet-access|compute> [--json]
///   nexusd run <unknown> --json            -> 结构化拒绝（UNKNOWN_RESOURCE，exit 0）
///   nexusd status --json                   -> §9 可观察性总览
///   nexusd dns status --json / dns cache --json
///   nexusd session watch --json
///   nexusd connectivity status --json
///   nexusd plan explain --json
///   nexusd platform capabilities --json
///   nexusd <workspace|compute|diagnose> ... --json
///                                          -> 领域未就绪：UNSUPPORTED（exit 0）
///
/// 语义：本 app 只承担 CLI 解析与装配（MODULE.md 冻结契约）；全部闭环与快照复用
/// `nexus` SDK 组合根函数，不复制领域逻辑。无效 CLI 用法 exit 非 0。
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [verb, resource, flag] if verb == "run" && flag == "--json" => run_resource(resource),
        [verb, resource] if verb == "run" => run_resource(resource),
        // §9 可观察性子命令：首个 token 命中即路由（透传完整命令，含 verb）。
        [verb, ..] if is_observability_verb(verb) => dispatch_observability(&args),
        _ => {
            eprintln!(
                "usage: nexusd run <service|internet-access|compute> [--json] | \
                 <status|dns|session|connectivity|plan|platform> ... --json"
            );
            ExitCode::FAILURE
        }
    }
}

/// 可观察性子命令首 token（PRODUCT §9）。
fn is_observability_verb(verb: &str) -> bool {
    matches!(
        verb,
        "status"
            | "dns"
            | "session"
            | "connectivity"
            | "plan"
            | "platform"
            | "workspace"
            | "compute"
            | "diagnose"
    )
}

/// 路由 §9 可观察性子命令到 SDK `observability` 模块。
fn dispatch_observability(args: &[String]) -> ExitCode {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        ["status", "--json"] => nexus::observability::status(),
        ["dns", "status", "--json"] => nexus::observability::dns_status(),
        ["dns", "cache", "--json"] => nexus::observability::dns_cache(),
        ["session", "watch", "--json"] => nexus::observability::session_watch(),
        ["connectivity", "status", "--json"] => nexus::observability::connectivity_status(),
        ["plan", "explain", "--json"] => nexus::observability::plan_explain(),
        ["platform", "capabilities", "--json"] => nexus::observability::platform_capabilities(),
        // 领域未就绪命令：显式 UNSUPPORTED（禁止静默降级，exit 0 = 请求已被处理）。
        cmd => {
            let name = cmd
                .iter()
                .take_while(|s| **s != "--json")
                .copied()
                .collect::<Vec<_>>()
                .join(" ");
            println!(
                "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"UNSUPPORTED\",\"command\":\"{name}\"}}}}"
            );
            return ExitCode::SUCCESS;
        }
    };
    print_json_result(result)
}

/// 路由资源名到 SDK 组合根闭环，并包装 daemon 入口元数据。
fn run_resource(resource: &str) -> ExitCode {
    let result: Result<Value, _> = match resource {
        "service" => nexus::remote_service_access_flow().map(|v| enrich("service", v)),
        "internet-access" => {
            nexus::remote_internet_access_flow().map(|v| enrich("internet-access", v))
        }
        "compute" => nexus::remote_compute_job_flow().map(|v| enrich("compute", v)),
        other => {
            // 未知资源：结构化拒绝（exit 0 = 请求已被 daemon 处理，拒绝也是处理结果）。
            println!(
                "{{\"verdict\":\"REJECTED\",\"error\":{{\"code\":\"UNKNOWN_RESOURCE\",\"resource\":\"{other}\"}},\"daemon\":{{\"entry\":\"nexusd\"}}}}"
            );
            return ExitCode::SUCCESS;
        }
    };
    print_json_result(result)
}

/// 在 SDK 输出的 JSON 对象上附加 daemon 入口元数据（场景断言 daemon.entry / daemon.resource）。
fn enrich(resource: &str, mut json: Value) -> Value {
    if let Some(obj) = json.as_object_mut() {
        obj.insert(
            "daemon".into(),
            serde_json::json!({ "entry": "nexusd", "resource": resource }),
        );
    }
    json
}

/// 输出结构化 JSON；无论成功/失败均 exit 0（请求已被 daemon 处理）。
fn print_json_result(result: Result<Value, impl std::fmt::Display>) -> ExitCode {
    match result {
        Ok(json) => {
            println!("{json}");
        }
        Err(e) => {
            println!(
                "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"INTERNAL\",\"message\":\"{e}\"}}}}"
            );
        }
    }
    ExitCode::SUCCESS
}

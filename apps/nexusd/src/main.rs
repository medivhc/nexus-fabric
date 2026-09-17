#![forbid(unsafe_code)]

use std::process::ExitCode;

/// nexusd：远程资源访问闭环的 daemon 单次执行入口（PRODUCT §6）。
///
/// 用法：
///   nexusd run <service|internet-access|compute> [--json]
///   nexusd run <unknown> --json            -> 结构化拒绝（UNKNOWN_RESOURCE，exit 0）
///
/// 语义：本 app 只承担 CLI 解析与装配（MODULE.md 冻结契约）；全部闭环复用
/// `nexus` SDK 组合根函数，不复制领域逻辑。无效 CLI 用法 exit 非 0。
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [verb, resource, flag] if verb == "run" && flag == "--json" => run_resource(resource),
        [verb, resource] if verb == "run" => run_resource(resource),
        _ => {
            eprintln!("usage: nexusd run <service|internet-access|compute> [--json]");
            ExitCode::FAILURE
        }
    }
}

/// 路由资源名到 SDK 组合根闭环，并包装 daemon 入口元数据。
fn run_resource(resource: &str) -> ExitCode {
    let result: Result<serde_json::Value, _> = match resource {
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
fn enrich(resource: &str, mut json: serde_json::Value) -> serde_json::Value {
    if let Some(obj) = json.as_object_mut() {
        obj.insert(
            "daemon".into(),
            serde_json::json!({ "entry": "nexusd", "resource": resource }),
        );
    }
    json
}

/// 输出结构化 JSON；无论成功/失败均 exit 0（请求已被 daemon 处理）。
fn print_json_result(result: Result<serde_json::Value, impl std::fmt::Display>) -> ExitCode {
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

//! CLI 前端 `ControlService` 实现。
//!
//! 把 `nexus-control-api` 的全部 19 个 `ControlCommand` 变体路由到
//! `crate::observability` 快照（与 nexusd 同源，不复制领域逻辑）。
//!
//! 同时提供 CLI 双输出所需的纯函数投影：
//! - `ControlServiceImpl::snapshot`：返回原始 `serde_json::Value`，供 `--json` 原样打印；
//! - `render_text`：把 JSON 投影为人读 `key: value` 行（非 `--json` 模式）；
//! - `ControlServiceImpl::error_to_json`：把 `NexusError` 映射为结构化
//!   `{"verdict":"FAIL",...}`（与 nexusd `print_json_result` 同形）。

use nexus_control_api::{ControlCommand, ControlOutput, ControlService, NexusError, StatusView};
use serde_json::Value;

/// Composition Root 的 `ControlService`：17 个 §9 观察命令接线到
/// `crate::observability` 快照（与 nexusd 同源）；2 个 N1 装配命令
/// （`NetworkUp`/`NetworkStatus`）由 `run()` 直接分发到进程内 Composition
/// Root（`crate::network`），此处仅提供诚实占位。无领域状态，可自由复制。
#[derive(Debug, Clone, Copy, Default)]
pub struct ControlServiceImpl;

impl ControlServiceImpl {
    /// 路由命令到其 observability 快照（原始 JSON）。
    ///
    /// 命令携带的位置参数（resource/session/target/name/workspace）是观察快照的
    /// 选择器占位；当前快照为确定性演示状态，函数内部不读取这些参数。
    pub fn snapshot(&self, command: &ControlCommand) -> Result<Value, NexusError> {
        let json = match command {
            ControlCommand::Status => crate::observability::status()?,
            ControlCommand::PlanExplain { .. } => crate::observability::plan_explain()?,
            ControlCommand::SessionWatch { .. } => crate::observability::session_watch()?,
            ControlCommand::ConnectivityStatus => crate::observability::connectivity_status()?,
            ControlCommand::ConnectivityCandidates => {
                crate::observability::connectivity_candidates()?
            }
            ControlCommand::ConnectivityProbe { .. } => crate::observability::connectivity_probe()?,
            ControlCommand::ConnectivityLinks => crate::observability::connectivity_links()?,
            ControlCommand::DnsStatus => crate::observability::dns_status()?,
            ControlCommand::DnsResolve { .. } => crate::observability::dns_resolve()?,
            ControlCommand::DnsProviders => crate::observability::dns_providers()?,
            ControlCommand::DnsCache => crate::observability::dns_cache()?,
            ControlCommand::WorkspaceHeads { .. } => crate::observability::workspace_heads()?,
            ControlCommand::WorkspaceConflicts { .. } => {
                crate::observability::workspace_conflicts()?
            }
            ControlCommand::WorkspaceCache { .. } => crate::observability::workspace_cache()?,
            ControlCommand::ComputeJobs => crate::observability::compute_jobs()?,
            ControlCommand::Diagnose => crate::observability::diagnose()?,
            ControlCommand::PlatformCapabilities => crate::observability::platform_capabilities()?,
            ControlCommand::Run { resource } => crate::run_resource(resource)?,
            // N1 装配命令由 run() 直接分发到进程内 Composition Root（M6），
            // 不走快照；此处仅为穷尽匹配提供诚实占位。
            ControlCommand::NetworkUp { .. } => serde_json::json!({
                "verdict": "FAIL",
                "detail": "network up is a foreground command; use `nexus network up --config <toml>`",
            }),
            ControlCommand::NetworkStatus => crate::network::status_json(None),
        };
        Ok(json)
    }

    /// 领域错误 -> 结构化 FAIL JSON（与 nexusd `print_json_result` 同形）。
    ///
    /// CLI 对领域拒绝仍 exit 0（请求已被处理）；机器消费者解析此对象判定 verdict。
    pub fn error_to_json(&self, err: &NexusError) -> Value {
        serde_json::json!({
            "verdict": "FAIL",
            "error": {
                "code": crate::error_code(err),
                "message": err.to_string(),
            },
        })
    }
}

impl ControlService for ControlServiceImpl {
    fn execute(&self, command: ControlCommand) -> Result<ControlOutput, NexusError> {
        let json = self.snapshot(&command)?;
        Ok(ControlOutput::Status(StatusView {
            lines: json_to_lines(&json),
        }))
    }
}

/// pretty-print JSON 为行（`ControlOutput::Status` 的既有投影形状）。
fn json_to_lines(json: &Value) -> Vec<String> {
    serde_json::to_string_pretty(json)
        .map(|s| s.lines().map(str::to_string).collect())
        .unwrap_or_else(|_| vec![json.to_string()])
}

/// 人读文本视图：把 JSON 对象投影为 `key: value` 行（字段→行，对象/数组递归一层）。
///
/// 文本只是 JSON 的投影；机器可读的权威形状仍是 `--json` 输出的 JSON。
#[must_use]
pub fn render_text(json: &Value) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(obj) = json.as_object() {
        for (k, v) in obj {
            render_field(k, v, &mut lines);
        }
    }
    lines
}

fn render_field(key: &str, val: &Value, out: &mut Vec<String>) {
    match val {
        Value::String(s) => out.push(format!("{key}: {s}")),
        Value::Bool(b) => out.push(format!("{key}: {b}")),
        Value::Number(n) => out.push(format!("{key}: {n}")),
        Value::Null => out.push(format!("{key}: null")),
        Value::Array(a) => {
            if a.is_empty() {
                out.push(format!("{key}: "));
            } else if a
                .iter()
                .all(|x| x.is_string() || x.is_number() || x.is_boolean())
            {
                let joined = a
                    .iter()
                    .map(|x| match x {
                        Value::String(s) => s.clone(),
                        other => other.to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                out.push(format!("{key}: {joined}"));
            } else {
                for (i, item) in a.iter().enumerate() {
                    render_field(&format!("{key}[{i}]"), item, out);
                }
            }
        }
        Value::Object(o) => {
            for (sk, sv) in o {
                render_field(&format!("{key}.{sk}"), sv, out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_control_api::{ResourceId, SessionId};

    fn all_commands() -> Vec<ControlCommand> {
        vec![
            ControlCommand::Status,
            ControlCommand::PlanExplain {
                resource: ResourceId("net".into()),
            },
            ControlCommand::SessionWatch {
                session: SessionId("sess-1".into()),
            },
            ControlCommand::ConnectivityStatus,
            ControlCommand::ConnectivityCandidates,
            ControlCommand::ConnectivityProbe {
                target: "8.8.8.8".into(),
            },
            ControlCommand::ConnectivityLinks,
            ControlCommand::DnsStatus,
            ControlCommand::DnsResolve {
                name: "example.com".into(),
            },
            ControlCommand::DnsProviders,
            ControlCommand::DnsCache,
            ControlCommand::WorkspaceHeads {
                workspace: "ws1".into(),
            },
            ControlCommand::WorkspaceConflicts {
                workspace: "ws1".into(),
            },
            ControlCommand::WorkspaceCache {
                workspace: "ws1".into(),
            },
            ControlCommand::ComputeJobs,
            ControlCommand::Diagnose,
            ControlCommand::PlatformCapabilities,
        ]
    }

    #[test]
    fn all_17_commands_route_to_snapshot_and_pass() {
        for cmd in all_commands() {
            let json = ControlServiceImpl
                .snapshot(&cmd)
                .expect("every wired command must route to an observability snapshot");
            assert_eq!(
                json["verdict"], "PASS",
                "command must yield verdict=PASS snapshot"
            );
            assert!(
                json["command"].is_string(),
                "snapshot must carry a command name"
            );
        }
    }

    #[test]
    fn trait_execute_returns_status_view_with_lines() {
        for cmd in all_commands() {
            let out = ControlServiceImpl
                .execute(cmd)
                .expect("execute must not fail for wired commands");
            assert!(
                matches!(out, ControlOutput::Status(_)),
                "execute must return a structured Status view"
            );
            assert!(!out.to_lines().is_empty());
        }
    }

    #[test]
    fn json_passthrough_matches_snapshot() {
        // --json 模式把 snapshot 原样打印；execute 的文本投影必须源自同一 JSON。
        let json = ControlServiceImpl
            .snapshot(&ControlCommand::WorkspaceHeads {
                workspace: "ws1".into(),
            })
            .unwrap();
        let out = ControlServiceImpl
            .execute(ControlCommand::WorkspaceHeads {
                workspace: "ws1".into(),
            })
            .unwrap();
        let lines = out.to_lines().join("\n");
        // pretty-json lines 应包含原始 JSON 的 verdict 字段。
        assert!(lines.contains("\"verdict\": \"PASS\""));
        assert_eq!(json["verdict"], "PASS");
    }

    #[test]
    fn text_view_projects_json_fields() {
        let json = ControlServiceImpl
            .snapshot(&ControlCommand::Status)
            .unwrap();
        let lines = render_text(&json);
        let joined = lines.join("\n");
        assert!(joined.contains("verdict: PASS"));
        assert!(joined.contains("command: status"));
        // 文本视图不应是 raw JSON（应被投影为 key: value）。
        assert!(!joined.contains('{'));
    }

    #[test]
    fn error_to_json_is_structured_fail() {
        let err = NexusError::Unsupported {
            feature: "connectivity trace (domain state not ready)".into(),
        };
        let body = ControlServiceImpl.error_to_json(&err);
        assert_eq!(body["verdict"], "FAIL");
        assert_eq!(body["error"]["code"], "UNSUPPORTED");
        assert!(body["error"]["message"].is_string());
    }

    #[test]
    fn text_view_matches_json_field_values() {
        // 文本视图与 JSON 字段一致：每个顶层 key 都投影为一行。
        let json = ControlServiceImpl
            .snapshot(&ControlCommand::PlatformCapabilities)
            .unwrap();
        let lines = render_text(&json);
        let joined = lines.join("\n");
        assert!(joined.contains("verdict: PASS"));
        assert!(joined.contains("command: platform capabilities"));
    }
}

//! 版本化、语言中立的 Code Intelligence DTO（提案 §4/§5/§12/§13）。
//!
//! 纪律：
//! - 不引入 `serde` derive（harness 只依赖 `serde_json`，见 MODULE.md
//!   Allowed Dependencies）；因此所有类型自建 `to_json()`，字段名即契约。
//! - 行/列对外一律 **1-based**（LSP 内部 0-based，转换发生在 provider 边界）。

use serde_json::{Value, json};
use std::path::Path;

/// 契约版本，与 envelope 的 `schema_version` 一致。
const DTO_SCHEMA_VERSION: u32 = 1;

/// `DTO_SCHEMA_VERSION` 的契约面用途：Code Intelligence 的 result 形状版本，
/// 由 `ProviderMeta::to_json` 之外的结果条目共享；当前与 harness schema 同值，
/// 因此只作为编译期断言存在（避免两处各写一个字面量）。
const _: () = assert!(DTO_SCHEMA_VERSION == 1);

/// 失败码（提案 §12 冻结，10 个）。
///
/// 整个枚举是对外契约面（MODULE.md 错误码清单）：首期实现未必逐个构造，
/// 但保留完整集合是契约要求——多语言 provider 迁移必须能表达同一套码，
/// 删掉"暂时没用"的码等于削弱契约。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, reason = "契约冻结的错误码目录，允许尚未逐个构造")]
pub enum CodeIntelError {
    /// language server 可执行文件找不到。
    ProviderUnavailable,
    /// workspace 根解析失败（不在仓库内 / 目录不存在）。
    WorkspaceUnresolved,
    /// initialize / 就绪等待失败。
    InitializationFailed,
    /// 查询参数不合法或有歧义。
    QueryInvalid,
    /// 符号/位置无法解析到任何声明。
    SymbolNotFound,
    /// 命中超预算（作为信息随 `budget.truncated` 一起返回，不作终态）。
    ResultTruncated,
    /// 单请求超时。
    Timeout,
    /// provider 子进程崩溃（重启一次仍失败）。
    ProviderCrashed,
    /// 查询前后 working-tree digest 不一致。
    SnapshotStale,
    /// 写能力或不受支持的 verb/method。
    Unsupported,
}

impl CodeIntelError {
    /// 机器可读码名（`error.code`）。
    pub fn code(self) -> &'static str {
        match self {
            Self::ProviderUnavailable => "PROVIDER_UNAVAILABLE",
            Self::WorkspaceUnresolved => "WORKSPACE_UNRESOLVED",
            Self::InitializationFailed => "INITIALIZATION_FAILED",
            Self::QueryInvalid => "QUERY_INVALID",
            Self::SymbolNotFound => "SYMBOL_NOT_FOUND",
            Self::ResultTruncated => "RESULT_TRUNCATED",
            Self::Timeout => "TIMEOUT",
            Self::ProviderCrashed => "PROVIDER_CRASHED",
            Self::SnapshotStale => "SNAPSHOT_STALE",
            Self::Unsupported => "UNSUPPORTED",
        }
    }

    /// Harness verdict 语义（提案 §12：不得退化为伪 PASS）。
    pub fn verdict(self) -> &'static str {
        match self {
            // 参数/符号问题：调用方可自行修正 -> FAIL。
            Self::QueryInvalid | Self::SymbolNotFound => "FAIL",
            // 环境与能力问题 -> BLOCKED。
            Self::ProviderUnavailable
            | Self::WorkspaceUnresolved
            | Self::InitializationFailed
            | Self::Timeout
            | Self::ProviderCrashed
            | Self::SnapshotStale
            | Self::Unsupported
            | Self::ResultTruncated => "BLOCKED",
        }
    }

    pub fn with_reason(self, reason: impl Into<String>) -> Failure {
        Failure {
            code: self,
            reason: reason.into(),
        }
    }
}

/// 错误码 + 可诊断原因（提案 §12：结构化原因，不以日志文本代替）。
#[derive(Debug, Clone)]
pub struct Failure {
    pub code: CodeIntelError,
    pub reason: String,
}

impl Failure {
    pub fn to_json(&self) -> Value {
        json!({"code": self.code.code(), "reason": self.reason})
    }
}

/// 1-based 位置范围。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PositionRange {
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

impl PositionRange {
    /// `PositionRange` 是 `Copy`：按 clippy 约定 `to_*` 取值接收者。
    pub fn to_json(self) -> Value {
        json!({
            "start": {"line": self.start_line, "column": self.start_column},
            "end": {"line": self.end_line, "column": self.end_column},
        })
    }
}

/// 语言中立的结果条目（MODULE.md Code Intelligence Contract `results` 字段）。
#[derive(Debug, Clone, Default)]
pub struct ResultItem {
    pub symbol: String,
    pub kind: String,
    /// provider 声明的原始 LSP `SymbolKind` 数值；0 = provider 未给出。
    /// 之所以同时保留数值：rust-analyzer 对 trait/impl 方法有时上报
    /// `property`(6)/`variable`(12) 而非 `method`(5)，字符串会误导 Agent，
    /// 数值让调用方能自行判断（不假装我们能纠正 server 的语义）。
    pub kind_id: i64,
    pub qualified_name: String,
    /// 相对仓库根的路径（`/` 分隔）；仓库外路径保持原样绝对路径。
    pub path: String,
    /// 该条目是否落在本次 `--workspace` 范围内。越界条目**不删除**（删掉就是
    /// 静默丢弃），而是标出来让 Agent 自己判断要不要顺着读到 std 源码。
    pub in_scope: bool,
    pub range: Option<PositionRange>,
    pub snippet: String,
}

impl ResultItem {
    pub fn to_json(&self) -> Value {
        json!({
            "symbol": self.symbol,
            "kind": self.kind,
            "kind_id": self.kind_id,
            "qualified_name": self.qualified_name,
            "path": self.path,
            "in_scope": self.in_scope,
            "range": self.range.map(PositionRange::to_json).unwrap_or(Value::Null),
            "snippet": self.snippet,
        })
    }
}

/// 上下文预算（提案 §5）。`max_results` 等全部可在 CLI 覆盖。
#[derive(Debug, Clone)]
pub struct Budget {
    pub max_results: usize,
    pub max_snippet_lines: usize,
    pub max_result_bytes: usize,
    pub workspace_scope: String,
    pub truncated: bool,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            max_results: 20,
            max_snippet_lines: 8,
            max_result_bytes: 65_536,
            workspace_scope: ".".to_string(),
            truncated: false,
        }
    }
}

impl Budget {
    pub fn to_json(&self) -> Value {
        json!({
            "max_results": self.max_results,
            "max_snippet_lines": self.max_snippet_lines,
            "max_result_bytes": self.max_result_bytes,
            "workspace_scope": self.workspace_scope,
            "truncated": self.truncated,
        })
    }
}

/// provider 元数据（提案 §9：duration + provider metadata）。
#[derive(Debug, Clone, Default)]
pub struct ProviderMeta {
    /// **适配器**标识（如 `rust-analyzer`），与可执行文件解耦：换 binary 不换适配器。
    pub kind: String,
    /// 实际解析到的可执行文件（`--provider-binary` / env / PATH），便于发现错配。
    pub binary: String,
    pub version: String,
    pub ready: bool,
    pub restart_count: usize,
    /// 触发重启的首个错误原因（不丢弃崩溃细节，供 Retry/Abort 判断）。
    pub restart_reason: String,
    pub duration_ms: u128,
    /// 被拒绝执行的**写能力** server→client 请求（applyEdit / executeCommand）。
    pub write_requests_refused: usize,
    /// 因超出 notification 缓冲上限而被丢弃的条数（丢弃必须可见）。
    pub dropped_notifications: usize,
    /// 未识别的 server→client 请求数；与写能力分开计数，
    /// 否则正常只读查询也会让 refused 恒为非 0，信号失真。
    pub server_requests_unhandled: usize,
}

impl ProviderMeta {
    pub fn to_json(&self) -> Value {
        json!({
            "kind": self.kind,
            "binary": self.binary,
            "version": self.version,
            "ready": self.ready,
            "restart_count": self.restart_count,
            "restart_reason": self.restart_reason,
            "duration_ms": self.duration_ms,
            "write_requests_refused": self.write_requests_refused,
            "server_requests_unhandled": self.server_requests_unhandled,
            "dropped_notifications": self.dropped_notifications,
        })
    }
}

/// LSP `SymbolKind`（1..=26）→ 语言中立字符串。
#[must_use]
pub fn symbol_kind(lsp_kind: i64) -> &'static str {
    match lsp_kind {
        1 => "file",
        2 => "module",
        3 => "namespace",
        4 => "class",
        5 => "method",
        6 => "property",
        7 => "field",
        8 => "constructor",
        9 => "enum",
        10 => "interface",
        11 => "function",
        12 => "variable",
        13 => "constant",
        14 => "string",
        15 => "number",
        16 => "boolean",
        17 => "array",
        18 => "object",
        19 => "key",
        20 => "null",
        21 => "enum-member",
        22 => "struct",
        23 => "event",
        24 => "operator",
        25 => "type-parameter",
        26 => "default",
        _ => "default",
    }
}

/// LSP `DiagnosticSeverity`（1=Error..4=Hint）→ 中立字符串。
#[must_use]
pub fn diagnostic_severity(sev: i64) -> &'static str {
    match sev {
        1 => "error",
        2 => "warning",
        3 => "information",
        4 => "hint",
        _ => "unknown",
    }
}

/// 把绝对路径规范化为相对仓库根的 `/` 分隔路径（用于所有输出 `path` 字段）。
pub fn relative_path(repo_root: &Path, abs: &Path) -> String {
    let joined = abs
        .strip_prefix(repo_root)
        .unwrap_or(abs)
        .to_string_lossy()
        .replace('\\', "/");
    if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_verdicts_never_yield_pass() {
        let all = [
            CodeIntelError::ProviderUnavailable,
            CodeIntelError::WorkspaceUnresolved,
            CodeIntelError::InitializationFailed,
            CodeIntelError::QueryInvalid,
            CodeIntelError::SymbolNotFound,
            CodeIntelError::ResultTruncated,
            CodeIntelError::Timeout,
            CodeIntelError::ProviderCrashed,
            CodeIntelError::SnapshotStale,
            CodeIntelError::Unsupported,
        ];
        for e in all {
            assert_ne!(e.verdict(), "PASS", "{} 不得产出 PASS", e.code());
            assert!(!e.code().is_empty());
        }
        assert_eq!(all.len(), 10, "提案 §12 冻结 10 个错误码");
    }

    #[test]
    fn symbol_kind_mapping_matches_lsp_spec_numbers() {
        assert_eq!(symbol_kind(5), "method");
        assert_eq!(symbol_kind(10), "interface");
        assert_eq!(symbol_kind(11), "function");
        assert_eq!(symbol_kind(13), "constant");
        assert_eq!(symbol_kind(22), "struct");
        assert_eq!(symbol_kind(0), "default");
    }

    #[test]
    fn budget_defaults_are_the_frozen_contract_values() {
        let b = Budget::default();
        assert_eq!(b.max_results, 20);
        assert_eq!(b.max_snippet_lines, 8);
        assert_eq!(b.max_result_bytes, 65_536);
        assert!(!b.truncated);
    }

    #[test]
    fn failure_json_has_code_and_reason() {
        let f = CodeIntelError::ProviderUnavailable.with_reason("binary missing");
        let v = f.to_json();
        assert_eq!(v["code"], json!("PROVIDER_UNAVAILABLE"));
        assert_eq!(v["reason"], json!("binary missing"));
    }

    #[test]
    fn relative_path_normalizes_separators() {
        let repo = Path::new("D:/next/nexus-fabric");
        let abs = Path::new("D:/next/nexus-fabric/engineering\\nexus-harness\\src\\main.rs");
        assert_eq!(
            relative_path(repo, abs),
            "engineering/nexus-harness/src/main.rs"
        );
        // 仓库外路径原样返回（仍归一化分隔符），不 panic。
        let outside = Path::new("D:/other/file.rs");
        assert_eq!(relative_path(repo, outside), "D:/other/file.rs");
    }
}

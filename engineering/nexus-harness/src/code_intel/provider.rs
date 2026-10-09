//! Code Intelligence Provider 边界（提案 §9：plugin category `code-intelligence`）。
//!
//! 上层（CLI）只认这里的 `Verb` / trait 与语言中立 DTO；换 clangd/gopls 时
//! 只需新增一个 trait 实现，Agent-facing API 不变。

use crate::code_intel::dto::{Budget, CodeIntelError, Failure, ProviderMeta, ResultItem};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Agent-facing verb（MODULE.md 冻结的 8 个只读查询）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    Symbol,
    Definition,
    References,
    Implementations,
    Callers,
    Callees,
    Hover,
    Diagnostics,
}

impl Verb {
    /// 已知 verb 全集；其余（含 `rename`/`format` 等写能力）返回 `None`。
    pub fn parse(raw: &str) -> Option<Verb> {
        Some(match raw {
            "symbol" => Self::Symbol,
            "definition" => Self::Definition,
            "references" => Self::References,
            "implementations" => Self::Implementations,
            "callers" => Self::Callers,
            "callees" => Self::Callees,
            "hover" => Self::Hover,
            "diagnostics" => Self::Diagnostics,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Symbol => "symbol",
            Self::Definition => "definition",
            Self::References => "references",
            Self::Implementations => "implementations",
            Self::Callers => "callers",
            Self::Callees => "callees",
            Self::Hover => "hover",
            Self::Diagnostics => "diagnostics",
        }
    }

    /// 该 verb 是否需要可解析的位置（`path:line:column`）。
    pub fn requires_location(self) -> bool {
        !matches!(self, Self::Symbol | Self::Diagnostics)
    }
}

/// `path:line:column`（1-based），provider 内部按 LSP 0-based 使用。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceLocation {
    pub path: PathBuf,
    pub line: usize,
    pub column: usize,
}

impl SourceLocation {
    /// 解析 `<path>:<line>:<col>`；行列必须是正整数。
    ///
    /// 从右切 3 段，因此 Windows 盘符（`d:/x.rs:9:8`）里的冒号留在 path 段。
    pub fn parse(raw: &str, resolve: &dyn Fn(&str) -> PathBuf) -> Result<SourceLocation, Failure> {
        let err = |reason: String| CodeIntelError::QueryInvalid.with_reason(reason);
        let mut pieces = raw.rsplitn(3, ':');
        let col_txt = pieces.next().unwrap_or("");
        let line_txt = pieces.next().unwrap_or("");
        let path_txt = pieces.next().unwrap_or("");
        if path_txt.is_empty() || line_txt.is_empty() || col_txt.is_empty() {
            return Err(err(format!(
                "位置必须是 <path>:<line>:<column>（1-based），收到 {raw}"
            )));
        }
        let line = line_txt
            .parse::<usize>()
            .map_err(|_| err(format!("line 必须是正整数：{line_txt}")))?;
        let column = col_txt
            .parse::<usize>()
            .map_err(|_| err(format!("column 必须是正整数：{col_txt}")))?;
        if line == 0 || column == 0 {
            return Err(err(format!("line/column 是 1-based，不能为 0：{raw}")));
        }
        Ok(SourceLocation {
            path: resolve(path_txt),
            line,
            column,
        })
    }

    /// LSP 0-based 位置对象。
    pub fn lsp_position(&self) -> Value {
        json!({"line": self.line - 1, "character": self.column - 1})
    }
}

/// 一条诊断（`code diagnostics` 的结构化条目，提案 §16.4）。
#[derive(Debug, Clone)]
pub struct DiagnosticItem {
    pub path: String,
    pub severity: String,
    pub code: String,
    pub message: String,
    pub range: Option<(usize, usize, usize, usize)>,
}

impl DiagnosticItem {
    pub fn to_json(&self) -> Value {
        json!({
            "symbol": self.code,
            "kind": "diagnostic",
            // 诊断不是符号：kind_id 固定 0（= provider 未给出符号类别）。
            "kind_id": 0,
            "qualified_name": self.severity,
            "in_scope": true,
            "path": self.path,
            "range": self.range.map(|(sl, sc, el, ec)| {
                json!({"start": {"line": sl, "column": sc}, "end": {"line": el, "column": ec}})
            }),
            "snippet": self.message,
        })
    }
}

/// Provider 契约（提案 §9 的 trait 形态，按现有 harness code style 收紧为
/// `&mut self` + 中立 DTO；所有方法只读）。
pub trait CodeIntelligenceProvider {
    fn symbols(&mut self, query: &str, budget: &Budget) -> Result<Vec<ResultItem>, Failure>;
    fn definition(
        &mut self,
        loc: &SourceLocation,
        budget: &Budget,
    ) -> Result<Vec<ResultItem>, Failure>;
    fn references(
        &mut self,
        loc: &SourceLocation,
        budget: &Budget,
    ) -> Result<Vec<ResultItem>, Failure>;
    fn implementations(
        &mut self,
        loc: &SourceLocation,
        budget: &Budget,
    ) -> Result<Vec<ResultItem>, Failure>;
    fn callers(
        &mut self,
        loc: &SourceLocation,
        budget: &Budget,
    ) -> Result<Vec<ResultItem>, Failure>;
    fn callees(
        &mut self,
        loc: &SourceLocation,
        budget: &Budget,
    ) -> Result<Vec<ResultItem>, Failure>;
    fn hover(&mut self, loc: &SourceLocation, budget: &Budget) -> Result<Vec<ResultItem>, Failure>;
    fn diagnostics(&mut self, file: &Path, budget: &Budget)
    -> Result<Vec<DiagnosticItem>, Failure>;
    /// provider 元数据（含 duration / refused writes / restart count）。
    fn meta(&self) -> &ProviderMeta;
    /// 关闭会话（幂等）。
    fn close(&mut self);
}

/// language server 可执行文件解析（MODULE.md Allowed Dependencies 冻结的顺序）：
/// `--provider-binary` 覆盖 -> `NEXUS_RUST_ANALYZER` -> `PATH`。
/// 三者都失败时返回 `PROVIDER_UNAVAILABLE`，绝不返回"看起来能用"的路径。
pub fn resolve_binary(override_value: Option<&str>) -> Result<PathBuf, Failure> {
    if let Some(explicit) = override_value {
        let candidate = PathBuf::from(explicit);
        if candidate.is_file() {
            return Ok(candidate);
        }
        return Err(CodeIntelError::ProviderUnavailable.with_reason(format!(
            "--provider-binary 指定的可执行文件不存在：{explicit}"
        )));
    }
    if let Some(from_env) = std::env::var_os("NEXUS_RUST_ANALYZER") {
        let candidate = PathBuf::from(from_env);
        if candidate.is_file() {
            return Ok(candidate);
        }
        return Err(CodeIntelError::ProviderUnavailable
            .with_reason("NEXUS_RUST_ANALYZER 指向的文件不存在".to_string()));
    }
    let exe_names: &[&str] = if cfg!(windows) {
        &["rust-analyzer.exe", "rust-analyzer"]
    } else {
        &["rust-analyzer"]
    };
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            for &name in exe_names {
                let candidate = dir.join(name);
                if candidate.is_file() {
                    return Ok(candidate);
                }
            }
        }
    }
    Err(CodeIntelError::ProviderUnavailable.with_reason(
        "找不到 rust-analyzer：请安装 `rustup component add rust-analyzer`，或设置 NEXUS_RUST_ANALYZER / --provider-binary"
            .to_string(),
    ))
}

/// 记录 provider 版本（`rust-analyzer --version` 首行）。
pub fn probe_version(binary: &Path) -> String {
    std::process::Command::new(binary)
        .arg("--version")
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
            } else {
                None
            }
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// 请求超时与就绪等待（`--timeout-secs` / `--ready-timeout-secs`）。
#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    pub request: Duration,
    pub ready: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts {
            request: Duration::from_secs(20),
            ready: Duration::from_secs(90),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verbs_cover_the_eight_read_only_queries() {
        for name in [
            "symbol",
            "definition",
            "references",
            "implementations",
            "callers",
            "callees",
            "hover",
            "diagnostics",
        ] {
            let verb = Verb::parse(name).expect("{name} 必须是已知 verb");
            assert_eq!(verb.name(), name);
        }
        // 写能力 verb 不进入 API：parse 返回 None（CLI 层拒绝）。
        for name in [
            "rename",
            "format",
            "apply-edit",
            "execute-command",
            "code-action",
        ] {
            assert!(Verb::parse(name).is_none(), "{name} 不得被接受");
        }
    }

    #[test]
    fn location_parses_one_based_triple() {
        let resolve = |p: &str| PathBuf::from(format!("/repo/{p}"));
        let loc = SourceLocation::parse("src/lib.rs:9:8", &resolve).expect("valid");
        assert_eq!(loc.path, PathBuf::from("/repo/src/lib.rs"));
        assert_eq!((loc.line, loc.column), (9, 8));
        assert_eq!(loc.lsp_position(), json!({"line": 8, "character": 7}));
    }

    #[test]
    fn location_accepts_paths_with_colons_and_rejects_zero() {
        let resolve = |p: &str| PathBuf::from(p);
        // Windows 盘符路径：rsplitn 从右切 3 段，盘符冒号留在 path 段。
        let d = SourceLocation::parse("d:/next/x/src/lib.rs:12:4", &resolve).expect("windows path");
        assert_eq!(d.path, PathBuf::from("d:/next/x/src/lib.rs"));
        assert_eq!((d.line, d.column), (12, 4));
        for bad in [
            "src/lib.rs:0:4",
            "src/lib.rs:5:0",
            "src/lib.rs:5",
            "src/lib.rs",
            ":5:4",
        ] {
            let err = SourceLocation::parse(bad, &resolve).expect_err("{bad} 必须失败");
            assert_eq!(err.code, CodeIntelError::QueryInvalid, "{bad}");
        }
    }

    #[test]
    fn symbol_and_diagnostics_do_not_require_location() {
        assert!(!Verb::Symbol.requires_location());
        assert!(!Verb::Diagnostics.requires_location());
        assert!(Verb::Hover.requires_location());
        assert!(Verb::References.requires_location());
    }

    #[test]
    fn explicit_missing_binary_is_provider_unavailable_not_empty_results() {
        let err = resolve_binary(Some("nexus-code-intel-provider-does-not-exist"))
            .expect_err("不存在的显式覆盖必须失败");
        assert_eq!(err.code, CodeIntelError::ProviderUnavailable);
        assert_eq!(err.code.verdict(), "BLOCKED");
    }

    #[test]
    fn probe_version_never_panics_on_missing_binary() {
        let v = probe_version(Path::new("nexus-code-intel-provider-does-not-exist"));
        assert_eq!(v, "unknown");
    }
}

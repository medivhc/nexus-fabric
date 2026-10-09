//! Code Intelligence CLI 层（提案 §4/§5/§7/§13）。
//!
//! 职责边界：
//! - 只做参数解析、作用域校验、预算裁剪、snapshot 绑定与 envelope 扩展字段拼装；
//! - 语义事实全部来自 `provider::CodeIntelligenceProvider`（首个实现是
//!   rust-analyzer），correctness 仍归 `cargo check/clippy/test`（提案 §7）；
//! - 输出恒带 `authority = "advisory"`，本层不产出最终 PASS 权。
//!
//! 路径约定（MODULE.md 冻结）：`--workspace`、位置参数里的 path、diagnostics
//! 目标一律**相对仓库根**解析；目标必须落在 `--workspace` 范围内（提案 §14）。

mod dto;
mod lsp;
mod provider;
mod rust_analyzer;

use dto::{Budget, CodeIntelError, Failure, ProviderMeta, ResultItem};
use provider::{CodeIntelligenceProvider, DiagnosticItem, SourceLocation, Timeouts, Verb};
use rust_analyzer::RustAnalyzerProvider;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::commands;
use crate::env::Repo;
use crate::evidence::Bindings;

type Outcome = (String, String, Vec<(String, Value)>);

/// 已校验的一次 `code` 请求。
struct Request {
    verb: Verb,
    target: Target,
    workspace: PathBuf,
    budget: Budget,
    timeouts: Timeouts,
    provider_override: Option<String>,
}

/// 查询目标在**启动 provider 之前**就完成解析与存在性校验：
/// 参数错误必须是 QUERY_INVALID/FAIL，不允许先起子进程再失败（提案 §12）。
enum Target {
    /// `code symbol <name>`
    Query(String),
    /// 位置型 verb
    Location(SourceLocation),
    /// `code diagnostics <file>`
    File(PathBuf),
}

/// 失败/成功都要带上的公共字段集合。
struct Envelope {
    command: String,
    budget: Option<Budget>,
    provider: Option<ProviderMeta>,
    snapshot: Option<Value>,
}

impl Envelope {
    fn new(command: &str) -> Envelope {
        Envelope {
            command: command.to_string(),
            budget: None,
            provider: None,
            snapshot: None,
        }
    }

    fn fields(&self) -> Vec<(String, Value)> {
        let mut out = vec![
            ("command".to_string(), json!(self.command)),
            ("authority".to_string(), json!("advisory")),
        ];
        if let Some(b) = &self.budget {
            out.push(("budget".to_string(), b.to_json()));
        }
        if let Some(p) = &self.provider {
            out.push(("provider".to_string(), p.to_json()));
        }
        if let Some(s) = &self.snapshot {
            out.push(("snapshot".to_string(), s.clone()));
        }
        out
    }
}

pub fn run(args: &[String]) -> Outcome {
    let verb_raw = args.first().map(String::as_str).unwrap_or("");
    let command = format!("code {verb_raw}");
    let base = Envelope::new(&command);

    if verb_raw.is_empty() {
        return fail(
            &base,
            &CodeIntelError::QueryInvalid.with_reason(
                "缺少 verb：code <symbol|definition|references|implementations|callers|callees|hover|diagnostics>",
            ),
        );
    }
    // 写能力（rename/format/apply-edit/execute-command…）根本不进入 API。
    let Some(verb) = Verb::parse(verb_raw) else {
        return fail(
            &base,
            &CodeIntelError::Unsupported.with_reason(format!(
                "code {verb_raw} 不是只读查询 verb；首期只支持 symbol/definition/references/implementations/callers/callees/hover/diagnostics"
            )),
        );
    };

    let (repo, _config) = match commands::setup() {
        Ok(pair) => pair,
        Err(outcome) => return enrich(outcome, &base),
    };

    let mut request = match parse_request(verb, &args[1..], &repo) {
        Ok(r) => r,
        Err(e) => return fail(&base, &e),
    };
    request.budget.workspace_scope = dto::relative_path(&repo.root, &request.workspace);

    if let Err(e) = validate_scope(&repo, &request) {
        let envelope = with_budget(base, &request);
        return fail(&envelope, &e);
    }

    let bindings_before = Bindings::current(&repo);
    let mut envelope = with_budget(base, &request);
    // MODULE.md 冻结的 snapshot 含 workspace_root，而 Bindings 不含该字段：
    // 在此显式补齐，避免"契约声明了、输出里没有"。
    let mut snapshot = bindings_before.to_json();
    if let Some(obj) = snapshot.as_object_mut() {
        obj.insert(
            "workspace_root".to_string(),
            json!(request.budget.workspace_scope),
        );
    }
    envelope.snapshot = Some(snapshot);

    let started = Instant::now();
    let binary = match provider::resolve_binary(request.provider_override.as_deref()) {
        Ok(b) => b,
        Err(e) => return fail(&envelope, &e),
    };
    let version = provider::probe_version(&binary);
    let mut session = match RustAnalyzerProvider::start(
        &binary,
        &request.workspace,
        &repo.root,
        &version,
        request.timeouts,
    ) {
        Ok(p) => p,
        Err(e) => {
            envelope.provider = Some(ProviderMeta {
                kind: "rust-analyzer".to_string(),
                binary: binary.to_string_lossy().replace('\\', "/"),
                version,
                ready: false,
                restart_count: 0,
                restart_reason: String::new(),
                duration_ms: started.elapsed().as_millis(),
                write_requests_refused: 0,
                server_requests_unhandled: 0,
                dropped_notifications: 0,
            });
            return fail(&envelope, &e);
        }
    };

    let execution = execute(&request, &mut session, &repo.root);
    let mut meta = session.finish_meta();
    meta.duration_ms = started.elapsed().as_millis();
    session.close();
    envelope.provider = Some(meta);

    let items = match execution {
        Ok(items) => items,
        Err(e) => return fail(&envelope, &e),
    };

    // 提案 §13：查询完成后再算一次 digest，工作树变了就不能当作当前事实。
    let bindings_after = Bindings::current(&repo);
    if bindings_after.working_tree_digest != bindings_before.working_tree_digest {
        let e = CodeIntelError::SnapshotStale
            .with_reason("查询期间工作树发生变化（working_tree_digest 不一致）".to_string());
        return fail(&envelope, &e);
    }

    let mut budget = request.budget.clone();
    let (kept, count, continuation) = apply_budget(items, &mut budget);
    let mut fields = envelope.fields();
    fields.push(("results".to_string(), json!(kept)));
    fields.push(("count".to_string(), json!(count)));
    if let Some(existing) = fields.iter_mut().find(|(k, _)| k == "budget") {
        existing.1 = budget.to_json();
    }
    if let Some(hint) = continuation {
        fields.push(("continuation".to_string(), json!({"refinement_hint": hint})));
    }
    let message = format!(
        "{}：命中 {count} 条，返回 {} 条",
        verb.name(),
        kept_count(&fields)
    );
    ("PASS".to_string(), message, fields)
}

fn kept_count(fields: &[(String, Value)]) -> usize {
    fields
        .iter()
        .find(|(k, _)| k == "results")
        .and_then(|(_, v)| v.as_array())
        .map(Vec::len)
        .unwrap_or(0)
}

fn with_budget(mut envelope: Envelope, request: &Request) -> Envelope {
    envelope.budget = Some(request.budget.clone());
    envelope
}

fn fail(envelope: &Envelope, failure: &Failure) -> Outcome {
    let mut fields = envelope.fields();
    fields.push(("error".to_string(), failure.to_json()));
    if !fields.iter().any(|(k, _)| k == "results") {
        fields.push(("results".to_string(), json!([])));
        fields.push(("count".to_string(), json!(0)));
    }
    (
        failure.code.verdict().to_string(),
        failure.reason.clone(),
        fields,
    )
}

/// `commands::setup()` 失败（不在 git 仓库内等）也要保持 code 的字段契约。
fn enrich(outcome: Outcome, envelope: &Envelope) -> Outcome {
    let mut fields = envelope.fields();
    fields.extend(outcome.2);
    fields.push((
        "error".to_string(),
        CodeIntelError::WorkspaceUnresolved
            .with_reason(outcome.1.clone())
            .to_json(),
    ));
    (outcome.0, outcome.1, fields)
}

/// 解析 options 与查询目标；相对路径按仓库根展开。
fn parse_request(verb: Verb, args: &[String], repo: &Repo) -> Result<Request, Failure> {
    let mut target: Option<String> = None;
    let mut workspace_raw: Option<String> = None;
    let mut budget = Budget::default();
    let mut timeouts = Timeouts::default();
    let mut provider_override: Option<String> = None;
    let mut index = 0usize;

    while index < args.len() {
        let arg = args[index].as_str();
        index += 1;
        match arg {
            "--workspace" => {
                workspace_raw = Some(take_option_arg(args, &mut index, "--workspace")?)
            }
            "--max-results" => {
                let raw = take_option_arg(args, &mut index, "--max-results")?;
                budget.max_results = parse_usize(&raw, "--max-results")?;
            }
            "--max-snippet-lines" => {
                let raw = take_option_arg(args, &mut index, "--max-snippet-lines")?;
                budget.max_snippet_lines = parse_usize(&raw, "--max-snippet-lines")?;
            }
            "--max-result-bytes" => {
                let raw = take_option_arg(args, &mut index, "--max-result-bytes")?;
                budget.max_result_bytes = parse_usize(&raw, "--max-result-bytes")?;
            }
            "--timeout-secs" => {
                let raw = take_option_arg(args, &mut index, "--timeout-secs")?;
                timeouts.request = Duration::from_secs(parse_usize(&raw, "--timeout-secs")? as u64);
            }
            "--ready-timeout-secs" => {
                let raw = take_option_arg(args, &mut index, "--ready-timeout-secs")?;
                timeouts.ready =
                    Duration::from_secs(parse_usize(&raw, "--ready-timeout-secs")? as u64);
            }
            "--provider-binary" => {
                provider_override = Some(take_option_arg(args, &mut index, "--provider-binary")?);
            }
            other if other.starts_with("--") => {
                return Err(CodeIntelError::QueryInvalid.with_reason(format!("未知选项：{other}")));
            }
            other => {
                if target.is_some() {
                    return Err(CodeIntelError::QueryInvalid
                        .with_reason(format!("多余的查询参数：{other}")));
                }
                target = Some(other.to_string());
            }
        }
    }

    let workspace = match workspace_raw {
        Some(raw) => repo.resolve(&raw),
        None => repo.root.clone(),
    };
    let target = match target {
        Some(raw) => build_target(repo, verb, &raw)?,
        None if verb.requires_location() => {
            return Err(CodeIntelError::QueryInvalid
                .with_reason(format!("{} 需要 <path>:<line>:<column>", verb.name())));
        }
        None => {
            return Err(CodeIntelError::QueryInvalid.with_reason(format!(
                "{} 需要查询参数（{}）",
                verb.name(),
                if verb == Verb::Symbol {
                    "<symbol>"
                } else {
                    "<file>"
                }
            )));
        }
    };

    Ok(Request {
        verb,
        target,
        workspace,
        budget,
        timeouts,
        provider_override,
    })
}

/// 按 verb 决定目标形状（全部在启动 provider 前校验）。
fn build_target(repo: &Repo, verb: Verb, raw: &str) -> Result<Target, Failure> {
    match verb {
        Verb::Symbol => Ok(Target::Query(raw.to_string())),
        Verb::Diagnostics => Ok(Target::File(checked_file(repo, raw, verb)?)),
        other => {
            // 冻结契约：location 型 verb 同时接受 `<path>:<line>:<col>` 与 `<symbol>`
            // （后者经 workspace/symbol 解析，歧义时报 QUERY_INVALID，不静默挑选）。
            match SourceLocation::parse(raw, &|p: &str| repo.resolve(p)) {
                Ok(loc) => Ok(Target::Location(checked_location(loc, other)?)),
                Err(e) if looks_like_path(raw) => Err(e),
                Err(_) => Ok(Target::Query(raw.to_string())),
            }
        }
    }
}

/// 看起来就是位置（含路径分隔符或 `.rs` 后缀），只是格式错——不能降级成符号名。
fn looks_like_path(raw: &str) -> bool {
    raw.contains('/') || raw.contains('\\') || raw.ends_with(".rs")
}

/// 位置存在性校验（path 已在 parse 阶段相对仓库根展开）。
fn checked_location(loc: SourceLocation, verb: Verb) -> Result<SourceLocation, Failure> {
    if !loc.path.is_file() {
        return Err(CodeIntelError::QueryInvalid.with_reason(format!(
            "{} 不是存在的文件（{} 需要真实位置）",
            loc.path.display(),
            verb.name()
        )));
    }
    Ok(loc)
}

fn checked_file(repo: &Repo, raw: &str, verb: Verb) -> Result<PathBuf, Failure> {
    let path = repo.resolve(raw);
    if !path.is_file() {
        return Err(CodeIntelError::QueryInvalid.with_reason(format!(
            "{} 不是存在的文件（{} 需要真实文件）",
            path.display(),
            verb.name()
        )));
    }
    Ok(path)
}

/// 取 `--opt <value>` 的值并前进游标。
fn take_option_arg(args: &[String], index: &mut usize, name: &str) -> Result<String, Failure> {
    let value = args
        .get(*index)
        .cloned()
        .ok_or_else(|| CodeIntelError::QueryInvalid.with_reason(format!("{name} 缺少参数值")))?;
    *index += 1;
    Ok(value)
}

fn parse_usize(raw: &str, name: &str) -> Result<usize, Failure> {
    let value = raw.parse::<usize>().map_err(|e| {
        CodeIntelError::QueryInvalid.with_reason(format!("{name} 需要整数，收到 {raw}：{e}"))
    })?;
    if value == 0 {
        // 0 会让每个请求立即超时 / 返回 0 条结果，属退化输入：显式拒绝。
        return Err(CodeIntelError::QueryInvalid.with_reason(format!("{name} 必须 >= 1，收到 0")));
    }
    Ok(value)
}

/// 查询目标必须落在 `--workspace` 内（提案 §14：语言服务器的工作目录边界）。
fn validate_target(request: &Request) -> Result<(), Failure> {
    let target = match &request.target {
        Target::File(path) => path.clone(),
        Target::Location(loc) => loc.path.clone(),
        // 符号名形态由 provider 解析，越界结果以 in_scope 标注而非静默丢弃。
        Target::Query(_) => return Ok(()),
    };
    if !crate::env::path_is_within(&target, &request.workspace) {
        return Err(CodeIntelError::QueryInvalid.with_reason(format!(
            "查询目标 {} 不在 --workspace {} 范围内",
            target.display(),
            request.workspace.display()
        )));
    }
    Ok(())
}

/// `--workspace` 必须是仓库内的目录；provider 的 cwd 也限制在其中（提案 §14）。
fn validate_scope(repo: &Repo, request: &Request) -> Result<(), Failure> {
    if !request.workspace.is_dir() {
        return Err(CodeIntelError::WorkspaceUnresolved.with_reason(format!(
            "workspace 根不是目录：{}",
            request.workspace.display()
        )));
    }
    validate_target(request)?;
    if !crate::env::path_is_within(&request.workspace, &repo.root) {
        return Err(CodeIntelError::WorkspaceUnresolved.with_reason(format!(
            "workspace 根超出仓库范围：{}",
            request.workspace.display()
        )));
    }
    Ok(())
}

/// 执行 verb，返回语言中立的 JSON 条目。
fn execute(
    request: &Request,
    session: &mut RustAnalyzerProvider,
    repo_root: &Path,
) -> Result<Vec<Value>, Failure> {
    let budget = request.budget.clone();
    let items: Vec<ResultItem> = match &request.target {
        Target::File(file) => {
            let diags = session.diagnostics(file, &budget)?;
            if diags.is_empty() {
                session.empty_is_trustworthy("diagnostics")?;
            }
            return Ok(diags.iter().map(DiagnosticItem::to_json).collect());
        }
        Target::Location(loc) => at_location(request.verb, loc, session, &budget)?,
        Target::Query(name) if request.verb == Verb::Symbol => session.symbols(name, &budget)?,
        // 符号名形态：先用 workspace/symbol 定位；歧义与缺失都显式报错，
        // 绝不"挑第一个"（MODULE.md 冻结语义）。
        Target::Query(name) => {
            let hits = session.symbols(name, &budget)?;
            if hits.is_empty() {
                session.empty_is_trustworthy("symbol")?;
                return Err(CodeIntelError::SymbolNotFound
                    .with_reason(format!("workspace/symbol 对 {name} 无任何命中")));
            }
            // 精确同名优先；没有同名项时只有在"唯一模糊命中"才自动采用，
            // 其余一律要求调用方用 <path>:<line>:<col> 消歧。
            let exact: Vec<&ResultItem> = hits.iter().filter(|i| &i.symbol == name).collect();
            let chosen: Vec<&ResultItem> = if exact.is_empty() {
                hits.iter().collect()
            } else {
                exact
            };
            if chosen.len() != 1 {
                let candidates: Vec<String> = chosen.iter().map(|i| candidate_label(i)).collect();
                return Err(CodeIntelError::QueryInvalid.with_reason(format!(
                    "{name} 有 {} 个候选，无法唯一确定位置；请用 <path>:<line>:<col> 指定其一：{candidates:?}",
                    chosen.len()
                )));
            }
            let picked = chosen[0];
            let range = picked.range.ok_or_else(|| {
                CodeIntelError::QueryInvalid
                    .with_reason(format!("符号 {} 没有可用位置", picked.symbol))
            })?;
            let loc = SourceLocation {
                path: repo_root.join(&picked.path),
                line: range.start_line,
                column: range.start_column,
            };
            at_location(request.verb, &loc, session, &budget)?
        }
    };
    if items.is_empty() {
        session.empty_is_trustworthy(request.verb.name())?;
    }
    Ok(items.iter().map(ResultItem::to_json).collect())
}

/// 歧义报错里给调用方看的候选标签。
fn candidate_label(item: &ResultItem) -> String {
    let line = item.range.map_or(0, |r| r.start_line);
    let column = item.range.map_or(0, |r| r.start_column);
    format!("{}:{}:{}", item.path, line, column)
}

/// 位置型 verb 的统一分派。
fn at_location(
    verb: Verb,
    loc: &SourceLocation,
    session: &mut RustAnalyzerProvider,
    budget: &Budget,
) -> Result<Vec<ResultItem>, Failure> {
    match verb {
        Verb::Definition => session.definition(loc, budget),
        Verb::References => session.references(loc, budget),
        Verb::Implementations => session.implementations(loc, budget),
        Verb::Callers => session.callers(loc, budget),
        Verb::Callees => session.callees(loc, budget),
        Verb::Hover => session.hover(loc, budget),
        // 内部一致性：Symbol/Diagnostics 的目标形状由 build_target 保证不会是
        // Location，走到这里说明分层出错。显式报错，绝不伪造条目。
        other => Err(CodeIntelError::QueryInvalid.with_reason(format!(
            "{} 不应以位置形态进入分派（内部一致性检查失败）",
            other.name()
        ))),
    }
}

/// 预算裁剪：条数与字节双重上限；超限必须显式 truncated + refinement hint（提案 §5）。
fn apply_budget(items: Vec<Value>, budget: &mut Budget) -> (Vec<Value>, usize, Option<String>) {
    let count = items.len();
    let mut kept: Vec<Value> = Vec::new();
    let mut bytes = 0usize;
    let mut byte_capped = false;
    for item in items {
        if kept.len() >= budget.max_results {
            break;
        }
        let size = serde_json::to_string(&item).map(|s| s.len()).unwrap_or(0);
        if bytes + size > budget.max_result_bytes {
            // 即使第一条就超字节预算，也要保留它（否则 Agent 拿到空列表却以为
            // "确实只有这么多"），但必须把 truncated 立起来。
            byte_capped = true;
            if kept.is_empty() {
                kept.push(item);
            }
            break;
        }
        bytes += size;
        kept.push(item);
    }
    budget.truncated = kept.len() < count || byte_capped;
    let continuation = if budget.truncated {
        Some(format!(
            "完整命中 {count} 条，已返回 {} 条；可提高 --max-results/--max-result-bytes 或收窄 --workspace",
            kept.len()
        ))
    } else {
        None
    };
    (kept, count, continuation)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(path: &str, line: usize) -> Value {
        json!({"symbol":"s","kind":"method","qualified_name":"C::s","path":path,
               "range":{"start":{"line":line,"column":1},"end":{"line":line,"column":2}},
               "snippet":"fn s()"})
    }

    #[test]
    fn budget_truncation_is_explicit_never_silent() {
        let items: Vec<Value> = (0..5).map(|i| item("a.rs", i + 1)).collect();
        let mut budget = Budget {
            max_results: 2,
            ..Budget::default()
        };
        let (kept, count, continuation) = apply_budget(items, &mut budget);
        assert_eq!(kept.len(), 2);
        assert_eq!(count, 5, "count 必须是截断前的完整命中数");
        assert!(budget.truncated);
        let hint = continuation.expect("截断必须给出 refinement hint");
        assert!(hint.contains("完整命中 5 条"));
        assert!(hint.contains("--max-results"));
    }

    #[test]
    fn budget_within_limits_is_not_truncated() {
        let items: Vec<Value> = (0..2).map(|i| item("a.rs", i + 1)).collect();
        let mut budget = Budget {
            max_results: 20,
            ..Budget::default()
        };
        let (kept, count, continuation) = apply_budget(items, &mut budget);
        assert_eq!((kept.len(), count), (2, 2));
        assert!(!budget.truncated);
        assert!(continuation.is_none());
    }

    #[test]
    fn byte_cap_also_marks_truncated() {
        let big = json!({"path": "a.rs", "snippet": "x".repeat(4_000)});
        let items = vec![big.clone(), big.clone(), big.clone()];
        let mut budget = Budget {
            max_results: 20,
            max_result_bytes: 6_000,
            ..Budget::default()
        };
        let (kept, count, _) = apply_budget(items, &mut budget);
        assert!(kept.len() < count);
        assert!(budget.truncated, "字节超限也必须显式 truncated");
    }

    #[test]
    fn unknown_verb_is_blocked_not_empty_pass() {
        let (verdict, _msg, extras) = run(&["rename".to_string(), "x.rs:1:1".to_string()]);
        assert_eq!(verdict, "BLOCKED");
        let obj: serde_json::Map<String, Value> = extras.into_iter().collect();
        assert_eq!(obj["error"]["code"], json!("UNSUPPORTED"));
        assert_eq!(obj["authority"], json!("advisory"));
        assert_eq!(obj["results"], json!([]));
        assert_eq!(obj["count"], json!(0));
    }

    /// QUERY_INVALID 的 verdict 是 FAIL（MODULE.md 冻结：歧义/参数错误显式 FAIL），
    /// UNSUPPORTED / PROVIDER_UNAVAILABLE / WORKSPACE_* 才是 BLOCKED。
    #[test]
    fn missing_verb_is_query_invalid() {
        let (verdict, msg, extras) = run(&[]);
        assert_eq!(verdict, "FAIL");
        assert!(msg.contains("缺少 verb"), "{msg}");
        let obj: serde_json::Map<String, Value> = extras.into_iter().collect();
        assert_eq!(obj["error"]["code"], json!("QUERY_INVALID"));
    }

    #[test]
    fn unknown_option_is_query_invalid() {
        let (verdict, msg, _) = run(&[
            "symbol".to_string(),
            "Egress".to_string(),
            "--bogus".to_string(),
        ]);
        assert_eq!(verdict, "FAIL");
        assert!(msg.contains("未知选项"), "{msg}");
    }

    #[test]
    fn non_numeric_budget_option_is_query_invalid() {
        let (verdict, msg, _) = run(&[
            "symbol".to_string(),
            "Egress".to_string(),
            "--max-results".to_string(),
            "many".to_string(),
        ]);
        assert_eq!(verdict, "FAIL");
        assert!(msg.contains("需要整数"), "{msg}");
    }

    #[test]
    fn missing_option_value_is_query_invalid() {
        let (verdict, msg, _) = run(&["symbol".to_string(), "--workspace".to_string()]);
        assert_eq!(verdict, "FAIL");
        assert!(msg.contains("缺少参数值"), "{msg}");
    }

    #[test]
    fn location_requiring_verb_without_target_is_query_invalid() {
        let (verdict, msg, _) = run(&["hover".to_string()]);
        assert_eq!(verdict, "FAIL");
        assert!(msg.contains("hover 需要 <path>"), "{msg}");
    }

    #[test]
    fn symbol_verb_without_query_is_query_invalid() {
        let (verdict, msg, _) = run(&["symbol".to_string()]);
        assert_eq!(verdict, "FAIL");
        assert!(msg.contains("symbol 需要查询参数"), "{msg}");
    }

    #[test]
    fn nonexistent_location_file_is_query_invalid_before_provider() {
        let (verdict, msg, extras) = run(&[
            "definition".to_string(),
            "no/such/file.rs:3:4".to_string(),
            "--workspace".to_string(),
            "engineering/nexus-harness/fixtures/code-intel".to_string(),
        ]);
        assert_eq!(verdict, "FAIL", "{msg}");
        assert!(msg.contains("不是存在的文件"), "{msg}");
        let obj: serde_json::Map<String, Value> = extras.into_iter().collect();
        assert_eq!(obj["error"]["code"], json!("QUERY_INVALID"));
        assert!(
            obj.get("provider").is_none(),
            "参数错误不得留下 provider 痕迹（说明没起子进程）"
        );
    }

    #[test]
    fn zero_based_position_is_rejected_before_spawning_provider() {
        let (verdict, msg, extras) = run(&[
            "definition".to_string(),
            "src/lib.rs:0:4".to_string(),
            "--workspace".to_string(),
            "engineering/nexus-harness/fixtures/code-intel".to_string(),
        ]);
        assert_eq!(verdict, "FAIL");
        assert!(msg.contains("1-based"), "{msg}");
        let obj: serde_json::Map<String, Value> = extras.into_iter().collect();
        assert_eq!(obj["error"]["code"], json!("QUERY_INVALID"));
        assert_eq!(obj["results"], json!([]), "解析失败不得启动 provider");
    }

    #[test]
    fn workspace_outside_repo_is_blocked() {
        let outside = std::env::temp_dir();
        let (verdict, msg, _) = run(&[
            "symbol".to_string(),
            "Egress".to_string(),
            "--workspace".to_string(),
            outside.to_string_lossy().to_string(),
        ]);
        assert_eq!(verdict, "BLOCKED", "{msg}");
        assert!(
            msg.contains("超出仓库范围") || msg.contains("不是目录"),
            "{msg}"
        );
    }
}

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
pub(crate) mod mcp;
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

/// CLI 一次性入口：不持有任何跨调用状态，provider 在本次调用内建立并关闭。
pub fn run(args: &[String]) -> Outcome {
    let mut session: Option<ProviderSession> = None;
    run_with_session(args, &mut session)
}

/// 带可复用会话的入口（`mcp serve` 用；契约见 MODULE.md「Provider Session Reuse」）。
///
/// `session` 由**调用方**持有：命中复用键就复用，否则重建（旧会话在替换时被 Drop 关掉）。
/// CLI 传一个用完即丢的局部 `None`，行为与从前完全一致 —— 复用绝不能变成
/// "默认悄悄留一个活进程"。
pub fn run_with_session(args: &[String], session: &mut Option<ProviderSession>) -> Outcome {
    let verb_raw = args.first().map(String::as_str).unwrap_or("");
    let command = format!("code {verb_raw}");
    let mut base = Envelope::new(&command);

    // 先做仓库发现：这样即便 verb/参数解析失败，envelope 里仍有 snapshot，
    // Agent 不必靠"有没有这个字段"去猜失败发生在哪一层。
    //
    // 这里**不写** `workspace_root`（旧实现写 `"."`）。`"."` 与成功路径上的真实作用域
    // 共用同一个字段名却语义相反（一个是"还没确定"、一个是"已确定为 X"），消费方按
    // 字段存在与否判断就会把"未确定"读成"就是仓库根"。独立 Review round 3 待办 4
    // 要求取消这一双含义：未确定作用域时该字段不出现（见 MODULE.md 字段可得性规则）。
    let setup = commands::setup();
    if let Ok((early_repo, _)) = &setup {
        base.snapshot = Some(Bindings::current(early_repo).to_json());
    }

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

    let (repo, _config) = match setup {
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
    // `Repo::working_tree_digest()` 在 git 调用失败时会降级成哨兵值（`tree-unknown` /
    // `dirty-unknown`）。若不加检查，"前后两次都失败"会被当成"工作树没变"，
    // 于是把"无法证明绑定"说成"绑定成立"——这正是提案 §12 禁止的伪 PASS。
    // git 侧的失败是可观测的：实测 `cargo test -p nexus-harness` 并发跑时
    // `git write-tree` 会因 index.lock 竞争失败（见 DEVELOPMENT.md §11.1）。
    if digest_is_unusable(&bindings_before.working_tree_digest) {
        let e = CodeIntelError::WorkspaceUnresolved.with_reason(
            "查询开始前取不到可信的工作树指纹（git status/write-tree 失败或降级），无法把结果绑定到 revision"
                .to_string(),
        );
        return fail(&with_budget(base, &request), &e);
    }
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
    // 复用键。四项全等才复用；**指纹一致**是"索引还描述当前工作树"的前提，
    // 不一致就重建 —— 宁可付一次冷启动，也不拿旧树的结果冒充新鲜（MODULE.md 该节第 2 条）。
    let want_key = SessionKey {
        binary: binary.to_string_lossy().replace('\\', "/"),
        workspace: request.budget.workspace_scope.clone(),
        version: version.clone(),
        digest: bindings_before.working_tree_digest.clone(),
    };
    let mut reused = false;
    let mut session_queries = 1usize;
    let mut invalidated: &'static str = "";
    match session.as_mut() {
        // 命中复用键：本次不新建 provider，计数累加到整个会话。
        Some(state) if state.key == want_key => {
            state.queries += 1;
            session_queries = state.queries;
            reused = true;
        }
        // 键不同 ⇒ 重建。旧会话在赋值时被 Drop 关闭（不手动 close，避免双重回收）。
        Some(state) => {
            invalidated = session_invalidated_reason(&state.key, &want_key);
            match RustAnalyzerProvider::start(
                &binary,
                &request.workspace,
                &repo.root,
                &version,
                request.timeouts,
            ) {
                Ok(provider) => {
                    *state = ProviderSession {
                        provider,
                        key: want_key.clone(),
                        queries: 1,
                    };
                }
                Err(e) => {
                    envelope.provider = Some(startup_failure_meta(&want_key, &version, &started));
                    return fail(&envelope, &e);
                }
            }
        }
        // 调用方没给会话槽（CLI 一次性路径）：新建一个用完即丢的，Drop 负责收尾。
        None => {
            match RustAnalyzerProvider::start(
                &binary,
                &request.workspace,
                &repo.root,
                &version,
                request.timeouts,
            ) {
                Ok(provider) => {
                    *session = Some(ProviderSession {
                        provider,
                        key: want_key.clone(),
                        queries: 1,
                    });
                }
                Err(e) => {
                    envelope.provider = Some(startup_failure_meta(&want_key, &version, &started));
                    return fail(&envelope, &e);
                }
            }
        }
    }

    let state = session.as_mut().expect("上面每个分支都建立了会话");
    let execution = execute(&request, &mut state.provider, &repo.root);
    let mut meta = state.provider.finish_meta();
    // duration_ms 是**本次查询**的耗时，不是会话累计：混进来会让 Agent 把"复用了"
    // 读成"这次很快"，或把"会话很久"读成"单次查询很慢"。
    meta.duration_ms = started.elapsed().as_millis();
    meta.session_reused = reused;
    meta.session_queries = session_queries;
    meta.session_invalidated_reason = invalidated.to_string();
    envelope.provider = Some(meta);

    let items = match execution {
        Ok(items) => items,
        Err(e) => return fail(&envelope, &e),
    };

    // 提案 §13：查询完成后再算一次 digest，工作树变了就不能当作当前事实。
    let bindings_after = Bindings::current(&repo);
    if digest_is_unusable(&bindings_after.working_tree_digest) {
        let e = CodeIntelError::WorkspaceUnresolved.with_reason(
            "查询结束后取不到可信的工作树指纹（git status/write-tree 失败或降级），无法证明结果仍绑定查询时的 revision"
                .to_string(),
        );
        return fail(&envelope, &e);
    }
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

/// provider 的复用键（MODULE.md「Provider Session Reuse」）。四项全等才算同一个会话。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKey {
    /// 解析后的可执行文件路径（`\\` 归一化成 `/`）。
    binary: String,
    /// 相对仓库根的 workspace 作用域。
    workspace: String,
    /// provider 版本：换了 server 不能拿旧索引冒充新 server 的结论。
    version: String,
    /// **会话建立时**的工作树指纹。
    digest: String,
}

/// 可跨查询持有的 provider 会话。目前唯一的持有者是 `mcp serve`。
///
/// `Drop` 里关闭 provider：这样"忘了关"不会留下孤儿 language server 进程，
/// 而重建路径（`*state = ProviderSession { .. }`）也自动回收旧进程。
pub struct ProviderSession {
    provider: RustAnalyzerProvider,
    key: SessionKey,
    queries: usize,
}

impl Drop for ProviderSession {
    fn drop(&mut self) {
        self.provider.close();
    }
}

/// 会话为什么被重建。顺序有意：指纹变化最危险，先报它。
fn session_invalidated_reason(saved: &SessionKey, want: &SessionKey) -> &'static str {
    if saved.digest != want.digest {
        "digest_changed"
    } else if saved.workspace != want.workspace {
        "workspace_changed"
    } else if saved.binary != want.binary {
        "binary_changed"
    } else {
        // 只剩版本（或内部状态）不同：一律算"换了 provider 进程"。
        "provider_restarted"
    }
}

/// provider 起不来时的元数据。`session_queries = 0` 是刻意的：
/// 一次都没服务成功，报 1 就是把失败说成发生过查询。
fn startup_failure_meta(key: &SessionKey, version: &str, started: &Instant) -> ProviderMeta {
    ProviderMeta {
        kind: "rust-analyzer".to_string(),
        binary: key.binary.clone(),
        version: version.to_string(),
        ready: false,
        restart_count: 0,
        restart_reason: String::new(),
        duration_ms: started.elapsed().as_millis(),
        write_requests_refused: 0,
        server_requests_unhandled: 0,
        dropped_notifications: 0,
        session_reused: false,
        session_queries: 0,
        session_invalidated_reason: String::new(),
    }
}

/// `context` 语义层的产物（提案 §15 Phase 2，契约见 MODULE.md「Context Semantic Anchoring」）。
pub struct SemanticReport {
    /// `ok` | `no_candidates` | `not_found` | `unavailable` | `timeout` | `stale`
    /// | `unsupported_scope`
    pub status: &'static str,
    /// 非 `ok` 时的结构化原因（`code` 沿用 `code` 命令的 10 个冻结错误码，不新造）。
    pub reason: Option<(String, String)>,
    /// 复用 `ResultItem` 的语言中立形状，不另造 DTO。
    pub anchors: Vec<Value>,
    pub candidate_queries: usize,
    /// 模块契约里看到的 code span 总数（>= candidate_queries 的取材上限），
    /// 用于让"写法不合规则被跳过"成为可见数字。
    pub candidate_spans: usize,
    pub max_results: usize,
    pub truncated: bool,
    pub workspace_scope: String,
    pub snapshot: Value,
}

/// `context` 的语义预算：比 `code` 小得多，因为它默认会被 Agent 当作"入口"反复调用。
pub const CONTEXT_MAX_RESULTS: usize = 8;
/// 最多尝试几个候选符号；**首个产出锚点的候选即停**（每次尝试都是一次冷启动，实测 30–90s）。
const CONTEXT_MAX_CANDIDATES: usize = 3;

/// 从模块契约里取候选符号名：只认反引号**成对包裹**的、首字母大写的 Rust 风格标识符。
/// 刻意不猜、不扫源码 —— 扫源码就把"语义层"退化成又一次文本匹配（提案 §1 要避免的东西）。
///
/// 返回 `(候选, 看到的 span 数)`：后者让"没被采用的格子"成为可见数字，
/// 否则 MODULE.md 写法不合规则漏收时，消费方只看到"锚点少"而分不清是没写还是没查到。
fn contract_candidates(module_md: &Path) -> (Vec<String>, usize) {
    let Ok(text) = std::fs::read_to_string(module_md) else {
        return (Vec::new(), 0);
    };
    let mut out: Vec<String> = Vec::new();
    let mut spans = 0usize;
    // 用状态机取"成对反引号之间"的内容。早先用 `split('`').skip(1)` 是把首个反引号之后的
    // 每一段都当作 code span，于是两个 span 之间的普通散文里一个首字母大写的单词也会漏进来
    // ——那不是候选符号，是散文（独立子代理实测指出）。
    let mut in_code = false;
    let mut span = String::new();
    for ch in text.chars() {
        if ch == '`' {
            if in_code {
                spans += 1;
                push_candidate(&mut out, &span);
                span.clear();
            }
            in_code = !in_code;
            continue;
        }
        if in_code {
            span.push(ch);
        }
    }
    (out, spans)
}

/// 只收**整段就是一个标识符**的 code span。
///
/// 刻意不做"取词首"那种截断：`Cargo.toml` 会变成 `Cargo`、`Context-Builder` 会变成 `Context`，
/// 而这些截断片段完全可能命中**另一个**符号，把 Agent 领到错地方 —— 比漏收更糟。
/// 代价是一格子里写多个名字（`Foo, Bar`）不会被采用，这必须写进 MODULE.md 的契约里，
/// 而不是让作者去猜；同时把"看到几个 span、采用几个"通过 `semantic_budget` 暴露出来，
/// 让漏收是可观测的（提案 §5：禁止静默丢弃）。
fn push_candidate(out: &mut Vec<String>, span: &str) {
    let word = span.trim();
    if word.len() < 3 || !word.starts_with(|c: char| c.is_ascii_uppercase()) {
        return;
    }
    if !word.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return;
    }
    if !out.iter().any(|s| *s == word) {
        out.push(word.to_string());
    }
}

/// 错误码 → `semantic_status`。保持与 `code` 一致的可观测语义：
/// "工具不在场"是 `unavailable`，"索引没收敛完"是 `timeout`，"确实没有这个符号"才是 `not_found`。
/// 10 个冻结错误码逐个表态，不留 catch-all 把"我们自己的用法错了"糊成"工具不可用"。
fn status_for_error(code: &str) -> &'static str {
    match code {
        "PROVIDER_UNAVAILABLE" | "INITIALIZATION_FAILED" | "PROVIDER_CRASHED" => "unavailable",
        "TIMEOUT" => "timeout",
        "SYMBOL_NOT_FOUND" => "not_found",
        "SNAPSHOT_STALE" => "stale",
        "WORKSPACE_UNRESOLVED" => "unsupported_scope",
        // 参数不合法是我们的用法问题，不是工具不在场：单独一个状态，便于场景与排查分辨。
        "QUERY_INVALID" => "invalid_query",
        // 截断本身由 `semantic_budget.truncated` 表达，不该作为失败码出现。
        // 真出现在失败路径上就说明实现有问题 —— 宁可"什么都不宣称"(unavailable)，
        // 也不把它翻译成 ok/not_found 这类看起来像结论的状态。
        "RESULT_TRUNCATED" => "unavailable",
        _ => "unavailable",
    }
}

/// 供 `context` 复用的入口（Phase 2）。
///
/// 这里刻意**复用 `run()`** 而不是另写一条语义查询路径：`run()` 里已经钉住了
/// 作用域归一化判定、"参数错误不得先起子进程"、指纹哨兵值拒用、预算截断可见、
/// `authority = advisory` 与全部错误码映射。另起一条路径就等于把这些不变量复制一份
/// ——而复制出去的不变量迟早漂移（round 2 的 `..` 绕过就是这么来的）。
/// 代价是要合成一次 argv，比暴露一个 typed 入口丑，但它换来的是"只有一套真相"。
pub fn anchors(repo: &Repo, module_dir: &Path, provider_override: Option<&str>) -> SemanticReport {
    let scope_rel = dto::relative_path(&repo.root, module_dir);
    let bindings = Bindings::current(repo);
    let digest = bindings.working_tree_digest.clone();
    let mut rep = SemanticReport {
        status: "ok",
        reason: None,
        anchors: Vec::new(),
        candidate_queries: 0,
        candidate_spans: 0,
        max_results: CONTEXT_MAX_RESULTS,
        truncated: false,
        workspace_scope: scope_rel.clone(),
        snapshot: bindings.to_json(),
    };

    // 1) 语义作用域必须是 cargo workspace root。理由写在契约里，不是实现细节：
    //    从成员目录启动 rust-analyzer 会把整个仓库 workspace 灌进索引（实测 30–90s 且
    //    `ready` 常常不收敛），有界预算兜不住，与其静默给一份偏低的锚点集合，
    //    不如明确说"这次不跑语义层"。
    let is_workspace_root = std::fs::read_to_string(module_dir.join("Cargo.toml"))
        .map(|text| text.lines().any(|l| l.trim().starts_with("[workspace]")))
        .unwrap_or(false);
    if !is_workspace_root {
        rep.status = "unsupported_scope";
        rep.reason = Some((
            "UNSUPPORTED".to_string(),
            format!(
                "{scope_rel} 不是 cargo workspace root（其 Cargo.toml 没有 [workspace] 声明），\
                 在此启动 rust-analyzer 会加载整个仓库 workspace；要语义锚点请对小作用域直接跑 \
                 `nexus-harness code symbol <Name> --workspace <workspace-root> --json`"
            ),
        ));
        return rep;
    }

    // 2) 指纹不可用 ⇒ 不起 provider（与 `code` 同一规则：不把"无法证明绑定"说成"绑定成立"）。
    if digest_is_unusable(&digest) {
        rep.status = "stale";
        rep.reason = Some((
            "SNAPSHOT_STALE".to_string(),
            "查询开始前取不到可信的工作树指纹（git status/write-tree 失败或降级）".to_string(),
        ));
        return rep;
    }

    // 3) 候选只来自模块契约。
    let (candidates, spans) = contract_candidates(&module_dir.join("MODULE.md"));
    rep.candidate_spans = spans;
    if candidates.is_empty() {
        rep.status = "no_candidates";
        rep.reason = Some((
            "SYMBOL_NOT_FOUND".to_string(),
            "模块契约 MODULE.md 里没有可解析的反引号标识符；语义层不猜名字也不扫源码".to_string(),
        ));
        return rep;
    }

    // 4) 逐个尝试，首个产出的即停；全部空手时保留**最后一条**失败原因（不编造）。
    let mut last_reason: Option<(String, String)> = None;
    for name in candidates.iter().take(CONTEXT_MAX_CANDIDATES) {
        rep.candidate_queries += 1;
        let mut args: Vec<String> = vec![
            "symbol".to_string(),
            name.clone(),
            "--workspace".to_string(),
            scope_rel.clone(),
            "--max-results".to_string(),
            CONTEXT_MAX_RESULTS.to_string(),
            // context 是入口，不是下钻工具：片段压到 1 行，要看细节再用 `code hover`。
            "--max-snippet-lines".to_string(),
            "1".to_string(),
        ];
        if let Some(binary) = provider_override {
            args.push("--provider-binary".to_string());
            args.push(binary.to_string());
        }

        let (verdict, _message, fields) = run(&args);
        let map: serde_json::Map<String, Value> = fields.into_iter().collect();
        let results = map
            .get("results")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if verdict == "PASS" && !results.is_empty() {
            rep.anchors = results.into_iter().take(CONTEXT_MAX_RESULTS).collect();
            rep.truncated = map
                .get("budget")
                .and_then(|b| b.get("truncated"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            rep.status = "ok";
            rep.reason = None;
            return rep;
        }
        let code = map
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(Value::as_str)
            .unwrap_or("SYMBOL_NOT_FOUND")
            .to_string();
        let reason_text = map
            .get("error")
            .and_then(|e| e.get("reason"))
            .and_then(Value::as_str)
            .unwrap_or("语义查询未产出锚点")
            .to_string();
        rep.status = status_for_error(&code);
        last_reason = Some((code, reason_text));
    }
    rep.reason = last_reason;
    rep
}

fn kept_count(fields: &[(String, Value)]) -> usize {
    fields
        .iter()
        .find(|(k, _)| k == "results")
        .and_then(|(_, v)| v.as_array())
        .map(Vec::len)
        .unwrap_or(0)
}

/// `Repo::working_tree_digest()` 的降级哨兵值（env.rs 的 `unwrap_or_else` 分支）。
/// 命中任一哨兵就说明**没取到**指纹，不能参与"前后一致"的判定。
const DIGEST_SENTINELS: [&str; 2] = ["tree-unknown", "dirty-unknown"];

fn digest_is_unusable(digest: &str) -> bool {
    digest.is_empty() || DIGEST_SENTINELS.contains(&digest)
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
/// **归一化后**比较：词法前缀判定会被 `fixtures/../../../../x` 这类 `..` 路径骗过。
fn validate_target(request: &Request) -> Result<(), Failure> {
    let target = match &request.target {
        Target::File(path) => path.clone(),
        Target::Location(loc) => loc.path.clone(),
        // 符号名形态由 provider 解析，越界结果以 in_scope 标注而非静默丢弃。
        Target::Query(_) => return Ok(()),
    };
    if !crate::env::path_is_within_resolved(&target, &request.workspace) {
        return Err(CodeIntelError::QueryInvalid.with_reason(format!(
            "查询目标 {} 不在 --workspace {} 范围内（按 canonical 后的组件比较；`..` 不能用来逃出作用域）",
            target.display(),
            request.workspace.display()
        )));
    }
    Ok(())
}

/// `--workspace` 必须是仓库内的目录；provider 的 cwd 也限制在其中（提案 §14）。
///
/// 顺序是契约的一部分：先验根、再验目标。round 2 的 B-R2-1 里越界的 `--workspace`
/// 因为只做了词法判定而被放行，结果**真的 spawn 了子进程**（错误发生在 initialize 之后），
/// 等于"仓库边界"只在看起来像失败时才失败。
fn validate_scope(repo: &Repo, request: &Request) -> Result<(), Failure> {
    if !request.workspace.is_dir() {
        return Err(CodeIntelError::WorkspaceUnresolved.with_reason(format!(
            "workspace 根不是目录：{}",
            request.workspace.display()
        )));
    }
    if !crate::env::path_is_within_resolved(&request.workspace, &repo.root) {
        return Err(CodeIntelError::WorkspaceUnresolved.with_reason(format!(
            "workspace 根超出仓库范围：{}（仓库根 {}）",
            request.workspace.display(),
            repo.root.display()
        )));
    }
    validate_target(request)
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

    /// 取不到工作树指纹时必须拒绝下结论；"前后两次都失败"不等于"工作树没变"。
    #[test]
    fn unusable_tree_digest_is_never_treated_as_fresh() {
        for sentinel in ["tree-unknown", "dirty-unknown", ""] {
            assert!(digest_is_unusable(sentinel), "{sentinel} 必须判为不可用");
        }
        assert!(!digest_is_unusable(
            "357bb50e37fe1c0f2a5d0b7a4a7e9f0c1b2d3e4f"
        ));
    }

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

    /// B-R2-1 表现一：带 `..` 的目标在词法上仍以 `--workspace` 为前缀，实际落在其外。
    /// canonical 之后它是 `engineering/nexus-harness/src/main.rs`（存在，故不是"文件不存在"）。
    #[test]
    fn dotdot_target_cannot_escape_workspace() {
        let (verdict, msg, extras) = run(&[
            "definition".to_string(),
            "engineering/nexus-harness/fixtures/code-intel/src/../../../src/main.rs:1:1"
                .to_string(),
            "--workspace".to_string(),
            "engineering/nexus-harness/fixtures/code-intel".to_string(),
        ]);
        assert_eq!(verdict, "FAIL", "{msg}");
        let obj: serde_json::Map<String, Value> = extras.into_iter().collect();
        assert_eq!(obj["error"]["code"], json!("QUERY_INVALID"), "{msg}");
        assert!(
            obj.get("provider").is_none(),
            "越界目标必须在 spawn 之前被拒：{obj:?}"
        );
    }

    /// B-R2-1 表现二：`--workspace` 根自身逃出仓库时，不得起子进程（round 2 实测曾 spawn）。
    #[test]
    fn workspace_escape_is_rejected_before_provider_spawn() {
        let (verdict, msg, extras) = run(&[
            "symbol".to_string(),
            "Egress".to_string(),
            "--workspace".to_string(),
            "engineering/nexus-harness/../../../".to_string(),
        ]);
        assert_eq!(verdict, "BLOCKED", "{msg}");
        let obj: serde_json::Map<String, Value> = extras.into_iter().collect();
        assert_eq!(obj["error"]["code"], json!("WORKSPACE_UNRESOLVED"), "{msg}");
        assert!(
            obj.get("provider").is_none(),
            "越界的 --workspace 不得启动 language server：{obj:?}"
        );
        // round 3 待办 4：作用域被拒时 snapshot 仍在（仓库发现已完成），但
        // `workspace_root` 不得出现——它只有"已确定为 X"这一种含义。
        let snap = &obj["snapshot"];
        assert!(snap.is_object(), "仓库发现成功就必须带 snapshot：{obj:?}");
        assert!(
            snap.get("workspace_root").is_none(),
            "未确定作用域时不得出现 workspace_root（旧实现写 `\".\"` 冒充仓库根）：{snap}"
        );
    }

    #[test]
    fn early_failures_never_claim_a_workspace_root() {
        // 同一不变量的另一条路径：verb 缺失（QUERY_INVALID → FAIL）与 verb 不认识
        // （UNSUPPORTED → BLOCKED）都发生在 options 解析之前，作用域从未被确定过，
        // 因此 `workspace_root` 不该出现。verdict 按 MODULE.md 冻结的错误码表逐个钉死。
        for (args, want_verdict, want_code) in [
            (Vec::<String>::new(), "FAIL", json!("QUERY_INVALID")),
            (
                vec!["rename".to_string(), "x".to_string()],
                "BLOCKED",
                json!("UNSUPPORTED"),
            ),
        ] {
            let (verdict, msg, extras) = run(&args);
            assert_eq!(verdict, want_verdict, "{msg}");
            let obj: serde_json::Map<String, Value> = extras.into_iter().collect();
            assert_eq!(obj["error"]["code"], want_code, "{msg}");
            if let Some(snap) = obj.get("snapshot") {
                assert!(
                    snap.get("workspace_root").is_none(),
                    "verb={} 的早期失败里 snapshot 冒充了作用域：{snap}",
                    args.first().map(String::as_str).unwrap_or("<none>")
                );
            }
        }
    }

    /// 每个用例独占的临时目录：测试在同一进程里并发跑，名字必须带用例标签与 pid；
    /// 一律落在 `std::env::temp_dir()` 下，绝不在仓库工作树里造文件。
    fn scratch_dir(tag: &str) -> PathBuf {
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("nexus-context-{tag}-{pid}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)
            .unwrap_or_else(|e| panic!("建临时目录 {} 失败：{e}", dir.display()));
        dir
    }

    /// `anchors` 的候选门之后就是 `run()`，一旦门次出错就会去找 language server。
    /// 传一个必然不存在的 binary 名，把"不该发生 provider 调用"变成可观测的断言：
    /// 真走到那一步的话 `resolve_binary` 报 `PROVIDER_UNAVAILABLE`，status 变成
    /// `unavailable` 且 `candidate_queries >= 1`，绝不再是预期的那个门状态。
    const BOGUS_PROVIDER: &str = "definitely-not-a-real-language-server";

    /// 候选只认反引号里的 Rust 风格标识符：首字母大写、长度 >= 3、逐字符是 ASCII
    /// 字母数字或下划线；重复项去重并保留首次出现顺序。
    ///
    /// `Foo, Bar` 的形状要说清：实现先做"整段逐字符合法"过滤，再取词首连续 run，
    /// 所以同一个反引号对里的列表**整体被丢弃**——既不产 `Foo` 也不产 `Bar`。
    /// 这与"取词首"的意图不符（也正因此那段 take_while 实际不可达）。这里按现状
    /// 钉死形状：生产侧改成先取词首时，本断言会立刻红，不会被静默放过。
    /// 复用键的四个维度必须**逐个**能单独触发重建，且原因串分辨得出是哪一维变了。
    /// 顺序也有意义：指纹变化最危险，所以它优先于 workspace/binary/version 被报出来。
    #[test]
    fn session_key_invalidation_reports_the_first_changed_dimension() {
        let base = SessionKey {
            binary: "rust-analyzer".to_string(),
            workspace: "crates/nexus-domain".to_string(),
            version: "1.98.1".to_string(),
            digest: "aaaa".to_string(),
        };
        assert_eq!(
            session_invalidated_reason(&base, &base.clone()),
            "provider_restarted"
        );

        let mut digest_changed = base.clone();
        digest_changed.digest = "bbbb".to_string();
        assert_eq!(
            session_invalidated_reason(&base, &digest_changed),
            "digest_changed",
            "工作树指纹变化必须最先报，它决定索引是否还描述当前代码"
        );

        // 指纹与 workspace 同时变时，仍先报 digest_changed（更危险的那一个优先）。
        let mut both = digest_changed.clone();
        both.workspace = "crates/nexus-network".to_string();
        assert_eq!(session_invalidated_reason(&base, &both), "digest_changed");

        let mut ws_only = base.clone();
        ws_only.workspace = "apps/nexus".to_string();
        assert_eq!(
            session_invalidated_reason(&base, &ws_only),
            "workspace_changed"
        );

        let mut bin_only = base.clone();
        bin_only.binary = "D:/other/rust-analyzer".to_string();
        assert_eq!(
            session_invalidated_reason(&base, &bin_only),
            "binary_changed"
        );

        // 版本不同没有独立标签（同一 binary/workspace 换 server 版本 = 进程换了），
        // 但绝不能被判成"可以复用"——键本身不相等。
        let mut ver_only = base.clone();
        ver_only.version = "1.95.0".to_string();
        assert_ne!(
            base, ver_only,
            "版本不同必须使键不等，否则旧索引冒充新 server 的结论"
        );
        assert_eq!(
            session_invalidated_reason(&base, &ver_only),
            "provider_restarted"
        );
    }

    /// provider 没起来时的元数据不许谎报会话状态：复用 false、查询次数 **0**、无失效原因。
    /// （0 而不是 1：一次都没成功服务过查询。）
    #[test]
    fn startup_failure_meta_claims_no_session_activity() {
        let key = SessionKey {
            binary: "rust-analyzer".to_string(),
            workspace: "crates/nexus-domain".to_string(),
            version: "1.98.1".to_string(),
            digest: "aaaa".to_string(),
        };
        let meta = startup_failure_meta(&key, "1.98.1", &Instant::now());
        assert!(!meta.ready, "起不来不得自称就绪");
        assert!(!meta.session_reused);
        assert_eq!(meta.session_queries, 0, "没起来就是零次查询");
        assert!(meta.session_invalidated_reason.is_empty());
        let json = meta.to_json();
        for field in [
            "session_reused",
            "session_queries",
            "session_invalidated_reason",
        ] {
            assert!(
                json.get(field).is_some(),
                "{field} 必须出现在 provider 输出里，否则消费方看不见复用状态"
            );
        }
    }

    #[test]
    fn contract_candidates_keeps_only_deduped_uppercase_identifiers() {
        let dir = scratch_dir("candidates");
        let md = dir.join("MODULE.md");
        std::fs::write(
            &md,
            "- `Egress` 出向网关\n\
             - `Scheduler` 调度\n\
             - `Foo, Bar` 一个反引号里的列表\n\
             - `run_static` 小写开头\n\
             - `AB` 长度不足 3\n\
             - `not a symbol` 含空格\n\
             - `Egress` 重复出现\n\
             - `Snapshot_1` 下划线与数字合法\n\
             - `Context-Builder` 含连字符\n",
        )
        .expect("写 MODULE.md");
        let (raw, spans) = contract_candidates(&md);
        let got: Vec<&str> = raw.iter().map(String::as_str).collect();
        assert_eq!(
            got,
            ["Egress", "Scheduler", "Snapshot_1"],
            "只留合法标识符并按首次顺序去重"
        );
        // 看到的 code span 总数必须如实上报：漏收要能被看见，而不是悄悄少几个锚点。
        assert_eq!(spans, 9, "成对反引号的格子总数");
        assert_eq!(
            got.iter().filter(|s| **s == "Egress").count(),
            1,
            "重复项必须去重"
        );
        // 一格里写多个名字（Foo, Bar）整格作废：刻意不做「取词首」，因为那会把
        // Cargo.toml 变成 Cargo、把 Context-Builder 变成 Context，而截断片段可能命中
        // 另一个符号、把 Agent 领到错的地方。取舍与代价都写在 MODULE.md 的契约里。
        for leak in [
            "Foo",
            "Bar",
            "run_static",
            "AB",
            "not a symbol",
            "Context-Builder",
        ] {
            assert!(!got.contains(&leak), "{leak:?} 不该成为候选");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 读不到 MODULE.md（文件不存在 / 该路径是目录 / 父目录都不在）一律返回空 Vec：
    /// 候选集不许靠猜，IO 失败也不许 panic——上层据此报 `no_candidates`。
    #[test]
    fn contract_candidates_without_readable_module_md_is_empty() {
        let dir = scratch_dir("missing-md");
        let absent = dir.join("MODULE.md");
        assert!(
            contract_candidates(&absent).0.is_empty(),
            "文件不存在时必须为空"
        );
        std::fs::create_dir_all(&absent).expect("把 MODULE.md 的位置做成目录");
        assert!(
            contract_candidates(&absent).0.is_empty(),
            "路径是目录时必须为空"
        );
        let deep = dir.join("no-such-dir").join("MODULE.md");
        assert!(
            contract_candidates(&deep).0.is_empty(),
            "父目录不存在时同样为空"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 映射表逐臂钉死，兜底必须是悲观值 `unavailable`：空串、拼错的码、大小写不符
    /// 都不许落到 `ok` / `no_candidates` / `not_found` 这类看起来像结论的状态——
    /// "我们没映射上这个码"不等于"查过了确实没有"。
    #[test]
    fn status_for_error_maps_every_arm_and_fails_closed() {
        for code in [
            "PROVIDER_UNAVAILABLE",
            "INITIALIZATION_FAILED",
            "PROVIDER_CRASHED",
        ] {
            assert_eq!(status_for_error(code), "unavailable", "{code} 是工具不在场");
        }
        assert_eq!(
            status_for_error("TIMEOUT"),
            "timeout",
            "索引未收敛不等于没有符号"
        );
        assert_eq!(status_for_error("SYMBOL_NOT_FOUND"), "not_found");
        assert_eq!(status_for_error("SNAPSHOT_STALE"), "stale");
        assert_eq!(
            status_for_error("WORKSPACE_UNRESOLVED"),
            "unsupported_scope"
        );
        // QUERY_INVALID 有独立状态：那是"我们自己的用法错了"，不能被糊成"工具不可用"。
        assert_eq!(status_for_error("QUERY_INVALID"), "invalid_query");
        // 剩下的冻结码（RESULT_TRUNCATED）与一切未知码都走悲观兜底。
        for code in [
            "",
            " ",
            "ok",
            "OK",
            "snapshot_stale",
            "RESULT_TRUNCATED",
            "BOGUS_CODE",
        ] {
            let got = status_for_error(code);
            assert_eq!(got, "unavailable", "未知码 {code:?} 必须落到悲观值");
            assert_ne!(got, "ok", "未知码 {code:?} 不得伪造成成功");
            assert_ne!(got, "no_candidates", "未知码 {code:?} 不得伪装成契约缺候选");
            assert_ne!(got, "not_found", "未知码 {code:?} 不得伪装成查过没有");
        }
    }

    /// 语义作用域门（gate 1）必须先于候选门与 provider：非 workspace root 只回
    /// `unsupported_scope` + `UNSUPPORTED`，且一次 `run()` 都不发起。
    /// MODULE.md 里刻意放一个合法候选——万一作用域门被挪到候选之后，代码就会走到
    /// `run()`，届时 status 变成 `unavailable`（假 binary 名）、`candidate_queries`
    /// 变成 1，下面关于这两项的断言会同时抓住它，不会静默起真的 rust-analyzer。
    #[test]
    fn anchors_refuses_non_workspace_scope_without_spawning_provider() {
        let repo = Repo::discover().expect("must run inside the nexus repository");
        for (tag, manifest) in [
            ("package-only", Some("[package]\nname = \"scratch\"\n")),
            ("no-manifest", None),
        ] {
            let dir = scratch_dir(&format!("scope-{tag}"));
            if let Some(text) = manifest {
                std::fs::write(dir.join("Cargo.toml"), text).expect("写 Cargo.toml");
            }
            std::fs::write(dir.join("MODULE.md"), "- `Egress` 出向网关\n").expect("写 MODULE.md");

            let rep = anchors(&repo, &dir, Some(BOGUS_PROVIDER));
            assert_eq!(
                rep.status, "unsupported_scope",
                "{tag}：status 实际为 {}",
                rep.status
            );
            let reason = rep.reason.as_ref().expect("非 ok 状态必须带结构化原因");
            assert_eq!(reason.0, "UNSUPPORTED", "{tag}：原因码沿用 code 的冻结表");
            assert!(
                reason.1.contains("cargo workspace root"),
                "{tag}：{}",
                reason.1
            );
            assert!(rep.anchors.is_empty(), "{tag}：作用域被拒时不得有锚点");
            assert_eq!(
                rep.candidate_queries, 0,
                "{tag}：0 次尝试才等于没起 language server"
            );
            assert!(!rep.truncated, "{tag}：没有查询就没有截断可报");
            assert_eq!(rep.max_results, CONTEXT_MAX_RESULTS, "{tag}");
            assert!(
                rep.snapshot.is_object(),
                "{tag}：仓库发现已完成，snapshot 必须在场"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// 候选集为空 ⇒ `no_candidates` + `SYMBOL_NOT_FOUND`，同样一次查询都不发起。
    /// 门次提醒：作用域门之后、候选门之前还有一道指纹门（gate 2），git 调用降级成
    /// 哨兵值时本用例只能观测到 `stale`（并发跑测试时的真实形态，见 env.rs 的
    /// index.lock 说明）。分支判定只允许用**这次调用产出的 snapshot**，不许再问一次
    /// git —— 二次取值会带来"实现降级了但测试没看出来"的假红。两个分支都写断言，
    /// 不用 early return 跳过——"没测到"不能伪装成"测过了"。
    #[test]
    fn anchors_without_contract_candidates_reports_no_candidates() {
        let repo = Repo::discover().expect("must run inside the nexus repository");
        let dir = scratch_dir("no-candidates");
        std::fs::write(dir.join("Cargo.toml"), "[workspace]\nmembers = []\n")
            .expect("写 Cargo.toml");
        std::fs::write(
            dir.join("MODULE.md"),
            "- 只有小写 `run_static` 与短名 `AB`，无合法候选\n",
        )
        .expect("写 MODULE.md");

        let rep = anchors(&repo, &dir, Some(BOGUS_PROVIDER));
        assert!(rep.anchors.is_empty(), "候选缺失时不得有锚点");
        assert_eq!(rep.candidate_queries, 0, "候选为空即返回，不得尝试任何查询");
        assert!(!rep.truncated);
        let reason = rep.reason.as_ref().expect("非 ok 状态必须带结构化原因");
        // 判据只能来自**这次调用自己的产物**：再问一次 git 会引入二次竞态
        // ——并发跑时 `anchors()` 里那次 `git write-tree` 可能因 index.lock 降级成哨兵值，
        // 而测试随后再问一次却拿到了正常指纹，于是走进 else 分支断言 `no_candidates`
        // 并假红（Linux 上实测过；Windows 单跑永远复现不出来）。
        let digest = rep.snapshot["working_tree_digest"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        if digest_is_unusable(&digest) {
            assert_eq!(
                rep.status, "stale",
                "这次调用的指纹是哨兵值时，门 2 必须先命中（digest={digest}）"
            );
            assert_eq!(reason.0, "SNAPSHOT_STALE");
        } else {
            assert_eq!(rep.status, "no_candidates", "status 实际为 {}", rep.status);
            assert_eq!(
                reason.0, "SYMBOL_NOT_FOUND",
                "不猜名字不等于'库里没有这个符号'"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 门次回归护栏：既没有 Cargo.toml 也没有 MODULE.md 时必须报 `unsupported_scope`，
    /// 而不是看似无害的 `no_candidates`——后者会被 Agent 读成"契约里没符号"而跑去改
    /// MODULE.md，真正该说的是"这个作用域压根不该跑语义层"。反向对照（补上 `[workspace]`
    /// 声明后落回后续门）证明 unsupported_scope 来自 Cargo.toml 判定，
    /// 不是"目录空无一物"的巧合。
    #[test]
    fn anchors_checks_workspace_scope_before_candidate_extraction() {
        let repo = Repo::discover().expect("must run inside the nexus repository");
        let dir = scratch_dir("scope-before-candidates");

        let bare = anchors(&repo, &dir, Some(BOGUS_PROVIDER));
        assert_eq!(
            bare.status, "unsupported_scope",
            "作用域门必须先于候选门命中"
        );
        let reason = bare.reason.as_ref().expect("非 ok 状态必须带结构化原因");
        assert_eq!(reason.0, "UNSUPPORTED", "空目录不得被说成契约缺候选");
        assert_eq!(bare.candidate_queries, 0, "门 1 命中时不该有任何语义尝试");
        assert!(bare.anchors.is_empty());

        std::fs::write(dir.join("Cargo.toml"), "[workspace]\nmembers = []\n")
            .expect("写 Cargo.toml");
        let after = anchors(&repo, &dir, Some(BOGUS_PROVIDER));
        assert_ne!(
            after.status, "unsupported_scope",
            "补上 [workspace] 后必须穿过作用域门"
        );
        assert!(
            matches!(after.status, "no_candidates" | "stale"),
            "只允许落到候选门或指纹门，实际 {}",
            after.status
        );
        assert_eq!(after.candidate_queries, 0, "两道门都在 run() 之前返回");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

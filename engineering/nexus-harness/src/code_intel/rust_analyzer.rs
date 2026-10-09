//! rust-analyzer provider：提案 §6 的只读语义查询实现。
//!
//! 生命周期（MODULE.md Side Effects 冻结）：
//!
//! ```text
//! resolve workspace root → spawn → initialize / initialized → 有界就绪等待
//!   → didOpen 目标文件 → 只读请求（超白名单即拒）→ 崩溃最多重启一次 → shutdown/exit
//! ```
//!
//! 就绪判定不依赖 rust-analyzer 私有状态字符串：优先接受
//! `rust-analyzer/status`（含 ready/idle）或 `$/progress` 的 `end`；若 server
//! 完全不上报进度，则在 3s 静默后视为就绪并把 `provider.ready` 记为 true。

use crate::code_intel::dto::{
    Budget, CodeIntelError, Failure, ProviderMeta, ResultItem, diagnostic_severity, relative_path,
    symbol_kind,
};
use crate::code_intel::lsp::{LspSession, path_to_uri, uri_to_path};
use crate::code_intel::provider::{
    CodeIntelligenceProvider, DiagnosticItem, SourceLocation, Timeouts,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// 就绪等待里的静默阈值：server 完全不上报进度时的兜底。
const QUIET_FALLBACK: Duration = Duration::from_millis(5_000);
/// 收敛判定所需的静默窗口：最后一组 progress 之后再无活动多久才算加载完。
const SETTLE: Duration = Duration::from_millis(1_500);
/// 单次轮询步进。
const POLL_STEP: Duration = Duration::from_millis(100);

/// LSP 范围（已转为 1-based）。
type LspRange = (usize, usize, usize, usize);

/// 一个已解析的声明位置 + 从中补全的符号信息。
struct ResolvedSite {
    abs_path: PathBuf,
    range: LspRange,
}

pub struct RustAnalyzerProvider {
    binary: PathBuf,
    workspace_root: PathBuf,
    repo_root: PathBuf,
    session: Option<LspSession>,
    opened: HashMap<PathBuf, String>,
    /// 每个已打开文件的 documentSymbol 缓存（用于补全 name/kind）。
    symbols: HashMap<PathBuf, Vec<SymbolRecord>>,
    meta: ProviderMeta,
    timeouts: Timeouts,
    /// progress 收敛跟踪（跨重连保留）。
    tracker: ReadinessTracker,
    /// ready 预算已耗尽仍未收敛（使 Pending 定格为 TimedOut）。
    budget_exhausted: bool,
    /// 缓存的 publishDiagnostics（pull 不可用时的兜底）。
    published: Vec<Value>,
}

#[derive(Clone)]
struct SymbolRecord {
    name: String,
    container: String,
    kind: u8,
    range: LspRange,
}

impl RustAnalyzerProvider {
    pub fn start(
        binary: &Path,
        workspace_root: &Path,
        repo_root: &Path,
        version: &str,
        timeouts: Timeouts,
    ) -> Result<RustAnalyzerProvider, Failure> {
        if !workspace_root.is_dir() {
            return Err(CodeIntelError::WorkspaceUnresolved.with_reason(format!(
                "workspace 根不存在或不是目录：{}",
                workspace_root.display()
            )));
        }
        let mut provider = RustAnalyzerProvider {
            binary: binary.to_path_buf(),
            workspace_root: workspace_root.to_path_buf(),
            repo_root: repo_root.to_path_buf(),
            session: None,
            opened: HashMap::new(),
            symbols: HashMap::new(),
            meta: ProviderMeta {
                kind: "rust-analyzer".to_string(),
                version: version.to_string(),
                ready: false,
                restart_count: 0,
                duration_ms: 0,
                write_requests_refused: 0,
            },
            timeouts,
            // connect() 前尚未就绪；保守值使空结果被判不可信。
            budget_exhausted: false,
            tracker: ReadinessTracker::new(),
            published: Vec::new(),
        };
        provider.connect()?;
        Ok(provider)
    }

    fn connect(&mut self) -> Result<(), Failure> {
        let mut session = LspSession::spawn(&self.binary, &self.workspace_root)?;
        let params = initialize_params(&self.workspace_root);
        // initialize 本身可能触发 cargo metadata / sysroot 探测，给到 ready 预算。
        session
            .request("initialize", params, self.timeouts.ready)
            .map_err(|e| {
                CodeIntelError::InitializationFailed.with_reason(format!(
                    "initialize 失败：{}｜provider stderr 尾部：{}",
                    e.reason,
                    session.stderr_tail(2000)
                ))
            })?;
        session.notify("initialized", json!({}))?;
        let state = wait_until_ready(
            &mut session,
            self.timeouts.ready,
            &mut self.published,
            &mut self.tracker,
        )?;
        if state == Readiness::TimedOut {
            self.budget_exhausted = true;
        }
        self.session = Some(session);
        Ok(())
    }

    /// 当前就绪状态：由 tracker 实时推导，budget 耗尽后把 Pending 定格为 TimedOut。
    /// （不做"一次性快照"，否则晚到的 progress begin 会被旧的 Quiet 掩盖。）
    fn readiness(&self) -> Readiness {
        let state = self.tracker.state(QUIET_FALLBACK, SETTLE);
        if state == Readiness::Pending && self.budget_exhausted {
            Readiness::TimedOut
        } else {
            state
        }
    }

    /// 吸干当前 notification，更新收敛跟踪（不阻塞）。
    fn refresh_readiness(&mut self) {
        let mut drained: Vec<Value> = Vec::new();
        if let Some(session) = self.session.as_mut() {
            while let Some(note) = session.try_notification() {
                if note.get("method").and_then(Value::as_str)
                    == Some("textDocument/publishDiagnostics")
                {
                    if let Some(params) = note.get("params") {
                        if self.published.len() < 64 {
                            self.published.push(params.clone());
                        }
                    }
                }
                drained.push(note);
            }
        }
        for note in drained {
            self.tracker.observe(&note);
        }
    }

    /// 语义查询专用：空结果在重试窗口内一律重试；窗口耗尽或已收敛才返回。
    /// 最终仍为空时，由 `readiness()` 决定这是可信答案还是 BLOCKED（提案 §12）。
    fn request_until_hits(&mut self, method: &str, params: Value) -> Result<Value, Failure> {
        let retry_until = Instant::now() + self.timeouts.ready.min(EMPTY_RETRY_WINDOW);
        let hard_deadline = Instant::now() + self.timeouts.ready;
        loop {
            let value = self.guarded_request(method, params.clone())?;
            self.refresh_readiness();
            if !is_empty_result(&value) {
                return Ok(value);
            }
            if self.readiness() == Readiness::Completed && Instant::now() >= retry_until {
                return Ok(value);
            }
            if Instant::now() >= hard_deadline {
                self.budget_exhausted = true;
                return Ok(value);
            }
            std::thread::sleep(POLL_STEP);
        }
    }

    /// 空结果只有在就绪收敛后才可当作答案；否则显式 BLOCKED（提案 §12：
    /// 不得把"尚未索引"伪装成"没有命中"）。
    pub fn empty_is_trustworthy(&self, what: &str) -> Result<(), Failure> {
        if self.readiness().trustworthy() {
            return Ok(());
        }
        Err(CodeIntelError::InitializationFailed.with_reason(format!(
            "{what} 返回空结果，但 provider 在预算内未收敛（rust-analyzer 可能仍在加载 workspace）；不能据此判定无命中"
        )))
    }

    /// 只读请求 + 崩溃重启一次（提案 §6/§14：crash 可重启但必须记录）。
    fn guarded_request(&mut self, method: &str, params: Value) -> Result<Value, Failure> {
        let first = match self.session.as_mut() {
            Some(s) => s.request(method, params.clone(), self.timeouts.request),
            None => {
                self.connect()?;
                self.session.as_mut().expect("connect 建立了会话").request(
                    method,
                    params.clone(),
                    self.timeouts.request,
                )
            }
        };
        match first {
            Ok(value) => Ok(value),
            Err(err)
                if err.code == CodeIntelError::ProviderCrashed && self.meta.restart_count == 0 =>
            {
                self.meta.restart_count = 1;
                if let Some(mut session) = self.session.take() {
                    session.close_quietly();
                }
                self.opened.clear();
                self.symbols.clear();
                self.connect()?;
                let session = self.session.as_mut().expect("重连建立了会话");
                session
                    .request(method, params, self.timeouts.request)
                    .map_err(|retry| {
                        CodeIntelError::ProviderCrashed.with_reason(format!(
                            "重启后仍失败（首次原因：{}）：{}",
                            err.reason, retry.reason
                        ))
                    })
            }
            Err(err) => Err(err),
        }
    }

    fn ensure_open(&mut self, path: &Path) -> Result<String, Failure> {
        if let Some(uri) = self.opened.get(path) {
            return Ok(uri.clone());
        }
        let abs = absolute(path);
        let text = std::fs::read_to_string(&abs).map_err(|e| {
            CodeIntelError::QueryInvalid.with_reason(format!("无法读取 {}: {e}", abs.display()))
        })?;
        let uri = path_to_uri(&abs);
        let params = json!({
            "textDocument": {
                "uri": uri,
                "languageId": "rust",
                "version": 1,
                "text": text,
            }
        });
        self.guarded_request_notify("textDocument/didOpen", params)?;
        self.opened.insert(abs.clone(), uri.clone());
        self.symbols.remove(&abs);
        Ok(uri)
    }

    fn guarded_request_notify(&mut self, method: &str, params: Value) -> Result<(), Failure> {
        let first = match self.session.as_mut() {
            Some(s) => s.notify(method, params.clone()),
            None => {
                self.connect()?;
                self.session
                    .as_mut()
                    .expect("connect 建立了会话")
                    .notify(method, params.clone())
            }
        };
        match first {
            Ok(()) => Ok(()),
            Err(err)
                if err.code == CodeIntelError::ProviderCrashed && self.meta.restart_count == 0 =>
            {
                self.meta.restart_count = 1;
                if let Some(mut session) = self.session.take() {
                    session.close_quietly();
                }
                self.opened.clear();
                self.symbols.clear();
                self.connect()?;
                self.session
                    .as_mut()
                    .expect("重连建立了会话")
                    .notify(method, params)
            }
            Err(err) => Err(err),
        }
    }

    /// 拉取并缓存某文件的 documentSymbol，用于把 LSP `Location` 补成
    /// 带 name/kind 的中立条目。
    fn symbol_records(&mut self, path: &Path) -> Result<Vec<SymbolRecord>, Failure> {
        let abs = absolute(path);
        if let Some(cached) = self.symbols.get(&abs) {
            let snapshot = cached.clone();
            return Ok(snapshot);
        }
        let uri = self.ensure_open(&abs)?;
        let result = self.request_until_hits(
            "textDocument/documentSymbol",
            json!({"textDocument": {"uri": uri}}),
        )?;
        let mut records = Vec::new();
        collect_symbols(&result, "", &mut records);
        self.symbols.insert(abs, records.clone());
        Ok(records)
    }

    /// 找出包含指定位置的最小符号（用于 name/kind 补全）。
    fn symbol_at(&mut self, path: &Path, line: usize, column: usize) -> Option<SymbolRecord> {
        let records = self.symbol_records(path).ok()?;
        let mut best: Option<&SymbolRecord> = None;
        for record in &records {
            let (sl, sc, el, ec) = record.range;
            let inside = (sl, sc) <= (line, column) && (line, column) <= (el, ec);
            if !inside {
                continue;
            }
            match best {
                Some(current) => {
                    let cur_area = (current.range.2 - current.range.0) * 1_000 + current.range.3
                        - current.range.1;
                    let new_area = (el - sl) * 1_000 + ec - sc;
                    if new_area < cur_area {
                        best = Some(record);
                    }
                }
                None => best = Some(record),
            }
        }
        best.cloned()
    }

    /// 把一个 `Location` 形状的结果转成中立条目；失败时退化为只带 path/range，
    /// `kind` 记为 "unknown"（不伪造 kind）。
    fn item_from_site(&mut self, site: &ResolvedSite, label: &str, max_lines: usize) -> ResultItem {
        let rel = relative_path(&self.repo_root, &site.abs_path);
        let snippet = snippet_of(&site.abs_path, site.range, max_lines);
        let symbol_name = if self.opened.contains_key(&site.abs_path) || self.opened.len() < 16 {
            self.symbol_at(&site.abs_path, site.range.0, site.range.1)
        } else {
            // 补全 name/kind 需要 didOpen 该文件；超出 16 个文件的上限后
            // 不再展开，kind 记为 "unknown"（不伪造、也不无限拉起 server 工作）。
            None
        };
        let (name, kind, kind_id, qualified) = match symbol_name {
            Some(record) => {
                let qualified = if record.container.is_empty() {
                    record.name.clone()
                } else {
                    format!("{}::{}", record.container, record.name)
                };
                (
                    record.name.clone(),
                    symbol_kind(i64::from(record.kind)).to_string(),
                    i64::from(record.kind),
                    qualified,
                )
            }
            None => (
                label.to_string(),
                "unknown".to_string(),
                0,
                if label.is_empty() {
                    rel.clone()
                } else {
                    label.to_string()
                },
            ),
        };
        ResultItem {
            symbol: name,
            kind,
            kind_id,
            qualified_name: qualified,
            path: rel,
            range: Some(crate::code_intel::dto::PositionRange {
                start_line: site.range.0,
                start_column: site.range.1,
                end_line: site.range.2,
                end_column: site.range.3,
            }),
            snippet,
        }
    }

    /// 结束前取元数据，并把会话内累计的写请求拒绝计数并入。
    pub fn finish_meta(&mut self) -> ProviderMeta {
        let refused = self.session.as_ref().map_or(0, |s| s.refused_writes);
        let mut meta = self.meta().clone();
        meta.write_requests_refused = refused;
        meta.ready = self.readiness().trustworthy();
        meta
    }

    /// CallHierarchyItem（incoming 的 `from` / outgoing 的 `to`）-> 中立条目。
    ///
    /// LSP 的 `detail` 是签名而不是命名空间，不能拼成 `签名::名字`；因此优先用
    /// documentSymbol 解析真实容器路径，解析不到才退回 item 自带的 name/kind。
    fn item_from_call(
        &mut self,
        call: &Value,
        key: &str,
        ranges_key: &str,
        budget: &Budget,
    ) -> Option<ResultItem> {
        let item = call.get(key)?;
        let uri = item.get("uri").and_then(Value::as_str).unwrap_or("");
        let abs = PathBuf::from(uri_to_path(uri));
        let range = item
            .get("selectionRange")
            .and_then(lsp_range_of_ref)
            .or_else(|| item.get("range").and_then(lsp_range_of_ref))
            .or_else(|| {
                call.get(ranges_key)
                    .and_then(Value::as_array)
                    .and_then(|a| a.first())
                    .and_then(lsp_range_of_ref)
            })?;
        let name = item
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let site = ResolvedSite {
            abs_path: abs,
            range,
        };
        let mut result = self.item_from_site(&site, &name, budget.max_snippet_lines);
        if result.kind_id == 0 {
            let raw = item.get("kind").and_then(Value::as_i64).unwrap_or(0);
            result.kind_id = raw;
            result.kind = symbol_kind(raw).to_string();
        }
        Some(result)
    }

    fn locations(
        &mut self,
        method: &str,
        loc: &SourceLocation,
        extra: Value,
    ) -> Result<Vec<ResolvedSite>, Failure> {
        let uri = self.ensure_open(&loc.path)?;
        let mut params = json!({
            "textDocument": {"uri": uri},
            "position": loc.lsp_position(),
        });
        if let Some(map) = extra.as_object() {
            for (k, v) in map {
                params[k] = v.clone();
            }
        }
        let result = self.request_until_hits(method, params)?;
        Ok(sites_from_value(&result, &self.workspace_root))
    }

    /// callHierarchy：prepare 后取 selectionRange 覆盖目标位置的 item。
    fn prepare_item(&mut self, loc: &SourceLocation) -> Result<Value, Failure> {
        let uri = self.ensure_open(&loc.path)?;
        let result = self.request_until_hits(
            "textDocument/prepareCallHierarchy",
            json!({"textDocument": {"uri": uri}, "position": loc.lsp_position()}),
        )?;
        let items = result.as_array().cloned().unwrap_or_default();
        let matched = items
            .iter()
            .find(|item| {
                item.pointer("/selectionRange")
                    .and_then(lsp_range_of_ref)
                    .is_some_and(|(sl, sc, el, ec)| {
                        (sl, sc) <= (loc.line, loc.column) && (loc.line, loc.column) <= (el, ec)
                    })
            })
            .cloned();
        matched.or_else(|| items.into_iter().next()).ok_or_else(|| {
            CodeIntelError::SymbolNotFound.with_reason(format!(
                "callHierarchy 无法在 {}（{}:{}）建立 item",
                loc.path.display(),
                loc.line,
                loc.column
            ))
        })
    }
}

/// `LspSession` 的静默关闭（重启路径用；错误一律丢弃）。
trait CloseQuietly {
    fn close_quietly(&mut self);
}

impl CloseQuietly for LspSession {
    fn close_quietly(&mut self) {
        let _ = self.request("shutdown", Value::Null, Duration::from_millis(500));
        let _ = self.notify("exit", Value::Null);
    }
}

impl CodeIntelligenceProvider for RustAnalyzerProvider {
    fn symbols(&mut self, query: &str, budget: &Budget) -> Result<Vec<ResultItem>, Failure> {
        if query.trim().is_empty() {
            return Err(CodeIntelError::QueryInvalid.with_reason("symbol 查询不能为空".to_string()));
        }
        let result = self.request_until_hits("workspace/symbol", json!({"query": query}))?;
        let mut items = Vec::new();
        for entry in result.as_array().into_iter().flatten() {
            let name = entry
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let container = entry
                .get("containerName")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let kind = entry.get("kind").and_then(Value::as_i64).unwrap_or(0) as u8;
            let Some(location) = entry.get("location") else {
                continue;
            };
            let Some((uri, range)) = location_pair(location) else {
                continue;
            };
            let abs = PathBuf::from(uri_to_path(&uri));
            let rel = relative_path(&self.repo_root, &abs);
            let qualified = if container.is_empty() {
                name.clone()
            } else {
                format!("{container}::{name}")
            };
            items.push(ResultItem {
                symbol: name,
                kind: symbol_kind(i64::from(kind)).to_string(),
                kind_id: i64::from(kind),
                qualified_name: qualified,
                path: rel,
                range: Some(crate::code_intel::dto::PositionRange {
                    start_line: range.0,
                    start_column: range.1,
                    end_line: range.2,
                    end_column: range.3,
                }),
                snippet: snippet_of(&abs, range, budget.max_snippet_lines),
            });
        }
        // 精确名优先（保持结果顺序确定，便于 fixture 断言）。
        items.sort_by(|a, b| {
            let a_exact = usize::from(a.symbol != query);
            let b_exact = usize::from(b.symbol != query);
            a_exact
                .cmp(&b_exact)
                .then_with(|| a.path.cmp(&b.path))
                .then_with(|| {
                    a.range
                        .map_or((0, 0), |r| (r.start_line, r.start_column))
                        .cmp(&b.range.map_or((0, 0), |r| (r.start_line, r.start_column)))
                })
        });
        Ok(items)
    }

    fn definition(
        &mut self,
        loc: &SourceLocation,
        budget: &Budget,
    ) -> Result<Vec<ResultItem>, Failure> {
        let sites = self.locations("textDocument/definition", loc, json!({}))?;
        if sites.is_empty() {
            return Err(CodeIntelError::SymbolNotFound.with_reason(format!(
                "{}（{}:{}）没有 definition",
                loc.path.display(),
                loc.line,
                loc.column
            )));
        }
        Ok(sites
            .into_iter()
            .map(|site| self.item_from_site(&site, "", budget.max_snippet_lines))
            .collect())
    }

    fn references(
        &mut self,
        loc: &SourceLocation,
        budget: &Budget,
    ) -> Result<Vec<ResultItem>, Failure> {
        let sites = self.locations(
            "textDocument/references",
            loc,
            json!({"context": {"includeDeclaration": true}}),
        )?;
        // 预算裁剪只在 CLI 层做一次：provider 内截断会让 `count` 变成
        // "截断后的条数"，等于静默丢弃结果（提案 §5 明令禁止）。
        Ok(sites
            .into_iter()
            .map(|site| self.item_from_site(&site, "", budget.max_snippet_lines))
            .collect())
    }

    fn implementations(
        &mut self,
        loc: &SourceLocation,
        budget: &Budget,
    ) -> Result<Vec<ResultItem>, Failure> {
        let sites = self.locations("textDocument/implementation", loc, json!({}))?;
        Ok(sites
            .into_iter()
            .map(|site| self.item_from_site(&site, "", budget.max_snippet_lines))
            .collect())
    }

    fn callers(
        &mut self,
        loc: &SourceLocation,
        budget: &Budget,
    ) -> Result<Vec<ResultItem>, Failure> {
        let item = self.prepare_item(loc)?;
        let result =
            self.request_until_hits("callHierarchy/incomingCalls", json!({"item": item}))?;
        let mut out = Vec::new();
        for call in result.as_array().into_iter().flatten() {
            if let Some(item) = self.item_from_call(call, "from", "fromRanges", budget) {
                out.push(item);
            }
        }
        Ok(out)
    }

    fn callees(
        &mut self,
        loc: &SourceLocation,
        budget: &Budget,
    ) -> Result<Vec<ResultItem>, Failure> {
        let item = self.prepare_item(loc)?;
        let result =
            self.request_until_hits("callHierarchy/outgoingCalls", json!({"item": item}))?;
        let mut out = Vec::new();
        for call in result.as_array().into_iter().flatten() {
            if let Some(item) = self.item_from_call(call, "to", "toRanges", budget) {
                out.push(item);
            }
        }
        Ok(out)
    }

    fn hover(&mut self, loc: &SourceLocation, budget: &Budget) -> Result<Vec<ResultItem>, Failure> {
        let uri = self.ensure_open(&loc.path)?;
        let result = self.request_until_hits(
            "textDocument/hover",
            json!({"textDocument": {"uri": uri}, "position": loc.lsp_position()}),
        )?;
        if result.is_null() {
            return Err(CodeIntelError::SymbolNotFound.with_reason(format!(
                "{}（{}:{}）没有 hover 内容",
                loc.path.display(),
                loc.line,
                loc.column
            )));
        }
        let text = cap_lines(&hover_text(&result), budget.max_snippet_lines);
        let abs = absolute(&loc.path);
        let record = self.symbol_at(&abs, loc.line, loc.column);
        let (name, kind, kind_id) = match &record {
            Some(r) => (
                r.name.clone(),
                symbol_kind(i64::from(r.kind)).to_string(),
                i64::from(r.kind),
            ),
            None => (String::new(), "unknown".to_string(), 0),
        };
        let qualified = record.map_or_else(
            || relative_path(&self.repo_root, &abs),
            |r| {
                if r.container.is_empty() {
                    r.name.clone()
                } else {
                    format!("{}::{}", r.container, r.name)
                }
            },
        );
        Ok(vec![ResultItem {
            symbol: name,
            kind,
            kind_id,
            qualified_name: qualified,
            path: relative_path(&self.repo_root, &abs),
            range: result
                .get("range")
                .and_then(lsp_range_of_ref)
                .map(|(sl, sc, el, ec)| crate::code_intel::dto::PositionRange {
                    start_line: sl,
                    start_column: sc,
                    end_line: el,
                    end_column: ec,
                }),
            snippet: text,
        }])
    }

    fn diagnostics(
        &mut self,
        file: &Path,
        _budget: &Budget,
    ) -> Result<Vec<DiagnosticItem>, Failure> {
        let abs = absolute(file);
        let uri = self.ensure_open(&abs)?;
        let rel = relative_path(&self.repo_root, &abs);
        let pull = self.request_until_hits(
            "textDocument/diagnostic",
            json!({"textDocument": {"uri": uri}}),
        );
        let items: Vec<Value> = match pull {
            Ok(report) => report
                .get("items")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
            Err(_) => {
                // 兜底：使用 didOpen 后收到的 publishDiagnostics 通知。
                self.pump_published();
                self.published
                    .iter()
                    .filter(|n| n.get("uri").and_then(Value::as_str) == Some(uri.as_str()))
                    .filter_map(|n| n.get("diagnostics").and_then(Value::as_array).cloned())
                    .flatten()
                    .collect()
            }
        };
        // 诊断条数不在这里裁剪（CLI 层统一按预算裁剪并标记 truncated）。
        Ok(items
            .into_iter()
            .map(|d| DiagnosticItem {
                path: rel.clone(),
                severity: diagnostic_severity(
                    d.get("severity").and_then(Value::as_i64).unwrap_or(0),
                )
                .to_string(),
                code: d
                    .get("code")
                    .map(|c| match c {
                        Value::String(s) => s.clone(),
                        other => other.to_string(),
                    })
                    .unwrap_or_default(),
                message: d
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                range: d.get("range").and_then(lsp_range_of_ref),
            })
            .collect())
    }

    fn meta(&self) -> &ProviderMeta {
        // duration_ms 反映"会话存活时间"，在返回前无法改写 &self，
        // 由 CLI 层用 started 另算；这里保持结构完整。
        &self.meta
    }

    fn close(&mut self) {
        if let Some(session) = self.session.take() {
            session.shutdown();
        }
    }
}

impl RustAnalyzerProvider {
    /// 把缓冲里的 publishDiagnostics 通知吸进 provider。
    fn pump_published(&mut self) {
        if let Some(session) = self.session.as_mut() {
            while let Some(note) = session.try_notification() {
                if note.get("method").and_then(Value::as_str)
                    == Some("textDocument/publishDiagnostics")
                {
                    if let Some(params) = note.get("params") {
                        if self.published.len() < 64 {
                            self.published.push(params.clone());
                        }
                    }
                }
            }
        }
    }
}

/// `initialize` 参数：只声明只读能力（`applyEdit = false`），并开启
/// workDoneProgress —— 实测 rust-analyzer 1.95 只有在客户端接受进度上报时
/// 才会发送 crate 图加载/索引的 `$/progress` 序列，而那是我们判定"空结果是否
/// 可信"的唯一依据。`initializationOptions` 只保留经过探针验证的
/// `cargo.buildScripts.enable = false`（安全 §14：不借 build script 执行任意代码），
/// 其余未验证的键不塞进去（RA 的 Config 反序列化对未知键并不宽容）。
fn initialize_params(workspace_root: &Path) -> Value {
    let uri = path_to_uri(workspace_root);
    json!({
        "processId": std::process::id(),
        "clientInfo": {"name": "nexus-harness-code-intel", "version": env!("CARGO_PKG_VERSION")},
        "locale": "en",
        "rootPath": workspace_root.to_string_lossy(),
        "rootUri": uri,
        "workspaceFolders": [{"uri": uri, "name": "nexus-code-intel"}],
        "capabilities": {
            "workspace": {
                "workspaceFolders": true,
                "configuration": true,
                "applyEdit": false,
                "didChangeWatchedFiles": {"dynamicRegistration": false},
                "symbol": {"symbolKind": {"valueSet": [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26]}},
            },
            "textDocument": {
                "synchronization": {"dynamicRegistration": false, "didSave": false},
                "hover": {"contentFormat": ["markdown", "plaintext"]},
                "definition": {"linkSupport": true, "dynamicRegistration": false},
                "typeDefinition": {"linkSupport": true, "dynamicRegistration": false},
                "implementation": {"linkSupport": true, "dynamicRegistration": false},
                "references": {"dynamicRegistration": false},
                "documentSymbol": {
                    "dynamicRegistration": false,
                    "hierarchicalDocumentSymbolSupport": true,
                    "symbolKind": {"valueSet": [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26]},
                },
                "callHierarchy": {"dynamicRegistration": false},
                "diagnostic": {"dynamicRegistration": false, "interFileDependencies": false, "relatedDocumentSupport": false},
                "publishDiagnostics": {"relatedInformation": false, "versionSupport": false, "codeDescriptionSupport": false},
            },
            "window": {"workDoneProgress": true},
            "general": {"regularExpressions": {"engine": "ECMAScript"}},
        },
        "initializationOptions": {
            "cargo": {"buildScripts": {"enable": false}},
        },
    })
}

/// 就绪收敛跟踪器。
///
/// rust-analyzer 的 workspace 加载是**多阶段**的：会连续发送多组
/// `$/progress` begin→report→end（实测 1.95：build plan → cargo metadata →
/// Loading root → Indexing std/core → idle）。因此"第一次 end"不代表就绪；
/// 判据是"至少见过一次 end、当前无进行中的 begin、且已静默 `SETTLE`"。
#[derive(Debug)]
struct ReadinessTracker {
    outstanding: usize,
    saw_end: bool,
    saw_begin: bool,
    last_activity: Option<Instant>,
}

/// 空结果重试窗口：didOpen 之后 rust-analyzer 仍需时间做文件级分析，
/// 首个查询返回空不能立即采信。窗口内一律重试；窗口耗尽后再由
/// `readiness()` 决定"空"是可信答案还是 BLOCKED。
const EMPTY_RETRY_WINDOW: Duration = Duration::from_secs(15);

impl ReadinessTracker {
    /// 从"现在"开始计静默窗口：完全不上报进度的 server 也要能被判定。
    fn new() -> ReadinessTracker {
        ReadinessTracker {
            outstanding: 0,
            saw_end: false,
            saw_begin: false,
            last_activity: Some(Instant::now()),
        }
    }

    fn observe(&mut self, note: &Value) {
        self.last_activity = Some(Instant::now());
        let method = note.get("method").and_then(Value::as_str).unwrap_or("");
        if method == "rust-analyzer/status" {
            let text = note
                .get("params")
                .map(|p| {
                    p.as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| p.to_string())
                })
                .unwrap_or_default();
            // 只认 "idle"（settled）。"ready to load" 里也含 "ready"，那是
            // 加载**开始**前的状态，当成收敛会过早采信空结果（实测踩过）。
            if text.contains("idle") {
                self.saw_end = true;
            }
            return;
        }
        if method != "$/progress" {
            return;
        }
        match note
            .pointer("/params/value/kind")
            .and_then(Value::as_str)
            .unwrap_or("")
        {
            "begin" => {
                self.saw_begin = true;
                self.outstanding += 1;
            }
            "end" => {
                self.outstanding = self.outstanding.saturating_sub(1);
                self.saw_end = true;
            }
            _ => {}
        }
    }

    /// 依据当前状态判定就绪程度。`quiet_limit` 用于完全不上报进度的 server。
    fn state(&self, quiet_limit: Duration, settle: Duration) -> Readiness {
        let Some(last) = self.last_activity else {
            return Readiness::Pending;
        };
        let quiet = last.elapsed();
        if self.saw_end && self.outstanding == 0 && quiet >= settle {
            return Readiness::Completed;
        }
        if !self.saw_begin && quiet >= quiet_limit {
            return Readiness::Quiet;
        }
        Readiness::Pending
    }
}

/// 就绪状态：只有"进度全部收敛"或"server 完全不上报进度且静默"时，空结果
/// 才可相信；否则必须显式 BLOCKED 而不是伪 PASS（提案 §12）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Readiness {
    /// 至少一组 progress 收敛且已静默（workspace 加载/索引完成）。
    Completed,
    /// server 从不上报 progress，且静默超过阈值。
    Quiet,
    /// 还没有结论（继续等或重试查询）。
    Pending,
    /// 预算耗尽仍未收敛。
    TimedOut,
}

impl Readiness {
    const fn trustworthy(self) -> bool {
        matches!(self, Self::Completed | Self::Quiet)
    }
}

/// 空结果判定：null / 空数组 / `Report{items:[]}`。
fn is_empty_result(value: &Value) -> bool {
    if value.is_null() {
        return true;
    }
    if let Some(items) = value.as_array() {
        return items.is_empty();
    }
    if let Some(items) = value.get("items").and_then(Value::as_array) {
        return items.is_empty();
    }
    false
}

/// 就绪等待：轮询 notification 直到收敛或超时。
fn wait_until_ready(
    session: &mut LspSession,
    timeout: Duration,
    published: &mut Vec<Value>,
    tracker: &mut ReadinessTracker,
) -> Result<Readiness, Failure> {
    let deadline = Instant::now() + timeout;
    loop {
        if !session.is_alive() {
            return Err(CodeIntelError::ProviderCrashed
                .with_reason("language server 在就绪等待期间退出".to_string()));
        }
        if let Some(note) = session.try_notification() {
            if note.get("method").and_then(Value::as_str) == Some("textDocument/publishDiagnostics")
            {
                if let Some(params) = note.get("params") {
                    if published.len() < 64 {
                        published.push(params.clone());
                    }
                }
            }
            tracker.observe(&note);
        }
        let state = tracker.state(QUIET_FALLBACK, SETTLE);
        if state.trustworthy() {
            return Ok(state);
        }
        if Instant::now() >= deadline {
            return Ok(Readiness::TimedOut);
        }
        std::thread::sleep(POLL_STEP);
    }
}

/// LSP `Range` → 1-based 四元组。
fn lsp_range_of_ref(value: &Value) -> Option<LspRange> {
    let start = value.pointer("/start")?;
    let end = value.pointer("/end")?;
    Some((
        start.get("line")?.as_u64()? as usize + 1,
        start.get("character")?.as_u64()? as usize + 1,
        end.get("line")?.as_u64()? as usize + 1,
        end.get("character")?.as_u64()? as usize + 1,
    ))
}

/// `{uri, range}`（LSP `Location`）。
fn location_pair(value: &Value) -> Option<(String, LspRange)> {
    let uri = value.get("uri")?.as_str()?.to_string();
    let range = value.get("range").and_then(lsp_range_of_ref)?;
    Some((uri, range))
}

/// 把 definition/implementation/references 的各种返回形状归一为站点列表。
///
/// 支持：`null`、`Location`、`Location[]`、`LocationLink`、`LocationLink[]`。
fn sites_from_value(result: &Value, _workspace_root: &Path) -> Vec<ResolvedSite> {
    let mut out: Vec<ResolvedSite> = Vec::new();
    let mut push = |uri: &str, range: LspRange| {
        let abs = PathBuf::from(uri_to_path(uri));
        let site = ResolvedSite {
            abs_path: abs,
            range,
        };
        if !out
            .iter()
            .any(|s: &ResolvedSite| s.abs_path == site.abs_path && s.range == site.range)
        {
            out.push(site);
        }
    };
    match result {
        Value::Null => {}
        Value::Array(items) => {
            for item in items {
                push_one(item, &mut push);
            }
        }
        other => push_one(other, &mut push),
    }
    out.sort_by(|a, b| {
        a.abs_path
            .cmp(&b.abs_path)
            .then_with(|| a.range.cmp(&b.range))
    });
    out
}

fn push_one(value: &Value, push: &mut impl FnMut(&str, LspRange)) {
    // LocationLink: {originSelectionRange, targetSelectionRange, targetRange, targetUri}
    if let (Some(uri), Some(range)) = (
        value.get("targetUri").and_then(Value::as_str),
        value
            .get("targetSelectionRange")
            .and_then(lsp_range_of_ref)
            .or_else(|| value.get("targetRange").and_then(lsp_range_of_ref)),
    ) {
        push(uri, range);
        return;
    }
    if let Some((uri, range)) = location_pair(value) {
        push(&uri, range);
    }
}

/// 递归展开 documentSymbol 结果（层级形状 + 扁平 `SymbolInformation[]` 都支持）。
fn collect_symbols(value: &Value, container: &str, out: &mut Vec<SymbolRecord>) {
    let Some(items) = value.as_array() else {
        return;
    };
    for item in items {
        let name = item
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let kind = item.get("kind").and_then(Value::as_i64).unwrap_or(0) as u8;
        let range = item
            .get("selectionRange")
            .and_then(lsp_range_of_ref)
            .or_else(|| item.get("range").and_then(lsp_range_of_ref))
            .or_else(|| {
                item.get("location")
                    .and_then(|l| l.get("range"))
                    .and_then(lsp_range_of_ref)
            });
        let Some(range) = range else { continue };
        let qualified_container = if container.is_empty() {
            String::new()
        } else {
            container.to_string()
        };
        out.push(SymbolRecord {
            name: name.clone(),
            container: qualified_container.clone(),
            kind,
            range,
        });
        let child_container = if qualified_container.is_empty() {
            name.clone()
        } else {
            format!("{qualified_container}::{name}")
        };
        if let Some(children) = item.get("children") {
            collect_symbols(children, &child_container, out);
        }
    }
}

/// 读取 range 覆盖的源码行（上限 `max_lines`，按行截断）。
fn snippet_of(path: &Path, range: LspRange, max_lines: usize) -> String {
    let Ok(text) = std::fs::read_to_string(path) else {
        return String::new();
    };
    let start = range.0;
    let end = range.2.min(start + max_lines.saturating_sub(1));
    text.lines()
        .enumerate()
        .filter(|(idx, _)| (idx + 1) >= start && (idx + 1) <= end)
        .map(|(_, line)| line.trim_end_matches('\r').to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

/// 按行截断自由文本（预算用，截断显式标注）。
fn cap_lines(text: &str, max_lines: usize) -> String {
    let limit = max_lines.max(1);
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() <= limit {
        return text.to_string();
    }
    let kept = lines[..limit].join("\n");
    format!("{kept}\n…(已按 --max-snippet-lines 截断)")
}

/// hover 的 `contents` 有三种形状：MarkupContent / MarkedString / 数组。
fn hover_text(result: &Value) -> String {
    let contents = result.get("contents").cloned().unwrap_or(Value::Null);
    match &contents {
        Value::String(s) => s.clone(),
        Value::Object(_) => contents
            .get("value")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::String(s) => s.clone(),
                other => other
                    .get("value")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            })
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("\n"),
        Value::Null => String::new(),
        // Bool/Number 不是合法的 hover 形状：按"无内容"处理，不猜。
        _ => String::new(),
    }
}

fn absolute(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_conversion_is_one_based() {
        let range = json!({"start":{"line":6,"character":10},"end":{"line":6,"character":16}});
        assert_eq!(
            lsp_range_of_ref(&range),
            Some((7, 11, 7, 17)),
            "LSP 0-based 必须转成 1-based 输出"
        );
        assert_eq!(lsp_range_of_ref(&json!({"start":{"line":0}})), None);
    }

    #[test]
    fn sites_from_value_handles_every_lsp_shape() {
        let uri = "file:///repo/src/lib.rs";
        let range = json!({"start":{"line":8,"character":7},"end":{"line":8,"character":11}});
        // null -> 空列表（不是 panic、不是伪结果）
        assert!(sites_from_value(&Value::Null, Path::new("/repo")).is_empty());
        // 单个 Location
        let single = json!({"uri": uri, "range": range});
        let got = sites_from_value(&single, Path::new("/repo"));
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].range, (9, 8, 9, 12));
        // Location[]
        let arr = json!([{"uri": uri, "range": range}, {"uri": uri, "range": range}]);
        assert_eq!(
            sites_from_value(&arr, Path::new("/repo")).len(),
            1,
            "重复站点必须去重"
        );
        // LocationLink[]（优先 targetSelectionRange）
        let link = json!([{
            "originSelectionRange": {"start":{"line":0,"character":0},"end":{"line":0,"character":1}},
            "targetUri": uri,
            "targetRange": {"start":{"line":7,"character":0},"end":{"line":9,"character":1}},
            "targetSelectionRange": {"start":{"line":8,"character":7},"end":{"line":8,"character":11}}
        }]);
        let got = sites_from_value(&link, Path::new("/repo"));
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].range, (9, 8, 9, 12));
    }

    #[test]
    fn document_symbol_flatten_walks_children_and_prefixes_container() {
        let value = json!([{
            "name": "Egress",
            "kind": 10,
            "range": {"start":{"line":6,"character":10},"end":{"line":13,"character":1}},
            "selectionRange": {"start":{"line":6,"character":10},"end":{"line":6,"character":16}},
            "children": [{
                "name": "send",
                "kind": 6,
                "range": {"start":{"line":8,"character":4},"end":{"line":8,"character":60}},
                "selectionRange": {"start":{"line":8,"character":7},"end":{"line":8,"character":11}}
            }]
        }]);
        let mut out = Vec::new();
        collect_symbols(&value, "", &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].name, "Egress");
        assert_eq!(out[1].name, "send");
        assert_eq!(out[1].container, "Egress");
        // 扁平 SymbolInformation[] 形状（location.range）也要能展开
        let flat = json!([{"name":"tick","kind":5,"location":{"uri":"file:///a.rs","range":{"start":{"line":1,"character":2},"end":{"line":1,"character":6}}}}]);
        let mut flat_out = Vec::new();
        collect_symbols(&flat, "", &mut flat_out);
        assert_eq!(flat_out.len(), 1);
        assert_eq!(flat_out[0].range, (2, 3, 2, 7));
    }

    #[test]
    fn hover_text_normalizes_all_shapes() {
        assert_eq!(hover_text(&json!({"contents": "plain"})), "plain");
        assert_eq!(
            hover_text(&json!({"contents": {"kind":"markdown","value":"```rust\nfn a()```"}})),
            "```rust\nfn a()```"
        );
        assert_eq!(
            hover_text(&json!({"contents": [{"language":"rust","value":"fn a()"}, "extra"]})),
            "fn a()\nextra"
        );
        assert_eq!(hover_text(&json!({})), "");
    }

    #[test]
    fn initialize_params_advertise_no_write_capability() {
        let params = initialize_params(Path::new("/repo"));
        assert_eq!(
            params["capabilities"]["workspace"]["applyEdit"],
            json!(false)
        );
        assert_eq!(
            params["capabilities"]["window"]["workDoneProgress"],
            json!(true),
            "必须接受 progress 上报，否则空结果无法判定是否已索引完成"
        );
        assert_eq!(
            params["initializationOptions"]["cargo"]["buildScripts"]["enable"],
            json!(false),
            "禁止 language server 借 build script 执行任意代码"
        );
        assert_eq!(params["rootUri"], json!("file:///repo"));
    }

    #[test]
    fn only_converged_readiness_makes_empty_results_trustworthy() {
        assert!(Readiness::Completed.trustworthy());
        assert!(Readiness::Quiet.trustworthy());
        assert!(
            !Readiness::Pending.trustworthy(),
            "还没收敛时的空结果必须不可信"
        );
        assert!(
            !Readiness::TimedOut.trustworthy(),
            "预算耗尽的空结果必须不可信"
        );
    }

    #[test]
    fn empty_result_shape_detection() {
        assert!(is_empty_result(&Value::Null));
        assert!(is_empty_result(&json!([])));
        assert!(is_empty_result(&json!({"kind": "full", "items": []})));
        assert!(!is_empty_result(&json!([{"uri": "file:///a.rs"}])));
        assert!(!is_empty_result(
            &json!({"kind": "full", "items": [{"message": "x"}]})
        ));
        // hover 的非空 contents、以及任意非空对象都算"有结果"。
        assert!(!is_empty_result(&json!({"contents": {"value": "fn a()"}})));
    }

    #[test]
    fn tracker_requires_settled_progress_before_trusting_empties() {
        let mut tracker = ReadinessTracker::new();
        assert_eq!(
            tracker.state(QUIET_FALLBACK, SETTLE),
            Readiness::Pending,
            "刚开始还没有任何活动 -> 未就绪"
        );
        tracker.observe(&json!({"method":"$/progress","params":{"value":{"kind":"begin"}}}));
        assert_eq!(tracker.state(QUIET_FALLBACK, SETTLE), Readiness::Pending);
        // 第一组 end：workspace 加载还有后续阶段，仍是 Pending。
        tracker.observe(&json!({"method":"$/progress","params":{"value":{"kind":"end"}}}));
        assert_eq!(
            tracker.state(QUIET_FALLBACK, SETTLE),
            Readiness::Pending,
            "刚 end 还没静默，不能立即采信空结果"
        );
        // 第二组 begin 未 end -> 不许收敛。
        tracker.observe(&json!({"method":"$/progress","params":{"value":{"kind":"begin"}}}));
        tracker.observe(&json!({"method":"$/progress","params":{"value":{"kind":"end"}}}));
        tracker.observe(&json!({"method":"$/progress","params":{"value":{"kind":"end"}}}));
        assert_eq!(
            tracker.state(QUIET_FALLBACK, SETTLE),
            Readiness::Pending,
            "SETTLE 窗口未到不许判定 Completed"
        );
        std::thread::sleep(SETTLE + Duration::from_millis(200));
        assert_eq!(
            tracker.state(QUIET_FALLBACK, SETTLE),
            Readiness::Completed,
            "静默超过 SETTLE 且无进行中的 begin -> 收敛"
        );
    }

    #[test]
    fn status_idle_marks_convergence() {
        let mut tracker = ReadinessTracker::new();
        tracker.observe(&json!({"method":"rust-analyzer/status","params":"idle"}));
        std::thread::sleep(SETTLE + Duration::from_millis(200));
        assert_eq!(tracker.state(QUIET_FALLBACK, SETTLE), Readiness::Completed);
    }

    #[test]
    fn status_ready_to_load_is_not_convergence() {
        // 实测踩坑：RA 早期状态 "ready to load" 含 "ready"，若当成就绪
        // 会把"尚未分析完"的空结果采信为可信答案。
        let mut tracker = ReadinessTracker::new();
        tracker.observe(&json!({"method":"rust-analyzer/status","params":"ready to load"}));
        std::thread::sleep(SETTLE + Duration::from_millis(200));
        assert_ne!(
            tracker.state(QUIET_FALLBACK, SETTLE),
            Readiness::Completed,
            "\"ready to load\" 不得判定收敛"
        );
    }

    #[test]
    fn snippet_is_line_capped() {
        let dir = std::env::temp_dir().join(format!("harness-snippet-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let file = dir.join("x.rs");
        std::fs::write(
            &file,
            (1..=30).map(|i| format!("line{i}\n")).collect::<String>(),
        )
        .expect("write fixture");
        let snippet = snippet_of(&file, (5, 1, 20, 1), 8);
        let lines: Vec<&str> = snippet.lines().collect();
        assert_eq!(lines.len(), 8, "超过 max_snippet_lines 必须截断");
        assert_eq!(lines[0], "line5");
        std::fs::remove_dir_all(&dir).ok();
    }
}

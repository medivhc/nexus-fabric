//! nexusd crash recovery（v9 §15.2 / §15.3）：Session + Connectivity 的 durable marker 与开机 reconcile。
//!
//! 范围（已拍板）：只覆盖 Session + Connectivity。Workspace / Compute 的恢复是 Phase 2/3，
//! 不许扩到本模块。
//!
//! 机制（已拍板）：Durable Marker（轻量）优先；Journal 不需要——所有写都是单文件
//! 原子替换（temp + fsync + rename），reconcile 幂等；crash 发生在 reconcile 中间时
//! 下次启动重跑即可，不存在"写一半丢用户可见状态"的多步事务。
//!
//! 诚实语义：
//! - session 记录只保留分类（phase/outcome 判别）+ 失败原因字符串；完整类型化
//!   `NexusError` 不进 durable 记录（load 时 `Failed` 重建为 `Internal{message}`）。
//!   reconcile 只需要分类信息，这是有意的设计，不是疏漏。
//! - link marker 的 stale 不是"恢复连接"：进程死亡 = socket 死亡，reconcile 把
//!   未 stale 的 marker 标为 stale（触发重建），不许假装链路还活着。
//! - 不能恢复的一律明确标记（孤儿 session → `Failed`），不许静默丢状态。
//!
//! 文件布局（`<config-dir>/state/`；watcher 只盯 4 个固定配置文件，不受影响）：
//! ```text
//! state/
//! ├── sessions.json   # [SessionRecord]（durable session marker）
//! ├── links.json      # [LinkMarker]（durable link marker）
//! └── run.marker      # {"pid":..,"started_at_unix":..}（存在 = 上次未干净退出）
//! ```

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use nexus_connectivity::{
    LinkKind, LinkMarker, LinkMarkerStore, LinkReconcileReport, reconcile_link_markers,
};
use nexus_domain::{LifecyclePhase, NexusError, SessionId, TerminalOutcome};
use nexus_session::{
    SessionReconcileReport, SessionRecord, SessionRecordStore, reconcile_session_records,
};
use serde_json::{Value, json};

/// state 目录名（config dir 下）。
pub const STATE_DIR_NAME: &str = "state";
const SESSIONS_FILE: &str = "sessions.json";
const LINKS_FILE: &str = "links.json";
const RUN_MARKER_FILE: &str = "run.marker";

/// 由 config dir 导出 state dir。
#[must_use]
pub fn state_dir(config_root: &Path) -> PathBuf {
    config_root.join(STATE_DIR_NAME)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 原子写文件：temp + write + fsync + rename（同目录，保证原子替换）。
fn atomic_write(path: &Path, data: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    let mut f = fs::File::create(&tmp).map_err(|e| format!("create tmp {}: {e}", tmp.display()))?;
    f.write_all(data)
        .map_err(|e| format!("write tmp {}: {e}", tmp.display()))?;
    f.sync_all()
        .map_err(|e| format!("fsync tmp {}: {e}", tmp.display()))?;
    drop(f);
    fs::rename(&tmp, path)
        .map_err(|e| format!("rename {} -> {}: {e}", tmp.display(), path.display()))
}

// ---------- SessionRecord / LinkMarker 的 JSON 编解码（durable 格式 v1） ----------

fn phase_to_str(p: &LifecyclePhase) -> &'static str {
    match p {
        LifecyclePhase::Allocating => "Allocating",
        LifecyclePhase::Active => "Active",
        LifecyclePhase::Draining => "Draining",
        LifecyclePhase::Disposed => "Disposed",
    }
}

fn parse_phase(s: &str) -> Result<LifecyclePhase, String> {
    match s {
        "Allocating" => Ok(LifecyclePhase::Allocating),
        "Active" => Ok(LifecyclePhase::Active),
        "Draining" => Ok(LifecyclePhase::Draining),
        "Disposed" => Ok(LifecyclePhase::Disposed),
        other => Err(format!("unknown phase: {other}")),
    }
}

/// outcome 判别 + 原因。durable 保真度契约：`Failed` 只保留原因字符串，
/// load 时重建为 `Internal{message}`（分类信息无损，类型细节不保留）。
fn outcome_to_json(o: &TerminalOutcome) -> (String, Option<String>) {
    match o {
        TerminalOutcome::Unfinished => ("Unfinished".into(), None),
        TerminalOutcome::Completed => ("Completed".into(), None),
        TerminalOutcome::Failed(e) => ("Failed".into(), Some(format!("{e:?}"))),
        TerminalOutcome::Cancelled => ("Cancelled".into(), None),
    }
}

fn parse_outcome(s: &str, reason: Option<&str>) -> Result<TerminalOutcome, String> {
    match s {
        "Unfinished" => Ok(TerminalOutcome::Unfinished),
        "Completed" => Ok(TerminalOutcome::Completed),
        "Failed" => Ok(TerminalOutcome::Failed(NexusError::Internal {
            message: reason.unwrap_or("unknown").to_string(),
        })),
        "Cancelled" => Ok(TerminalOutcome::Cancelled),
        other => Err(format!("unknown outcome: {other}")),
    }
}

fn encode_sessions(records: &[SessionRecord]) -> Value {
    Value::Array(
        records
            .iter()
            .map(|r| {
                let (outcome, reason) = outcome_to_json(&r.outcome);
                let mut obj = serde_json::Map::new();
                obj.insert("session".into(), Value::String(r.session.0.clone()));
                obj.insert("phase".into(), Value::String(phase_to_str(&r.phase).into()));
                obj.insert("outcome".into(), Value::String(outcome));
                if let Some(reason) = reason {
                    obj.insert("reason".into(), Value::String(reason));
                }
                Value::Object(obj)
            })
            .collect(),
    )
}

fn decode_sessions(v: &Value) -> Result<Vec<SessionRecord>, String> {
    let arr = v
        .as_array()
        .ok_or_else(|| "sessions.json: top level must be an array".to_string())?;
    arr.iter()
        .map(|item| {
            let session = item.get("session").and_then(Value::as_str).ok_or_else(|| {
                "sessions.json: record missing string field 'session'".to_string()
            })?;
            let phase = item
                .get("phase")
                .and_then(Value::as_str)
                .ok_or_else(|| "sessions.json: record missing string field 'phase'".to_string())?;
            let outcome = item.get("outcome").and_then(Value::as_str).ok_or_else(|| {
                "sessions.json: record missing string field 'outcome'".to_string()
            })?;
            let reason = item.get("reason").and_then(Value::as_str);
            Ok(SessionRecord {
                session: SessionId(session.to_string()),
                phase: parse_phase(phase)?,
                outcome: parse_outcome(outcome, reason)?,
                // N2 P0-3：sessions.json 暂无 plan_snapshot 字段（P0-4 SessionManager
                // 落地后写入）；旧记录按 None 读入，不伪造。
                plan_snapshot: None,
            })
        })
        .collect()
}

fn link_kind_to_str(k: &LinkKind) -> &'static str {
    match k {
        LinkKind::Direct => "direct",
        LinkKind::Relay => "relay",
    }
}

fn parse_link_kind(s: &str) -> Result<LinkKind, String> {
    match s {
        "direct" => Ok(LinkKind::Direct),
        "relay" => Ok(LinkKind::Relay),
        other => Err(format!("unknown link kind: {other}")),
    }
}

fn encode_links(markers: &[LinkMarker]) -> Value {
    Value::Array(
        markers
            .iter()
            .map(|m| {
                json!({
                    "link_id": m.link_id,
                    "kind": link_kind_to_str(&m.kind),
                    "locator": m.locator,
                    "established_at_unix": m.established_at_unix,
                    "stale": m.stale,
                })
            })
            .collect(),
    )
}

fn decode_links(v: &Value) -> Result<Vec<LinkMarker>, String> {
    let arr = v
        .as_array()
        .ok_or_else(|| "links.json: top level must be an array".to_string())?;
    arr.iter()
        .map(|item| {
            let link_id = item
                .get("link_id")
                .and_then(Value::as_str)
                .ok_or_else(|| "links.json: marker missing string field 'link_id'".to_string())?;
            let kind = item
                .get("kind")
                .and_then(Value::as_str)
                .ok_or_else(|| "links.json: marker missing string field 'kind'".to_string())?;
            let locator = item
                .get("locator")
                .and_then(Value::as_str)
                .ok_or_else(|| "links.json: marker missing string field 'locator'".to_string())?;
            let established_at_unix = item
                .get("established_at_unix")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    "links.json: marker missing u64 field 'established_at_unix'".to_string()
                })?;
            let stale = item.get("stale").and_then(Value::as_bool).unwrap_or(false);
            Ok(LinkMarker {
                link_id: link_id.to_string(),
                kind: parse_link_kind(kind)?,
                locator: locator.to_string(),
                established_at_unix,
                stale,
            })
        })
        .collect()
}

// ---------- 文件存储实现（Composition Root 注入） ----------

/// 基于文件的 `SessionRecordStore`（`sessions.json`，原子替换写）。
pub struct FileSessionRecordStore {
    path: PathBuf,
}

impl FileSessionRecordStore {
    /// `state_dir` 下的 `sessions.json`。
    #[must_use]
    pub fn new(state_dir: &Path) -> Self {
        Self {
            path: state_dir.join(SESSIONS_FILE),
        }
    }
}

impl SessionRecordStore for FileSessionRecordStore {
    fn load(&self) -> Result<Vec<SessionRecord>, String> {
        match fs::read_to_string(&self.path) {
            Ok(text) => {
                let v: Value = serde_json::from_str(&text)
                    .map_err(|e| format!("parse {}: {e}", self.path.display()))?;
                decode_sessions(&v)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(format!("read {}: {e}", self.path.display())),
        }
    }

    fn save(&mut self, record: &SessionRecord) -> Result<(), String> {
        // load 失败（损坏）时不静默覆盖取证现场：直接报错，由调用方决定。
        let mut records = self.load()?;
        if let Some(slot) = records.iter_mut().find(|r| r.session == record.session) {
            *slot = record.clone();
        } else {
            records.push(record.clone());
        }
        let data = serde_json::to_string(&encode_sessions(&records))
            .map_err(|e| format!("encode sessions: {e}"))?;
        atomic_write(&self.path, data.as_bytes())
    }
}

/// 基于文件的 `LinkMarkerStore`（`links.json`，原子替换写）。
pub struct FileLinkMarkerStore {
    path: PathBuf,
}

impl FileLinkMarkerStore {
    /// `state_dir` 下的 `links.json`。
    #[must_use]
    pub fn new(state_dir: &Path) -> Self {
        Self {
            path: state_dir.join(LINKS_FILE),
        }
    }
}

impl LinkMarkerStore for FileLinkMarkerStore {
    fn load(&self) -> Result<Vec<LinkMarker>, String> {
        match fs::read_to_string(&self.path) {
            Ok(text) => {
                let v: Value = serde_json::from_str(&text)
                    .map_err(|e| format!("parse {}: {e}", self.path.display()))?;
                decode_links(&v)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(format!("read {}: {e}", self.path.display())),
        }
    }

    fn save(&mut self, marker: &LinkMarker) -> Result<(), String> {
        let mut markers = self.load()?;
        if let Some(slot) = markers.iter_mut().find(|m| m.link_id == marker.link_id) {
            *slot = marker.clone();
        } else {
            markers.push(marker.clone());
        }
        let data = serde_json::to_string(&encode_links(&markers))
            .map_err(|e| format!("encode links: {e}"))?;
        atomic_write(&self.path, data.as_bytes())
    }
}

// ---------- Run marker（上次是否干净退出） ----------

fn run_marker_path(state_dir: &Path) -> PathBuf {
    state_dir.join(RUN_MARKER_FILE)
}

/// 上次运行是否未干净退出（run marker 残留）。
#[must_use]
pub fn previous_crashed(state_dir: &Path) -> bool {
    run_marker_path(state_dir).exists()
}

/// 写入本次运行的 run marker（boot reconcile 成功后调用）。
pub fn write_run_marker(state_dir: &Path) -> Result<(), String> {
    let data = json!({
        "pid": std::process::id(),
        "started_at_unix": now_unix(),
    });
    let text = serde_json::to_string(&data).map_err(|e| format!("encode run marker: {e}"))?;
    atomic_write(&run_marker_path(state_dir), text.as_bytes())
}

/// 清除 run marker（干净关闭时调用；不存在视为成功，幂等）。
pub fn clear_run_marker(state_dir: &Path) -> Result<(), String> {
    match fs::remove_file(run_marker_path(state_dir)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("remove run marker: {e}")),
    }
}

// ---------- 开机 reconcile ----------

/// 开机 reconcile 的结构化报告（JSON 可观测）。
#[derive(Debug, Clone, Default)]
pub struct BootReconcileReport {
    /// 上次是否未干净退出。
    pub crashed_before: bool,
    /// 检查的 session 记录数。
    pub sessions_checked: usize,
    /// 被分类为孤儿并提交 Failed 的 session 数。
    pub orphans_classified: usize,
    /// 检查的 link marker 数。
    pub links_checked: usize,
    /// 被标为 stale 的 link marker 数。
    pub links_staled: usize,
    /// 是否隔离了损坏的存储文件（取证保留，不静默丢弃）。
    pub store_corrupt_quarantined: bool,
    /// F1：清理掉的 orphan FUSE 挂载点（Linux；workspace.toml 配置的
    /// mountpoint 中 kill -9 后残留在内核的挂载）。加法字段。
    pub orphan_mounts_cleaned: Vec<String>,
    /// reconcile 中遇到的非致命错误（boot 不因此中断，如实上报）。
    pub errors: Vec<String>,
}

impl BootReconcileReport {
    /// 机器可读 JSON（nexusd 启动时打印一行）。
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "event": "boot-reconcile",
            "crashed_before": self.crashed_before,
            "sessions_checked": self.sessions_checked,
            "orphans_classified": self.orphans_classified,
            "links_checked": self.links_checked,
            "links_staled": self.links_staled,
            "store_corrupt_quarantined": self.store_corrupt_quarantined,
            "orphan_mounts_cleaned": self.orphan_mounts_cleaned,
            "errors": self.errors,
        })
    }
}

/// 损坏文件隔离：重命名为 `<name>.corrupt-<unix_ts>`，保留取证，不静默丢弃。
fn quarantine_corrupt(state_dir: &Path, file: &str) -> Result<bool, String> {
    let path = state_dir.join(file);
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(format!("read {}: {e}", path.display())),
    };
    let sessions_ok = file != SESSIONS_FILE
        || serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|v| decode_sessions(&v).ok())
            .is_some();
    let links_ok = file != LINKS_FILE
        || serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|v| decode_links(&v).ok())
            .is_some();
    if sessions_ok && links_ok {
        return Ok(false);
    }
    let dst = state_dir.join(format!("{file}.corrupt-{}", now_unix()));
    fs::rename(&path, &dst).map_err(|e| format!("quarantine {}: {e}", path.display()))?;
    Ok(true)
}

/// orphan FUSE 挂载清理（F1；仅 Linux）：对 workspace.toml 配置的挂载点做
/// 幂等 `fusermount -u` 清理（busy 则 lazy）。
///
/// 幂等：未挂载的路径直接跳过，不报错；清理后仍挂载的记入 errors。
/// 返回 `(实际清理掉的挂载点, 错误)`，调用方记入 reconcile 报告。
#[cfg(target_os = "linux")]
fn reconcile_orphan_mounts(mountpoints: &[PathBuf]) -> (Vec<String>, Vec<String>) {
    use nexus_platform_linux::fuse_ws::{cleanup_orphan_mount, is_mounted};
    let mut cleaned = Vec::new();
    let mut errors = Vec::new();
    for mp in mountpoints {
        if !is_mounted(mp) {
            continue;
        }
        cleanup_orphan_mount(mp);
        if is_mounted(mp) {
            errors.push(format!(
                "orphan mount still mounted after cleanup: {}",
                mp.display()
            ));
        } else {
            cleaned.push(mp.to_string_lossy().into_owned());
        }
    }
    (cleaned, errors)
}

/// 冷启动 reconcile（v9 §15.3，幂等）：
///
/// ```text
/// 建 state dir → 读 run marker（上次是否 crash）
///   → 隔离损坏文件（取证保留） → reconcile session 记录（孤儿 → Failed）
///   → reconcile link marker（未 stale → stale）
///   → 清理 orphan FUSE 挂载（F1；仅 Linux，workspace.toml 的 mountpoint）
///   → 写新的 run marker
/// ```
///
/// `orphan_mountpoints`：workspace.toml 解析出的挂载点（`WorkspaceManager::`
/// `resolve_mountpoints`）；非 Linux 传空即可（清理步骤仅 Linux 编译）。
///
/// 不 panic：存储错误记入报告 `errors`，boot 继续（daemon 不因 reconcile 失败而拒绝启动；
/// 孤儿分类失败的记录下次启动会再次尝试——幂等）。
#[must_use]
#[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
pub fn boot_reconcile(state_dir: &Path, orphan_mountpoints: &[PathBuf]) -> BootReconcileReport {
    let mut report = BootReconcileReport::default();

    if let Err(e) = fs::create_dir_all(state_dir) {
        report
            .errors
            .push(format!("create state dir {}: {e}", state_dir.display()));
        return report;
    }

    report.crashed_before = previous_crashed(state_dir);

    for file in [SESSIONS_FILE, LINKS_FILE] {
        match quarantine_corrupt(state_dir, file) {
            Ok(true) => report.store_corrupt_quarantined = true,
            Ok(false) => {}
            Err(e) => report.errors.push(e),
        }
    }

    let mut sess_store = FileSessionRecordStore::new(state_dir);
    match reconcile_session_records(&mut sess_store, false) {
        Ok(SessionReconcileReport {
            records_checked,
            orphans_classified,
        }) => {
            report.sessions_checked = records_checked;
            report.orphans_classified = orphans_classified;
        }
        Err(e) => report.errors.push(format!("session reconcile: {e}")),
    }

    let mut link_store = FileLinkMarkerStore::new(state_dir);
    match reconcile_link_markers(&mut link_store) {
        Ok(LinkReconcileReport {
            markers_checked,
            marked_stale,
        }) => {
            report.links_checked = markers_checked;
            report.links_staled = marked_stale;
        }
        Err(e) => report.errors.push(format!("link reconcile: {e}")),
    }

    // F1：orphan OS resources——清理残留的 FUSE 挂载（仅 Linux 编译）。
    // WorkspaceManager::start 里保留了同样的幂等清理作兜底（自保护）；
    // 双重清理无害（未挂载时直接返回）。
    #[cfg(target_os = "linux")]
    {
        let (cleaned, errors) = reconcile_orphan_mounts(orphan_mountpoints);
        report.orphan_mounts_cleaned = cleaned;
        report.errors.extend(errors);
    }

    if let Err(e) = write_run_marker(state_dir) {
        report.errors.push(format!("write run marker: {e}"));
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_domain::LifecyclePhase;

    fn temp_state_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "nexusd-recovery-test-{}-{}",
            tag,
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn active_unfinished(id: &str) -> SessionRecord {
        SessionRecord {
            session: SessionId(id.to_string()),
            phase: LifecyclePhase::Active,
            outcome: TerminalOutcome::Unfinished,
            plan_snapshot: None,
        }
    }

    #[test]
    fn session_store_roundtrip() {
        let dir = temp_state_dir("sess-rt");
        let mut store = FileSessionRecordStore::new(&dir);
        assert_eq!(store.load().unwrap(), vec![]);
        store.save(&active_unfinished("s-1")).unwrap();
        store
            .save(&SessionRecord {
                session: SessionId("s-2".into()),
                phase: LifecyclePhase::Disposed,
                outcome: TerminalOutcome::Completed,
                plan_snapshot: None,
            })
            .unwrap();
        // upsert 同 id
        store
            .save(&SessionRecord {
                session: SessionId("s-1".into()),
                phase: LifecyclePhase::Disposed,
                outcome: TerminalOutcome::Cancelled,
                plan_snapshot: None,
            })
            .unwrap();
        let records = store.load().unwrap();
        assert_eq!(records.len(), 2);
        let s1 = records.iter().find(|r| r.session.0 == "s-1").unwrap();
        assert_eq!(s1.phase, LifecyclePhase::Disposed);
        assert_eq!(s1.outcome, TerminalOutcome::Cancelled);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn session_store_failed_reason_roundtrip() {
        let dir = temp_state_dir("sess-fail");
        let mut store = FileSessionRecordStore::new(&dir);
        store
            .save(&SessionRecord {
                session: SessionId("s-f".into()),
                phase: LifecyclePhase::Active,
                outcome: TerminalOutcome::Failed(NexusError::SessionFailed {
                    session: SessionId("s-f".into()),
                    reason: "boom".into(),
                }),
                plan_snapshot: None,
            })
            .unwrap();
        let records = store.load().unwrap();
        // 保真度契约：分类 + 原因字符串保留，类型重建为 Internal。
        assert!(matches!(
            &records[0].outcome,
            TerminalOutcome::Failed(NexusError::Internal { message })
            if message.contains("boom")
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn session_store_corrupt_load_fails_loudly() {
        let dir = temp_state_dir("sess-corrupt");
        fs::write(dir.join(SESSIONS_FILE), "{not json").unwrap();
        let store = FileSessionRecordStore::new(&dir);
        assert!(store.load().is_err());
        // save 不静默覆盖损坏现场
        let mut store = store;
        assert!(store.save(&active_unfinished("s-x")).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn link_store_roundtrip_and_upsert() {
        let dir = temp_state_dir("link-rt");
        let mut store = FileLinkMarkerStore::new(&dir);
        store
            .save(&LinkMarker::established(
                "direct/p1",
                LinkKind::Direct,
                "10.0.0.1:1",
                100,
            ))
            .unwrap();
        let mut stale = LinkMarker::established("direct/p1", LinkKind::Direct, "10.0.0.1:1", 100);
        stale.stale = true;
        store.save(&stale).unwrap();
        let markers = store.load().unwrap();
        assert_eq!(markers.len(), 1);
        assert!(markers[0].stale);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn boot_reconcile_classifies_orphan_and_stales_link() {
        let dir = temp_state_dir("boot-1");
        let state = state_dir(&dir);
        fs::create_dir_all(&state).unwrap();
        // 模拟 crash 前的状态：未终态 session + 已建立 link + run marker 残留
        let mut sess = FileSessionRecordStore::new(&state);
        sess.save(&active_unfinished("s-orphan")).unwrap();
        let mut links = FileLinkMarkerStore::new(&state);
        links
            .save(&LinkMarker::established(
                "direct/p9",
                LinkKind::Direct,
                "10.9.9.9:9",
                200,
            ))
            .unwrap();
        write_run_marker(&state).unwrap();

        let report = boot_reconcile(&state, &[]);
        assert!(report.crashed_before);
        assert_eq!(report.orphans_classified, 1);
        assert_eq!(report.links_staled, 1);
        assert!(report.errors.is_empty());

        // 孤儿被恰一次提交 Failed 并清理到 Disposed
        let records = sess.load().unwrap();
        assert!(matches!(records[0].outcome, TerminalOutcome::Failed(_)));
        assert_eq!(records[0].phase, LifecyclePhase::Disposed);
        // link 被标 stale
        assert!(links.load().unwrap()[0].stale);

        // 幂等：第二次 reconcile 不再重复分类
        let report2 = boot_reconcile(&state, &[]);
        assert_eq!(report2.orphans_classified, 0);
        assert_eq!(report2.links_staled, 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn boot_reconcile_quarantines_corrupt_files() {
        let dir = temp_state_dir("boot-corrupt");
        let state = state_dir(&dir);
        fs::create_dir_all(&state).unwrap();
        fs::write(state.join(SESSIONS_FILE), "garbage{{{").unwrap();

        let report = boot_reconcile(&state, &[]);
        assert!(report.store_corrupt_quarantined);
        // 隔离文件保留取证
        let quarantined: Vec<_> = fs::read_dir(&state)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("sessions.json.corrupt-"))
            .collect();
        assert_eq!(quarantined.len(), 1);
        // boot 继续，不中断
        assert!(report.errors.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn boot_reconcile_orphan_mount_noop_when_not_mounted() {
        // F1 幂等：未挂载的路径清理不得让 boot 失败；报告保持空。
        let dir = temp_state_dir("boot-orphan-noop");
        let state = state_dir(&dir);
        fs::create_dir_all(&state).unwrap();
        let bogus = dir.join("definitely-not-a-mountpoint");
        let report = boot_reconcile(&state, std::slice::from_ref(&bogus));
        assert!(report.orphan_mounts_cleaned.is_empty());
        assert!(report.errors.is_empty());
        // 二次启动零清理（幂等）。
        let report2 = boot_reconcile(&state, std::slice::from_ref(&bogus));
        assert!(report2.orphan_mounts_cleaned.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn boot_reconcile_report_json_has_orphan_mounts_cleaned() {
        // 报告 JSON 加法字段：默认空数组，老字段语义不变。
        let report = BootReconcileReport::default();
        let v = report.to_json();
        assert_eq!(v["event"], "boot-reconcile");
        assert!(v["orphan_mounts_cleaned"].is_array());
        assert_eq!(v["orphan_mounts_cleaned"].as_array().unwrap().len(), 0);
        // 老字段仍在。
        assert!(v.get("orphans_classified").is_some());
        assert!(v.get("links_staled").is_some());
        assert!(v.get("crashed_before").is_some());
    }

    #[test]
    fn run_marker_lifecycle() {
        let dir = temp_state_dir("run-marker");
        let state = state_dir(&dir);
        fs::create_dir_all(&state).unwrap();
        assert!(!previous_crashed(&state));
        write_run_marker(&state).unwrap();
        assert!(previous_crashed(&state));
        clear_run_marker(&state).unwrap();
        assert!(!previous_crashed(&state));
        // 幂等：重复清除不报错
        clear_run_marker(&state).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }
}

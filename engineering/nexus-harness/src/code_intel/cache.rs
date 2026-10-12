//! digest 键控的结果缓存（MODULE.md「Provider Daemon & Result Cache」结果层）。
//!
//! 口径（都是契约里的句子，不是实现自选）：
//! - 键 = `(working_tree_digest, workspace 根, verb, target, provider 版本, 预算)`，
//!   六元组全等才允许命中；
//! - 载荷 = 查询结果本体（`results`/`count`/`budget`/`continuation`）加四个"记事实"的
//!   provider 字段（`kind`/`binary`/`version`/`ready`）。**本次运行才有的成本与计数**
//!   （`duration_ms`、`session_*`、三个 refusal 计数、`snapshot.*`、`daemon.*`、`cache.*`）
//!   不进条目，由调用方按当次生成；
//! - 只有 `verdict=="PASS"` 且 `provider.ready==true` 的结果入缓存（门在调用方）；
//! - 有界：每 workspace 命名空间 512 条 / 8 MiB，超限**不写入**且计数可见。
//!
//! 文件名里的摘要用本地 FNV-1a，不经 `git hash-object`：那个 helper 属于 `Repo`，
//! 而缓存查找发生在仓库发现之后、不一定带 `Repo` 的调用点上；更关键的是**对外契约字段是
//! `cache.key_digest` = 键里的工作树指纹本身**，文件名只是实现细节，不该为它多起一个进程。

use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};

/// 每个 workspace 命名空间的条目上限（契约数值）。
pub const MAX_ENTRIES: usize = 512;
/// 每个 workspace 命名空间的累计字节上限（契约数值）。
pub const MAX_TOTAL_BYTES: u64 = 8 * 1024 * 1024;

/// 64 位 FNV-1a（`daemon`/`cache` 命名空间与条目文件名用；不是对外摘要）。
pub fn fnv1a_hex(data: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in data.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// 缓存键的六个组成部分，逐名对应契约句子。缺任何一个都可能让两个不同事实共用一条目。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheKey {
    pub digest: String,
    pub workspace: String,
    pub verb: String,
    pub target: String,
    pub provider_version: String,
    pub budget: String,
}

impl CacheKey {
    /// 规范化成一行：键的相等性只取决于这六个量，不受路径分隔符写法影响。
    fn canonical(&self) -> String {
        [
            self.digest.as_str(),
            &self.workspace.replace('\\', "/"),
            self.verb.as_str(),
            self.target.as_str(),
            self.provider_version.as_str(),
            self.budget.as_str(),
        ]
        .join("\u{1f}")
    }

    fn file_stem(&self) -> String {
        fnv1a_hex(&self.canonical())
    }

    fn file_name(&self) -> String {
        format!("{}.json", self.file_stem())
    }
}

/// 命中后回放的内容。`digest` 是条目键里的工作树指纹，调用方把它原样报成
/// `cache.key_digest`，使"命中依据哪个指纹"在输出里可比对。
#[derive(Debug, Clone, PartialEq)]
pub struct Hit {
    pub digest: String,
    pub results: Vec<Value>,
    pub count: usize,
    pub budget: Value,
    pub provider: Value,
    pub continuation: Option<Value>,
}

/// 写缓存的结果。`stored=false` 必须带原因且计数照旧可见，否则"没写进去"与
/// "写了但下次没命中"在输出里长得一样。
#[derive(Debug, Clone, PartialEq)]
pub struct StoreReport {
    pub stored: bool,
    pub reason: &'static str,
    pub entries: usize,
    pub bytes: u64,
}

/// 构造条目载荷。刻意只接受这五个量：多一个字段就多一条"过期事实被回放"的路径。
pub fn build_payload(
    results: &[Value],
    count: usize,
    budget: &Value,
    provider: &Value,
    continuation: Option<&Value>,
) -> Value {
    let facts = json!({
        "kind": provider.get("kind").cloned().unwrap_or(Value::Null),
        "binary": provider.get("binary").cloned().unwrap_or(Value::Null),
        "version": provider.get("version").cloned().unwrap_or(Value::Null),
        "ready": provider.get("ready").cloned().unwrap_or(Value::Null),
    });
    let mut obj = serde_json::Map::new();
    obj.insert("results".to_string(), json!(results));
    obj.insert("count".to_string(), json!(count));
    obj.insert("budget".to_string(), budget.clone());
    obj.insert("provider".to_string(), facts);
    if let Some(c) = continuation {
        obj.insert("continuation".to_string(), c.clone());
    }
    Value::Object(obj)
}

pub fn lookup(dir: &Path, key: &CacheKey) -> Option<Hit> {
    let text = fs::read_to_string(dir.join(key.file_name())).ok()?;
    let value: Value = serde_json::from_str(&text).ok()?;
    let obj = value.as_object()?;
    // 条目里存一份键的各分量是为了自检：任何一项与本次不符就按 miss 处理，
    // 绝不"大方向一致就算命中"——那正是拿旧指纹冒充新事实的形状。
    let stored_key = obj.get("key")?.as_object()?;
    let matches = stored_key.get("digest").and_then(Value::as_str) == Some(key.digest.as_str())
        && stored_key.get("workspace").and_then(Value::as_str)
            == Some(&key.workspace.replace('\\', "/"))
        && stored_key.get("verb").and_then(Value::as_str) == Some(key.verb.as_str())
        && stored_key.get("target").and_then(Value::as_str) == Some(key.target.as_str())
        && stored_key.get("provider_version").and_then(Value::as_str)
            == Some(key.provider_version.as_str())
        && stored_key.get("budget").and_then(Value::as_str) == Some(key.budget.as_str());
    if !matches {
        return None;
    }
    Some(Hit {
        digest: key.digest.clone(),
        results: obj.get("results")?.as_array()?.clone(),
        count: obj.get("count")?.as_u64()? as usize,
        budget: obj.get("budget")?.clone(),
        provider: obj.get("provider")?.clone(),
        continuation: obj.get("continuation").filter(|v| !v.is_null()).cloned(),
    })
}

pub fn store(dir: &Path, key: &CacheKey, payload: &Value) -> StoreReport {
    let (entries, bytes) = stats(dir);
    let mut envelope = match payload.as_object().cloned() {
        Some(o) => o,
        None => return report(false, "payload_not_object", entries, bytes),
    };
    let mut stored_key = serde_json::Map::new();
    stored_key.insert("digest".to_string(), json!(key.digest));
    stored_key.insert(
        "workspace".to_string(),
        json!(key.workspace.replace('\\', "/")),
    );
    stored_key.insert("verb".to_string(), json!(key.verb));
    stored_key.insert("target".to_string(), json!(key.target));
    stored_key.insert("provider_version".to_string(), json!(key.provider_version));
    stored_key.insert("budget".to_string(), json!(key.budget));
    envelope.insert("key".to_string(), Value::Object(stored_key));

    let body = match serde_json::to_vec(&Value::Object(envelope)) {
        Ok(b) => b,
        Err(_) => return report(false, "encode_failed", entries, bytes),
    };
    if entries + 1 > MAX_ENTRIES {
        return report(false, "entry_cap", entries, bytes);
    }
    if bytes.saturating_add(body.len() as u64) > MAX_TOTAL_BYTES {
        return report(false, "byte_cap", entries, bytes);
    }
    if fs::create_dir_all(dir).is_err() {
        return report(false, "mkdir_failed", entries, bytes);
    }
    let tmp = dir.join(format!(".{}.tmp", key.file_stem()));
    let final_path = dir.join(key.file_name());
    // 先写临时名再 rename：否则并发读写可能读到半截 JSON（表现为 miss，是性能问题；
    // 表现为"命中了半个结果"才是正确性问题）。
    let written = fs::write(&tmp, &body).and_then(|()| fs::rename(&tmp, &final_path));
    if let Err(_e) = written {
        let _ = fs::remove_file(&tmp);
        return report(false, "write_failed", entries, bytes);
    }
    let (n, b) = stats(dir);
    report(true, "stored", n, b)
}

fn report(stored: bool, reason: &'static str, entries: usize, bytes: u64) -> StoreReport {
    StoreReport {
        stored,
        reason,
        entries,
        bytes,
    }
}

/// 目录里的条目数与累计字节。上限判定与对外 `cache.entries`/`cache.bytes` 走同一个函数，
/// 避免"按 A 判定、报 B 数字"。
pub fn stats(dir: &Path) -> (usize, u64) {
    let Ok(read) = fs::read_dir(dir) else {
        return (0, 0);
    };
    let mut n = 0usize;
    let mut b = 0u64;
    for entry in read.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".json") || name.starts_with('.') {
            continue;
        }
        n += 1;
        b += entry.metadata().map(|m| m.len()).unwrap_or(0);
    }
    (n, b)
}

/// `stop` / idle 退出时清掉整个缓存目录（契约：缓存文件必须随生命周期结束被删除）。
pub fn purge(dir: &Path) {
    let _ = fs::remove_dir_all(dir);
}

pub fn cache_dir_for(namespace: &Path) -> PathBuf {
    namespace.join("cache")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(digest: &str) -> CacheKey {
        CacheKey {
            digest: digest.to_string(),
            workspace: "engineering/nexus-harness/fixtures/code-intel".to_string(),
            verb: "symbol".to_string(),
            target: "Egress".to_string(),
            provider_version: "rust-analyzer 1.98.1".to_string(),
            budget: "20/8/65536".to_string(),
        }
    }

    fn payload() -> Value {
        build_payload(
            &[json!({"symbol": "Egress"})],
            1,
            &json!({"max_results": 20, "truncated": false}),
            &json!({"kind": "rust-analyzer", "binary": "ra", "version": "1.98.1", "ready": true}),
            None,
        )
    }

    fn scratch(tag: &str) -> PathBuf {
        let suffix = fnv1a_hex(tag);
        let dir = std::env::temp_dir().join(format!(
            "nexus-cache-test-{tag}-{}-{}",
            std::process::id(),
            suffix.get(8..).unwrap_or("0")
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    /// 契约「点名单测」之一：不同 working_tree_digest 必须 miss，绝不能拿旧指纹的结果冒充。
    #[test]
    fn cache_key_misses_when_digest_differs() {
        let dir = scratch("digest");
        assert!(store(&dir, &key("aaaa"), &payload()).stored);
        let hit = lookup(&dir, &key("aaaa")).expect("同键应命中");
        assert_eq!(
            hit.digest, "aaaa",
            "cache.key_digest 必须报出命中依据的指纹"
        );
        assert!(
            lookup(&dir, &key("bbbb")).is_none(),
            "换了工作树指纹却仍命中，就是把过期事实冒充当前事实"
        );
        purge(&dir);
    }

    /// 键的六个分量逐个可变：任一不同都必须 miss（漏掉一项就是少一层冒充的可能）。
    #[test]
    fn every_key_component_participates_in_the_miss_decision() {
        let dir = scratch("components");
        assert!(store(&dir, &key("same"), &payload()).stored);
        let mut variants = Vec::new();
        let sets: [fn(&mut CacheKey); 5] = [
            |k: &mut CacheKey| k.workspace = "other".to_string(),
            |k: &mut CacheKey| k.verb = "references".to_string(),
            |k: &mut CacheKey| k.target = "Egressg".to_string(),
            |k: &mut CacheKey| k.provider_version = "1.99".to_string(),
            |k: &mut CacheKey| k.budget = "5/8/65536".to_string(),
        ];
        for set in sets {
            let mut k = key("same");
            set(&mut k);
            variants.push(k);
        }
        for k in variants {
            assert!(lookup(&dir, &k).is_none(), "键分量 {} 被忽略", k.verb);
        }
        purge(&dir);
    }

    /// 契约「点名单测」之一：载荷只允许结果字段 + 四个 provider 记事实字段。
    /// 这条同时证伪"顺手把 duration_ms / snapshot 也存进条目"的实现漂移 —— 那些是本次运行的量。
    #[test]
    fn cache_stores_only_result_fields() {
        let provider = json!({
            "kind": "rust-analyzer",
            "binary": "/usr/bin/rust-analyzer",
            "version": "1.98.1",
            "ready": true,
            "duration_ms": 1234,
            "restart_count": 1,
            "session_reused": true,
            "session_queries": 7,
        });
        let built = build_payload(
            &[json!({"symbol": "Egress", "snippet": "struct Egress;"})],
            1,
            &json!({"max_results": 20, "truncated": false}),
            &provider,
            Some(&json!({"refinement_hint": "用 path:line:col"})),
        );
        let obj = built.as_object().expect("载荷应是对象");
        let allowed = ["results", "count", "budget", "provider", "continuation"];
        for k in obj.keys() {
            assert!(allowed.contains(&k.as_str()), "载荷多出非结果字段: {k}");
        }
        let facts = obj["provider"].as_object().expect("provider 应是对象");
        let allowed_facts = ["kind", "binary", "version", "ready"];
        for k in facts.keys() {
            assert!(
                allowed_facts.contains(&k.as_str()),
                "provider 块带进了本次运行的量: {k}"
            );
        }
        // 落盘后的条目同样不许混进运行元数据。
        let dir = scratch("shape");
        assert!(store(&dir, &key("shape"), &built).stored);
        let text = fs::read_to_string(dir.join(format!("{}.json", key("shape").file_stem())))
            .expect("条目应可读回");
        let on_disk: Value = serde_json::from_str(&text).expect("条目应是合法 JSON");
        let keys = on_disk.as_object().expect("落盘条目应是对象");
        let allowed_disk = [
            "results",
            "count",
            "budget",
            "provider",
            "continuation",
            "key",
        ];
        for k in keys.keys() {
            assert!(allowed_disk.contains(&k.as_str()), "落盘条目多出: {k}");
        }
        purge(&dir);
    }

    /// 契约「点名单测」之一：超限不写入，且 `cache.entries`/`cache.bytes` 仍是可核对的数字。
    #[test]
    fn cache_refuses_entries_beyond_cap() {
        let dir = scratch("cap");
        fs::create_dir_all(&dir).expect("建目录");
        for i in 0..MAX_ENTRIES {
            let r = store(&dir, &key(&format!("entry-{i}")), &payload());
            assert!(r.stored, "第 {i} 条本应在上限内写入: {}", r.reason);
        }
        let (entries, bytes) = stats(&dir);
        assert_eq!(entries, MAX_ENTRIES);
        assert!(bytes > 0);
        let over = store(&dir, &key("beyond-cap"), &payload());
        assert!(!over.stored);
        assert_eq!(over.reason, "entry_cap");
        assert_eq!(over.entries, MAX_ENTRIES, "拒绝写入后计数仍可见");
        purge(&dir);
        assert!(!dir.exists());
    }

    #[test]
    fn cache_byte_cap_refuses_an_oversize_entry() {
        let dir = scratch("bytes");
        // 单条就要吃掉整个预算：8 MiB + 余量。用真实载荷形状（结果数组）而不是随手一个字符串，
        // 否则测的是"载荷不是对象"这条分支。
        let items = vec![json!({"symbol": "x".repeat(256)}); (MAX_TOTAL_BYTES as usize / 256) + 64];
        let big = build_payload(&items, items.len(), &json!({}), &json!({}), None);
        let r = store(&dir, &key("huge"), &big);
        assert!(!r.stored, "超过 8 MiB 仍写入就是把 temp 当无限磁盘");
        assert_eq!(r.reason, "byte_cap");
        assert_eq!(r.entries, 0, "拒绝写入时计数仍如实报出当前状态");
        purge(&dir);
    }

    #[test]
    fn cache_key_is_stable_across_path_separators() {
        let mut a = key("same");
        let mut b = key("same");
        a.workspace = "engineering\\nexus-harness".to_string();
        b.workspace = "engineering/nexus-harness".to_string();
        assert_eq!(
            a.file_stem(),
            b.file_stem(),
            "同一 workspace 不该因分隔符得到两个条目名"
        );
        assert_eq!(a.canonical(), b.canonical());
    }
}

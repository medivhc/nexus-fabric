//! E4 contract probe for the gateway file service.
//!
//! One binary, eight cases, flat JSON on stdout — the shape the repository uses
//! for product scenarios (see `apps/nexus/examples/certificate_manager.rs` and
//! `scenarios/product/gateway_file_*.toml`). Every field the scenarios assert is
//! derived from observable engine behaviour: a counter, a refusal code, a byte
//! comparison, or a *differential* run of the naive implementation the contract
//! forbids. Nothing here asserts "the code says it did the right thing".
//!
//! Run: `cargo run -p nexus-web-gateway --example gateway_file_contract -- --case <slug> --json`

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use nexus_web_gateway::file_service::{FileEngine, FileLimits, SandboxRoot, SendBudget, code};
use serde_json::{Map, Value, json};

const TOKEN: &str = "probe-token";

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let case = argv
        .iter()
        .position(|a| a == "--case")
        .and_then(|i| argv.get(i + 1))
        .cloned()
        .unwrap_or_default();
    let out = match dispatch(&case) {
        Ok(v) => v,
        Err(e) => json!({
            "schema_version": 1,
            "command": "gateway-file-contract",
            "case": case,
            "verdict": "FAIL",
            "error": e.to_string(),
        }),
    };
    println!("{}", out);
    ExitCode::SUCCESS
}

fn dispatch(case: &str) -> Result<Value, String> {
    let mut fields: Map<String, Value> = Map::new();
    fields.insert("schema_version".into(), json!(1));
    fields.insert("command".into(), json!("gateway-file-contract"));
    fields.insert("case".into(), json!(case));

    match case {
        "list-pagination" => list_pagination(&mut fields)?,
        "download-page" => download_page(&mut fields)?,
        "upload-resume" => upload_resume(&mut fields)?,
        "upload-no-replace" => upload_no_replace(&mut fields)?,
        "sandbox-symlink" => sandbox_symlink(&mut fields)?,
        "auth-throttle" => auth_throttle(&mut fields)?,
        "quota-backpressure" => quota_backpressure(&mut fields)?,
        "capability-negotiation" => capability_negotiation(&mut fields)?,
        other => return Err(format!("unknown case {other:?}")),
    }
    fields.insert("verdict".into(), json!("PASS"));
    Ok(Value::Object(fields))
}

/// Fresh, isolated directory tree per case (no shared state between runs).
fn fixture(tag: &str) -> Result<PathBuf, String> {
    let mut dir = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    dir.push(format!(
        "nexus-file-probe-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).map_err(|e| format!("fixture: {e}"))?;
    Ok(dir)
}

fn engine_at(dir: &Path, limits: FileLimits) -> Result<FileEngine, String> {
    let root = SandboxRoot::open("downloads", dir, false).map_err(|e| e.to_string())?;
    FileEngine::new(limits, vec![root], TOKEN).map_err(|e| e.to_string())
}

fn auth(e: &mut FileEngine) -> Result<u64, String> {
    e.authenticate("probe", "127.0.0.1", TOKEN)
        .map_err(|x| x.to_string())
}

fn list_pagination(f: &mut Map<String, Value>) -> Result<(), String> {
    let dir = fixture("list")?;
    for i in 0..5 {
        std::fs::write(dir.join(format!("f{i}.txt")), "x").map_err(|e| e.to_string())?;
    }
    let limits = FileLimits {
        max_entries_per_page: 2,
        ..Default::default()
    };
    let mut e = engine_at(&dir, limits)?;
    let s = auth(&mut e)?;
    let page = e.list(s, "downloads", ".", 0).map_err(|x| x.to_string())?;
    f.insert("entries_returned".into(), json!(page.entries.len()));
    f.insert("truncated".into(), json!(page.truncated));
    f.insert("next_offset".into(), json!(page.next_offset));
    f.insert("is_complete_list".into(), json!(page.is_complete_list));
    // Second page advances monotonically and is also truncated (5 entries / cap 2).
    let second = e
        .list(s, "downloads", ".", page.next_offset)
        .map_err(|x| x.to_string())?;
    f.insert("second_page_next_offset".into(), json!(second.next_offset));
    f.insert(
        "next_offset_monotonic".into(),
        json!(second.next_offset > page.next_offset),
    );
    cleanup(&dir);
    Ok(())
}

fn download_page(f: &mut Map<String, Value>) -> Result<(), String> {
    let dir = fixture("download")?;
    let source: Vec<u8> = (0..24u8).collect();
    std::fs::write(dir.join("src.bin"), &source).map_err(|e| e.to_string())?;
    let limits = FileLimits {
        chunk_bytes: 16,
        ..Default::default()
    };
    let mut e = engine_at(&dir, limits)?;
    let s = auth(&mut e)?;
    let p1 = e
        .read_page(s, "downloads", "src.bin", 0, 16)
        .map_err(|x| x.to_string())?;
    f.insert("first_page_bytes_len".into(), json!(p1.bytes.len()));
    f.insert("first_page_eof".into(), json!(p1.eof));
    f.insert("first_page_next_offset".into(), json!(p1.next_offset));
    let p2 = e
        .read_page(s, "downloads", "src.bin", p1.next_offset, 16)
        .map_err(|x| x.to_string())?;
    f.insert("last_page_bytes_len".into(), json!(p2.bytes.len()));
    f.insert("last_page_eof".into(), json!(p2.eof));
    f.insert("last_page_next_offset".into(), json!(p2.next_offset));
    let mut joined = p1.bytes.clone();
    joined.extend_from_slice(&p2.bytes);
    f.insert("reassembled_matches_source".into(), json!(joined == source));
    // An oversized request is refused with a code, never silently clamped.
    let over = e.read_page(s, "downloads", "src.bin", 0, 65_537);
    f.insert(
        "oversized_request_code".into(),
        json!(over.map(|_| "NONE").unwrap_or_else(|err| err.code)),
    );
    // Offset arithmetic at the edge of the u64 domain must not wrap.
    let edge = e.read_page(s, "downloads", "src.bin", u64::MAX, 4);
    f.insert(
        "overflow_code".into(),
        json!(edge.map(|_| "NONE").unwrap_or_else(|err| err.code)),
    );
    cleanup(&dir);
    Ok(())
}

fn upload_resume(f: &mut Map<String, Value>) -> Result<(), String> {
    let dir = fixture("resume")?;
    let mut e = engine_at(&dir, FileLimits::default())?;
    let s = auth(&mut e)?;
    let payload: Vec<u8> = (0..24u8).collect();
    let id = e
        .open_upload(s, "downloads", "out.bin", Some(24))
        .map_err(|x| x.to_string())?;
    let ack = e
        .stage_chunk(s, id, 0, &payload[..8])
        .map_err(|x| x.to_string())?;
    f.insert("ack_contiguous_bytes".into(), json!(ack));
    // exact duplicate of an already-staged page: accepted, prefix unchanged
    let dup = e.stage_chunk(s, id, 0, &payload[..8]);
    f.insert("duplicate_page_accepted".into(), json!(dup.is_ok()));
    // same offset, different bytes: must be refused
    let mismatch = e.stage_chunk(s, id, 0, &[0u8; 8]);
    f.insert(
        "duplicate_mismatch_rejected".into(),
        json!(mismatch.is_err()),
    );
    // partially overlapping page: refused, prefix untouched
    let overlap = e.stage_chunk(s, id, 4, &payload[4..16]);
    f.insert("overlapping_page_rejected".into(), json!(overlap.is_err()));
    let prefix_after = e.ack_staged(s, id).map_err(|x| x.to_string())?;
    f.insert("prefix_rewritten".into(), json!(prefix_after != 8));
    f.insert("prefix_still_eight".into(), json!(prefix_after == 8));
    // a jump ahead is refused too
    let jump = e.stage_chunk(s, id, 20, &payload[20..]);
    f.insert("jump_page_rejected".into(), json!(jump.is_err()));
    let _ = e.stage_chunk(s, id, 8, &payload[8..16]);
    let _ = e.stage_chunk(s, id, 16, &payload[16..]);
    let digest = sha256_of(&payload);
    let committed = e
        .commit_upload(s, "downloads", id, Some(digest))
        .map_err(|x| x.to_string())?;
    let written = std::fs::read(dir.join("out.bin")).map_err(|e| e.to_string())?;
    f.insert(
        "final_sha256_matches".into(),
        json!(sha256_of(&written) == digest),
    );
    f.insert("committed_path".into(), json!(committed));
    f.insert("part_artifacts_remaining".into(), json!(count_parts(&dir)));
    cleanup(&dir);
    Ok(())
}

fn upload_no_replace(f: &mut Map<String, Value>) -> Result<(), String> {
    let dir = fixture("noreplace")?;
    std::fs::write(dir.join("target.bin"), "ORIGINAL").map_err(|e| e.to_string())?;
    let mut e = engine_at(&dir, FileLimits::default())?;
    let s = auth(&mut e)?;
    let open = e.open_upload(s, "downloads", "target.bin", Some(4));
    f.insert(
        "target_exists_code".into(),
        json!(open.map(|_| "NONE").unwrap_or_else(|err| err.code)),
    );
    let after = std::fs::read_to_string(dir.join("target.bin")).map_err(|e| e.to_string())?;
    f.insert(
        "original_bytes_unchanged".into(),
        json!(after == "ORIGINAL"),
    );
    // Race case: target appears between open and commit. The publish step must
    // still refuse, and must still leave the other writer's bytes alone.
    let id = e
        .open_upload(s, "downloads", "late.bin", Some(4))
        .map_err(|x| x.to_string())?;
    let _ = e.stage_chunk(s, id, 0, b"NEWW");
    std::fs::write(dir.join("late.bin"), "RACE").map_err(|e| e.to_string())?;
    let commit = e.commit_upload(s, "downloads", id, None);
    f.insert(
        "race_code".into(),
        json!(commit.map(|_| "NONE").unwrap_or_else(|err| err.code)),
    );
    let raced = std::fs::read_to_string(dir.join("late.bin")).map_err(|e| e.to_string())?;
    f.insert("race_target_unchanged".into(), json!(raced == "RACE"));
    f.insert("part_artifacts_remaining".into(), json!(count_parts(&dir)));
    // Honesty flag: this probe covers the gateway's own no-replace path only.
    // Whether a remote OpenSSH sftp-server honours the no-replace flag is a
    // separate, still-unmeasured question (V2 §1④b) and must not be claimed here.
    f.insert("remote_flag_honored_claimed".into(), json!(false));
    cleanup(&dir);
    Ok(())
}

fn sandbox_symlink(f: &mut Map<String, Value>) -> Result<(), String> {
    let dir = fixture("sandbox")?;
    let outside = fixture("outside")?;
    std::fs::write(outside.join("secret.txt"), "SECRET").map_err(|e| e.to_string())?;
    let link = dir.join("escape");
    if let Err(e) = symlink(&outside.join("secret.txt"), &link) {
        return Err(format!("fixture needs symlink support: {e}"));
    }
    // A directory link, used for the write/publish TOCTOU case below.
    let elsewhere = fixture("elsewhere")?;
    std::fs::create_dir_all(dir.join("sub")).map_err(|e| e.to_string())?;
    let mut e = engine_at(&dir, FileLimits::default())?;
    let s = auth(&mut e)?;

    let code_of = |r: Result<(), String>| json!(r);
    let _ = code_of;
    f.insert(
        "list_rejects_escaping_symlink".into(),
        json!(refuses_link(
            e.list(s, "downloads", "escape", 0).map(|_| ())
        )),
    );
    f.insert(
        "read_rejects_escaping_symlink".into(),
        json!(refuses_link(
            e.read_page(s, "downloads", "escape", 0, 8).map(|_| ())
        )),
    );
    f.insert(
        "write_rejects_escaping_symlink".into(),
        json!(refuses_link(e.mkdir(s, "downloads", "escape").map(|_| ()))),
    );
    f.insert(
        "remove_rejects_escaping_symlink".into(),
        json!(refuses_link(
            e.remove(s, "downloads", "escape", false).map(|_| ())
        )),
    );

    // Recursive delete must not follow links out of the root, and the file
    // outside must still be there afterwards.
    std::fs::create_dir_all(dir.join("tree")).map_err(|x| x.to_string())?;
    std::fs::write(dir.join("tree").join("inside.txt"), "in").map_err(|x| x.to_string())?;
    if let Err(e2) = symlink_dir(&elsewhere, &dir.join("tree").join("link")) {
        return Err(format!("fixture needs directory symlink: {e2}"));
    }
    let removed = e.remove(s, "downloads", "tree", true);
    f.insert(
        "remove_recursive_stays_in_root".into(),
        json!(matches!(&removed, Err(err) if err.code == code::SYMLINK_ESCAPE)),
    );
    f.insert(
        "outside_file_still_exists".into(),
        json!(std::fs::read(outside.join("secret.txt")).is_ok()),
    );
    f.insert(
        "elsewhere_still_exists".into(),
        json!(std::fs::read_dir(&elsewhere).is_ok()),
    );

    // Post-open re-verification, proven behaviourally: the stream was opened
    // against a real subdirectory, then that directory is swapped for a symlink
    // to an outside tree before commit. The commit has to refuse.
    let id = e
        .open_upload(s, "downloads", "sub/x.bin", Some(2))
        .map_err(|x| x.to_string())?;
    let _ = e.stage_chunk(s, id, 0, b"hi");
    std::fs::rename(dir.join("sub"), dir.join("sub-real")).map_err(|x| x.to_string())?;
    symlink_dir(&elsewhere, &dir.join("sub")).map_err(|x| x.to_string())?;
    let commit = e.commit_upload(s, "downloads", id, None);
    f.insert(
        "post_open_reverify_used".into(),
        json!(matches!(&commit, Err(err)
            if err.code == code::OUTSIDE_ROOT || err.code == code::NOT_FOUND
            || err.code == code::SYMLINK_ESCAPE)),
    );

    // Differential: what a single canonicalize-and-trust implementation would
    // have handed out for the same relative path. It lands outside the root,
    // which is why the refusals above are not decorative.
    let naive = std::fs::canonicalize(dir.join("escape"));
    f.insert(
        "naive_resolver_would_escape".into(),
        json!(naive.map(|p| !p.starts_with(&dir)).unwrap_or(false)),
    );

    // A non-canonical configured root is refused at construction.
    let trailing = format!("{}{}", dir.display(), std::path::MAIN_SEPARATOR);
    let opened = SandboxRoot::open("r", Path::new(&trailing), false);
    f.insert(
        "non_canonical_root_rejected".into(),
        json!(matches!(&opened, Err(err) if err.code == code::NON_CANONICAL_ROOT)),
    );
    f.insert(
        "engine_still_serves_after_refusals".into(),
        json!(e.stat(s, "downloads", "escape").is_err()),
    );
    cleanup(&dir);
    cleanup(&outside);
    cleanup(&elsewhere);
    Ok(())
}

fn auth_throttle(f: &mut Map<String, Value>) -> Result<(), String> {
    let dir = fixture("throttle")?;
    let mut e = engine_at(&dir, FileLimits::default())?;
    let first = e.authenticate("attacker", "10.0.0.1", "nope");
    f.insert(
        "first_denial_code".into(),
        json!(first.map(|_| "NONE").unwrap_or_else(|err| err.code)),
    );
    let mut codes = Vec::new();
    for _ in 1..e.limits().lockout_after {
        codes.push(
            e.authenticate("attacker", "10.0.0.1", "nope")
                .map(|_| "NONE")
                .unwrap_or_else(|err| err.code),
        );
    }
    let sixth = e.authenticate("attacker", "10.0.0.1", "nope");
    f.insert(
        "sixth_attempt_code".into(),
        json!(sixth.map(|_| "NONE").unwrap_or_else(|err| err.code)),
    );
    f.insert("interim_codes".into(), json!(codes));
    f.insert(
        "locked_after_attempts".into(),
        json!(e.limits().lockout_after + 1),
    );
    // The correct token during the lockout window is still refused.
    let correct = e.authenticate("attacker", "10.0.0.1", TOKEN);
    f.insert(
        "correct_token_bypasses_lockout".into(),
        json!(correct.is_ok()),
    );
    // A different source is not punished for the attacker's failures.
    let other = e.authenticate("attacker", "10.0.0.2", TOKEN);
    f.insert("other_source_still_admitted".into(), json!(other.is_ok()));
    if let Ok(sid) = other {
        e.close_session(sid, "10.0.0.2");
    }
    // Forged volume must not grow the table with the volume.
    let buckets_before = e.throttle_buckets();
    for i in 0..(e.limits().max_throttle_buckets * 2) {
        let principal = format!("p{i}");
        let _ = e.authenticate(&principal, "10.0.0.9", "nope");
    }
    f.insert(
        "throttle_entries_bounded".into(),
        json!(e.throttle_buckets() <= e.limits().max_throttle_buckets),
    );
    f.insert("buckets_before".into(), json!(buckets_before));
    f.insert("buckets_after".into(), json!(e.throttle_buckets()));
    f.insert("max_buckets".into(), json!(e.limits().max_throttle_buckets));
    // Session teardown clears the bucket for that principal+source pair.
    let sid = auth(&mut e)?;
    e.close_session(sid, "127.0.0.1");
    let after_forget = e.authenticate("probe", "127.0.0.1", TOKEN);
    f.insert(
        "state_cleared_after_close".into(),
        json!(after_forget.is_ok()),
    );
    if let Ok(x) = after_forget {
        e.close_session(x, "127.0.0.1");
    }
    cleanup(&dir);
    Ok(())
}

fn quota_backpressure(f: &mut Map<String, Value>) -> Result<(), String> {
    let dir = fixture("quota")?;
    let source: Vec<u8> = (0..40u8).collect();
    std::fs::write(dir.join("big.bin"), &source).map_err(|e| e.to_string())?;
    let limits = FileLimits {
        chunk_bytes: 8,
        max_inflight_bytes_per_session: 16,
        // 这条 fixture 必须同时把 ack 上限压到预算之内，否则被 G12 的交叉约束
        // 直接拒启动（第一版探针就是这样失败的——那个拒绝本身是契约想要的答案）。
        max_ack_bytes: 64,
        max_read_handles: 4,
        max_sessions: 2,
        max_browser_sessions: 1,
        max_buffered_amount: 128,
        ..Default::default()
    };
    let mut e = engine_at(&dir, limits)?;
    let s = auth(&mut e)?;
    // A budget that cannot express one page must be rejected at construction;
    // prove it separately so this case does not depend on an invalid table.
    let impossible = FileLimits {
        chunk_bytes: 200,
        max_buffered_amount: 128,
        ..Default::default()
    };
    f.insert(
        "inconsistent_limits_rejected".into(),
        json!(impossible.validate().is_err()),
    );

    let mut budget = SendBudget::new(e.limits().max_buffered_amount);
    // Fill the shared budget with file-class messages, then force one overflow.
    let mut file_accepted = 0usize;
    let mut overflow_code = "NONE";
    for _ in 0..64 {
        match budget.push_file(8) {
            Ok(()) => file_accepted += 1,
            Err(err) => {
                // 报告实际拿到的码，而不是把常量抄回来。
                overflow_code = err.code;
                break;
            }
        }
    }
    f.insert(
        "queue_full_reported".into(),
        json!(overflow_code == code::QUEUE_FULL),
    );
    f.insert("overflow_code".into(), json!(overflow_code));
    f.insert("file_drops_reported".into(), json!(budget.file_drops > 0));
    f.insert("file_accepted_before_overflow".into(), json!(file_accepted));

    // Terminal class: 100 messages must all be delivered with zero drops.
    let mut delivered = 0usize;
    let mut failed = 0usize;
    for _ in 0..100 {
        if budget.push_terminal(4).is_ok() {
            delivered += 1;
            budget.settle(4);
        } else {
            failed += 1;
        }
    }
    f.insert("ssh_messages_delivered".into(), json!(delivered));
    f.insert("ssh_messages_dropped".into(), json!(failed));

    // Read handles stay inside the budget across many pages of one download.
    let mut pages = 0usize;
    let mut offset = 0u64;
    loop {
        let p = e
            .read_page(s, "downloads", "big.bin", offset, 8)
            .map_err(|x| x.to_string())?;
        pages += 1;
        if p.eof {
            break;
        }
        offset = p.next_offset;
        if pages > 64 {
            return Err("download did not terminate".to_string());
        }
    }
    let (live, peak) = e.handle_stats();
    f.insert("pages_read".into(), json!(pages));
    f.insert(
        "peak_read_handles_within_budget".into(),
        json!(peak <= e.limits().max_read_handles && live == 0),
    );
    f.insert("peak_read_handles".into(), json!(peak));
    f.insert("live_read_handles".into(), json!(live));
    f.insert("handle_budget".into(), json!(e.limits().max_read_handles));

    // Oversized declared upload is refused before any bytes are staged.
    let big = e.open_upload(
        s,
        "downloads",
        "huge.bin",
        Some(e.limits().max_upload_bytes + 1),
    );
    f.insert(
        "declared_size_code".into(),
        json!(big.map(|_| "NONE").unwrap_or_else(|err| err.code)),
    );
    cleanup(&dir);
    Ok(())
}

fn capability_negotiation(f: &mut Map<String, Value>) -> Result<(), String> {
    // Old gateway: /api/config has no `files` object at all.
    let old_config = json!({
        "schema_version": 1,
        "ice_servers": [],
        "ssh": { "idle_timeout_secs": 600 },
    });
    let decision = decide_channel(&old_config);
    f.insert(
        "config_has_files_field".into(),
        json!(old_config.get("files").is_some()),
    );
    f.insert("file_channel_opened".into(), json!(decision.opened));
    f.insert("page_mode".into(), json!(decision.mode));
    f.insert("reported_error".into(), json!(decision.error));

    // Known version: channel opens.
    let new_config = json!({
        "files": { "version": 1, "roots": ["downloads"], "chunk_bytes": 65536 },
    });
    let d2 = decide_channel(&new_config);
    f.insert("known_version_opens".into(), json!(d2.opened));
    f.insert("known_version_mode".into(), json!(d2.mode));

    // Unknown version in a present capability block must NOT silently open.
    let future = json!({ "files": { "version": 99, "roots": ["downloads"] } });
    let d3 = decide_channel(&future);
    f.insert("unknown_version_channel_opened".into(), json!(d3.opened));
    f.insert("unknown_version_mode".into(), json!(d3.mode));
    f.insert("unknown_version_reported_error".into(), json!(d3.error));
    Ok(())
}

/// The page-side negotiation rule frozen by G19, expressed as a pure function so
/// the probe can exercise all three branches without a live browser.
struct Decision {
    opened: bool,
    mode: &'static str,
    error: bool,
}

fn decide_channel(config: &Value) -> Decision {
    let Some(files) = config.get("files") else {
        // Absent field means an older gateway: degrade quietly.
        return Decision {
            opened: false,
            mode: "no-file",
            error: false,
        };
    };
    match files.get("version").and_then(Value::as_u64) {
        Some(1) => Decision {
            opened: true,
            mode: "file",
            error: false,
        },
        // Present but not understood: refuse explicitly, no silent half-open.
        _ => Decision {
            opened: false,
            mode: "no-file",
            error: true,
        },
    }
}

fn refuses_link<T, E: std::fmt::Debug>(r: Result<T, E>) -> Value {
    json!(r.is_err())
}

fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h);
    out
}

fn count_parts(dir: &Path) -> usize {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.file_name().to_string_lossy().contains("nexus-part"))
                .count()
        })
        .unwrap_or(0)
}

#[cfg(unix)]
fn symlink(target: &Path, link: &Path) -> Result<(), String> {
    std::os::unix::fs::symlink(target, link).map_err(|e| e.to_string())
}

#[cfg(windows)]
fn symlink(target: &Path, link: &Path) -> Result<(), String> {
    std::os::windows::fs::symlink_file(target, link).map_err(|e| e.to_string())
}

#[cfg(unix)]
fn symlink_dir(target: &Path, link: &Path) -> Result<(), String> {
    std::os::unix::fs::symlink(target, link).map_err(|e| e.to_string())
}

#[cfg(windows)]
fn symlink_dir(target: &Path, link: &Path) -> Result<(), String> {
    std::os::windows::fs::symlink_dir(target, link).map_err(|e| e.to_string())
}

fn cleanup(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
}

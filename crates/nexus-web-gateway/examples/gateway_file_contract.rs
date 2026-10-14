//! E4 contract probe for the gateway file service.
//!
//! One binary, nine cases, flat JSON on stdout — the shape the repository uses
//! for product scenarios (see `apps/nexus/examples/certificate_manager.rs` and
//! `scenarios/product/gateway_file_*.toml`). Every field the scenarios assert is
//! derived from observable engine behaviour: a counter, a refusal code, a byte
//! comparison, or a *differential* run of the naive implementation the contract
//! forbids. Nothing here asserts "the code says it did the right thing".
//!
//! 一处**已登记的例外**（评审 r2 W-7 / r3 W-6）：`capability-negotiation` 一案判定的是
//! 探针里自己实现的 `decide_channel`（版本/能力门控的规则模型），产品侧还没有这段代码
//! ——`GatewayConfig` 尚无 `files` 字段，配置接线属 M1 剩余项。所以那 7 条期望与
//! 引擎代码零耦合，跑绿不等于网关已经会做能力协商；该场景与上面那句话不符，直到
//! M2 把 `/api/config.files` 真接出来为止。
//!
//! Run: `cargo run -p nexus-web-gateway --example gateway_file_contract -- --case <slug> --json`

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use nexus_web_gateway::config::{
    FileRootConfig, FilesConfig, GatewayConfig, MAX_FILE_WINDOW_SECS, MIN_FILE_LOCKOUT_WINDOW_SECS,
    MeshConfig, MeshNodeInfo, SshConfig, TlsConfig,
};
use nexus_web_gateway::error::GatewayError;
use nexus_web_gateway::file_service::{
    BackendKind, FileEngine, FileLimits, FileResult, SandboxRoot, code,
};
use serde_json::{Map, Value, json};

const TOKEN: &str = "probe-token";

/// A `files` section that is numerically self-consistent and *disabled*, which is
/// the state a pre-file-service config parses into. Each case flips exactly the
/// field under test so a pass can't come from an unrelated violation.
fn base_files() -> FilesConfig {
    FilesConfig::default()
}

/// Wrap a `files` section in an otherwise valid gateway config.
fn base_config(files: FilesConfig) -> GatewayConfig {
    GatewayConfig {
        listen_addr: "127.0.0.1:8443".parse().expect("static"),
        node_id: "probe-node".into(),
        node_name: "probe-node".into(),
        node_list: vec![MeshNodeInfo {
            peer_id: "probe-node".into(),
            name: "probe-node".into(),
            addrs: vec!["127.0.0.1:8443".into()],
            services: vec!["ssh".into()],
        }],
        ice_servers: vec![],
        tls: TlsConfig::AutoGenerate {
            names: vec!["localhost".into()],
            ips: vec!["127.0.0.1".parse().expect("static")],
            cert_dir: None,
        },
        ssh: SshConfig::default(),
        files,
        mesh: MeshConfig::InMemory,
    }
}

/// The validation error string, empty when the config is accepted. Some
/// expectations claim **which layer** refuses; `is_err()` alone cannot tell a
/// config bound apart of the delegated engine table, because
/// `FilesConfig::validate` runs `FileLimits::validate` too (measured as
/// mutations MC01/MC02, which left an `is_err()`-only object green).
fn config_err(cfg: &GatewayConfig) -> String {
    match cfg.validate() {
        Ok(()) => String::new(),
        Err(e) => e.to_string(),
    }
}

/// True when the **config layer's own** window bound refused rather than the
/// delegated engine table (whose text is `files limits: lockout_window must ...`).
/// Substring, not prefix: `GatewayError::Config`'s Display prepends `config error: `.
fn refused_by_config_bound(msg: &str) -> bool {
    msg.contains("files.lockout_window_secs")
}

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
        "sftp-backend-boundary" => sftp_backend_boundary(&mut fields)?,
        "config" => gateway_config(&mut fields)?,
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

/// G14 fail-closed boundary (owner decision 2026-10-11, option (b)).
///
/// The non-overwriting publish promised for uploads cannot be expressed over SFTP
/// with ssh2 0.9.6: libssh2 advertises and pins SFTP v3
/// (`include/libssh2_sftp.h:51  #define LIBSSH2_SFTP_VERSION 3`) and the rename
/// flags are only serialized when `sftp->version >= 5` (`src/sftp.c:2833-2834`),
/// with no assignment to that field anywhere in the tree - so
/// `Some(ATOMIC|NATIVE)` and `None` produce byte-identical packets.
/// The primitive that would work (`SSH_FXP_POSIX_RENAME` /
/// `libssh2_sftp_posix_rename_ex`) is not wrapped by the crate.
///
/// Rather than ship an upload path that silently overwrites a remote file, the
/// engine refuses every mutation on an SFTP-backed root. M1 implements only the
/// local transport, so reads on an SFTP root are refused too - a remote path
/// handed to the local resolver would otherwise produce a misleading NOT_FOUND.
fn sftp_backend_boundary(f: &mut Map<String, Value>) -> Result<(), String> {
    let dir = fixture("sftp-boundary")?;
    let local = SandboxRoot::open("downloads", &dir, false).map_err(|e| e.to_string())?;
    let remote = SandboxRoot::open_sftp("remotedir", "/home/user/files", false)
        .map_err(|e| e.to_string())?;
    assert_eq!(local.backend(), BackendKind::Local);
    assert_eq!(remote.backend(), BackendKind::Sftp);
    let mut e = FileEngine::new(FileLimits::default(), vec![local, remote], TOKEN)
        .map_err(|x| x.to_string())?;
    let s = auth(&mut e)?;

    f.insert(
        "local_upload_supported".into(),
        json!(e.open_upload(s, "downloads", "a.bin", Some(1)).is_ok()),
    );
    f.insert(
        "sftp_upload_supported".into(),
        json!(e.open_upload(s, "remotedir", "a.bin", Some(1)).is_ok()),
    );
    let refusal = e.open_upload(s, "remotedir", "b.bin", Some(1));
    f.insert(
        "refusal_code".into(),
        json!(refusal.map(|_| "NONE").unwrap_or_else(|err| err.code)),
    );
    f.insert(
        "sftp_mkdir_supported".into(),
        json!(e.mkdir(s, "remotedir", "sub").is_ok()),
    );
    f.insert(
        "sftp_remove_supported".into(),
        json!(e.remove(s, "remotedir", "a.bin", false).is_ok()),
    );
    f.insert(
        "sftp_rename_supported".into(),
        json!(e.rename(s, "remotedir", "a.bin", "c.bin").is_ok()),
    );
    f.insert(
        "sftp_list_supported".into(),
        json!(e.list(s, "remotedir", ".", 0).is_ok()),
    );
    // Static half of the promise: mutation capability is a property of the
    // backend kind, not a runtime negotiation that could be misconfigured.
    f.insert(
        "mutation_capability_of_sftp_backend".into(),
        json!(BackendKind::Sftp.allows_mutation()),
    );
    // 评审 F3：上面那一条是常量回读——把 `allows_mutation()` 翻成 true，
    // 下一道 `require_local_io` 仍然回 UNSUPPORTED，场景照样绿。所以再报
    // **是哪一道门拒的**：G14"没有无覆盖发布原语"必须与"传输未实现"可区分，
    // 翻转能力位就会把这个字段从 G14_* 变成 TRANSPORT_*，场景因此变红。
    let gate = match e.open_upload(s, "remotedir", "gate.bin", Some(1)) {
        Ok(_) => "ACCEPTED",
        Err(err) if err.message.contains("non-overwriting") => "G14_NO_NON_OVERWRITING_PUBLISH",
        Err(err) if err.message.contains("no implemented transport") => "TRANSPORT_NOT_IMPLEMENTED",
        Err(_) => "OTHER",
    };
    f.insert("sftp_refusal_gate".into(), json!(gate));
    // 评审 r2 NEW-1：提交动词曾绕过权限门，而且流不记它开在哪个 root 上，
    // 所以"在可写根上传、换个 root 参数提交"能落进只读根或把远端路径丢给本地解析器。
    let sid = e
        .open_upload(s, "downloads", "bound.bin", Some(4))
        .map_err(|x| x.to_string())?;
    e.stage_chunk(s, sid, 0, b"abcd")
        .map_err(|x| x.to_string())?;
    let redirect = e
        .commit_upload(s, "remotedir", sid, None)
        .map(|_| "NONE")
        .unwrap_or_else(|err| err.code);
    f.insert("commit_root_redirect_code".into(), json!(redirect));
    // 拒绝不得吃掉流：回到真正的 root 必须仍能发布。
    let recovered = match e.commit_upload(s, "downloads", sid, None) {
        Ok(p) => p,
        Err(err) => format!("ERR:{}", err.code),
    };
    f.insert(
        "commit_after_refusal_recovers".into(),
        json!(recovered == "bound.bin"),
    );
    // A remote root must not be silently accepted in a non-absolute or dotted form.
    f.insert(
        "relative_remote_root_rejected".into(),
        json!(SandboxRoot::open_sftp("r", "home/user", false).is_err()),
    );
    f.insert(
        "dotdot_remote_root_rejected".into(),
        json!(SandboxRoot::open_sftp("r", "/home/../etc", false).is_err()),
    );
    cleanup(&dir);
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
    // 评审 r2 W-6：过去这里把 `lockout_after + 1` 当测量值回读。改成观测：
    // 一直喂错令牌直到第一次出现 THROTTLED，再看紧接着一次**正确令牌**是否仍被拒，
    // 那个尝试序号才是"锁定生效于第几次"。
    let mut e3 = engine_at(&dir, FileLimits::default())?;
    let mut attempt_of_throttle = 0usize;
    for n in 1..=64usize {
        let denial = e3
            .authenticate("observer", "10.0.0.5", "nope")
            .map(|_| "NONE")
            .unwrap_or_else(|err| err.code);
        if denial == code::THROTTLED {
            attempt_of_throttle = n;
            break;
        }
    }
    let locked_attempt =
        if attempt_of_throttle > 0 && e3.authenticate("observer", "10.0.0.5", TOKEN).is_err() {
            attempt_of_throttle + 1
        } else {
            0
        };
    f.insert("locked_after_attempts".into(), json!(locked_attempt));
    // 评审 r2 NEW-3：节流表被伪造量填满时旧实现是 fail-**open**（只累加私有计数，
    // 从不写 `locked`，令牌比对继续做）⇒ 轮换 principal 就能买无限次猜测。
    let mut e4 = engine_at(
        &dir,
        FileLimits {
            max_throttle_buckets: 8,
            lockout_after: 3,
            // 取交叉规则的上界 8×3：让下面 11 条单源洪水先撞上"表满"这条大路。
            max_failures_per_source: 24,
            ..Default::default()
        },
    )?;
    for i in 0..8 {
        let _ = e4.authenticate(&format!("p{i}"), "10.0.0.6", "nope");
    }
    let overflow_codes: Vec<&str> = (0..3)
        .map(|_| {
            e4.authenticate("rot", "10.0.0.6", "nope")
                .map(|_| "NONE")
                .unwrap_or_else(|err| err.code)
        })
        .collect();
    // 两个群体都要断言。评审 r5 N-7：只断言"不在册"的主体对旧豁免逻辑零杀伤力
    // （旧写法恰恰只作用于不在册人群），所以必须 additionally 拿一个**已在册**的
    // p0 去试正确令牌——旧实现这里是 ACCEPTED。
    let in_table_correct = e4
        .authenticate("p0", "10.0.0.6", TOKEN)
        .map(|_| "ACCEPTED")
        .unwrap_or_else(|err| err.code);
    let fresh_correct = e4
        .authenticate("brand-new", "10.0.0.6", TOKEN)
        .map(|_| "ACCEPTED")
        .unwrap_or_else(|err| err.code);
    f.insert(
        "throttle_buckets_at_cap".into(),
        json!(e4.throttle_buckets()),
    );
    f.insert("throttle_overflow_codes".into(), json!(overflow_codes));
    f.insert(
        "throttle_overflow_count".into(),
        json!(e4.throttle_overflow()),
    );
    f.insert(
        "throttle_full_fail_closed".into(),
        json!(
            e4.throttle_buckets() == 8
                && e4.throttle_overflow() >= 3
                && e4.throttle_globally_locked()
                && in_table_correct == code::THROTTLED
                && fresh_correct == code::THROTTLED
        ),
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
        let _ = e.close_session(sid, "10.0.0.2");
    }
    // 会话拆除现在**不**清节流状态（`Throttle::succeed` 上记着为什么）：这里验的是
    // "成功认证过一对身份之后，同一对的下一条失败从 0 数起"，也就是 succeed 那条路。
    // 顺序是**有意的**：它必须跑在下面的伪造量淹没之前——NEW-3 把表满改成
    // fail-closed 之后，淹没过的引擎会对任何未在册主体拒认证，这段就会假红
    // （第一次 Linux 跑正是这样红的）。
    let sid = auth(&mut e)?;
    e.close_session(sid, "127.0.0.1")
        .map_err(|x| x.to_string())?;
    let after_forget = e.authenticate("probe", "127.0.0.1", TOKEN);
    f.insert(
        "state_cleared_after_close".into(),
        json!(after_forget.is_ok()),
    );
    if let Ok(x) = after_forget {
        let _ = e.close_session(x, "127.0.0.1");
    }
    // Forged volume must not grow the table with the volume.
    // 地址轮换着灌：每个地址只花 32 条（< 默认 `max_failures_per_source` = 40），
    // 这样这条判据量的仍然是"表位是否随伪造量线性增长"，而不是被单源限额提前截断。
    // 单源那条大路下面另有一道观测（`single_address_cannot_fill_the_table`）。
    let buckets_before = e.throttle_buckets();
    let addr_for = |i: usize| format!("10.0.9.{}", i / 32);
    for i in 0..(e.limits().max_throttle_buckets * 2) {
        let principal = format!("p{i}");
        let _ = e.authenticate(&principal, &addr_for(i), "nope");
    }
    f.insert(
        "throttle_entries_bounded".into(),
        json!(e.throttle_buckets() <= e.limits().max_throttle_buckets),
    );
    f.insert("buckets_before".into(), json!(buckets_before));
    f.insert("buckets_after".into(), json!(e.throttle_buckets()));
    f.insert("max_buckets".into(), json!(e.limits().max_throttle_buckets));
    // 同一台引擎在淹没之后必须 fail-closed（r2 NEW-3 在产品引擎上的直接观测，
    // 不只是 e4 那台小表引擎）。两个群体都断言：`p0` 已在册（旧豁免逻辑下这里
    // 是 ACCEPTED，评审 r5 N-7），`fresh-after-flood` 不在册。地址必须与建桶时同一个，
    // 否则查的就不是那条身份了。
    let in_table_post_flood = e
        .authenticate("p0", &addr_for(0), TOKEN)
        .map(|_| "ACCEPTED")
        .unwrap_or_else(|err| err.code);
    let post_flood = e
        .authenticate("fresh-after-flood", &addr_for(0), TOKEN)
        .map(|_| "ACCEPTED")
        .unwrap_or_else(|err| err.code);
    f.insert(
        "product_engine_fails_closed_when_flooded".into(),
        json!(
            e.throttle_globally_locked()
                && in_table_post_flood == code::THROTTLED
                && post_flood == code::THROTTLED
        ),
    );
    // 单源限额在产品尺寸引擎上的直接观测（r7 整改清单第 3 条 / r8 R7-N-9）：一个
    // 地址即使狂灌 2048 条失败，也占不满 1024 行的表——它自己在第 40 条就被锁到
    // 窗口结束。表满那条大路仍然可达（上面用轮转地址证明了），但"一个 peer 花掉
    // 整池额度"这条路被这道门关上了。
    let mut e_cap = engine_at(&dir, FileLimits::default())?;
    for i in 0..(e_cap.limits().max_throttle_buckets * 2) {
        let _ = e_cap.authenticate(&format!("solo{i}"), "10.0.0.99", "nope");
    }
    f.insert(
        "solo_rows_after_flood".into(),
        json!(e_cap.throttle_buckets()),
    );
    f.insert(
        "single_address_cannot_fill_the_table".into(),
        json!(
            e_cap.throttle_buckets() < e_cap.limits().max_throttle_buckets
                && e_cap.throttle_source_locks() == 1
                && !e_cap.throttle_globally_locked()
                && e_cap
                    .authenticate("solo-late", "10.0.0.99", TOKEN)
                    .map(|_| false)
                    .unwrap_or_else(|err| err.code == code::THROTTLED)
                && e_cap.authenticate("other-addr", "10.0.0.98", TOKEN).is_ok()
        ),
    );
    // 评审 r6 NOTE-4（owner 裁决：节流键改为身份摘要）。旧写法把两半裁到 128 字节，
    // 于是"同一前缀 + 同一总长"的两个身份共用一个桶：伪造者只要用
    // `base+"bbbb"` 喂满 `lockout_after` 条失败，就把 `base+"aaaa"` 那个合法主体
    // 锁在门外——一个**不淹没任何东西**的定向锁定。摘要键之后这需要 SHA-256 碰撞。
    let mut e5 = engine_at(&dir, FileLimits::default())?;
    let base = "b".repeat(128);
    let victim = format!("{base}aaaa");
    let forged = format!("{base}bbbb");
    for _ in 0..e5.limits().lockout_after {
        let _ = e5.authenticate(&forged, "10.0.0.10", "nope");
    }
    // 受害者自己也错一次：旧写法下这条会把共用桶推到 `lockout_after + 1` 并再次
    // 武装，正确令牌必被拒；摘要键下它只是自己桶里的 1 条失败。
    let _ = e5.authenticate(&victim, "10.0.0.10", "nope");
    // 观测值必须在"受害者认证成功"**之前**取：`succeed` 会清掉它自己的桶，
    // 之后再读就只剩伪造者那一行，判据就空转了。
    let rows_before_success = e5.throttle_buckets();
    let failures_before_success = e5.throttle_failures();
    let victim_after_forged = e5
        .authenticate(&victim, "10.0.0.10", TOKEN)
        .map(|_| "ACCEPTED")
        .unwrap_or_else(|err| err.code);
    f.insert(
        "throttle_rows_before_victim_success".into(),
        json!([rows_before_success, failures_before_success]),
    );
    f.insert(
        "throttle_identity_prefixes_are_separate_buckets".into(),
        json!(
            rows_before_success == 2
                && failures_before_success == e5.limits().lockout_after + 1
                && victim_after_forged == "ACCEPTED"
        ),
    );
    f.insert(
        "victim_code_after_forged_prefix".into(),
        json!(victim_after_forged),
    );
    // R4-W-6（owner 裁决：实现桶衰减）。停止注入满一个窗口之后，伪造量占住的桶位
    // 必须自己腾出来：全局窗口解除、表清空、新来的合法主体重新拿到**自己的桶**
    // 而不是被扫进 fail-closed 的溢出人群。窗口取 100 ms、静置 400 ms（4 倍余量），
    // 让"是否真的按窗口回收"由时间决定而不是由巧合决定。
    let mut e6 = engine_at(
        &dir,
        FileLimits {
            max_throttle_buckets: 4,
            lockout_after: 2,
            // 交叉规则的上界 4×2；下面的洪水是 6 条，故意留在源额度之下，
            // 这样"自愈"量的仍是表位与溢出计数，不是源锁。
            max_failures_per_source: 8,
            lockout_window: std::time::Duration::from_millis(100),
            ..Default::default()
        },
    )?;
    for i in 0..6 {
        let _ = e6.authenticate(&format!("flood{i}"), "10.0.0.11", "nope");
    }
    let armed_before = e6.throttle_globally_locked();
    std::thread::sleep(std::time::Duration::from_millis(400));
    let lapsed = !e6.throttle_globally_locked();
    // 表清空**且锁表也清空**才算自愈：锁表大小此前在契约面上不可读（r8 R8-W-3）。
    let table_empty = e6.throttle_buckets() == 0 && e6.throttle_locks() == 0;
    let overflow_zero = e6.throttle_overflow() == 0;
    let late = e6.authenticate("late-comer", "10.0.0.12", TOKEN);
    let admitted = late.is_ok();
    if let Ok(sid) = late {
        let _ = e6.close_session(sid, "10.0.0.12");
    }
    let _ = e6.authenticate("fresh-failure", "10.0.0.12", "nope");
    let healed = e6.throttle_buckets() == 1 && e6.throttle_overflow() == 0;
    f.insert(
        "flood_armed_before_quiet_window".into(),
        json!(armed_before),
    );
    f.insert(
        "throttle_flood_self_heals_after_quiet_window".into(),
        json!(armed_before && lapsed && table_empty && overflow_zero && admitted && healed),
    );
    // 评审 r7 R7-W-2 → r8 R8-W-2 的落点：拆会话**什么节流状态都不清**（既不删锁，
    // 也不删计数），计数只由成功认证与窗口衰减两途清。
    // 整条序列不靠时钟：会话号顺序自增、而 `close_session` 在 M2 接线前没有归属检查，
    // 所以"拆会话即解锁"等于给一个能猜整数的人无限猜测预算（完整三段历史因果写在
    // `Throttle::succeed` 上）。射程要看准：本字段只观测**锁定**是否被拆除抹掉，
    // 所以它打得住最早的 `forget`（连带删 `locked` ⇒ 这里回 ACCEPTED ⇒ 红），
    // 打不住第八片那版"清计数不删锁"（锁还在 ⇒ 本字段仍 true）——后者由单测
    // `session_teardown_touches_no_throttle_state` 的 (a) 半打（拆会话后第二条失败
    // 必须是 THROTTLED，清了计数就变 AUTH_DENIED ⇒ 红）。
    let mut e7 = engine_at(&dir, FileLimits::default())?;
    let td = e7
        .authenticate("teardown", "10.0.0.13", TOKEN)
        .map_err(|x| x.to_string())?;
    for _ in 0..e7.limits().lockout_after {
        let _ = e7.authenticate("teardown", "10.0.0.13", "nope");
    }
    let locked_before_teardown = e7
        .authenticate("teardown", "10.0.0.13", TOKEN)
        .map(|_| "ACCEPTED")
        .unwrap_or_else(|err| err.code);
    e7.close_session(td, "10.0.0.13")
        .map_err(|x| x.to_string())?;
    let locked_after_teardown = e7
        .authenticate("teardown", "10.0.0.13", TOKEN)
        .map(|_| "ACCEPTED")
        .unwrap_or_else(|err| err.code);
    f.insert(
        "lock_survives_session_teardown".into(),
        json!(
            locked_before_teardown == code::THROTTLED && locked_after_teardown == code::THROTTLED
        ),
    );
    f.insert("code_after_teardown".into(), json!(locked_after_teardown));
    // R7-N-6：长度前缀这条性质原先只有 1 根柱子且在单测里，契约面零期望。
    // ("ab","c") 与 ("a","bc") 在不写长度的拼接式摘要下是同一段字节 ⇒ 后者会被前者的
    // 锁定连坐；现在必须各自成键，而"确实锁过"由 teardown 那一把自证。
    for _ in 0..e7.limits().lockout_after {
        let _ = e7.authenticate("ab", "c", "nope");
    }
    let concat_other = e7
        .authenticate("a", "bc", TOKEN)
        .map(|_| "ACCEPTED")
        .unwrap_or_else(|err| err.code);
    f.insert(
        "throttle_pair_concatenation_is_separate".into(),
        json!(
            e7.throttle_locked("ab", "c")
                && concat_other == "ACCEPTED"
                && e7.throttle_locked("teardown", "10.0.0.13")
        ),
    );
    f.insert("concat_other_code".into(), json!(concat_other));
    // R7-W-1：桶衰减把"整台引擎每窗口能记下多少条失败"从一次性消耗品变成**可续额度池**。
    // 这句代价必须能在产品路径上红，而不是只写在契约里。夹具 = 8 行 × 每行
    // `lockout_after - 1` 条失败 × 3 轮，轮间静置 1.5 个窗口，全程用**新**身份。
    // 现状（有衰减）：48 条全是 AUTH_DENIED，一次都不武装。
    // 变异 N6（`decay` 不回收桶）下的**真实**机制（r8 纠正了我上一版——不是"计数粘住、
    // 每行第一条推到阈值"）：第 1 轮 8 行恰好灌满表且永不空，第 2、3 轮的新身份根本
    // 拿不到行 ⇒ 全部走**溢出计数**分支；溢出计数自己的时钟没坏，于是每轮白送
    // `lockout_after - 1` = 2 条 AUTH_DENIED，第 3 条武装全局窗口、其余被短路成
    // THROTTLED ⇒ 实测 16 + 2 + 2 = **20** 条拒绝、**28** 条锁定。r7 §2.1 推的"约 16"
    // 连机制带数字都不对，两个方向都红但只有这套机制解释得上数字。
    let rows = 8usize;
    let rounds = 3usize;
    let mut e8 = engine_at(
        &dir,
        FileLimits {
            max_throttle_buckets: rows,
            lockout_after: 3,
            // 每个地址一个窗口只花 (lockout_after-1) × rounds = 6 条，故意留在源额度
            // 之下——否则这里量到的就是"单源限额开火"而不是"表位可续额度池"。
            // 两层键的池子与单源额度是两道不同的门，各自要有自己的对象。
            max_failures_per_source: 8,
            lockout_window: std::time::Duration::from_millis(100),
            ..Default::default()
        },
    )?;
    let mut denied = 0usize;
    let mut throttled = 0usize;
    for round in 0..rounds {
        for i in 0..rows {
            for _ in 0..(e8.limits().lockout_after - 1) {
                // 一个主体配一个地址：额度池这条判据要的是"很多身份各花一点"。
                let seen = e8
                    .authenticate(&format!("pool{round}-{i}"), &format!("10.0.16.{i}"), "nope")
                    .map(|_| "NONE")
                    .unwrap_or_else(|err| err.code);
                if seen == code::AUTH_DENIED {
                    denied += 1;
                } else if seen == code::THROTTLED {
                    throttled += 1;
                } else {
                    return Err(format!("unexpected throttle code {seen}"));
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(150));
    }
    f.insert("pool_denials_observed".into(), json!(denied));
    f.insert("pool_lockouts_observed".into(), json!(throttled));
    f.insert(
        "throttle_sustainable_failure_budget".into(),
        json!(
            denied == rows * rounds * (e8.limits().lockout_after - 1)
                && throttled == 0
                && !e8.throttle_globally_locked()
        ),
    );
    // 评审 r7 整改清单第 3 条 / r8 R7-N-9：键是按对分的，所以一个源地址本来可以为
    // 任意多个自己 not 拥有的主体把整张表的额度花光。单源额度把这件事变成"这个地址
    // 自己锁一个窗口"，并且**不**牵连别的地址、也不升级为全体 fail-closed。
    let mut e9 = engine_at(
        &dir,
        FileLimits {
            max_throttle_buckets: 64,
            lockout_after: 3,
            max_failures_per_source: 6,
            ..Default::default()
        },
    )?;
    let mut cap_codes = Vec::new();
    for i in 0..6 {
        cap_codes.push(
            e9.authenticate(&format!("many{i}"), "10.0.0.15", "nope")
                .map(|_| "NONE")
                .unwrap_or_else(|err| err.code),
        );
    }
    let same_addr_new_principal = e9
        .authenticate("fresh-same-addr", "10.0.0.15", TOKEN)
        .map(|_| "ACCEPTED")
        .unwrap_or_else(|err| err.code);
    let other_addr_new_principal = e9
        .authenticate("fresh-other-addr", "10.0.0.16", TOKEN)
        .map(|_| "ACCEPTED")
        .unwrap_or_else(|err| err.code);
    if let Ok(sid) = e9.authenticate("fresh-other-addr", "10.0.0.16", TOKEN) {
        let _ = e9.close_session(sid, "10.0.0.16");
    }
    f.insert("per_source_cap_codes".into(), json!(cap_codes));
    f.insert(
        "throttle_per_source_budget_scoped_to_address".into(),
        json!(
            cap_codes
                .iter()
                .filter(|c| **c == code::AUTH_DENIED)
                .count()
                == 5
                && cap_codes.last().map(|c| *c == code::THROTTLED) == Some(true)
                && e9.throttle_source_locks() == 1
                && !e9.throttle_globally_locked()
                && same_addr_new_principal == code::THROTTLED
                && other_addr_new_principal == "ACCEPTED"
        ),
    );
    // r8 R8-W-2 的根因这一半：`close_session` 现在要出示与会话相同的传输地址。
    // 拒绝时必须什么都没发生（会话还在、`.part` 还在），且审计行与"id 不存在"同形。
    let mut e10 = engine_at(&dir, FileLimits::default())?;
    let owned = e10
        .authenticate("owner", "10.0.0.17", TOKEN)
        .map_err(|x| x.to_string())?;
    let stream = e10
        .open_upload(owned, "downloads", "keep.bin", None)
        .map_err(|x| x.to_string())?;
    e10.stage_chunk(owned, stream, 0, b"abc")
        .map_err(|x| x.to_string())?;
    let foreign = e10
        .close_session(owned, "10.0.0.18")
        .map(|_| "ACCEPTED")
        .map_err(|err| err.code)
        .unwrap_or_else(|c| c);
    let parts_after = std::fs::read_dir(&dir)
        .map_err(|e| e.to_string())?
        .flatten()
        .filter(|d| d.file_name().to_string_lossy().contains("nexus-part"))
        .count();
    let still_usable = e10.stat(owned, "downloads", ".").is_ok();
    // 同形性必须**在审计面上**也成立，否则"不做存在性 oracle"这句只是返回值层面：
    // 未知 id 与不属于自己的 id 两行的 action/principal/root/result_code 逐格相同，
    // rel 两处都必须是那个数字 id（它本来就不同，形如 "999999" vs "1"）。
    let rows_before = e10.audit().len();
    let _ = e10.close_session(999_999, "10.0.0.18");
    let unknown_row = e10
        .audit()
        .back()
        .expect("fixture: refusal recorded")
        .clone();
    let _ = e10.close_session(owned, "10.0.0.18");
    let foreign_row = e10
        .audit()
        .back()
        .expect("fixture: refusal recorded")
        .clone();
    let same_shape = unknown_row.action == foreign_row.action
        && unknown_row.principal == foreign_row.principal
        && unknown_row.root == foreign_row.root
        && unknown_row.result_code == foreign_row.result_code
        && unknown_row.principal.is_empty()
        && foreign_row.result_code == code::NOT_FOUND
        && e10.audit().len() == rows_before + 2;
    let owned_close = e10.close_session(owned, "10.0.0.17");
    f.insert(
        "foreign_close_audit_shape_is_indistinguishable".into(),
        json!(same_shape),
    );
    f.insert(
        "audit_rows_for_refused_closes".into(),
        json!([unknown_row.result_code, foreign_row.result_code]),
    );
    f.insert(
        "foreign_close_refused_and_session_survives".into(),
        json!(
            foreign == code::NOT_FOUND
                // 被拒的拆除不许删掉别人的暂存文件——这才是真正的破坏面
                && parts_after == 1
                && still_usable
                && owned_close.is_ok()
                && e10.stat(owned, "downloads", ".").is_err()
        ),
    );
    // 从 r1 挂到现在的残余："没有任何断言约束 authenticate 真的用 constant_time_eq"。
    // 现在有了计数：可比较的尝试恰好 +1，被锁定短路的尝试 +0。
    let mut e11 = engine_at(
        &dir,
        FileLimits {
            lockout_after: 2,
            ..Default::default()
        },
    )?;
    let base_compares = e11.token_comparisons();
    let _ = e11.authenticate("meter", "10.0.0.19", "nope");
    let after_one = e11.token_comparisons();
    for _ in 0..(e11.limits().lockout_after - 1) {
        let _ = e11.authenticate("meter", "10.0.0.19", "nope");
    }
    let after_armed = e11.token_comparisons();
    let locked_code = e11
        .authenticate("meter", "10.0.0.19", TOKEN)
        .map(|_| "ACCEPTED")
        .unwrap_or_else(|err| err.code);
    let after_locked_attempts = e11.token_comparisons();
    f.insert(
        "token_comparisons_short_circuit_when_locked".into(),
        json!(
            after_one == base_compares + 1
                && after_armed == base_compares + e11.limits().lockout_after
                && locked_code == code::THROTTLED
                && after_locked_attempts == after_armed
        ),
    );
    // 空传输地址在**进入节流器之前**就被拒（评审 r9 R9-W-1：本批两个新机制都键在地址串
    // 上，空串会让五个消费点共用同一个退化键——归属、单源额度、源锁、per-peer 配额、
    // `(主体,源)` 摘要键的源那一半；r11 R11-W-2 把早先"三处"的说法对齐）。契约面要的不
    // 只是返回码：它一次令牌比较都不做，也不在节流的两张源表里留下任何东西。
    let empty_compares = e11.token_comparisons();
    let empty_buckets = e11.throttle_buckets();
    let empty_ledgers = e11.throttle_source_ledgers();
    let empty_code = e11
        .authenticate("nolist", "", TOKEN)
        .map(|_| "ACCEPTED")
        .unwrap_or_else(|err| err.code);
    f.insert(
        "empty_source_is_refused_before_the_throttle".into(),
        json!(
            empty_code == code::AUTH_DENIED
                && e11.token_comparisons() == empty_compares
                && e11.throttle_buckets() == empty_buckets
                && e11.throttle_source_ledgers() == empty_ledgers
        ),
    );
    // r10 R10-N-4：引擎**不**归一化传输地址 ⇒ 同一条物理地址的两种写法各拿**一份**单源
    // 额度，归属检查也按字符串判。契约面钉住"分账"那一格（`close_session` 的漂移后果由
    // 单测 address_representation_drift_arms_two_independent_source_locks 负责，探针不重做
    // 文件系统夹具）。将来谁加了归一化，这条会红，G16/PRODUCT/REQ-010 的散文必须同步。
    let mut e13 = engine_at(
        &dir,
        FileLimits {
            // 4 == 4：G12 的交叉规则要求 `max_failures_per_source >= lockout_after`（第一版
            // 写成 9/4 直接被 `validate` 拒了，D0 复跑当场红——见本节 D 轮第 1 点）。于是
            // pair 侧在这道夹具里也会武装，最后的断言换一个**从没失败过**的主体，让
            // "是谁把这次请求拒了"没有第二种解释。
            lockout_after: 4,
            max_failures_per_source: 4,
            ..Default::default()
        },
    )?;
    const BARE_IPV6: &str = "2001:db8::1";
    const BRACKET_IPV6: &str = "[2001:db8::1]:44337";
    let drift_budget = e13.limits().max_failures_per_source;
    for _ in 0..drift_budget {
        let _ = e13.authenticate("probe", BARE_IPV6, "wrong");
        let _ = e13.authenticate("probe", BRACKET_IPV6, "wrong");
    }
    let drift_locked_code = e13
        .authenticate("bystander", BARE_IPV6, TOKEN)
        .map(|_| "ACCEPTED")
        .unwrap_or_else(|err| err.code);
    f.insert(
        "address_representation_drift_splits_the_source_budget".into(),
        json!(
            e13.throttle_source_locks() == 2
                && e13.throttle_source_ledgers() == 0
                && drift_locked_code == code::THROTTLED
        ),
    );
    // r12 R12-W-1：上面 e13 钉的是**机制**（摘要吃不吃地址），这条钉**数量**——同一 principal
    // 用两种写法 ⇒ 两个桶 ⇒ pair 侧门槛翻倍。方向与"共享桶提前武装"相反，所以两格一起读才
    // 不失真：交替喂 2×(lockout_after-1) 条不该武装，同总量的单写法必须已经武装。
    let mut e14 = engine_at(
        &dir,
        FileLimits {
            lockout_after: 3,
            max_failures_per_source: 8,
            ..Default::default()
        },
    )?;
    const DRIFT_A: &str = "2001:db8::7";
    const DRIFT_B: &str = "[2001:db8::7]:44337";
    for _ in 0..(e14.limits().lockout_after - 1) {
        let _ = e14.authenticate("split", DRIFT_A, "wrong");
        let _ = e14.authenticate("split", DRIFT_B, "wrong");
    }
    // **必须在出示正确令牌之前取桶数**：成功认证会 `succeed()` 清掉它自己那一格，
    // 事后读就成了 1 而不是 2。这一格是 E4 期望当场把我抓红的——单测里同样的夹具因为
    // 断言顺序正确而一直是绿的，两个对象对同一个顺序错误只有一边有杀伤力。
    let spread_buckets = e14.throttle_buckets();
    let spread_code = e14
        .authenticate("split", DRIFT_A, TOKEN)
        .map(|_| "ACCEPTED")
        .unwrap_or_else(|err| err.code);
    let mut e14b = engine_at(
        &dir,
        FileLimits {
            lockout_after: 3,
            max_failures_per_source: 8,
            ..Default::default()
        },
    )?;
    for _ in 0..(2 * (e14b.limits().lockout_after - 1)) {
        let _ = e14b.authenticate("split", DRIFT_A, "wrong");
    }
    let single_code = e14b
        .authenticate("split", DRIFT_A, TOKEN)
        .map(|_| "ACCEPTED")
        .unwrap_or_else(|err| err.code);
    f.insert(
        "pair_threshold_doubles_across_address_spellings".into(),
        json!(spread_buckets == 2 && spread_code == "ACCEPTED" && single_code == code::THROTTLED),
    );
    // 源账本满 ⇒ 陌生地址的**第一条**失败就被锁（fail-closed，不给它建行），并且
    // 锁表自己也有门禁：满了就与两层键同一条大路一致，升级为全局窗口
    // （评审 r9 R9-W-2：没有这道门禁时，"每条失败换一条表项"是最便宜的内存放大）。
    let mut e12 = engine_at(
        &dir,
        FileLimits {
            max_throttle_buckets: 2,
            lockout_after: 9,
            max_failures_per_source: 12,
            ..Default::default()
        },
    )?;
    for i in 0..2 {
        let _ = e12.authenticate(&format!("ledger{i}"), &format!("10.0.8.{i}"), "nope");
    }
    let ledger_full = e12.throttle_source_ledgers() == 2;
    let first_two_locked = (0..2)
        .filter(|i| {
            e12.authenticate(&format!("fresh{i}"), &format!("10.0.9.{i}"), "nope")
                .map(|_| false)
                .unwrap_or_else(|err| err.code == code::THROTTLED)
        })
        .count();
    let escalated_to_global = {
        let _ = e12.authenticate("one-too-many", "10.0.9.9", "nope");
        e12.throttle_globally_locked()
            && e12.throttle_source_locks() <= e12.limits().max_throttle_buckets
            && e12
                .authenticate("anyone", "10.0.9.10", TOKEN)
                .map(|_| false)
                .unwrap_or_else(|err| err.code == code::THROTTLED)
    };
    f.insert(
        "unknown_source_locked_on_first_failure_when_ledger_full".into(),
        json!(ledger_full && first_two_locked == 2 && escalated_to_global),
    );
    cleanup(&dir);
    Ok(())
}

fn quota_backpressure(f: &mut Map<String, Value>) -> Result<(), String> {
    let dir = fixture("quota")?;
    let source: Vec<u8> = (0..40u8).collect();
    std::fs::write(dir.join("big.bin"), &source).map_err(|e| e.to_string())?;
    let limits = FileLimits {
        chunk_bytes: 8,
        // G12 要求 per-session in-flight <= 共享预算，这里取等号：让**共享发送
        // 预算**成为本案的约束（per-session 上限单独用第三个引擎验，避免两个
        // 约束互相掩盖）。评审 F1：预算必须真的接在引擎上，不是探针手搓一份。
        max_inflight_bytes_per_session: 128,
        // 这条 fixture 必须同时把 ack 上限压到预算之内，否则被 G12 的交叉约束
        // 直接拒启动（第一版探针就是这样失败的——那个拒绝本身是契约想要的答案）；
        // 它同时不能低于"信封 + 一个条目"的下限，否则 list 页永远截断成 0 条。
        max_ack_bytes: 128,
        max_read_handles: 4,
        max_sessions: 2,
        max_browser_sessions: 1,
        max_buffered_amount: 128,
        ..Default::default()
    };
    let mut e = engine_at(&dir, limits.clone())?;
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

    // 灌满共享预算走的是引擎的过账入口（wire 层报真实序列化长度），
    // 不是探针自己 new 一个 SendBudget。
    let mut file_accepted = 0usize;
    let mut overflow_code = "NONE";
    for _ in 0..64 {
        match e.send_file_message(s, 8) {
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
    f.insert(
        "file_drops_reported".into(),
        json!(e.budget().file_drops > 0),
    );
    f.insert("file_accepted_before_overflow".into(), json!(file_accepted));
    f.insert("budget_limit".into(), json!(e.budget().limit));
    f.insert("budget_buffered".into(), json!(e.budget().buffered()));

    // Terminal class: 100 messages must all be delivered with zero drops.
    let mut delivered = 0usize;
    let mut failed = 0usize;
    for _ in 0..100 {
        if e.send_terminal(4).is_ok() {
            delivered += 1;
            e.settle_terminal(4);
        } else {
            failed += 1;
        }
    }
    f.insert("ssh_messages_delivered".into(), json!(delivered));
    f.insert("ssh_messages_dropped".into(), json!(failed));
    // 评审 r1 F2 的机器化，并按 r2 NEW-5 的意见改成**独立一段**：上一版把断言挂在
    // "100 条 4 字节终端消息之后"，队列深度就取决于挤占次序，静态读法能算出 0
    // 而主机实测是 15 —— 同一个字段两种读法，这种证据不合格。现在用一台全新引擎：
    // 灌满 → 一次整预算的终端发送 → 被挤掉的条数必须**恰好等于**灌进去的条数。
    let mut eb = engine_at(&dir, limits.clone())?;
    let sb = auth(&mut eb)?;
    let mut queued = 0usize;
    while eb.send_file_message(sb, 8).is_ok() {
        queued += 1;
        if queued > 64 {
            return Err("file queue did not bound".to_string());
        }
    }
    let drops_before = eb.budget().file_drops;
    let final_limit = eb.budget().limit;
    let terminal_ok = eb.send_terminal(final_limit).is_ok();
    let squeezed = eb.budget().file_drops - drops_before;
    f.insert("messages_queued_before_final_send".into(), json!(queued));
    f.insert("file_messages_squeezed_out".into(), json!(squeezed));
    f.insert("final_terminal_send_ok".into(), json!(terminal_ok));
    f.insert(
        "pending_messages_after_final_send".into(),
        json!(eb.budget().pending_file_messages()),
    );
    f.insert(
        "squeeze_accounting_is_per_message".into(),
        json!(
            queued > 1
                && terminal_ok
                && squeezed == queued
                && eb.budget().pending_file_messages() == 0
        ),
    );
    // r2 NEW-2 第 1 点：被挤掉的消息必须同时回冲它自己会话的 in-flight 额度，
    // 否则客户端只能去 ack 一份它从未收到的页。
    f.insert(
        "inflight_released_on_squeeze".into(),
        json!(eb.inflight_bytes(sb) == 0 && eb.inflight_matches_budget(sb)),
    );
    // r2 NEW-2 第 2 点：会话拆除（断线/闲置）必须归还共享预算。
    let mut et = engine_at(&dir, limits.clone())?;
    let st_ = auth(&mut et)?;
    et.send_file_message(st_, 8).map_err(|x| x.to_string())?;
    let held = et.budget().buffered();
    et.close_session(st_, "127.0.0.1")
        .map_err(|x| x.to_string())?;
    f.insert("teardown_held_bytes".into(), json!(held));
    f.insert(
        "teardown_releases_budget".into(),
        json!(held == 8 && et.budget().buffered() == 0 && et.budget().pending_file_messages() == 0),
    );
    // r2 NEW-4：会话配额是**准入**检查，不是只在 validate 里比一下。
    let mut ea = engine_at(&dir, limits.clone())?;
    let admission: Vec<FileResult<u64>> = (0..8)
        .map(|_| ea.authenticate("quota-probe", "10.0.0.7", TOKEN))
        .collect();
    let accepted = admission.iter().filter(|r| r.is_ok()).count();
    let admission_code = admission
        .iter()
        .find_map(|r| r.as_ref().err().map(|e| e.code))
        .unwrap_or("NONE");
    let first_session = admission.iter().find_map(|r| r.as_ref().ok()).copied();
    f.insert("sessions_accepted".into(), json!(accepted));
    f.insert("max_sessions".into(), json!(ea.limits().max_sessions));
    f.insert(
        "max_browser_sessions".into(),
        json!(ea.limits().max_browser_sessions),
    );
    f.insert(
        "session_admission_capped".into(),
        json!(accepted == ea.limits().max_browser_sessions && admission_code == code::CAPACITY),
    );
    // r2 W-4：0 字节页请求必须显式拒，否则 next_offset 原地踏步。
    let zero_err = first_session
        .map(|sid| {
            ea.read_page(sid, "downloads", "big.bin", 0, 0)
                .map(|_| "NONE")
                .unwrap_or_else(|err| err.code)
        })
        .unwrap_or("NO_SESSION");
    f.insert(
        "zero_byte_page_refused".into(),
        json!(zero_err == code::PAGE_TOO_LARGE),
    );

    // 真实下载路径同样过账：read_page 不 settle 就会在预算耗尽时显式 QUEUE_FULL，
    // ack 之后才能继续（G18 拉式）。这一段证明预算长在引擎上，不是模型。
    let mut e2 = engine_at(&dir, limits.clone())?;
    let s2 = auth(&mut e2)?;
    let first = e2
        .read_page(s2, "downloads", "big.bin", 0, 8)
        .map_err(|x| x.to_string())?;
    f.insert(
        "read_page_charged_to_shared_budget".into(),
        json!(e2.budget().file_buffered() == first.bytes.len() && e2.inflight_bytes(s2) == 8),
    );
    let mut page_overflow_code = "NONE";
    for _ in 0..64 {
        match e2.read_page(s2, "downloads", "big.bin", 0, 8) {
            Ok(_) => {}
            Err(err) => {
                page_overflow_code = err.code;
                break;
            }
        }
    }
    f.insert("read_page_overflow_code".into(), json!(page_overflow_code));
    // 对端 ack 一页 ⇒ 预算与 per-session in-flight 同时释放，下载可以继续。
    e2.settle_file(s2, 8);
    f.insert(
        "settle_releases_budget_and_inflight".into(),
        json!(
            e2.inflight_bytes(s2) == e2.budget().file_buffered()
                && e2.read_page(s2, "downloads", "big.bin", 0, 8).is_ok()
        ),
    );

    // per-session in-flight 上限是独立约束：共享预算宽裕时它也必须生效。
    // 走 `send_file_message` 而不是 `read_page`：夹具里 big.bin 只有 40 字节，
    // 读不出 128 字节的在途量，而这条要验的是额度记账不是文件内容。
    let mut e3 = engine_at(
        &dir,
        FileLimits {
            max_inflight_bytes_per_session: 128,
            max_ack_bytes: 128,
            max_buffered_amount: 4096,
            ..limits.clone()
        },
    )?;
    let s3 = auth(&mut e3)?;
    let mut charged = 0usize;
    while e3.send_file_message(s3, 8).is_ok() {
        charged += 1;
        if charged > 64 {
            return Err("per-session ceiling never bound".to_string());
        }
    }
    f.insert("inflight_bytes_before_ceiling".into(), json!(charged * 8));
    f.insert(
        "per_session_inflight_ceiling_enforced".into(),
        json!(
            charged * 8 == 128
                && e3.budget().file_buffered() == 128
                && e3.budget().limit == 4096
                && e3.inflight_matches_budget(s3)
        ),
    );

    // Read handles stay inside the budget across many pages of one download.
    let mut e4 = engine_at(&dir, limits)?;
    let s4 = auth(&mut e4)?;
    let mut pages = 0usize;
    let mut offset = 0u64;
    loop {
        let p = e4
            .read_page(s4, "downloads", "big.bin", offset, 8)
            .map_err(|x| x.to_string())?;
        pages += 1;
        // 拉式协议：每页落地后才取下一页（同时释放预算与 in-flight）。
        e4.settle_file(s4, p.bytes.len());
        if p.eof {
            break;
        }
        offset = p.next_offset;
        if pages > 64 {
            return Err("download did not terminate".to_string());
        }
    }
    let (live, peak) = e4.handle_stats();
    f.insert("pages_read".into(), json!(pages));
    f.insert(
        "peak_read_handles_within_budget".into(),
        json!(peak <= e4.limits().max_read_handles && live == 0),
    );
    f.insert("peak_read_handles".into(), json!(peak));
    f.insert("live_read_handles".into(), json!(live));
    f.insert("handle_budget".into(), json!(e4.limits().max_read_handles));

    // Oversized declared upload is refused before any bytes are staged.
    let big = e4.open_upload(
        s4,
        "downloads",
        "huge.bin",
        Some(e4.limits().max_upload_bytes + 1),
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

/// 拒绝**且理由是符号链接**才算数。旧写法只看 `is_err()`，于是把 `resolve` 的
/// 符号链接检查整段删掉，这两个字段仍然 true（`list` 会因 read_dir 失败、
/// `mkdir` 会因 create_dir_all 失败而"看起来拒了"）——评审 r2 W-6。
fn refuses_link<T>(r: FileResult<T>) -> Value {
    json!(match r {
        Err(err) => err.code == code::SYMLINK_ESCAPE,
        Ok(_) => false,
    })
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

/// 配置接线面（`files` 段）的对象集合：关断默认、关断不免责、开起来必须自洽、
/// 数值镜像必须逐字段精确、以及"合法配置真的能起出引擎"。
///
/// 与单测的分工：单测管因果与错误信息可执行，这里管**同一批性质在 JSON 路径上成立**
/// （运维面上到的是 JSON，不是 Rust 字面量）。
fn gateway_config(f: &mut Map<String, Value>) -> Result<(), String> {
    let dir = fixture("config")?;
    let root_path = dir.display().to_string();

    // 1) 老配置（没有 files 段）必须等价于关断，并且结构性地起不出引擎。
    //
    // 这两格**故意不早退**（评审 r14 N-1 登记的那条改进）：以前这里用 `map_err(...)?`，
    // 于是 MC05/MC06/MC11/MC12 四条配方只能以"探针整体 FAIL、21 个字段缺席"的形式被拦住——
    // 第三方从翻转名单里看不出是哪一条宣称坏了。改成记 `false` 继续跑，杀伤就落在自己那一格上。
    // 语义不变：解析不过 / 关断态起出了引擎 / 关断态构造报错，三种都算这格为假。
    let legacy: Option<GatewayConfig> = GatewayConfig::from_json_str(
        r#"{"listen_addr":"127.0.0.1:8443","node_id":"a","node_name":"a",
            "node_list":[{"peer_id":"a","name":"a"}],
            "tls":{"mode":"auto_generate","names":[],"ips":[]}}"#,
    )
    .ok();
    let absent_disabled = legacy.as_ref().is_some_and(|c| !c.files.enabled);
    let disabled_no_engine = legacy
        .as_ref()
        .and_then(|c| c.file_engine().ok())
        .is_some_and(|engine| engine.is_none());
    f.insert("absent_section_is_disabled".into(), json!(absent_disabled));
    f.insert(
        "disabled_yields_no_engine".into(),
        json!(disabled_no_engine),
    );

    // 2) 关断不免责：坏表在 `enabled = false` 时也必须拒（否则打开的那天静默上线）。
    let mut off_bad_pairing = base_files();
    off_bad_pairing.enabled = false;
    off_bad_pairing.max_ack_bytes = off_bad_pairing.max_inflight_bytes_per_session + 1;
    let disabled_rejects_pairing = base_config(off_bad_pairing).validate().is_err();
    let mut off_zero_ceiling = base_files();
    off_zero_ceiling.enabled = false;
    off_zero_ceiling.chunk_bytes = 0;
    let disabled_rejects_zero = base_config(off_zero_ceiling).validate().is_err();
    f.insert(
        "disabled_still_rejects_inconsistent_table".into(),
        json!(disabled_rejects_pairing),
    );
    f.insert(
        "disabled_still_rejects_zero_ceiling".into(),
        json!(disabled_rejects_zero),
    );

    // 3) 打开时的必备项：令牌（含只含空白的）、根列表、别名。
    let mut no_token = base_files();
    no_token.enabled = true;
    no_token.roots = vec![FileRootConfig {
        alias: "downloads".into(),
        path: root_path.clone(),
        read_only: false,
    }];
    no_token.token = String::new();
    let rejected_no_token = base_config(no_token.clone()).validate().is_err();
    no_token.token = "   ".into();
    let rejected_blank_token = base_config(no_token.clone()).validate().is_err();
    let mut no_roots = no_token.clone();
    no_roots.token = "s3cret".into();
    no_roots.roots.clear();
    let rejected_no_roots = base_config(no_roots).validate().is_err();
    let mut blank_alias = no_token.clone();
    blank_alias.token = "s3cret".into();
    blank_alias.roots[0].alias = " ".into();
    let rejected_blank_alias = base_config(blank_alias).validate().is_err();
    let mut dup_alias = no_token.clone();
    dup_alias.token = "s3cret".into();
    dup_alias.roots.push(FileRootConfig {
        alias: "downloads".into(),
        path: root_path.clone(),
        read_only: true,
    });
    let rejected_dup_alias = base_config(dup_alias).validate().is_err();
    f.insert(
        "enabled_without_token_rejected".into(),
        json!(rejected_no_token),
    );
    f.insert(
        "whitespace_only_token_rejected".into(),
        json!(rejected_blank_token),
    );
    f.insert(
        "enabled_without_roots_rejected".into(),
        json!(rejected_no_roots),
    );
    f.insert(
        "blank_root_alias_rejected".into(),
        json!(rejected_blank_alias),
    );
    f.insert(
        "duplicate_root_alias_rejected".into(),
        json!(rejected_dup_alias),
    );

    // 4) 别名/路径的**存在性**在启动前挡下：配置面允许一个不存在的目录通过 validate，
    //    但 `file_engine()` 必须失败——否则变成随机启动失败。
    let mut ghost_root = base_files();
    ghost_root.enabled = true;
    ghost_root.token = "s3cret".into();
    ghost_root.roots = vec![FileRootConfig {
        alias: "downloads".into(),
        path: dir.join("does-not-exist").display().to_string(),
        read_only: false,
    }];
    let ghost = base_config(ghost_root);
    // `FileEngine` 不实现 Debug，所以这里不能 `{other:?}`——探针本身也编译不过就等于
    // 没有这条对象。分三支把"拿到的是什么"写成可执行的错误信息。
    // 收紧（覆盖率那节的空档）：只写 `Err(Config(_)) => true` 的话，"被别的原因拒"也算过——
    // 变异 MC18（打开根失败就静默丢掉这个根，最后由"至少要有一个根"兜住）照样给
    // `Err(Config)`，那一格就不会翻。红因必须是**路径检查本身**。
    let missing_path_rejected = match ghost.file_engine() {
        Err(GatewayError::Config(msg)) => msg.contains("files.roots"),
        Err(other) => {
            return Err(format!("不存在的根必须以 Config 错误被拒，拿到 {other}"));
        }
        Ok(Some(_)) => {
            return Err("不存在的根必须被拒，却起出了引擎".into());
        }
        Ok(None) => {
            return Err("enabled=true 的配置必须起得出引擎，却拿到 None".into());
        }
    };
    f.insert(
        "missing_root_path_rejected".into(),
        json!(missing_path_rejected),
    );

    // 5) 数值镜像必须逐字段相等；时长换算成引擎的 Duration 单位。
    let mirrored = {
        let d = base_files();
        let l = d.to_limits();
        let e = FileLimits::default();
        l.chunk_bytes == e.chunk_bytes
            && l.max_entries_per_page == e.max_entries_per_page
            && l.max_ack_bytes == e.max_ack_bytes
            && l.max_sessions == e.max_sessions
            && l.max_browser_sessions == e.max_browser_sessions
            && l.max_read_handles == e.max_read_handles
            && l.max_inflight_bytes_per_session == e.max_inflight_bytes_per_session
            && l.max_upload_bytes == e.max_upload_bytes
            && l.max_rehash_bytes_per_stream == e.max_rehash_bytes_per_stream
            && l.idle_timeout == e.idle_timeout
            && l.lockout_after == e.lockout_after
            && l.lockout_window == e.lockout_window
            && l.max_throttle_buckets == e.max_throttle_buckets
            && l.max_failures_per_source == e.max_failures_per_source
            && l.max_buffered_amount == e.max_buffered_amount
    };
    let units = {
        let mut c = base_files();
        c.idle_timeout_secs = 77;
        c.lockout_window_secs = 13;
        let l = c.to_limits();
        l.idle_timeout == Duration::from_secs(77) && l.lockout_window == Duration::from_secs(13)
    };
    f.insert("limits_round_trip_is_exact".into(), json!(mirrored));
    f.insert("durations_map_to_engine_units".into(), json!(units));

    // 6) 窗口两侧界。这里钉的其实是**两件事**，评审 r15 W-1 要求把它们分开写：
    //    ① 可诊断性：错误串必须点名坏掉的那个旋钮（`files.lockout_window_secs`），
    //       运维才知道改哪一行；
    //    ② 安全性：越界值起不出引擎——这一条**不依赖"是哪一层答的"**，因为配置层与
    //       引擎层这两道界的判定集合相同，删掉任一侧都还是拒（评审方的 R15A 正是
    //       "删配置层那条 + 把标签搬进引擎消息"，实测 0 红 0 翻，而行为只差在文本上）。
    //    所以"各钉一层"这个说法先前是**写过界的**，现已在 MODULE/PRODUCT/REQ 三处降级成
    //    上面这两条；配对的真正杀伤对象是 MC03/MC04（拆委托 / 只在开时校验）。
    //    引擎那半仍由 `to_limits().validate()` 直调钉住——它是"至少一层要拦"的对象，不是"层身份"的对象。
    let mut on_files = base_files();
    on_files.enabled = true;
    on_files.token = "s3cret".into();
    on_files.roots = no_token.roots.clone();
    on_files.lockout_window_secs = MIN_FILE_LOCKOUT_WINDOW_SECS;
    let rejected_sub_second = {
        let mut c = on_files.clone();
        c.lockout_window_secs = 0;
        refused_by_config_bound(&config_err(&base_config(c)))
    };
    let floor_is_usable = base_config(on_files.clone()).validate().is_ok();
    let rejected_over_24h = {
        let mut c = on_files.clone();
        c.lockout_window_secs = MAX_FILE_WINDOW_SECS + 1;
        let cfg_err = config_err(&base_config(c.clone()));
        let over = refused_by_config_bound(&cfg_err);
        // 引擎层单独调，不经委托：删引擎那条 24h 也会翻这里。
        over && c.to_limits().validate().is_err()
    };
    f.insert(
        "sub_second_window_rejected_by_config".into(),
        json!(rejected_sub_second && floor_is_usable),
    );
    f.insert(
        "over_24h_window_rejected_by_config".into(),
        json!(rejected_over_24h),
    );

    // 6b) `idle_timeout` 的两侧界同样各钉一层。评审 r14 W-1 的 NEW20 配方把配置层那条
    //     idle 24h 上界拆掉，实测 **0 条单测红、0 条期望翻转**——委托让引擎那条同规则
    //     替它答话，而我先前只给 `lockout_window` 写过带层标签的对象。这里补上：
    //     串里含 `files.idle_timeout_secs` 才算配置层答的；引擎那半由 `to_limits()` 直接调。
    let rejected_idle_floor = {
        let mut c = on_files.clone();
        c.idle_timeout_secs = 0;
        config_err(&base_config(c)).contains("files.idle_timeout_secs")
    };
    let idle_floor_is_usable = {
        let mut c = on_files.clone();
        c.idle_timeout_secs = 1;
        base_config(c).validate().is_ok()
    };
    let rejected_idle_ceiling = {
        let mut c = on_files.clone();
        c.idle_timeout_secs = MAX_FILE_WINDOW_SECS + 1;
        config_err(&base_config(c.clone())).contains("files.idle_timeout_secs")
            && c.to_limits().validate().is_err()
    };
    f.insert(
        "idle_floor_rejected_by_config_layer".into(),
        json!(rejected_idle_floor && idle_floor_is_usable),
    );
    f.insert(
        "idle_ceiling_rejected_by_config_layer".into(),
        json!(rejected_idle_ceiling),
    );

    // 6c) 边界**本身必须可用**（评审 r15 R15B 的形状：把上界写成 `>=` 之后，
    //     恰好等于 24h 的合法配置也被拒，而"越界必须被拒"那几格照样绿——因为它们的
    //     红是引擎替它红的话，两侧同集合时删任一侧都不改变判定）。
    //     这两格是**加法**，不动任何已冻结的期望：冻结的那几条继续只管"越界要拒"，
    //     新加的两条专门管"边界值不许被误杀"。
    let window_ceiling_is_usable = {
        let mut c = on_files.clone();
        c.lockout_window_secs = MAX_FILE_WINDOW_SECS;
        base_config(c).validate().is_ok()
    };
    let idle_ceiling_is_usable = {
        let mut c = on_files.clone();
        c.idle_timeout_secs = MAX_FILE_WINDOW_SECS;
        base_config(c).validate().is_ok()
    };
    f.insert(
        "window_ceiling_boundary_is_usable".into(),
        json!(window_ceiling_is_usable),
    );
    f.insert(
        "idle_ceiling_boundary_is_usable".into(),
        json!(idle_ceiling_is_usable),
    );

    // 7) 单源额度的两条交叉界必须在真实配置路径上跑到（G12）。
    let rejected_low = {
        let mut c = on_files.clone();
        c.max_failures_per_source = c.lockout_after - 1;
        base_config(c).validate().is_err()
    };
    let rejected_huge = {
        let mut c = on_files.clone();
        c.max_failures_per_source = c.max_throttle_buckets * c.lockout_after + 1;
        base_config(c).validate().is_err()
    };
    f.insert(
        "source_budget_below_pair_threshold_rejected".into(),
        json!(rejected_low),
    );
    f.insert(
        "source_budget_above_table_capacity_rejected".into(),
        json!(rejected_huge),
    );

    // 7b) 构造缝自己必须检验：**不合法的开启态表不能起出引擎**。
    // "先 validate 再构造"这句话在没有这条期望之前只是注释——变异 MC07（把缝里那句
    // `self.validate()?` 删掉）在第一版对象集上实测 0 条单测红、0 条期望翻转。
    let mut inconsistent = on_files.clone();
    inconsistent.chunk_bytes = 0;
    let engine_refused = match base_config(inconsistent).file_engine() {
        Err(GatewayError::Config(msg)) => msg.contains("files limits"),
        Err(other) => {
            return Err(format!("不合法的表必须以 Config 类错误被拒，拿到 {other}"));
        }
        Ok(_) => false,
    };
    f.insert(
        "invalid_table_yields_no_engine".into(),
        json!(engine_refused),
    );

    // 7c) 缝上**只有配置层才有**的两条规则。评审 r13 W-1 指出 7b 的红是词法性的：
    //     `FileEngine::new` 第一句就 `limits.validate()?`，所以删掉缝里那句 `self.validate()?`
    //     之后坏数值表仍然被拒（只是错误串换了标签）。真正不可替代这条缝的是：
    //     ① 只含空白但非空的令牌——引擎只查 `is_empty()`，照收 "   "；
    //     ② 空白根别名——`SandboxRoot::open` 与 `FileEngine::new` 都不检查别名内容。
    let mut blank_token_cfg = on_files.clone();
    blank_token_cfg.token = "   ".into();
    let blank_token_refused = match base_config(blank_token_cfg).file_engine() {
        Err(GatewayError::Config(msg)) => msg.contains("files.token"),
        Err(other) => {
            return Err(format!("空白令牌必须以 Config 类错误被拒，拿到 {other}"));
        }
        Ok(None) => return Err("enabled=true 时缝不该返回 None，那会把拒绝藏起来".into()),
        Ok(Some(_)) => false,
    };
    let mut blank_alias_cfg = on_files.clone();
    blank_alias_cfg.roots[0].alias = "  ".into();
    let blank_alias_refused = match base_config(blank_alias_cfg).file_engine() {
        Err(GatewayError::Config(msg)) => msg.contains("empty alias"),
        Err(other) => {
            return Err(format!("空白别名必须以 Config 类错误被拒，拿到 {other}"));
        }
        Ok(None) => return Err("enabled=true 时缝不该返回 None".into()),
        Ok(Some(_)) => false,
    };
    f.insert(
        "blank_token_yields_no_engine".into(),
        json!(blank_token_refused),
    );
    f.insert(
        "blank_alias_yields_no_engine".into(),
        json!(blank_alias_refused),
    );

    // 8) 合法配置必须真的起得出引擎，且 JSON 往返不丢这一段。
    let good = base_config(on_files.clone());
    let launched = match good.file_engine() {
        Ok(Some(engine)) => engine.limits().max_sessions == on_files.max_sessions,
        Ok(None) => false,
        Err(err) => return Err(format!("合法配置起不来: {err}")),
    };
    let json = serde_json::to_string(&good).map_err(|e| e.to_string())?;
    let back = GatewayConfig::from_json_str(&json).map_err(|e| e.to_string())?;
    let survived = back.files == on_files && back.files.enabled;
    f.insert("valid_config_launches_engine".into(), json!(launched));
    f.insert(
        "files_section_survives_json_round_trip".into(),
        json!(survived),
    );
    cleanup(&dir);
    Ok(())
}

fn cleanup(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
}

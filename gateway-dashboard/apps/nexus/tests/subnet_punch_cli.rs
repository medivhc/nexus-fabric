//! P4.2 §12.9.6：`subnet punch` CLI 层打洞——错误分类 + 打洞状态观察通道（E2）。
//!
//! 覆盖：空候选 / attempts=0 / 未知 peer / config 缺失的错误分类；
//! up 后状态文件 punch 字段为 null（老文件兼容）；打洞失败（dead 目标耗尽）
//! 仍持久化 punch 记录 → `subnet status` 复查（observability 通道失败分支）。

use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use nexus::subnet_cli::{subnet_punch, subnet_status, subnet_up};

/// 串行化真实 UDP bind 测试（pick_port 有 drop 竞态窗口，并行测试会端口冲突）。
static PORT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
fn port_lock() -> &'static Mutex<()> {
    PORT_LOCK.get_or_init(|| Mutex::new(()))
}

fn tmp_dir() -> PathBuf {
    std::env::temp_dir().join(format!("nexus-p426-it-{}", std::process::id()))
}

fn write_cfg(tag: &str, peer_vip: Option<&str>) -> PathBuf {
    let dir = tmp_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let peer_line = match peer_vip {
        Some(vip) => format!(
            "\n[[subnet.peers]]\n\
             virtual_ip = \"{vip}\"\n\
             locator = \"udp://127.0.0.1:9\"\n"
        ),
        None => String::new(),
    };
    let cfg = format!(
        "[subnet]\n\
         virtual_ip = \"10.0.0.1\"\n\
         cidr = \"10.0.0.0/24\"\n\
         encryption = false{peer_line}\n"
    );
    let path = dir.join(format!("punch.{tag}.toml"));
    std::fs::write(&path, cfg).unwrap();
    path
}

fn state_path(tag: &str) -> PathBuf {
    tmp_dir().join(format!("punch.{tag}.state.json"))
}

/// 系统分配一个空闲 loopback UDP 端口（并行测试避免端口冲突）。
fn pick_port() -> u16 {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = s.local_addr().unwrap().port();
    drop(s);
    port
}

#[test]
fn punch_empty_targets_errors() {
    let cfg = write_cfg("empty", Some("10.0.0.2"));
    let state = state_path("empty");
    subnet_up(&cfg, &state, false).unwrap();
    let err = subnet_punch(&cfg, &state, "10.0.0.2", &[], "udp://127.0.0.1:0", 10)
        .expect_err("empty targets must fail");
    assert!(
        err.starts_with("HOLE_PUNCH_EMPTY_TARGETS"),
        "unexpected: {err}"
    );
}

#[test]
fn punch_zero_attempts_errors() {
    let cfg = write_cfg("zero", Some("10.0.0.2"));
    let state = state_path("zero");
    subnet_up(&cfg, &state, false).unwrap();
    let err = subnet_punch(
        &cfg,
        &state,
        "10.0.0.2",
        &["udp://127.0.0.1:9".to_string()],
        "udp://127.0.0.1:0",
        0,
    )
    .expect_err("zero attempts must fail");
    assert!(err.starts_with("INVALID_ATTEMPTS"), "unexpected: {err}");
}

#[test]
fn punch_unknown_peer_errors() {
    let cfg = write_cfg("unknown", Some("10.0.0.2"));
    let state = state_path("unknown");
    subnet_up(&cfg, &state, false).unwrap();
    let err = subnet_punch(
        &cfg,
        &state,
        "10.0.0.99",
        &["udp://127.0.0.1:9".to_string()],
        "udp://127.0.0.1:0",
        10,
    )
    .expect_err("unknown peer must fail");
    assert!(err.starts_with("PEER_NOT_FOUND"), "unexpected: {err}");
}

#[test]
fn punch_missing_config_errors() {
    let state = state_path("cfgmiss");
    let cfg = write_cfg("cfgmiss", Some("10.0.0.2"));
    subnet_up(&cfg, &state, false).unwrap();
    let missing = tmp_dir().join("missing.toml");
    let err = subnet_punch(
        &missing,
        &state,
        "10.0.0.2",
        &["udp://127.0.0.1:9".to_string()],
        "udp://127.0.0.1:0",
        10,
    )
    .expect_err("missing config must fail");
    assert!(err.starts_with("READ_CONFIG"), "unexpected: {err}");
}

#[test]
fn subnet_status_after_up_punch_is_null() {
    let cfg = write_cfg("null", Some("10.0.0.2"));
    let state = state_path("null");
    subnet_up(&cfg, &state, false).unwrap();
    let status = subnet_status(&state);
    assert_eq!(status["verdict"], "PASS");
    assert!(
        status["subnet"]["punch"].is_null(),
        "punch must be null after up"
    );
}

#[test]
fn punch_invalid_listen_errors() {
    let cfg = write_cfg("listen", Some("10.0.0.2"));
    let state = state_path("listen");
    subnet_up(&cfg, &state, false).unwrap();
    let err = subnet_punch(
        &cfg,
        &state,
        "10.0.0.2",
        &["udp://127.0.0.1:9".to_string()],
        "not-a-locator",
        10,
    )
    .expect_err("invalid listen must fail");
    assert!(err.starts_with("PUNCH_BIND_FAILED"), "unexpected: {err}");
}

#[test]
fn punch_invalid_config_parse_errors() {
    let state = state_path("cfgparse");
    let cfg = write_cfg("cfgparse", Some("10.0.0.2"));
    subnet_up(&cfg, &state, false).unwrap();
    let bad = tmp_dir().join("bad.toml");
    std::fs::write(&bad, "this is [ not valid toml").unwrap();
    let err = subnet_punch(
        &bad,
        &state,
        "10.0.0.2",
        &["udp://127.0.0.1:9".to_string()],
        "udp://127.0.0.1:0",
        10,
    )
    .expect_err("invalid config must fail");
    assert!(err.starts_with("PARSE_TOML"), "unexpected: {err}");
}

#[test]
fn punch_encrypted_state_preserved() {
    let _g = port_lock().lock().unwrap();
    let cfg = write_cfg("enc", Some("10.0.0.2"));
    let state = state_path("enc");
    subnet_up(&cfg, &state, true).unwrap();
    let raw_after_up = std::fs::read(&state).unwrap();
    assert!(
        !raw_after_up.starts_with(b"{"),
        "up must write encrypted state"
    );
    // dead 目标单次尝试 → 失败仍以原加密模式重写（不降级明文）。
    let dead = format!("udp://127.0.0.1:{}", pick_port());
    let lsn = format!("udp://127.0.0.1:{}", pick_port());
    let out = subnet_punch(
        &cfg,
        &state,
        "10.0.0.2",
        std::slice::from_ref(&dead),
        &lsn,
        1,
    )
    .unwrap();
    assert_eq!(out["verdict"], "FAIL");
    let raw_after_punch = std::fs::read(&state).unwrap();
    assert!(
        !raw_after_punch.starts_with(b"{"),
        "punch must preserve encrypted state"
    );
    let status = subnet_status(&state);
    assert_eq!(status["verdict"], "PASS");
    assert_eq!(status["subnet"]["punch"]["succeeded"], false);
}

#[test]
fn punch_failure_persists_state_for_status() {
    let _g = port_lock().lock().unwrap();
    let cfg = write_cfg("fail", Some("10.0.0.2"));
    let state = state_path("fail");
    subnet_up(&cfg, &state, false).unwrap();
    // dead 目标（无监听端口）单次尝试 → 失败仍持久化 punch 记录。
    let dead = format!("udp://127.0.0.1:{}", pick_port());
    let lsn = format!("udp://127.0.0.1:{}", pick_port());
    let out = subnet_punch(
        &cfg,
        &state,
        "10.0.0.2",
        std::slice::from_ref(&dead),
        &lsn,
        1,
    )
    .unwrap();
    assert_eq!(out["verdict"], "FAIL", "dead target must fail");
    let status = subnet_status(&state);
    assert_eq!(status["verdict"], "PASS");
    assert_eq!(status["subnet"]["punch"]["peer_vip"], "10.0.0.2");
    assert_eq!(status["subnet"]["punch"]["succeeded"], false);
    assert_eq!(status["subnet"]["punch"]["attempts"], 1);
}

//! E4: 真实 TUN + sing-box 参照端的 VLESS / AnyTLS / Shadowsocks 出站真流量验证。
//!
//! 场景 `scenarios/product/tun_outbound_vless_flow.toml` /
//! `tun_outbound_anytls_flow.toml` / `tun_outbound_shadowsocks_flow.toml` 的被测进程：
//! - 用 `TunRsDevice` 创建**真实 TUN**（需 CAP_NET_ADMIN；由
//!   `scripts/e4/tun_outbound_ref_flow.sh` 在特权命名空间内启动）；
//! - `Dataplane::new` + `ProxyEngine::new(proxy.yaml)` 装配生产路径；
//! - 常态驱动 `tick(now_millis)`（生产驱动点），把 TUN 上的真实 TCP 流经代理出站转发；
//! - 客户端流量由脚本在独立 netns 注入（目标路由指向本 TUN）。
//!
//! 输出（stdout，单行 JSON）：verdict / outbound.kind / outbound.tag /
//! stats.* / tun.name。状态文件（`--status-file`）在 TUN 就绪后写出，供脚本
//! 配置地址与路由，避免竞态。

use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use nexus_projection::TunDevice;
use nexusd::dataplane::{Dataplane, DataplaneConfig};
use nexusd::proxy_fwd::ProxyEngine;
use serde_json::json;

struct Args {
    kind: String,
    proxy_yaml: PathBuf,
    tun_name: String,
    done_file: PathBuf,
    status_file: PathBuf,
    timeout: Duration,
}

fn parse_args() -> Result<Args, String> {
    let mut kind = String::new();
    let mut proxy_yaml = PathBuf::new();
    let mut tun_name = "nxout0".to_string();
    let mut done_file = PathBuf::new();
    let mut status_file = PathBuf::new();
    let mut timeout_secs = 45u64;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--kind" => kind = args.next().ok_or("missing --kind value")?,
            "--proxy-yaml" => proxy_yaml = PathBuf::from(args.next().ok_or("missing yaml")?),
            "--tun-name" => tun_name = args.next().ok_or("missing tun name")?,
            "--done-file" => done_file = PathBuf::from(args.next().ok_or("missing done file")?),
            "--status-file" => {
                status_file = PathBuf::from(args.next().ok_or("missing status file")?);
            }
            "--timeout-secs" => {
                timeout_secs = args
                    .next()
                    .ok_or("missing timeout")?
                    .parse()
                    .map_err(|_| "bad timeout")?;
            }
            // 机器输出为默认行为；`--json` 仅为与其他 E4 example 的调用约定对齐。
            "--json" => {}
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    if kind.is_empty() || proxy_yaml.as_os_str().is_empty() {
        return Err("--kind and --proxy-yaml are required".to_string());
    }
    if done_file.as_os_str().is_empty() || status_file.as_os_str().is_empty() {
        return Err("--done-file and --status-file are required".to_string());
    }
    Ok(Args {
        kind,
        proxy_yaml,
        tun_name,
        done_file,
        status_file,
        timeout: Duration::from_secs(timeout_secs),
    })
}

fn fail(error: impl Into<String>) -> serde_json::Value {
    json!({"verdict": "FAIL", "error": error.into()})
}

fn main() {
    let output = match run() {
        Ok(value) => value,
        Err(error) => fail(error),
    };
    println!("{}", serde_json::to_string(&output).expect("json"));
    if output["verdict"] != "PASS" {
        std::process::exit(1);
    }
}

fn run() -> Result<serde_json::Value, String> {
    let args = parse_args()?;
    let proxy_yaml = std::fs::read_to_string(&args.proxy_yaml)
        .map_err(|error| format!("read proxy.yaml: {error}"))?;

    let engine = match ProxyEngine::new(Some(&proxy_yaml)) {
        Ok(Some(engine)) => engine,
        Ok(None) => return Err("ProxyEngine::new returned None".to_string()),
        Err(error) => return Err(format!("proxy engine init: {}", error.variant())),
    };
    // E4 可观测：selected 的 kind/tag 由 outbound_manifest::select_index 决定
    // （与 engine 建表同源，N9），不在此处复制选路逻辑。
    let parsed = nexus_proxy_config::parse(&proxy_yaml)
        .map_err(|error| format!("parse proxy.yaml: {error}"))?;
    let selected = nexus::outbound_manifest::select_index(&parsed.outbounds)
        .ok_or_else(|| "no selected proxy outbound".to_string())?;
    let outbound_kind = parsed.outbounds[selected].kind.as_str().to_string();
    let outbound_tag = parsed.outbounds[selected].tag.clone();

    let pattern = format!("{}%d", args.tun_name);
    let tun = nexus_projection::tun_rs_device::TunRsDevice::create(&pattern, 1500)
        .map_err(|error| format!("create TUN: {error}"))?;
    let tun_name = tun.name().to_string();

    let config = DataplaneConfig {
        mesh_cidrs: Vec::new(),
        bypass_cidrs: Vec::new(),
        proxy_configured: true,
        ..Default::default()
    };
    let mut dataplane = Dataplane::new(Box::new(tun), config, None)
        .map_err(|error| format!("dataplane init: {error}"))?;
    dataplane.set_proxy_engine(engine);
    // 生产装配同源：`Dataplane::new` 初始规则为空（fail-closed），必须注入与
    // ProxyEngine 同一份 proxy.yaml 的规则引擎，否则包被判 Drop（P3）。
    dataplane.set_rule_engine(Box::new(
        nexus_proxy::domain_engine::DomainRuleEngine::from_yaml(&proxy_yaml)
            .map_err(|error| format!("dataplane rule engine: {error}"))?,
    ));

    // TUN 就绪：脚本据此配置地址与路由。
    let status = json!({"tun": tun_name});
    write_json(&args.status_file, &status)?;

    let start = Instant::now();
    let deadline = start + args.timeout;
    let mut client_done = false;
    while Instant::now() < deadline {
        let now_millis = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        match dataplane.tick(now_millis) {
            Ok(_) => {}
            Err(error) => return Err(format!("dataplane tick: {error}")),
        }
        if !client_done && args.done_file.exists() {
            client_done = true;
        }
        if client_done {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }

    // 客户端已完成：继续驱动一小段时间，让关闭/回包走完。
    let drain_until = Instant::now() + Duration::from_millis(500);
    while Instant::now() < drain_until {
        let now_millis = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        match dataplane.tick(now_millis) {
            Ok(_) => {}
            Err(error) => return Err(format!("dataplane drain: {error}")),
        }
        std::thread::sleep(Duration::from_millis(1));
    }

    let stats = dataplane.stats();
    let dialed = stats.proxy_forwarded > 0;
    let downlink = stats.proxy_tcp_bytes > 0;
    let verdict = client_done && dialed && downlink && stats.direct_forwarded == 0;

    Ok(json!({
        "verdict": if verdict { "PASS" } else { "FAIL" },
        "client.completed": client_done,
        "outbound.kind": outbound_kind,
        "outbound.tag": outbound_tag,
        "tun.name": tun_name,
        "tun.created": true,
        "stats.proxy_forwarded": stats.proxy_forwarded,
        "stats.proxy_tcp_bytes": stats.proxy_tcp_bytes,
        "stats.proxy_tcp_streams": stats.proxy_tcp_streams,
        "stats.proxy_dropped_no_proxy": stats.proxy_dropped_no_proxy,
        "stats.direct_forwarded": stats.direct_forwarded,
        "stats.tun_written": stats.tun_written,
        "engine.tcp_dials_ok": engine_stats_ok(&stats),
        "expected.kind": args.kind,
    }))
}

/// 兼容字段：`proxy_forwarded` 即 dial 成功数（§6.4 映射）。
fn engine_stats_ok(stats: &nexusd::dataplane::DataplaneStats) -> u64 {
    stats.proxy_forwarded
}

fn write_json(path: &PathBuf, value: &serde_json::Value) -> Result<(), String> {
    let mut file = std::fs::File::create(path).map_err(|error| format!("status file: {error}"))?;
    file.write_all(value.to_string().as_bytes())
        .map_err(|error| format!("status write: {error}"))?;
    Ok(())
}

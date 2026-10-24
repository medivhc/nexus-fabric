//! 产品载波（AC-04 / B8）：生成 proxy.yaml → `proxy_serve_once` 线程 → 最小 SOCKS5 客户端。
//!
//! 只使用产品既有出站字段（§7.3），不新增配置面。

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::Outcome;
use crate::config::{
    Cell, Credentials, HeaderFormat, Hy2Obfs, InteropProbeConfig, Protocol, Variant,
};
use crate::evidence::{ErrorClass, ErrorInfo, Metrics, Verdict};
use crate::util;

/// 协议在产品里的 outbound kind 标签。
#[must_use]
pub fn product_kind(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Vless => "vless",
        Protocol::Anytls => "anytls",
        Protocol::Hysteria2 => "hysteria2",
        Protocol::Trojan => "trojan",
        Protocol::Shadowsocks => "shadowsocks",
    }
}

/// 渲染 proxy.yaml（一条 match 规则 → select_outbound ref）。
pub fn proxy_yaml(cfg: &InteropProbeConfig) -> Result<String, String> {
    let locator = format!("{}:{}", cfg.reference.host, cfg.reference.port);
    let mut out = String::new();
    out.push_str("schema_version: 1\n");
    out.push_str("rules:\n");
    out.push_str("  - tag: rule-match\n    kind: match\n    match: \"\"\n");
    out.push_str("    action:\n      - kind: select_outbound\n        tag: ref\n");
    out.push_str("outbounds:\n  - tag: ref\n");
    match (&cfg.protocol, &cfg.credentials) {
        (Protocol::Vless, Credentials::Vless(c)) => {
            out.push_str(&format!(
                "    kind: vless\n    locator: \"{locator}\"\n    uuid: \"{}\"\n    flow: \"{}\"\n    tls: true\n    servername: \"{}\"\n    skip_cert_verify: {}\n",
                c.uuid,
                c.flow.as_wire(),
                cfg.tls.sni,
                cfg.tls.skip_cert_verify
            ));
        }
        (Protocol::Anytls, Credentials::Anytls(c)) => {
            out.push_str(&format!(
                "    kind: anytls\n    locator: \"{locator}\"\n    password: \"{}\"\n    sni: \"{}\"\n    skip_cert_verify: {}\n",
                c.password, cfg.tls.sni, cfg.tls.skip_cert_verify
            ));
        }
        (Protocol::Hysteria2, Credentials::Hysteria2(c)) => {
            out.push_str(&format!(
                "    kind: hysteria2\n    locator: \"{locator}\"\n    password: \"{}\"\n    sni: \"{}\"\n    skip_cert_verify: {}\n",
                c.password, cfg.tls.sni, cfg.tls.skip_cert_verify
            ));
            if let Hy2Obfs::Salamander { password } = &c.obfs {
                out.push_str(&format!(
                    "    obfs: \"salamander\"\n    obfs_password: \"{password}\"\n"
                ));
            }
        }
        (Protocol::Trojan, Credentials::Trojan(c)) => {
            let header = match c.header_format {
                HeaderFormat::Standard => "standard",
                HeaderFormat::Singbox => "singbox",
            };
            out.push_str(&format!(
                "    kind: trojan\n    locator: \"{locator}\"\n    password: \"{}\"\n    skip_cert_verify: {}\n    header_format: \"{header}\"\n",
                c.password, cfg.tls.skip_cert_verify
            ));
        }
        (Protocol::Shadowsocks, Credentials::Shadowsocks(c)) => {
            out.push_str(&format!(
                "    kind: shadowsocks\n    locator: \"{locator}\"\n    method: \"{}\"\n    password: \"{}\"\n",
                c.method.as_wire(),
                c.password
            ));
        }
        _ => return Err("credentials/protocol mismatch".into()),
    }
    Ok(out)
}

struct ProxyConn {
    stream: TcpStream,
    rx: mpsc::Receiver<Result<serde_json::Value, String>>,
}

impl ProxyConn {
    fn open(cfg: &InteropProbeConfig, timeout: Duration) -> Result<Self, String> {
        let yaml = proxy_yaml(cfg)?;
        let listener =
            TcpListener::bind(("127.0.0.1", 0)).map_err(|e| format!("bind proxy: {e}"))?;
        let addr = listener.local_addr().map_err(|e| e.to_string())?;
        let clone = listener.try_clone().map_err(|e| e.to_string())?;
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let result = nexus::proxy_serve_once(&clone, &yaml).map_err(|e| format!("{e:?}"));
            let _ = tx.send(result);
        });
        let stream = socks5_connect(addr, &cfg.target.host, cfg.target.port, timeout)?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| e.to_string())?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|e| e.to_string())?;
        Ok(Self { stream, rx })
    }

    /// 关闭隧道并等待 proxy JSON（有界等待，避免中继未终止时挂死探针）。
    fn finish(self, wait: Duration) -> (Option<serde_json::Value>, Option<String>) {
        let Self { stream, rx } = self;
        drop(stream);
        match rx.recv_timeout(wait) {
            Ok(Ok(value)) => (Some(value), None),
            Ok(Err(err)) => (None, Some(err)),
            Err(_) => (
                None,
                Some("proxy relay did not terminate within wait window".into()),
            ),
        }
    }
}

/// 最小 SOCKS5 客户端（NO-AUTH + CONNECT IPv4/域名）。
fn socks5_connect(
    proxy: SocketAddr,
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<TcpStream, String> {
    let mut stream = TcpStream::connect_timeout(&proxy, timeout)
        .map_err(|e| format!("connect proxy {proxy}: {e}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .map_err(|e| format!("socks5 greeting: {e}"))?;
    let mut reply = [0u8; 2];
    stream
        .read_exact(&mut reply)
        .map_err(|e| format!("socks5 greeting reply: {e}"))?;
    if reply != [0x05, 0x00] {
        return Err(format!("socks5 no-auth rejected: {reply:?}"));
    }
    let mut req = vec![0x05, 0x01, 0x00];
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        req.push(0x01);
        req.extend_from_slice(&ip.octets());
    } else {
        req.push(0x03);
        req.push(u8::try_from(host.len()).map_err(|_| "host too long")?);
        req.extend_from_slice(host.as_bytes());
    }
    req.extend_from_slice(&port.to_be_bytes());
    stream
        .write_all(&req)
        .map_err(|e| format!("socks5 connect request: {e}"))?;
    let mut head = [0u8; 4];
    stream
        .read_exact(&mut head)
        .map_err(|e| format!("socks5 connect reply: {e}"))?;
    if head[0] != 0x05 || head[1] != 0x00 {
        return Err(format!("socks5 connect refused: {head:?}"));
    }
    match head[3] {
        0x01 => {
            let mut rest = [0u8; 6];
            stream.read_exact(&mut rest).map_err(|e| e.to_string())?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).map_err(|e| e.to_string())?;
            let mut rest = vec![0u8; usize::from(len[0]) + 2];
            stream.read_exact(&mut rest).map_err(|e| e.to_string())?;
        }
        0x04 => {
            let mut rest = [0u8; 18];
            stream.read_exact(&mut rest).map_err(|e| e.to_string())?;
        }
        other => return Err(format!("socks5 unknown atyp {other:#x}")),
    }
    Ok(stream)
}

/// 单连接工作负载（在 SOCKS5 隧道上跑）。
struct WorkloadResult {
    echo_ok: bool,
    echoed: Vec<u8>,
    errors: Vec<String>,
    metrics: Metrics,
}

fn tcp_roundtrip(
    stream: &mut TcpStream,
    payload: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    stream
        .write_all(payload)
        .map_err(|e| format!("tunnel write: {e}"))?;
    let mut back = vec![0u8; payload.len()];
    stream
        .read_exact(&mut back)
        .map_err(|e| format!("tunnel read: {e}"))?;
    Ok(back)
}

fn run_t2(stream: &mut TcpStream, cfg: &InteropProbeConfig) -> Result<Metrics, String> {
    let cell = cfg.cell.label();
    let seed = util::cell_seed(cfg.protocol.label(), cfg.variant.label(), cell);
    let mut metrics = Metrics::default();
    let mut up_ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut down_ctx = ring::digest::Context::new(&ring::digest::SHA256);

    // 预热（不计样本）。
    let warm = util::payload_with_seed(seed, cfg.workload.warmup_bytes);
    upload_sink(stream, &warm, &mut up_ctx)?;
    download_sink(stream, cfg.workload.warmup_bytes, &mut down_ctx)?;

    let payload = util::payload_with_seed(seed, cfg.workload.throughput_bytes);
    for _ in 0..cfg.workload.throughput_repeats {
        let started = Instant::now();
        let up_digest = upload_sink(stream, &payload, &mut up_ctx)?;
        let down = download_sink(stream, cfg.workload.throughput_bytes, &mut down_ctx)?;
        let expected_down = util::sha256_hex(&util::source_payload(cfg.workload.throughput_bytes));
        if up_digest != util::sha256_hex(&payload) {
            return Err("sink upload digest mismatch".into());
        }
        if down != expected_down {
            return Err("source download digest mismatch".into());
        }
        let elapsed = started.elapsed().as_secs_f64().max(0.000_001);
        let bits = (payload.len() + cfg.workload.throughput_bytes) as f64 * 8.0;
        metrics.throughput_samples_bps.push((bits / elapsed) as u64);
    }
    metrics.bytes_up = (cfg.workload.warmup_bytes
        + cfg.workload.throughput_bytes * cfg.workload.throughput_repeats as usize)
        as u64;
    metrics.bytes_down = metrics.bytes_up;
    metrics.sha256_up = util::to_hex(up_ctx.finish().as_ref());
    metrics.sha256_down = util::to_hex(down_ctx.finish().as_ref());
    let mut samples = metrics.throughput_samples_bps.clone();
    samples.sort_unstable();
    metrics.throughput_median_bps = samples[samples.len() / 2];
    Ok(metrics)
}

fn upload_sink(
    stream: &mut TcpStream,
    payload: &[u8],
    _outer: &mut ring::digest::Context,
) -> Result<String, String> {
    stream.write_all(&[0x55]).map_err(|e| e.to_string())?;
    stream
        .write_all(&(payload.len() as u64).to_be_bytes())
        .map_err(|e| e.to_string())?;
    stream.write_all(payload).map_err(|e| e.to_string())?;
    let mut digest = [0u8; 32];
    stream
        .read_exact(&mut digest)
        .map_err(|e| format!("sink digest read: {e}"))?;
    Ok(util::to_hex(&digest))
}

fn download_sink(
    stream: &mut TcpStream,
    len: usize,
    _outer: &mut ring::digest::Context,
) -> Result<String, String> {
    stream.write_all(&[0x44]).map_err(|e| e.to_string())?;
    stream
        .write_all(&(len as u64).to_be_bytes())
        .map_err(|e| e.to_string())?;
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut remaining = len;
    let mut buf = vec![0u8; 64 * 1024];
    while remaining > 0 {
        let want = remaining.min(buf.len());
        stream
            .read_exact(&mut buf[..want])
            .map_err(|e| format!("source read: {e}"))?;
        ctx.update(&buf[..want]);
        remaining -= want;
    }
    Ok(util::to_hex(ctx.finish().as_ref()))
}

fn run_workload(
    cfg: &InteropProbeConfig,
    stream: &mut TcpStream,
) -> Result<WorkloadResult, String> {
    let cell = cfg.cell.label();
    let seed = util::cell_seed(cfg.protocol.label(), cfg.variant.label(), cell);
    let mut metrics = Metrics::default();
    let mut errors = Vec::new();
    let timeout = Duration::from_millis(if cfg.cell.is_failure_cell() {
        cfg.timeouts.failure_ms
    } else {
        cfg.timeouts.cell_ms
    });
    let (echo_ok, echoed) = match cfg.cell {
        Cell::Handshake => {
            let payload = util::payload_with_seed(seed, 1);
            match tcp_roundtrip(stream, &payload, timeout) {
                Ok(back) => {
                    let ok = back == payload;
                    metrics.bytes_up += 1;
                    metrics.bytes_down += back.len() as u64;
                    metrics.sha256_up = util::sha256_hex(&payload);
                    metrics.sha256_down = util::sha256_hex(&back);
                    (ok, back)
                }
                Err(e) => {
                    errors.push(e);
                    (false, Vec::new())
                }
            }
        }
        Cell::TcpSmall => {
            let payload = util::payload_with_seed(seed, cfg.workload.small_bytes);
            match tcp_roundtrip(stream, &payload, timeout) {
                Ok(back) => {
                    let ok = back == payload;
                    metrics.bytes_up += payload.len() as u64;
                    metrics.bytes_down += back.len() as u64;
                    metrics.sha256_up = util::sha256_hex(&payload);
                    metrics.sha256_down = util::sha256_hex(&back);
                    (ok, back)
                }
                Err(e) => {
                    errors.push(e);
                    (false, Vec::new())
                }
            }
        }
        Cell::TcpThroughput => {
            let m = run_t2(stream, cfg)?;
            metrics = m;
            (true, Vec::new())
        }
        Cell::LongLived => {
            let mut ok = 0u32;
            let start = Instant::now();
            for i in 0..cfg.workload.long_lived_heartbeats {
                let payload = util::payload_with_seed(seed ^ u64::from(i), 1);
                match tcp_roundtrip(stream, &payload, timeout) {
                    Ok(back) if back == payload => {
                        ok += 1;
                        metrics.bytes_up += 1;
                        metrics.bytes_down += 1;
                    }
                    Ok(_) => {
                        errors.push(format!("heartbeat {i} mismatched echo"));
                        break;
                    }
                    Err(e) => {
                        errors.push(format!("heartbeat {i}: {e}"));
                        break;
                    }
                }
                if i + 1 < cfg.workload.long_lived_heartbeats {
                    let target =
                        start + Duration::from_millis(cfg.timeouts.heartbeat_ms * u64::from(i + 1));
                    let now = Instant::now();
                    if target > now {
                        thread::sleep(target - now);
                    }
                }
            }
            metrics.heartbeats_ok = ok;
            (ok == cfg.workload.long_lived_heartbeats, Vec::new())
        }
        Cell::BadCredential | Cell::BadConfig => {
            let payload = util::payload_with_seed(seed, 16);
            stream
                .set_read_timeout(Some(timeout))
                .map_err(|e| e.to_string())?;
            let mut buf = [0u8; 512];
            match stream.write_all(&payload) {
                Ok(()) => {}
                Err(e) => errors.push(format!("tunnel write: {e}")),
            }
            match stream.read(&mut buf) {
                Ok(0) => {
                    errors.push("eof".into());
                    (false, Vec::new())
                }
                Ok(n) => {
                    let got = buf[..n].to_vec();
                    (got == payload, got)
                }
                Err(e) => {
                    errors.push(format!("read: {e}"));
                    (false, Vec::new())
                }
            }
        }
        Cell::Reconnect | Cell::UdpEcho | Cell::QpackDiag | Cell::PaddingDiag => {
            return Err(format!("cell {cell} is not a product tunnel workload"));
        }
    };
    metrics.heartbeats_ok = metrics.heartbeats_ok.max(if echo_ok { 1 } else { 0 });
    Ok(WorkloadResult {
        echo_ok,
        echoed,
        errors,
        metrics,
    })
}

/// 产品载波 cell 执行入口。
pub fn run_cell(cfg: &InteropProbeConfig) -> Result<Outcome, String> {
    if cfg.cell == Cell::Reconnect {
        return run_reconnect(cfg);
    }
    let timeout = Duration::from_millis(if cfg.cell.is_failure_cell() {
        cfg.timeouts.failure_ms
    } else {
        cfg.timeouts.cell_ms
    });
    let mut conn = ProxyConn::open(cfg, timeout)?;
    let workload = match run_workload(cfg, &mut conn.stream) {
        Ok(workload) => workload,
        Err(err) => WorkloadResult {
            echo_ok: false,
            echoed: Vec::new(),
            errors: vec![err],
            metrics: Metrics::default(),
        },
    };
    let join_wait = Duration::from_secs(if cfg.cell == Cell::LongLived { 10 } else { 3 });
    let (proxy_json, proxy_error) = conn.finish(join_wait);
    Ok(judge(
        cfg,
        &workload,
        proxy_json.as_ref(),
        proxy_error.as_deref(),
        0,
    ))
}

fn run_reconnect(cfg: &InteropProbeConfig) -> Result<Outcome, String> {
    let seed = util::cell_seed(cfg.protocol.label(), cfg.variant.label(), cfg.cell.label());
    let payload = util::payload_with_seed(seed, 1);
    let mut ok = 0u32;
    let mut notes = Vec::new();
    let mut metrics = Metrics::default();
    let mut last_proxy = None;
    for i in 0..cfg.workload.reconnect_cycles {
        let timeout = Duration::from_millis(cfg.timeouts.cell_ms);
        let mut conn = ProxyConn::open(cfg, timeout)?;
        match tcp_roundtrip(
            &mut conn.stream,
            &payload,
            Duration::from_millis(cfg.timeouts.failure_ms),
        ) {
            Ok(back) if back == payload => ok += 1,
            Ok(_) => notes.push(format!("cycle {i}: mismatched echo")),
            Err(e) => notes.push(format!("cycle {i}: {e}")),
        }
        metrics.bytes_up += 1;
        metrics.bytes_down += 1;
        let (proxy_json, proxy_error) = conn.finish(Duration::from_secs(3));
        if let Some(err) = proxy_error {
            notes.push(format!("cycle {i}: proxy {err}"));
        }
        last_proxy = proxy_json.or(last_proxy);
        if i + 1 < cfg.workload.reconnect_cycles {
            thread::sleep(Duration::from_millis(cfg.timeouts.reconnect_wait_ms));
        }
    }
    metrics.reconnects_ok = ok;
    let workload = WorkloadResult {
        echo_ok: ok == cfg.workload.reconnect_cycles,
        echoed: Vec::new(),
        errors: notes,
        metrics,
    };
    Ok(judge(
        cfg,
        &workload,
        last_proxy.as_ref(),
        None,
        cfg.workload.reconnect_cycles - ok,
    ))
}

fn class_label(class: ErrorClass) -> &'static str {
    match class {
        ErrorClass::ENexusHandshakeWire => "E_NEXUS_HANDSHAKE_WIRE",
        ErrorClass::ENexusAuthEncoding => "E_NEXUS_AUTH_ENCODING",
        ErrorClass::ENexusFraming => "E_NEXUS_FRAMING",
        ErrorClass::ENexusTransport => "E_NEXUS_TRANSPORT",
        ErrorClass::ENexusUdp => "E_NEXUS_UDP",
        ErrorClass::ENexusCodec => "E_NEXUS_CODEC",
        ErrorClass::ENexusNotImplemented => "E_NEXUS_NOT_IMPLEMENTED",
        ErrorClass::ERefConfig => "E_REF_CONFIG",
        ErrorClass::ERefUnsupported => "E_REF_UNSUPPORTED",
        ErrorClass::ERefBehavior => "E_REF_BEHAVIOR",
        ErrorClass::EExpectedAuthReject => "E_EXPECTED_AUTH_REJECT",
        ErrorClass::EExpectedConfigReject => "E_EXPECTED_CONFIG_REJECT",
        ErrorClass::ENetworkEnv => "E_NETWORK_ENV",
        ErrorClass::ETimeoutHang => "E_TIMEOUT_HANG",
        ErrorClass::EToolBug => "E_TOOL_BUG",
        ErrorClass::EEvidenceGap => "E_EVIDENCE_GAP",
        ErrorClass::ERefLimitation => "E_REF_LIMITATION",
    }
}

fn judge(
    cfg: &InteropProbeConfig,
    workload: &WorkloadResult,
    proxy_json: Option<&serde_json::Value>,
    proxy_error: Option<&str>,
    reconnects_failed: u32,
) -> Outcome {
    let mut notes = Vec::new();
    let kind = product_kind(cfg.protocol);
    let mut routing_ok = true;
    if let Some(value) = proxy_json {
        let routing_kind = value
            .pointer("/routing/outbound_kind")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("<missing>");
        let outbound_kind = value
            .pointer("/outbound/kind")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("<missing>");
        notes.push(format!(
            "proxy_json routing.outbound_kind={routing_kind} outbound.kind={outbound_kind}"
        ));
        routing_ok = routing_kind == kind && outbound_kind == kind;
    }
    if let Some(err) = proxy_error {
        notes.push(format!("proxy_error={err}"));
    }
    for err in &workload.errors {
        notes.push(format!("workload_error={err}"));
    }
    let mut metrics = workload.metrics.clone();
    if !workload.echo_ok && metrics.sha256_up.is_empty() {
        metrics.sha256_up = String::new();
    }

    if cfg.cell.is_failure_cell() {
        let expected_class = if cfg.cell == Cell::BadCredential {
            ErrorClass::EExpectedAuthReject
        } else {
            ErrorClass::EExpectedConfigReject
        };
        let rejected = !workload.echo_ok && proxy_json.is_none();
        if rejected {
            notes.push(format!("classification={}", class_label(expected_class)));
            notes.push("reference rejected the negative case".into());
            return Outcome {
                verdict: Verdict::Pass,
                error: None,
                metrics,
                notes,
                proxy_json: proxy_json.cloned(),
            };
        }
        if workload.echo_ok {
            notes.push("negative case was accepted (bad credential/config)".into());
            return Outcome {
                verdict: Verdict::Blocked,
                error: Some(ErrorInfo {
                    class: ErrorClass::ERefBehavior,
                    message: "reference tolerated a negative case".into(),
                    first_failure_artifact: Some("pcap.pcap".into()),
                }),
                metrics,
                notes,
                proxy_json: proxy_json.cloned(),
            };
        }
        if !workload.echoed.is_empty() {
            if cfg.variant == Variant::TrojanFallback {
                notes.push(
                    "fallback response was relayed as tunnel data; D1 has no dedicated class, using E_NEXUS_FRAMING"
                        .into(),
                );
                return Outcome {
                    verdict: Verdict::Fail,
                    error: Some(ErrorInfo {
                        class: ErrorClass::ENexusFraming,
                        message: "fallback HTTP response silently surfaced as tunnel payload"
                            .into(),
                        first_failure_artifact: Some("pcap.pcap".into()),
                    }),
                    metrics,
                    notes,
                    proxy_json: proxy_json.cloned(),
                };
            }
            notes.push("negative case returned non-echo bytes".into());
            return Outcome {
                verdict: Verdict::Blocked,
                error: Some(ErrorInfo {
                    class: ErrorClass::ERefBehavior,
                    message: "reference returned non-echo bytes for a negative case".into(),
                    first_failure_artifact: Some("pcap.pcap".into()),
                }),
                metrics,
                notes,
                proxy_json: proxy_json.cloned(),
            };
        }
        // 无 echo、无字节：视为拒绝（连接被关闭）。
        notes.push(format!("classification={}", class_label(expected_class)));
        notes.push("reference closed the session on the negative case".into());
        return Outcome {
            verdict: Verdict::Pass,
            error: None,
            metrics,
            notes,
            proxy_json: proxy_json.cloned(),
        };
    }

    if cfg.cell == Cell::PaddingDiag {
        // 诊断格：握手成功即可推断 ServerSettings；否则看错误文案。
        if let Some(json) = proxy_json {
            if routing_ok {
                notes.push("serversettings_inferred".into());
                return Outcome {
                    verdict: Verdict::Pass,
                    error: None,
                    metrics,
                    notes,
                    proxy_json: Some(json.clone()),
                };
            }
        }
        let text = notes.join(" ");
        if text.contains("padding scheme update") {
            notes.push("update_padding_scheme".into());
            return Outcome {
                verdict: Verdict::Pass,
                error: None,
                metrics,
                notes,
                proxy_json: proxy_json.cloned(),
            };
        }
        return Outcome {
            verdict: Verdict::Blocked,
            error: Some(ErrorInfo {
                class: ErrorClass::EEvidenceGap,
                message: "could not infer ServerSettings or UpdatePaddingScheme".into(),
                first_failure_artifact: Some("probe.stdout.jsonl".into()),
            }),
            metrics,
            notes,
            proxy_json: proxy_json.cloned(),
        };
    }

    let ok = workload.echo_ok && routing_ok && proxy_json.is_some() && reconnects_failed == 0;
    if ok {
        return Outcome {
            verdict: Verdict::Pass,
            error: None,
            metrics,
            notes,
            proxy_json: proxy_json.cloned(),
        };
    }
    if proxy_json.is_some() && !routing_ok {
        notes.push("proxy routing/outbound kind did not match protocol".into());
    }
    if proxy_json.is_none() {
        notes.push("proxy JSON unavailable; carrier assertion incomplete".into());
    }
    let class = if workload.errors.iter().any(|e| e.contains("timeout")) {
        ErrorClass::ETimeoutHang
    } else if cfg.cell == Cell::Handshake {
        ErrorClass::ENexusHandshakeWire
    } else {
        ErrorClass::ENexusFraming
    };
    Outcome {
        verdict: Verdict::Fail,
        error: Some(ErrorInfo {
            class,
            message: format!("product path cell did not satisfy assertions: {notes:?}"),
            first_failure_artifact: Some("pcap.pcap".into()),
        }),
        metrics,
        notes,
        proxy_json: proxy_json.cloned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::base_json;

    fn cfg(v: serde_json::Value) -> InteropProbeConfig {
        serde_json::from_value(v).expect("config")
    }

    #[test]
    fn yaml_has_required_fields_for_all_protocols() {
        let vless = proxy_yaml(&cfg(base_json())).expect("vless yaml");
        assert!(vless.contains("kind: vless"));
        assert!(vless.contains("uuid:"));
        assert!(vless.contains("tls: true"));
        assert!(vless.contains("servername: \"localhost\""));
    }

    #[test]
    fn socks5_frames_are_rejected_on_dead_port() {
        let addr: SocketAddr = "127.0.0.1:9".parse().expect("addr");
        assert!(socks5_connect(addr, "127.0.0.1", 26200, Duration::from_millis(200)).is_err());
    }
}

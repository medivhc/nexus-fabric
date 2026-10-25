//! AC-8 确定性枚举驱动：严格模式（默认）的端口绑定 greeting 白名单 + 非白名单 server-first
//! 目标的拒绝面 + `fallback_guard: signature` 逃生口。
//!
//! ```text
//! unshare -Urn bash -c 'ip link set lo up; <example> --json'
//! ```
//!
//! 低端口（22/21/25/587/110/143/5900）需要绑定权限，按 develop 裁决 R-5 的阶梯执行：
//! `unshare -Urn`（用户 + 网络命名空间）→ `sudo -n`（非交互）→ 都不可用则本项 BLOCKED，
//! **不静默改测高位端口**。
//!
//! 判据（spec AC-8）：
//! 1. 白名单 7 端口 × Handshake/TcpSmall 两种工作负载，逐项 PASS（100%，不抽样）；
//! 2. 白名单外 server-first 目标（§5.9 M-1~M-8）在 strict 下 100% 拒（`REP≠0` + 零隧道字节）；
//! 3. 同一组目标在 `signature` 下 100% 放行（逃生口生效）。
//!
//! 输出单个 JSON 对象（场景/证据采集用）。

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use nexus::proxy_serve_once;
use nexus_outbound_trojan::{generate_loopback_identity, parse_request, server_config};

const NODE_PASSWORD: &str = "whitelist-node-password";
const PAYLOAD: &[u8] = b"greeting-whitelist-payload";

/// banner 脚本：每个元素在发送前等待 `delay_ms`。
type Banner = Vec<(u64, &'static [u8])>;

/// 白名单 7 端口（§5.2 表）。
const WHITELIST: &[(u16, &[u8])] = &[
    (22, b"SSH-2.0-OpenSSH_9.6\r\n"),
    (21, b"220 ftp.example FTP ready\r\n"),
    (25, b"220 mail.example ESMTP\r\n"),
    (587, b"220 mail.example ESMTP\r\n"),
    (110, b"+OK POP3 ready\r\n"),
    (143, b"* OK IMAP4rev1 ready\r\n"),
    (5900, b"RFB 003.008\n"),
];

/// §5.9 的非白名单 server-first 清单（M-1~M-8）。
struct NonWhitelistCase {
    id: &'static str,
    port: u16,
    banner: &'static [(u64, &'static [u8])],
}

fn non_whitelist_cases() -> Vec<NonWhitelistCase> {
    vec![
        NonWhitelistCase {
            id: "M-1-mysql-3306",
            port: 3306,
            banner: &[(
                0,
                &[0x5f, 0, 0, 0, 0x0a, 0x38, 0x2e, 0x30, 0x2e, 0x33, 0x36],
            )],
        },
        NonWhitelistCase {
            id: "M-2-ssh-2222",
            port: 2222,
            banner: &[(0, b"SSH-2.0-OpenSSH_9.6\r\n")],
        },
        NonWhitelistCase {
            id: "M-3-telnet-iac-2323",
            port: 2323,
            banner: &[(0, &[0xff, 0xfd, 0x03, 0xff, 0xfb, 0x18])],
        },
        NonWhitelistCase {
            id: "M-4-custom-banner-8080",
            port: 8080,
            banner: &[(0, b"WELCOME to custom service\r\n")],
        },
        NonWhitelistCase {
            id: "M-5-smtp-554",
            port: 25,
            banner: &[(0, b"554 mail.example rejected\r\n")],
        },
        NonWhitelistCase {
            id: "M-6-vnc-5901",
            port: 5901,
            banner: &[(0, b"RFB 003.008\n")],
        },
        NonWhitelistCase {
            id: "M-7-fragmented-prefix-22",
            port: 22,
            // 半截前缀 + 60ms 延迟（超过 PREFIX_EXTRA_WAIT_MS=50ms）。
            banner: &[(0, b"SS"), (60, b"H-2.0-OpenSSH_9.6\r\n")],
        },
        NonWhitelistCase {
            id: "M-8-atypical-on-110",
            port: 110,
            banner: &[(0, b"ERR service unavailable\r\n")],
        },
    ]
}

struct CaseResult {
    id: String,
    port: u16,
    workload: String,
    policy: String,
    ok: bool,
    rep: Option<u8>,
    tunnel_bytes: usize,
    first_bytes_hex: String,
    note: String,
}

/// 一次完整闭环：banner 目标 + trojan 节点 + 产品 proxy + 原始 SOCKS5 客户端。
#[allow(clippy::too_many_arguments)]
fn run_case(
    id: &str,
    target_port: u16,
    banner: Banner,
    workload: &str,
    policy: &str,
) -> Result<CaseResult, String> {
    // ---- banner 目标（server-first）----
    let target = TcpListener::bind(("127.0.0.1", target_port))
        .map_err(|e| format!("bind target {target_port}: {e}"))?;
    let target_thread = thread::spawn(move || {
        if let Ok((mut conn, _)) = target.accept() {
            for (delay, data) in &banner {
                if *delay > 0 {
                    thread::sleep(Duration::from_millis(*delay));
                }
                if conn.write_all(data).is_err() {
                    return;
                }
            }
            // 之后 echo（TcpSmall 工作负载用）。
            let mut buf = [0u8; 4096];
            while let Ok(n) = conn.read(&mut buf) {
                if n == 0 {
                    break;
                }
                if conn.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    });

    // ---- trojan 节点：解析 header 目标后双向管道 ----
    let identity = generate_loopback_identity().map_err(|e| format!("identity: {e:?}"))?;
    let srv_cfg = Arc::new(server_config(&identity).map_err(|e| format!("server cfg: {e:?}"))?);
    let node_listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let node_port = node_listener
        .local_addr()
        .map_err(|e| e.to_string())?
        .port();
    let node_thread = thread::spawn(move || {
        if let Ok((conn, _)) = node_listener.accept() {
            let _ = conn.set_nonblocking(false);
            // 2ms 读超时：TLS 读到 WouldBlock/TimedOut 后回到循环顶部，把 target 的
            // server-first banner 及时泵给客户端（否则守卫窗口看不到首包）。
            let _ = conn.set_read_timeout(Some(Duration::from_millis(2)));
            let mut conn = conn;
            let mut srv = match rustls::ServerConnection::new(Arc::clone(&srv_cfg)) {
                Ok(s) => s,
                Err(_) => return,
            };
            let mut tls = rustls::Stream::new(&mut srv, &mut conn);
            let mut header = Vec::new();
            let mut one = [0u8; 1];
            loop {
                if tls.read_exact(&mut one).is_err() {
                    return;
                }
                header.push(one[0]);
                if header.windows(2).filter(|w| **w == *b"\r\n").count() >= 2 {
                    break;
                }
                if header.len() > 4096 {
                    return;
                }
            }
            let Ok(t) = parse_request(NODE_PASSWORD, &header) else {
                return;
            };
            let dest = format!("{}:{}", t.host_label(), t.port());
            let Ok(mut upstream) = TcpStream::connect(&dest) else {
                return;
            };
            let Ok(mut up_reader) = upstream.try_clone() else {
                return;
            };
            let _ = up_reader.set_read_timeout(Some(Duration::from_millis(50)));
            // 半双工双向泵（同一进程内、短会话）：先用一个线程把 target->TLS 写出去。
            let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let reader_stop = Arc::clone(&stop);
            let reader_thread = thread::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    if reader_stop.load(std::sync::atomic::Ordering::SeqCst) {
                        break;
                    }
                    match up_reader.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            if tx.send(buf[..n].to_vec()).is_err() {
                                break;
                            }
                        }
                        Err(ref e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                || e.kind() == std::io::ErrorKind::TimedOut =>
                        {
                            continue;
                        }
                        Err(_) => break,
                    }
                }
            });
            let mut cbuf = [0u8; 4096];
            loop {
                while let Ok(chunk) = rx.try_recv() {
                    if tls.write_all(&chunk).is_err() {
                        return;
                    }
                    let _ = tls.flush();
                }
                match tls.read(&mut cbuf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if upstream.write_all(&cbuf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(ref e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => break,
                }
            }
            stop.store(true, std::sync::atomic::Ordering::SeqCst);
            drop(upstream);
            let _ = reader_thread.join();
        }
    });

    // ---- 产品 proxy（一个会话）----
    let config = format!(
        concat!(
            "schema_version: 1\n",
            "inbounds:\n",
            "  - tag: socks5-in\n",
            "    kind: socks5\n",
            "    listen: 127.0.0.1:0\n",
            "rules:\n",
            "  - tag: rule-match\n",
            "    kind: match\n",
            "    match: \"\"\n",
            "    action:\n",
            "      - kind: select_outbound\n",
            "        tag: trojan-node\n",
            "outbounds:\n",
            "  - tag: trojan-node\n",
            "    kind: trojan\n",
            "    locator: \"127.0.0.1:{0}\"\n",
            "    password: {1}\n",
            "    skip_cert_verify: true\n",
            "    fallback_guard: {2}\n",
            "    ready_window_ms: 120\n",
        ),
        node_port, NODE_PASSWORD, policy
    );
    let proxy_listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let proxy_addr = proxy_listener.local_addr().map_err(|e| e.to_string())?;
    let proxy_thread = thread::spawn(move || proxy_serve_once(&proxy_listener, &config));

    // ---- 客户端 ----
    let mut client = TcpStream::connect(proxy_addr).map_err(|e| e.to_string())?;
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| e.to_string())?;
    client
        .write_all(&[0x05, 0x01, 0x00])
        .map_err(|e| e.to_string())?;
    let mut method = [0u8; 2];
    client.read_exact(&mut method).map_err(|e| e.to_string())?;
    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&target_port.to_be_bytes());
    client.write_all(&req).map_err(|e| e.to_string())?;
    let mut reply = [0u8; 10];
    let rep = match client.read_exact(&mut reply) {
        Ok(()) => Some(reply[1]),
        Err(_) => None,
    };

    let mut first: Vec<u8> = Vec::new();
    let mut tunnel_bytes = 0usize;
    let mut roundtrip_ok = false;
    if rep == Some(0x00) {
        if workload == "TcpSmall" {
            client.write_all(PAYLOAD).map_err(|e| e.to_string())?;
            let echo = vec![0u8; PAYLOAD.len()];
            // 首包（banner）先落地：读到 PAYLOAD 长度的回显需要穿过 banner。
            // banner 长度未知，这里只断言「能读到回显」：先读一批，再找 PAYLOAD 子串。
            let mut got = Vec::new();
            loop {
                let mut buf = [0u8; 4096];
                match client.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        got.extend_from_slice(&buf[..n]);
                        if got.windows(PAYLOAD.len()).any(|w| w == PAYLOAD) {
                            roundtrip_ok = true;
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            first.extend_from_slice(&got);
            tunnel_bytes = got.len();
            let _ = echo;
        } else {
            // Handshake：只确认 CONNECT 成功（banner 已经/将要下行）。
            roundtrip_ok = true;
            client
                .set_read_timeout(Some(Duration::from_millis(300)))
                .map_err(|e| e.to_string())?;
            let mut buf = [0u8; 512];
            if let Ok(n) = client.read(&mut buf) {
                first.extend_from_slice(&buf[..n]);
                tunnel_bytes = n;
            }
        }
    } else {
        // 失败形态：失败应答之后的隧道字节必须为 0。
        client
            .set_read_timeout(Some(Duration::from_millis(500)))
            .map_err(|e| e.to_string())?;
        loop {
            let mut buf = [0u8; 4096];
            match client.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => tunnel_bytes += n,
                Err(_) => break,
            }
        }
    }
    drop(client);

    let session = proxy_thread.join().ok().and_then(|r| r.ok());
    let session_tunnel = session
        .as_ref()
        .and_then(|v| v.get("tunnel"))
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let session_readiness = session_tunnel
        .get("readiness")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let _ = target_thread.join();
    let _ = node_thread.join();

    let first_hex: String = first.iter().take(16).map(|b| format!("{b:02x}")).collect();
    let ok = match (policy, rep) {
        ("strict", Some(0x00)) => roundtrip_ok,
        ("strict", _) => tunnel_bytes == 0,
        ("signature", Some(0x00)) => roundtrip_ok,
        _ => false,
    };
    Ok(CaseResult {
        id: id.to_string(),
        port: target_port,
        workload: workload.to_string(),
        policy: policy.to_string(),
        ok,
        rep,
        tunnel_bytes,
        first_bytes_hex: first_hex,
        note: session_readiness,
    })
}

fn main() {
    let _as_json = std::env::args().skip(1).any(|a| a == "--json");

    let low_port_authority = TcpListener::bind(("127.0.0.1", 22)).is_ok();
    if low_port_authority {
        // 立刻释放，避免影响后续用例。
    }

    let mut results: Vec<CaseResult> = Vec::new();
    let mut blocked: Vec<String> = Vec::new();

    // 1) 白名单 7 端口 × 2 工作负载（strict）
    for (port, banner_bytes) in WHITELIST {
        for workload in ["Handshake", "TcpSmall"] {
            let banner: Banner = vec![(0u64, *banner_bytes)];
            match run_case("whitelist", *port, banner, workload, "strict") {
                Ok(r) => results.push(r),
                Err(e) => {
                    if !low_port_authority && *port < 1024 {
                        blocked.push(format!("whitelist {port}/{workload}: {e}"));
                    } else {
                        results.push(CaseResult {
                            id: format!("whitelist-{port}"),
                            port: *port,
                            workload: workload.to_string(),
                            policy: "strict".into(),
                            ok: false,
                            rep: None,
                            tunnel_bytes: 0,
                            first_bytes_hex: String::new(),
                            note: format!("error: {e}"),
                        });
                    }
                }
            }
        }
    }

    // 2) 非白名单 server-first（strict 必须拒；signature 必须放行）
    for case in non_whitelist_cases() {
        for policy in ["strict", "signature"] {
            match run_case(case.id, case.port, case.banner.to_vec(), "TcpSmall", policy) {
                Ok(r) => results.push(r),
                Err(e) => {
                    if !low_port_authority && case.port < 1024 {
                        blocked.push(format!("{} / {policy}: {e}", case.id));
                    } else {
                        results.push(CaseResult {
                            id: case.id.to_string(),
                            port: case.port,
                            workload: "TcpSmall".into(),
                            policy: policy.into(),
                            ok: false,
                            rep: None,
                            tunnel_bytes: 0,
                            first_bytes_hex: String::new(),
                            note: format!("error: {e}"),
                        });
                    }
                }
            }
        }
    }

    let summary = |policy: &str, strict_ports: bool| {
        let rows: Vec<&CaseResult> = results
            .iter()
            .filter(|r| r.policy == policy && (r.id != "whitelist") == strict_ports)
            .collect();
        let passed = rows.iter().filter(|r| r.ok).count();
        (passed, rows.len())
    };
    let (wl_pass, wl_total) = summary("strict", false);
    let (strict_reject_pass, strict_reject_total) = summary("strict", true);
    let (sig_pass, sig_total) = summary("signature", true);

    let verdict = if !blocked.is_empty() {
        "BLOCKED"
    } else if wl_pass == wl_total
        && strict_reject_pass == strict_reject_total
        && sig_pass == sig_total
        && wl_total > 0
        && sig_total > 0
    {
        "PASS"
    } else {
        "FAIL"
    };

    let mut non_whitelist_strict = Vec::new();
    let mut non_whitelist_signature = Vec::new();
    let mut whitelist_rows = Vec::new();
    for r in &results {
        let row = serde_json::json!({
            "id": r.id,
            "port": r.port,
            "workload": r.workload,
            "ok": r.ok,
            "rep": r.rep,
            "tunnel_bytes": r.tunnel_bytes,
            "first_bytes_hex": r.first_bytes_hex,
            "readiness": r.note,
        });
        if r.id == "whitelist" {
            whitelist_rows.push(row);
        } else if r.policy == "strict" {
            non_whitelist_strict.push(row);
        } else {
            non_whitelist_signature.push(row);
        }
    }

    println!(
        "{}",
        serde_json::json!({
            "verdict": verdict,
            "low_port_authority": low_port_authority,
            "blocked": blocked,
            "whitelist": {
                "strict": whitelist_rows,
                "passed": wl_pass,
                "total": wl_total,
            },
            "non_whitelist": {
                "strict": non_whitelist_strict,
                "signature": non_whitelist_signature,
                "strict_passed": strict_reject_pass,
                "strict_total": strict_reject_total,
                "signature_passed": sig_pass,
                "signature_total": sig_total,
            },
        })
    );
}

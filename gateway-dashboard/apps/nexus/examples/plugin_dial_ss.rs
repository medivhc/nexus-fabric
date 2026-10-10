//! E4 `product.plugin-dial-ss`：ss 出站配 xor 插件 dial。
//!
//! 协议：
//! 1. 构造 `OutboundConfig{kind=shadowsocks, locator=<server>, obfs=xor}`，
//!    从中取出 (addr, obfs, params)——与 `proxy_serve_once` 的 ss arm 取参逻辑一致；
//! 2. `dial_with_obfs(addr, Some("xor"), params)` 拨号（走全局注册表）；
//! 3. client 经 wrapped 流发 P（N 字节确定性明文）；
//! 4. server 先从 raw 流读 N 字节线字节 W，断言 `W != P`（混淆在线上生效）；
//! 5. server 用同 key xor 包裹该流（只用写方向），回显 P；
//! 6. client 经 wrapped 流读回显 E，断言 `E == P`；
//! 7. 断言可观测 `dial_ok_count("xor") >= 1`（P5）。
//!
//! 只用公开 API + 可观测输出。TCP loopback 不可用 → SKIP（exit 0）。

use nexus_plugin::{ObfsParams, dial_ok_count, dial_with_obfs, init_builtin_plugins, wrap_stream};
use nexus_proxy_config::{OutboundConfig, OutboundKind};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

const N: usize = 65536;
const KEY: &str = "nexus-plugin-dial-e4-key";

/// 确定性明文：0..255 循环（收发双方各自独立构造）。
fn plaintext() -> Vec<u8> {
    (0..N).map(|i| (i % 256) as u8).collect()
}

enum Outcome {
    Skip(String),
    Fail(String),
}

fn run() -> Result<String, Outcome> {
    init_builtin_plugins();
    let p = plaintext();

    let listener =
        TcpListener::bind("127.0.0.1:0").map_err(|e| Outcome::Skip(format!("bind: {e}")))?;
    let addr = listener
        .local_addr()
        .map_err(|e| Outcome::Fail(format!("local_addr: {e}")))?;

    // 1. ss 出站配置（P2）：obfs=xor。取参与 ss arm 一致。
    let cfg = OutboundConfig {
        tag: "ss-e4".to_string(),
        kind: OutboundKind::Shadowsocks,
        locator: Some(addr.to_string()),
        method: Some("chacha20-ietf-poly1305".to_string()),
        password: Some("e4-password".to_string()),
        alpn: None,
        skip_cert_verify: None,
        header_format: None,
        obfs: Some("xor".to_string()),
        obfs_key: Some(KEY.to_string()),
        uuid: None,
        flow: None,
        tls: None,
        servername: None,
        sni: None,
        ports: None,
        up: None,
        down: None,
        obfs_password: None,
    };
    let obfs = cfg.obfs.as_deref();
    let params = ObfsParams {
        key: cfg.obfs_key.as_deref().unwrap_or("").as_bytes(),
    };
    let node_addr: std::net::SocketAddr = cfg
        .locator
        .as_deref()
        .ok_or_else(|| Outcome::Fail("locator missing".into()))?
        .parse()
        .map_err(|e| Outcome::Fail(format!("locator parse: {e}")))?;

    // Server（扮演 plugin-aware ss 节点）：读线字节 W → xor 包裹回显 P。
    let server = thread::spawn(move || -> Result<Vec<u8>, String> {
        let (mut raw, _) = listener.accept().map_err(|e| format!("accept: {e}"))?;
        let mut w = vec![0u8; N];
        raw.read_exact(&mut w)
            .map_err(|e| format!("read wire: {e}"))?;
        let mut wrapped = wrap_stream(
            raw,
            Some("xor"),
            &ObfsParams {
                key: KEY.as_bytes(),
            },
        )
        .map_err(|e| format!("server wrap: {e}"))?;
        let p = plaintext();
        wrapped
            .write_all(&p)
            .map_err(|e| format!("server echo: {e}"))?;
        wrapped.flush().map_err(|e| format!("server flush: {e}"))?;
        Ok(w)
    });

    // 2. 经 dial_with_obfs 拨号（P1 统一接线点）。
    let mut wrapped = dial_with_obfs(node_addr, obfs, &params)
        .map_err(|e| Outcome::Fail(format!("dial: {e}")))?;
    // 3. 发 P。
    wrapped
        .write_all(&p)
        .map_err(|e| Outcome::Fail(format!("client write: {e}")))?;
    wrapped
        .flush()
        .map_err(|e| Outcome::Fail(format!("client flush: {e}")))?;
    // 6. 读回显 E。
    let mut e = vec![0u8; N];
    wrapped
        .read_exact(&mut e)
        .map_err(|e| Outcome::Fail(format!("client read: {e}")))?;
    let roundtrip_ok = e == p;

    // 4. 线字节被混淆。
    let w = match server.join() {
        Ok(Ok(w)) => w,
        Ok(Err(e)) => return Err(Outcome::Fail(format!("server thread: {e}"))),
        Err(_) => return Err(Outcome::Fail("server thread panicked".into())),
    };
    let wire_obfuscated = w != p;

    if !wire_obfuscated {
        return Err(Outcome::Fail(
            "wire bytes equal plaintext: obfuscation not in effect".into(),
        ));
    }
    if !roundtrip_ok {
        return Err(Outcome::Fail("echo mismatch after de-obfuscation".into()));
    }
    // 7. P5 可观测。
    let dial_ok = dial_ok_count("xor");
    if dial_ok < 1 {
        return Err(Outcome::Fail(format!(
            "obfs_dial_ok{{xor}} = {dial_ok}, want >= 1"
        )));
    }

    Ok(format!(
        "{{\"verdict\":\"PASS\",\"wire_obfuscated\":{wire_obfuscated},\"roundtrip_ok\":{roundtrip_ok},\"dial_ok_xor\":{dial_ok}}}"
    ))
}

fn main() {
    let json = std::env::args().any(|a| a == "--json");
    match run() {
        Ok(out) => {
            if json {
                println!("{out}");
            } else {
                println!("plugin-dial-ss E4: PASS");
            }
        }
        Err(Outcome::Skip(reason)) => {
            if json {
                println!("{{\"verdict\":\"SKIP\",\"reason\":{reason:?}}}");
            } else {
                println!("plugin-dial-ss E4: SKIP ({reason})");
            }
        }
        Err(Outcome::Fail(reason)) => {
            if json {
                println!("{{\"verdict\":\"FAIL\",\"reason\":{reason:?}}}");
            } else {
                eprintln!("plugin-dial-ss E4: FAIL ({reason})");
            }
            std::process::exit(1);
        }
    }
}

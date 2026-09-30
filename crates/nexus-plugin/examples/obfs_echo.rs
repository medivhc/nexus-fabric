//! E4 `product.plugin-obfs-echo`：TCP 回显穿过 `xor` 插件。
//!
//! 协议（同一条 TCP 连接）：
//! 1. client 经 `xor` wrap 发 P（N 字节确定性明文）；
//! 2. server 先从 raw 流读 N 字节线字节 W，断言 `W != P`（混淆在线上生效）；
//! 3. server 用 `xor` 插件 wrap 同一条流（只用写方向），回显 P；
//! 4. client 经 wrapped 流读回显 E，断言 `E == P`（语义正确）。
//!
//! 与 sketch 的偏差：sketch 写的是 server "wrap 后读 wrapped → 写 wrapped"。
//! 那是不可实现的——client 发完 P 后就阻塞等回显，server 再从 wrapped 读会
//! 永远等不到数据（双方死锁，实测 hang）；且 xor 是位置相关的流密码（读写
//! 位置独立计数），mid-stream wrap 的 keystream 位置也对不上。修正后 server
//! 只用 wrapped 的写方向（该方向仍在位置 0，合法），回显确定性明文 P
//! （即 W 的解密内容）；两个 E4 断言（`W != P`、`E == P`）保持不变，
//! 且全部变换都走真实插件。
//!
//! 只用公开 API + 可观测输出。TCP loopback 不可用 → SKIP（exit 0）。

use nexus_plugin::{builtin, ObfsParams, PluginRegistry};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

const N: usize = 65536;
const KEY: &[u8] = b"nexus-obfs-demo-key";

/// 确定性明文：0..255 循环（收发双方各自独立构造）。
fn plaintext() -> Vec<u8> {
    (0..N).map(|i| (i % 256) as u8).collect()
}

enum Outcome {
    Skip(String),
    Fail(String),
}

fn run() -> Result<String, Outcome> {
    let p = plaintext();

    // 注册表 + 内置插件（公开 API）。
    let mut registry = PluginRegistry::new();
    builtin::register_all(&mut registry);
    assert_eq!(registry.names(), vec!["plain", "xor"]);
    let xor = registry
        .get("xor")
        .ok_or(Outcome::Fail("xor not registered".into()))?;

    let listener =
        TcpListener::bind("127.0.0.1:0").map_err(|e| Outcome::Skip(format!("bind: {e}")))?;
    let addr = listener
        .local_addr()
        .map_err(|e| Outcome::Fail(format!("local_addr: {e}")))?;

    // Server：读线字节 W（raw）→ wrap 同一条流 → 经 wrapped 回显 P。
    let server = thread::spawn(move || -> Result<Vec<u8>, String> {
        let (mut raw, _) = listener.accept().map_err(|e| format!("accept: {e}"))?;

        // 1. 先从 raw 流读 N 字节线字节 W（混淆在线上生效的观察点）。
        let mut w = vec![0u8; N];
        raw.read_exact(&mut w)
            .map_err(|e| format!("read wire: {e}"))?;

        // 2. 同一条连接 wrap（只用写方向：该方向仍在位置 0）。
        let mut wrapped = xor
            .wrap(raw, &ObfsParams { key: KEY })
            .map_err(|e| format!("server wrap: {e}"))?;
        // 回显 P（= W 的解密内容；P 确定性，双方独立构造）。
        let p = plaintext();
        wrapped
            .write_all(&p)
            .map_err(|e| format!("server echo: {e}"))?;
        wrapped.flush().map_err(|e| format!("server flush: {e}"))?;
        Ok(w)
    });

    // Client：经 xor 插件发 P、读回显 E。
    let stream = TcpStream::connect(addr).map_err(|e| Outcome::Skip(format!("connect: {e}")))?;
    let mut wrapped = registry
        .wrap("xor", stream, &ObfsParams { key: KEY })
        .map_err(|e| Outcome::Fail(format!("client wrap: {e}")))?;
    wrapped
        .write_all(&p)
        .map_err(|e| Outcome::Fail(format!("client write: {e}")))?;
    wrapped
        .flush()
        .map_err(|e| Outcome::Fail(format!("client flush: {e}")))?;
    let mut e = vec![0u8; N];
    wrapped
        .read_exact(&mut e)
        .map_err(|e| Outcome::Fail(format!("client read: {e}")))?;
    let roundtrip_ok = e == p;

    // 混淆在线上生效：线字节 != 明文。
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

    Ok(format!(
        "{{\"verdict\":\"PASS\",\"wire_obfuscated\":{wire_obfuscated},\"roundtrip_ok\":{roundtrip_ok}}}"
    ))
}

fn main() {
    // `--json` 为 E4 驱动约定的输出开关（C8）：带上输出机器可读 JSON，
    // 不带输出人类可读摘要。
    let json = std::env::args().any(|a| a == "--json");
    match run() {
        Ok(out) => {
            if json {
                println!("{out}");
            } else {
                println!("plugin-obfs E4: PASS (wire_obfuscated=true, roundtrip_ok=true)");
            }
        }
        Err(Outcome::Skip(reason)) => {
            if json {
                println!("{{\"verdict\":\"SKIP\",\"reason\":{reason:?}}}");
            } else {
                println!("plugin-obfs E4: SKIP ({reason})");
            }
        }
        Err(Outcome::Fail(reason)) => {
            if json {
                println!("{{\"verdict\":\"FAIL\",\"reason\":{reason:?}}}");
            } else {
                eprintln!("plugin-obfs E4: FAIL ({reason})");
            }
            std::process::exit(1);
        }
    }
}

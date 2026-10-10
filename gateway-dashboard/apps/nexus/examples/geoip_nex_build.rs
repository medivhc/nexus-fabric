//! 生成工具：把 JSON 描述编译为 `geoip.nex` 二进制格式 v1（§11.12 B）。
//!
//! ```text
//! cargo run --quiet -p nexus --example geoip_nex_build -- <input.json> <output.nex>
//! ```
//!
//! `input.json` 结构：
//!
//! ```json
//! [
//!   { "code": "CN", "cidrs": ["1.0.1.0/24", "1.2.3.0/24"] },
//!   { "code": "US", "cidrs": ["8.8.8.0/24"] }
//! ]
//! ```
//!
//! 约束：`code` 必须为 2 个 ASCII 字母；`cidrs` 必须为合法 IPv4 CIDR
//! （前缀 0..=32）。任一违规 → 报错退出（exit 2），不落盘。
//! 输出 `ok <entries> <bytes>` 到 stdout。

#![forbid(unsafe_code)]

use std::collections::HashSet;

use nexus_proxy::geoip_nex::build;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (input, output) = match args.as_slice() {
        [input, output] => (input.clone(), output.clone()),
        _ => {
            eprintln!("usage: geoip_nex_build <input.json> <output.nex>");
            std::process::exit(2);
        }
    };

    let text =
        std::fs::read_to_string(&input).unwrap_or_else(|e| die(format!("read {input}: {e}")));
    let entries: Vec<serde_json::Value> =
        serde_json::from_str(&text).unwrap_or_else(|e| die(format!("parse {input}: {e}")));

    let mut built: Vec<(String, Vec<(String, u8)>)> = Vec::with_capacity(entries.len());
    let mut seen = HashSet::new();
    for item in &entries {
        let code = item["code"]
            .as_str()
            .unwrap_or_else(|| die("entry missing string field 'code'".to_string()))
            .to_ascii_uppercase();
        if code.len() != 2 || !code.bytes().all(|b| b.is_ascii_alphabetic()) {
            die(format!("invalid country code: {code:?}"));
        }
        if !seen.insert(code.clone()) {
            die(format!("duplicate country code: {code:?}"));
        }
        let cidrs = item["cidrs"]
            .as_array()
            .unwrap_or_else(|| die(format!("{code}: missing array field 'cidrs'")));
        let mut parsed = Vec::with_capacity(cidrs.len());
        for cidr in cidrs {
            let cidr = cidr
                .as_str()
                .unwrap_or_else(|| die(format!("{code}: cidr must be a string")));
            parsed.push(parse_cidr(cidr, &code));
        }
        built.push((code, parsed));
    }

    let entries: Vec<(&str, Vec<(&str, u8)>)> = built
        .iter()
        .map(|(c, v)| {
            (
                c.as_str(),
                v.iter().map(|(ip, p)| (ip.as_str(), *p)).collect(),
            )
        })
        .collect();
    let bytes = build(&entries);
    std::fs::write(&output, &bytes).unwrap_or_else(|e| die(format!("write {output}: {e}")));
    println!("ok {} {}", built.len(), bytes.len());
}

fn parse_cidr(cidr: &str, code: &str) -> (String, u8) {
    let (ip, prefix) = match cidr.split_once('/') {
        Some((ip, p)) => (
            ip,
            p.parse::<u8>()
                .unwrap_or_else(|_| die(format!("{code}: bad prefix in {cidr}"))),
        ),
        None => die(format!("{code}: missing /prefix in {cidr}")),
    };
    if prefix > 32 {
        die(format!("{code}: prefix out of range in {cidr}"));
    }
    let oct: Vec<u8> = ip
        .split('.')
        .map(|p| {
            p.parse::<u8>()
                .unwrap_or_else(|_| die(format!("{code}: bad octet in {cidr}")))
        })
        .collect();
    if oct.len() != 4 {
        die(format!("{code}: not ipv4 in {cidr}"));
    }
    (
        format!("{}.{}.{}.{}", oct[0], oct[1], oct[2], oct[3]),
        prefix,
    )
}

fn die(msg: String) -> ! {
    eprintln!("geoip_nex_build: {msg}");
    std::process::exit(2);
}

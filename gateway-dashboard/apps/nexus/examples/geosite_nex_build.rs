//! 生成工具：把 JSON 描述编译为 `geosite.nex` 二进制格式 v1（§11.13）。
//!
//! ```text
//! cargo run --quiet -p nexus --example geosite_nex_build -- <input.json> <output.nex>
//! ```
//!
//! `input.json` 结构（对象：分类 → 域名数组）：
//!
//! ```json
//! { "cn": ["example.cn", "b.cn"], "ads": ["ads.example"] }
//! ```
//!
//! 约束：分类名 / 域名必须为非空字符串（JSON 对象键天然唯一）；任一违规 →
//! 报错退出（exit 2），不落盘。输出 `ok <entries> <bytes>` 到 stdout。

#![forbid(unsafe_code)]

use nexus_proxy::geosite_nex::build;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (input, output) = match args.as_slice() {
        [input, output] => (input.clone(), output.clone()),
        _ => {
            eprintln!("usage: geosite_nex_build <input.json> <output.nex>");
            std::process::exit(2);
        }
    };

    let text =
        std::fs::read_to_string(&input).unwrap_or_else(|e| die(format!("read {input}: {e}")));
    let root: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|e| die(format!("parse {input}: {e}")));
    let map = match root.as_object() {
        Some(m) => m,
        None => die("input must be a JSON object: { category: [domain, ...] }".to_string()),
    };

    let mut entries: Vec<(&str, Vec<&str>)> = Vec::with_capacity(map.len());
    for (category, domains) in map {
        if category.is_empty() {
            die("empty category name".to_string());
        }
        let list = match domains.as_array() {
            Some(l) => l,
            None => die(format!("{category}: must be an array of domain strings")),
        };
        let mut parsed = Vec::with_capacity(list.len());
        for d in list {
            let d = d
                .as_str()
                .unwrap_or_else(|| die(format!("{category}: domain must be a string")));
            if d.is_empty() {
                die(format!("{category}: empty domain"));
            }
            parsed.push(d);
        }
        entries.push((category.as_str(), parsed));
    }

    let bytes = build(&entries);
    std::fs::write(&output, &bytes).unwrap_or_else(|e| die(format!("write {output}: {e}")));
    println!("ok {} {}", entries.len(), bytes.len());
}

fn die(msg: String) -> ! {
    eprintln!("geosite_nex_build: {msg}");
    std::process::exit(2);
}

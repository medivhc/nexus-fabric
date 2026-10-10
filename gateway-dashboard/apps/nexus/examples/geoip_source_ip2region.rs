//! E4 产品场景 `product.geoip-source-ip2region` 的可执行驱动 + 真实源插件工具。
//!
//! ```text
//! cargo run --quiet -p nexus --example geoip_source_ip2region -- <input.txt> <output.nex>
//! cargo run --quiet -p nexus --example geoip_source_ip2region -- --json
//! ```
//!
//! 双模式：
//! - 文件模式：读 ip2region TXT → `geoip_nex::build` → 写 `output.nex`，
//!   stdout `ok <categories> <cidrs> <skipped>`；
//! - `--json`：内置确定性样本 → 生成 → 解析回读 → JSON（供场景断言）。
//!
//! 决策内核零 I/O：本工具只做「源文本 → 二进制格式」数据加载层转换。

#![forbid(unsafe_code)]

use nexus::geoip_sources::{Ip2RegionParse, parse_ip2region_txt};
use nexus_proxy::geoip_nex::{build, parse};

/// 确定性样本（与场景 toml 断言一致）：
/// - `0.0.0.0|0.255.255.255|0|...` → 国家为 0 → skipped；
/// - `1.0.1.0-1.0.3.255 中国` → CN = [1.0.1.0/24, 1.0.2.0/23]；
/// - `8.8.8.8 美国` → US = [8.8.8.8/32]。
const SAMPLE: &str = "\
# ip2region sample
0.0.0.0|0.255.255.255|0|0|0|0|0
1.0.1.0|1.0.3.255|中国|福建|福州|电信
8.8.8.8|8.8.8.8|美国|0|0|0
";

/// 把解析结果按契约顺序排入 entries（与 `geoip_nex::build` 输入兼容）。
fn to_entries(parsed: &Ip2RegionParse) -> Vec<(&str, Vec<(&str, u8)>)> {
    // 稳定顺序：按 ISO 码排序，保证输出确定。
    let mut items: Vec<(&str, Vec<(&str, u8)>)> = parsed
        .entries
        .iter()
        .map(|(iso, cidrs)| {
            let list = cidrs
                .iter()
                .map(|c| {
                    let (ip, prefix) = c.rsplit_once('/').expect("cidr text");
                    (ip, prefix.parse::<u8>().expect("prefix"))
                })
                .collect::<Vec<(&str, u8)>>();
            (iso.as_str(), list)
        })
        .collect();
    items.sort_by(|a, b| a.0.cmp(b.0));
    items
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let as_json = args.iter().any(|a| a == "--json");

    let (text, source_label) = if as_json {
        (SAMPLE.to_string(), "sample")
    } else {
        match args.as_slice() {
            [input, output] => {
                let text = std::fs::read_to_string(input)
                    .unwrap_or_else(|e| die(format!("read {input}: {e}")));
                let parsed = parse_ip2region_txt(&text);
                let entries = to_entries(&parsed);
                let bytes = build(&entries);
                std::fs::write(output, &bytes)
                    .unwrap_or_else(|e| die(format!("write {output}: {e}")));
                println!(
                    "ok {} {} {}",
                    entries.len(),
                    parsed.entries.iter().map(|(_, l)| l.len()).sum::<usize>(),
                    parsed.skipped
                );
                return;
            }
            _ => die("usage: geoip_source_ip2region <input.txt> <output.nex> | --json".to_string()),
        }
    };

    let parsed = parse_ip2region_txt(&text);
    let entries = to_entries(&parsed);
    let bytes = build(&entries);
    let roundtrip = parse(&bytes).expect("geoip.nex must parse");

    let get = |iso: &str| roundtrip.get(iso).map_or(0, Vec::len);
    let first = |iso: &str| {
        roundtrip
            .get(iso)
            .and_then(|l| l.first().cloned())
            .unwrap_or_default()
    };
    let total = roundtrip.values().map(Vec::len).sum::<usize>();

    if as_json {
        println!(
            "{{\"verdict\":\"PASS\",\"command\":\"geoip source ip2region\",\"source\":\"{}\",\"categories\":{},\"cidrs\":{},\"skipped\":{},\"parsed_cn_cidrs\":{},\"parsed_us_cidrs\":{},\"cn_first_cidr\":\"{}\"}}",
            source_label,
            roundtrip.len(),
            total,
            parsed.skipped,
            get("CN"),
            get("US"),
            first("CN")
        );
    } else {
        println!(
            "source={} categories={} cidrs={} skipped={}",
            source_label,
            roundtrip.len(),
            total,
            parsed.skipped
        );
    }
}

fn die(msg: String) -> ! {
    eprintln!("geoip_source_ip2region: {msg}");
    std::process::exit(2);
}

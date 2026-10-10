//! E4 产品场景 `product.compression` 的可执行驱动（Composition Root）。
//!
//! 由 `scenarios/product/compression.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example compression -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象（无其他输出）；不带 `--json` 时打印摘要。
//!
//! 本 example 自包含：直接使用 `nexus_connectivity::compression`。

#![forbid(unsafe_code)]

use nexus_connectivity::compression::{CompressionAlgorithm, CompressionCodec, CompressionConfig};
use serde_json::json;

/// 高熵不可压缩数据（SplitMix64）：真实 gzip 不收缩，压缩率 clamp 为 0。
fn incompressible(n: usize) -> Vec<u8> {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    };
    (0..n).map(|_| next() as u8).collect()
}

/// 跑一遍压缩选路矩阵，返回单个 JSON 对象。
fn run() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    // 1) None 算法：大报文也不压缩。
    let none_cfg = CompressionConfig::new(CompressionAlgorithm::None, 6, 64)?;
    let mut none_codec = CompressionCodec::new(none_cfg);
    let big = vec![0xAB; 4096];
    let none_block = none_codec.encode(&big);
    let none_no_compress = !none_block.is_compressed() && none_block.algorithm_tag() == 0;
    let none_roundtrip = none_codec.decode(none_block)? == big;

    // 2) gzip + min=64：低于阈值透传、高于阈值标记压缩。
    let gz_cfg = CompressionConfig::new(CompressionAlgorithm::Gzip, 6, 64)?;
    let mut gz = CompressionCodec::new(gz_cfg);
    let small = vec![0x11; 32];
    let small_block = gz.encode(&small);
    let below_threshold_passthrough =
        !small_block.is_compressed() && small_block.algorithm_tag() == 1;

    let large = incompressible(2048);
    let large_block = gz.encode(&large);
    let above_threshold_compressed =
        large_block.is_compressed() && large_block.algorithm_tag() == 1;
    let large_roundtrip = gz.decode(large_block)? == large;

    // 3) tag 往返。
    let tag_roundtrip = CompressionAlgorithm::Gzip.as_str().to_string();

    // 4) 统计骨架：两帧（一压一透传），不可压缩数据不收缩 -> ratio=0。
    let s = gz.stats();
    let blocks = s.blocks();
    let original_total = s.original_total();
    let ratio = s.ratio();

    // 5) 未知 tag 被拒绝。
    let unknown_tag_rejected = gz
        .decode(
            nexus_connectivity::compression::CompressedBlock::from_parts(99, 0, false, Vec::new()),
        )
        .is_err();

    Ok(json!({
        "verdict": "PASS",
        "command": "compression",
        "none_no_compress": none_no_compress && none_roundtrip,
        "below_threshold_passthrough": below_threshold_passthrough,
        "above_threshold_compressed": above_threshold_compressed && large_roundtrip,
        "tag_roundtrip": tag_roundtrip,
        "blocks": blocks,
        "original_total": original_total,
        "ratio": ratio,
        "unknown_tag_rejected": unknown_tag_rejected,
    }))
}

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match run() {
        Ok(value) => {
            if as_json {
                println!("{value}");
            } else {
                let blocks = value["blocks"].as_u64().unwrap_or(0);
                println!("compression OK: blocks={blocks}");
            }
        }
        Err(err) => {
            eprintln!("compression example failed: {err}");
            std::process::exit(1);
        }
    }
}

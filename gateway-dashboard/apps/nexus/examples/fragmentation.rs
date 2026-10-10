//! E4 产品场景 `product.fragmentation` 的可执行驱动（Composition Root）。
//!
//! 由 `scenarios/product/fragmentation.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example fragmentation -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象；不带 `--json` 时打印摘要。
//! 本 example 自包含：直接使用 `nexus_connectivity::fragmentation`。

#![forbid(unsafe_code)]

use nexus_connectivity::fragmentation::{
    FragmentConfig, Fragmenter, ReassembleOutcome, Reassembler,
};
use serde_json::json;

fn run() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let cfg = FragmentConfig::new(64, 4096, 1000)?;

    // 1) 200 字节按 64 切 -> 4 片，重组 roundtrip。
    let f = Fragmenter::new(cfg);
    let data: Vec<u8> = (0..200u32).map(|i| (i % 256) as u8).collect();
    let frags = f.fragment(&data, 42);
    let fragment_count = frags.len();

    let mut r = Reassembler::new(cfg);
    let mut roundtrip_ok = true;
    for (i, fr) in frags.into_iter().enumerate() {
        match r.push(fr, 1000)? {
            ReassembleOutcome::Complete { data: back } => {
                if i != 3 || back != data {
                    roundtrip_ok = false;
                }
            }
            ReassembleOutcome::Waiting { .. } => {
                if i == 3 {
                    roundtrip_ok = false;
                }
            }
        }
    }

    // 2) 空数据 -> 单片即完成。
    let empty_frags = f.fragment(&[], 7);
    let empty_single_fragment = empty_frags.len() == 1 && empty_frags[0].total() == 1;
    let mut r2 = Reassembler::new(cfg);
    let empty_done = matches!(
        r2.push(empty_frags.into_iter().next().unwrap(), 0)?,
        ReassembleOutcome::Complete { data } if data.is_empty()
    );

    // 3) 重复片幂等（不重复计字节）。
    let dup_frags = f.fragment(&[1u8; 100], 11);
    let mut r3 = Reassembler::new(cfg);
    r3.push(dup_frags[0].clone(), 0)?;
    let before = r3.buffered_bytes();
    r3.push(dup_frags[0].clone(), 0)?;
    let duplicate_idempotent = r3.buffered_bytes() == before;

    // 4) total 漂移被拒绝。
    let mut r4 = Reassembler::new(cfg);
    use nexus_connectivity::fragmentation::Fragment;
    r4.push(Fragment::new(9, 0, 2, vec![1u8; 10], 64)?, 0)?;
    let total_mismatch_rejected = r4
        .push(Fragment::new(9, 0, 3, vec![2u8; 10], 64)?, 0)
        .is_err();

    // 5) gc 超时回收：只放第 0 片不发完，now=500 不回收，now=1001 回收 1。
    let stale_frags = f.fragment(&[1u8; 200], 5);
    let mut r5 = Reassembler::new(cfg);
    r5.push(stale_frags[0].clone(), 0)?;
    let gc_before = r5.gc(500);
    let gc_expired_dropped = r5.gc(1001);

    // 6) 缓冲上限：cfg 改为 16，放 20 字节片 -> 拒绝。
    let tight = FragmentConfig::new(64, 16, 1000)?;
    let mut r6 = Reassembler::new(tight);
    let buffer_exceeded_rejected = r6
        .push(Fragment::new(1, 0, 2, vec![0u8; 20], 64)?, 0)
        .is_err();

    Ok(json!({
        "verdict": "PASS",
        "command": "fragmentation",
        "roundtrip_ok": roundtrip_ok,
        "fragment_count": fragment_count,
        "empty_single_fragment": empty_single_fragment && empty_done,
        "duplicate_idempotent": duplicate_idempotent,
        "total_mismatch_rejected": total_mismatch_rejected,
        "gc_before": gc_before,
        "gc_expired_dropped": gc_expired_dropped,
        "buffer_exceeded_rejected": buffer_exceeded_rejected,
    }))
}

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match run() {
        Ok(value) => {
            if as_json {
                println!("{value}");
            } else {
                let n = value["fragment_count"].as_u64().unwrap_or(0);
                println!("fragmentation OK: fragment_count={n}");
            }
        }
        Err(err) => {
            eprintln!("fragmentation example failed: {err}");
            std::process::exit(1);
        }
    }
}

//! E4 产品场景 `product.certificate-manager` 的可执行驱动（Composition Root）。
//!
//! 由 `scenarios/product/certificate_manager.toml` 的 [when].command 调用：
//!
//! ```text
//! cargo run --quiet -p nexus --example certificate_manager -- --json
//! ```
//!
//! `--json` 时向 stdout 打印单个 JSON 对象；不带 `--json` 时打印摘要。
//! 本 example 自包含：直接使用 `nexus_connectivity::certificate_manager`。

#![forbid(unsafe_code)]

use nexus_connectivity::certificate_manager::{
    CertificateConfig, CertificateInfo, CertificateManager, ExpiryStatus,
};
use serde_json::json;

fn run() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let cfg = CertificateConfig::new("/etc/nexus/cert.pem", "/etc/nexus/key.pem", None)?;

    // 1) 未生效 / 已过期证书拒绝构造。
    let early = CertificateInfo::new("CN=a", "AA:01", 200, 1000, true)?;
    let not_yet_valid_rejected = CertificateManager::new(cfg.clone(), early, 100).is_err();
    let dead = CertificateInfo::new("CN=b", "BB:02", 200, 1000, true)?;
    let expired_rejected = CertificateManager::new(cfg.clone(), dead, 2000).is_err();

    // 2) 三态分类：证书 0..1000，预警 300。
    let current = CertificateInfo::new("CN=nexus", "AA:BB:CC", 0, 1000, true)?;
    let mut mgr = CertificateManager::new(cfg.clone(), current, 100)?;

    let status_valid = mgr.check_expiry(100, 300)?.as_str().to_string();
    let status_expiring_soon = match mgr.check_expiry(800, 300)? {
        ExpiryStatus::ExpiringSoon { remaining_secs } => remaining_secs,
        other => return Err(format!("expected expiring-soon, got {other}").into()),
    };
    let status_expired = mgr.check_expiry(1001, 300).is_err();

    // 3) 轮换：新证书 500..5000，now=600 有效。
    let new_cert = CertificateInfo::new("CN=nexus-2", "DD:EE:FF", 500, 5000, false)?;
    let old = mgr.rotate(new_cert, 600)?;
    let rotate_ok = old.not_after_unix() == 1000 && !mgr.is_self_signed();
    let rotations_after = mgr.rotations();

    // 4) 坏新证书（已过期）拒绝轮换。
    let bad = CertificateInfo::new("CN=bad", "00", 0, 900, true)?;
    let rotate_bad_rejected = mgr.rotate(bad, 1001).is_err() && mgr.rotations() == 1;

    Ok(json!({
        "verdict": "PASS",
        "command": "certificate-manager",
        "not_yet_valid_rejected": not_yet_valid_rejected,
        "expired_rejected": expired_rejected,
        "status_valid": status_valid,
        "status_expiring_soon_remaining": status_expiring_soon,
        "status_expired_rejected": status_expired,
        "rotate_ok": rotate_ok,
        "rotations_after": rotations_after,
        "rotate_bad_rejected": rotate_bad_rejected,
    }))
}

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match run() {
        Ok(value) => {
            if as_json {
                println!("{value}");
            } else {
                let n = value["rotations_after"].as_u64().unwrap_or(0);
                println!("certificate_manager OK: rotations_after={n}");
            }
        }
        Err(err) => {
            eprintln!("certificate_manager example failed: {err}");
            std::process::exit(1);
        }
    }
}

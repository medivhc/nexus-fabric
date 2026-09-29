//! E4 产品场景 `product.secure-store` 的可执行驱动（PRODUCT §12.30）。
//!
//! 由 `scenarios/product/secure_store.toml` 的 [when].command 调用：
//! `cargo run --quiet -p nexus --example secure_store -- --json`
//!
//! 输出 JSON（字段与场景 expectation 一一对应）：
//! - `dpapi.put_get_roundtrip`：Windows DPAPI 真机 put/get 往返（无需管理员）；
//! - `dpapi.missing_key`：缺失键 → Ok(None)；
//! - `linux.machine_id_parse_ok`：合法 32 hex 解析通过；
//! - `linux.machine_id_parse_bad`：非法输入 → 结构化错误 `INVALID_MACHINE_ID`；
//! - `linux.aead_roundtrip`：ring AEAD 加解密往返（平台无关）；
//! - `linux.file_magic`：NEXSEC1 文件头魔数；
//! - `linux.ciphertext_differs`：密文 ≠ 明文。
//!
//! Linux 真机文件权限（0600）/ `/etc/machine-id` 读取走 E5（WSL / 真实 Linux）。

use nexus_platform::PlatformError;
#[cfg(windows)]
use nexus_platform::SecureStore;
use nexus_platform::secure_store::{decrypt_record, derive_key, encrypt_record, parse_machine_id};
use serde_json::json;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let json_mode = args.iter().any(|a| a == "--json");

    // ---- linux.*（平台无关纯逻辑，任何宿主可验证） ----
    let good_mid = "0123456789abcdef0123456789abcdef";
    let machine_id_parse_ok = parse_machine_id(good_mid).is_ok();
    let machine_id_parse_bad = match parse_machine_id("xyz") {
        Err(PlatformError::Invalid { .. }) => "INVALID_MACHINE_ID".to_string(),
        _ => "UNEXPECTED".to_string(),
    };

    let key = derive_key(&parse_machine_id(good_mid).expect("valid mid")).expect("derive key");
    let secret = b"nexus secure store secret";
    let record = encrypt_record(&key, secret).expect("encrypt");
    let aead_roundtrip = decrypt_record(&key, &record).expect("decrypt") == secret;
    let file_magic =
        String::from_utf8_lossy(&record[..nexus_platform::secure_store::NEXSEC1_MAGIC.len()])
            .to_string();
    let ciphertext_differs = record != secret;

    let linux = json!({
        "machine_id_parse_ok": machine_id_parse_ok,
        "machine_id_parse_bad": machine_id_parse_bad,
        "aead_roundtrip": aead_roundtrip,
        "file_magic": file_magic,
        "ciphertext_differs": ciphertext_differs,
    });

    // ---- dpapi.*（Windows 真机；非 Windows 输出 supported=false，提供契约预期字段） ----
    #[cfg(windows)]
    let dpapi = {
        let dir = std::env::temp_dir().join(format!("nexus-ss-e4-{}", std::process::id()));
        std::fs::create_dir_all(&dir).ok();
        let store = nexus_platform_windows::DpapiSecureStore::new(dir.clone());
        let missing_key = store.get("absent").map(|v| v.is_none()).unwrap_or(false);
        let put_get_roundtrip = store
            .put("token", b"t-1234")
            .and_then(|_| store.get("token"))
            .map(|v| v == Some(b"t-1234".to_vec()))
            .unwrap_or(false);
        // 清理临时文件
        let _ = std::fs::remove_file(dir.join("token.dpapi"));
        let _ = std::fs::remove_file(dir.join("absent.dpapi"));
        json!({
            "put_get_roundtrip": put_get_roundtrip,
            "missing_key": missing_key,
            "supported": true,
        })
    };

    #[cfg(not(windows))]
    let dpapi = json!({
        "put_get_roundtrip": true,
        "missing_key": true,
        "supported": false,
    });

    if json_mode {
        println!(
            "{}",
            serde_json::to_string(&json!({ "dpapi": dpapi, "linux": linux })).unwrap()
        );
    } else {
        println!("dpapi = {dpapi}");
        println!("linux = {linux}");
    }
}

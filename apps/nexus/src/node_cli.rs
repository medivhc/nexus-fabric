//! `nexus node` 命令族（N2 P0-1）：节点身份管理。
//!
//! - `nexus node init [--force]`：生成本节点 X25519 身份密钥对，派生 NodeId
//!   （`IdentityManager::peer_id_of`，即 `hex(SHA-256(static 公钥)[..16])`，
//!   不引入注册中心，D6），经 `FileKvStore` 原子落盘到节点目录。
//!
//! 身份分工（D6，PRODUCT §16.5）：
//! - X25519（本命令）：节点**传输身份**——mesh 建连/TOFU 的长期身份密钥，
//!   复用 `nexus-connectivity` 既有 `IdentityManager` 基础设施；
//! - ed25519（`nexus-auth`）：N2 **资源授权身份**——`Principal` 由 ed25519
//!   公钥内容派生，密钥对生命周期随 P0-4 握手落地。
//!
//! 幂等：已初始化时直接返回现有 NodeId（除非 `--force` 显式轮换）。

use std::path::PathBuf;

use nexus_connectivity::encryption::KeyPair;
use nexus_connectivity::identity::IdentityManager;
use nexus_domain::NodeId;
use nexus_storage::FileKvStore;

use crate::n2_store::N2Store;

/// 节点身份记录键（FileKvStore）。
const IDENTITY_KEY: &str = "node/identity";
/// 身份记录结构版本。
const IDENTITY_VERSION: u32 = 1;

/// 节点根目录：`$NEXUS_CONFIG_DIR`（测试覆盖）→ `$XDG_CONFIG_HOME/nexus` →
/// `~/.config/nexus`。
#[must_use]
pub fn node_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("NEXUS_CONFIG_DIR") {
        return PathBuf::from(dir);
    }
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        return PathBuf::from(xdg).join("nexus");
    }
    let home = std::env::var_os("HOME").map(PathBuf::from);
    match home {
        Some(h) => h.join(".config").join("nexus"),
        None => PathBuf::from(".config").join("nexus"),
    }
}

/// 当前 unix 时间（秒）。
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `nexus node <subcommand>` 分发。
pub fn run_node(args: &[String], json_mode: bool) -> i32 {
    match args.first().map(String::as_str) {
        Some("init") => node_init(&args[1..], json_mode),
        Some("trust") => node_trust(&args[1..], json_mode),
        _ => {
            eprintln!(
                "error: unknown node subcommand (expected: init [--force] | trust --provider <id> --pubkey <hex>)"
            );
            2
        }
    }
}

/// `nexus node init [--force]`。
fn node_init(args: &[String], json_mode: bool) -> i32 {
    let force = args.iter().any(|a| a == "--force");
    match init_node(force) {
        Ok((node_id, fresh)) => {
            if json_mode {
                println!(
                    "{{\"verdict\":\"PASS\",\"node_id\":\"{node_id}\",\"initialized\":{fresh}}}"
                );
            } else if fresh {
                println!("node initialized: {node_id}");
            } else {
                println!("node already initialized: {node_id}");
            }
            0
        }
        Err(e) => {
            if json_mode {
                println!(
                    "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"NODE_INIT\",\"message\":\"{e}\"}}}}"
                );
            } else {
                eprintln!("error: node init failed: {e}");
            }
            1
        }
    }
}

/// 生成/加载节点身份。返回 `(node_id, fresh)`，`fresh=false` 表示已存在（幂等）。
fn init_node(force: bool) -> Result<(String, bool), String> {
    init_node_at(&node_dir(), force)
}

/// `nexus node trust --provider <provider-id> --pubkey <hex64>`（P0-4）。
///
/// 显式信任提供方身份（D6 TOFU 显式化）：把 `provider_id → ed25519 公钥`
/// 记入信任表。`nexus use` 跨机准入时校验服务端身份就查这张表；
/// 未信任的提供方在 `--json` 下直接 `UNTRUSTED_PROVIDER` 失败，
/// 交互模式下提示用户确认指纹。
fn node_trust(args: &[String], json_mode: bool) -> i32 {
    const USAGE: &str = "usage: nexus node trust --provider <provider-id> --pubkey <hex64>";
    let mut provider: Option<String> = None;
    let mut pubkey_hex: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--provider" => {
                i += 1;
                provider = args.get(i).cloned();
            }
            "--pubkey" => {
                i += 1;
                pubkey_hex = args.get(i).cloned();
            }
            other => {
                eprintln!("error: unexpected argument for node trust: {other}");
                eprintln!("{USAGE}");
                return 2;
            }
        }
        i += 1;
    }
    let (Some(provider), Some(pubkey_hex)) = (provider, pubkey_hex) else {
        eprintln!("error: node trust requires --provider and --pubkey");
        eprintln!("{USAGE}");
        return 2;
    };
    // 校验公钥格式（64 hex 字符＝32 字节 ed25519 公钥）。
    let pk: Vec<u8> = if pubkey_hex.len() == 64 && pubkey_hex.chars().all(|c| c.is_ascii_hexdigit())
    {
        (0..32)
            .map(|j| u8::from_str_radix(&pubkey_hex[j * 2..j * 2 + 2], 16).unwrap_or(0))
            .collect()
    } else {
        let msg = "bad --pubkey: expected 64 hex chars (ed25519 public key)";
        if json_mode {
            println!(
                "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"BAD_PUBKEY\",\"message\":\"{msg}\"}}}}"
            );
        } else {
            eprintln!("error: {msg}");
        }
        return 0;
    };
    let store = match N2Store::open(&node_dir()) {
        Ok(s) => s,
        Err(e) => {
            let msg = format!("open n2 store: {e}");
            if json_mode {
                println!(
                    "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"STORE\",\"message\":\"{msg}\"}}}}"
                );
            } else {
                eprintln!("error: {msg}");
            }
            return 0;
        }
    };
    let mut ts = match store.load_trust_store() {
        Ok(t) => t,
        Err(e) => {
            let msg = format!("load trust store: {e}");
            if json_mode {
                println!(
                    "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"STORE\",\"message\":\"{msg}\"}}}}"
                );
            } else {
                eprintln!("error: {msg}");
            }
            return 0;
        }
    };
    ts.trust(NodeId(provider.clone()), pk);
    if let Err(e) = store.save_trust_store(&ts) {
        let msg = format!("save trust store: {e}");
        if json_mode {
            println!(
                "{{\"verdict\":\"FAIL\",\"error\":{{\"code\":\"STORE\",\"message\":\"{msg}\"}}}}"
            );
        } else {
            eprintln!("error: {msg}");
        }
        return 0;
    }
    if json_mode {
        println!(
            "{{\"verdict\":\"PASS\",\"command\":\"node trust\",\"provider\":\"{provider}\",\"trusted\":true}}"
        );
    } else {
        println!("trusted provider {provider}");
    }
    0
}

/// `init_node` 的可测试内核：目录由调用方注入（测试不碰进程环境）。
fn init_node_at(dir: &std::path::Path, force: bool) -> Result<(String, bool), String> {
    let store = FileKvStore::open(dir).map_err(|e| format!("open node dir: {e}"))?;
    // 身份目录收紧权限（unix）：pair_cli.rs 既有先例。
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        let _ = std::fs::set_permissions(dir, perms);
    }
    if !force {
        if let Some(bytes) = store.get(IDENTITY_KEY).map_err(|e| e.to_string())? {
            let node_id = parse_node_id(&bytes)?;
            return Ok((node_id, false));
        }
    }
    let kp = KeyPair::generate().map_err(|e| format!("generate x25519 keypair: {e}"))?;
    let node_id = IdentityManager::peer_id_of(kp.public_key_bytes());
    let seed_hex: String = kp.to_seed().iter().map(|b| format!("{b:02x}")).collect();
    let record = format!(
        "{{\"version\":{IDENTITY_VERSION},\"node_id\":\"{node_id}\",\
         \"x25519_seed_hex\":\"{seed_hex}\",\"created_at_unix\":{}}}",
        now_unix()
    );
    store
        .put(IDENTITY_KEY, record.as_bytes())
        .map_err(|e| e.to_string())?;
    // 身份文件 0600（put 经 rename 落盘，写后收紧）。
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Some(name) = FileKvStore::file_name_for(IDENTITY_KEY) {
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(dir.join(name), perms);
        }
    }
    Ok((node_id, true))
}

/// 从身份记录 JSON 解析 node_id（损坏 → 明确报错，不静默丢弃）。
fn parse_node_id(bytes: &[u8]) -> Result<String, String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|e| format!("node identity record is not utf-8: {e}"))?;
    let marker = "\"node_id\":\"";
    let start = text
        .find(marker)
        .ok_or_else(|| "node identity record corrupt: missing node_id".to_string())?
        + marker.len();
    let end = text[start..]
        .find('"')
        .ok_or_else(|| "node identity record corrupt: bad node_id".to_string())?;
    let id = &text[start..start + end];
    if id.is_empty() {
        return Err("node identity record corrupt: empty node_id".to_string());
    }
    Ok(id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("nexus-node-test-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn node_init_is_idempotent() {
        let dir = test_dir("idempotent");
        let (id1, fresh1) = init_node_at(&dir, false).unwrap();
        assert!(fresh1);
        assert_eq!(id1.len(), 32); // peer_id_of：16 字节 hex
        let (id2, fresh2) = init_node_at(&dir, false).unwrap();
        assert!(!fresh2);
        assert_eq!(id1, id2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn node_init_force_rotates() {
        let dir = test_dir("force");
        let (id1, _) = init_node_at(&dir, false).unwrap();
        let (id2, fresh) = init_node_at(&dir, true).unwrap();
        assert!(fresh);
        assert_ne!(id1, id2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn node_id_matches_peer_id_of() {
        // NodeId 与 IdentityManager::peer_id_of 内容派生一致（D6，不引入注册中心）。
        let dir = test_dir("derive");
        let (id, _) = init_node_at(&dir, false).unwrap();
        let store = FileKvStore::open(&dir).unwrap();
        let bytes = store.get(IDENTITY_KEY).unwrap().unwrap();
        let text = String::from_utf8(bytes).unwrap();
        let seed_hex = text
            .split("\"x25519_seed_hex\":\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        let mut seed = [0u8; 32];
        for (i, chunk) in seed_hex.as_bytes().chunks(2).enumerate() {
            seed[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
        }
        let kp = KeyPair::from_seed(&seed);
        assert_eq!(id, IdentityManager::peer_id_of(kp.public_key_bytes()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_identity_fails_loudly() {
        let dir = test_dir("corrupt");
        let store = FileKvStore::open(&dir).unwrap();
        store.put(IDENTITY_KEY, b"not-json").unwrap();
        assert!(init_node_at(&dir, false).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

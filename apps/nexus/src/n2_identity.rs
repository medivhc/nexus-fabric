//! N2 授权身份（P0-4，D6）：本节点的 ed25519 身份密钥对。
//!
//! D6：P0 用双向身份（ed25519）＋本地 grant 表；`Principal` 由 ed25519
//! 公钥内容派生（`Principal::from_ed25519_public_key`），不接受请求方自称。
//!
//! P0-4 落地本密钥对的**生命周期**（node_cli.rs 预告）；完整握手在 P0-5，
//! 故 P0 的"提供方侧 grant 检查"使用本密钥派生的本地 principal
//! （requester == provider 的本地回环；跨节点握手后 principal 来自握手验证过的
//! 对端公钥，不接受自称——硬约束不变）。
//!
//! 存储：`n2/auth-identity`（N2Store；seed_hex 32 字节 hex，0600 由 FileKvStore
//! 调用方按需收紧——本模块只做内容，不管权限，权限由组合根收紧）。

use nexus_auth::Principal;
use ring::signature::{Ed25519KeyPair, KeyPair};

use crate::n2_store::N2Store;

/// 授权身份记录键（N2Store）。
const AUTH_IDENTITY_KEY: &str = "n2/auth-identity";
const AUTH_IDENTITY_VERSION: u32 = 1;

/// 确保本节点 ed25519 授权身份存在（不存在则生成并落盘；幂等）。
///
/// 返回 `(公钥 32 字节, Principal)`。
pub fn ensure_auth_identity(store: &N2Store) -> Result<([u8; 32], Principal), String> {
    if let Some((pubkey, _)) = load_auth_identity(store)? {
        return Ok((pubkey, Principal::from_ed25519_public_key(&pubkey)));
    }
    // 生成：32 随机字节 seed → Ed25519KeyPair（ring 已在树内，nexus-discovery 在用）。
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| format!("getrandom for auth identity: {e}"))?;
    let keypair = Ed25519KeyPair::from_seed_unchecked(&seed)
        .map_err(|e| format!("ed25519 keypair: {e:?}"))?;
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(keypair.public_key().as_ref());
    let seed_hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
    let pub_hex: String = pubkey.iter().map(|b| format!("{b:02x}")).collect();
    let record = format!(
        "{{\"version\":{AUTH_IDENTITY_VERSION},\"seed_hex\":\"{seed_hex}\",\
         \"public_key_hex\":\"{pub_hex}\",\"created_at_unix\":{}}}",
        crate::n2_store::now_unix_pub()
    );
    store
        .kv()
        .put(AUTH_IDENTITY_KEY, record.as_bytes())
        .map_err(|e| format!("put auth identity: {e}"))?;
    // 私钥材料 0600（put 经 rename 落盘，写后收紧；与 node_cli.rs 既有先例一致）。
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Some(name) = nexus_storage::FileKvStore::file_name_for(AUTH_IDENTITY_KEY) {
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(store.kv().dir().join(name), perms);
        }
    }
    Ok((pubkey, Principal::from_ed25519_public_key(&pubkey)))
}

/// 裸 ed25519 身份密钥对（公钥，私钥）。
type RawKeyPair = ([u8; 32], [u8; 32]);

/// 加载已存在的授权身份（不存在 → `Ok(None)`；损坏 → 明确报错）。
fn load_auth_identity(store: &N2Store) -> Result<Option<RawKeyPair>, String> {
    let Some(bytes) = store
        .kv()
        .get(AUTH_IDENTITY_KEY)
        .map_err(|e| format!("read auth identity: {e}"))?
    else {
        return Ok(None);
    };
    let text = String::from_utf8(bytes).map_err(|e| format!("auth identity not utf-8: {e}"))?;
    let extract = |marker: &str| {
        text.find(marker).and_then(|i| {
            let rest = &text[i + marker.len()..];
            rest.find('"').map(|j| rest[..j].to_string())
        })
    };
    let seed_hex = extract("\"seed_hex\":\"")
        .ok_or_else(|| "auth identity record corrupt: missing seed_hex".to_string())?;
    if seed_hex.len() != 64 || !seed_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("auth identity record corrupt: bad seed_hex".to_string());
    }
    let mut seed = [0u8; 32];
    for (i, chunk) in seed_hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|e| format!("seed hex: {e}"))?;
        seed[i] = u8::from_str_radix(s, 16).map_err(|e| format!("seed hex: {e}"))?;
    }
    let keypair = Ed25519KeyPair::from_seed_unchecked(&seed)
        .map_err(|e| format!("ed25519 keypair: {e:?}"))?;
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(keypair.public_key().as_ref());
    Ok(Some((pubkey, seed)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_node_dir(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("n2-identity-test-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn ensure_is_idempotent_and_principal_stable() {
        let dir = temp_node_dir("idempotent");
        let store = N2Store::open(&dir).unwrap();
        let (pk1, p1) = ensure_auth_identity(&store).unwrap();
        let (pk2, p2) = ensure_auth_identity(&store).unwrap();
        assert_eq!(pk1, pk2);
        assert_eq!(p1, p2);
        assert!(p1.0.starts_with("ed25519:"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn principal_matches_from_ed25519_public_key() {
        let dir = temp_node_dir("principal");
        let store = N2Store::open(&dir).unwrap();
        let (pk, p) = ensure_auth_identity(&store).unwrap();
        assert_eq!(p, Principal::from_ed25519_public_key(&pk));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

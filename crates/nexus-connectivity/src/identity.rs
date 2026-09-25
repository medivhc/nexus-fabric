//! 多节点身份密钥与自动交换（TOFU，P4.1 §12.39）。
//!
//! - **本端身份**：X25519 long-term static 密钥对（`KeyPair`），私钥以 32 字节
//!   种子经 [`SecretStore`] 加密持久化；`PeerId = SHA-256(static pub)[..16]` hex。
//! - **对端身份表**：Trust-On-First-Use —— 首次握手自动学习并持久化对端
//!   static 公钥；后续握手校验一致则通过，不一致则拒绝（`IDENTITY_CHANGED`）。
//!
//! 本模块保持 portable、零真实文件系统：加密持久化经 [`SecretStore`] trait
//! 注入（平台实现：DPAPI secure-store；测试/示例：内存实现）。

use std::collections::HashMap;

use ring::digest::{Context, SHA256};

use crate::encryption::{KeyPair, PUBLIC_KEY_LEN};

/// secure-store 中本端身份记录的键。
pub const IDENTITY_RECORD_KEY: &str = "nexus.identity.v1";
/// 对端身份表记录键前缀（后接 peer_id）。
pub const PEER_RECORD_PREFIX: &str = "nexus.peer.v1.";
/// PeerId 字节长度（static 公钥 SHA-256 的前 16 字节）。
pub const PEER_ID_BYTES: usize = 16;

/// 身份面的结构化错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// 持久化存储不可用（secure-store 失败）。
    StoreUnavailable,
    /// 对端身份与已学习身份不一致（TOFU 拒绝，`IDENTITY_CHANGED`）。
    PeerIdentityChanged,
}

impl core::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::StoreUnavailable => write!(f, "identity secure-store unavailable"),
            Self::PeerIdentityChanged => write!(f, "peer identity changed (TOFU mismatch)"),
        }
    }
}

impl std::error::Error for IdentityError {}

/// 加密持久化最小抽象（Deletion Test：平台 DPAPI secure-store 与内存测试替身
/// 是两个独立变化维度；本模块不依赖具体文件系统/平台 API）。
pub trait SecretStore {
    /// 读取一条加密记录；不存在返回 `None`。
    fn read_secret(&self, key: &str) -> Option<Vec<u8>>;
    /// 写入一条加密记录。
    fn write_secret(&mut self, key: &str, data: &[u8]) -> Result<(), IdentityError>;
}

/// 内存 SecretStore（测试 / 进程内 E4 驱动）。
#[derive(Default)]
pub struct InMemorySecretStore {
    records: HashMap<String, Vec<u8>>,
}

impl InMemorySecretStore {
    /// 空存储。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecretStore for InMemorySecretStore {
    fn read_secret(&self, key: &str) -> Option<Vec<u8>> {
        self.records.get(key).cloned()
    }

    fn write_secret(&mut self, key: &str, data: &[u8]) -> Result<(), IdentityError> {
        self.records.insert(key.to_string(), data.to_vec());
        Ok(())
    }
}

/// 身份管理器的单次操作结果（供事件流观测）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityAction {
    /// 本端无身份密钥，自动生成并持久化。
    KeyGenerated,
    /// 首次学习对端身份（TOFU 持久化）。
    PeerLearned,
    /// 对端身份与已学习记录一致（验证通过）。
    PeerVerified,
}

/// 节点身份管理器：本端长期身份 + 对端 TOFU 身份表。
///
/// 生命周期由调用方（隧道 / daemon）持有；`load_or_generate` 必须在首次握手前
/// 调用，保证本端身份可用。存储以 trait object 注入（平台 DPAPI / 内存）。
pub struct IdentityManager {
    store: Box<dyn SecretStore>,
    identity: Option<KeyPair>,
    peers: HashMap<String, [u8; PUBLIC_KEY_LEN]>,
}

impl IdentityManager {
    /// 以给定存储构造身份管理器（身份未加载）。
    #[must_use]
    pub fn new(store: Box<dyn SecretStore>) -> Self {
        Self {
            store,
            identity: None,
            peers: HashMap::new(),
        }
    }

    /// 加载或生成本端身份密钥并持久化。
    ///
    /// 返回 `true` 表示本次自动生成了新身份（事件：`IdentityKeyGenerated`）。
    pub fn load_or_generate(&mut self) -> Result<bool, IdentityError> {
        if self.identity.is_some() {
            return Ok(false);
        }
        let seed = self.store.read_secret(IDENTITY_RECORD_KEY);
        let generated =
            seed.is_none() || seed.as_deref().is_some_and(|b| b.len() != PUBLIC_KEY_LEN);
        let keypair = match seed {
            Some(bytes) if bytes.len() == PUBLIC_KEY_LEN => {
                let mut seed_arr = [0u8; PUBLIC_KEY_LEN];
                seed_arr.copy_from_slice(&bytes);
                KeyPair::from_seed(&seed_arr)
            }
            _ => {
                let kp = KeyPair::generate().map_err(|_| IdentityError::StoreUnavailable)?;
                self.store
                    .write_secret(IDENTITY_RECORD_KEY, &kp.to_seed())
                    .map_err(|_| IdentityError::StoreUnavailable)?;
                kp
            }
        };
        self.identity = Some(keypair);
        Ok(generated)
    }

    /// 本端长期身份密钥（加载后可用）。
    #[must_use]
    pub fn identity(&self) -> Option<&KeyPair> {
        self.identity.as_ref()
    }

    /// 由 static 公钥计算 PeerId（SHA-256 前 16 字节的 hex）。
    #[must_use]
    pub fn peer_id_of(static_public: &[u8; PUBLIC_KEY_LEN]) -> String {
        let mut ctx = Context::new(&SHA256);
        ctx.update(static_public);
        let digest = ctx.finish();
        let mut hex = String::with_capacity(2 * PEER_ID_BYTES);
        for b in &digest.as_ref()[..PEER_ID_BYTES] {
            use std::fmt::Write;
            let _ = write!(hex, "{b:02x}");
        }
        hex
    }

    /// 本端 PeerId。
    #[must_use]
    pub fn peer_id(&self) -> Option<String> {
        self.identity
            .as_ref()
            .map(|kp| Self::peer_id_of(kp.public_key_bytes()))
    }

    /// 对端 TOFU 校验（自动交换核心，P4.1 §12.39）：
    /// - 无记录 -> 学习并持久化，返回 [`IdentityAction::PeerLearned`]；
    /// - 记录一致 -> 返回 [`IdentityAction::PeerVerified`]；
    /// - 记录不一致 -> [`IdentityError::PeerIdentityChanged`]（拒绝握手）。
    ///
    /// `record_key` 由调用方决定身份粒度：隧道层传对端虚拟 IP（VIP），使同一
    /// VIP 更换 static 身份即触发 `PeerIdentityChanged`（防止节点顶替/中间人）。
    pub fn verify_peer(
        &mut self,
        record_key: &str,
        static_public: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<IdentityAction, IdentityError> {
        let record_key = format!("{PEER_RECORD_PREFIX}{record_key}");
        match self.store.read_secret(&record_key) {
            None => {
                self.store
                    .write_secret(&record_key, static_public)
                    .map_err(|_| IdentityError::StoreUnavailable)?;
                self.peers.insert(record_key, *static_public);
                Ok(IdentityAction::PeerLearned)
            }
            Some(bytes) if bytes.len() == PUBLIC_KEY_LEN && bytes == static_public => {
                self.peers.insert(record_key, *static_public);
                Ok(IdentityAction::PeerVerified)
            }
            _ => Err(IdentityError::PeerIdentityChanged),
        }
    }

    /// 已学习（或已验证）的对端身份公钥。
    #[must_use]
    pub fn known_peer(&self, record_key: &str) -> Option<&[u8; PUBLIC_KEY_LEN]> {
        self.peers.get(&format!("{PEER_RECORD_PREFIX}{record_key}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_persists_across_manager_reload() -> Result<(), IdentityError> {
        let mut m1 = IdentityManager::new(Box::new(InMemorySecretStore::new()));
        assert!(m1.load_or_generate()?); // 首次生成
        let peer_id_1 = m1.peer_id().unwrap();
        let pub_1 = *m1.identity().unwrap().public_key_bytes();

        // 同一存储重建 -> 恢复同一身份（PeerId 稳定）。
        let mut m2 = IdentityManager::new(m1.store);
        assert!(!m2.load_or_generate()?); // 已存在，不重新生成
        assert_eq!(m2.peer_id().unwrap(), peer_id_1);
        assert_eq!(m2.identity().unwrap().public_key_bytes(), &pub_1);
        Ok(())
    }

    #[test]
    fn tofu_learn_then_verify_then_reject() -> Result<(), IdentityError> {
        let mut m = IdentityManager::new(Box::new(InMemorySecretStore::new()));
        m.load_or_generate()?;

        let peer_kp = KeyPair::generate().map_err(|_| IdentityError::StoreUnavailable)?;
        let peer_id = IdentityManager::peer_id_of(peer_kp.public_key_bytes());
        // 隧道层语义：以对端 VIP 作为身份记录键（同一 VIP 更换身份即拒绝）。
        let record_key = "10.0.0.2";

        // 首次：学习。
        assert_eq!(
            m.verify_peer(record_key, peer_kp.public_key_bytes())?,
            IdentityAction::PeerLearned
        );
        assert_eq!(m.known_peer(record_key), Some(peer_kp.public_key_bytes()));
        // 再次：验证通过。
        assert_eq!(
            m.verify_peer(record_key, peer_kp.public_key_bytes())?,
            IdentityAction::PeerVerified
        );
        // 身份替换（同一 VIP 换了 static）：拒绝。
        let impostor = KeyPair::generate().map_err(|_| IdentityError::StoreUnavailable)?;
        assert_eq!(
            m.verify_peer(record_key, impostor.public_key_bytes()),
            Err(IdentityError::PeerIdentityChanged)
        );
        // peer_id 仍可按公钥计算（用于事件/显示）。
        assert_eq!(peer_id.len(), 2 * PEER_ID_BYTES);
        Ok(())
    }

    #[test]
    fn peer_id_is_stable_and_distinct() -> Result<(), IdentityError> {
        let kp1 = KeyPair::generate().map_err(|_| IdentityError::StoreUnavailable)?;
        let kp2 = KeyPair::generate().map_err(|_| IdentityError::StoreUnavailable)?;
        let id1 = IdentityManager::peer_id_of(kp1.public_key_bytes());
        let id2 = IdentityManager::peer_id_of(kp2.public_key_bytes());
        assert_eq!(id1.len(), 2 * PEER_ID_BYTES);
        assert_ne!(id1, id2);
        // 同一公钥 -> 同一 PeerId。
        assert_eq!(id1, IdentityManager::peer_id_of(kp1.public_key_bytes()));
        Ok(())
    }
}

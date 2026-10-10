//! 证书管理（加载骨架 + 过期检查 + 自签名识别 + 轮换，内存骨架，纯逻辑）。
//!
//! 本模块是 delivery 层共享底座的证书管理骨架：
//! - **配置**：`CertificateConfig { cert_path, key_path, ca_path }` 记录证书/私钥/
//!   信任锚的文件位置；骨架**不真实读 PEM**（真实解析需 x509 库，见文末 TODO），
//!   证书内容以 `CertificateInfo` 由调用方在内存中构造后注入；
//! - **证书信息**：`CertificateInfo { subject, serial, not_before_unix, not_after_unix,
//!   self_signed }`--自签名由 `self_signed` 标记区分（CA == 主体时即自签名）；
//! - **过期检查**：`CertificateManager::check_expiry(now_unix, warn_before_secs)`
//!   返回 `ExpiryStatus::Valid` / `ExpiringSoon { remaining_secs }` / `Expired`；
//!   也会拒绝 `now < not_before`（尚未生效，记为 `NotYetValid` 错误）；
//! - **轮换**：`CertificateManager::rotate(new_cert, now_unix)` 原子替换当前证书，
//!   新证书必须当前有效（未过期、已生效），返回被替换的旧证书便于审计。
//!
//! 边界（PRODUCT §12.35 冻结）：
//! - 纯内存、纯同步、纯逻辑骨架；时间由调用方以 `now_unix: i64` 显式注入，模块不读墙钟；
//! - 不做真实文件 I/O、不做链验证（CA 链构建留 TODO）；
//! - 路径仅做非空校验，不做存在性校验。
//!
//! TODO（真实证书集成，非本骨架范围）：
//! - 从 `cert_path`/`key_path`/`ca_path` 真实解析 PEM（x509-parser / rustls 加载）；
//! - CA 链构建与主机名 SAN 校验；
//! - 证书文件热轮换监听（watch fs）。
//!
//! 错误面独立：`CertificateError` 是本模块自有类型化 enum，不以 panic / 日志代替。

use std::fmt;

// ---------- 错误 ----------

/// 证书管理相关结构化错误（delivery 层自有错误面，类型化）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateError {
    /// 配置字段非法（路径为空）。
    InvalidConfig {
        /// 非法字段名（人可读）。
        field: String,
    },
    /// 证书尚未生效（now < not_before）。
    NotYetValid {
        /// 生效时间（unix 秒）。
        not_before_unix: i64,
        /// 当前时间（unix 秒）。
        now_unix: i64,
    },
    /// 证书已过期（now > not_after）。
    Expired {
        /// 过期时间（unix 秒）。
        not_after_unix: i64,
        /// 当前时间（unix 秒）。
        now_unix: i64,
    },
    /// 证书时间区间非法（not_before >= not_after）。
    InvalidValidity {
        /// 生效时间（unix 秒）。
        not_before_unix: i64,
        /// 过期时间（unix 秒）。
        not_after_unix: i64,
    },
}

impl fmt::Display for CertificateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig { field } => {
                write!(f, "CERT_INVALID_CONFIG: field {field:?} is empty")
            }
            Self::NotYetValid {
                not_before_unix,
                now_unix,
            } => {
                write!(
                    f,
                    "CERT_NOT_YET_VALID: not_before={not_before_unix} now={now_unix}"
                )
            }
            Self::Expired {
                not_after_unix,
                now_unix,
            } => {
                write!(f, "CERT_EXPIRED: not_after={not_after_unix} now={now_unix}")
            }
            Self::InvalidValidity {
                not_before_unix,
                not_after_unix,
            } => {
                write!(
                    f,
                    "CERT_INVALID_VALIDITY: not_before={not_before_unix} >= not_after={not_after_unix}"
                )
            }
        }
    }
}

impl std::error::Error for CertificateError {}

// ---------- 配置 ----------

/// 证书管理配置（文件位置骨架；真实读盘留 TODO）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateConfig {
    /// 证书文件路径（必须非空）。
    cert_path: String,
    /// 私钥文件路径（必须非空）。
    key_path: String,
    /// 信任锚（CA）路径；None 表示仅用系统默认/自签名。
    ca_path: Option<String>,
}

impl CertificateConfig {
    /// 构造配置并校验：`cert_path` / `key_path` 非空；`ca_path` 若给也非空串。
    pub fn new(
        cert_path: impl Into<String>,
        key_path: impl Into<String>,
        ca_path: Option<String>,
    ) -> Result<Self, CertificateError> {
        let cert_path = cert_path.into();
        let key_path = key_path.into();
        if cert_path.is_empty() {
            return Err(CertificateError::InvalidConfig {
                field: "cert_path".to_string(),
            });
        }
        if key_path.is_empty() {
            return Err(CertificateError::InvalidConfig {
                field: "key_path".to_string(),
            });
        }
        if let Some(ca) = &ca_path {
            if ca.is_empty() {
                return Err(CertificateError::InvalidConfig {
                    field: "ca_path".to_string(),
                });
            }
        }
        Ok(Self {
            cert_path,
            key_path,
            ca_path,
        })
    }

    /// 证书文件路径。
    #[must_use]
    pub fn cert_path(&self) -> &str {
        &self.cert_path
    }

    /// 私钥文件路径。
    #[must_use]
    pub fn key_path(&self) -> &str {
        &self.key_path
    }

    /// 信任锚路径（可能为 None）。
    #[must_use]
    pub fn ca_path(&self) -> Option<&str> {
        self.ca_path.as_deref()
    }
}

// ---------- 证书信息 ----------

/// 一张证书的关键字段（骨架内由调用方在内存中构造，不做 PEM 解析）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateInfo {
    /// 证书主体 DN（人可读）。
    subject: String,
    /// 序列号（人可读十六进制串）。
    serial: String,
    /// 生效时间（unix 秒，UTC）。
    not_before_unix: i64,
    /// 过期时间（unix 秒，UTC）。
    not_after_unix: i64,
    /// 是否自签名（CA 与主体相同）。
    self_signed: bool,
}

impl CertificateInfo {
    /// 构造并校验时间区间：`not_before < not_after`。
    pub fn new(
        subject: impl Into<String>,
        serial: impl Into<String>,
        not_before_unix: i64,
        not_after_unix: i64,
        self_signed: bool,
    ) -> Result<Self, CertificateError> {
        if not_before_unix >= not_after_unix {
            return Err(CertificateError::InvalidValidity {
                not_before_unix,
                not_after_unix,
            });
        }
        Ok(Self {
            subject: subject.into(),
            serial: serial.into(),
            not_before_unix,
            not_after_unix,
            self_signed,
        })
    }

    /// 证书主体。
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// 序列号。
    #[must_use]
    pub fn serial(&self) -> &str {
        &self.serial
    }

    /// 生效时间。
    #[must_use]
    pub fn not_before_unix(&self) -> i64 {
        self.not_before_unix
    }

    /// 过期时间。
    #[must_use]
    pub fn not_after_unix(&self) -> i64 {
        self.not_after_unix
    }

    /// 是否自签名。
    #[must_use]
    pub fn is_self_signed(&self) -> bool {
        self.self_signed
    }
}

// ---------- 过期状态 ----------

/// 证书过期检查结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiryStatus {
    /// 在有效期内且距离过期超过 `warn_before_secs`。
    Valid,
    /// 在有效期内但距过期不足 `warn_before_secs`。
    ExpiringSoon {
        /// 距过期剩余秒数（>= 0）。
        remaining_secs: i64,
    },
    /// 已过期。
    Expired,
}

impl ExpiryStatus {
    /// 返回稳定字符串标签（"valid"/"expiring-soon"/"expired"）。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::ExpiringSoon { .. } => "expiring-soon",
            Self::Expired => "expired",
        }
    }
}

impl fmt::Display for ExpiryStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------- 管理器 ----------

/// 证书管理器：持有配置与当前证书，纯内存纯逻辑。
///
/// 时钟为 unix 秒（`now_unix`），由调用方显式注入；不读墙钟、不读文件。
pub struct CertificateManager {
    /// 配置（文件位置骨架）。
    config: CertificateConfig,
    /// 当前生效证书。
    current: CertificateInfo,
    /// 已轮换次数（每次 rotate 自增）。
    rotations: u64,
}

impl CertificateManager {
    /// 用配置 + 当前证书构造管理器；构造时校验当前证书在 `now_unix` 有效。
    pub fn new(
        config: CertificateConfig,
        current: CertificateInfo,
        now_unix: i64,
    ) -> Result<Self, CertificateError> {
        Self::assert_effective(&current, now_unix)?;
        Ok(Self {
            config,
            current,
            rotations: 0,
        })
    }

    /// 校验证书在 `now_unix` 已生效且未过期。
    fn assert_effective(cert: &CertificateInfo, now_unix: i64) -> Result<(), CertificateError> {
        if now_unix < cert.not_before_unix {
            return Err(CertificateError::NotYetValid {
                not_before_unix: cert.not_before_unix,
                now_unix,
            });
        }
        if now_unix > cert.not_after_unix {
            return Err(CertificateError::Expired {
                not_after_unix: cert.not_after_unix,
                now_unix,
            });
        }
        Ok(())
    }

    /// 配置引用。
    #[must_use]
    pub fn config(&self) -> &CertificateConfig {
        &self.config
    }

    /// 当前证书引用。
    #[must_use]
    pub fn current(&self) -> &CertificateInfo {
        &self.current
    }

    /// 已轮换次数。
    #[must_use]
    pub fn rotations(&self) -> u64 {
        self.rotations
    }

    /// 当前证书是否自签名。
    #[must_use]
    pub fn is_self_signed(&self) -> bool {
        self.current.self_signed
    }

    /// 过期检查：`now_unix` 为当前时间，`warn_before_secs` 为"即将过期"预警阈值。
    ///
    /// - `now < not_before` -> `NotYetValid` 错误；
    /// - `now > not_after` -> `Expired`；
    /// - `not_after - now <= warn_before_secs` -> `ExpiringSoon { remaining_secs }`；
    /// - 否则 `Valid`。
    pub fn check_expiry(
        &self,
        now_unix: i64,
        warn_before_secs: i64,
    ) -> Result<ExpiryStatus, CertificateError> {
        if now_unix < self.current.not_before_unix {
            return Err(CertificateError::NotYetValid {
                not_before_unix: self.current.not_before_unix,
                now_unix,
            });
        }
        let remaining = self.current.not_after_unix - now_unix;
        if remaining < 0 {
            return Err(CertificateError::Expired {
                not_after_unix: self.current.not_after_unix,
                now_unix,
            });
        }
        if remaining <= warn_before_secs {
            return Ok(ExpiryStatus::ExpiringSoon {
                remaining_secs: remaining,
            });
        }
        Ok(ExpiryStatus::Valid)
    }

    /// 原子轮换到新证书；新证书必须在 `now_unix` 已生效且未过期。
    ///
    /// 成功后返回被替换的旧证书，`rotations` +1。
    pub fn rotate(
        &mut self,
        new_cert: CertificateInfo,
        now_unix: i64,
    ) -> Result<CertificateInfo, CertificateError> {
        Self::assert_effective(&new_cert, now_unix)?;
        let old = std::mem::replace(&mut self.current, new_cert);
        self.rotations = self.rotations.saturating_add(1);
        Ok(old)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert(not_before: i64, not_after: i64, self_signed: bool) -> CertificateInfo {
        CertificateInfo::new("CN=nexus", "AA:BB:CC", not_before, not_after, self_signed)
            .expect("valid cert")
    }

    fn cfg() -> CertificateConfig {
        CertificateConfig::new("/etc/nexus/cert.pem", "/etc/nexus/key.pem", None)
            .expect("valid config")
    }

    #[test]
    fn new_rejects_not_yet_valid_and_expired() {
        // now=100，证书 200..1000 -> NotYetValid。
        let early = cert(200, 1000, true);
        assert!(matches!(
            CertificateManager::new(cfg(), early, 100),
            Err(CertificateError::NotYetValid { .. })
        ));
        // now=2000，证书 200..1000 -> Expired。
        let expired = cert(200, 1000, true);
        assert!(matches!(
            CertificateManager::new(cfg(), expired, 2000),
            Err(CertificateError::Expired { .. })
        ));
    }

    #[test]
    fn check_expiry_classifies_states() {
        let mgr = CertificateManager::new(cfg(), cert(0, 1000, true), 100).expect("ok");
        // now=100，剩余 900 > 300 预警 -> Valid。
        assert_eq!(mgr.check_expiry(100, 300).expect("ok").as_str(), "valid");
        // now=800，剩余 200 <= 300 -> ExpiringSoon。
        match mgr.check_expiry(800, 300).expect("ok") {
            ExpiryStatus::ExpiringSoon { remaining_secs } => assert_eq!(remaining_secs, 200),
            other => panic!("expected expiring-soon, got {other:?}"),
        }
        // now=1001 -> Expired 错误。
        assert!(matches!(
            mgr.check_expiry(1001, 300),
            Err(CertificateError::Expired { .. })
        ));
    }

    #[test]
    fn rotate_swaps_and_rejects_bad_new_cert() {
        let mut mgr = CertificateManager::new(cfg(), cert(0, 1000, true), 100).expect("mgr");
        assert_eq!(mgr.rotations(), 0);
        assert!(mgr.is_self_signed());

        let new_cert = cert(500, 5000, false);
        let old = mgr.rotate(new_cert.clone(), 600).expect("rotate ok");
        assert_eq!(old.not_after_unix(), 1000);
        assert_eq!(mgr.rotations(), 1);
        assert_eq!(mgr.current().serial(), "AA:BB:CC");
        assert!(!mgr.is_self_signed());

        // 新证书已过期 -> 拒绝轮换，当前不变。
        let bad = cert(0, 900, true);
        assert!(matches!(
            mgr.rotate(bad, 1001),
            Err(CertificateError::Expired { .. })
        ));
        assert_eq!(mgr.rotations(), 1);
    }

    #[test]
    fn invalid_config_rejected() {
        assert!(CertificateConfig::new("", "k", None).is_err());
        assert!(CertificateConfig::new("c", "", None).is_err());
        assert!(CertificateConfig::new("c", "k", Some(String::new())).is_err());
        // 时间区间非法。
        assert!(CertificateInfo::new("s", "x", 1000, 1000, true).is_err());
        assert!(CertificateInfo::new("s", "x", 1001, 1000, true).is_err());
    }

    #[test]
    fn check_expiry_rejects_not_yet_valid() {
        // 证书 100..1000，now=50 -> NotYetValid。
        let mgr = CertificateManager::new(cfg(), cert(100, 1000, true), 100).expect("mgr");
        match mgr.check_expiry(50, 300) {
            Err(CertificateError::NotYetValid {
                not_before_unix,
                now_unix,
            }) => {
                assert_eq!(not_before_unix, 100);
                assert_eq!(now_unix, 50);
            }
            other => panic!("expected NotYetValid, got {other:?}"),
        }
    }

    #[test]
    fn rotate_rejects_not_yet_valid_new_cert() {
        let mut mgr = CertificateManager::new(cfg(), cert(0, 1000, true), 100).expect("mgr");
        // 新证书尚未生效（not_before=500 > now=400）-> 拒绝。
        let future = cert(500, 5000, false);
        assert!(matches!(
            mgr.rotate(future, 400),
            Err(CertificateError::NotYetValid { .. })
        ));
        assert_eq!(mgr.rotations(), 0);
    }

    #[test]
    fn expiry_status_as_str() {
        assert_eq!(ExpiryStatus::Valid.as_str(), "valid");
        assert_eq!(
            ExpiryStatus::ExpiringSoon { remaining_secs: 5 }.as_str(),
            "expiring-soon"
        );
        assert_eq!(ExpiryStatus::Expired.as_str(), "expired");
    }
}

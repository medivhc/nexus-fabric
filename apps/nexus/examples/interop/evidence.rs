//! CellEvidence / 事件日志 / evidence_id / artifact（D2.3 / D3.1 / AC-18）。

use serde::Serialize;
use std::path::{Path, PathBuf};

use crate::config::InteropProbeConfig;
use crate::util;

/// 载波。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Carrier {
    CrateDirect,
    ProductSocks5,
}

impl Carrier {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::CrateDirect => "CrateDirect",
            Self::ProductSocks5 => "ProductSocks5",
        }
    }
}

/// 作用域。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Scope {
    ProtocolWire,
    ProductPath,
}

impl Scope {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::ProtocolWire => "ProtocolWire",
            Self::ProductPath => "ProductPath",
        }
    }
}

/// 格状态（五值）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Verdict {
    Pass,
    Fail,
    Blocked,
    NotApplicable,
    NotImplemented,
}

impl Verdict {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Blocked => "BLOCKED",
            Self::NotApplicable => "NOT_APPLICABLE",
            Self::NotImplemented => "NOT_IMPLEMENTED",
        }
    }
}

/// D1 错误分类（17 个，序列化 `E_*`；不得新增）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[allow(clippy::enum_variant_names)]
pub enum ErrorClass {
    ENexusHandshakeWire,
    ENexusAuthEncoding,
    ENexusFraming,
    ENexusTransport,
    ENexusUdp,
    ENexusCodec,
    ENexusNotImplemented,
    ERefConfig,
    ERefUnsupported,
    ERefBehavior,
    EExpectedAuthReject,
    EExpectedConfigReject,
    ENetworkEnv,
    ETimeoutHang,
    EToolBug,
    EEvidenceGap,
    ERefLimitation,
}

/// artifact 种类（D2.3；`SelfCheck` 为 B-8 默认解法里 probe 自产的回环自检产物）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ArtifactKind {
    ProbeJson,
    RefLog,
    ClientLog,
    Pcap,
    Config,
    Manifest,
    SelfCheck,
}

/// 单个 artifact。
#[derive(Debug, Clone, Serialize)]
pub struct Artifact {
    pub kind: ArtifactKind,
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

/// 被测侧元信息（取自环境变量，B-4）。
#[derive(Debug, Clone, Serialize)]
pub struct NexusInfo {
    pub commit: String,
    pub binary_sha256: String,
    pub cargo_target_dir: String,
}

/// 参照侧元信息。
#[derive(Debug, Clone, Serialize)]
pub struct ReferenceInfo {
    pub implementation: String,
    pub version: String,
    pub binary_sha256: String,
    pub config_sha256: String,
}

/// 量化指标。
#[derive(Debug, Clone, Default, Serialize)]
pub struct Metrics {
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub sha256_up: String,
    pub sha256_down: String,
    pub throughput_samples_bps: Vec<u64>,
    pub throughput_median_bps: u64,
    pub heartbeats_ok: u32,
    pub reconnects_ok: u32,
    pub udp_sent: u32,
    pub udp_received: u32,
    pub udp_corrupt: u32,
}

/// 结构化错误。
#[derive(Debug, Clone, Serialize)]
pub struct ErrorInfo {
    pub class: ErrorClass,
    pub message: String,
    pub first_failure_artifact: Option<String>,
}

/// 证据正本。
#[derive(Debug, Clone, Serialize)]
pub struct CellEvidence {
    pub schema_version: u32,
    pub evidence_id: String,
    pub run_id: String,
    pub protocol: crate::config::Protocol,
    pub variant: crate::config::Variant,
    pub cell: crate::config::Cell,
    pub carrier: Carrier,
    pub scope: Scope,
    pub verdict: Verdict,
    pub started_at_utc: String,
    pub duration_ms: u64,
    pub nexus: NexusInfo,
    pub reference: ReferenceInfo,
    pub effective_config_sha256: String,
    pub metrics: Metrics,
    pub error: Option<ErrorInfo>,
    pub notes: Vec<String>,
    pub artifacts: Vec<Artifact>,
}

impl CellEvidence {
    /// verdict/error 互斥规则（D2.3）。
    pub fn check_consistency(&self) -> Result<(), String> {
        match (self.verdict, self.error.as_ref()) {
            (Verdict::Pass | Verdict::NotApplicable, None) => Ok(()),
            (Verdict::Fail | Verdict::Blocked | Verdict::NotImplemented, Some(e)) => {
                if self.verdict == Verdict::NotImplemented
                    && e.class != ErrorClass::ENexusNotImplemented
                {
                    return Err("NotImplemented must use E_NEXUS_NOT_IMPLEMENTED".into());
                }
                Ok(())
            }
            (Verdict::Pass | Verdict::NotApplicable, Some(_)) => {
                Err("Pass/NotApplicable must not carry error".into())
            }
            (Verdict::Fail | Verdict::Blocked | Verdict::NotImplemented, None) => {
                Err("Fail/Blocked/NotImplemented must carry error".into())
            }
        }
    }
}

/// 事件日志（stdout JSONL，D3.1 固定字段）。
pub struct Events {
    pub cell: &'static str,
    pub evidence_id: String,
    pub carrier: &'static str,
    pub scope: &'static str,
}

impl Events {
    pub fn emit(&self, level: &str, event: &str, reason: &str, detail: &str) {
        let line = serde_json::json!({
            "ts": util::utc_now_rfc3339(),
            "component": "nexus-interop-probe",
            "level": level,
            "event": event,
            "cell": self.cell,
            "evidence_id": self.evidence_id,
            "carrier": self.carrier,
            "scope": self.scope,
            "reason": reason,
            "detail": detail,
        });
        println!("{line}");
    }
}

/// 生成 evidence_id 并创建 cell 目录（seq 扫描同前缀既有目录）。
pub fn prepare_cell_dir(
    evidence_root: &Path,
    cfg: &InteropProbeConfig,
) -> Result<(String, PathBuf), String> {
    let protocol = cfg.protocol.label();
    let variant = cfg.variant.label();
    let cell = cfg.cell.label();
    let parent = evidence_root.join(protocol).join(variant).join(cell);
    std::fs::create_dir_all(&parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    let prefix = format!(
        "PIV-{protocol}-{variant}-{cell}-{}-",
        util::utc_now_compact()
    );
    let mut max_seq = 0u32;
    if let Ok(entries) = std::fs::read_dir(&parent) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(rest) = name.strip_prefix(&prefix) {
                if let Ok(seq) = rest.parse::<u32>() {
                    max_seq = max_seq.max(seq);
                }
            }
        }
    }
    let evidence_id = format!("{prefix}{:03}", max_seq + 1);
    let dir = parent.join(&evidence_id);
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    Ok((evidence_id, dir))
}

/// 计算 artifact（路径相对 `base` 时原样保存相对路径；否则绝对路径）。
pub fn artifact(kind: ArtifactKind, base: &Path, path: &Path) -> Result<Artifact, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let rel = path
        .strip_prefix(base)
        .map_or_else(|_| path.display().to_string(), |p| p.display().to_string());
    Ok(Artifact {
        kind,
        path: rel,
        sha256: util::sha256_hex(&bytes),
        bytes: u64::try_from(bytes.len()).unwrap_or(0),
    })
}

/// 从环境变量读取 B-4 元信息；缺任一 → 错误（不猜、不默认空串）。
pub fn nexus_info_from_env() -> Result<NexusInfo, String> {
    let commit =
        std::env::var("PIV_NEXUS_COMMIT").map_err(|_| "missing PIV_NEXUS_COMMIT".to_string())?;
    let target_dir = std::env::var("PIV_NEXUS_TARGET_DIR")
        .or_else(|_| std::env::var("CARGO_TARGET_DIR"))
        .unwrap_or_default();
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let bytes = std::fs::read(&exe).map_err(|e| format!("read probe binary: {e}"))?;
    Ok(NexusInfo {
        commit,
        binary_sha256: util::sha256_hex(&bytes),
        cargo_target_dir: target_dir,
    })
}

/// 从环境变量读取参照元信息（B-4）。
pub fn reference_info_from_env() -> Result<ReferenceInfo, String> {
    let get = |key: &str| std::env::var(key).map_err(|_| format!("missing {key}"));
    Ok(ReferenceInfo {
        implementation: get("PIV_REF_IMPLEMENTATION")?,
        version: get("PIV_REF_VERSION")?,
        binary_sha256: get("PIV_REF_BIN_SHA256")?,
        config_sha256: get("PIV_REF_CONFIG_SHA256")?,
    })
}

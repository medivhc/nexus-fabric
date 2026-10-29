//! 出站协议互操作 probe（D2.4 CLI / D2.3 证据 / D3.1 事件）。
//!
//! ```text
//! protocol_interop_probe --config <json> --out <json> --evidence-root <dir>
//! ```
//!
//! 退出码：0 PASS；1 FAIL；2 BLOCKED/配置非法/合成格；3 工具错误。

#![forbid(unsafe_code)]

#[path = "interop/config.rs"]
mod config;
#[path = "interop/crate_direct.rs"]
mod crate_direct;
#[path = "interop/evidence.rs"]
mod evidence;
#[path = "interop/product.rs"]
mod product;
#[path = "interop/selfcheck.rs"]
mod selfcheck;
#[path = "interop/targets.rs"]
mod targets;
#[path = "interop/tls.rs"]
mod tls;
#[path = "interop/util.rs"]
mod util;
#[path = "interop/vision.rs"]
mod vision;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use config::{Cell, InteropProbeConfig, Protocol, Variant};
use evidence::{Carrier, CellEvidence, ErrorClass, ErrorInfo, Events, Metrics, Scope, Verdict};

/// probe 错误（D2.4）。
#[derive(Debug)]
pub enum ProbeError {
    ConfigInvalid { field: String, detail: String },
    SelfCheckFailed { detail: String },
    EvidenceWrite { path: String, detail: String },
    CellPanic { detail: String },
}

impl core::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ConfigInvalid { field, detail } => {
                write!(f, "config_invalid field={field} detail={detail}")
            }
            Self::SelfCheckFailed { detail } => write!(f, "selfcheck_failed detail={detail}"),
            Self::EvidenceWrite { path, detail } => {
                write!(f, "evidence_write path={path} detail={detail}")
            }
            Self::CellPanic { detail } => write!(f, "cell_panic detail={detail}"),
        }
    }
}

/// 解析后的 CLI。
#[derive(Debug, Clone)]
pub struct ProbeCli {
    pub config_path: PathBuf,
    pub out_path: PathBuf,
    pub evidence_root: PathBuf,
}

/// 解析 CLI（缺参 → ConfigInvalid，退出码 2）。
pub fn parse_args(args: &[String]) -> Result<ProbeCli, ProbeError> {
    let mut config_path = None;
    let mut out_path = None;
    let mut evidence_root = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let slot = match arg.as_str() {
            "--config" => &mut config_path,
            "--out" => &mut out_path,
            "--evidence-root" => &mut evidence_root,
            other => {
                return Err(ProbeError::ConfigInvalid {
                    field: "args".into(),
                    detail: format!("unknown argument {other}"),
                });
            }
        };
        let value = iter.next().ok_or_else(|| ProbeError::ConfigInvalid {
            field: "args".into(),
            detail: format!("{arg} requires a value"),
        })?;
        *slot = Some(PathBuf::from(value));
    }
    let missing = |name: &str| ProbeError::ConfigInvalid {
        field: "args".into(),
        detail: format!("missing {name}"),
    };
    Ok(ProbeCli {
        config_path: config_path.ok_or_else(|| missing("--config"))?,
        out_path: out_path.ok_or_else(|| missing("--out"))?,
        evidence_root: evidence_root.ok_or_else(|| missing("--evidence-root"))?,
    })
}

/// 一次 cell 运行结果（模块间通用）。
pub struct Outcome {
    pub verdict: Verdict,
    pub error: Option<ErrorInfo>,
    pub metrics: Metrics,
    pub notes: Vec<String>,
    pub proxy_json: Option<serde_json::Value>,
}

impl Outcome {
    #[must_use]
    pub fn pass(metrics: Metrics, notes: Vec<String>) -> Self {
        Self {
            verdict: Verdict::Pass,
            error: None,
            metrics,
            notes,
            proxy_json: None,
        }
    }

    #[must_use]
    pub fn fail(class: ErrorClass, message: String, metrics: Metrics) -> Self {
        Self {
            verdict: Verdict::Fail,
            error: Some(ErrorInfo {
                class,
                message,
                first_failure_artifact: Some("pcap.pcap".into()),
            }),
            metrics,
            notes: Vec::new(),
            proxy_json: None,
        }
    }

    #[must_use]
    pub fn blocked(class: ErrorClass, message: String) -> Self {
        Self {
            verdict: Verdict::Blocked,
            error: Some(ErrorInfo {
                class,
                message,
                first_failure_artifact: Some("probe.stdout.jsonl".into()),
            }),
            metrics: Metrics::default(),
            notes: Vec::new(),
            proxy_json: None,
        }
    }

    #[must_use]
    pub fn not_applicable(reason: &str) -> Self {
        Self {
            verdict: Verdict::NotApplicable,
            error: None,
            metrics: Metrics::default(),
            notes: vec![reason.to_string()],
            proxy_json: None,
        }
    }

    #[must_use]
    pub fn not_implemented(reason: &str) -> Self {
        Self {
            verdict: Verdict::NotImplemented,
            error: Some(ErrorInfo {
                class: ErrorClass::ENexusNotImplemented,
                message: reason.to_string(),
                first_failure_artifact: Some("code-refs.json".into()),
            }),
            metrics: Metrics::default(),
            notes: vec![reason.to_string()],
            proxy_json: None,
        }
    }
}

/// 合成格（不发连接，D-10；Q10：只对 crate 级 diag / 不可表达负向格生效）。
#[must_use]
pub fn is_synthetic(cfg: &InteropProbeConfig) -> bool {
    matches!(
        (cfg.protocol, cfg.cell),
        (Protocol::Trojan | Protocol::Shadowsocks, Cell::UdpEchoCrate)
            | (Protocol::Trojan, Cell::BadConfig)
    )
}

/// 载波/作用域派生（§6.3 唯一映射：配置面不含 carrier 字段）。
///
/// Q10（spec §9.1/§9.2）：
/// - `UdpEcho` → `ProductSocks5`/`ProductPath`（required，产品入口 + 出站全链路）；
/// - `UdpEchoCrate` → `CrateDirect`/`ProtocolWire`（diag，保留 crate 级证据）；
/// - QPACK 诊断格与 VLESS Vision 格仍为 crate 直调。
#[must_use]
pub fn carrier_for(cfg: &InteropProbeConfig) -> (Carrier, Scope) {
    if cfg.cell == Cell::UdpEchoCrate
        || cfg.cell == Cell::QpackDiag
        || cfg.variant == Variant::VlessVision
    {
        (Carrier::CrateDirect, Scope::ProtocolWire)
    } else {
        (Carrier::ProductSocks5, Scope::ProductPath)
    }
}

/// 回环自检（不经协议/参照端）。
pub fn run_loopback_selfcheck(
    cfg: &InteropProbeConfig,
) -> Result<selfcheck::SelfCheckReport, ProbeError> {
    selfcheck::run(cfg).map_err(|detail| ProbeError::SelfCheckFailed { detail })
}

/// 执行一个 cell 并产出证据。
pub fn run_cell(cfg: &InteropProbeConfig, cli: &ProbeCli) -> Result<CellEvidence, ProbeError> {
    let (carrier, scope) = carrier_for(cfg);
    let started_at = util::utc_now_rfc3339();
    let started = std::time::Instant::now();
    let (evidence_id, dir) =
        evidence::prepare_cell_dir(&cli.evidence_root, cfg).map_err(|detail| {
            ProbeError::EvidenceWrite {
                path: cli.evidence_root.display().to_string(),
                detail,
            }
        })?;
    let events = Events {
        cell: cfg.cell.label(),
        evidence_id: evidence_id.clone(),
        carrier: carrier.label(),
        scope: scope.label(),
    };

    let mut artifacts = Vec::new();
    let mut notes = Vec::new();
    let mut extras: Vec<(evidence::ArtifactKind, PathBuf)> = Vec::new();
    extras.push((evidence::ArtifactKind::Config, cli.config_path.clone()));

    let synthetic = is_synthetic(cfg);
    let target_set = if synthetic {
        None
    } else {
        targets::TargetSet::assert_ports(cfg.target.kind, cfg.target.port).map_err(|detail| {
            ProbeError::ConfigInvalid {
                field: "target.port".into(),
                detail,
            }
        })?;
        Some(targets::TargetSet::start(cfg).map_err(|detail| ProbeError::CellPanic { detail })?)
    };
    let report = if synthetic {
        selfcheck::skipped(cfg.target.kind, "synthetic cell: no target connection")
    } else {
        events.emit(
            "INFO",
            "selfcheck_start",
            "NONE",
            "loopback target selfcheck",
        );
        let report = run_loopback_selfcheck(cfg)?;
        if !report.ok {
            events.emit(
                "ERROR",
                "tool_error",
                "E_TOOL_BUG",
                "loopback selfcheck failed",
            );
            return Err(ProbeError::SelfCheckFailed {
                detail: serde_json::to_string(&report).unwrap_or_default(),
            });
        }
        report
    };
    let selfcheck_path = dir.join("selfcheck.json");
    let selfcheck_bytes =
        serde_json::to_vec_pretty(&report).map_err(|e| ProbeError::EvidenceWrite {
            path: selfcheck_path.display().to_string(),
            detail: e.to_string(),
        })?;
    util::atomic_write(&selfcheck_path, &selfcheck_bytes).map_err(|e| {
        ProbeError::EvidenceWrite {
            path: selfcheck_path.display().to_string(),
            detail: e.to_string(),
        }
    })?;
    extras.push((evidence::ArtifactKind::SelfCheck, selfcheck_path));
    if !synthetic {
        events.emit("INFO", "selfcheck_ok", "NONE", "target reachable");
    }

    // 目标端计数基线：回环自检本身会给 UdpEcho 目标发 1 包，产品格断言必须看增量。
    let target_udp_baseline = target_set.as_ref().map_or(0, |set| {
        set.stats.to_json()["udp_datagrams"].as_u64().unwrap_or(0)
    });

    events.emit("INFO", "cell_start", "NONE", "cell execution started");
    let mut outcome = if synthetic {
        match crate_direct::run_cell(cfg, &dir) {
            Ok(outcome) => outcome,
            Err(detail) => return Err(ProbeError::CellPanic { detail }),
        }
    } else {
        let target_set = target_set
            .as_ref()
            .expect("target set for non-synthetic cell");
        if target_set.handles_len() == 0 {
            return Err(ProbeError::CellPanic {
                detail: "no target servers started".into(),
            });
        }
        if cfg.variant == Variant::VlessVision {
            vision::run_cell(cfg).map_err(|detail| ProbeError::CellPanic { detail })?
        } else {
            match carrier {
                Carrier::ProductSocks5 => product::run_cell(cfg, &dir)
                    .map_err(|detail| ProbeError::CellPanic { detail })?,
                Carrier::CrateDirect => crate_direct::run_cell(cfg, &dir)
                    .map_err(|detail| ProbeError::CellPanic { detail })?,
            }
        }
    };
    // spec §9.1 第 7 步 / §9.3-6：UdpEcho 的 PASS 必须伴随目标端真实收包；
    // 未实现协议的 fail-closed 格必须目标端零收包（无直连、无伪造回包）。
    if cfg.cell == Cell::UdpEcho
        && let Some(target_set) = target_set.as_ref()
    {
        let total = target_set.stats.to_json()["udp_datagrams"]
            .as_u64()
            .unwrap_or(0);
        let delta = total.saturating_sub(target_udp_baseline);
        outcome.notes.push(format!(
            "target_udp_baseline={target_udp_baseline} target_udp_delta={delta}"
        ));
        let downgrade = match outcome.verdict {
            Verdict::Pass => delta == 0,
            Verdict::NotImplemented => delta != 0,
            _ => false,
        };
        if downgrade {
            outcome.notes.push(format!(
                "target_stats_assertion_failed udp_datagrams_delta={delta} verdict={}",
                outcome.verdict.label()
            ));
            outcome.verdict = Verdict::Fail;
            outcome.error = Some(ErrorInfo {
                class: ErrorClass::ENexusUdp,
                message: format!(
                    "target datagram delta {delta} contradicts the product udp verdict"
                ),
                first_failure_artifact: Some("target.json".into()),
            });
        }
    }
    notes.extend(outcome.notes.iter().cloned());
    if let Some(target_set) = target_set.as_ref() {
        let target_path = dir.join("target.json");
        let target_bytes = serde_json::to_vec_pretty(&target_set.stats.to_json()).map_err(|e| {
            ProbeError::EvidenceWrite {
                path: target_path.display().to_string(),
                detail: e.to_string(),
            }
        })?;
        util::atomic_write(&target_path, &target_bytes).map_err(|e| ProbeError::EvidenceWrite {
            path: target_path.display().to_string(),
            detail: e.to_string(),
        })?;
        notes.push(format!("target_stats={}", target_set.stats.to_json()));
    }

    if let Some(json) = &outcome.proxy_json {
        let path = dir.join("proxy.json");
        let bytes = serde_json::to_vec_pretty(json).map_err(|e| ProbeError::EvidenceWrite {
            path: path.display().to_string(),
            detail: e.to_string(),
        })?;
        util::atomic_write(&path, &bytes).map_err(|e| ProbeError::EvidenceWrite {
            path: path.display().to_string(),
            detail: e.to_string(),
        })?;
        extras.push((evidence::ArtifactKind::ClientLog, path));
    }
    let manifest = dir.join("code-refs.json");
    if manifest.exists() {
        extras.push((evidence::ArtifactKind::Manifest, manifest));
    }

    let nexus = evidence::nexus_info_from_env().map_err(|detail| ProbeError::EvidenceWrite {
        path: "--env".into(),
        detail,
    })?;
    let reference =
        evidence::reference_info_from_env().map_err(|detail| ProbeError::EvidenceWrite {
            path: "--env".into(),
            detail,
        })?;
    let config_bytes = std::fs::read(&cli.config_path).map_err(|e| ProbeError::EvidenceWrite {
        path: cli.config_path.display().to_string(),
        detail: e.to_string(),
    })?;
    for (kind, path) in extras {
        open_artifact(kind, &cli.evidence_root, &path, &mut artifacts, &mut notes);
    }

    let evidence = CellEvidence {
        schema_version: 1,
        evidence_id: evidence_id.clone(),
        run_id: cfg.run_id.clone(),
        protocol: cfg.protocol,
        variant: cfg.variant,
        cell: cfg.cell,
        carrier,
        scope,
        verdict: outcome.verdict,
        started_at_utc: started_at,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        nexus,
        reference,
        effective_config_sha256: util::sha256_hex(&config_bytes),
        metrics: outcome.metrics.clone(),
        error: outcome.error.clone(),
        notes,
        artifacts,
    };
    evidence
        .check_consistency()
        .map_err(|detail| ProbeError::CellPanic { detail })?;
    write_evidence(&evidence, &cli.out_path)?;
    let level = match evidence.verdict {
        Verdict::Pass => "INFO",
        Verdict::Fail => "ERROR",
        _ => "WARN",
    };
    let event = match evidence.verdict {
        Verdict::Pass => "cell_pass",
        Verdict::Fail => "cell_fail",
        Verdict::Blocked => "cell_blocked",
        Verdict::NotApplicable | Verdict::NotImplemented => "cell_blocked",
    };
    events.emit(
        level,
        event,
        evidence
            .error
            .as_ref()
            .map_or("NONE", |e| error_label(e.class)),
        &format!("verdict={}", evidence.verdict.label()),
    );
    events.emit(
        "INFO",
        "evidence_write",
        "NONE",
        &cli.out_path.display().to_string(),
    );
    Ok(evidence)
}

fn open_artifact(
    kind: evidence::ArtifactKind,
    base: &Path,
    path: &Path,
    artifacts: &mut Vec<evidence::Artifact>,
    notes: &mut Vec<String>,
) {
    match evidence::artifact(kind, base, path) {
        Ok(artifact) => artifacts.push(artifact),
        Err(err) => notes.push(format!("artifact_error={err}")),
    }
}

fn error_label(class: ErrorClass) -> &'static str {
    match class {
        ErrorClass::ENexusHandshakeWire => "E_NEXUS_HANDSHAKE_WIRE",
        ErrorClass::ENexusAuthEncoding => "E_NEXUS_AUTH_ENCODING",
        ErrorClass::ENexusFraming => "E_NEXUS_FRAMING",
        ErrorClass::ENexusTransport => "E_NEXUS_TRANSPORT",
        ErrorClass::ENexusUdp => "E_NEXUS_UDP",
        ErrorClass::ENexusCodec => "E_NEXUS_CODEC",
        ErrorClass::ENexusNotImplemented => "E_NEXUS_NOT_IMPLEMENTED",
        ErrorClass::ERefConfig => "E_REF_CONFIG",
        ErrorClass::ERefUnsupported => "E_REF_UNSUPPORTED",
        ErrorClass::ERefBehavior => "E_REF_BEHAVIOR",
        ErrorClass::EExpectedAuthReject => "E_EXPECTED_AUTH_REJECT",
        ErrorClass::EExpectedConfigReject => "E_EXPECTED_CONFIG_REJECT",
        ErrorClass::ENetworkEnv => "E_NETWORK_ENV",
        ErrorClass::ETimeoutHang => "E_TIMEOUT_HANG",
        ErrorClass::EToolBug => "E_TOOL_BUG",
        ErrorClass::EEvidenceGap => "E_EVIDENCE_GAP",
        ErrorClass::ERefLimitation => "E_REF_LIMITATION",
    }
}

/// 证据原子写（`--out`）。
pub fn write_evidence(e: &CellEvidence, out: &Path) -> Result<(), ProbeError> {
    let bytes = serde_json::to_vec_pretty(e).map_err(|err| ProbeError::EvidenceWrite {
        path: out.display().to_string(),
        detail: err.to_string(),
    })?;
    util::atomic_write(out, &bytes).map_err(|err| ProbeError::EvidenceWrite {
        path: out.display().to_string(),
        detail: err.to_string(),
    })
}

fn print_config_invalid(field: &str, detail: &str) {
    println!(
        "{}",
        serde_json::json!({
            "schema_version": 1,
            "error": "config_invalid",
            "field": field,
            "detail": detail,
        })
    );
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cli = match parse_args(&args) {
        Ok(cli) => cli,
        Err(ProbeError::ConfigInvalid { field, detail }) => {
            print_config_invalid(&field, &detail);
            return ExitCode::from(2);
        }
        Err(other) => {
            print_config_invalid("args", &other.to_string());
            return ExitCode::from(2);
        }
    };
    let cfg = match config::load_config(&cli.config_path) {
        Ok(cfg) => cfg,
        Err(ProbeError::ConfigInvalid { field, detail }) => {
            print_config_invalid(&field, &detail);
            return ExitCode::from(2);
        }
        Err(other) => {
            print_config_invalid("config", &other.to_string());
            return ExitCode::from(2);
        }
    };
    if let Err(ProbeError::ConfigInvalid { field, detail }) = config::validate_config(&cfg) {
        print_config_invalid(&field, &detail);
        return ExitCode::from(2);
    }
    match run_cell(&cfg, &cli) {
        Ok(evidence) => {
            let code = match evidence.verdict {
                Verdict::Pass => 0,
                Verdict::Fail => 1,
                Verdict::Blocked | Verdict::NotApplicable | Verdict::NotImplemented => 2,
            };
            ExitCode::from(code)
        }
        Err(err) => {
            println!(
                "{}",
                serde_json::json!({
                    "schema_version": 1,
                    "error": "tool_error",
                    "field": "runtime",
                    "detail": err.to_string(),
                })
            );
            eprintln!("probe tool error: {err}");
            ExitCode::from(3)
        }
    }
}

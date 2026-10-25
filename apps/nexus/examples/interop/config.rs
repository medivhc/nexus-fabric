//! probe 输入配置（D2.2）：`deny_unknown_fields` + 结构化校验。
//!
//! 枚举值用 PascalCase（Rust 变体名），未知值/未知字段/类型错 → 配置非法。

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::ProbeError;

/// 五协议。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Vless,
    Anytls,
    Hysteria2,
    Trojan,
    Shadowsocks,
}

impl Protocol {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Vless => "vless",
            Self::Anytls => "anytls",
            Self::Hysteria2 => "hysteria2",
            Self::Trojan => "trojan",
            Self::Shadowsocks => "shadowsocks",
        }
    }
}

/// 变体（冻结枚举）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Variant {
    Default,
    VlessVision,
    Hy2Salamander,
    TrojanFallback,
    AnyTlsCustomPadding,
}

impl Variant {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::VlessVision => "vless-vision",
            Self::Hy2Salamander => "hy2-salamander",
            Self::TrojanFallback => "trojan-fallback",
            Self::AnyTlsCustomPadding => "anytls-custom-padding",
        }
    }
}

/// cell（冻结枚举）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Cell {
    Handshake,
    TcpSmall,
    TcpThroughput,
    UdpEcho,
    BadCredential,
    BadConfig,
    LongLived,
    Reconnect,
    QpackDiag,
    PaddingDiag,
}

impl Cell {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Handshake => "handshake",
            Self::TcpSmall => "tcp-small",
            Self::TcpThroughput => "tcp-throughput",
            Self::UdpEcho => "udp-echo",
            Self::BadCredential => "bad-credential",
            Self::BadConfig => "bad-config",
            Self::LongLived => "long-lived",
            Self::Reconnect => "reconnect",
            Self::QpackDiag => "qpack-diag",
            Self::PaddingDiag => "padding-diag",
        }
    }

    /// 失败格（F1/F1-fallback/F2 语义）。
    #[must_use]
    pub fn is_failure_cell(self) -> bool {
        matches!(self, Self::BadCredential | Self::BadConfig)
    }
}

/// 参照端。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceEndpoint {
    pub host: String,
    pub port: u16,
    pub server_name: String,
    pub alpn: Vec<String>,
}

/// 目标端种类。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetKind {
    TcpEcho,
    TcpSink,
    TcpSource,
    UdpEcho,
    HttpFallback,
}

/// 目标端。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetEndpoint {
    pub kind: TargetKind,
    pub host: String,
    pub port: u16,
}

/// VLESS flow 取值。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VlessFlowKind {
    None,
    Vision,
}

impl VlessFlowKind {
    #[must_use]
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::None => "",
            Self::Vision => "xtls-rprx-vision",
        }
    }
}

/// VLESS 凭据。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VlessCred {
    pub uuid: String,
    pub flow: VlessFlowKind,
}

/// AnyTLS 凭据。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnytlsCred {
    pub password: String,
    pub padding_md5_hex: String,
}

/// Hysteria2 混淆。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Hy2Obfs {
    None,
    Salamander { password: String },
}

/// Hysteria2 凭据。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hysteria2Cred {
    pub password: String,
    pub obfs: Hy2Obfs,
}

/// Trojan 请求头格式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HeaderFormat {
    Standard,
    Singbox,
}

/// Trojan 凭据。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrojanCred {
    pub password: String,
    pub header_format: HeaderFormat,
}

/// Shadowsocks 加密方法。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SsMethodKind {
    Chacha20IetfPoly1305,
}

impl SsMethodKind {
    #[must_use]
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Chacha20IetfPoly1305 => "chacha20-ietf-poly1305",
        }
    }
}

/// Shadowsocks 凭据。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowsocksCred {
    pub password: String,
    pub method: SsMethodKind,
}

/// 外部标签凭据（`{"Vless":{...}}`）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Credentials {
    Vless(VlessCred),
    Anytls(AnytlsCred),
    Hysteria2(Hysteria2Cred),
    Trojan(TrojanCred),
    Shadowsocks(ShadowsocksCred),
}

/// TLS 参数。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub skip_cert_verify: bool,
    pub sni: String,
}

/// 传输参数。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportConfig {
    pub fast_open: bool,
    pub udp: bool,
    pub vision_direct: bool,
}

/// 超时（毫秒）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Timeouts {
    pub handshake_ms: u64,
    pub cell_ms: u64,
    pub failure_ms: u64,
    pub long_lived_ms: u64,
    pub heartbeat_ms: u64,
    pub reconnect_wait_ms: u64,
}

/// 工作量。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workload {
    pub small_bytes: usize,
    pub throughput_bytes: usize,
    pub throughput_repeats: u32,
    pub warmup_bytes: usize,
    pub udp_datagrams: u32,
    pub udp_payload_bytes: usize,
    pub udp_interval_ms: u64,
    pub long_lived_heartbeats: u32,
    pub reconnect_cycles: u32,
}

/// probe 配置顶层。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InteropProbeConfig {
    pub schema_version: u32,
    pub run_id: String,
    pub protocol: Protocol,
    pub variant: Variant,
    pub cell: Cell,
    pub reference: ReferenceEndpoint,
    pub target: TargetEndpoint,
    pub credentials: Credentials,
    pub tls: TlsConfig,
    pub transport: TransportConfig,
    pub timeouts: Timeouts,
    pub workload: Workload,
}

impl InteropProbeConfig {
    /// 凭据是否与协议匹配（不匹配时返回字段名）。
    #[must_use]
    pub fn credentials_field(&self) -> Option<&'static str> {
        let ok = matches!(
            (self.protocol, &self.credentials),
            (Protocol::Vless, Credentials::Vless(_))
                | (Protocol::Anytls, Credentials::Anytls(_))
                | (Protocol::Hysteria2, Credentials::Hysteria2(_))
                | (Protocol::Trojan, Credentials::Trojan(_))
                | (Protocol::Shadowsocks, Credentials::Shadowsocks(_))
        );
        if ok { None } else { Some("credentials") }
    }

    /// 该协议允许的 cell（§6.3）。
    #[must_use]
    pub fn cell_allowed(&self) -> bool {
        use Cell as C;
        match self.protocol {
            Protocol::Vless => matches!(
                self.cell,
                C::Handshake
                    | C::TcpSmall
                    | C::TcpThroughput
                    | C::UdpEcho
                    | C::BadCredential
                    | C::BadConfig
                    | C::LongLived
                    | C::Reconnect
            ),
            Protocol::Anytls => matches!(
                self.cell,
                C::Handshake
                    | C::PaddingDiag
                    | C::TcpSmall
                    | C::TcpThroughput
                    | C::UdpEcho
                    | C::BadCredential
                    | C::BadConfig
                    | C::LongLived
                    | C::Reconnect
            ),
            Protocol::Hysteria2 => matches!(
                self.cell,
                C::Handshake
                    | C::QpackDiag
                    | C::TcpSmall
                    | C::TcpThroughput
                    | C::UdpEcho
                    | C::BadCredential
                    | C::BadConfig
                    | C::LongLived
                    | C::Reconnect
            ),
            Protocol::Trojan | Protocol::Shadowsocks => matches!(
                self.cell,
                C::Handshake
                    | C::TcpSmall
                    | C::TcpThroughput
                    | C::UdpEcho
                    | C::BadCredential
                    | C::BadConfig
                    | C::LongLived
                    | C::Reconnect
            ),
        }
    }

    /// 该协议允许的 variant（D2.2 / §6.3）。
    #[must_use]
    pub fn variant_allowed(&self) -> bool {
        use Variant as V;
        match self.protocol {
            Protocol::Vless => matches!(self.variant, V::Default | V::VlessVision),
            Protocol::Anytls => matches!(self.variant, V::Default | V::AnyTlsCustomPadding),
            Protocol::Hysteria2 => matches!(self.variant, V::Default | V::Hy2Salamander),
            Protocol::Trojan => matches!(self.variant, V::Default | V::TrojanFallback),
            Protocol::Shadowsocks => matches!(self.variant, V::Default),
        }
    }
}

/// 读取并反序列化配置（JSON）。
pub fn load_config(path: &Path) -> Result<InteropProbeConfig, ProbeError> {
    let bytes = std::fs::read(path).map_err(|e| ProbeError::ConfigInvalid {
        field: "config".into(),
        detail: format!("read {}: {e}", path.display()),
    })?;
    serde_json::from_slice(&bytes).map_err(|e| ProbeError::ConfigInvalid {
        field: serde_field(&e),
        detail: e.to_string(),
    })
}

/// 从 serde 错误里尽量提取字段路径（不含输入原文/凭据）。
fn serde_field(err: &serde_json::Error) -> String {
    let text = err.to_string();
    // serde_json 文案形如 "unknown field `x`, expected ..." / "missing field `y`"。
    for marker in ["unknown field `", "missing field `"] {
        if let Some(rest) = text.split(marker).nth(1) {
            if let Some(name) = rest.split('`').next() {
                return name.to_string();
            }
        }
    }
    "config".to_string()
}

fn invalid(field: &str, detail: impl Into<String>) -> ProbeError {
    ProbeError::ConfigInvalid {
        field: field.to_string(),
        detail: detail.into(),
    }
}

/// 结构化校验（D2.2 数值/组合规则）。
pub fn validate_config(cfg: &InteropProbeConfig) -> Result<(), ProbeError> {
    if cfg.schema_version != 1 {
        return Err(invalid("schema_version", "must be 1"));
    }
    if cfg.run_id.is_empty() {
        return Err(invalid("run_id", "must be non-empty"));
    }
    if cfg.reference.host.is_empty() {
        return Err(invalid("reference.host", "must be non-empty"));
    }
    if cfg.reference.port == 0 {
        return Err(invalid("reference.port", "must be non-zero"));
    }
    if cfg.target.port == 0 {
        return Err(invalid("target.port", "must be non-zero"));
    }
    if cfg.target.host.is_empty() {
        return Err(invalid("target.host", "must be non-empty"));
    }
    for (name, value) in [
        ("handshake_ms", cfg.timeouts.handshake_ms),
        ("cell_ms", cfg.timeouts.cell_ms),
        ("failure_ms", cfg.timeouts.failure_ms),
        ("long_lived_ms", cfg.timeouts.long_lived_ms),
        ("heartbeat_ms", cfg.timeouts.heartbeat_ms),
        ("reconnect_wait_ms", cfg.timeouts.reconnect_wait_ms),
    ] {
        if value == 0 {
            return Err(invalid(&format!("timeouts.{name}"), "must be non-zero"));
        }
    }
    if cfg.workload.udp_payload_bytes > 4096 {
        return Err(invalid("workload.udp_payload_bytes", "must be <= 4096"));
    }
    if cfg.workload.throughput_repeats < 1 {
        return Err(invalid("workload.throughput_repeats", "must be >= 1"));
    }
    if cfg.workload.small_bytes == 0 {
        return Err(invalid("workload.small_bytes", "must be non-zero"));
    }
    if cfg.workload.throughput_bytes == 0 || cfg.workload.warmup_bytes == 0 {
        return Err(invalid("workload.throughput_bytes", "must be non-zero"));
    }
    if cfg.workload.udp_datagrams == 0 || cfg.workload.udp_payload_bytes < 16 {
        return Err(invalid(
            "workload.udp_datagrams",
            "datagrams must be non-zero and payload >= 16",
        ));
    }
    if cfg.workload.long_lived_heartbeats == 0 || cfg.workload.reconnect_cycles == 0 {
        return Err(invalid(
            "workload.long_lived_heartbeats",
            "long_lived_heartbeats/reconnect_cycles must be non-zero",
        ));
    }
    if !cfg.variant_allowed() {
        return Err(invalid("variant", "not allowed for protocol"));
    }
    if !cfg.cell_allowed() {
        return Err(invalid("cell", "not allowed for protocol"));
    }
    if let Some(field) = cfg.credentials_field() {
        return Err(invalid(field, "credential variant does not match protocol"));
    }
    match (&cfg.protocol, &cfg.variant, &cfg.credentials) {
        (Protocol::Vless, Variant::VlessVision, Credentials::Vless(c)) => {
            if c.flow != VlessFlowKind::Vision {
                return Err(invalid("credentials.Vless.flow", "must be Vision"));
            }
        }
        (Protocol::Vless, Variant::Default, Credentials::Vless(c)) => {
            if c.flow != VlessFlowKind::None {
                return Err(invalid("credentials.Vless.flow", "must be None"));
            }
            nexus_outbound_vless::VlessUuid::parse(&c.uuid)
                .map_err(|_| invalid("credentials.Vless.uuid", "invalid uuid"))?;
        }
        (Protocol::Anytls, _, Credentials::Anytls(c)) => {
            let expected = nexus_outbound_anytls::padding_md5_hex(
                nexus_outbound_anytls::DEFAULT_PADDING_SCHEME,
            );
            if c.padding_md5_hex != expected {
                return Err(invalid(
                    "credentials.Anytls.padding_md5_hex",
                    "must equal crate DEFAULT_PADDING_SCHEME md5 (drift guard)",
                ));
            }
        }
        (Protocol::Hysteria2, Variant::Hy2Salamander, Credentials::Hysteria2(c))
            if !matches!(c.obfs, Hy2Obfs::Salamander { .. }) =>
        {
            return Err(invalid("credentials.Hysteria2.obfs", "must be Salamander"));
        }
        (Protocol::Hysteria2, Variant::Default, Credentials::Hysteria2(c))
            if !matches!(c.obfs, Hy2Obfs::None) =>
        {
            return Err(invalid("credentials.Hysteria2.obfs", "must be None"));
        }
        _ => {}
    }
    if cfg.variant == Variant::TrojanFallback && cfg.cell != Cell::BadCredential {
        return Err(invalid("variant", "TrojanFallback only for BadCredential"));
    }
    if cfg.variant == Variant::AnyTlsCustomPadding && cfg.cell != Cell::BadConfig {
        return Err(invalid("variant", "AnyTlsCustomPadding only for BadConfig"));
    }
    if cfg.variant == Variant::Hy2Salamander
        && !matches!(cfg.cell, Cell::Handshake | Cell::TcpSmall)
    {
        return Err(invalid(
            "variant",
            "Hy2Salamander only for Handshake | TcpSmall",
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::carrier_for;

    pub(crate) fn base_json() -> serde_json::Value {
        serde_json::json!({
            "schema_version": 1,
            "run_id": "protocol-interop-verification",
            "protocol": "Vless",
            "variant": "Default",
            "cell": "Handshake",
            "reference": {"host": "127.0.0.1", "port": 26100, "server_name": "localhost", "alpn": []},
            "target": {"kind": "TcpEcho", "host": "127.0.0.1", "port": 26200},
            "credentials": {"Vless": {"uuid": "6af74a31-cd3b-49ee-83fe-34fb1b68497d", "flow": "None"}},
            "tls": {"skip_cert_verify": true, "sni": "localhost"},
            "transport": {"fast_open": true, "udp": true, "vision_direct": false},
            "timeouts": {"handshake_ms": 10000, "cell_ms": 60000, "failure_ms": 10000,
                         "long_lived_ms": 120000, "heartbeat_ms": 10000, "reconnect_wait_ms": 2000},
            "workload": {"small_bytes": 65536, "throughput_bytes": 33554432, "throughput_repeats": 3,
                         "warmup_bytes": 1048576, "udp_datagrams": 1000, "udp_payload_bytes": 512,
                         "udp_interval_ms": 1, "long_lived_heartbeats": 12, "reconnect_cycles": 3}
        })
    }

    fn parse(v: serde_json::Value) -> Result<InteropProbeConfig, ProbeError> {
        let cfg: InteropProbeConfig =
            serde_json::from_value(v).map_err(|e| ProbeError::ConfigInvalid {
                field: serde_field(&e),
                detail: e.to_string(),
            })?;
        Ok(cfg)
    }

    fn check(v: serde_json::Value) -> Result<(), ProbeError> {
        validate_config(&parse(v)?)
    }

    #[test]
    fn accepts_valid_baseline() {
        check(base_json()).expect("baseline must validate");
    }

    #[test]
    fn rejects_unknown_field() {
        let mut v = base_json();
        v["extra"] = serde_json::json!(1);
        assert!(parse(v).is_err());
    }

    #[test]
    fn rejects_unknown_enum() {
        let mut v = base_json();
        v["cell"] = serde_json::json!("Bogus");
        assert!(parse(v).is_err());
    }

    #[test]
    fn rejects_missing_field() {
        let mut v = base_json();
        v.as_object_mut().expect("obj").remove("target");
        assert!(parse(v).is_err());
    }

    #[test]
    fn rejects_zero_ports_and_timeouts() {
        let mut v = base_json();
        v["reference"]["port"] = serde_json::json!(0);
        assert!(check(v).is_err());
        let mut v = base_json();
        v["target"]["port"] = serde_json::json!(0);
        assert!(check(v).is_err());
        let mut v = base_json();
        v["timeouts"]["failure_ms"] = serde_json::json!(0);
        assert!(check(v).is_err());
    }

    #[test]
    fn rejects_wrong_credential_variant() {
        let mut v = base_json();
        v["protocol"] = serde_json::json!("Trojan");
        assert!(check(v).is_err());
    }

    #[test]
    fn rejects_disallowed_variant_cell_combo() {
        let mut v = base_json();
        v["variant"] = serde_json::json!("VlessVision");
        assert!(check(v).is_err(), "vision with flow None must be rejected");
        let mut v = base_json();
        v["cell"] = serde_json::json!("PaddingDiag");
        assert!(check(v).is_err(), "vless padding-diag not in matrix");
    }

    #[test]
    fn hy2_salamander_accepts_handshake_and_tcpsmall_only() {
        let mut v = base_json();
        v["protocol"] = serde_json::json!("Hysteria2");
        v["variant"] = serde_json::json!("Hy2Salamander");
        v["reference"]["port"] = serde_json::json!(26104);
        v["credentials"] = serde_json::json!({
            "Hysteria2": {
                "password": "hy2-password",
                "obfs": {"Salamander": {"password": "hy2-obfs-password"}}
            }
        });
        v["cell"] = serde_json::json!("Handshake");
        assert!(check(v.clone()).is_ok(), "Handshake must be accepted");
        v["cell"] = serde_json::json!("TcpSmall");
        assert!(check(v.clone()).is_ok(), "TcpSmall must be accepted");
        v["cell"] = serde_json::json!("TcpThroughput");
        assert!(
            check(v.clone()).is_err(),
            "TcpThroughput must be rejected for Hy2Salamander"
        );
        v["cell"] = serde_json::json!("UdpEcho");
        assert!(
            check(v).is_err(),
            "UdpEcho must be rejected for Hy2Salamander"
        );
    }

    #[test]
    fn rejects_anytls_padding_md5_drift() {
        let mut v = base_json();
        v["protocol"] = serde_json::json!("Anytls");
        v["credentials"] =
            serde_json::json!({"Anytls": {"password": "x", "padding_md5_hex": "deadbeef"}});
        assert!(check(v.clone()).is_err());
        v["credentials"]["Anytls"]["padding_md5_hex"] = serde_json::json!(
            nexus_outbound_anytls::padding_md5_hex(nexus_outbound_anytls::DEFAULT_PADDING_SCHEME)
        );
        assert!(check(v).is_ok());
    }

    #[test]
    fn rejects_udp_payload_over_4096() {
        let mut v = base_json();
        v["workload"]["udp_payload_bytes"] = serde_json::json!(4097);
        assert!(check(v).is_err());
    }

    #[test]
    fn carrier_derivation_matches_matrix() {
        let cfg = parse(base_json()).expect("parse");
        assert_eq!(
            carrier_for(&cfg),
            (
                crate::evidence::Carrier::ProductSocks5,
                crate::evidence::Scope::ProductPath
            )
        );
        let mut v = base_json();
        v["cell"] = serde_json::json!("UdpEcho");
        let cfg = parse(v).expect("parse");
        assert_eq!(
            carrier_for(&cfg),
            (
                crate::evidence::Carrier::CrateDirect,
                crate::evidence::Scope::ProtocolWire
            )
        );
    }

    #[test]
    fn all_probe_templates_validate() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/protocols/interop/probe-config");
        let mut count = 0usize;
        for entry in std::fs::read_dir(&dir).expect("probe-config dir") {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read template");
            let text = text
                .replace("${VLESS_UUID}", "6af74a31-cd3b-49ee-83fe-34fb1b68497d")
                .replace(
                    "${ANYTLS_PADDING_MD5}",
                    &nexus_outbound_anytls::padding_md5_hex(
                        nexus_outbound_anytls::DEFAULT_PADDING_SCHEME,
                    ),
                )
                .replace("${ANYTLS_PASSWORD}", "anytls-password")
                .replace("${HY2_PASSWORD}", "hy2-password")
                .replace("${HY2_OBFS_PASSWORD}", "hy2-obfs-password")
                .replace("${TROJAN_PASSWORD}", "trojan-password")
                .replace("${SS_PASSWORD}", "ss-password");
            assert!(
                !text.contains("${"),
                "unresolved token in {}",
                path.display()
            );
            let cfg: InteropProbeConfig =
                serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            validate_config(&cfg).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            count += 1;
        }
        assert_eq!(count, 47, "expected 47 probe templates");
    }

    #[test]
    fn error_class_serializes_to_frozen_labels() {
        use crate::evidence::ErrorClass;
        let labels = [
            (ErrorClass::ENexusHandshakeWire, "E_NEXUS_HANDSHAKE_WIRE"),
            (ErrorClass::ENexusAuthEncoding, "E_NEXUS_AUTH_ENCODING"),
            (ErrorClass::ENexusFraming, "E_NEXUS_FRAMING"),
            (ErrorClass::ENexusTransport, "E_NEXUS_TRANSPORT"),
            (ErrorClass::ENexusUdp, "E_NEXUS_UDP"),
            (ErrorClass::ENexusCodec, "E_NEXUS_CODEC"),
            (ErrorClass::ENexusNotImplemented, "E_NEXUS_NOT_IMPLEMENTED"),
            (ErrorClass::ERefConfig, "E_REF_CONFIG"),
            (ErrorClass::ERefUnsupported, "E_REF_UNSUPPORTED"),
            (ErrorClass::ERefBehavior, "E_REF_BEHAVIOR"),
            (ErrorClass::EExpectedAuthReject, "E_EXPECTED_AUTH_REJECT"),
            (
                ErrorClass::EExpectedConfigReject,
                "E_EXPECTED_CONFIG_REJECT",
            ),
            (ErrorClass::ENetworkEnv, "E_NETWORK_ENV"),
            (ErrorClass::ETimeoutHang, "E_TIMEOUT_HANG"),
            (ErrorClass::EToolBug, "E_TOOL_BUG"),
            (ErrorClass::EEvidenceGap, "E_EVIDENCE_GAP"),
            (ErrorClass::ERefLimitation, "E_REF_LIMITATION"),
        ];
        for (class, label) in labels {
            assert_eq!(
                serde_json::to_string(&class).expect("ser"),
                format!("\"{label}\"")
            );
        }
    }
}

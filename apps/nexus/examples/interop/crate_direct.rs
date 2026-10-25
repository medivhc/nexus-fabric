//! crate 直调载波（AC-05）：VLESS/AnyTLS/Hysteria2 的 UDP，Trojan/SS 合成格，QPACK 诊断。

use std::collections::VecDeque;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

use nexus_outbound_anytls::{
    AnyTlsCommand, AnyTlsTarget, CLIENT_IDENT, client_handshake, client_open_uot_stream,
    decode_uot_datagrams, encode_uot_datagram, read_frame, write_frame,
};
use nexus_outbound_hysteria2::{CcRx, CertVerify, Hysteria2Client, Hysteria2Target, Obfs};
use nexus_outbound_vless::{
    VlessCommand, VlessConn, VlessFlow, VlessRequest, VlessTarget, VlessUuid, encode_udp_datagram,
    read_udp_datagram,
};

use crate::Outcome;
use crate::config::{Cell, Credentials, Hy2Obfs, InteropProbeConfig, Protocol};
use crate::evidence::{ErrorClass, ErrorInfo, Metrics, Verdict};
use crate::targets::UDP_PORT;
use crate::util;

/// crate 直调入口。
pub fn run_cell(cfg: &InteropProbeConfig, cell_dir: &Path) -> Result<Outcome, String> {
    match (cfg.protocol, cfg.cell) {
        (Protocol::Vless, Cell::UdpEcho) => vless_udp(cfg),
        (Protocol::Anytls, Cell::UdpEcho) => anytls_udp(cfg),
        (Protocol::Hysteria2, Cell::UdpEcho) => hysteria2_udp(cfg),
        (Protocol::Hysteria2, Cell::QpackDiag) => hysteria2_qpack_diag(cfg, cell_dir),
        (Protocol::Trojan, Cell::UdpEcho) => {
            write_manifest(
                cell_dir,
                "trojan-udp-not-implemented",
                "Nexus Trojan 出站只实现 CMD 0x01（TCP）；无 UDP 关联/帧路径",
                &[
                    (
                        "crates/nexus-outbound-trojan/src/lib.rs",
                        "117-158",
                        "encode_request_fmt（仅 CMD 0x01）",
                    ),
                    (
                        "crates/nexus-ingress/src/lib.rs",
                        "232-241",
                        "SOCKS5 BND/UDP ASSOCIATE 明确拒绝",
                    ),
                ],
            )?;
            Ok(Outcome::not_implemented(
                "Trojan UDP 路径未实现（产品入口 + 出站均无）",
            ))
        }
        (Protocol::Shadowsocks, Cell::UdpEcho) => {
            write_manifest(
                cell_dir,
                "shadowsocks-udp-not-implemented",
                "Nexus Shadowsocks 出站仅 TCP record 帧；无 UDP 关联",
                &[
                    (
                        "crates/nexus-outbound-shadowsocks/src/lib.rs",
                        "279-380",
                        "SsStream 仅 TCP record seal/open",
                    ),
                    (
                        "crates/nexus-ingress/src/lib.rs",
                        "232-241",
                        "SOCKS5 BND/UDP ASSOCIATE 明确拒绝",
                    ),
                ],
            )?;
            Ok(Outcome::not_implemented(
                "Shadowsocks UDP 路径未实现（产品入口 + 出站均无）",
            ))
        }
        (Protocol::Trojan, Cell::BadConfig) => {
            write_manifest(
                cell_dir,
                "trojan-badconfig-not-applicable",
                "TrojanHeaderFormat::Standard 与 Singbox 的请求头字节等价，客户端无法表达仅服务端不同的负向配置",
                &[(
                    "crates/nexus-outbound-trojan/src/lib.rs",
                    "107-158",
                    "TrojanHeaderFormat + encode_request_fmt",
                )],
            )?;
            Ok(Outcome::not_applicable(
                "Trojan BadConfig 在 Nexus 出站配置面不可表达",
            ))
        }
        (protocol, cell) => Err(format!(
            "crate-direct carrier does not implement {protocol:?}/{cell:?}"
        )),
    }
}

fn udp_target() -> &'static str {
    "127.0.0.1:26202"
}

trait UdpTransport {
    fn send(&mut self, payload: &[u8]) -> Result<(), String>;
    fn recv(&mut self) -> Result<Vec<u8>, String>;
}

fn run_udp_loop(
    cfg: &InteropProbeConfig,
    transport: &mut dyn UdpTransport,
) -> Result<Outcome, String> {
    let seed = util::cell_seed(cfg.protocol.label(), cfg.variant.label(), cfg.cell.label());
    let total = cfg.workload.udp_datagrams;
    let len = cfg.workload.udp_payload_bytes;
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut metrics = Metrics::default();
    for seq in 0..u64::from(total) {
        if Instant::now() >= deadline {
            metrics.udp_sent = u32::try_from(seq).unwrap_or(u32::MAX);
            return Ok(Outcome::fail(
                ErrorClass::ENexusUdp,
                format!("udp window exceeded at seq {seq}/{total}"),
                metrics,
            ));
        }
        let payload = util::udp_payload(seed, seq, len);
        if let Err(e) = transport.send(&payload) {
            metrics.udp_sent = u32::try_from(seq).unwrap_or(u32::MAX);
            return Ok(Outcome::fail(
                ErrorClass::ENexusUdp,
                format!("udp send seq {seq}: {e}"),
                metrics,
            ));
        }
        metrics.udp_sent += 1;
        match transport.recv() {
            Ok(got) => {
                metrics.udp_received += 1;
                metrics.bytes_down += got.len() as u64;
                if got != payload {
                    metrics.udp_corrupt += 1;
                    return Ok(Outcome::fail(
                        ErrorClass::ENexusUdp,
                        format!("udp payload mismatch at seq {seq}"),
                        metrics,
                    ));
                }
            }
            Err(e) => {
                return Ok(Outcome::fail(
                    ErrorClass::ENexusUdp,
                    format!("udp recv seq {seq}: {e}"),
                    metrics,
                ));
            }
        }
        metrics.bytes_up += len as u64;
        if cfg.workload.udp_interval_ms > 0 {
            std::thread::sleep(Duration::from_millis(cfg.workload.udp_interval_ms));
        }
    }
    if metrics.udp_received == total && metrics.udp_corrupt == 0 {
        Ok(Outcome::pass(metrics, vec!["udp_seq_and_hash_ok".into()]))
    } else {
        Ok(Outcome::fail(
            ErrorClass::ENexusUdp,
            format!(
                "udp incomplete: sent={} received={}",
                metrics.udp_sent, metrics.udp_received
            ),
            metrics,
        ))
    }
}

struct VlessUdp {
    conn: VlessConn<rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>>,
}

impl UdpTransport for VlessUdp {
    fn send(&mut self, payload: &[u8]) -> Result<(), String> {
        let framed = encode_udp_datagram(payload).map_err(|e| e.to_string())?;
        self.conn.write_all(&framed).map_err(|e| e.to_string())
    }

    fn recv(&mut self) -> Result<Vec<u8>, String> {
        read_udp_datagram(&mut self.conn).map_err(|e| e.to_string())
    }
}

fn vless_udp(cfg: &InteropProbeConfig) -> Result<Outcome, String> {
    let Credentials::Vless(cred) = &cfg.credentials else {
        return Err("vless udp requires Vless credentials".into());
    };
    let uuid = VlessUuid::parse(&cred.uuid).map_err(|_| "invalid uuid")?;
    let timeout = Duration::from_millis(cfg.timeouts.cell_ms);
    let stream = match crate::tls::connect(
        &cfg.reference.host,
        cfg.reference.port,
        &cfg.reference.server_name,
        cfg.tls.skip_cert_verify,
        &cfg.reference.alpn,
        timeout,
    ) {
        Ok(stream) => stream,
        Err(e) => {
            return Ok(Outcome::blocked(
                ErrorClass::ERefConfig,
                format!("vless udp reference connect: {e}"),
            ));
        }
    };
    let mut conn = VlessConn::new(stream);
    if let Err(e) = conn.handshake(&VlessRequest {
        uuid,
        flow: VlessFlow::None,
        command: VlessCommand::Udp,
        port: UDP_PORT,
        target: Some(VlessTarget::Ipv4(std::net::Ipv4Addr::LOCALHOST)),
    }) {
        return Ok(Outcome::blocked(
            ErrorClass::ENexusHandshakeWire,
            format!("vless udp handshake: {e}"),
        ));
    }
    run_udp_loop(cfg, &mut VlessUdp { conn })
}

struct AnyTlsUdp {
    stream: rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>,
    stream_id: u32,
    pending: VecDeque<Vec<u8>>,
}

impl UdpTransport for AnyTlsUdp {
    fn send(&mut self, payload: &[u8]) -> Result<(), String> {
        let framed = encode_uot_datagram(payload).map_err(|e| e.to_string())?;
        write_frame(
            &mut self.stream,
            AnyTlsCommand::Psh,
            self.stream_id,
            &framed,
        )
        .map_err(|e| e.to_string())
    }

    fn recv(&mut self) -> Result<Vec<u8>, String> {
        if let Some(payload) = self.pending.pop_front() {
            return Ok(payload);
        }
        let frame = read_frame(&mut self.stream).map_err(|e| e.to_string())?;
        if frame.stream_id != self.stream_id {
            return Err(format!("unexpected stream {}", frame.stream_id));
        }
        let datagrams = decode_uot_datagrams(&frame.data).map_err(|e| e.to_string())?;
        self.pending.extend(datagrams);
        self.pending
            .pop_front()
            .ok_or_else(|| "empty uot frame".to_string())
    }
}

fn anytls_udp(cfg: &InteropProbeConfig) -> Result<Outcome, String> {
    let Credentials::Anytls(cred) = &cfg.credentials else {
        return Err("anytls udp requires Anytls credentials".into());
    };
    let timeout = Duration::from_millis(cfg.timeouts.cell_ms);
    let mut stream = match crate::tls::connect(
        &cfg.reference.host,
        cfg.reference.port,
        &cfg.reference.server_name,
        cfg.tls.skip_cert_verify,
        &cfg.reference.alpn,
        timeout,
    ) {
        Ok(stream) => stream,
        Err(e) => {
            return Ok(Outcome::blocked(
                ErrorClass::ERefConfig,
                format!("anytls udp reference connect: {e}"),
            ));
        }
    };
    let mut hs = match client_handshake(
        &mut stream,
        &cred.password,
        0,
        CLIENT_IDENT,
        &cred.padding_md5_hex,
    ) {
        Ok(hs) => hs,
        Err(e) => {
            return Ok(Outcome::blocked(
                ErrorClass::ENexusHandshakeWire,
                format!("anytls udp handshake: {e}"),
            ));
        }
    };
    let target = AnyTlsTarget::Ipv4([127, 0, 0, 1], UDP_PORT);
    let stream_id = match client_open_uot_stream(&mut stream, &mut hs, &target) {
        Ok(id) => id,
        Err(e) => {
            return Ok(Outcome::blocked(
                ErrorClass::ENexusHandshakeWire,
                format!("anytls uot open: {e}"),
            ));
        }
    };
    run_udp_loop(
        cfg,
        &mut AnyTlsUdp {
            stream,
            stream_id,
            pending: VecDeque::new(),
        },
    )
}

struct Hy2Udp {
    client: Hysteria2Client,
    session: u32,
    failure_ms: u64,
}

impl UdpTransport for Hy2Udp {
    fn send(&mut self, payload: &[u8]) -> Result<(), String> {
        self.client
            .send_udp(self.session, udp_target(), payload)
            .map_err(|e| format!("{e}"))
    }

    fn recv(&mut self) -> Result<Vec<u8>, String> {
        match self.client.recv_udp(Duration::from_millis(self.failure_ms)) {
            Ok(msg) => Ok(msg.payload),
            Err(e) => Err(format!("{e}")),
        }
    }
}

fn hysteria2_target(cfg: &InteropProbeConfig) -> Result<Hysteria2Target, String> {
    let Credentials::Hysteria2(cred) = &cfg.credentials else {
        return Err("hysteria2 requires Hysteria2 credentials".into());
    };
    let mut target = Hysteria2Target::new(
        cfg.reference.host.clone(),
        cfg.reference.port,
        cred.password.clone(),
    );
    target.sni = Some(cfg.tls.sni.clone());
    target.verify = if cfg.tls.skip_cert_verify {
        CertVerify::Insecure
    } else {
        CertVerify::SystemRoots
    };
    target.obfs = match &cred.obfs {
        Hy2Obfs::None => Obfs::None,
        Hy2Obfs::Salamander { password } => Obfs::parse("salamander", password.as_bytes())
            .map_err(|e| format!("obfs parse: {e}"))?,
    };
    target.fast_open = cfg.transport.fast_open;
    target.udp = cfg.transport.udp;
    target.handshake_timeout = Duration::from_millis(cfg.timeouts.handshake_ms);
    Ok(target)
}

fn hysteria2_udp(cfg: &InteropProbeConfig) -> Result<Outcome, String> {
    let target = hysteria2_target(cfg)?;
    let mut client = match Hysteria2Client::connect(&target) {
        Ok(client) => client,
        Err(e) => {
            return Ok(Outcome::blocked(
                ErrorClass::ERefConfig,
                format!("hy2 connect: {e}"),
            ));
        }
    };
    let session = client.alloc_udp_session();
    run_udp_loop(
        cfg,
        &mut Hy2Udp {
            client,
            session,
            failure_ms: cfg.timeouts.failure_ms,
        },
    )
}

fn cc_rx_label(cc_rx: &CcRx) -> String {
    match cc_rx {
        CcRx::Unlimited => "0".to_string(),
        CcRx::Auto => "auto".to_string(),
        CcRx::Bps(bps) => bps.to_string(),
    }
}

fn hysteria2_qpack_diag(cfg: &InteropProbeConfig, cell_dir: &Path) -> Result<Outcome, String> {
    let target = hysteria2_target(cfg)?;
    match Hysteria2Client::connect(&target) {
        Ok(client) => {
            write_manifest(
                cell_dir,
                "qpack-diag-handshake-ok",
                "Hy2 认证握手成功；未触发 QPACK 诊断分支",
                &[(
                    "crates/nexus-outbound-hysteria2/src/qpack.rs",
                    "1-200",
                    "QPACK 编解码",
                )],
            )?;
            Ok(Outcome::pass(
                Metrics::default(),
                vec![
                    "qpack_diag_not_triggered=handshake_ok".into(),
                    "hy2_error=null".into(),
                    "hy2_auth_status=233".into(),
                    "hy2_auth_status_source=connect_ok_after_decode_auth_response".into(),
                    format!("hy2_udp_enabled={}", client.udp_enabled()),
                    format!("hy2_cc_rx={}", cc_rx_label(client.cc_rx())),
                ],
            ))
        }
        Err(e) => {
            let message = format!("{e}");
            write_manifest(
                cell_dir,
                "qpack-diag-hypothesis",
                "Hy2 认证握手失败；错误原文见 notes。S26 按源码级判定（B-3）归类",
                &[
                    (
                        "crates/nexus-outbound-hysteria2/src/auth.rs",
                        "decode_auth_response",
                        "认证响应解析",
                    ),
                    (
                        "crates/nexus-outbound-hysteria2/src/qpack.rs",
                        "1-200",
                        "QPACK 编解码",
                    ),
                ],
            )?;
            Ok(Outcome {
                verdict: Verdict::Blocked,
                error: Some(ErrorInfo {
                    class: ErrorClass::EEvidenceGap,
                    message: message.clone(),
                    first_failure_artifact: Some("pcap.pcap".into()),
                }),
                metrics: Metrics::default(),
                notes: vec![format!("hy2_error={message}")],
                proxy_json: None,
            })
        }
    }
}

fn write_manifest(
    cell_dir: &Path,
    tag: &str,
    reason: &str,
    refs: &[(&str, &str, &str)],
) -> Result<(), String> {
    let refs: Vec<serde_json::Value> = refs
        .iter()
        .map(|(file, lines, symbol)| {
            serde_json::json!({"file": file, "lines": lines, "symbol": symbol})
        })
        .collect();
    let manifest = serde_json::json!({
        "schema_version": 1,
        "tag": tag,
        "reason": reason,
        "code_refs": refs,
    });
    let bytes = serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?;
    util::atomic_write(&cell_dir.join("code-refs.json"), &bytes)
        .map_err(|e| format!("write code-refs.json: {e}"))
}

//! VLESS Vision（crate 直调）：外层 TLS + VisionWriter/VisionReader（S25）。

use std::io::Read;
use std::time::{Duration, Instant};

use nexus_outbound_vless::{
    VisionCommand, VisionReader, VisionWriter, VlessCommand, VlessFlow, VlessRequest, VlessTarget,
    VlessUuid,
};

use crate::Outcome;
use crate::config::{Cell, Credentials, InteropProbeConfig};
use crate::evidence::{ErrorClass, ErrorInfo, Metrics, Verdict};
use crate::util;

/// Vision 写块上限：Vision 帧 content_len 是 u16（<=65535）。
const VISION_CHUNK: usize = 32 * 1024;

pub fn run_cell(cfg: &InteropProbeConfig) -> Result<Outcome, String> {
    let Credentials::Vless(cred) = &cfg.credentials else {
        return Err("vision cell requires Vless credentials".into());
    };
    let uuid = VlessUuid::parse(&cred.uuid).map_err(|_| "invalid uuid")?;
    let timeout = Duration::from_millis(cfg.timeouts.cell_ms);
    let deadline = Instant::now() + timeout;
    let stream = crate::tls::connect(
        &cfg.reference.host,
        cfg.reference.port,
        &cfg.reference.server_name,
        cfg.tls.skip_cert_verify,
        &cfg.reference.alpn,
        timeout,
    )?;

    let len = match cfg.cell {
        Cell::Handshake => 1,
        Cell::TcpSmall => cfg.workload.small_bytes,
        other => return Err(format!("vision does not support cell {other:?}")),
    };
    let seed = util::cell_seed(cfg.protocol.label(), cfg.variant.label(), cfg.cell.label());
    let payload = util::payload_with_seed(seed, len);

    let mut conn = nexus_outbound_vless::VlessConn::new(stream);
    conn.handshake(&VlessRequest {
        uuid,
        flow: VlessFlow::XtlsRprxVision,
        command: VlessCommand::Tcp,
        port: cfg.target.port,
        target: Some(VlessTarget::Ipv4(std::net::Ipv4Addr::LOCALHOST)),
    })
    .map_err(|e| format!("vless vision handshake: {e}"))?;

    let mut writer = VisionWriter::new(*uuid.as_bytes(), false, seed);
    let first = &payload[..payload.len().min(VISION_CHUNK)];
    let framed = writer.write_chunk(first);
    crate::tls::write_all(&mut conn, &framed)?;
    let mut pos = first.len();
    while pos < payload.len() {
        let end = (pos + VISION_CHUNK).min(payload.len());
        let chunk = writer.write_chunk(&payload[pos..end]);
        crate::tls::write_all(&mut conn, &chunk)?;
        pos = end;
    }

    let mut reader = VisionReader::new();
    let mut got = Vec::with_capacity(payload.len());
    let mut command_log = Vec::new();
    let mut raw_tail = false;
    while got.len() < payload.len() {
        if reader.is_ended() || raw_tail {
            let mut buf = [0u8; 8192];
            let want = (payload.len() - got.len()).min(buf.len());
            match conn.read(&mut buf[..want]) {
                Ok(0) => break,
                Ok(n) => got.extend_from_slice(&buf[..n]),
                Err(e) => {
                    return Ok(Outcome::fail(
                        ErrorClass::ENexusTransport,
                        format!("vision raw read: {e}"),
                        Metrics::default(),
                    ));
                }
            }
            raw_tail = true;
            continue;
        }
        match reader.read_frame(&mut conn, uuid.as_bytes()) {
            Ok((cmd, content)) => {
                command_log.push(match cmd {
                    VisionCommand::Continue => "continue".to_string(),
                    VisionCommand::End => "end".to_string(),
                    VisionCommand::Direct => "direct".to_string(),
                });
                got.extend_from_slice(&content);
                if matches!(cmd, VisionCommand::End | VisionCommand::Direct) {
                    raw_tail = true;
                }
            }
            Err(e) => {
                return Ok(Outcome::fail(
                    ErrorClass::ENexusCodec,
                    format!("vision frame read: {e}; commands={command_log:?}"),
                    Metrics::default(),
                ));
            }
        }
        if Instant::now() >= deadline {
            break;
        }
    }

    let echo_ok = got == payload;
    let metrics = Metrics {
        bytes_up: payload.len() as u64,
        bytes_down: got.len() as u64,
        sha256_up: util::sha256_hex(&payload),
        sha256_down: util::sha256_hex(&got),
        ..Metrics::default()
    };
    let mut notes = vec![format!("vision_commands={command_log:?}")];
    if !echo_ok {
        notes.push(format!(
            "vision echo mismatch: sent={} got={}",
            payload.len(),
            got.len()
        ));
        return Ok(Outcome {
            verdict: Verdict::Fail,
            error: Some(ErrorInfo {
                class: ErrorClass::ENexusCodec,
                message: "vision roundtrip mismatch".into(),
                first_failure_artifact: Some("pcap.pcap".into()),
            }),
            metrics,
            notes,
            proxy_json: None,
        });
    }
    Ok(Outcome {
        verdict: Verdict::Pass,
        error: None,
        metrics,
        notes,
        proxy_json: None,
    })
}

//! 数据面管线（PRODUCT §12.40）：把 firewall / QoS / compression / fragmentation 六个骨架
//! 串成 VirtualSubnetTunnel 收发路径上的每包门控/记账/压缩/分片环节。
//!
//! 核心不变量：未启用管线时，本模块不参与，wire 字节与冻结前逐字节一致。
//! 激活后数据帧以魔数 `NXP1` 开头，与 legacy `src->dst:` / `hs:` / `ph:` / `pa:` 帧区分。
//!
//! 发送序：firewall 出向 → qos 出向 → compression → fragmentation → carrier。
//! 接收序：重组 → 解压 → firewall 入向（对称）→ qos 入向 → wire 记账 → legacy 帧交付。

use std::time::Duration;

use crate::ConnectivityError;
use crate::compression::{CompressedBlock, CompressionCodec, CompressionConfig};
use crate::firewall::{FirewallEngine, PacketContext, Protocol};
use crate::fragmentation::{Fragment, FragmentConfig, Fragmenter, ReassembleOutcome, Reassembler};
use crate::qos::{QosConfig, QosController};
use crate::virtual_subnet::TunnelFrameHeader;

/// 管线单元 wire 魔数（4 字节）。
const PIPELINE_MAGIC: &[u8; 4] = b"NXP1";
/// 管线 wire 版本。
const PIPELINE_VER: u8 = 1;
/// kind: 整块（未分片）。
const KIND_WHOLE: u8 = 1;
/// kind: 分片。
const KIND_FRAGMENT: u8 = 2;
/// 固定头长度：magic(4) + ver(1) + kind(1)。
const HEADER_LEN: usize = 6;

/// 数据面管线配置（未设置任何环节 = 完全透传，与今日行为逐字节一致）。
pub struct DataplanePipelineConfig {
    /// 出向+入向包过滤门控（对称决策）。
    pub firewall: Option<FirewallEngine>,
    /// 出向/入向带宽门控（令牌桶）。
    pub qos: Option<QosConfig>,
    /// 载荷压缩。
    pub compression: Option<CompressionConfig>,
    /// MTU 分片（None = 不分片）。
    pub fragmentation: Option<FragmentConfig>,
    /// 默认用于构造 PacketContext 的协议（无真实 IP 头解析）。
    pub default_proto: Protocol,
    /// 默认源端口。
    pub default_src_port: u16,
    /// 默认目的端口。
    pub default_dst_port: u16,
}

impl Default for DataplanePipelineConfig {
    fn default() -> Self {
        Self {
            firewall: None,
            qos: None,
            compression: None,
            fragmentation: None,
            default_proto: Protocol::Tcp,
            default_src_port: 0,
            default_dst_port: 0,
        }
    }
}

impl DataplanePipelineConfig {
    /// 空配置（全 None，透传）。
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }
}

/// 管线只读统计快照（纯计数/聚合，热路径无 per-frame 日志）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PipelineStats {
    /// 被防火墙丢弃的包数。
    pub firewall_dropped: u64,
    /// 被 QoS 丢弃的字节数。
    pub qos_dropped: u64,
    /// 已发送的分片数。
    pub fragments_sent: u64,
    /// 压缩块数。
    pub compression_blocks: u64,
    /// 发送侧累计发送 wire 字节。
    pub wire_bytes_sent: u64,
    /// 接收侧累计收到 wire 字节。
    pub wire_bytes_received: u64,
}

/// 发送侧处理结果。
#[derive(Debug)]
pub(crate) enum EgressOutcome {
    /// 被防火墙丢弃。
    DroppedFirewall,
    /// 被 QoS 丢弃。
    DroppedQos,
    /// 产生若干管线 wire 单元，交 carrier 发送。
    Send(Vec<Vec<u8>>),
}

/// 接收侧处理结果。
#[derive(Debug)]
pub(crate) enum IngressOutcome {
    /// 被门控丢弃（不交付 VPI）。
    Drop,
    /// 分片尚未收齐（不交付）。
    NeedMore,
    /// 还原出 legacy inner 帧，交既有解封装/转发逻辑。
    Deliver(Vec<u8>),
}

/// 管线运行时状态（由 VirtualSubnetTunnel 持有，经 `&mut self` 访问）。
pub(crate) struct DataplanePipeline {
    firewall: Option<FirewallEngine>,
    qos: Option<QosController>,
    compression: Option<CompressionCodec>,
    fragmenter: Option<Fragmenter>,
    frag_max: usize,
    reassembler: Reassembler,
    clock_now: Duration,
    next_packet_id: u64,
    default_proto: Protocol,
    default_src_port: u16,
    default_dst_port: u16,
    firewall_dropped: u64,
    qos_dropped: u64,
    fragments_sent: u64,
    wire_bytes_sent: u64,
    wire_bytes_received: u64,
}

impl DataplanePipeline {
    /// 用配置构造管线运行时。
    #[must_use]
    pub(crate) fn new(cfg: DataplanePipelineConfig) -> Self {
        let default_frag =
            FragmentConfig::new(1024, 65536, 10000).expect("valid default fragment config");
        let frag_max = cfg
            .fragmentation
            .as_ref()
            .map_or(usize::MAX, |fc| fc.max_fragment_size());
        let (fragmenter, reassembler) = match cfg.fragmentation {
            Some(fc) => (Some(Fragmenter::new(fc)), Reassembler::new(fc)),
            None => (None, Reassembler::new(default_frag)),
        };
        Self {
            firewall: cfg.firewall,
            qos: cfg.qos.as_ref().map(QosController::new),
            compression: cfg.compression.map(CompressionCodec::new),
            fragmenter,
            frag_max,
            reassembler,
            clock_now: Duration::ZERO,
            next_packet_id: 1,
            default_proto: cfg.default_proto,
            default_src_port: cfg.default_src_port,
            default_dst_port: cfg.default_dst_port,
            firewall_dropped: 0,
            qos_dropped: 0,
            fragments_sent: 0,
            wire_bytes_sent: 0,
            wire_bytes_received: 0,
        }
    }

    /// 注入逻辑时钟（QoS 确定性推进）。
    pub(crate) fn set_clock(&mut self, now: Duration) {
        self.clock_now = now;
    }

    /// 调整 PacketContext 默认协议/端口（E4 中用于切换命中/未命中防火墙规则的流）。
    pub(crate) fn set_defaults(&mut self, proto: Protocol, src_port: u16, dst_port: u16) {
        self.default_proto = proto;
        self.default_src_port = src_port;
        self.default_dst_port = dst_port;
    }

    /// 只读统计快照。
    #[must_use]
    pub(crate) fn stats(&self) -> PipelineStats {
        PipelineStats {
            firewall_dropped: self.firewall_dropped,
            qos_dropped: self.qos_dropped,
            fragments_sent: self.fragments_sent,
            compression_blocks: self.compression.as_ref().map_or(0, |c| c.stats().blocks()),
            wire_bytes_sent: self.wire_bytes_sent,
            wire_bytes_received: self.wire_bytes_received,
        }
    }

    /// 发送路径：门控 + 压缩 + 分片，产出 wire 单元。
    pub(crate) fn egress(
        &mut self,
        inner: &[u8],
        src_vip: &str,
        dst_vip: &str,
        tag: &str,
    ) -> Result<EgressOutcome, ConnectivityError> {
        // 1. firewall 出向判定（对称）。
        if let Some(engine) = &self.firewall {
            let ctxt = PacketContext::transport(
                src_vip,
                dst_vip,
                Some(self.default_src_port),
                Some(self.default_dst_port),
                self.default_proto,
            );
            if !engine.evaluate(&ctxt).is_allow() {
                self.firewall_dropped += 1;
                return Ok(EgressOutcome::DroppedFirewall);
            }
        }
        // 2. qos 出向门控。
        if let Some(q) = &mut self.qos {
            if !q.try_egress(tag, inner.len() as u64, self.clock_now) {
                self.qos_dropped += inner.len() as u64;
                return Ok(EgressOutcome::DroppedQos);
            }
        }
        // 3. compression。
        let block_wire: Vec<u8> = if let Some(codec) = &mut self.compression {
            let block = codec.encode(inner);
            serialize_block(&block)
        } else {
            inner.to_vec()
        };
        // 4. fragmentation。
        let units: Vec<Vec<u8>> = if let Some(frag) = &self.fragmenter {
            let packet_id = self.next_packet_id;
            self.next_packet_id += 1;
            let frags = frag.fragment(&block_wire, packet_id);
            self.fragments_sent += frags.len() as u64;
            frags
                .into_iter()
                .map(|f| {
                    let mut unit = Vec::with_capacity(HEADER_LEN + 8 + 2 + 2 + f.payload_len());
                    unit.extend_from_slice(PIPELINE_MAGIC);
                    unit.push(PIPELINE_VER);
                    unit.push(KIND_FRAGMENT);
                    unit.extend_from_slice(&f.packet_id().to_be_bytes());
                    unit.extend_from_slice(&f.index().to_be_bytes());
                    unit.extend_from_slice(&f.total().to_be_bytes());
                    unit.extend(f.into_payload());
                    unit
                })
                .collect()
        } else {
            let mut unit = Vec::with_capacity(HEADER_LEN + block_wire.len());
            unit.extend_from_slice(PIPELINE_MAGIC);
            unit.push(PIPELINE_VER);
            unit.push(KIND_WHOLE);
            unit.extend_from_slice(&block_wire);
            vec![unit]
        };
        let total: u64 = units.iter().map(|u| u.len() as u64).sum();
        self.wire_bytes_sent += total;
        Ok(EgressOutcome::Send(units))
    }

    /// 接收路径：重组 + 解压 + 门控 + 记账，还原 legacy inner 帧。
    pub(crate) fn ingress(
        &mut self,
        wire: &[u8],
        tag: &str,
    ) -> Result<IngressOutcome, ConnectivityError> {
        // 周期回收超时的重组上下文（§12.40）。
        self.reassembler.gc(self.clock_now.as_millis() as u64);
        if wire.len() < HEADER_LEN {
            return Ok(IngressOutcome::NeedMore);
        }
        let kind = wire[5];
        let block_wire: Vec<u8> = match kind {
            KIND_WHOLE => wire[HEADER_LEN..].to_vec(),
            KIND_FRAGMENT => {
                if wire.len() < HEADER_LEN + 8 + 2 + 2 {
                    return Ok(IngressOutcome::NeedMore);
                }
                let packet_id = u64::from_be_bytes(wire[6..14].try_into().expect("8 bytes"));
                let index = u16::from_be_bytes(wire[14..16].try_into().expect("2 bytes"));
                let total = u16::from_be_bytes(wire[16..18].try_into().expect("2 bytes"));
                let payload = wire[18..].to_vec();
                let frag = Fragment::new(packet_id, index, total, payload, self.frag_max).map_err(
                    |e| ConnectivityError::Invalid {
                        message: format!("PIPELINE_FRAGMENT: {e}"),
                    },
                )?;
                match self
                    .reassembler
                    .push(frag, self.clock_now.as_millis() as u64)
                    .map_err(|e| ConnectivityError::Invalid {
                        message: format!("PIPELINE_REASSEMBLE: {e}"),
                    })? {
                    ReassembleOutcome::Waiting { .. } => return Ok(IngressOutcome::NeedMore),
                    ReassembleOutcome::Complete { data } => data,
                }
            }
            other => {
                return Err(ConnectivityError::Invalid {
                    message: format!("PIPELINE_UNKNOWN_KIND: {other}"),
                });
            }
        };
        let block_wire_len = block_wire.len() as u64;
        // 解压（无压缩时 block_wire 即 inner）。
        let inner: Vec<u8> = if let Some(codec) = &mut self.compression {
            let block = deserialize_block(&block_wire)?;
            codec
                .decode(block)
                .map_err(|e| ConnectivityError::Invalid {
                    message: format!("PIPELINE_DECOMPRESS: {e}"),
                })?
        } else {
            block_wire
        };
        // 入向 firewall（对称）：从 inner tunnel header 取 src/dst。
        // 不可解析的 inner 帧按 fail-closed 丢弃（不静默放行畸形帧）。
        if let Some(engine) = &self.firewall {
            match TunnelFrameHeader::deserialize(&inner) {
                Some((header, _)) => {
                    let ctxt = PacketContext::transport(
                        &header.src_virtual_ip,
                        &header.dst_virtual_ip,
                        Some(self.default_src_port),
                        Some(self.default_dst_port),
                        self.default_proto,
                    );
                    if !engine.evaluate(&ctxt).is_allow() {
                        self.firewall_dropped += 1;
                        return Ok(IngressOutcome::Drop);
                    }
                }
                None => {
                    self.firewall_dropped += 1;
                    return Ok(IngressOutcome::Drop);
                }
            }
        }
        // 入向 qos。
        if let Some(q) = &mut self.qos {
            if !q.try_ingress(tag, block_wire_len, self.clock_now) {
                self.qos_dropped += block_wire_len;
                return Ok(IngressOutcome::Drop);
            }
        }
        self.wire_bytes_received += wire.len() as u64;
        Ok(IngressOutcome::Deliver(inner))
    }
}

/// 判断一帧是否为管线单元（以魔数开头）。
#[must_use]
pub(crate) fn is_pipeline_unit(data: &[u8]) -> bool {
    data.len() >= HEADER_LEN && &data[..4] == PIPELINE_MAGIC
}

/// 序列化一个压缩块为 wire 字节：tag(1) | orig_len(4 BE) | compressed(1) | payload。
pub(crate) fn serialize_block(block: &CompressedBlock) -> Vec<u8> {
    let mut out = Vec::with_capacity(6 + block.payload_len());
    out.push(block.algorithm_tag());
    out.extend_from_slice(&(block.original_len() as u32).to_be_bytes());
    out.push(block.is_compressed() as u8);
    out.extend_from_slice(block.payload());
    out
}

/// 从 wire 字节反序列化一个压缩块。
pub(crate) fn deserialize_block(wire: &[u8]) -> Result<CompressedBlock, ConnectivityError> {
    if wire.len() < 6 {
        return Err(ConnectivityError::Invalid {
            message: "PIPELINE_BLOCK_TRUNCATED".to_string(),
        });
    }
    let tag = wire[0];
    let orig_len = u32::from_be_bytes(wire[1..5].try_into().expect("4 bytes")) as usize;
    let compressed = wire[6 - 1] != 0;
    let payload = wire[6..].to_vec();
    Ok(CompressedBlock::from_parts(
        tag, orig_len, compressed, payload,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compression::{CompressionAlgorithm, CompressionConfig};
    use crate::firewall::{FirewallAction, FirewallConfig, FirewallEngine, Protocol};

    fn inner_frame(src: &str, dst: &str, payload: &[u8]) -> Vec<u8> {
        let mut h = format!("{}->{}:", src, dst).into_bytes();
        h.extend_from_slice(payload);
        h
    }

    #[test]
    fn zero_config_egress_ingress_is_byte_identical_passthrough() {
        let mut p = DataplanePipeline::new(DataplanePipelineConfig::empty());
        let inner = inner_frame("10.0.0.1", "10.0.0.2", &[0xDE, 0xAD, 0xBE, 0xEF]);
        let units = match p.egress(&inner, "10.0.0.1", "10.0.0.2", "peer") {
            Ok(EgressOutcome::Send(u)) => u,
            other => panic!("expected Send, got {:?}", other),
        };
        assert_eq!(units.len(), 1);
        let wire = &units[0];
        assert!(is_pipeline_unit(wire));
        match p.ingress(wire, "peer") {
            Ok(IngressOutcome::Deliver(back)) => assert_eq!(back, inner),
            other => panic!("expected Deliver, got {:?}", other),
        }
    }

    #[test]
    fn unknown_kind_returns_structured_err() {
        let mut p = DataplanePipeline::new(DataplanePipelineConfig::empty());
        let bad: Vec<u8> = vec![b'N', b'X', b'P', b'1', 1, 99, 0xAA, 0xBB];
        let err = p.ingress(&bad, "peer").unwrap_err();
        let ConnectivityError::Invalid { message } = err else {
            panic!("expected Invalid, got {:?}", err);
        };
        assert!(message.contains("PIPELINE_UNKNOWN_KIND"), "got {}", message);
    }

    #[test]
    fn truncated_wire_below_header_len_is_need_more() {
        let mut p = DataplanePipeline::new(DataplanePipelineConfig::empty());
        let short: Vec<u8> = vec![b'N', b'X', b'P', b'1'];
        assert!(matches!(
            p.ingress(&short, "peer"),
            Ok(IngressOutcome::NeedMore)
        ));
    }

    #[test]
    fn decompress_failure_returns_structured_err() {
        let mut cfg = DataplanePipelineConfig::empty();
        cfg.compression = Some(CompressionConfig::new(CompressionAlgorithm::Gzip, 6, 1).unwrap());
        let mut p = DataplanePipeline::new(cfg);
        // Build a whole unit whose block_wire is garbage (not a valid gzip block).
        let mut wire = Vec::new();
        wire.extend_from_slice(PIPELINE_MAGIC);
        wire.push(PIPELINE_VER);
        wire.push(KIND_WHOLE);
        wire.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // garbage block
        let err = p.ingress(&wire, "peer").unwrap_err();
        let ConnectivityError::Invalid { message } = err else {
            panic!("expected Invalid, got {:?}", err);
        };
        assert!(message.contains("PIPELINE_DECOMPRESS"), "got {}", message);
    }

    #[test]
    fn egress_firewall_drop_counts_and_does_not_send() {
        let rule = crate::firewall::FirewallRule::new(
            FirewallAction::Deny,
            None::<String>,
            None::<String>,
            None,
            Some(crate::firewall::PortRange::new(80, 80).unwrap()),
            Some(Protocol::Tcp),
        )
        .unwrap();
        let fw =
            FirewallEngine::new(&FirewallConfig::new(FirewallAction::Allow, vec![rule]).unwrap())
                .unwrap();
        let mut cfg = DataplanePipelineConfig::empty();
        cfg.firewall = Some(fw);
        cfg.default_dst_port = 80;
        let mut p = DataplanePipeline::new(cfg);
        let inner = inner_frame("10.0.0.1", "10.0.0.2", b"x");
        assert!(matches!(
            p.egress(&inner, "10.0.0.1", "10.0.0.2", "peer"),
            Ok(EgressOutcome::DroppedFirewall)
        ));
        assert_eq!(p.stats().firewall_dropped, 1);
    }

    #[test]
    fn ingress_firewall_drops_unparseable_inner_fail_closed() {
        // default-allow engine, but inner is garbage (no tunnel header) => fail-closed Drop.
        let fw = FirewallEngine::new(&FirewallConfig::new(FirewallAction::Allow, vec![]).unwrap())
            .unwrap();
        let mut cfg = DataplanePipelineConfig::empty();
        cfg.firewall = Some(fw);
        let mut p = DataplanePipeline::new(cfg);
        // Build a whole unit wrapping garbage inner.
        let mut wire = Vec::new();
        wire.extend_from_slice(PIPELINE_MAGIC);
        wire.push(PIPELINE_VER);
        wire.push(KIND_WHOLE);
        wire.extend_from_slice(&[0x00, 0x01, 0x02]); // not src->dst:
        assert!(matches!(p.ingress(&wire, "peer"), Ok(IngressOutcome::Drop)));
        assert_eq!(p.stats().firewall_dropped, 1);
    }
}

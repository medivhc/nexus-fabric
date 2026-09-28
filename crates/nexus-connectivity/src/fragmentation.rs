//! 分片传输（大报文分片 + 重组 + 超时清理，内存骨架，纯逻辑）。
//!
//! 本模块是 delivery 层共享底座的分片传输骨架：
//! - **分片**：`Fragmenter::fragment(data, packet_id)` 把 `data` 按
//!   `max_fragment_size` 切成有序 `Fragment { packet_id, index, total, payload }`；
//!   空数据返回单个空载荷分片（total=1），保持"一个报文至少一片"语义；
//! - **重组**：`Reassembler::push(fragment, now_ms)` 按 `packet_id` 聚合；
//!   收齐 `total` 片后按 `index` 序拼接返回 `Complete { data }`，否则 `Waiting { .. }`；
//!   重复片幂等（同 packet_id 同 index 重复到达不重复计入字节）；
//! - **超时清理**：`Reassembler::gc(now_ms)` 丢弃
//!   `now_ms - inserted_at_ms > reassembly_timeout_ms` 的未完成重组上下文，返回丢弃个数；
//! - **缓冲上限**：所有未完成上下文累计字节不得超过 `max_reassembly_buffer`，
//!   超限的 `push` 返回 `ReassemblyBufferExceeded`（避免单片洪水 OOM）。
//!
//! 边界（PRODUCT §12.34 冻结）：
//! - 纯内存、纯同步、纯逻辑骨架；时间由调用方以 `now_ms: u64` 显式注入，模块不读墙钟；
//! - 不做真实网络收发、不做丢包重传（重传由上层 QoS/重试负责）；
//! - 字节计数用 saturating。
//!
//! TODO（真实传输集成，非本骨架范围）：
//! - 分片序列号抗重放（当前仅按 index 拼接，不防伪造）；
//! - 重组乱序窗口、部分到达后的选择性 ACK 与重传请求。
//!
//! 错误面独立：`FragmentationError` 是本模块自有类型化 enum，不以 panic / 日志代替。

use std::collections::HashMap;
use std::fmt;

// ---------- 错误 ----------

/// 分片/重组相关结构化错误（delivery 层自有错误面，类型化）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FragmentationError {
    /// 配置字段非法。
    InvalidConfig {
        /// 非法字段名（人可读）。
        field: String,
    },
    /// 单片载荷超过 `max_fragment_size`（Fragmenter 不应产生，对端异常帧会触发）。
    FragmentTooLarge {
        /// 实际载荷长度。
        actual: usize,
        /// 上限。
        limit: usize,
    },
    /// 分片序号与 total 字段自相矛盾（index >= total，或 total=0）。
    InconsistentFragment {
        /// 人可读原因。
        reason: &'static str,
    },
    /// 同一 packet_id 的后续分片声称了不同的 total。
    TotalMismatch {
        /// 报文 ID。
        packet_id: u64,
        /// 首次见到的 total。
        expected: u16,
        /// 本次声称的 total。
        actual: u16,
    },
    /// 重组缓冲累计字节将超过 `max_reassembly_buffer`。
    ReassemblyBufferExceeded {
        /// 当前累计字节。
        current: usize,
        /// 上限。
        limit: usize,
    },
}

impl fmt::Display for FragmentationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig { field } => {
                write!(
                    f,
                    "FRAGMENT_INVALID_CONFIG: field {field:?} is out of range"
                )
            }
            Self::FragmentTooLarge { actual, limit } => {
                write!(f, "FRAGMENT_TOO_LARGE: actual={actual} limit={limit}")
            }
            Self::InconsistentFragment { reason } => {
                write!(f, "FRAGMENT_INCONSISTENT: {reason}")
            }
            Self::TotalMismatch {
                packet_id,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "FRAGMENT_TOTAL_MISMATCH: packet_id={packet_id} expected={expected} actual={actual}"
                )
            }
            Self::ReassemblyBufferExceeded { current, limit } => {
                write!(
                    f,
                    "FRAGMENT_REASSEMBLY_BUFFER_EXCEEDED: current={current} limit={limit}"
                )
            }
        }
    }
}

impl std::error::Error for FragmentationError {}

// ---------- 配置 ----------

/// 分片传输配置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentConfig {
    /// 单片最大载荷字节（不含分片头），必须 >= 1。
    max_fragment_size: usize,
    /// 所有未完成重组上下文的累计字节上限，必须 >= 1。
    max_reassembly_buffer: usize,
    /// 重组超时（毫秒）：某上下文首次插入后超过此时间仍未收齐即被 gc 丢弃，必须 > 0。
    reassembly_timeout_ms: u64,
}

impl FragmentConfig {
    /// 构造配置并校验：
    /// - `max_fragment_size >= 1`；`max_reassembly_buffer >= 1`；`reassembly_timeout_ms > 0`。
    pub fn new(
        max_fragment_size: usize,
        max_reassembly_buffer: usize,
        reassembly_timeout_ms: u64,
    ) -> Result<Self, FragmentationError> {
        if max_fragment_size < 1 {
            return Err(FragmentationError::InvalidConfig {
                field: "max_fragment_size".to_string(),
            });
        }
        if max_reassembly_buffer < 1 {
            return Err(FragmentationError::InvalidConfig {
                field: "max_reassembly_buffer".to_string(),
            });
        }
        if reassembly_timeout_ms == 0 {
            return Err(FragmentationError::InvalidConfig {
                field: "reassembly_timeout_ms".to_string(),
            });
        }
        Ok(Self {
            max_fragment_size,
            max_reassembly_buffer,
            reassembly_timeout_ms,
        })
    }

    /// 单片最大载荷字节。
    #[must_use]
    pub fn max_fragment_size(&self) -> usize {
        self.max_fragment_size
    }
}

// ---------- 分片 ----------

/// 一个数据分片。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    /// 所属报文 ID（同一原始报文的所有分片共享）。
    packet_id: u64,
    /// 本片序号（0 基）。
    index: u16,
    /// 总分片数（必须 >= 1，且 `index < total`）。
    total: u16,
    /// 本片载荷。
    payload: Vec<u8>,
}

impl Fragment {
    /// 构造并校验分片：`total >= 1`、`index < total`、`payload.len() <= max_fragment_size`。
    pub fn new(
        packet_id: u64,
        index: u16,
        total: u16,
        payload: Vec<u8>,
        max_fragment_size: usize,
    ) -> Result<Self, FragmentationError> {
        if total < 1 {
            return Err(FragmentationError::InconsistentFragment {
                reason: "total must be >= 1",
            });
        }
        if index >= total {
            return Err(FragmentationError::InconsistentFragment {
                reason: "index must be < total",
            });
        }
        if payload.len() > max_fragment_size {
            return Err(FragmentationError::FragmentTooLarge {
                actual: payload.len(),
                limit: max_fragment_size,
            });
        }
        Ok(Self {
            packet_id,
            index,
            total,
            payload,
        })
    }

    /// 报文 ID。
    #[must_use]
    pub fn packet_id(&self) -> u64 {
        self.packet_id
    }

    /// 本片序号。
    #[must_use]
    pub fn index(&self) -> u16 {
        self.index
    }

    /// 总分片数。
    #[must_use]
    pub fn total(&self) -> u16 {
        self.total
    }

    /// 载荷长度。
    #[must_use]
    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }

    /// 消费并取回载荷字节（数据面管线 wire 序列化用，PRODUCT §12.40）。
    #[must_use]
    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }
}

// ---------- 分片器 ----------

/// 分片器：把原始字节流切成有序分片序列。
pub struct Fragmenter {
    /// 配置。
    config: FragmentConfig,
}

impl Fragmenter {
    /// 用配置构造分片器。
    #[must_use]
    pub fn new(config: FragmentConfig) -> Self {
        Self { config }
    }

    /// 把 `data` 切成总分片数 `ceil(data.len / max_fragment_size)` 的有序分片。
    ///
    /// 空 `data` 也返回 1 片（total=1，index=0，空载荷），保证对端一定收到一个可完成的报文。
    pub fn fragment(&self, data: &[u8], packet_id: u64) -> Vec<Fragment> {
        let mfs = self.config.max_fragment_size;
        let total = if data.is_empty() {
            1u16
        } else {
            let n = data.len().div_ceil(mfs);
            // u16 上限保护：超大报文在骨架内截断 total 到 u16::MAX（真实 MTU 远小于此）。
            u16::try_from(n).unwrap_or(u16::MAX)
        };
        let mut out = Vec::with_capacity(usize::from(total));
        let mut idx: u16 = 0;
        let mut offset = 0;
        loop {
            if idx >= total {
                break;
            }
            let end = (offset + mfs).min(data.len());
            let chunk = if offset >= end {
                Vec::new()
            } else {
                data[offset..end].to_vec()
            };
            // 分片构造必然合法（mfs 自洽、index<total），unwrap 在数学上不可达。
            let frag = Fragment::new(packet_id, idx, total, chunk, mfs)
                .expect("fragment built by Fragmenter is always valid");
            out.push(frag);
            offset = end;
            idx += 1;
            if data.is_empty() {
                break; // 空数据只产 1 片。
            }
        }
        out
    }
}

// ---------- 重组 ----------

/// 重组结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReassembleOutcome {
    /// 尚未收齐：当前已到 `received` 片（去重后），共需 `total` 片。
    Waiting {
        /// 已收到（去重）的片数。
        received: u16,
        /// 该报文总分片数。
        total: u16,
    },
    /// 已收齐并按序拼接完成。
    Complete {
        /// 重组后的原始字节。
        data: Vec<u8>,
    },
}

impl ReassembleOutcome {
    /// 返回稳定字符串标签（"waiting"/"complete"）。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Waiting { .. } => "waiting",
            Self::Complete { .. } => "complete",
        }
    }
}

impl fmt::Display for ReassembleOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 单个报文的重组状态。
struct Assembly {
    /// 按 index 槽位存放已到载荷；`None` 表示未到。
    slots: Vec<Option<Vec<u8>>>,
    /// 首次插入的逻辑毫秒时间戳（用于超时 gc）。
    inserted_at_ms: u64,
    /// 已累计载荷字节（用于缓冲上限记账）。
    buffered_bytes: usize,
}

/// 重组器：按 packet_id 聚合分片，超时清理未完成上下文，纯内存纯逻辑。
pub struct Reassembler {
    /// 配置。
    config: FragmentConfig,
    /// packet_id -> 重组上下文。
    table: HashMap<u64, Assembly>,
    /// 当前所有未完成上下文累计字节。
    buffered_total: usize,
}

impl Reassembler {
    /// 用配置构造空重组器。
    #[must_use]
    pub fn new(config: FragmentConfig) -> Self {
        Self {
            config,
            table: HashMap::new(),
            buffered_total: 0,
        }
    }

    /// 当前未完成上下文个数。
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.table.len()
    }

    /// 当前累计缓冲字节。
    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        self.buffered_total
    }

    /// 推入一个分片（逻辑毫秒 `now_ms`）。
    ///
    /// - 首次见到该 `packet_id`：按 `total` 建槽位，记账；
    /// - 后续片：`total` 必须与首次一致（否则 `TotalMismatch`）；
    /// - 重复片（同 index 已有载荷）：幂等，不重复计字节；
    /// - 收齐所有槽位 -> 拼接返回 `Complete` 并释放该上下文；
    /// - 否则 `Waiting { received, total }`。
    pub fn push(
        &mut self,
        fragment: Fragment,
        now_ms: u64,
    ) -> Result<ReassembleOutcome, FragmentationError> {
        let packet_id = fragment.packet_id;
        let total = usize::from(fragment.total);
        let index = usize::from(fragment.index);

        let entry = match self.table.get_mut(&packet_id) {
            Some(existing) => {
                // total 一致性。
                if existing.slots.len() != total {
                    return Err(FragmentationError::TotalMismatch {
                        packet_id,
                        expected: u16::try_from(existing.slots.len()).unwrap_or(u16::MAX),
                        actual: fragment.total,
                    });
                }
                existing
            }
            None => {
                // 缓冲上限预检：新上下文至少要放这一片。
                let would = self.buffered_total.saturating_add(fragment.payload.len());
                if would > self.config.max_reassembly_buffer {
                    return Err(FragmentationError::ReassemblyBufferExceeded {
                        current: self.buffered_total,
                        limit: self.config.max_reassembly_buffer,
                    });
                }
                self.table.insert(
                    packet_id,
                    Assembly {
                        slots: (0..total).map(|_| None).collect(),
                        inserted_at_ms: now_ms,
                        buffered_bytes: 0,
                    },
                );
                self.table.get_mut(&packet_id).expect("just inserted")
            }
        };

        // index 越界防护（Fragment::new 已挡 index<total，这里双保险）。
        if index >= entry.slots.len() {
            return Err(FragmentationError::InconsistentFragment {
                reason: "fragment index out of range for this packet",
            });
        }

        let payload_len = fragment.payload.len();
        let slot = &mut entry.slots[index];
        if slot.is_none() {
            // 首次到达该 index：记账。
            let would = self.buffered_total.saturating_add(payload_len);
            if would > self.config.max_reassembly_buffer {
                return Err(FragmentationError::ReassemblyBufferExceeded {
                    current: self.buffered_total,
                    limit: self.config.max_reassembly_buffer,
                });
            }
            entry.buffered_bytes = entry.buffered_bytes.saturating_add(payload_len);
            self.buffered_total = would;
            *slot = Some(fragment.payload);
        }
        // 重复片：slot 已有值，幂等丢弃，不重复记账。

        let received = entry.slots.iter().filter(|s| s.is_some()).count();
        if received == total {
            // 收齐：拼接并释放上下文。
            let assembly = self
                .table
                .remove(&packet_id)
                .expect("present because we just mutated it");
            self.buffered_total = self.buffered_total.saturating_sub(assembly.buffered_bytes);
            let mut data = Vec::with_capacity(assembly.buffered_bytes);
            for s in assembly.slots {
                data.extend(s.expect("slot present when complete"));
            }
            return Ok(ReassembleOutcome::Complete { data });
        }

        Ok(ReassembleOutcome::Waiting {
            received: u16::try_from(received).unwrap_or(u16::MAX),
            total: fragment.total,
        })
    }

    /// 清理超时未收齐的上下文：`now_ms - inserted_at_ms > reassembly_timeout_ms`。
    ///
    /// 返回被丢弃的上下文个数；丢弃时释放其缓冲字节。
    pub fn gc(&mut self, now_ms: u64) -> usize {
        let timeout = self.config.reassembly_timeout_ms;
        let expired: Vec<u64> = self
            .table
            .iter()
            .filter_map(|(id, a)| {
                if now_ms.saturating_sub(a.inserted_at_ms) > timeout {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect();
        let n = expired.len();
        for id in expired {
            if let Some(a) = self.table.remove(&id) {
                self.buffered_total = self.buffered_total.saturating_sub(a.buffered_bytes);
            }
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> FragmentConfig {
        FragmentConfig::new(64, 1024, 1000).expect("valid config")
    }

    #[test]
    fn fragment_splits_and_reassembles_roundtrip() {
        let f = Fragmenter::new(cfg());
        let data: Vec<u8> = (0..200u32).map(|i| (i % 256) as u8).collect();
        let frags = f.fragment(&data, 42);
        // 200 / 64 = 3.125 -> 4 片。
        assert_eq!(frags.len(), 4);
        assert_eq!(frags[0].total, 4);

        let mut r = Reassembler::new(cfg());
        for (i, fr) in frags.into_iter().enumerate() {
            let out = r.push(fr, 1000).expect("push ok");
            if i < 3 {
                assert_eq!(out.as_str(), "waiting");
            } else {
                match out {
                    ReassembleOutcome::Complete { data: back } => assert_eq!(back, data),
                    other => panic!("expected complete, got {other:?}"),
                }
            }
        }
        assert_eq!(r.pending_count(), 0);
        assert_eq!(r.buffered_bytes(), 0);
    }

    #[test]
    fn empty_data_yields_single_empty_fragment() {
        let f = Fragmenter::new(cfg());
        let frags = f.fragment(&[], 7);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].total, 1);
        assert_eq!(frags[0].payload_len(), 0);

        let mut r = Reassembler::new(cfg());
        let out = r.push(frags.into_iter().next().unwrap(), 0).expect("ok");
        match out {
            ReassembleOutcome::Complete { data } => assert!(data.is_empty()),
            other => panic!("expected complete empty, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_fragment_idempotent() {
        let f = Fragmenter::new(cfg());
        let frags = f.fragment(&[1u8; 100], 1);
        let mut r = Reassembler::new(cfg());
        // 先放第 0 片。
        r.push(frags[0].clone(), 0).expect("ok");
        let after_first = r.buffered_bytes();
        // 重复放第 0 片：不应重复计字节。
        r.push(frags[0].clone(), 0).expect("ok");
        assert_eq!(r.buffered_bytes(), after_first);
    }

    #[test]
    fn total_mismatch_rejected() {
        let mut r = Reassembler::new(cfg());
        let f1 = Fragment::new(9, 0, 2, vec![1u8; 10], 64).unwrap();
        r.push(f1, 0).unwrap();
        let bad = Fragment::new(9, 0, 3, vec![2u8; 10], 64).unwrap();
        assert!(matches!(
            r.push(bad, 0),
            Err(FragmentationError::TotalMismatch {
                packet_id: 9,
                expected: 2,
                actual: 3
            })
        ));
    }

    #[test]
    fn gc_drops_stale_contexts() {
        let f = Fragmenter::new(cfg());
        let frags = f.fragment(&[1u8; 200], 5);
        let mut r = Reassembler::new(cfg());
        // 只放第 0 片，不发完 -> 一直 Waiting。
        r.push(frags[0].clone(), 0).unwrap();
        assert_eq!(r.pending_count(), 1);
        // now=500 < timeout=1000 -> 不回收。
        assert_eq!(r.gc(500), 0);
        assert_eq!(r.pending_count(), 1);
        // now=1001 > timeout=1000 -> 回收。
        assert_eq!(r.gc(1001), 1);
        assert_eq!(r.pending_count(), 0);
        assert_eq!(r.buffered_bytes(), 0);
    }

    #[test]
    fn buffer_exceeded_rejects_push() {
        // 把缓冲上限调到 16 字节。
        let cfg = FragmentConfig::new(64, 16, 1000).unwrap();
        let mut r = Reassembler::new(cfg);
        let big = Fragment::new(1, 0, 2, vec![0u8; 20], 64).unwrap();
        let err = r.push(big, 0).unwrap_err();
        assert!(matches!(
            err,
            FragmentationError::ReassemblyBufferExceeded { limit: 16, .. }
        ));
    }

    #[test]
    fn fragment_validation_rejects_bad_shape() {
        assert!(Fragment::new(1, 0, 0, vec![], 64).is_err()); // total=0
        assert!(Fragment::new(1, 3, 2, vec![], 64).is_err()); // index>=total
        assert!(Fragment::new(1, 0, 1, vec![0u8; 100], 64).is_err()); // 超 mfs
    }

    #[test]
    fn invalid_config_rejected() {
        assert!(FragmentConfig::new(0, 1024, 1000).is_err());
        assert!(FragmentConfig::new(64, 0, 1000).is_err());
        assert!(FragmentConfig::new(64, 1024, 0).is_err());
    }

    #[test]
    fn outcome_as_str() {
        assert_eq!(
            ReassembleOutcome::Waiting {
                received: 1,
                total: 3
            }
            .as_str(),
            "waiting"
        );
        assert_eq!(
            ReassembleOutcome::Complete { data: vec![] }.as_str(),
            "complete"
        );
    }
}

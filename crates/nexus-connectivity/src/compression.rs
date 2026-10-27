//! 数据压缩（算法选择 + 自适应门控 + 帧头封装 + 压缩统计，内存骨架，纯逻辑）。
//!
//! 本模块是 v9 CLI 产品线运行时（frozen）的数据压缩：
//! - **算法选择**：`CompressionAlgorithm` 三态--`None`（不压缩）/ `Gzip` / `Lz4`；
//!   Gzip 经 flate2（rust_backend）、Lz4 经 lz4_flex 做真实编解码（PRODUCT §12.41）；
//! - **自适应门控**：`CompressionCodec::should_compress(data_len)` 在
//!   `algorithm != None` 且 `data_len >= min_original_bytes` 时才压缩；过小报文直接透传
//!   （避免元数据开销超过收益）；
//! - **帧头**：`CompressedBlock` 携带 `algorithm_tag`（0=none/1=gzip/2=lz4）、
//!   `original_len`、`compressed` 标记与 `payload`；`encode`/`decode` 对称；
//! - **统计**：`CompressionStats` 累计 `original_total` / `compressed_total` / `blocks`，
//!   `ratio()` 返回 `1.0 - compressed/original`（未压缩块按 compressed==original 计入，
//!   不污染压缩率；不可压缩数据略膨胀时经 clamp 仍为 0）。
//!
//! 边界（PRODUCT §12.33/§12.41 冻结）：
//! - 纯内存、纯同步、纯逻辑；不读墙钟、不做真实 I/O；压缩库均为纯 Rust（rust_backend）；
//! - `CompressionCodec` 持有配置与统计，`encode`/`decode` 做真实 gzip/lz4；
//! - 统计用 saturating 累加，不溢出。
//!
//! 帧头仅 tag + len，不防伪（魔数/校验和留 TODO）。
//!
//! 错误面独立：`CompressionError` 是本模块自有类型化 enum，不以 panic / 日志代替。

use std::fmt;
use std::io::Write;

use flate2::Compression;
use flate2::read::GzDecoder;
use lz4_flex::block::{compress_prepend_size, decompress_size_prepended};

// ---------- 错误 ----------

/// 数据压缩相关结构化错误（delivery 层自有错误面，类型化）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompressionError {
    /// 配置字段非法。
    InvalidConfig {
        /// 非法字段名（人可读）。
        field: String,
    },
    /// 帧头算法标签未知（decode 时收到未识别 tag）。
    UnknownAlgorithmTag {
        /// 未识别的标签字节。
        tag: u8,
    },
    /// 算法与帧头标记不一致（如声称已压缩但 compressed=false，或 tag 与 payload 不匹配）。
    InconsistentBlock {
        /// 人可读原因。
        reason: &'static str,
    },
}

impl fmt::Display for CompressionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig { field } => {
                write!(
                    f,
                    "COMPRESSION_INVALID_CONFIG: field {field:?} is out of range"
                )
            }
            Self::UnknownAlgorithmTag { tag } => {
                write!(f, "COMPRESSION_UNKNOWN_ALGORITHM_TAG: tag={tag}")
            }
            Self::InconsistentBlock { reason } => {
                write!(f, "COMPRESSION_INCONSISTENT_BLOCK: {reason}")
            }
        }
    }
}

impl std::error::Error for CompressionError {}

// ---------- 算法 ----------

/// 压缩算法选择。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionAlgorithm {
    /// 不压缩（透传）。
    None,
    /// gzip（骨架内为身份透传，真实实现 TODO）。
    Gzip,
    /// lz4（骨架内为身份透传，真实实现 TODO）。
    Lz4,
}

impl CompressionAlgorithm {
    /// 返回稳定字符串标签（"none"/"gzip"/"lz4"）。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Gzip => "gzip",
            Self::Lz4 => "lz4",
        }
    }

    /// 返回帧头标签字节（0/1/2），decode 时反查。
    #[must_use]
    pub const fn tag(&self) -> u8 {
        match self {
            Self::None => 0,
            Self::Gzip => 1,
            Self::Lz4 => 2,
        }
    }

    /// 从帧头标签字节反查算法；未知标签返回 `UnknownAlgorithmTag`。
    pub fn from_tag(tag: u8) -> Result<Self, CompressionError> {
        match tag {
            0 => Ok(Self::None),
            1 => Ok(Self::Gzip),
            2 => Ok(Self::Lz4),
            other => Err(CompressionError::UnknownAlgorithmTag { tag: other }),
        }
    }
}

impl fmt::Display for CompressionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------- 配置 ----------

/// 数据压缩配置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressionConfig {
    /// 选用算法（None 即全局关闭）。
    algorithm: CompressionAlgorithm,
    /// 压缩级别（0-9；骨架内仅记录，不参与计算）。
    level: u8,
    /// 原始字节数低于此值不压缩（自适应门控阈值），必须 >= 1。
    min_original_bytes: usize,
}

impl CompressionConfig {
    /// 构造配置并校验：
    /// - `level <= 9`；`min_original_bytes >= 1`。
    pub fn new(
        algorithm: CompressionAlgorithm,
        level: u8,
        min_original_bytes: usize,
    ) -> Result<Self, CompressionError> {
        if level > 9 {
            return Err(CompressionError::InvalidConfig {
                field: "level".to_string(),
            });
        }
        if min_original_bytes < 1 {
            return Err(CompressionError::InvalidConfig {
                field: "min_original_bytes".to_string(),
            });
        }
        Ok(Self {
            algorithm,
            level,
            min_original_bytes,
        })
    }

    /// 选用算法。
    #[must_use]
    pub fn algorithm(&self) -> CompressionAlgorithm {
        self.algorithm
    }

    /// 压缩级别。
    #[must_use]
    pub fn level(&self) -> u8 {
        self.level
    }

    /// 自适应门控阈值。
    #[must_use]
    pub fn min_original_bytes(&self) -> usize {
        self.min_original_bytes
    }
}

// ---------- 压缩块 ----------

/// 一帧压缩结果（帧头 + 载荷）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressedBlock {
    /// 算法标签字节（0/1/2，见 `CompressionAlgorithm::tag`）。
    algorithm_tag: u8,
    /// 压缩前原始字节数。
    original_len: usize,
    /// 实际是否做了压缩（None 算法或低于阈值透传时为 false）。
    compressed: bool,
    /// 载荷（骨架内：compressed=true 时为占位身份拷贝，真实压缩 TODO）。
    payload: Vec<u8>,
}

impl CompressedBlock {
    /// 从对端线上字节反序列化一帧（构造入口）。
    ///
    /// 与 `encode` 产出的内存块对称；`decode` 会再次校验 tag 与压缩一致性。
    #[must_use]
    pub fn from_parts(
        algorithm_tag: u8,
        original_len: usize,
        compressed: bool,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            algorithm_tag,
            original_len,
            compressed,
            payload,
        }
    }

    /// 算法标签。
    #[must_use]
    pub fn algorithm_tag(&self) -> u8 {
        self.algorithm_tag
    }

    /// 原始长度。
    #[must_use]
    pub fn original_len(&self) -> usize {
        self.original_len
    }

    /// 是否实际压缩。
    #[must_use]
    pub fn is_compressed(&self) -> bool {
        self.compressed
    }

    /// 载荷长度。
    #[must_use]
    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }

    /// 载荷字节（借用；数据面管线 wire 序列化用，PRODUCT §12.41）。
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// 消费并取回载荷字节。
    #[must_use]
    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }
}

// ---------- 统计 ----------

/// 压缩统计（累计值，saturating 累加）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CompressionStats {
    /// 累计原始字节。
    original_total: u64,
    /// 累计载荷字节（压缩后或透传）。
    compressed_total: u64,
    /// 累计处理块数。
    blocks: u64,
}

impl CompressionStats {
    /// 累加一帧的统计。
    fn record(&mut self, original_len: usize, payload_len: usize) {
        self.original_total = self
            .original_total
            .saturating_add(u64::try_from(original_len).unwrap_or(u64::MAX));
        self.compressed_total = self
            .compressed_total
            .saturating_add(u64::try_from(payload_len).unwrap_or(u64::MAX));
        self.blocks = self.blocks.saturating_add(1);
    }

    /// 累计原始字节。
    #[must_use]
    pub fn original_total(&self) -> u64 {
        self.original_total
    }

    /// 累计载荷字节。
    #[must_use]
    pub fn compressed_total(&self) -> u64 {
        self.compressed_total
    }

    /// 累计块数。
    #[must_use]
    pub fn blocks(&self) -> u64 {
        self.blocks
    }

    /// 压缩率 `1.0 - compressed/original`；原始为 0 时返回 0.0。
    /// 恒 <= 1.0；透传块因 compressed==original 不贡献压缩率。
    #[must_use]
    pub fn ratio(&self) -> f64 {
        if self.original_total == 0 {
            return 0.0;
        }
        let orig = self.original_total as f64;
        let comp = self.compressed_total as f64;
        (1.0 - comp / orig).clamp(0.0, 1.0)
    }
}

// ---------- 编解码器 ----------

/// 压缩编解码器：持有配置与统计，纯内存纯逻辑。
pub struct CompressionCodec {
    /// 配置。
    config: CompressionConfig,
    /// 累计统计。
    stats: CompressionStats,
}

impl CompressionCodec {
    /// 用配置构造编解码器；统计清零。
    #[must_use]
    pub fn new(config: CompressionConfig) -> Self {
        Self {
            config,
            stats: CompressionStats::default(),
        }
    }

    /// 自适应门控：`algorithm != None` 且 `data_len >= min_original_bytes` 才压缩。
    #[must_use]
    pub fn should_compress(&self, data_len: usize) -> bool {
        self.config.algorithm != CompressionAlgorithm::None
            && data_len >= self.config.min_original_bytes
    }

    /// 编码一帧。
    ///
    /// - 算法 None -> 标签 0、`compressed=false`、载荷原样；
    /// - 长度低于阈值 -> 标签仍记录所选算法、`compressed=false`、载荷原样（自适应透传）；
    /// - 否则 -> `compressed=true`，载荷为真实 gzip / lz4 压缩字节。
    pub fn encode(&mut self, data: &[u8]) -> CompressedBlock {
        let alg = self.config.algorithm;
        let should = self.should_compress(data.len());
        let block = if alg == CompressionAlgorithm::None {
            CompressedBlock {
                algorithm_tag: CompressionAlgorithm::None.tag(),
                original_len: data.len(),
                compressed: false,
                payload: data.to_vec(),
            }
        } else if should {
            let payload = match alg {
                CompressionAlgorithm::Gzip => gzip_compress(data, self.config.level),
                CompressionAlgorithm::Lz4 => compress_prepend_size(data),
                CompressionAlgorithm::None => data.to_vec(),
            };
            CompressedBlock {
                algorithm_tag: alg.tag(),
                original_len: data.len(),
                compressed: true,
                payload,
            }
        } else {
            // 低于阈值透传：仍记录所选算法标签，便于对端识别。
            CompressedBlock {
                algorithm_tag: alg.tag(),
                original_len: data.len(),
                compressed: false,
                payload: data.to_vec(),
            }
        };
        self.stats.record(block.original_len, block.payload.len());
        block
    }

    /// 解码一帧（与 `encode` 对称）。
    ///
    /// 校验：tag 必须可识别；`compressed=true` 时按所选算法真实解压出 `original_len`
    /// 字节，解失败（流损坏/长度不符）返回 `InconsistentBlock`。
    pub fn decode(&self, block: CompressedBlock) -> Result<Vec<u8>, CompressionError> {
        let alg = CompressionAlgorithm::from_tag(block.algorithm_tag)?;
        if !block.compressed {
            return Ok(block.payload);
        }
        let out = match alg {
            CompressionAlgorithm::Gzip => gzip_decompress(&block.payload)?,
            CompressionAlgorithm::Lz4 => {
                decompress_size_prepended(&block.payload).map_err(|_| {
                    CompressionError::InconsistentBlock {
                        reason: "lz4 decompress failed",
                    }
                })?
            }
            CompressionAlgorithm::None => {
                return Err(CompressionError::InconsistentBlock {
                    reason: "compressed block with none algorithm",
                });
            }
        };
        if out.len() != block.original_len {
            return Err(CompressionError::InconsistentBlock {
                reason: "decompressed len != original_len",
            });
        }
        Ok(out)
    }

    /// 当前统计快照。
    #[must_use]
    pub fn stats(&self) -> &CompressionStats {
        &self.stats
    }
}

// ---------- 真实 gzip 编解码（flate2 rust_backend） ----------

/// 用 gzip 压缩 `data`，级别 clamp 到 0-9。
fn gzip_compress(data: &[u8], level: u8) -> Vec<u8> {
    let mut encoder =
        flate2::write::GzEncoder::new(Vec::new(), Compression::new(level.min(9) as u32));
    // 压缩为内存操作，写入失败仅因 OOM；此处不 panic，失败时退化为空载荷（decode 会拒绝）。
    let _ = encoder.write_all(data);
    encoder.finish().unwrap_or_default()
}

/// 用 gzip 解压 `data`；失败映射为类型化 `InconsistentBlock`。
fn gzip_decompress(data: &[u8]) -> Result<Vec<u8>, CompressionError> {
    let mut decoder = GzDecoder::new(data);
    let mut out = Vec::new();
    std::io::Read::read_to_end(&mut decoder, &mut out).map_err(|_| {
        CompressionError::InconsistentBlock {
            reason: "gzip decode failed",
        }
    })?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(alg: CompressionAlgorithm) -> CompressionConfig {
        CompressionConfig::new(alg, 6, 64).expect("valid config")
    }

    #[test]
    fn none_algorithm_never_compresses() {
        let mut c = CompressionCodec::new(cfg(CompressionAlgorithm::None));
        assert!(!c.should_compress(10_000));
        let b = c.encode(&vec![0xAB; 1000]);
        assert!(!b.is_compressed());
        assert_eq!(b.algorithm_tag(), 0);
        assert_eq!(c.decode(b).expect("ok"), vec![0xAB; 1000]);
    }

    #[test]
    fn below_threshold_passthrough() {
        let mut c = CompressionCodec::new(cfg(CompressionAlgorithm::Gzip));
        // 32 < min_original_bytes=64 -> 自适应透传，不压缩。
        assert!(!c.should_compress(32));
        let b = c.encode(&[0x11; 32]);
        assert!(!b.is_compressed());
        assert_eq!(b.algorithm_tag(), 1); // 仍记录 gzip 标签。
    }

    #[test]
    fn above_threshold_marks_compressed() {
        let mut c = CompressionCodec::new(cfg(CompressionAlgorithm::Lz4));
        assert!(c.should_compress(128));
        let b = c.encode(&[0x22; 128]);
        assert!(b.is_compressed());
        assert_eq!(b.algorithm_tag(), 2);
        assert_eq!(c.decode(b).expect("ok"), vec![0x22; 128]);
    }

    #[test]
    fn stats_track_original_and_ratio() {
        let mut c = CompressionCodec::new(cfg(CompressionAlgorithm::Gzip));
        // 高熵不可压缩数据（SplitMix64）：真实 gzip 不收缩（略膨胀），ratio 经 clamp 仍为 0。
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        let incompressible: Vec<u8> = (0..1000).map(|_| next() as u8).collect();
        c.encode(&incompressible); // 压（不可压缩，载荷 >= 原始）
        c.encode(&[0u8; 10]); // 透传（<64）
        let s = c.stats();
        assert_eq!(s.blocks(), 2);
        assert_eq!(s.original_total(), 1010);
        // 不可压缩数据不应收缩；统计载荷不小于原始。
        assert!(s.compressed_total() >= s.original_total());
        // 不可压缩 -> 压缩率 clamp 为 0。
        assert_eq!(s.ratio(), 0.0);
    }

    #[test]
    fn compressible_data_shrinks() {
        let mut c = CompressionCodec::new(cfg(CompressionAlgorithm::Gzip));
        c.encode(&[0u8; 4096]); // 高可压缩
        let s = c.stats();
        assert!(s.compressed_total() < s.original_total());
        assert!(s.ratio() > 0.0);
    }

    #[test]
    fn unknown_tag_rejected() {
        let c = CompressionCodec::new(cfg(CompressionAlgorithm::Gzip));
        let bad = CompressedBlock {
            algorithm_tag: 9,
            original_len: 0,
            compressed: false,
            payload: Vec::new(),
        };
        assert!(matches!(
            c.decode(bad),
            Err(CompressionError::UnknownAlgorithmTag { tag: 9 })
        ));
    }

    #[test]
    fn inconsistent_compressed_block_rejected() {
        let c = CompressionCodec::new(cfg(CompressionAlgorithm::Gzip));
        let bad = CompressedBlock {
            algorithm_tag: 1,
            original_len: 100,
            compressed: true,
            payload: vec![0u8; 50],
        };
        assert!(matches!(
            c.decode(bad),
            Err(CompressionError::InconsistentBlock { .. })
        ));
    }

    #[test]
    fn invalid_config_rejected() {
        assert!(CompressionConfig::new(CompressionAlgorithm::Gzip, 10, 64).is_err());
        assert!(CompressionConfig::new(CompressionAlgorithm::Gzip, 6, 0).is_err());
        let err = CompressionConfig::new(CompressionAlgorithm::Gzip, 10, 64).unwrap_err();
        assert!(err.to_string().starts_with("COMPRESSION_INVALID_CONFIG:"));
    }

    #[test]
    fn as_str_and_tag_roundtrip() {
        assert_eq!(CompressionAlgorithm::None.as_str(), "none");
        assert_eq!(CompressionAlgorithm::Gzip.as_str(), "gzip");
        assert_eq!(CompressionAlgorithm::Lz4.as_str(), "lz4");
        for alg in [
            CompressionAlgorithm::None,
            CompressionAlgorithm::Gzip,
            CompressionAlgorithm::Lz4,
        ] {
            assert_eq!(CompressionAlgorithm::from_tag(alg.tag()).expect("tag"), alg);
        }
    }
}

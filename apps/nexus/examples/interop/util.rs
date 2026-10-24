//! 确定性工具：载荷 PRNG、FNV-1a、SHA-256（ring）、UTC 时间、原子写。
//!
//! 目标：同一 (protocol, variant, cell) 在任何机器上产生同一载荷字节，
//! 时间只用于证据元数据，不参与协议判定。

use std::io::Write as _;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// 载荷主种子常量（D-13）。
pub const PAYLOAD_SEED: u64 = 0x9E37_79B9_7F4A_7C15;

/// FNV-1a 64 位哈希（稳定、无依赖）。
#[must_use]
pub fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// xorshift64（种子 0 替换为常量，避免退化）。
#[derive(Debug, Clone)]
pub struct XorShift64(u64);

impl XorShift64 {
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self(if seed == 0 { PAYLOAD_SEED } else { seed })
    }

    #[must_use]
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

/// cell 级种子：`PAYLOAD_SEED ^ fnv1a64("<protocol>|<variant>|<cell>")`。
#[must_use]
pub fn cell_seed(protocol: &str, variant: &str, cell: &str) -> u64 {
    PAYLOAD_SEED ^ fnv1a64(format!("{protocol}|{variant}|{cell}").as_bytes())
}

/// 确定性载荷（指定种子）。
#[must_use]
pub fn payload_with_seed(seed: u64, len: usize) -> Vec<u8> {
    let mut rng = XorShift64::new(seed);
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        out.extend_from_slice(&rng.next_u64().to_le_bytes());
    }
    out.truncate(len);
    out
}

/// TCP source 目标的确定性下行流（client 与 target 共用）。
#[must_use]
pub fn source_payload(len: usize) -> Vec<u8> {
    payload_with_seed(PAYLOAD_SEED ^ fnv1a64(b"tcp-source"), len)
}

/// UDP 数据报载荷：`seq(8B BE) || 确定性字节`。
#[must_use]
pub fn udp_payload(seed: u64, seq: u64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&seq.to_be_bytes());
    let body = payload_with_seed(seed ^ seq, len.saturating_sub(8));
    out.extend_from_slice(&body);
    out.truncate(len);
    out
}

/// SHA-256 十六进制（ring，无新增依赖）。
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    to_hex(digest.as_ref())
}

#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit(u32::from(b >> 4), 16).expect("hex"));
        out.push(char::from_digit(u32::from(b & 0x0f), 16).expect("hex"));
    }
    out
}

/// 当前 UTC 的 RFC3339 秒精度（`YYYY-MM-DDTHH:MM:SSZ`）。
#[must_use]
pub fn utc_now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_utc(secs)
}

/// 把 Unix 秒格式化为 RFC3339（Z 结尾，秒精度）。
#[must_use]
pub fn format_utc(unix_secs: u64) -> String {
    let days = i64::try_from(unix_secs / 86_400).unwrap_or(0);
    let rem = unix_secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = rem / 3_600;
    let minute = (rem % 3_600) / 60;
    let second = rem % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// 证据 ID 里的紧凑时间戳（`YYYYmmddTHHMMSSZ`）。
#[must_use]
pub fn utc_now_compact() -> String {
    let stamp = utc_now_rfc3339();
    digest_stamp(&stamp)
}

fn digest_stamp(rfc3339: &str) -> String {
    // "2026-10-25T01:02:03Z" -> "20261025T010203Z"
    let digits: String = rfc3339
        .chars()
        .filter(|c| *c != '-')
        .filter(|c| *c != ':')
        .collect();
    digits
}

/// Howard Hinnant 的 civil_from_days（Unix epoch 起）。
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (
        y,
        u32::try_from(m).unwrap_or(1),
        u32::try_from(d).unwrap_or(1),
    )
}

/// 原子写：同目录临时文件 + rename。
pub fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_is_deterministic() {
        let a = payload_with_seed(42, 1024);
        let b = payload_with_seed(42, 1024);
        assert_eq!(a, b);
        assert_eq!(a.len(), 1024);
        assert_ne!(a, payload_with_seed(43, 1024));
    }

    #[test]
    fn fnv_is_stable() {
        assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
    }

    #[test]
    fn utc_epoch_and_known_stamp() {
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc(1_791_286_400), "2026-10-06T11:33:20Z");
        assert_eq!(digest_stamp("2026-10-25T01:02:03Z"), "20261025T010203Z");
    }

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn udp_payload_seq_prefix() {
        let p = udp_payload(7, 258, 512);
        assert_eq!(&p[..8], &258u64.to_be_bytes());
        assert_eq!(p.len(), 512);
    }
}

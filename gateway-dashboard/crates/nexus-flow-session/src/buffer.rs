//! UDP 建连期有界缓冲（D4）。

/// UDP 缓冲上限：32 包。
pub const UDP_BUFFER_MAX_PACKETS: usize = 32;
/// UDP 缓冲上限：64KB。
pub const UDP_BUFFER_MAX_BYTES: usize = 64 * 1024;

/// UDP 首包触发建会话后、会话 Active 前的上行包缓冲。
///
/// 有界：超 bound 的包被丢弃并计数（`dropped_over_bound`），会话仍正常建立。
#[derive(Debug, Default)]
pub struct UdpBuffer {
    packets: Vec<Vec<u8>>,
    total_bytes: usize,
    dropped_over_bound: u64,
}

impl UdpBuffer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 入缓冲；超 bound 返回 false（调用方计数丢弃）。
    pub fn push(&mut self, packet: Vec<u8>) -> bool {
        if self.packets.len() >= UDP_BUFFER_MAX_PACKETS
            || self.total_bytes + packet.len() > UDP_BUFFER_MAX_BYTES
        {
            self.dropped_over_bound += 1;
            return false;
        }
        self.total_bytes += packet.len();
        self.packets.push(packet);
        true
    }

    /// 取出全部缓冲包（会话 Active 后 flush 用）；清空缓冲。
    #[must_use]
    pub fn drain(&mut self) -> Vec<Vec<u8>> {
        self.total_bytes = 0;
        std::mem::take(&mut self.packets)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.packets.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    #[must_use]
    pub fn dropped_over_bound(&self) -> u64 {
        self.dropped_over_bound
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_by_packet_count() {
        let mut b = UdpBuffer::new();
        for _ in 0..UDP_BUFFER_MAX_PACKETS {
            assert!(b.push(vec![0u8; 10]));
        }
        assert!(!b.push(vec![0u8; 10]));
        assert_eq!(b.dropped_over_bound(), 1);
        assert_eq!(b.len(), UDP_BUFFER_MAX_PACKETS);
    }

    #[test]
    fn bounded_by_bytes() {
        let mut b = UdpBuffer::new();
        assert!(b.push(vec![0u8; UDP_BUFFER_MAX_BYTES]));
        assert!(!b.push(vec![0u8; 1]));
        assert_eq!(b.dropped_over_bound(), 1);
    }

    #[test]
    fn drain_clears_and_returns_all() {
        let mut b = UdpBuffer::new();
        b.push(vec![1u8; 4]);
        b.push(vec![2u8; 4]);
        let out = b.drain();
        assert_eq!(out.len(), 2);
        assert!(b.is_empty());
        // drain 后可复用。
        assert!(b.push(vec![3u8; 4]));
    }
}

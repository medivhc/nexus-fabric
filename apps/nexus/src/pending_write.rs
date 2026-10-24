//! 非阻塞中继写状态机（relay pump 共享）。
//!
//! 非阻塞 socket 上的 `write_all` 语义不成立：`WouldBlock` 时已写字节不可回退、
//! 未写尾部必须保留。`PendingWrite` 把「待写尾部 + 进度 + flush 背压」收敛为一个
//! 小状态机，供 trojan / anytls / vless / hysteria2 的中继泵共用：
//!
//! - [`PendingWrite::try_write`] 单次 `write`（绝不 `write_all`），保留未写尾部；
//! - 尾部非空（或 rustls 内部缓冲尚未 flush）时 [`PendingWrite::ready_for_read`]
//!   为 false，读侧暂停，形成背压；
//! - `Ok(0)` 报 `WriteZero`，避免忙等。

use std::io::{Read, Write};

/// 待写尾部状态机的队列。
pub(crate) struct PendingWrite {
    buf: Vec<u8>,
    pos: usize,
    flush_blocked: bool,
}

/// 一次 `try_write` 后队列是否已彻底排空。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WriteProgress {
    /// 尾部已清空且 `flush` 成功。
    Drained,
    /// 仍有未写尾部，或 `flush` 被 `WouldBlock` 挡住。
    Blocked,
}

impl PendingWrite {
    pub(crate) fn new() -> Self {
        Self {
            buf: Vec::new(),
            pos: 0,
            flush_blocked: false,
        }
    }

    /// 追加待写字节。调用点保证只在 [`Self::ready_for_read`] 时读，因此正常路径
    /// 不会在未清空时追加；即使误用，追加也保持字节顺序。
    pub(crate) fn enqueue(&mut self, data: &[u8]) {
        debug_assert!(
            self.buffered().is_empty(),
            "enqueue while pending tail is non-empty"
        );
        self.buf.extend_from_slice(data);
    }

    /// 是否允许继续从源端读取：无未写尾部且无 flush 背压。
    pub(crate) fn ready_for_read(&self) -> bool {
        self.pos >= self.buf.len() && !self.flush_blocked
    }

    /// 尚未写出的尾部（测试与额度断言用）。
    pub(crate) fn buffered(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    /// 读侧背压门：pending 非空时不触碰 `src`（不发起 `read`）。
    pub(crate) fn try_read<R: Read>(
        &self,
        src: &mut R,
        out: &mut [u8],
    ) -> Option<std::io::Result<usize>> {
        if !self.ready_for_read() {
            return None;
        }
        Some(src.read(out))
    }

    /// 推进一次非阻塞写，返回（队列状态, 本次实际写出字节数）。
    pub(crate) fn try_write<W: Write>(
        &mut self,
        dst: &mut W,
    ) -> std::io::Result<(WriteProgress, usize)> {
        let mut advanced = 0usize;
        if self.pos < self.buf.len() {
            match dst.write(&self.buf[self.pos..]) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "pending write returned Ok(0)",
                    ));
                }
                Ok(n) => {
                    self.pos += n;
                    advanced = n;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return Ok((WriteProgress::Blocked, 0));
                }
                Err(e) => return Err(e),
            }
        }
        if self.pos < self.buf.len() {
            return Ok((WriteProgress::Blocked, advanced));
        }
        self.buf.clear();
        self.pos = 0;
        match dst.flush() {
            Ok(()) => {
                self.flush_blocked = false;
                Ok((WriteProgress::Drained, advanced))
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                self.flush_blocked = true;
                Ok((WriteProgress::Blocked, advanced))
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    const DATA: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

    struct Recorder {
        out: Vec<u8>,
    }

    impl Recorder {
        fn new() -> Self {
            Self { out: Vec::new() }
        }
    }

    /// 首轮 `WouldBlock`，之后全量接收。
    struct WouldBlockThenAll {
        blocked_once: bool,
        rec: Recorder,
    }

    impl std::io::Write for WouldBlockThenAll {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if !self.blocked_once {
                self.blocked_once = true;
                return Err(Error::from(ErrorKind::WouldBlock));
            }
            self.rec.out.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// 每次最多接收 `cap` 字节（部分写）。
    struct Capped {
        cap: usize,
        rec: Recorder,
    }

    impl std::io::Write for Capped {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let n = buf.len().min(self.cap);
            self.rec.out.extend_from_slice(&buf[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// 交替 `WouldBlock` 与部分写（每次最多 4 字节）。
    struct Alternating {
        turn: u32,
        rec: Recorder,
    }

    impl std::io::Write for Alternating {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.turn += 1;
            if self.turn % 2 == 1 {
                return Err(Error::from(ErrorKind::WouldBlock));
            }
            let n = buf.len().min(4);
            self.rec.out.extend_from_slice(&buf[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// `write` 全量接收，`flush` 首次 `WouldBlock`、之后成功。
    struct FlushBlocking {
        flush_calls: u32,
    }

    impl std::io::Write for FlushBlocking {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.flush_calls += 1;
            if self.flush_calls == 1 {
                return Err(Error::from(ErrorKind::WouldBlock));
            }
            Ok(())
        }
    }

    struct ZeroWrite;
    impl std::io::Write for ZeroWrite {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Ok(0)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct BrokenPipeWrite;
    impl std::io::Write for BrokenPipeWrite {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(Error::from(ErrorKind::BrokenPipe))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct CountingReader {
        calls: usize,
        data: &'static [u8],
    }

    impl std::io::Read for CountingReader {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            self.calls += 1;
            let n = self.data.len().min(out.len());
            out[..n].copy_from_slice(&self.data[..n]);
            Ok(n)
        }
    }

    fn drained(p: &PendingWrite) -> bool {
        p.buffered().is_empty() && p.ready_for_read()
    }

    #[test]
    fn wouldblock_preserves_tail_and_does_not_close() {
        let mut pending = PendingWrite::new();
        pending.enqueue(DATA);
        let mut w = WouldBlockThenAll {
            blocked_once: false,
            rec: Recorder::new(),
        };
        let (progress, n) = pending.try_write(&mut w).expect("WouldBlock 不是致命错误");
        assert_eq!(progress, WriteProgress::Blocked);
        assert_eq!(n, 0);
        assert_eq!(pending.buffered(), DATA, "WouldBlock 不得丢字节");
        assert!(!pending.ready_for_read(), "待写尾部非空时读侧必须暂停");
        assert!(w.rec.out.is_empty());
    }

    #[test]
    fn partial_write_keeps_exact_unwritten_tail() {
        let mut pending = PendingWrite::new();
        pending.enqueue(DATA);
        let mut w = Capped {
            cap: 3,
            rec: Recorder::new(),
        };
        let (_, n0) = pending.try_write(&mut w).expect("部分写不是错误");
        assert_eq!(n0, 3);
        assert_eq!(pending.buffered(), &DATA[3..], "保留的尾部恰为未写字节");

        let mut offset = 3usize;
        loop {
            let (progress, n) = pending.try_write(&mut w).expect("部分写不是错误");
            if n > 0 {
                assert_eq!(
                    &w.rec.out[offset..offset + n],
                    &DATA[offset..offset + n],
                    "续写起点必须正确"
                );
                offset += n;
            }
            if progress == WriteProgress::Drained {
                break;
            }
            assert!(n > 0, "队列未排空时必须继续推进");
        }
        assert_eq!(offset, DATA.len());
        assert_eq!(w.rec.out, DATA, "最终拼出的字节序列等于输入");
        assert!(drained(&pending));
    }

    #[test]
    fn alternating_eagain_and_partial_writes_complete_in_order() {
        let mut pending = PendingWrite::new();
        pending.enqueue(DATA);
        let mut w = Alternating {
            turn: 0,
            rec: Recorder::new(),
        };
        let mut offset = 0usize;
        let mut rounds = 0u32;
        loop {
            rounds += 1;
            assert!(rounds < 10_000, "状态机不得无限循环");
            let (progress, n) = pending.try_write(&mut w).expect("EAGAIN 不是错误");
            if n > 0 {
                assert_eq!(
                    &w.rec.out[offset..offset + n],
                    &DATA[offset..offset + n],
                    "顺序不得改变"
                );
                offset += n;
            }
            if progress == WriteProgress::Drained {
                break;
            }
        }
        assert_eq!(w.rec.out, DATA);
        assert_eq!(offset, DATA.len());
    }

    #[test]
    fn no_early_exit_on_wouldblock() {
        let mut pending = PendingWrite::new();
        pending.enqueue(DATA);
        let mut w = Alternating {
            turn: 0,
            rec: Recorder::new(),
        };
        // 首轮 WouldBlock：Blocked 且读侧门关闭。
        let (progress, n) = pending.try_write(&mut w).unwrap();
        assert_eq!(progress, WriteProgress::Blocked);
        assert_eq!(n, 0);
        assert!(!pending.ready_for_read());
        // 第二轮部分写后尾部仍非空：Blocked 且读侧门仍关闭。
        let (progress, n) = pending.try_write(&mut w).unwrap();
        assert!(n > 0);
        assert_eq!(progress, WriteProgress::Blocked);
        assert!(!pending.ready_for_read());
        // 继续驱动仍能完成，不早退。
        loop {
            let (progress, _) = pending.try_write(&mut w).unwrap();
            if progress == WriteProgress::Drained {
                break;
            }
        }
        assert_eq!(w.rec.out, DATA);
        assert!(drained(&pending));
    }

    #[test]
    fn read_is_not_polled_while_pending_tail_nonempty() {
        let mut pending = PendingWrite::new();
        pending.enqueue(DATA);
        let mut reader = CountingReader {
            calls: 0,
            data: b"hello",
        };
        let mut out = [0u8; 16];
        assert!(
            pending.try_read(&mut reader, &mut out).is_none(),
            "pending 非空时 try_read 必须返回 None"
        );
        assert_eq!(reader.calls, 0, "不得触碰源端读取");

        let mut w = Capped {
            cap: 4,
            rec: Recorder::new(),
        };
        loop {
            let (progress, _) = pending.try_write(&mut w).unwrap();
            if progress == WriteProgress::Drained {
                break;
            }
        }
        assert!(pending.ready_for_read());
        let n = pending
            .try_read(&mut reader, &mut out)
            .expect("排空后允许读取")
            .expect("读取成功");
        assert_eq!(reader.calls, 1);
        assert_eq!(n, 5);
    }

    #[test]
    fn flush_wouldblock_keeps_backpressure() {
        let mut pending = PendingWrite::new();
        pending.enqueue(DATA);
        let mut w = FlushBlocking { flush_calls: 0 };
        let (progress, n) = pending
            .try_write(&mut w)
            .expect("flush WouldBlock 不是致命错误");
        assert_eq!(n, DATA.len());
        assert_eq!(progress, WriteProgress::Blocked);
        assert!(pending.buffered().is_empty(), "字节已全部交给写入端");
        assert!(
            !pending.ready_for_read(),
            "rustls 内部缓冲未 flush 时读侧必须暂停（背压）"
        );
        let (progress, n) = pending.try_write(&mut w).expect("再次 flush 成功");
        assert_eq!(n, 0);
        assert_eq!(progress, WriteProgress::Drained);
        assert!(pending.ready_for_read());
        assert_eq!(w.flush_calls, 2);
    }

    #[test]
    fn zero_write_is_reported() {
        let mut pending = PendingWrite::new();
        pending.enqueue(DATA);
        let err = pending
            .try_write(&mut ZeroWrite)
            .expect_err("Ok(0) 必须报错");
        assert_eq!(err.kind(), ErrorKind::WriteZero);
        assert_eq!(pending.buffered(), DATA, "报错不改动待写尾部");
    }

    #[test]
    fn non_wouldblock_write_error_is_returned() {
        let mut pending = PendingWrite::new();
        pending.enqueue(DATA);
        let err = pending
            .try_write(&mut BrokenPipeWrite)
            .expect_err("非 WouldBlock 错误必须原样返回");
        assert_eq!(err.kind(), ErrorKind::BrokenPipe);
    }
}

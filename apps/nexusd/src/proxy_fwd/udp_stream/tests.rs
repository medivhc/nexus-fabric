//! 代理流表单测（PRODUCT §11.18.1；test review r3 的 T1–T7、T13、T14、T15、T17）。
//!
//! 内存假 dialer：`open_udp` 可按目的地址阻塞（闸门）或失败；打开的流把写出的数据报
//! 记下来，回包由测试经通道注入（`None` = 对端关闭）。时间由测试传入。

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Condvar, Mutex};

use super::*;
use crate::proxy_fwd::adapter::{OutboundError, TunnelStream, UdpCapability, UdpMode};
use crate::proxy_fwd::udp_relay::UdpForwarder;

fn addr(last: u8, port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, last), port))
}

const SRC_A: u8 = 2;
const SRC_B: u8 = 3;

fn dst(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), port)
}

struct FakeStream {
    written: Arc<Mutex<Vec<Vec<u8>>>>,
    replies: Receiver<Option<Vec<u8>>>,
    timeout: Duration,
}

impl UdpStream for FakeStream {
    fn send_datagram(&mut self, datagram: &[u8]) -> io::Result<()> {
        self.written
            .lock()
            .map_err(|_| io::Error::other("lock"))?
            .push(datagram.to_vec());
        Ok(())
    }

    fn recv_datagrams(&mut self) -> io::Result<Option<Vec<Vec<u8>>>> {
        match self.replies.recv_timeout(self.timeout) {
            Ok(Some(payload)) => Ok(Some(vec![payload])),
            Ok(None) | Err(RecvTimeoutError::Disconnected) => Ok(None),
            Err(RecvTimeoutError::Timeout) => Err(io::ErrorKind::TimedOut.into()),
        }
    }

    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.timeout = timeout.unwrap_or(Duration::from_secs(3600));
        Ok(())
    }

    fn set_write_timeout(&mut self, _timeout: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    fn shutdown(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// 一条已打开的假流（测试侧句柄）。
#[derive(Clone)]
struct Opened {
    target: SocketAddr,
    written: Arc<Mutex<Vec<Vec<u8>>>>,
    replies: Sender<Option<Vec<u8>>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fail {
    No,
    Refused,
    Timeout,
}

#[derive(Default)]
struct FakeState {
    blocked: HashSet<SocketAddr>,
    opened: Vec<Opened>,
    attempts: usize,
}

struct FakeDialer {
    state: Mutex<FakeState>,
    unblocked: Condvar,
    fail: Mutex<Fail>,
}

impl FakeDialer {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(FakeState::default()),
            unblocked: Condvar::new(),
            fail: Mutex::new(Fail::No),
        })
    }

    fn block(&self, target: SocketAddr) {
        self.state.lock().expect("lock").blocked.insert(target);
    }

    fn unblock(&self, target: SocketAddr) {
        self.state.lock().expect("lock").blocked.remove(&target);
        self.unblocked.notify_all();
    }

    fn set_fail(&self, fail: Fail) {
        *self.fail.lock().expect("lock") = fail;
    }

    fn attempts(&self) -> usize {
        self.state.lock().expect("lock").attempts
    }

    fn opened(&self) -> Vec<Opened> {
        self.state.lock().expect("lock").opened.clone()
    }
}

impl OutboundDialer for FakeDialer {
    fn kind(&self) -> OutboundKind {
        OutboundKind::Vless
    }

    fn tag(&self) -> &str {
        "t"
    }

    fn dial_tcp(&self, _target: SocketAddr) -> Result<Box<dyn TunnelStream>, OutboundError> {
        Err(OutboundError::Closed)
    }

    fn udp_capability(&self) -> UdpCapability {
        UdpCapability::Supported(UdpMode::VlessOverTcp { server: dst(443) })
    }

    fn open_udp(&self, target: SocketAddr) -> Result<Box<dyn UdpStream>, OutboundError> {
        let mut state = self.state.lock().expect("lock");
        while state.blocked.contains(&target) {
            state = self.unblocked.wait(state).expect("wait");
        }
        state.attempts += 1;
        match *self.fail.lock().expect("lock") {
            Fail::Refused => {
                return Err(OutboundError::TcpConnect {
                    kind: io::ErrorKind::ConnectionRefused,
                });
            }
            Fail::Timeout => return Err(OutboundError::ConnectTimeout),
            Fail::No => {}
        }
        let written = Arc::new(Mutex::new(Vec::new()));
        let (replies, replies_rx) = mpsc::channel();
        state.opened.push(Opened {
            target,
            written: Arc::clone(&written),
            replies,
        });
        Ok(Box::new(FakeStream {
            written,
            replies: replies_rx,
            timeout: Duration::from_secs(3600),
        }))
    }
}

fn table(dialer: &Arc<FakeDialer>) -> StreamTable {
    StreamTable::new(Arc::clone(dialer) as Arc<dyn OutboundDialer>)
}

/// 反复 `poll(now)` 直到 `done` 成立（最多 5 s 墙钟），返回期间收到的回包。
fn poll_until(
    table: &mut StreamTable,
    now: Instant,
    stats: &mut ProxyFwdStats,
    mut done: impl FnMut(&StreamTable, &ProxyFwdStats, &[UdpReply]) -> bool,
) -> Vec<UdpReply> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut replies = Vec::new();
    loop {
        replies.extend(table.poll(now, stats));
        if done(table, stats, &replies) {
            return replies;
        }
        assert!(Instant::now() < deadline, "condition not reached");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn written(opened: &Opened) -> Vec<Vec<u8>> {
    opened.written.lock().expect("lock").clone()
}

fn wait_written(opened: &Opened, n: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while written(opened).len() < n {
        assert!(Instant::now() < deadline, "datagrams not written");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn wait_opened(dialer: &FakeDialer, n: usize) -> Vec<Opened> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let opened = dialer.opened();
        if opened.len() >= n {
            return opened;
        }
        assert!(Instant::now() < deadline, "streams not opened");
        std::thread::sleep(Duration::from_millis(5));
    }
}

// ---- T1：建流不在 dataplane 线程上 ----

#[test]
fn open_runs_off_the_dataplane_thread() {
    let dialer = FakeDialer::new();
    dialer.block(dst(1));
    let mut table = table(&dialer);
    let mut stats = ProxyFwdStats::default();
    let t0 = Instant::now();
    let call = Instant::now();
    assert!(table.send(
        addr(SRC_A, 5000),
        dst(1),
        b"blocked".to_vec(),
        t0,
        &mut stats
    ));
    assert!(call.elapsed() < Duration::from_millis(50), "send blocked");
    // 第二个流键在第一个建流仍阻塞时照常建流、写出、收回包。
    assert!(table.send(addr(SRC_A, 5000), dst(2), b"free".to_vec(), t0, &mut stats));
    let opened = wait_opened(&dialer, 1);
    assert_eq!(opened[0].target, dst(2));
    wait_written(&opened[0], 1);
    opened[0]
        .replies
        .send(Some(b"reply".to_vec()))
        .expect("reply");
    let replies = poll_until(&mut table, t0, &mut stats, |_, _, r| !r.is_empty());
    assert_eq!(
        replies,
        vec![UdpReply {
            local: addr(SRC_A, 5000),
            remote: dst(2),
            payload: b"reply".to_vec(),
        }]
    );
    dialer.unblock(dst(1));
    let opened = wait_opened(&dialer, 2);
    wait_written(&opened[1], 1);
    poll_until(&mut table, t0, &mut stats, |_, s, _| s.udp_sent == 2);
    assert_eq!(stats.udp_send_failed, 0);
}

// ---- T2 / T15：建流期间按序排队，每流键 64 个；udp_sent 在写出时计 ----

#[test]
fn queue_in_order_with_cap_64_per_flow_key() {
    let dialer = FakeDialer::new();
    dialer.block(dst(1));
    let mut table = table(&dialer);
    let mut stats = ProxyFwdStats::default();
    let t0 = Instant::now();
    let accepted: Vec<bool> = (0..70u8)
        .map(|i| table.send(addr(SRC_A, 5000), dst(1), vec![i], t0, &mut stats))
        .collect();
    assert!(accepted[..64].iter().all(|ok| *ok));
    assert!(accepted[64..].iter().all(|ok| !*ok));
    assert_eq!(stats.udp_send_failed, 6);
    // 另一个本地源发往同一目的地址：独立的流与独立的 64 个队列位。
    for i in 0..64u8 {
        assert!(table.send(addr(SRC_B, 5000), dst(1), vec![i], t0, &mut stats));
    }
    let _ = table.poll(t0, &mut stats);
    assert_eq!(
        stats.udp_sent, 0,
        "nothing is sent before the open completes"
    );
    dialer.unblock(dst(1));
    let opened = wait_opened(&dialer, 2);
    for stream in &opened {
        wait_written(stream, 64);
        assert_eq!(
            written(stream),
            (0..64u8).map(|i| vec![i]).collect::<Vec<_>>()
        );
    }
    poll_until(&mut table, t0, &mut stats, |_, s, _| s.udp_sent == 128);
    assert_eq!(stats.udp_send_failed, 6);
}

// ---- T3：建流失败丢弃队列、逐个计数、限频日志 ----

#[test]
fn open_failure_drops_the_queue_and_counts_each() {
    let dialer = FakeDialer::new();
    dialer.block(dst(1));
    dialer.set_fail(Fail::Refused);
    let mut table = table(&dialer);
    let mut stats = ProxyFwdStats::default();
    let t0 = Instant::now();
    for i in 0..5u8 {
        assert!(table.send(addr(SRC_A, 5000), dst(1), vec![i], t0, &mut stats));
    }
    dialer.unblock(dst(1));
    poll_until(&mut table, t0, &mut stats, |t, _, _| t.live_streams() == 0);
    assert_eq!(stats.udp_send_failed, 5);
    assert_eq!(stats.udp_sent, 0);
    assert!(dialer.opened().is_empty());
}

#[test]
fn open_failure_log_is_rate_limited_per_cause() {
    let dialer = FakeDialer::new();
    let mut table = table(&dialer);
    let t0 = Instant::now();
    let at = |ms: u64| t0 + Duration::from_millis(ms);
    assert_eq!(
        table.open_failed_line("tcp_connect", t0).as_deref(),
        Some(
            "[proxy-fwd] event=udp_stream_open_failed kind=vless tag=t cause=tcp_connect suppressed=0"
        )
    );
    assert_eq!(table.open_failed_line("tcp_connect", at(5_000)), None);
    assert_eq!(table.open_failed_line("tcp_connect", at(9_999)), None);
    // 另一个原因有自己的节奏。
    assert_eq!(
        table
            .open_failed_line("connect_timeout", at(5_000))
            .as_deref(),
        Some(
            "[proxy-fwd] event=udp_stream_open_failed kind=vless tag=t cause=connect_timeout suppressed=0"
        )
    );
    assert_eq!(
        table.open_failed_line("tcp_connect", at(10_000)).as_deref(),
        Some(
            "[proxy-fwd] event=udp_stream_open_failed kind=vless tag=t cause=tcp_connect suppressed=2"
        )
    );
    assert_eq!(table.open_failed_line("tcp_connect", at(10_001)), None);
}

// ---- T4：建流失败后同一流键至少间隔 1 s 才重试 ----

#[test]
fn open_retry_waits_one_second_per_flow_key() {
    let dialer = FakeDialer::new();
    dialer.set_fail(Fail::Timeout);
    let mut table = table(&dialer);
    let mut stats = ProxyFwdStats::default();
    let t_fail = Instant::now();
    let at = |ms: u64| t_fail + Duration::from_millis(ms);
    assert!(table.send(addr(SRC_A, 5000), dst(1), b"x".to_vec(), t_fail, &mut stats));
    poll_until(&mut table, t_fail, &mut stats, |t, _, _| {
        t.live_streams() == 0
    });
    assert_eq!(dialer.attempts(), 1);
    let failed_before = stats.udp_send_failed;
    assert!(!table.send(
        addr(SRC_A, 5000),
        dst(1),
        b"x".to_vec(),
        at(999),
        &mut stats
    ));
    assert_eq!(stats.udp_send_failed, failed_before + 1);
    // 同一目的地址的另一个流键不受影响。
    assert!(table.send(
        addr(SRC_B, 5000),
        dst(1),
        b"x".to_vec(),
        at(500),
        &mut stats
    ));
    poll_until(&mut table, at(500), &mut stats, |t, _, _| {
        t.live_streams() == 0
    });
    assert_eq!(dialer.attempts(), 2);
    assert!(table.send(
        addr(SRC_A, 5000),
        dst(1),
        b"x".to_vec(),
        at(1_000),
        &mut stats
    ));
    poll_until(&mut table, at(1_000), &mut stats, |t, _, _| {
        t.live_streams() == 0
    });
    assert_eq!(dialer.attempts(), 3);
}

// ---- T5：任一方向空闲 60 s 关闭并回收 worker ----

#[test]
fn idle_in_both_directions_closes_after_sixty_seconds() {
    let dialer = FakeDialer::new();
    let mut table = table(&dialer);
    let mut stats = ProxyFwdStats::default();
    let t0 = Instant::now();
    let at = |ms: u64| t0 + Duration::from_millis(ms);
    assert!(table.send(addr(SRC_A, 5000), dst(1), b"x".to_vec(), t0, &mut stats));
    let opened = wait_opened(&dialer, 1);
    // 只有回包的流量也刷新空闲计时。
    opened[0].replies.send(Some(b"r".to_vec())).expect("reply");
    poll_until(&mut table, at(30_000), &mut stats, |_, _, r| !r.is_empty());
    let _ = table.poll(at(89_999), &mut stats);
    assert_eq!(
        table.live_streams(),
        1,
        "still open at 59.999 s after the reply"
    );
    let _ = table.poll(at(90_000), &mut stats);
    assert_eq!(
        table.live_streams(),
        0,
        "closed 60 s after the last datagram"
    );
    // worker 被 join（不是被丢弃）：之后的 poll 把它从回收列表里清掉。
    poll_until(&mut table, at(90_000), &mut stats, |t, _, _| {
        t.workers_pending_join() == 0
    });
    assert_eq!(
        Arc::strong_count(&dialer),
        2,
        "table + test hold the dialer"
    );
    // 下一个数据报重新建流。
    assert!(table.send(
        addr(SRC_A, 5000),
        dst(1),
        b"y".to_vec(),
        at(90_001),
        &mut stats
    ));
    wait_opened(&dialer, 2);
}

// ---- T6：对端关闭 → 回收，下一个数据报重开并回到同一本地源 ----

#[test]
fn peer_close_reclaims_and_the_next_datagram_reopens() {
    let dialer = FakeDialer::new();
    let mut table = table(&dialer);
    let mut stats = ProxyFwdStats::default();
    let t0 = Instant::now();
    assert!(table.send(addr(SRC_A, 5000), dst(1), b"x".to_vec(), t0, &mut stats));
    let opened = wait_opened(&dialer, 1);
    opened[0].replies.send(None).expect("close");
    poll_until(&mut table, t0, &mut stats, |t, _, _| {
        t.live_streams() == 0 && t.workers_pending_join() == 0
    });
    assert!(table.send(addr(SRC_A, 5000), dst(1), b"y".to_vec(), t0, &mut stats));
    let opened = wait_opened(&dialer, 2);
    wait_written(&opened[1], 1);
    opened[1]
        .replies
        .send(Some(b"again".to_vec()))
        .expect("reply");
    let replies = poll_until(&mut table, t0, &mut stats, |_, _, r| !r.is_empty());
    assert_eq!(replies[0].local, addr(SRC_A, 5000));
    assert_eq!(replies[0].payload, b"again".to_vec());
}

// ---- T7：上限 1024，超出不驱逐 ----

#[test]
fn cap_rejects_new_flow_keys_without_evicting_existing_streams() {
    let dialer = FakeDialer::new();
    let mut table = table(&dialer);
    let mut stats = ProxyFwdStats::default();
    let t0 = Instant::now();
    let key = |i: usize| (addr(SRC_A, 10_000 + i as u16), dst(1));
    for i in 0..MAX_STREAMS {
        let (local, remote) = key(i);
        assert!(table.send(local, remote, vec![1], t0, &mut stats), "{i}");
    }
    let (local, remote) = key(MAX_STREAMS);
    assert!(!table.send(local, remote, vec![1], t0, &mut stats));
    assert_eq!(stats.udp_send_failed, 1);
    let opened = wait_opened(&dialer, MAX_STREAMS);
    for stream in &opened {
        wait_written(stream, 1);
        stream.replies.send(Some(b"r".to_vec())).expect("reply");
    }
    let replies = poll_until(&mut table, t0, &mut stats, |_, _, r| r.len() == MAX_STREAMS);
    let locals: HashSet<SocketAddr> = replies.iter().map(|r| r.local).collect();
    assert_eq!(
        locals.len(),
        MAX_STREAMS,
        "every existing stream still delivers"
    );
    // 回收一条后，新流键可以进入。
    opened[0].replies.send(None).expect("close");
    poll_until(&mut table, t0, &mut stats, |t, _, _| {
        t.live_streams() == MAX_STREAMS - 1
    });
    assert!(table.send(local, remote, vec![1], t0, &mut stats));
}

// ---- T17：Drop 关闭全部流并 join worker ----

#[test]
fn drop_closes_streams_and_joins_workers() {
    let dialer = FakeDialer::new();
    let mut table = table(&dialer);
    let mut stats = ProxyFwdStats::default();
    let t0 = Instant::now();
    for port in 1..=3 {
        assert!(table.send(addr(SRC_A, 5000), dst(port), vec![1], t0, &mut stats));
    }
    let opened = wait_opened(&dialer, 3);
    for stream in &opened {
        wait_written(stream, 1);
    }
    let started = Instant::now();
    drop(table);
    assert!(
        started.elapsed() < SHUTDOWN_GRACE,
        "{:?}",
        started.elapsed()
    );
    assert_eq!(Arc::strong_count(&dialer), 1, "all workers joined");
}

#[test]
fn drop_does_not_wait_past_the_grace_for_a_blocked_open() {
    let dialer = FakeDialer::new();
    dialer.block(dst(1));
    let mut table = table(&dialer);
    let mut stats = ProxyFwdStats::default();
    assert!(table.send(
        addr(SRC_A, 5000),
        dst(1),
        vec![1],
        Instant::now(),
        &mut stats
    ));
    let started = Instant::now();
    drop(table);
    let waited = started.elapsed();
    assert!(
        waited >= SHUTDOWN_GRACE && waited < SHUTDOWN_GRACE * 2,
        "{waited:?}"
    );
    // 建流返回后 worker 立即退出（命令通道已断开），不写任何数据报。
    dialer.unblock(dst(1));
    let deadline = Instant::now() + Duration::from_secs(5);
    while Arc::strong_count(&dialer) > 1 {
        assert!(
            Instant::now() < deadline,
            "worker did not exit after the open"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(written(&dialer.opened()[0]).is_empty());
}

// ---- T13：经 UdpForwarder 的回包归属（两个本地源 → 同一目的地址） ----

fn ipv4_udp(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let (SocketAddr::V4(src), SocketAddr::V4(dst)) = (src, dst) else {
        unreachable!("IPv4 test addresses")
    };
    let total = u16::try_from(28 + payload.len()).expect("len");
    let mut pkt = vec![0u8; usize::from(total)];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&total.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&src.ip().octets());
    pkt[16..20].copy_from_slice(&dst.ip().octets());
    pkt[20..22].copy_from_slice(&src.port().to_be_bytes());
    pkt[22..24].copy_from_slice(&dst.port().to_be_bytes());
    pkt[24..26].copy_from_slice(&u16::try_from(8 + payload.len()).expect("len").to_be_bytes());
    pkt[28..].copy_from_slice(payload);
    pkt
}

#[test]
fn forwarder_attributes_replies_to_the_source_that_opened_the_stream() {
    let dialer = FakeDialer::new();
    let mut forwarder = UdpForwarder::new(Arc::clone(&dialer) as Arc<dyn OutboundDialer>);
    let (a, b) = (addr(SRC_A, 5000), addr(SRC_B, 6000));
    assert!(forwarder.handle_packet(&ipv4_udp(a, dst(53), b"from-a")));
    assert!(forwarder.handle_packet(&ipv4_udp(b, dst(53), b"from-b")));
    let opened = wait_opened(&dialer, 2);
    for stream in &opened {
        wait_written(stream, 1);
        let sent = written(stream)[0].clone();
        stream
            .replies
            .send(Some([b"re:".as_slice(), &sent].concat()))
            .expect("reply");
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut replies = Vec::new();
    while replies.len() < 2 {
        replies.extend(forwarder.drain_replies());
        assert!(Instant::now() < deadline, "replies");
        std::thread::sleep(Duration::from_millis(5));
    }
    for reply in &replies {
        let expected = if reply.local == a {
            b"re:from-a".to_vec()
        } else {
            assert_eq!(reply.local, b);
            b"re:from-b".to_vec()
        };
        assert_eq!(reply.remote, dst(53));
        assert_eq!(reply.payload, expected);
    }
    let stats = forwarder.stats();
    assert_eq!((stats.udp_sent, stats.udp_send_failed), (2, 0));
    assert_eq!(
        (
            stats.udp_unsupported,
            stats.udp_unsupported_vless,
            stats.udp_unsupported_anytls
        ),
        (0, 0, 0)
    );
}

// ---- T14：TPROXY `send_udp` 入队即 Ok，调用内丢弃即 Err ----

#[test]
fn tproxy_send_udp_is_ok_when_queued_and_err_inside_the_retry_gap() {
    use crate::proxy_fwd::OutboundRegistry;
    use crate::tproxy_egress::StreamProxyEgress;
    use nexus_projection::egress::FlowKey;
    use nexus_projection::transparent::ProxyFlowEgress;

    // 关闭的端口：VLESS 建流（TCP 连接）失败。
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("port");
    let yaml = format!(
        "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: v\noutbounds:\n  - tag: v\n    kind: vless\n    locator: {closed}\n    uuid: 11111111-1111-1111-1111-111111111111\n"
    );
    let registry = OutboundRegistry::build(Some(&yaml))
        .expect("registry")
        .expect("some");
    let mut egress = StreamProxyEgress::from_registry(registry).expect("egress");
    let orig_dst = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 53);
    let key = FlowKey {
        src_ip: u32::from(Ipv4Addr::new(10, 0, 0, 3)),
        dst_ip: u32::from(*orig_dst.ip()),
        src_port: 5001,
        dst_port: 53,
        proto: 17,
    };
    egress.note_udp_outbound(key, "v");
    assert!(egress.send_udp(key, orig_dst, b"queued").is_ok());
    // 建流失败被处理后，1 s 内同一 flow 的数据报在调用内被丢弃 → Err。
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let _ = egress.poll();
        if egress.send_udp(key, orig_dst, b"in-gap").is_err() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "open failure was never processed"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

// ---- T12：最大 IPv4 UDP 载荷经 forwarder 往返，回包重构为完整 IP 包 ----

#[test]
fn forwarder_carries_the_largest_ipv4_datagram_both_ways() {
    let dialer = FakeDialer::new();
    let mut forwarder = UdpForwarder::new(Arc::clone(&dialer) as Arc<dyn OutboundDialer>);
    let payload: Vec<u8> = (0..65_507u32).map(|i| (i % 251) as u8).collect();
    let local = addr(SRC_A, 5000);
    assert!(forwarder.handle_packet(&ipv4_udp(local, dst(53), &payload)));
    let opened = wait_opened(&dialer, 1);
    wait_written(&opened[0], 1);
    assert_eq!(written(&opened[0])[0], payload);
    opened[0]
        .replies
        .send(Some(payload.clone()))
        .expect("reply");
    let deadline = Instant::now() + Duration::from_secs(5);
    let reply = loop {
        if let Some(reply) = forwarder.drain_replies().pop() {
            break reply;
        }
        assert!(Instant::now() < deadline, "reply");
        std::thread::sleep(Duration::from_millis(5));
    };
    let packet =
        crate::proxy_fwd::udp_relay::build_udp_reply(reply.local, reply.remote, &reply.payload)
            .expect("packet");
    assert_eq!(packet.len(), 65_535);
    assert_eq!(&packet[28..], payload.as_slice());
}

// ---- T18：建流失败 / 重试间隔内，目的地址收不到任何数据报（绝不直连） ----

#[test]
fn failed_opens_never_send_directly_to_the_destination() {
    use crate::proxy_fwd::OutboundRegistry;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let echo = std::net::UdpSocket::bind("127.0.0.1:0").expect("echo");
    let destination = echo.local_addr().expect("addr");
    echo.set_read_timeout(Some(Duration::from_millis(50)))
        .expect("timeout");
    let received = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&received);
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stopper = Arc::clone(&stop);
    let echo_thread = std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while !stopper.load(Ordering::SeqCst) {
            if let Ok((_, from)) = echo.recv_from(&mut buf) {
                counter.fetch_add(1, Ordering::SeqCst);
                let _ = echo.send_to(b"direct", from);
            }
        }
    });
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("port");
    let yaml = format!(
        "schema_version: 1\nrules:\n  - tag: r1\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: v\noutbounds:\n  - tag: v\n    kind: vless\n    locator: {closed}\n    uuid: 11111111-1111-1111-1111-111111111111\n"
    );
    let registry = OutboundRegistry::build(Some(&yaml))
        .expect("registry")
        .expect("some");
    let dialer = Arc::clone(registry.dialer("v").expect("dialer"));
    let mut forwarder = UdpForwarder::new(dialer);
    let local = addr(SRC_A, 5000);
    for i in 0..3u8 {
        assert!(forwarder.handle_packet(&ipv4_udp(local, destination, &[i])));
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while forwarder.stats().udp_send_failed < 3 {
        assert!(forwarder.drain_replies().is_empty(), "no fabricated reply");
        assert!(Instant::now() < deadline, "open failure not processed");
        std::thread::sleep(Duration::from_millis(5));
    }
    // 重试间隔内：调用内丢弃。
    assert!(!forwarder.handle_packet(&ipv4_udp(local, destination, b"gap")));
    std::thread::sleep(Duration::from_millis(200));
    assert!(forwarder.drain_replies().is_empty(), "no fabricated reply");
    let stats = forwarder.stats();
    assert_eq!((stats.udp_sent, stats.udp_send_failed), (0, 4));
    stop.store(true, Ordering::SeqCst);
    echo_thread.join().expect("echo");
    assert_eq!(
        received.load(Ordering::SeqCst),
        0,
        "nothing reached the destination"
    );
}

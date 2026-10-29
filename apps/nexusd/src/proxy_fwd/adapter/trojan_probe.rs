//! Trojan 凭据探测（PRODUCT §11.9.5 / MODULE P6）。
//!
//! - [`ProbeGate`]：每个 wired trojan 出站一份的探测状态（registry 拥有、不持久化），
//!   决定一次拨号是用缓存结果、等待进行中的探测（single-flight），还是自己探测；
//! - [`run_probe`]：一次探测的线缆动作——独立的新 TCP + TLS 连接（与该出站拨号相同的
//!   SNI / ALPN / 证书校验），写 Trojan 请求头（目标 `credential-probe.nexus.invalid:9`）
//!   与一个 HTTP GET，然后只读，最多 3 s。
//!
//! 探测在发起拨号的 worker 线程内同步执行：不新建线程，不阻塞 dataplane `tick()`。
//! 各阶段按截止时刻（而不是每次 socket 调用的超时）计时，单次探测 ≤ 5 + 5 + 3 = 13 s。

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use nexus_outbound_trojan::{TrojanTarget, encode_request};
use nexus_proxy_transport::TrojanTlsConfig;
use rustls::pki_types::ServerName;

use super::tls::{self, TlsStream};

/// 探测目标：RFC 6761 保留域，密码正确时节点解析失败而关闭。
pub(crate) const PROBE_HOST: &str = "credential-probe.nexus.invalid";
/// 探测目标端口（discard）。
pub(crate) const PROBE_PORT: u16 = 9;
/// TCP 建连上限。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// TLS 握手与写请求合计上限。
const HANDSHAKE_AND_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// 写完请求后的读窗口。
const READ_WINDOW: Duration = Duration::from_secs(3);
/// 单次探测上限；等待同一结果的拨号最多等这么久。
const PROBE_BOUND: Duration = Duration::from_secs(13);
/// `passed` 的有效期（自探测结束）。
const PASSED_TTL: Duration = Duration::from_secs(600);
/// `rejected` 的有效期（自探测结束）。
const REJECTED_TTL: Duration = Duration::from_secs(60);
/// `inconclusive` 之后到下一次探测的最小间隔（自探测结束）。
const INCONCLUSIVE_SPACING: Duration = Duration::from_secs(10);
/// 日志中 `first_bytes_hex` 最多覆盖的下行字节数。
const FIRST_BYTES_MAX: usize = 16;

/// 一次探测（或一次拨号采用）的判定。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// 密码被接受，或节点没有 fallback：照常拨号。
    Passed,
    /// 读窗口内收到下行字节：只能来自 fallback，拨号以 `auth_rejected` 失败。
    Rejected,
    /// 无法判定：照常拨号，不缓存。
    Inconclusive,
}

impl Verdict {
    fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Rejected => "rejected",
            Self::Inconclusive => "inconclusive",
        }
    }
}

/// 一次探测的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProbeReport {
    pub(crate) verdict: Verdict,
    /// 读窗口内收到的前若干下行字节（只在 `Rejected` 时非空）。
    pub(crate) first_bytes: Vec<u8>,
    pub(crate) elapsed: Duration,
}

/// 一次拨号该怎么做。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    /// 直接采用该判定，不探测。
    Use(Verdict),
    /// 由本次拨号探测。
    Probe,
    /// 等待进行中的探测。
    Wait,
}

/// 探测状态；时间全部由调用方以 `Instant` 传入（单测可构造边界）。
#[derive(Debug, Default)]
struct GateState {
    /// `passed` / `rejected` 的缓存判定及其到期时刻。
    cached: Option<(Verdict, Instant)>,
    /// `inconclusive` 之后的下一次可探测时刻。
    no_probe_before: Option<Instant>,
    /// 有一次探测正在进行。
    in_flight: bool,
    /// 已完成的探测次数；等待者据此识别它等的那次已结束。
    completed: u64,
    /// 最近一次完成的探测判定。
    last: Option<Verdict>,
}

impl GateState {
    fn decide(&self, now: Instant) -> Decision {
        if self.in_flight {
            return Decision::Wait;
        }
        if let Some((verdict, until)) = self.cached
            && now < until
        {
            return Decision::Use(verdict);
        }
        if let Some(at) = self.no_probe_before
            && now < at
        {
            return Decision::Use(Verdict::Inconclusive);
        }
        Decision::Probe
    }

    fn record(&mut self, verdict: Verdict, ended: Instant) {
        match verdict {
            Verdict::Passed => {
                self.cached = Some((verdict, ended + PASSED_TTL));
                self.no_probe_before = None;
            }
            Verdict::Rejected => {
                self.cached = Some((verdict, ended + REJECTED_TTL));
                self.no_probe_before = None;
            }
            Verdict::Inconclusive => {
                self.cached = None;
                self.no_probe_before = Some(ended + INCONCLUSIVE_SPACING);
            }
        }
        self.in_flight = false;
        self.completed += 1;
        self.last = Some(verdict);
    }
}

/// 一个 trojan 出站的探测闸门（MODULE P6）。
pub(crate) struct ProbeGate {
    tag: String,
    state: Mutex<GateState>,
    finished: Condvar,
}

impl ProbeGate {
    pub(crate) fn new(tag: String) -> Self {
        Self {
            tag,
            state: Mutex::new(GateState::default()),
            finished: Condvar::new(),
        }
    }

    /// 本次拨号采用的判定；需要时调用 `probe` 探测（同一时刻至多一个探测，其余等待其结果）。
    /// 每次探测结束打印一行 stderr（[`log_line`]）。
    pub(crate) fn verdict(&self, probe: impl FnOnce() -> ProbeReport) -> Verdict {
        let mut state = self.lock();
        loop {
            match state.decide(Instant::now()) {
                Decision::Use(verdict) => return verdict,
                Decision::Wait => {
                    let ticket = state.completed;
                    let deadline = Instant::now() + PROBE_BOUND;
                    while state.in_flight && state.completed == ticket {
                        let remaining = deadline.saturating_duration_since(Instant::now());
                        if remaining.is_zero() {
                            return Verdict::Inconclusive;
                        }
                        state = self
                            .finished
                            .wait_timeout(state, remaining)
                            .unwrap_or_else(PoisonError::into_inner)
                            .0;
                    }
                    if state.completed != ticket {
                        return state.last.unwrap_or(Verdict::Inconclusive);
                    }
                    // 探测方异常退出（未记录结果）：重新判定。
                }
                Decision::Probe => {
                    state.in_flight = true;
                    drop(state);
                    let mut in_flight = InFlight {
                        gate: self,
                        recorded: false,
                    };
                    let report = probe();
                    self.lock().record(report.verdict, Instant::now());
                    in_flight.recorded = true;
                    self.finished.notify_all();
                    eprintln!("{}", log_line(&self.tag, &report));
                    return report.verdict;
                }
            }
        }
    }

    fn lock(&self) -> MutexGuard<'_, GateState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// 探测方 unwind 时清除 `in_flight` 并唤醒等待者，避免闸门永久卡在「探测中」。
struct InFlight<'a> {
    gate: &'a ProbeGate,
    recorded: bool,
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        if !self.recorded {
            self.gate.lock().in_flight = false;
            self.gate.finished.notify_all();
        }
    }
}

/// 探测结束的 stderr 行（PRODUCT §11.9.5「可观察」）；不含密码及其哈希。
pub(crate) fn log_line(tag: &str, report: &ProbeReport) -> String {
    let (warn, first_bytes_hex) = match report.verdict {
        Verdict::Rejected => (
            "WARN ",
            report
                .first_bytes
                .iter()
                .take(FIRST_BYTES_MAX)
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        ),
        Verdict::Passed | Verdict::Inconclusive => ("", String::new()),
    };
    format!(
        "[nexusd] {warn}trojan credential probe tag={tag} result={} elapsed_ms={} first_bytes_hex={first_bytes_hex}",
        report.verdict.as_str(),
        report.elapsed.as_millis(),
    )
}

/// 探测请求：Trojan 请求头（出站密码、CONNECT、探测目标）+ HTTP GET（`Host` = SNI）。
fn probe_request(password: &str, sni: &str) -> Vec<u8> {
    let target = TrojanTarget::Domain(PROBE_HOST.to_string(), PROBE_PORT);
    let mut request = encode_request(password, &target);
    request.extend_from_slice(
        format!("GET / HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n").as_bytes(),
    );
    request
}

/// 对 `config` 描述的节点执行一次探测。
pub(crate) fn run_probe(config: &TrojanTlsConfig) -> ProbeReport {
    let started = Instant::now();
    let (verdict, first_bytes) = match open_and_send(config) {
        Ok(mut stream) => read_verdict(&mut stream, READ_WINDOW),
        Err(_) => (Verdict::Inconclusive, Vec::new()),
    };
    ProbeReport {
        verdict,
        first_bytes,
        elapsed: started.elapsed(),
    }
}

/// 建连、TLS 握手、写请求；任一阶段失败（含写入时被 reset）→ `Err`（判 inconclusive）。
fn open_and_send(config: &TrojanTlsConfig) -> io::Result<TlsStream> {
    let client = tls::build_client_config(config.skip_cert_verify, &config.alpn)
        .map_err(|_| io::Error::other("TLS client config"))?;
    let server_name = ServerName::try_from(config.sni.clone())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "SNI"))?;
    let connection =
        rustls::ClientConnection::new(Arc::new(client), server_name).map_err(io::Error::other)?;
    let socket = TcpStream::connect_timeout(&config.server, CONNECT_TIMEOUT)?;
    let mut stream = rustls::StreamOwned::new(connection, socket);
    let deadline = Instant::now() + HANDSHAKE_AND_WRITE_TIMEOUT;
    // 握手完成前写入的明文由 rustls 缓存，握手完成后随首批应用数据发出。
    stream
        .conn
        .writer()
        .write_all(&probe_request(&config.password, &config.sni))?;
    while stream.conn.is_handshaking() || stream.conn.wants_write() {
        let remaining = remaining_until(deadline)?;
        stream.sock.set_read_timeout(Some(remaining))?;
        stream.sock.set_write_timeout(Some(remaining))?;
        if stream.conn.wants_write() {
            stream.conn.write_tls(&mut stream.sock)?;
        } else {
            if stream.conn.read_tls(&mut stream.sock)? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            stream
                .conn
                .process_new_packets()
                .map_err(io::Error::other)?;
        }
    }
    Ok(stream)
}

fn remaining_until(deadline: Instant) -> io::Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(io::ErrorKind::TimedOut.into());
    }
    Ok(remaining)
}

/// 读窗口内的判定：任意下行字节 → rejected；零字节 EOF（含无 close_notify）/ reset →
/// passed；窗口耗尽仍无字节 → inconclusive。其他读错误（TLS 告警、解码失败等）不在
/// §11.9.5 的列举内，按无法判定处理（照常拨号、不缓存）。
fn read_verdict(stream: &mut TlsStream, window: Duration) -> (Verdict, Vec<u8>) {
    let deadline = Instant::now() + window;
    let mut buf = [0u8; FIRST_BYTES_MAX];
    loop {
        match stream.conn.reader().read(&mut buf) {
            Ok(0) => return (Verdict::Passed, Vec::new()),
            Ok(n) => return (Verdict::Rejected, buf[..n].to_vec()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return (Verdict::Passed, Vec::new());
            }
            Err(_) => return (Verdict::Inconclusive, Vec::new()),
        }
        let Ok(remaining) = remaining_until(deadline) else {
            return (Verdict::Inconclusive, Vec::new());
        };
        if stream.sock.set_read_timeout(Some(remaining)).is_err() {
            return (Verdict::Inconclusive, Vec::new());
        }
        match stream.conn.read_tls(&mut stream.sock) {
            Ok(_) => {
                if stream.conn.process_new_packets().is_err() {
                    return (Verdict::Inconclusive, Vec::new());
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                ) =>
            {
                return (Verdict::Passed, Vec::new());
            }
            Err(_) => return (Verdict::Inconclusive, Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests;

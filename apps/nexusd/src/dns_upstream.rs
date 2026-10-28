//! Non-blocking upstream DNS engine (§4.2).
//!
//! Owned by the single DNS service thread: no locks, no shared state. The
//! engine keeps a pending table (one nonblocking UDP socket per in-flight
//! query), applies §4.2.3 timeouts/retries/failover, validates responses per
//! R2, falls back to TCP on `TC=1` under the R1 wait rule, and caches positive
//! and negative answers.
//!
//! `DnsReply` is defined here (not in `dns_service`) so this module compiles
//! before the service module lands; `dns_service` re-exports it, keeping the
//! frozen `apps::nexusd::dns_service::DnsReply` path.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use nexus_dns::DnsClass;
use nexus_dns::wire::{self, DnsQuestion, DnsRcode};

use crate::config::UpstreamConfig;

/// Consecutive failures that move a server behind the healthy ones (§4.2.2).
pub const DEGRADED_AFTER: u32 = 3;
/// Hard server cap (§4.2.1).
pub const MAX_SERVERS: usize = 8;

/// A DNS response ready for the dataplane to write back.
#[derive(Debug, Clone)]
pub struct DnsReply {
    /// Original client address (source of the intercepted packet).
    pub client: SocketAddr,
    /// Original query destination (server address/port, usually `:53`).
    pub server: SocketAddr,
    /// Response wire (txid already patched to the client's id).
    pub wire: Vec<u8>,
    /// Classification that produced the answer.
    pub class: DnsClass,
    /// Response RCODE (0/1/2/3/5...).
    pub rcode: u16,
}

/// One cache entry exposed to `/dns/cache` (§4.2.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheEntryView {
    /// Query name (lowercase).
    pub name: String,
    /// Query type (1 = A, 28 = AAAA).
    pub qtype: u16,
    /// Monotonic expiry in ms since engine creation.
    pub expires_at_ms: u64,
    /// Negative (NXDOMAIN / NODATA) entry.
    pub negative: bool,
    /// Cached RCODE.
    pub rcode: u8,
}

/// Engine counters (§6.5 `UpstreamCounters`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UpstreamCounters {
    /// Submissions (cache hits included).
    pub queries: u64,
    /// Positive/negative cache hits.
    pub cache_hits: u64,
    /// Cacheable submissions that missed.
    pub cache_misses: u64,
    /// Same-server resends.
    pub retries: u64,
    /// Server switches.
    pub failovers: u64,
    /// TCP fallbacks attempted.
    pub tcp_fallbacks: u64,
    /// TCP fallbacks that failed.
    pub tcp_fallbacks_failed: u64,
    /// Malformed responses / wrong source / wrong txid.
    pub malformed: u64,
    /// Submissions rejected because `max_inflight` was reached.
    pub overloaded: u64,
}

/// Construction failures (§6.5 `UpstreamInitError`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamInitError {
    /// No servers configured (defensive: `dns.toml` already rejects this).
    NoServers,
    /// More than [`MAX_SERVERS`].
    TooManyServers,
    /// Port 0 (defensive: config already rejects this).
    BadServer(SocketAddr),
}

impl std::fmt::Display for UpstreamInitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoServers => write!(f, "upstream: no servers configured"),
            Self::TooManyServers => write!(f, "upstream: at most {MAX_SERVERS} servers"),
            Self::BadServer(addr) => write!(f, "upstream: bad server {addr}"),
        }
    }
}

impl std::error::Error for UpstreamInitError {}

/// Submission failures (§6.5 `UpstreamSubmitError`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamSubmitError {
    /// `max_inflight` reached; caller must answer SERVFAIL locally.
    Overloaded,
}

/// Per-server health snapshot (feeds `dns_status::UpstreamServerStatus`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamServerSnapshot {
    /// `host:port`.
    pub addr: String,
    /// Successes.
    pub ok: u64,
    /// Failures.
    pub fail: u64,
    /// Consecutive failures.
    pub consecutive_failures: u32,
    /// Last success in ms since engine creation.
    pub last_ok_ms: Option<u64>,
    /// Last failure reason.
    pub last_error: Option<String>,
}

/// UDP/TCP I/O seam. Production uses [`RealTransport`]; tests script it.
trait UpstreamTransport: Send {
    fn bind_udp(&mut self, server: SocketAddr) -> std::io::Result<u64>;
    fn send_udp(&mut self, sock: u64, wire: &[u8], server: SocketAddr) -> std::io::Result<()>;
    fn recv_udp(&mut self, sock: u64) -> std::io::Result<Option<(SocketAddr, Vec<u8>)>>;
    fn close_udp(&mut self, sock: u64);
    fn tcp_query(
        &mut self,
        server: SocketAddr,
        wire: &[u8],
        timeout: Duration,
    ) -> std::io::Result<Vec<u8>>;
}

#[derive(Default)]
struct RealTransport {
    next: u64,
    sockets: HashMap<u64, UdpSocket>,
}

impl UpstreamTransport for RealTransport {
    fn bind_udp(&mut self, server: SocketAddr) -> std::io::Result<u64> {
        let bind: SocketAddr = if server.is_ipv4() {
            "0.0.0.0:0".parse().expect("static bind address")
        } else {
            "[::]:0".parse().expect("static bind address")
        };
        let socket = UdpSocket::bind(bind)?;
        socket.set_nonblocking(true)?;
        self.next += 1;
        let id = self.next;
        self.sockets.insert(id, socket);
        Ok(id)
    }

    fn send_udp(&mut self, sock: u64, wire: &[u8], server: SocketAddr) -> std::io::Result<()> {
        let socket = self
            .sockets
            .get(&sock)
            .ok_or_else(|| std::io::Error::other("unknown dns socket"))?;
        socket.send_to(wire, server)?;
        Ok(())
    }

    fn recv_udp(&mut self, sock: u64) -> std::io::Result<Option<(SocketAddr, Vec<u8>)>> {
        let socket = self
            .sockets
            .get(&sock)
            .ok_or_else(|| std::io::Error::other("unknown dns socket"))?;
        let mut buf = vec![0u8; 4096];
        match socket.recv_from(&mut buf) {
            Ok((n, src)) => {
                buf.truncate(n);
                Ok(Some((src, buf)))
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn close_udp(&mut self, sock: u64) {
        self.sockets.remove(&sock);
    }

    fn tcp_query(
        &mut self,
        server: SocketAddr,
        wire: &[u8],
        timeout: Duration,
    ) -> std::io::Result<Vec<u8>> {
        let mut stream = TcpStream::connect_timeout(&server, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        let len = u16::try_from(wire.len())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "query too long"))?;
        let mut framed = Vec::with_capacity(2 + wire.len());
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(wire);
        stream.write_all(&framed)?;
        let mut len_bytes = [0u8; 2];
        stream.read_exact(&mut len_bytes)?;
        let mut body = vec![0u8; usize::from(u16::from_be_bytes(len_bytes))];
        stream.read_exact(&mut body)?;
        Ok(body)
    }
}

#[derive(Debug, Clone)]
struct ServerState {
    addr: SocketAddr,
    ok: u64,
    fail: u64,
    consecutive_failures: u32,
    last_ok_ms: Option<u64>,
    last_error: Option<String>,
}

impl Default for ServerState {
    fn default() -> Self {
        Self {
            addr: "0.0.0.0:0".parse().expect("static placeholder"),
            ok: 0,
            fail: 0,
            consecutive_failures: 0,
            last_ok_ms: None,
            last_error: None,
        }
    }
}

#[derive(Debug, Clone)]
struct CacheEntry {
    wire: Vec<u8>,
    expires_at: Instant,
    negative: bool,
    rcode: u8,
    name: String,
    qtype: u16,
}

#[derive(Debug)]
struct Inflight {
    client: SocketAddr,
    server: SocketAddr,
    question: DnsQuestion,
    sock: u64,
    txid: u16,
    order: Vec<usize>,
    order_pos: usize,
    server_index: usize,
    attempts: u8,
    sent_at: Instant,
    deadline: Instant,
    edns_size: Option<u16>,
    use_edns: bool,
    edns_retry_done: bool,
}

/// Single-owner upstream engine.
pub struct UpstreamEngine {
    cfg: UpstreamConfig,
    transport: Box<dyn UpstreamTransport>,
    servers: Vec<ServerState>,
    inflight: Vec<Inflight>,
    cache: HashMap<(String, u16), CacheEntry>,
    ready: Vec<DnsReply>,
    counters: UpstreamCounters,
    last_error: Option<String>,
    epoch: Instant,
    txid_counter: u64,
}

impl std::fmt::Debug for UpstreamEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamEngine")
            .field("servers", &self.servers.len())
            .field("inflight", &self.inflight.len())
            .field("cache", &self.cache.len())
            .field("counters", &self.counters)
            .finish()
    }
}

impl UpstreamEngine {
    /// Build with the real UDP/TCP transport.
    ///
    /// # Errors
    ///
    /// See [`UpstreamInitError`].
    pub fn new(cfg: UpstreamConfig) -> Result<Self, UpstreamInitError> {
        Self::with_transport(cfg, Box::new(RealTransport::default()))
    }

    fn with_transport(
        cfg: UpstreamConfig,
        transport: Box<dyn UpstreamTransport>,
    ) -> Result<Self, UpstreamInitError> {
        if cfg.servers.is_empty() {
            return Err(UpstreamInitError::NoServers);
        }
        if cfg.servers.len() > MAX_SERVERS {
            return Err(UpstreamInitError::TooManyServers);
        }
        if let Some(bad) = cfg.servers.iter().find(|s| s.port() == 0) {
            return Err(UpstreamInitError::BadServer(*bad));
        }
        let servers = cfg
            .servers
            .iter()
            .map(|addr| ServerState {
                addr: *addr,
                ..ServerState::default()
            })
            .collect();
        Ok(Self {
            cfg,
            transport,
            servers,
            inflight: Vec::new(),
            cache: HashMap::new(),
            ready: Vec::new(),
            counters: UpstreamCounters::default(),
            last_error: None,
            epoch: Instant::now(),
            txid_counter: 0,
        })
    }

    /// Accept a query and start (or instantly answer) it.
    ///
    /// # Errors
    ///
    /// `Overloaded` when `max_inflight` is reached.
    pub fn submit(
        &mut self,
        client: SocketAddr,
        server: SocketAddr,
        question: DnsQuestion,
        now: Instant,
    ) -> Result<(), UpstreamSubmitError> {
        let name = question.name.to_ascii_lowercase();
        let cacheable = matches!(question.qtype, 1 | 28);

        if cacheable {
            if let Some(entry) = self.cache.get(&(name.clone(), question.qtype)) {
                if now < entry.expires_at {
                    self.counters.queries += 1;
                    self.counters.cache_hits += 1;
                    let mut wire = entry.wire.clone();
                    let rcode = u16::from(entry.rcode);
                    let _ = wire::patch_id(&mut wire, question.id);
                    self.ready.push(DnsReply {
                        client,
                        server,
                        wire,
                        class: DnsClass::Upstream,
                        rcode,
                    });
                    return Ok(());
                }
            }
        }

        if self.inflight.len() >= self.cfg.max_inflight {
            self.counters.overloaded += 1;
            return Err(UpstreamSubmitError::Overloaded);
        }

        self.counters.queries += 1;
        if cacheable {
            self.counters.cache_misses += 1;
        }

        let order = self.ordered_servers();
        let txid = self.next_txid();
        let edns_size = (self.cfg.edns_udp_size != 0).then_some(self.cfg.edns_udp_size);
        let mut inflight = Inflight {
            client,
            server,
            question,
            sock: 0,
            txid,
            order,
            order_pos: 0,
            server_index: 0,
            attempts: 0,
            sent_at: now,
            deadline: now + Duration::from_millis(self.cfg.total_budget_ms),
            edns_size,
            use_edns: edns_size.is_some(),
            edns_retry_done: false,
        };

        // Walk the ordered servers until one accepts the datagram.
        loop {
            let Some(&index) = inflight.order.get(inflight.order_pos) else {
                self.last_error = Some("all-servers-failed".to_string());
                let reply =
                    self.error_reply(&inflight.question, client, server, DnsRcode::ServFail);
                self.ready.push(reply);
                return Ok(());
            };
            inflight.server_index = index;
            match self.send_to(&mut inflight, index, now) {
                Ok(()) => {
                    self.inflight.push(inflight);
                    return Ok(());
                }
                Err(reason) => {
                    self.mark_server_failure(index, &reason, now);
                    inflight.order_pos += 1;
                    inflight.attempts = 0;
                }
            }
        }
    }

    /// Drive in-flight queries and append completed replies.
    pub fn poll(&mut self, now: Instant, out: &mut Vec<DnsReply>) {
        out.append(&mut self.ready);
        let pending = std::mem::take(&mut self.inflight);
        let mut keep = Vec::with_capacity(pending.len());
        for inflight in pending {
            if let Some(still_pending) = self.step(inflight, now, out) {
                keep.push(still_pending);
            }
        }
        self.inflight = keep;
    }

    /// Cache view for `/dns/cache` (sorted for deterministic output).
    #[must_use]
    pub fn cache_snapshot(&self) -> Vec<CacheEntryView> {
        let mut entries: Vec<CacheEntryView> = self
            .cache
            .values()
            .map(|entry| CacheEntryView {
                name: entry.name.clone(),
                qtype: entry.qtype,
                expires_at_ms: entry
                    .expires_at
                    .saturating_duration_since(self.epoch)
                    .as_millis() as u64,
                negative: entry.negative,
                rcode: entry.rcode,
            })
            .collect();
        entries.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.qtype.cmp(&b.qtype)));
        entries
    }

    /// Counters snapshot.
    #[must_use]
    pub fn stats(&self) -> UpstreamCounters {
        self.counters
    }

    /// Per-server health, declaration order.
    #[must_use]
    pub fn server_status(&self) -> Vec<UpstreamServerSnapshot> {
        self.servers
            .iter()
            .map(|server| UpstreamServerSnapshot {
                addr: server.addr.to_string(),
                ok: server.ok,
                fail: server.fail,
                consecutive_failures: server.consecutive_failures,
                last_ok_ms: server.last_ok_ms,
                last_error: server.last_error.clone(),
            })
            .collect()
    }

    /// Last aggregate failure (`budget-exhausted`, `all-servers-failed`).
    #[must_use]
    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    /// Whether any query is still pending (service shutdown drain).
    #[must_use]
    pub fn has_inflight(&self) -> bool {
        !self.inflight.is_empty()
    }

    /// Close sockets and drop pending work.
    pub fn shutdown(&mut self) {
        for inflight in self.inflight.drain(..) {
            self.transport.close_udp(inflight.sock);
        }
    }

    fn step(
        &mut self,
        mut inflight: Inflight,
        now: Instant,
        out: &mut Vec<DnsReply>,
    ) -> Option<Inflight> {
        // Drain first so a TC=1 arriving at the deadline still takes the R1
        // path (immediate give-up + failover) instead of being masked by the
        // budget branch.
        loop {
            match self.transport.recv_udp(inflight.sock) {
                Ok(Some((src, packet))) => {
                    let expected = self.servers[inflight.server_index].addr;
                    if src != expected {
                        self.counters.malformed += 1;
                        continue;
                    }
                    if packet.len() < 2
                        || u16::from_be_bytes([packet[0], packet[1]]) != inflight.txid
                    {
                        self.counters.malformed += 1;
                        continue;
                    }
                    match wire::parse_response(&packet, &inflight.question) {
                        Ok(reply) if reply.truncated => {
                            return self.on_truncated(inflight, now, out);
                        }
                        Ok(reply) => {
                            return self.on_response(inflight, reply, now, out);
                        }
                        Err(_) => {
                            self.counters.malformed += 1;
                            continue;
                        }
                    }
                }
                Ok(None) => break,
                Err(reason) => {
                    return self.advance(inflight, Some(format!("io: {reason}")), now, out);
                }
            }
        }

        // Hard total budget (from submit) unless a packet was just handled.
        if now >= inflight.deadline {
            self.last_error = Some("budget-exhausted".to_string());
            let reply = self.error_reply(
                &inflight.question,
                inflight.client,
                inflight.server,
                DnsRcode::ServFail,
            );
            out.push(reply);
            self.transport.close_udp(inflight.sock);
            return None;
        }

        let attempt_timeout = Duration::from_millis(self.cfg.attempt_timeout_ms);
        if now.saturating_duration_since(inflight.sent_at) >= attempt_timeout {
            if inflight.attempts < self.cfg.attempts_per_server {
                match self.resend(&mut inflight, now) {
                    Ok(()) => {
                        self.counters.retries += 1;
                        return Some(inflight);
                    }
                    Err(reason) => {
                        return self.advance(inflight, Some(reason), now, out);
                    }
                }
            }
            return self.advance(inflight, Some("timeout".to_string()), now, out);
        }

        Some(inflight)
    }

    fn on_response(
        &mut self,
        inflight: Inflight,
        reply: wire::UpstreamReply,
        now: Instant,
        out: &mut Vec<DnsReply>,
    ) -> Option<Inflight> {
        match reply.rcode {
            DnsRcode::ServFail | DnsRcode::Refused => {
                return self.advance(
                    inflight,
                    Some(format!("rcode-{}", reply.rcode.code())),
                    now,
                    out,
                );
            }
            DnsRcode::FormErr => {
                if inflight.use_edns
                    && !inflight.edns_retry_done
                    && inflight.attempts < self.cfg.attempts_per_server
                {
                    let mut inflight = inflight;
                    inflight.use_edns = false;
                    inflight.edns_retry_done = true;
                    match self.resend(&mut inflight, now) {
                        Ok(()) => {
                            self.counters.retries += 1;
                            return Some(inflight);
                        }
                        Err(reason) => {
                            return self.advance(inflight, Some(reason), now, out);
                        }
                    }
                }
                return self.advance(inflight, Some("formerr".to_string()), now, out);
            }
            _ => {}
        }

        self.mark_server_success(inflight.server_index, now);
        self.store_cache(&inflight.question, &reply, now);

        let mut wire = reply.wire.clone();
        let rcode = u16::from(reply.rcode.code());
        if wire::patch_id(&mut wire, inflight.question.id).is_err() {
            let reply = self.error_reply(
                &inflight.question,
                inflight.client,
                inflight.server,
                DnsRcode::ServFail,
            );
            out.push(reply);
        } else {
            out.push(DnsReply {
                client: inflight.client,
                server: inflight.server,
                wire,
                class: DnsClass::Upstream,
                rcode,
            });
        }
        self.transport.close_udp(inflight.sock);
        None
    }

    fn on_truncated(
        &mut self,
        inflight: Inflight,
        now: Instant,
        out: &mut Vec<DnsReply>,
    ) -> Option<Inflight> {
        if !self.cfg.tcp_fallback {
            return self.advance(
                inflight,
                Some("truncated-without-tcp".to_string()),
                now,
                out,
            );
        }
        // R1: actual wait = min(tcp_timeout_ms, total_budget_ms - elapsed).
        let remaining = inflight.deadline.saturating_duration_since(now);
        if remaining.is_zero() {
            self.counters.tcp_fallbacks_failed += 1;
            return self.advance(inflight, Some("tcp-budget-exhausted".to_string()), now, out);
        }
        let wait = Duration::from_millis(self.cfg.tcp_timeout_ms).min(remaining);
        let query = build_upstream_query(
            &inflight.question,
            inflight.txid,
            inflight.use_edns.then_some(self.cfg.edns_udp_size),
        );
        self.counters.tcp_fallbacks += 1;
        let server = self.servers[inflight.server_index].addr;
        match self.transport.tcp_query(server, &query, wait) {
            Ok(bytes) => match wire::parse_response(&bytes, &inflight.question) {
                Ok(reply) if reply.truncated => {
                    self.counters.tcp_fallbacks_failed += 1;
                    self.advance(inflight, Some("tcp-truncated".to_string()), now, out)
                }
                Ok(reply) => self.on_response(inflight, reply, now, out),
                Err(_) => {
                    self.counters.malformed += 1;
                    self.counters.tcp_fallbacks_failed += 1;
                    self.advance(inflight, Some("tcp-malformed".to_string()), now, out)
                }
            },
            Err(reason) => {
                self.counters.tcp_fallbacks_failed += 1;
                self.advance(inflight, Some(format!("tcp: {reason}")), now, out)
            }
        }
    }

    /// Mark the current server failed and move to the next one in the original
    /// order; when exhausted, answer SERVFAIL (never leak the last REFUSED).
    fn advance(
        &mut self,
        mut inflight: Inflight,
        reason: Option<String>,
        now: Instant,
        out: &mut Vec<DnsReply>,
    ) -> Option<Inflight> {
        self.transport.close_udp(inflight.sock);
        inflight.sock = 0;
        if let Some(reason) = reason {
            self.mark_server_failure(inflight.server_index, &reason, now);
        }
        loop {
            inflight.order_pos += 1;
            let Some(&index) = inflight.order.get(inflight.order_pos) else {
                self.last_error = Some("all-servers-failed".to_string());
                let reply = self.error_reply(
                    &inflight.question,
                    inflight.client,
                    inflight.server,
                    DnsRcode::ServFail,
                );
                out.push(reply);
                return None;
            };
            inflight.server_index = index;
            inflight.attempts = 0;
            inflight.use_edns = inflight.edns_size.is_some();
            inflight.edns_retry_done = false;
            match self.send_to(&mut inflight, index, now) {
                Ok(()) => {
                    self.counters.failovers += 1;
                    return Some(inflight);
                }
                Err(reason) => {
                    self.mark_server_failure(index, &reason, now);
                }
            }
        }
    }

    fn send_to(
        &mut self,
        inflight: &mut Inflight,
        index: usize,
        now: Instant,
    ) -> Result<(), String> {
        let server = self.servers[index].addr;
        if inflight.sock == 0 {
            inflight.sock = self
                .transport
                .bind_udp(server)
                .map_err(|e| format!("bind: {e}"))?;
        }
        let query = build_upstream_query(
            &inflight.question,
            inflight.txid,
            inflight.use_edns.then_some(self.cfg.edns_udp_size),
        );
        if query.is_empty() {
            return Err("query-encode-failed".to_string());
        }
        self.transport
            .send_udp(inflight.sock, &query, server)
            .map_err(|e| format!("send: {e}"))?;
        inflight.attempts = inflight.attempts.saturating_add(1);
        inflight.sent_at = now;
        Ok(())
    }

    fn resend(&mut self, inflight: &mut Inflight, now: Instant) -> Result<(), String> {
        let server = self.servers[inflight.server_index].addr;
        let query = build_upstream_query(
            &inflight.question,
            inflight.txid,
            inflight.use_edns.then_some(self.cfg.edns_udp_size),
        );
        if query.is_empty() {
            return Err("query-encode-failed".to_string());
        }
        self.transport
            .send_udp(inflight.sock, &query, server)
            .map_err(|e| format!("send: {e}"))?;
        inflight.attempts = inflight.attempts.saturating_add(1);
        inflight.sent_at = now;
        Ok(())
    }

    fn ordered_servers(&self) -> Vec<usize> {
        let mut healthy = Vec::new();
        let mut degraded = Vec::new();
        for (index, server) in self.servers.iter().enumerate() {
            if server.consecutive_failures >= DEGRADED_AFTER {
                degraded.push(index);
            } else {
                healthy.push(index);
            }
        }
        healthy.extend(degraded);
        healthy
    }

    fn mark_server_success(&mut self, index: usize, now: Instant) {
        let server = &mut self.servers[index];
        server.ok += 1;
        server.consecutive_failures = 0;
        server.last_ok_ms = Some(now.saturating_duration_since(self.epoch).as_millis() as u64);
    }

    fn mark_server_failure(&mut self, index: usize, reason: &str, _now: Instant) {
        let server = &mut self.servers[index];
        server.fail += 1;
        server.consecutive_failures = server.consecutive_failures.saturating_add(1);
        server.last_error = Some(reason.to_string());
    }

    fn store_cache(&mut self, question: &DnsQuestion, reply: &wire::UpstreamReply, now: Instant) {
        if self.cfg.cache_max_entries == 0 || !matches!(question.qtype, 1 | 28) {
            return;
        }
        let name = question.name.to_ascii_lowercase();
        let negative = matches!(reply.rcode, DnsRcode::NxDomain)
            || (reply.rcode == DnsRcode::NoError && reply.records.is_empty());
        let ttl_secs = if negative {
            if self.cfg.negative_ttl_secs == 0 {
                return;
            }
            self.cfg.negative_ttl_secs
        } else if reply.rcode == DnsRcode::NoError {
            if reply.min_ttl_secs == 0 {
                return;
            }
            reply.min_ttl_secs.clamp(1, self.cfg.cache_max_ttl_secs)
        } else {
            return;
        };
        if self.cache.len() >= self.cfg.cache_max_entries {
            if let Some(oldest) = self
                .cache
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(key, _)| key.clone())
            {
                self.cache.remove(&oldest);
            }
        }
        self.cache.insert(
            (name.clone(), question.qtype),
            CacheEntry {
                wire: reply.wire.clone(),
                expires_at: now + Duration::from_secs(u64::from(ttl_secs)),
                negative,
                rcode: reply.rcode.code(),
                name,
                qtype: question.qtype,
            },
        );
    }

    fn error_reply(
        &self,
        question: &DnsQuestion,
        client: SocketAddr,
        server: SocketAddr,
        rcode: DnsRcode,
    ) -> DnsReply {
        let query = build_upstream_query(question, question.id, None);
        let wire = wire::build_error(&query, rcode).unwrap_or_default();
        DnsReply {
            client,
            server,
            wire,
            class: DnsClass::Upstream,
            rcode: u16::from(rcode.code()),
        }
    }

    fn next_txid(&mut self) -> u16 {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hasher};

        self.txid_counter = self.txid_counter.wrapping_add(1);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_u128(nanos);
        hasher.write_u64(self.txid_counter);
        let hashed = hasher.finish();
        (hashed as u16) ^ (hashed >> 16) as u16 ^ self.txid_counter as u16
    }
}

/// Encode an upstream query for an arbitrary QTYPE.
///
/// `wire::build_query` only models A/AAAA (`DnsQuery`), while the upstream
/// passthrough must preserve HTTPS/TXT/PTR; this keeps the same wire shape.
fn build_upstream_query(question: &DnsQuestion, id: u16, edns_size: Option<u16>) -> Vec<u8> {
    let Some(name) = encode_name(&question.name) else {
        return Vec::new();
    };
    let arcount: u16 = if edns_size.is_some() { 1 } else { 0 };
    let mut out = Vec::with_capacity(12 + name.len() + 4 + 11);
    out.extend_from_slice(&id.to_be_bytes());
    let mut flags = 0u16;
    if question.rd {
        flags |= 0x0100;
    }
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&arcount.to_be_bytes());
    out.extend_from_slice(&name);
    out.extend_from_slice(&question.qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // IN
    if let Some(size) = edns_size {
        out.push(0); // root name
        out.extend_from_slice(&41u16.to_be_bytes()); // OPT
        out.extend_from_slice(&size.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
    }
    out
}

fn encode_name(name: &str) -> Option<Vec<u8>> {
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    if trimmed.is_empty() || trimmed.len() > 253 {
        return None;
    }
    let mut out = Vec::with_capacity(trimmed.len() + 2);
    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_dns::wire::WireRecord;
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Clone)]
    enum Script {
        Silent,
        Answer {
            rcode: DnsRcode,
            records: Vec<(u16, IpAddr)>,
            ttl: u32,
        },
        Truncated,
        WrongSource {
            rcode: DnsRcode,
            records: Vec<(u16, IpAddr)>,
            ttl: u32,
        },
        MismatchedTxid {
            rcode: DnsRcode,
            records: Vec<(u16, IpAddr)>,
            ttl: u32,
        },
        MismatchedQuestion,
        Burst(Vec<Script>),
    }

    fn answer(query: &[u8], rcode: DnsRcode, records: &[(u16, IpAddr)], ttl: u32) -> Vec<u8> {
        let records: Vec<WireRecord> = records
            .iter()
            .map(|(rtype, ip)| WireRecord {
                rtype: *rtype,
                ttl_secs: ttl,
                address: Some(*ip),
            })
            .collect();
        wire::build_answer(query, &records, rcode).expect("test response builds")
    }

    #[derive(Default)]
    struct FakeTransport {
        next: u64,
        sent: Vec<(u64, SocketAddr, Vec<u8>)>,
        inbox: HashMap<u64, VecDeque<(SocketAddr, Vec<u8>)>>,
        script: VecDeque<Script>,
        tcp_waits: Vec<Duration>,
        tcp_answer: Option<(DnsRcode, Vec<(u16, IpAddr)>, u32)>,
        tcp_error: bool,
    }

    impl FakeTransport {
        fn push(&mut self, sock: u64, src: SocketAddr, packet: Vec<u8>) {
            self.inbox.entry(sock).or_default().push_back((src, packet));
        }

        fn produce(
            &self,
            script: &Script,
            query: &[u8],
            server: SocketAddr,
        ) -> Vec<(SocketAddr, Vec<u8>)> {
            match script {
                Script::Silent => Vec::new(),
                Script::Answer {
                    rcode,
                    records,
                    ttl,
                } => vec![(server, answer(query, *rcode, records, *ttl))],
                Script::Truncated => {
                    let mut wire = answer(query, DnsRcode::NoError, &[], 0);
                    wire[2] |= 0x02; // TC
                    vec![(server, wire)]
                }
                Script::WrongSource {
                    rcode,
                    records,
                    ttl,
                } => vec![(
                    "203.0.113.9:53".parse().expect("static"),
                    answer(query, *rcode, records, *ttl),
                )],
                Script::MismatchedTxid {
                    rcode,
                    records,
                    ttl,
                } => {
                    let mut wire = answer(query, *rcode, records, *ttl);
                    wire[1] ^= 0xff;
                    vec![(server, wire)]
                }
                Script::MismatchedQuestion => {
                    let question = wire::parse_question(query).expect("query parses");
                    let mut other = question.clone();
                    other.name = "other.example".to_string();
                    let other_query = build_upstream_query(&other, question.id, None);
                    let response = wire::build_answer(&other_query, &[], DnsRcode::NoError)
                        .expect("other response");
                    vec![(server, response)]
                }
                Script::Burst(items) => items
                    .iter()
                    .flat_map(|item| self.produce(item, query, server))
                    .collect(),
            }
        }
    }

    struct SharedFake(Arc<Mutex<FakeTransport>>);

    impl UpstreamTransport for SharedFake {
        fn bind_udp(&mut self, _server: SocketAddr) -> std::io::Result<u64> {
            let mut fake = self.0.lock().expect("fake transport lock");
            fake.next += 1;
            Ok(fake.next)
        }

        fn send_udp(&mut self, sock: u64, wire: &[u8], server: SocketAddr) -> std::io::Result<()> {
            let mut fake = self.0.lock().expect("fake transport lock");
            fake.sent.push((sock, server, wire.to_vec()));
            let script = fake.script.pop_front().unwrap_or(Script::Silent);
            let packets = fake.produce(&script, wire, server);
            for (src, packet) in packets {
                fake.push(sock, src, packet);
            }
            Ok(())
        }

        fn recv_udp(&mut self, sock: u64) -> std::io::Result<Option<(SocketAddr, Vec<u8>)>> {
            let mut fake = self.0.lock().expect("fake transport lock");
            Ok(fake.inbox.entry(sock).or_default().pop_front())
        }

        fn close_udp(&mut self, _sock: u64) {}

        fn tcp_query(
            &mut self,
            _server: SocketAddr,
            wire: &[u8],
            timeout: Duration,
        ) -> std::io::Result<Vec<u8>> {
            let mut fake = self.0.lock().expect("fake transport lock");
            fake.tcp_waits.push(timeout);
            if fake.tcp_error {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "fake tcp timeout",
                ));
            }
            match fake.tcp_answer.clone() {
                Some((rcode, records, ttl)) => Ok(answer(wire, rcode, &records, ttl)),
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "no tcp script",
                )),
            }
        }
    }

    fn default_cfg(servers: Vec<SocketAddr>) -> UpstreamConfig {
        UpstreamConfig {
            servers,
            attempt_timeout_ms: 500,
            attempts_per_server: 2,
            total_budget_ms: 4000,
            edns_udp_size: 1232,
            tcp_fallback: true,
            tcp_timeout_ms: 2000,
            cache_max_entries: 1024,
            cache_max_ttl_secs: 3600,
            negative_ttl_secs: 60,
            max_inflight: 64,
        }
    }

    fn build(
        ports: &[u16],
        tweak: impl FnOnce(&mut UpstreamConfig),
    ) -> (UpstreamEngine, Arc<Mutex<FakeTransport>>) {
        let mut cfg = default_cfg(ports.iter().map(|p| addr(*p)).collect());
        tweak(&mut cfg);
        let fake = Arc::new(Mutex::new(FakeTransport::default()));
        let engine = UpstreamEngine::with_transport(cfg, Box::new(SharedFake(fake.clone())))
            .expect("engine builds");
        (engine, fake)
    }

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().expect("test addr")
    }

    fn client() -> SocketAddr {
        "127.0.0.1:40000".parse().expect("test client")
    }

    fn server() -> SocketAddr {
        "127.0.0.1:53".parse().expect("test server")
    }

    fn question(name: &str, qtype: u16) -> DnsQuestion {
        DnsQuestion {
            id: 0x1234,
            name: name.to_string(),
            qtype,
            rd: true,
            edns_udp_size: None,
        }
    }

    fn sent_to(fake: &Arc<Mutex<FakeTransport>>) -> Vec<SocketAddr> {
        fake.lock()
            .expect("fake transport lock")
            .sent
            .iter()
            .map(|(_, server, _)| *server)
            .collect()
    }

    const A: u16 = 1;
    const AAAA: u16 = 28;

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse::<Ipv4Addr>().expect("v4 literal"))
    }

    #[test]
    fn constants_match_the_frozen_table() {
        assert_eq!(DEGRADED_AFTER, 3);
        assert_eq!(MAX_SERVERS, 8);
    }

    #[test]
    fn attempt_timeout_retries_same_server_then_fails_over() {
        let (mut engine, fake) = build(&[5301, 5302], |cfg| {
            cfg.attempt_timeout_ms = 500;
            cfg.attempts_per_server = 2;
        });
        let t0 = Instant::now();
        engine
            .submit(client(), server(), question("a.example", A), t0)
            .expect("submit");
        assert_eq!(sent_to(&fake), vec![addr(5301)]);

        let mut out = Vec::new();
        engine.poll(t0 + Duration::from_millis(499), &mut out);
        assert!(out.is_empty());
        assert_eq!(fake.lock().expect("fake transport lock").sent.len(), 1);

        engine.poll(t0 + Duration::from_millis(500), &mut out);
        assert_eq!(sent_to(&fake), vec![addr(5301), addr(5301)]);
        assert_eq!(engine.stats().retries, 1);

        engine.poll(t0 + Duration::from_millis(1000), &mut out);
        assert_eq!(sent_to(&fake), vec![addr(5301), addr(5301), addr(5302)]);
        assert_eq!(engine.stats().failovers, 1);
    }

    #[test]
    fn total_budget_exhaustion_answers_servfail() {
        let (mut engine, _fake) = build(&[5301], |cfg| cfg.total_budget_ms = 4000);
        let t0 = Instant::now();
        engine
            .submit(client(), server(), question("slow.example", A), t0)
            .expect("submit");
        let mut out = Vec::new();
        engine.poll(t0 + Duration::from_millis(4000), &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rcode, 2);
        assert_eq!(engine.last_error(), Some("budget-exhausted"));
        assert!(!engine.has_inflight());
    }

    #[test]
    fn r2_rejects_wrong_source_txid_and_question_then_accepts() {
        let (mut engine, fake) = build(&[5301], |cfg| cfg.attempt_timeout_ms = 5000);
        fake.lock()
            .expect("fake transport lock")
            .script
            .push_back(Script::Burst(vec![
                Script::WrongSource {
                    rcode: DnsRcode::NoError,
                    records: vec![(A, v4("1.2.3.4"))],
                    ttl: 60,
                },
                Script::MismatchedTxid {
                    rcode: DnsRcode::NoError,
                    records: vec![(A, v4("1.2.3.4"))],
                    ttl: 60,
                },
                Script::MismatchedQuestion,
                Script::Answer {
                    rcode: DnsRcode::NoError,
                    records: vec![(A, v4("5.6.7.8"))],
                    ttl: 60,
                },
            ]));
        let t0 = Instant::now();
        engine
            .submit(client(), server(), question("r2.example", A), t0)
            .expect("submit");
        let mut out = Vec::new();
        engine.poll(t0 + Duration::from_millis(1), &mut out);
        assert_eq!(engine.stats().malformed, 3);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rcode, 0);
        let parsed = wire::parse_response(&out[0].wire, &question("r2.example", A))
            .expect("reply is a valid response");
        assert_eq!(parsed.records[0].address, Some(v4("5.6.7.8")));
        assert_eq!(&out[0].wire[0..2], &0x1234u16.to_be_bytes());
    }

    #[test]
    fn r1_tcp_wait_is_min_of_timeout_and_remaining_budget() {
        // Plenty of budget: wait = tcp_timeout_ms.
        let (mut engine, fake) = build(&[5301], |cfg| {
            cfg.tcp_timeout_ms = 2000;
            cfg.total_budget_ms = 4000;
        });
        fake.lock()
            .expect("fake transport lock")
            .script
            .push_back(Script::Truncated);
        fake.lock().expect("fake transport lock").tcp_answer =
            Some((DnsRcode::NoError, vec![(A, v4("1.2.3.4"))], 60));
        let t0 = Instant::now();
        engine
            .submit(client(), server(), question("tc.example", A), t0)
            .expect("submit");
        let mut out = Vec::new();
        engine.poll(t0 + Duration::from_millis(100), &mut out);
        assert_eq!(
            fake.lock().expect("fake transport lock").tcp_waits,
            vec![Duration::from_millis(2000)]
        );
        assert_eq!(engine.stats().tcp_fallbacks, 1);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rcode, 0);

        // 500 ms of budget left: wait = 500 ms.
        let (mut engine, fake) = build(&[5301], |cfg| {
            cfg.tcp_timeout_ms = 2000;
            cfg.total_budget_ms = 4000;
        });
        fake.lock()
            .expect("fake transport lock")
            .script
            .push_back(Script::Truncated);
        fake.lock().expect("fake transport lock").tcp_answer =
            Some((DnsRcode::NoError, Vec::new(), 0));
        let t0 = Instant::now();
        engine
            .submit(client(), server(), question("tc2.example", A), t0)
            .expect("submit");
        engine.poll(t0 + Duration::from_millis(3500), &mut out);
        assert_eq!(
            fake.lock().expect("fake transport lock").tcp_waits,
            vec![Duration::from_millis(500)]
        );
    }

    #[test]
    fn r1_zero_remaining_budget_gives_up_tcp_immediately() {
        let (mut engine, fake) = build(&[5301, 5302], |cfg| {
            cfg.tcp_timeout_ms = 2000;
            cfg.total_budget_ms = 4000;
        });
        fake.lock()
            .expect("fake transport lock")
            .script
            .push_back(Script::Truncated);
        let t0 = Instant::now();
        engine
            .submit(client(), server(), question("tc3.example", A), t0)
            .expect("submit");
        let mut out = Vec::new();
        engine.poll(t0 + Duration::from_millis(4000), &mut out);
        assert!(
            fake.lock()
                .expect("fake transport lock")
                .tcp_waits
                .is_empty()
        );
        assert_eq!(engine.stats().tcp_fallbacks_failed, 1);
        assert_eq!(engine.stats().failovers, 1);
        assert_eq!(sent_to(&fake), vec![addr(5301), addr(5302)]);
    }

    #[test]
    fn cache_clamps_ttl_skips_zero_and_caches_negative() {
        let (mut engine, fake) = build(&[5301], |_| {});
        let t0 = Instant::now();

        // Positive with TTL above the cap.
        fake.lock()
            .expect("fake transport lock")
            .script
            .push_back(Script::Answer {
                rcode: DnsRcode::NoError,
                records: vec![(A, v4("1.2.3.4"))],
                ttl: 5000,
            });
        engine
            .submit(client(), server(), question("pos.example", A), t0)
            .expect("submit");
        let mut out = Vec::new();
        engine.poll(t0 + Duration::from_millis(1), &mut out);
        assert_eq!(out.len(), 1);
        let cache = engine.cache_snapshot();
        assert_eq!(cache.len(), 1);
        assert!(cache[0].expires_at_ms >= 3_600_000);
        assert!(cache[0].expires_at_ms <= 3_601_000);
        assert!(!cache[0].negative);

        // Cache hit answers without touching the transport.
        let before = fake.lock().expect("fake transport lock").sent.len();
        engine
            .submit(
                client(),
                server(),
                question("pos.example", A),
                t0 + Duration::from_millis(2),
            )
            .expect("submit");
        engine.poll(t0 + Duration::from_millis(2), &mut out);
        assert_eq!(fake.lock().expect("fake transport lock").sent.len(), before);
        assert_eq!(engine.stats().cache_hits, 1);
        assert_eq!(&out[0].wire[0..2], &0x1234u16.to_be_bytes());

        // TTL 0 is not cached.
        fake.lock()
            .expect("fake transport lock")
            .script
            .push_back(Script::Answer {
                rcode: DnsRcode::NoError,
                records: vec![(A, v4("1.2.3.5"))],
                ttl: 0,
            });
        engine
            .submit(client(), server(), question("zero.example", A), t0)
            .expect("submit");
        engine.poll(t0 + Duration::from_millis(3), &mut out);
        assert!(
            engine
                .cache_snapshot()
                .iter()
                .all(|e| e.name != "zero.example")
        );

        // NXDOMAIN is negatively cached for negative_ttl_secs.
        fake.lock()
            .expect("fake transport lock")
            .script
            .push_back(Script::Answer {
                rcode: DnsRcode::NxDomain,
                records: Vec::new(),
                ttl: 0,
            });
        engine
            .submit(client(), server(), question("nx.example", A), t0)
            .expect("submit");
        engine.poll(t0 + Duration::from_millis(4), &mut out);
        let negative = engine
            .cache_snapshot()
            .into_iter()
            .find(|e| e.name == "nx.example")
            .expect("negative cached");
        assert!(negative.negative);
        assert_eq!(negative.rcode, 3);
        let before = fake.lock().expect("fake transport lock").sent.len();
        engine
            .submit(
                client(),
                server(),
                question("nx.example", A),
                t0 + Duration::from_millis(5),
            )
            .expect("submit");
        engine.poll(t0 + Duration::from_millis(5), &mut out);
        assert_eq!(fake.lock().expect("fake transport lock").sent.len(), before);
    }

    #[test]
    fn capacity_evicts_the_earliest_expiry() {
        let (mut engine, fake) = build(&[5301], |cfg| cfg.cache_max_entries = 2);
        let t0 = Instant::now();
        for (name, ttl) in [("a.example", 100), ("b.example", 200), ("c.example", 300)] {
            fake.lock()
                .expect("fake transport lock")
                .script
                .push_back(Script::Answer {
                    rcode: DnsRcode::NoError,
                    records: vec![(A, v4("1.2.3.4"))],
                    ttl,
                });
            engine
                .submit(client(), server(), question(name, A), t0)
                .expect("submit");
            let mut out = Vec::new();
            engine.poll(t0 + Duration::from_millis(1), &mut out);
        }
        let names: Vec<String> = engine
            .cache_snapshot()
            .into_iter()
            .map(|entry| entry.name)
            .collect();
        assert_eq!(names, vec!["b.example", "c.example"]);
    }

    #[test]
    fn max_inflight_returns_overloaded() {
        let (mut engine, _fake) = build(&[5301], |cfg| cfg.max_inflight = 1);
        let t0 = Instant::now();
        engine
            .submit(client(), server(), question("one.example", A), t0)
            .expect("first accepted");
        assert_eq!(
            engine.submit(client(), server(), question("two.example", A), t0),
            Err(UpstreamSubmitError::Overloaded)
        );
        assert_eq!(engine.stats().overloaded, 1);
    }

    #[test]
    fn formerr_with_edns_retries_once_without_opt() {
        let (mut engine, fake) = build(&[5301], |_| {});
        fake.lock()
            .expect("fake transport lock")
            .script
            .push_back(Script::Answer {
                rcode: DnsRcode::FormErr,
                records: Vec::new(),
                ttl: 0,
            });
        fake.lock()
            .expect("fake transport lock")
            .script
            .push_back(Script::Answer {
                rcode: DnsRcode::NoError,
                records: vec![(A, v4("9.9.9.9"))],
                ttl: 60,
            });
        let t0 = Instant::now();
        engine
            .submit(client(), server(), question("edns.example", A), t0)
            .expect("submit");
        let mut out = Vec::new();
        engine.poll(t0 + Duration::from_millis(1), &mut out);
        let sent = fake.lock().expect("fake transport lock").sent.clone();
        assert_eq!(sent.len(), 2);
        let first = wire::parse_question(&sent[0].2).expect("first query");
        let second = wire::parse_question(&sent[1].2).expect("second query");
        assert_eq!(first.edns_udp_size, Some(1232));
        assert_eq!(second.edns_udp_size, None);
        assert_eq!(engine.stats().retries, 1);
        engine.poll(t0 + Duration::from_millis(2), &mut out);
        assert_eq!(out.last().expect("reply").rcode, 0);
    }

    #[test]
    fn servfail_and_refused_fail_over_to_the_next_server() {
        let (mut engine, fake) = build(&[5301, 5302], |_| {});
        fake.lock()
            .expect("fake transport lock")
            .script
            .push_back(Script::Answer {
                rcode: DnsRcode::Refused,
                records: Vec::new(),
                ttl: 0,
            });
        fake.lock()
            .expect("fake transport lock")
            .script
            .push_back(Script::Answer {
                rcode: DnsRcode::NoError,
                records: vec![(A, v4("8.8.4.4"))],
                ttl: 60,
            });
        let t0 = Instant::now();
        engine
            .submit(client(), server(), question("failover.example", A), t0)
            .expect("submit");
        let mut out = Vec::new();
        engine.poll(t0 + Duration::from_millis(1), &mut out);
        engine.poll(t0 + Duration::from_millis(2), &mut out);
        assert_eq!(engine.stats().failovers, 1);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rcode, 0);
        let status = engine.server_status();
        assert_eq!(status[0].fail, 1);
        assert!(
            status[0]
                .last_error
                .as_deref()
                .unwrap_or("")
                .contains("rcode-5")
        );
    }

    #[test]
    fn three_failures_move_a_server_behind_healthy_ones() {
        let (mut engine, fake) = build(&[5301, 5302], |cfg| {
            cfg.cache_max_entries = 0;
            cfg.attempt_timeout_ms = 500;
            cfg.attempts_per_server = 2;
        });
        let mut out = Vec::new();
        for i in 0..3 {
            fake.lock().expect("fake transport lock").script = VecDeque::from([
                Script::Silent,
                Script::Silent,
                Script::Answer {
                    rcode: DnsRcode::NoError,
                    records: vec![(A, v4("1.1.1.1"))],
                    ttl: 60,
                },
            ]);
            let t = Instant::now() + Duration::from_secs(10 * i);
            engine
                .submit(client(), server(), question(&format!("d{i}.example"), A), t)
                .expect("submit");
            engine.poll(t, &mut out);
            engine.poll(t + Duration::from_millis(500), &mut out);
            engine.poll(t + Duration::from_millis(1000), &mut out);
            engine.poll(t + Duration::from_millis(1001), &mut out);
        }
        assert_eq!(engine.server_status()[0].consecutive_failures, 3);
        assert_eq!(engine.stats().failovers, 3);

        // The next query starts on the healthy server.
        fake.lock().expect("fake transport lock").script = VecDeque::from([Script::Answer {
            rcode: DnsRcode::NoError,
            records: vec![(A, v4("1.1.1.1"))],
            ttl: 60,
        }]);
        let t = Instant::now() + Duration::from_secs(60);
        engine
            .submit(client(), server(), question("after.example", A), t)
            .expect("submit");
        let sent = fake.lock().expect("fake transport lock").sent.clone();
        assert_eq!(sent.last().expect("send").1, addr(5302));
        engine.poll(t + Duration::from_millis(1), &mut out);
    }

    #[test]
    fn non_a_aaaa_qtype_is_preserved_and_not_cached() {
        let (mut engine, fake) = build(&[5301], |_| {});
        for _ in 0..2 {
            fake.lock()
                .expect("fake transport lock")
                .script
                .push_back(Script::Answer {
                    rcode: DnsRcode::NoError,
                    records: Vec::new(),
                    ttl: 0,
                });
        }
        let t0 = Instant::now();
        for round in 0..2 {
            engine
                .submit(
                    client(),
                    server(),
                    question("https.example", 65),
                    t0 + Duration::from_millis(round),
                )
                .expect("submit");
            let mut out = Vec::new();
            engine.poll(t0 + Duration::from_millis(round + 1), &mut out);
        }
        let sent = fake.lock().expect("fake transport lock").sent.clone();
        assert_eq!(sent.len(), 2);
        assert_eq!(wire::parse_question(&sent[0].2).expect("query").qtype, 65);
        assert!(engine.cache_snapshot().is_empty());
    }

    #[test]
    fn aaaa_answers_are_cached_with_the_same_ttl_rules() {
        let (mut engine, fake) = build(&[5301], |_| {});
        fake.lock()
            .expect("fake transport lock")
            .script
            .push_back(Script::Answer {
                rcode: DnsRcode::NoError,
                records: vec![(AAAA, "2001:db8::1".parse().expect("v6"))],
                ttl: 120,
            });
        let t0 = Instant::now();
        engine
            .submit(client(), server(), question("v6.example", AAAA), t0)
            .expect("submit");
        let mut out = Vec::new();
        engine.poll(t0 + Duration::from_millis(1), &mut out);
        let cache = engine.cache_snapshot();
        assert_eq!(cache.len(), 1);
        assert_eq!(cache[0].qtype, AAAA);
        assert!(!cache[0].negative);
    }

    #[test]
    fn init_rejects_empty_and_oversized_server_sets() {
        let mut cfg = default_cfg(Vec::new());
        assert_eq!(
            UpstreamEngine::new(cfg.clone()).expect_err("empty"),
            UpstreamInitError::NoServers
        );
        cfg.servers = (1..=9).map(|i| addr(5300 + i)).collect();
        assert_eq!(
            UpstreamEngine::new(cfg).expect_err("too many"),
            UpstreamInitError::TooManyServers
        );
    }
}

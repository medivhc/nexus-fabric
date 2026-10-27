//! Discovery pump: mDNS and LSA gossip sockets in one thread.
//!
//! The pump owns the sockets and the timers; the discovery state machine itself
//! lives behind [`DiscoveryHub`], so this module only moves bytes and books
//! counters (no protocol re-implementation).
//!
//! Thread = `nexusd-discovery` (mDNS and LSA share it, worst case ~40ms per
//! round). Socket I/O never holds a hub lock: every hub call is
//! `send → hub → send`.
//!
//! Honest boundary (spec §4.8.1 / CR-BLOCKED-1): the advertised SRV target /
//! LSA locator is the discovery/gossip endpoint (`advertise_ip:gossip_port`),
//! **not** an N1 dial target. Production has no N1 inbound listener.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use nexus_discovery::PeerId;
use nexus_discovery::hub::DiscoveryHub;
use nexus_discovery::lsa::{Lsa, LsaFrame, UpdateOutcome, decode_lsa_frame, encode_lsa_frame};

/// mDNS group (RFC 6762).
const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
/// mDNS port.
const MDNS_PORT: u16 = 5353;
/// Socket read timeout per socket per round.
const READ_TIMEOUT: Duration = Duration::from_millis(20);
/// Hard LSA datagram cap (spec §4.9.6).
const LSA_FRAME_CAP: usize = 1200;
/// Max fresh LSAs in a Hello reply.
const MAX_LSAS_PER_REPLY: usize = 64;
/// Spacing between Hello-reply adverts.
const HELLO_REPLY_SPACING: Duration = Duration::from_millis(10);
/// Outbound flood rate (frames per second, global).
const FLOOD_RATE_PER_SEC: usize = 10;

/// Pump configuration (spec §6.5).
#[derive(Debug, Clone)]
pub struct DiscoveryRuntimeConfig {
    pub gossip_bind: SocketAddr,
    pub advertise_ip: Option<Ipv4Addr>,
    pub lsa_enabled: bool,
    pub mdns_enabled: bool,
    pub lsa_hello_interval: Duration,
    pub lsa_self_refresh: Duration,
    pub mdns_announce_interval: Duration,
    /// Static peer addresses with the gossip-port substitution already applied
    /// (all of `N1PeerEntry.addrs`, not just `addrs[0]`).
    pub static_gossip_addrs: Vec<SocketAddr>,
}

/// Self-LSA inputs (spec §4.9.2).
#[derive(Debug, Clone)]
pub struct SelfLsaConfig {
    pub node_id: PeerId,
    pub vip: String,
    pub capabilities: u32,
    pub incarnation: u64,
}

/// Handle owned by the composition root (join on shutdown).
pub struct DiscoveryRuntimeHandle {
    thread: Option<std::thread::JoinHandle<()>>,
    status: Arc<DiscoveryPumpStatus>,
}

impl DiscoveryRuntimeHandle {
    /// Shared pump status (also registered with the LocalAPI snapshot).
    pub fn status(&self) -> Arc<DiscoveryPumpStatus> {
        Arc::clone(&self.status)
    }

    /// Stop has already been requested by the caller; wait up to `timeout` for
    /// the thread to finish. Polls `is_finished` every 10ms; on timeout the
    /// handle is dropped and a WARN is logged (the thread still exits on its
    /// own, the process reclaims it).
    pub fn join(mut self, timeout: Duration) {
        let Some(thread) = self.thread.take() else {
            return;
        };
        let deadline = Instant::now() + timeout;
        while !thread.is_finished() {
            if Instant::now() >= deadline {
                eprintln!(
                    "[discovery] WARN: pump thread did not stop within {}ms",
                    timeout.as_millis()
                );
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = thread.join();
    }
}

/// Discovery pump entry point.
pub struct DiscoveryRuntime;

impl DiscoveryRuntime {
    /// Start the pump thread unless both protocols are disabled.
    pub fn start(
        hub: Arc<DiscoveryHub>,
        cfg: DiscoveryRuntimeConfig,
        self_lsa: SelfLsaConfig,
        stop: Arc<AtomicBool>,
    ) -> DiscoveryRuntimeHandle {
        Self::start_with(
            hub,
            cfg,
            self_lsa,
            stop,
            PumpAddrs::production(),
            Faults::none(),
        )
    }

    fn start_with(
        hub: Arc<DiscoveryHub>,
        cfg: DiscoveryRuntimeConfig,
        self_lsa: SelfLsaConfig,
        stop: Arc<AtomicBool>,
        addrs: PumpAddrs,
        faults: Faults,
    ) -> DiscoveryRuntimeHandle {
        let status = Arc::new(DiscoveryPumpStatus::default());
        if !cfg.mdns_enabled && !cfg.lsa_enabled {
            // Both protocols off: no thread, both statuses stay "disabled".
            return DiscoveryRuntimeHandle {
                thread: None,
                status,
            };
        }
        let thread_status = Arc::clone(&status);
        let thread = std::thread::Builder::new()
            .name("nexusd-discovery".to_string())
            .spawn(move || run_pump(hub, cfg, self_lsa, stop, thread_status, addrs, faults))
            .ok();
        DiscoveryRuntimeHandle { thread, status }
    }
}

/// Internal socket addresses (tests point them at scratch ports).
struct PumpAddrs {
    mdns: SocketAddr,
    gossip: SocketAddr,
}

impl PumpAddrs {
    fn production() -> Self {
        Self {
            mdns: SocketAddr::from((Ipv4Addr::UNSPECIFIED, MDNS_PORT)),
            gossip: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        }
    }
}

/// Test-only fault injection (no production surface).
#[derive(Clone, Copy, Default)]
struct Faults {
    fail_mdns_join: bool,
}

impl Faults {
    fn none() -> Self {
        Self::default()
    }
}

/// Pump status (spec §6.5, additive-free: the frozen shape is untouched).
pub struct DiscoveryPumpStatus {
    inner: std::sync::Mutex<DiscoveryPumpStatusSnapshot>,
}

impl Default for DiscoveryPumpStatus {
    fn default() -> Self {
        Self {
            inner: std::sync::Mutex::new(DiscoveryPumpStatusSnapshot {
                mdns: "disabled",
                lsa: "disabled",
                ..DiscoveryPumpStatusSnapshot::default()
            }),
        }
    }
}

impl DiscoveryPumpStatus {
    /// Current snapshot.
    #[must_use]
    pub fn snapshot(&self) -> DiscoveryPumpStatusSnapshot {
        self.inner
            .lock()
            .map(|g| g.clone())
            .unwrap_or_else(|e| e.into_inner().clone())
    }

    fn update(&self, f: impl FnOnce(&mut DiscoveryPumpStatusSnapshot)) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut g);
    }
}

/// Published discovery counters (spec §6.5).
#[derive(Debug, Clone)]
pub struct DiscoveryPumpStatusSnapshot {
    pub mdns: &'static str,
    pub lsa: &'static str,
    pub mdns_cached_peers: usize,
    pub lsa_lsdb_entries: usize,
    pub lsa_fresh_peers: usize,
    pub mdns_queries_sent: u64,
    pub mdns_announces_sent: u64,
    pub lsa_hellos_sent: u64,
    pub lsa_adverts_sent: u64,
    pub lsa_adverts_recv: u64,
    pub lsa_floods_sent: u64,
    pub lsa_floods_suppressed: u64,
    pub lsa_decode_errors: u64,
    pub lsa_frame_too_large: u64,
    pub last_error: Option<String>,
}

impl Default for DiscoveryPumpStatusSnapshot {
    fn default() -> Self {
        Self {
            mdns: "disabled",
            lsa: "disabled",
            mdns_cached_peers: 0,
            lsa_lsdb_entries: 0,
            lsa_fresh_peers: 0,
            mdns_queries_sent: 0,
            mdns_announces_sent: 0,
            lsa_hellos_sent: 0,
            lsa_adverts_sent: 0,
            lsa_adverts_recv: 0,
            lsa_floods_sent: 0,
            lsa_floods_suppressed: 0,
            lsa_decode_errors: 0,
            lsa_frame_too_large: 0,
            last_error: None,
        }
    }
}

/// Pump failures (spec §5.1, frozen variant set).
#[derive(Debug)]
pub enum DiscoveryPumpError {
    GossipBind(io::Error),
    MdnsBind(io::Error),
    MdnsJoinMulticast(io::Error),
    AdvertiseIpUnavailable,
    InvalidGossipPort(u16),
    FrameDecode(String),
    FrameTooLarge { len: usize },
    FloodRateLimited,
}

impl std::fmt::Display for DiscoveryPumpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiscoveryPumpError::GossipBind(e) => write!(f, "gossip bind failed ({e})"),
            DiscoveryPumpError::MdnsBind(e) => write!(f, "mdns bind failed ({e})"),
            DiscoveryPumpError::MdnsJoinMulticast(e) => {
                write!(f, "mdns join multicast failed ({e})")
            }
            DiscoveryPumpError::AdvertiseIpUnavailable => f.write_str("no advertise IPv4"),
            DiscoveryPumpError::InvalidGossipPort(p) => write!(f, "invalid gossip port {p}"),
            DiscoveryPumpError::FrameDecode(e) => write!(f, "decode error ({e})"),
            DiscoveryPumpError::FrameTooLarge { len } => write!(f, "frame too large ({len}B)"),
            DiscoveryPumpError::FloodRateLimited => f.write_str("flood rate limited"),
        }
    }
}

impl std::error::Error for DiscoveryPumpError {}

/// Select the IPv4 address to advertise (spec §4.8.4).
///
/// Filters unspecified/loopback/multicast/broadcast/link-local, sorts and
/// dedupes, then prefers a private address. `None` when nothing usable exists.
pub fn select_advertise_ipv4() -> Option<Ipv4Addr> {
    let mut addrs: Vec<Ipv4Addr> = Vec::new();
    #[cfg(target_os = "linux")]
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return None;
        }
        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_addr.is_null() && (*ifa.ifa_addr).sa_family as i32 == libc::AF_INET {
                let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                let ip = Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
                let link_local = ip.octets()[0] == 169 && ip.octets()[1] == 254;
                if !ip.is_unspecified()
                    && !ip.is_loopback()
                    && !ip.is_multicast()
                    && !ip.is_broadcast()
                    && !link_local
                {
                    addrs.push(ip);
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    addrs.sort();
    addrs.dedup();
    let is_private = |ip: &Ipv4Addr| {
        let o = ip.octets();
        o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
    };
    addrs
        .iter()
        .find(|ip| is_private(ip))
        .copied()
        .or_else(|| addrs.first().copied())
}

// ---------- pump core (state machine + counters, no sockets) ----------

#[derive(Default)]
struct PumpCounters {
    mdns_queries_sent: u64,
    mdns_announces_sent: u64,
    lsa_hellos_sent: u64,
    lsa_adverts_sent: u64,
    lsa_adverts_recv: u64,
    lsa_floods_sent: u64,
    lsa_floods_suppressed: u64,
    lsa_decode_errors: u64,
    lsa_frame_too_large: u64,
}

/// Global outbound flood rate limiter (10 frames/s).
#[derive(Default)]
struct FloodLimiter {
    window_start: Option<Instant>,
    count: usize,
}

impl FloodLimiter {
    fn allow(&mut self, now: Instant) -> bool {
        match self.window_start {
            Some(start) if now.saturating_duration_since(start) < Duration::from_secs(1) => {
                if self.count >= FLOOD_RATE_PER_SEC {
                    return false;
                }
            }
            _ => {
                self.window_start = Some(now);
                self.count = 0;
            }
        }
        self.count += 1;
        true
    }
}

/// Discovery state machine driver: turns datagrams into outbound datagrams and
/// keeps the counters. The socket loop below is the only other participant.
/// One datagram to send, plus the spacing to honour before sending it
/// (Hello replies are paced; floods are not).
struct Outbound {
    target: SocketAddr,
    bytes: Vec<u8>,
    spacing: Duration,
}

struct PumpCore {
    hub: Arc<DiscoveryHub>,
    cfg: DiscoveryRuntimeConfig,
    self_lsa: Lsa,
    counters: PumpCounters,
    limiter: FloodLimiter,
    /// Neighbours learned from Hello ingress (kept for the session).
    learned_neighbours: Vec<SocketAddr>,
}

impl PumpCore {
    fn new(hub: Arc<DiscoveryHub>, cfg: DiscoveryRuntimeConfig, self_lsa: SelfLsaConfig) -> Self {
        let locator = cfg
            .advertise_ip
            .map(|ip| format!("udp://{ip}:{}", cfg.gossip_bind.port()));
        let lsa = Lsa {
            node_id: self_lsa.node_id,
            vip: self_lsa.vip,
            incarnation: self_lsa.incarnation.max(1),
            seq: 1,
            capabilities: self_lsa.capabilities,
            locator,
            neighbors: Vec::new(),
        };
        Self {
            hub,
            cfg,
            self_lsa: lsa,
            counters: PumpCounters::default(),
            limiter: FloodLimiter::default(),
            learned_neighbours: Vec::new(),
        }
    }

    /// Publish the self LSA once at start-up.
    fn publish_self(&self, now: Instant) {
        self.hub.set_self_lsa(self.self_lsa.clone(), now);
    }

    /// Neighbour set: static gossip addrs ∪ discovered candidates, minus self.
    fn neighbours(&self, now: Instant) -> Vec<SocketAddr> {
        let mut out: Vec<SocketAddr> = Vec::new();
        for addr in &self.cfg.static_gossip_addrs {
            out.push(*addr);
        }
        for resolved in self.hub.neighbor_candidates(now) {
            out.push(resolved.addr);
        }
        out.extend(self.learned_neighbours.iter().copied());
        if let Some(ip) = self.cfg.advertise_ip {
            let own = SocketAddr::V4(SocketAddrV4::new(ip, self.cfg.gossip_bind.port()));
            out.retain(|a| *a != own);
        }
        out.sort();
        out.dedup();
        out
    }

    /// Encode with the 1200-byte cap; returns `None` (and counts) when too big.
    fn encode(
        &mut self,
        frame: &LsaFrame,
        target: SocketAddr,
    ) -> Option<(SocketAddr, Vec<u8>, Duration)> {
        self.encode_spaced(frame, target, Duration::ZERO)
    }

    fn encode_spaced(
        &mut self,
        frame: &LsaFrame,
        target: SocketAddr,
        spacing: Duration,
    ) -> Option<(SocketAddr, Vec<u8>, Duration)> {
        let bytes = match encode_lsa_frame(frame) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[discovery-lsa] WARN: encode error ({e})");
                return None;
            }
        };
        if bytes.len() > LSA_FRAME_CAP {
            self.counters.lsa_frame_too_large += 1;
            eprintln!(
                "[discovery-lsa] WARN: frame too large ({}B); dropped",
                bytes.len()
            );
            return None;
        }
        Some((target, bytes, spacing))
    }

    /// Periodic Hello to every neighbour.
    fn hello_datagrams(&mut self, now: Instant) -> Vec<Outbound> {
        let frame = LsaFrame::Hello {
            node_id: self.self_lsa.node_id.clone(),
            vip: self.self_lsa.vip.clone(),
            capabilities: self.self_lsa.capabilities,
            incarnation: self.self_lsa.incarnation,
        };
        let mut out = Vec::new();
        for target in self.neighbours(now) {
            if let Some((target, bytes, spacing)) = self.encode(&frame, target) {
                out.push(Outbound {
                    target,
                    bytes,
                    spacing,
                });
                self.counters.lsa_hellos_sent += 1;
            }
        }
        out
    }

    /// Periodic self LSA refresh.
    fn self_refresh_datagrams(&mut self, now: Instant) -> Vec<Outbound> {
        let frame = LsaFrame::LsaAdvert {
            lsa: self.self_lsa.clone(),
        };
        let mut out = Vec::new();
        for target in self.neighbours(now) {
            if let Some((target, bytes, spacing)) = self.encode(&frame, target) {
                out.push(Outbound {
                    target,
                    bytes,
                    spacing,
                });
                self.counters.lsa_adverts_sent += 1;
            }
        }
        out
    }

    /// Handle one LSA datagram; returns the datagrams to send.
    fn on_lsa_datagram(&mut self, data: &[u8], from: SocketAddr, now: Instant) -> Vec<Outbound> {
        if data.len() > LSA_FRAME_CAP {
            self.counters.lsa_frame_too_large += 1;
            eprintln!(
                "[discovery-lsa] WARN: frame too large ({}B); dropped",
                data.len()
            );
            return Vec::new();
        }
        let frame = match decode_lsa_frame(data) {
            Ok(f) => f,
            Err(e) => {
                self.counters.lsa_decode_errors += 1;
                eprintln!("[discovery-lsa] WARN: decode error ({e}) from {from}");
                return Vec::new();
            }
        };
        match frame {
            LsaFrame::Hello { node_id, .. } => {
                if node_id != self.self_lsa.node_id {
                    self.hub.note_lsa_heard(&node_id, now);
                    if !self.learned_neighbours.contains(&from) {
                        self.learned_neighbours.push(from);
                    }
                }
                self.hello_reply(from, now)
            }
            LsaFrame::LsaAdvert { lsa } => {
                self.counters.lsa_adverts_recv += 1;
                self.apply_advert(lsa, Some(from), now)
            }
            LsaFrame::Welcome { lsas } => {
                // We never send Welcome; accept up to 64 entries defensively.
                let take = lsas.len().min(MAX_LSAS_PER_REPLY);
                if lsas.len() > MAX_LSAS_PER_REPLY {
                    eprintln!(
                        "[discovery-lsa] WARN: Welcome carries {} entries; processing first {MAX_LSAS_PER_REPLY}",
                        lsas.len()
                    );
                }
                let mut out = Vec::new();
                for lsa in lsas.into_iter().take(take) {
                    out.extend(self.apply_advert(lsa, Some(from), now));
                }
                out
            }
        }
    }

    /// Reply to a Hello: fresh remote LSAs (max 64, 10ms apart) + self LSA.
    fn hello_reply(&mut self, from: SocketAddr, now: Instant) -> Vec<Outbound> {
        let _ = now;
        let mut out = Vec::new();
        for lsa in self.hub.all_lsas().into_iter().take(MAX_LSAS_PER_REPLY) {
            if let Some((target, bytes, spacing)) =
                self.encode_spaced(&LsaFrame::LsaAdvert { lsa }, from, HELLO_REPLY_SPACING)
            {
                out.push(Outbound {
                    target,
                    bytes,
                    spacing,
                });
                self.counters.lsa_adverts_sent += 1;
            }
        }
        if let Some((target, bytes, spacing)) = self.encode(
            &LsaFrame::LsaAdvert {
                lsa: self.self_lsa.clone(),
            },
            from,
        ) {
            out.push(Outbound {
                target,
                bytes,
                spacing,
            });
            self.counters.lsa_adverts_sent += 1;
        }
        out
    }

    /// Apply one received advert; returns flood output (ingress excluded).
    fn apply_advert(
        &mut self,
        lsa: Lsa,
        ingress: Option<SocketAddr>,
        now: Instant,
    ) -> Vec<Outbound> {
        let flood = self
            .hub
            .should_flood(&lsa.node_id, lsa.incarnation, lsa.seq);
        let outcome = self.hub.upsert_lsa(lsa.clone(), now);
        self.hub.note_lsa_heard(&lsa.node_id, now);
        let interesting = matches!(outcome, UpdateOutcome::New | UpdateOutcome::Updated);
        if !interesting || !flood {
            self.counters.lsa_floods_suppressed += 1;
            return Vec::new();
        }
        let frame = LsaFrame::LsaAdvert { lsa };
        let mut out = Vec::new();
        for target in self.neighbours(now) {
            if Some(target) == ingress {
                continue;
            }
            if !self.limiter.allow(now) {
                self.counters.lsa_floods_suppressed += 1;
                continue;
            }
            if let Some((target, bytes, spacing)) = self.encode(&frame, target) {
                out.push(Outbound {
                    target,
                    bytes,
                    spacing,
                });
                self.counters.lsa_floods_sent += 1;
            }
        }
        out
    }

    /// Publish counters + hub-derived gauges into the shared status.
    fn publish(&self, status: &DiscoveryPumpStatus, now: Instant) {
        status.update(|s| {
            s.mdns_cached_peers = self.hub.mdns_cached_peers();
            s.lsa_lsdb_entries = self.hub.lsdb_len();
            s.lsa_fresh_peers = self.hub.fresh_lsa_peers(now).len();
            s.mdns_queries_sent = self.counters.mdns_queries_sent;
            s.mdns_announces_sent = self.counters.mdns_announces_sent;
            s.lsa_hellos_sent = self.counters.lsa_hellos_sent;
            s.lsa_adverts_sent = self.counters.lsa_adverts_sent;
            s.lsa_adverts_recv = self.counters.lsa_adverts_recv;
            s.lsa_floods_sent = self.counters.lsa_floods_sent;
            s.lsa_floods_suppressed = self.counters.lsa_floods_suppressed;
            s.lsa_decode_errors = self.counters.lsa_decode_errors;
            s.lsa_frame_too_large = self.counters.lsa_frame_too_large;
        });
    }
}

// ---------- socket loop ----------

fn log_pump_warning(err: &DiscoveryPumpError) {
    match err {
        DiscoveryPumpError::MdnsBind(e) => {
            eprintln!("[discovery-mdns] WARN: bind failed ({e}); mdns disabled");
        }
        DiscoveryPumpError::MdnsJoinMulticast(e) => {
            eprintln!("[discovery-mdns] WARN: join multicast failed ({e}); mdns disabled");
        }
        DiscoveryPumpError::GossipBind(e) => {
            eprintln!("[discovery-lsa] WARN: bind failed ({e}); lsa disabled");
        }
        DiscoveryPumpError::AdvertiseIpUnavailable => {
            eprintln!("[discovery-mdns] WARN: no advertise IPv4; mdns disabled");
        }
        DiscoveryPumpError::InvalidGossipPort(p) => {
            eprintln!("[discovery-lsa] WARN: invalid gossip port {p}; lsa disabled");
        }
        _ => {}
    }
}

fn bind_mdns(addr: SocketAddr) -> io::Result<socket2::Socket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    Ok(socket)
}

fn join_mdns(socket: &socket2::Socket, faults: Faults) -> io::Result<()> {
    if faults.fail_mdns_join {
        return Err(io::Error::other("injected join failure"));
    }
    let group = std::net::Ipv4Addr::UNSPECIFIED;
    socket.join_multicast_v4(&MDNS_GROUP, &group)
}

fn run_pump(
    hub: Arc<DiscoveryHub>,
    cfg: DiscoveryRuntimeConfig,
    self_lsa: SelfLsaConfig,
    stop: Arc<AtomicBool>,
    status: Arc<DiscoveryPumpStatus>,
    addrs: PumpAddrs,
    faults: Faults,
) {
    let mut core = PumpCore::new(Arc::clone(&hub), cfg.clone(), self_lsa);
    let now = Instant::now();
    core.publish_self(now);

    // --- mDNS socket (optional, with explicit degradation reasons) ---
    let mut mdns_socket: Option<std::net::UdpSocket> = None;
    if cfg.mdns_enabled {
        match cfg.advertise_ip {
            None => {
                // No advertise address: never attempt a bind (spec §4.8.4).
                let err = DiscoveryPumpError::AdvertiseIpUnavailable;
                log_pump_warning(&err);
                status.update(|s| {
                    s.mdns = "disabled";
                    s.last_error = Some("advertise-ip-unavailable".to_string());
                });
            }
            Some(_) => {
                let bind_addr = addrs.mdns;
                match bind_mdns(bind_addr) {
                    Ok(socket) => {
                        let shadow = socket;
                        match join_mdns(&shadow, faults) {
                            Ok(()) => {
                                if let Err(e) = shadow.set_read_timeout(Some(READ_TIMEOUT)) {
                                    eprintln!(
                                        "[discovery-mdns] WARN: read timeout setup failed ({e})"
                                    );
                                }
                                mdns_socket = Some(std::net::UdpSocket::from(shadow));
                                status.update(|s| s.mdns = "enabled");
                            }
                            Err(e) => {
                                let err = DiscoveryPumpError::MdnsJoinMulticast(e);
                                log_pump_warning(&err);
                                status.update(|s| {
                                    s.mdns = "degraded:join";
                                    s.last_error = Some("mdns-join-failed".to_string());
                                });
                            }
                        }
                    }
                    Err(e) => {
                        let err = DiscoveryPumpError::MdnsBind(e);
                        log_pump_warning(&err);
                        status.update(|s| {
                            s.mdns = "degraded:bind";
                            s.last_error = Some("mdns-bind-failed".to_string());
                        });
                    }
                }
            }
        }
    }

    // --- LSA gossip socket (optional) ---
    let gossip_port = cfg.gossip_bind.port();
    let mut lsa_socket: Option<std::net::UdpSocket> = None;
    if cfg.lsa_enabled {
        if gossip_port == 0 {
            let err = DiscoveryPumpError::InvalidGossipPort(gossip_port);
            log_pump_warning(&err);
            status.update(|s| {
                s.lsa = "degraded:config";
                s.last_error = Some("gossip-port-invalid".to_string());
            });
        } else {
            let bind_addr = SocketAddr::new(addrs.gossip.ip(), gossip_port);
            match std::net::UdpSocket::bind(bind_addr) {
                Ok(sock) => {
                    if let Err(e) = sock.set_read_timeout(Some(READ_TIMEOUT)) {
                        eprintln!("[discovery-lsa] WARN: read timeout setup failed ({e})");
                    }
                    lsa_socket = Some(sock);
                    status.update(|s| s.lsa = "enabled");
                }
                Err(e) => {
                    let err = DiscoveryPumpError::GossipBind(e);
                    log_pump_warning(&err);
                    status.update(|s| {
                        s.lsa = "degraded:bind";
                        s.last_error = Some("gossip-bind-failed".to_string());
                    });
                }
            }
        }
    }

    // --- timers ---
    let mut next_hello = Instant::now();
    let mut next_refresh = Instant::now() + cfg.lsa_self_refresh;
    let mut next_mdns_announce = Instant::now();
    let mut mdns_send_warned: Option<Instant> = None;
    let mut buf = [0u8; 2048];

    while !stop.load(Ordering::SeqCst) {
        let now = Instant::now();

        // mDNS: announce/query then drain the socket.
        if let Some(sock) = &mdns_socket {
            if now >= next_mdns_announce {
                next_mdns_announce = now + cfg.mdns_announce_interval;
                let target = SocketAddr::from((MDNS_GROUP, MDNS_PORT));
                if let Some(query) = hub.mdns_query() {
                    match sock.send_to(&query, target) {
                        Ok(_) => core.counters.mdns_queries_sent += 1,
                        Err(e) => {
                            if mdns_send_warned
                                .map(|at| {
                                    now.saturating_duration_since(at) >= Duration::from_secs(60)
                                })
                                .unwrap_or(true)
                            {
                                mdns_send_warned = Some(now);
                                eprintln!("[discovery-mdns] WARN: send failed ({e})");
                            }
                        }
                    }
                }
                if let Some(announce) = hub.mdns_announce() {
                    match sock.send_to(&announce, target) {
                        Ok(_) => core.counters.mdns_announces_sent += 1,
                        Err(e) => {
                            if mdns_send_warned
                                .map(|at| {
                                    now.saturating_duration_since(at) >= Duration::from_secs(60)
                                })
                                .unwrap_or(true)
                            {
                                mdns_send_warned = Some(now);
                                eprintln!("[discovery-mdns] WARN: send failed ({e})");
                            }
                        }
                    }
                }
            }
            loop {
                match sock.recv_from(&mut buf) {
                    Ok((n, _from)) => {
                        let replies = hub.mdns_handle_datagram(&buf[..n], Instant::now());
                        let target = SocketAddr::from((MDNS_GROUP, MDNS_PORT));
                        for reply in replies {
                            let _ = sock.send_to(&reply, target);
                        }
                    }
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::TimedOut =>
                    {
                        break;
                    }
                    Err(_) => break,
                }
            }
            hub.mdns_prune(Instant::now());
        }

        // LSA: hellos, self refresh, drain the socket.
        if let Some(sock) = &lsa_socket {
            if now >= next_hello {
                next_hello = now + cfg.lsa_hello_interval;
                for dgram in core.hello_datagrams(now) {
                    let _ = sock.send_to(&dgram.bytes, dgram.target);
                }
            }
            if now >= next_refresh {
                next_refresh = now + cfg.lsa_self_refresh;
                for dgram in core.self_refresh_datagrams(now) {
                    let _ = sock.send_to(&dgram.bytes, dgram.target);
                }
            }
            loop {
                match sock.recv_from(&mut buf) {
                    Ok((n, from)) => {
                        let out = core.on_lsa_datagram(&buf[..n], from, Instant::now());
                        for dgram in out {
                            // Hello replies are paced (spec §4.9.4).
                            if !dgram.spacing.is_zero() {
                                std::thread::sleep(dgram.spacing);
                            }
                            let _ = sock.send_to(&dgram.bytes, dgram.target);
                        }
                    }
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::TimedOut =>
                    {
                        break;
                    }
                    Err(_) => break,
                }
            }
        }

        core.publish(&status, Instant::now());
        std::thread::sleep(Duration::from_millis(20));
    }

    // Final publish so the status reflects the last round at shutdown.
    core.publish(&status, Instant::now());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(byte: u8) -> PeerId {
        PeerId(format!("{byte:02x}").repeat(32))
    }

    fn cfg_with_neighbour(neighbour: SocketAddr) -> DiscoveryRuntimeConfig {
        DiscoveryRuntimeConfig {
            gossip_bind: "127.0.0.1:19010".parse().unwrap(),
            advertise_ip: Some(Ipv4Addr::new(10, 0, 0, 1)),
            lsa_enabled: true,
            mdns_enabled: false,
            lsa_hello_interval: Duration::from_secs(30),
            lsa_self_refresh: Duration::from_secs(30),
            mdns_announce_interval: Duration::from_secs(60),
            static_gossip_addrs: vec![neighbour],
        }
    }

    fn core_with(hub: Arc<DiscoveryHub>, cfg: DiscoveryRuntimeConfig) -> PumpCore {
        PumpCore::new(
            hub,
            cfg,
            SelfLsaConfig {
                node_id: peer(0x11),
                vip: "10.99.0.1".to_string(),
                capabilities: 0x04,
                incarnation: 1,
            },
        )
    }

    fn advert(byte: u8, seq: u64) -> Vec<u8> {
        encode_lsa_frame(&LsaFrame::LsaAdvert {
            lsa: Lsa {
                node_id: peer(byte),
                vip: "10.99.0.2".to_string(),
                incarnation: 1,
                seq,
                capabilities: 0,
                locator: Some(format!("udp://10.0.0.{}:19010", byte.max(1))),
                neighbors: Vec::new(),
            },
        })
        .unwrap()
    }

    #[test]
    fn decode_error_counted() {
        let hub = Arc::new(DiscoveryHub::new(
            peer(0x11),
            Vec::new(),
            None,
            Duration::from_secs(90),
        ));
        let mut core = core_with(hub, cfg_with_neighbour("127.0.0.1:19011".parse().unwrap()));
        let now = Instant::now();
        let out = core.on_lsa_datagram(b"not-a-frame", "127.0.0.1:50000".parse().unwrap(), now);
        assert!(out.is_empty());
        assert_eq!(core.counters.lsa_decode_errors, 1);
    }

    #[test]
    fn flood_dedup_and_rate_cap() {
        let hub = Arc::new(DiscoveryHub::new(
            peer(0x11),
            Vec::new(),
            None,
            Duration::from_secs(90),
        ));
        let neighbour: SocketAddr = "127.0.0.1:19011".parse().unwrap();
        let core_hub = Arc::clone(&hub);
        let mut core = core_with(core_hub, cfg_with_neighbour(neighbour));
        let now = Instant::now();
        let ingress: SocketAddr = "127.0.0.1:50001".parse().unwrap();

        // First advert: forwarded to the neighbour (flood).
        let out = core.on_lsa_datagram(&advert(0x21, 1), ingress, now);
        assert!(!out.is_empty());
        assert!(out.iter().any(|d| d.target == neighbour));
        // The peer's own locator is a discovered neighbour too, so more than one
        // copy can leave; every copy is counted as a flood send.
        assert_eq!(core.counters.lsa_floods_sent as usize, out.len());
        assert_eq!(core.counters.lsa_adverts_recv, 1);

        // Duplicate (same node/incarnation/seq): suppressed, no forward.
        let out = core.on_lsa_datagram(&advert(0x21, 1), ingress, now);
        assert!(out.is_empty());
        assert_eq!(core.counters.lsa_floods_suppressed, 1);

        // Rate cap: more than 10 fresh adverts within one second are dropped.
        let mut forwarded = 0;
        for seq in 2..=15 {
            let out = core.on_lsa_datagram(&advert(0x22, seq), ingress, now);
            forwarded += out.len();
        }
        assert!(
            forwarded <= FLOOD_RATE_PER_SEC,
            "flood rate cap must drop excess frames (forwarded {forwarded})"
        );
        assert!(core.counters.lsa_floods_suppressed >= 4);

        // Oversized frame (1210B) is dropped and counted, never decoded.
        let before = core.counters.lsa_frame_too_large;
        let out = core.on_lsa_datagram(&[0u8; 1210], ingress, now);
        assert!(out.is_empty());
        assert_eq!(core.counters.lsa_frame_too_large, before + 1);
    }

    #[test]
    fn hello_reply_is_bounded() {
        let hub = Arc::new(DiscoveryHub::new(
            peer(0x11),
            Vec::new(),
            None,
            Duration::from_secs(90),
        ));
        let now = Instant::now();
        for i in 0x40..0x40 + 70u8 {
            hub.upsert_lsa(
                Lsa {
                    node_id: peer(i),
                    vip: "10.99.0.1".to_string(),
                    incarnation: 1,
                    seq: 1,
                    capabilities: 0,
                    locator: Some(format!("udp://10.1.1.{}:19010", i)),
                    neighbors: Vec::new(),
                },
                now,
            );
        }
        let mut core = core_with(
            Arc::clone(&hub),
            cfg_with_neighbour("127.0.0.1:19011".parse().unwrap()),
        );
        let hello = encode_lsa_frame(&LsaFrame::Hello {
            node_id: peer(0x31),
            vip: "10.99.0.9".to_string(),
            capabilities: 0,
            incarnation: 1,
        })
        .unwrap();
        let from: SocketAddr = "127.0.0.1:50002".parse().unwrap();
        let out = core.on_lsa_datagram(&hello, from, now);
        // 64 fresh LSAs + self LSA.
        assert_eq!(out.len(), MAX_LSAS_PER_REPLY + 1);
        assert_eq!(
            core.counters.lsa_adverts_sent as usize,
            MAX_LSAS_PER_REPLY + 1
        );
        assert_eq!(hub.lsdb_len(), 70);
    }

    #[test]
    fn select_advertise_ipv4_never_unspecified() {
        if let Some(ip) = select_advertise_ipv4() {
            assert!(!ip.is_unspecified());
            assert!(!ip.is_loopback());
            assert!(!ip.is_multicast());
        }
    }

    // ---------- degradation matrix (AC7) ----------

    fn start_and_join(
        cfg: DiscoveryRuntimeConfig,
        addrs: PumpAddrs,
    ) -> DiscoveryPumpStatusSnapshot {
        start_and_join_with(cfg, addrs, Faults::none())
    }

    fn start_and_join_with(
        cfg: DiscoveryRuntimeConfig,
        addrs: PumpAddrs,
        faults: Faults,
    ) -> DiscoveryPumpStatusSnapshot {
        let hub = Arc::new(DiscoveryHub::new(
            peer(0x11),
            Vec::new(),
            None,
            Duration::from_secs(90),
        ));
        let stop = Arc::new(AtomicBool::new(false));
        let handle = DiscoveryRuntime::start_with(
            hub,
            cfg,
            SelfLsaConfig {
                node_id: peer(0x11),
                vip: "10.99.0.1".to_string(),
                capabilities: 0,
                incarnation: 1,
            },
            Arc::clone(&stop),
            addrs,
            faults,
        );
        let status = handle.status();
        // Give the thread a moment to reach the loop, then stop it.
        std::thread::sleep(Duration::from_millis(80));
        stop.store(true, Ordering::SeqCst);
        handle.join(Duration::from_secs(2));
        status.snapshot()
    }

    fn base_cfg() -> DiscoveryRuntimeConfig {
        DiscoveryRuntimeConfig {
            gossip_bind: "127.0.0.1:0".parse().unwrap(),
            advertise_ip: None,
            lsa_enabled: true,
            mdns_enabled: true,
            lsa_hello_interval: Duration::from_secs(30),
            lsa_self_refresh: Duration::from_secs(30),
            mdns_announce_interval: Duration::from_secs(60),
            static_gossip_addrs: Vec::new(),
        }
    }

    /// Occupy a UDP port without SO_REUSEADDR so our bind must fail.
    fn occupied_port() -> (std::net::UdpSocket, u16) {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = sock.local_addr().unwrap().port();
        (sock, port)
    }

    #[test]
    fn degrade_no_advertise_ip() {
        let cfg = DiscoveryRuntimeConfig {
            advertise_ip: None,
            lsa_enabled: false,
            mdns_enabled: true,
            ..base_cfg()
        };
        let snap = start_and_join(cfg, PumpAddrs::production());
        assert_eq!(snap.mdns, "disabled");
        assert_eq!(snap.last_error.as_deref(), Some("advertise-ip-unavailable"));
    }

    #[test]
    fn degrade_invalid_gossip_port() {
        let cfg = DiscoveryRuntimeConfig {
            gossip_bind: "127.0.0.1:0".parse().unwrap(),
            mdns_enabled: false,
            ..base_cfg()
        };
        // Port 0 is intercepted before any bind attempt.
        let snap = start_and_join(cfg, PumpAddrs::production());
        assert_eq!(snap.lsa, "degraded:config");
        assert_eq!(snap.last_error.as_deref(), Some("gossip-port-invalid"));
    }

    #[test]
    fn degrade_gossip_bind() {
        let (_sock, port) = occupied_port();
        let cfg = DiscoveryRuntimeConfig {
            gossip_bind: format!("127.0.0.1:{port}").parse().unwrap(),
            mdns_enabled: false,
            ..base_cfg()
        };
        let snap = start_and_join(cfg, PumpAddrs::production());
        assert_eq!(snap.lsa, "degraded:bind");
        assert_eq!(snap.last_error.as_deref(), Some("gossip-bind-failed"));
    }

    #[test]
    fn degrade_mdns_join() {
        let cfg = DiscoveryRuntimeConfig {
            advertise_ip: Some(Ipv4Addr::new(10, 0, 0, 1)),
            lsa_enabled: false,
            mdns_enabled: true,
            ..base_cfg()
        };
        let addrs = PumpAddrs {
            mdns: "127.0.0.1:0".parse().unwrap(),
            gossip: "127.0.0.1:0".parse().unwrap(),
        };
        let snap = start_and_join_with(
            cfg,
            addrs,
            Faults {
                fail_mdns_join: true,
            },
        );
        assert_eq!(snap.mdns, "degraded:join");
        assert_eq!(snap.last_error.as_deref(), Some("mdns-join-failed"));
    }

    #[test]
    fn degrade_mdns_bind() {
        let (_sock, port) = occupied_port();
        let cfg = DiscoveryRuntimeConfig {
            advertise_ip: Some(Ipv4Addr::new(10, 0, 0, 1)),
            lsa_enabled: false,
            mdns_enabled: true,
            ..base_cfg()
        };
        let addrs = PumpAddrs {
            mdns: format!("127.0.0.1:{port}").parse().unwrap(),
            gossip: "127.0.0.1:0".parse().unwrap(),
        };
        let snap = start_and_join(cfg, addrs);
        assert_eq!(snap.mdns, "degraded:bind");
        assert_eq!(snap.last_error.as_deref(), Some("mdns-bind-failed"));
    }
}

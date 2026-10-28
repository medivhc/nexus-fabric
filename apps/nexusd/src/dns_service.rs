//! Single-owner DNS service thread (§4.1).
//!
//! The dataplane submits `DnsRequest`s through a bounded channel; this thread
//! owns `UnifiedDns`, `FakeIpPool`, `UpstreamEngine` and all upstream sockets,
//! so none of that state needs a lock. Replies flow back through a second
//! bounded channel and are written by the dataplane (C11).
//!
//! Queue sizes, tick period, reclaim interval and join timeout are frozen
//! constants (§4.2.3 / §4.1). Shutdown drops the request sender, drains
//! in-flight queries for at most [`JOIN_TIMEOUT`], then marks the status
//! `failed` and exits.

pub use crate::dns_upstream::DnsReply;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::time::{Duration, Instant};

use nexus_dns::wire::{self, DnsRcode, WireRecord};
use nexus_dns::{
    DnsClass, DnsError, DnsQuery, ProxyClassifier, ResolveStep, StaticMeshResolver, UnifiedDns,
};

use crate::config::DnsFileConfig;
use crate::dns_classify::{DnsProxyClassifier, usable_outbound};
use crate::dns_status::{
    DnsClassStates, DnsCounters, DnsProxyPolicyStatus, DnsServiceState, DnsStatus,
    DnsStatusSnapshot, FakeIpStatus, UnmatchedPolicy, UpstreamServerStatus, UpstreamStatus,
};
use crate::dns_upstream::{DEGRADED_AFTER, UpstreamEngine};

/// dataplane → DNS thread queue (§4.2.3).
pub const DNS_REQUEST_QUEUE: usize = 256;
/// DNS thread → dataplane queue (§4.2.3).
pub const DNS_REPLY_QUEUE: usize = 256;
/// TCP-fallback queue bound; full → that query SERVFAILs (§4.2.3).
pub const TCP_WORKER_QUEUE: usize = 32;
/// Idle poll interval while driving retries/timeouts (§4.2.3).
pub const TICK_MS: u64 = 5;
/// Upper bound for fake-IP reclamation scans (§4.2.3).
pub const RECLAIM_INTERVAL_SECS: u64 = 60;
/// Shutdown join budget (§4.1).
pub const JOIN_TIMEOUT: Duration = Duration::from_secs(2);
/// TTL for local (hosts/mesh/fake-IP) answers; not part of the query schema.
const LOCAL_TTL_SECS: u32 = 300;

/// One query handed to the DNS thread.
#[derive(Debug, Clone)]
pub struct DnsRequest {
    /// Source address of the intercepted packet.
    pub client: SocketAddr,
    /// Original destination (server address, usually `:53`).
    pub server: SocketAddr,
    /// Raw DNS query.
    pub wire: Vec<u8>,
}

/// Submission failure (`§5.4`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRequestError {
    /// Request queue full.
    QueueFull,
    /// Thread exited / channel disconnected.
    ServiceDown,
}

impl std::fmt::Display for DnsRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QueueFull => write!(f, "dns request queue full"),
            Self::ServiceDown => write!(f, "dns service down"),
        }
    }
}

impl std::error::Error for DnsRequestError {}

/// Handle held by `run_dataplane`.
pub struct DnsServiceHandle {
    /// Request channel (bounded).
    pub tx: SyncSender<DnsRequest>,
    /// Reply channel (bounded).
    pub rx: Receiver<DnsReply>,
    /// Live status.
    pub status: Arc<DnsStatus>,
    /// DNS thread; `None` after a successful join.
    pub thread: Option<std::thread::JoinHandle<()>>,
}

impl DnsServiceHandle {
    /// Non-blocking submit.
    ///
    /// # Errors
    ///
    /// [`DnsRequestError::QueueFull`] / [`DnsRequestError::ServiceDown`].
    pub fn submit(&self, request: DnsRequest) -> Result<(), DnsRequestError> {
        try_submit(&self.tx, request)
    }

    /// Join with a budget; returns `false` on timeout (never hangs).
    pub fn join(&mut self, timeout: Duration) -> bool {
        let Some(thread) = self.thread.as_ref() else {
            return true;
        };
        let deadline = Instant::now() + timeout;
        while !thread.is_finished() {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        true
    }
}

impl std::fmt::Debug for DnsServiceHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsServiceHandle")
            .field("status", &self.status.snapshot())
            .finish_non_exhaustive()
    }
}

/// DNS service factory (no public fields).
#[derive(Debug)]
pub struct DnsService;

impl DnsService {
    /// Start the DNS thread.
    ///
    /// `status` is filled with the real startup snapshot before the thread is
    /// spawned; the caller publishes it (D-impl-9).
    ///
    /// # Errors
    ///
    /// Invalid classifier/upstream config, or thread spawn failure.
    pub fn start(
        config: DnsFileConfig,
        proxy_yaml: Option<&str>,
        status: Arc<DnsStatus>,
    ) -> std::io::Result<DnsServiceHandle> {
        let invalid =
            |detail: String| std::io::Error::new(std::io::ErrorKind::InvalidInput, detail);

        let unevaluable_hits = Arc::new(AtomicU64::new(0));
        let (classifier, rules, unevaluable_rules, default_proxied): (
            Box<dyn ProxyClassifier>,
            usize,
            usize,
            bool,
        ) = match proxy_yaml {
            Some(yaml) => {
                let usable = usable_outbound(yaml).map_err(|e| invalid(e.to_string()))?;
                let classifier = DnsProxyClassifier::from_yaml(yaml, config.proxy.clone(), usable)
                    .map_err(|e| invalid(e.to_string()))?;
                let rules = classifier.rule_count();
                let unevaluable_rules = classifier.unevaluable_count();
                let default_proxied = classifier.default_proxied();
                let counting = CountingClassifier {
                    inner: classifier,
                    hits: Arc::clone(&unevaluable_hits),
                };
                (
                    Box::new(counting),
                    rules,
                    unevaluable_rules,
                    default_proxied,
                )
            }
            None => {
                if config.proxy.unmatched == UnmatchedPolicy::Proxied {
                    return Err(invalid(
                        "dns.unmatched=proxied requires a usable outbound".to_string(),
                    ));
                }
                (Box::new(NoProxyClassifier), 0, 0, false)
            }
        };

        let mesh = StaticMeshResolver::new(config.mesh_hosts.clone())
            .map_err(|e| invalid(format!("dns.mesh.hosts: {e}")))?;
        let unified = UnifiedDns::new(
            config.unified.clone(),
            Box::new(mesh),
            classifier,
            Box::new(NoUpstream),
        )
        .map_err(|e| invalid(format!("dns unified: {e}")))?;
        let engine = UpstreamEngine::new(config.upstream.clone())
            .map_err(|e| invalid(format!("dns upstream: {e}")))?;

        let mut snapshot = DnsStatusSnapshot {
            enabled: true,
            service: DnsServiceState::Running,
            config_generation: 1,
            classes: DnsClassStates {
                hosts: !config.unified.hosts.is_empty(),
                mesh: !config.mesh_hosts.is_empty(),
                proxy_classifier: proxy_yaml.is_some(),
                upstream: true,
            },
            proxy_policy: DnsProxyPolicyStatus {
                unmatched: config.proxy.unmatched,
                unevaluable: config.proxy.unevaluable,
                rules,
                unevaluable_rules,
                default_proxied,
            },
            upstream: UpstreamStatus {
                state: "ok".to_string(),
                plaintext: true,
                servers: config
                    .upstream
                    .servers
                    .iter()
                    .map(|addr| UpstreamServerStatus {
                        addr: addr.to_string(),
                        ok: 0,
                        fail: 0,
                        consecutive_failures: 0,
                        last_ok_ms: None,
                        last_error: None,
                    })
                    .collect(),
                last_error: None,
            },
            counters: DnsCounters::default(),
            fake_ip: FakeIpStatus {
                enabled: config.unified.fake_ip_enabled,
                allocated: unified.fake_ip_count(),
                capacity: unified.fake_ip_capacity(),
                exhausted: 0,
            },
        };
        snapshot.upstream.state = "ok".to_string();
        status.update(|current| *current = snapshot.clone());

        let (req_tx, req_rx) = sync_channel::<DnsRequest>(DNS_REQUEST_QUEUE);
        let (reply_tx, reply_rx) = sync_channel::<DnsReply>(DNS_REPLY_QUEUE);

        let worker_status = Arc::clone(&status);
        let thread = std::thread::Builder::new()
            .name("nexusd-dns".to_string())
            .spawn(move || {
                run_worker(
                    unified,
                    engine,
                    req_rx,
                    reply_tx,
                    worker_status,
                    snapshot,
                    unevaluable_hits,
                );
            })
            .map_err(|e| {
                status.update(|s| {
                    s.service = DnsServiceState::Failed;
                    s.upstream.last_error = Some(format!("thread spawn failed: {e}"));
                });
                e
            })?;

        Ok(DnsServiceHandle {
            tx: req_tx,
            rx: reply_rx,
            status,
            thread: Some(thread),
        })
    }
}

struct NoUpstream;

impl nexus_dns::Resolver for NoUpstream {
    fn resolve(&mut self, _query: &DnsQuery) -> Result<Vec<IpAddr>, DnsError> {
        Err(DnsError::ResolutionFailed(
            "dns service owns upstream I/O".to_string(),
        ))
    }
}

struct NoProxyClassifier;

impl ProxyClassifier for NoProxyClassifier {
    fn is_proxied(&self, _domain: &str) -> bool {
        false
    }
}

struct CountingClassifier {
    inner: DnsProxyClassifier,
    hits: Arc<AtomicU64>,
}

impl ProxyClassifier for CountingClassifier {
    fn is_proxied(&self, domain: &str) -> bool {
        let outcome = self.inner.evaluate(domain);
        if outcome.is_unevaluable() {
            self.hits.fetch_add(1, Ordering::Relaxed);
        }
        outcome.proxied()
    }
}

fn try_submit(tx: &SyncSender<DnsRequest>, request: DnsRequest) -> Result<(), DnsRequestError> {
    match tx.try_send(request) {
        Ok(()) => Ok(()),
        Err(TrySendError::Full(_)) => Err(DnsRequestError::QueueFull),
        Err(TrySendError::Disconnected(_)) => Err(DnsRequestError::ServiceDown),
    }
}

#[derive(Default)]
struct LocalCounters {
    queries_total: u64,
    malformed: u64,
    exhausted: u64,
}

fn run_worker(
    mut unified: UnifiedDns,
    mut engine: UpstreamEngine,
    request_rx: Receiver<DnsRequest>,
    reply_tx: SyncSender<DnsReply>,
    status: Arc<DnsStatus>,
    mut snapshot: DnsStatusSnapshot,
    unevaluable_hits: Arc<AtomicU64>,
) {
    let start = Instant::now();
    let mut last_reclaim = 0;
    let mut local = LocalCounters::default();
    let mut reply_buf = Vec::new();

    loop {
        let mut disconnected = false;
        match request_rx.recv_timeout(Duration::from_millis(TICK_MS)) {
            Ok(request) => {
                handle_request(
                    &mut unified,
                    &mut engine,
                    request,
                    start,
                    &mut local,
                    &reply_tx,
                );
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => disconnected = true,
        }
        if !disconnected {
            // Drain a bounded batch so a burst cannot starve upstream polling.
            for _ in 0..DNS_REQUEST_QUEUE {
                match request_rx.try_recv() {
                    Ok(request) => handle_request(
                        &mut unified,
                        &mut engine,
                        request,
                        start,
                        &mut local,
                        &reply_tx,
                    ),
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                }
            }
        }

        let now = Instant::now();
        reply_buf.clear();
        engine.poll(now, &mut reply_buf);
        for reply in reply_buf.drain(..) {
            let _ = reply_tx.try_send(reply);
        }

        let now_secs = now.saturating_duration_since(start).as_secs();
        if now_secs >= last_reclaim + RECLAIM_INTERVAL_SECS {
            unified.reclaim_expired(now_secs);
            last_reclaim = now_secs;
        }

        refresh_status(&mut snapshot, &engine, &unified, &local, &unevaluable_hits);
        status.update(|current| *current = snapshot.clone());

        if disconnected {
            // Drain in-flight queries for at most the join budget.
            let deadline = Instant::now() + JOIN_TIMEOUT;
            while engine.has_inflight() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(TICK_MS));
                let now = Instant::now();
                reply_buf.clear();
                engine.poll(now, &mut reply_buf);
                for reply in reply_buf.drain(..) {
                    let _ = reply_tx.try_send(reply);
                }
            }
            engine.shutdown();
            status.update(|s| s.service = DnsServiceState::Failed);
            break;
        }
    }
}

fn refresh_status(
    snapshot: &mut DnsStatusSnapshot,
    engine: &UpstreamEngine,
    unified: &UnifiedDns,
    local: &LocalCounters,
    unevaluable_hits: &Arc<AtomicU64>,
) {
    let stats = engine.stats();
    snapshot.counters = DnsCounters {
        queries_total: local.queries_total,
        malformed_queries: local.malformed,
        cache_hits: stats.cache_hits,
        cache_misses: stats.cache_misses,
        upstream_retries: stats.retries,
        upstream_failovers: stats.failovers,
        tcp_fallbacks: stats.tcp_fallbacks,
        tcp_fallbacks_failed: stats.tcp_fallbacks_failed,
        overloaded: stats.overloaded,
        classify_unevaluable: unevaluable_hits.load(Ordering::Relaxed),
    };
    snapshot.fake_ip = FakeIpStatus {
        enabled: snapshot.fake_ip.enabled,
        allocated: unified.fake_ip_count(),
        capacity: unified.fake_ip_capacity(),
        exhausted: local.exhausted,
    };
    let servers = engine.server_status();
    let all_failed = !servers.is_empty()
        && servers
            .iter()
            .all(|s| s.consecutive_failures >= DEGRADED_AFTER);
    let any_degraded = servers
        .iter()
        .any(|s| s.consecutive_failures >= DEGRADED_AFTER);
    snapshot.upstream.state = if all_failed {
        "failed"
    } else if any_degraded {
        "degraded"
    } else {
        "ok"
    }
    .to_string();
    snapshot.upstream.servers = servers
        .into_iter()
        .map(|server| UpstreamServerStatus {
            addr: server.addr,
            ok: server.ok,
            fail: server.fail,
            consecutive_failures: server.consecutive_failures,
            last_ok_ms: server.last_ok_ms,
            last_error: server.last_error,
        })
        .collect();
    snapshot.upstream.last_error = engine.last_error().map(str::to_string);
    snapshot.service = DnsServiceState::Running;
}

fn handle_request(
    unified: &mut UnifiedDns,
    engine: &mut UpstreamEngine,
    request: DnsRequest,
    start: Instant,
    local: &mut LocalCounters,
    reply_tx: &SyncSender<DnsReply>,
) {
    let question = match wire::parse_question(&request.wire) {
        Ok(question) => question,
        Err(wire::DnsWireError::Truncated) => {
            // No trustworthy txid: drop, never answer (§5.2 / §5.7 R2).
            local.malformed += 1;
            return;
        }
        Err(wire::DnsWireError::BadHeader | wire::DnsWireError::BadName) => {
            local.malformed += 1;
            local.queries_total += 1;
            if let Ok(wire) = wire::build_error(&request.wire, DnsRcode::FormErr) {
                let _ = reply_tx.try_send(DnsReply {
                    client: request.client,
                    server: request.server,
                    wire,
                    class: DnsClass::Upstream,
                    rcode: 1,
                });
            }
            return;
        }
        Err(_) => {
            local.malformed += 1;
            return;
        }
    };
    local.queries_total += 1;
    let now_secs = Instant::now().saturating_duration_since(start).as_secs();

    if let Some(qtype) = question.as_dns_type() {
        let query = DnsQuery {
            name: question.name.clone(),
            qtype,
        };
        match unified.step(&query, now_secs) {
            Ok(ResolveStep::Local(answer)) => {
                if let Some(wire) =
                    build_local_answer(&request.wire, &answer.records, DnsRcode::NoError)
                {
                    let _ = reply_tx.try_send(DnsReply {
                        client: request.client,
                        server: request.server,
                        wire,
                        class: answer.class,
                        rcode: 0,
                    });
                }
            }
            Ok(ResolveStep::Upstream { class }) => {
                unified.note_upstream_answer();
                match engine.submit(request.client, request.server, question, Instant::now()) {
                    Ok(()) => {}
                    Err(_) => {
                        send_error(reply_tx, &request, class, DnsRcode::ServFail);
                    }
                }
            }
            Err(error) => {
                let class = unified.classify(&question.name);
                let rcode = error_rcode(&error);
                if matches!(error, DnsError::ResolutionFailed(_)) {
                    local.exhausted += 1;
                }
                send_error(reply_tx, &request, class, rcode);
            }
        }
        return;
    }

    // Non-A/AAAA: Hosts/Mesh/FakeIp answer NODATA; Upstream forwards the query
    // with its original qtype (D-impl-4).
    let class = unified.classify(&question.name);
    if class == DnsClass::Upstream {
        unified.note_upstream_answer();
        match engine.submit(request.client, request.server, question, Instant::now()) {
            Ok(()) => {}
            Err(_) => send_error(reply_tx, &request, class, DnsRcode::ServFail),
        }
    } else if let Some(wire) = build_local_answer(&request.wire, &[], DnsRcode::NoError) {
        let _ = reply_tx.try_send(DnsReply {
            client: request.client,
            server: request.server,
            wire,
            class,
            rcode: 0,
        });
    }
}

fn error_rcode(error: &DnsError) -> DnsRcode {
    match error {
        DnsError::NameNotFound(_) => DnsRcode::NxDomain,
        DnsError::InvalidQuery(_) => DnsRcode::FormErr,
        DnsError::LoopDetected(_) => DnsRcode::Refused,
        DnsError::ResolutionFailed(_)
        | DnsError::NegativeCached(_)
        | DnsError::UnknownServer(_) => DnsRcode::ServFail,
    }
}

fn send_error(
    reply_tx: &SyncSender<DnsReply>,
    request: &DnsRequest,
    class: DnsClass,
    rcode: DnsRcode,
) {
    if let Ok(wire) = wire::build_error(&request.wire, rcode) {
        let _ = reply_tx.try_send(DnsReply {
            client: request.client,
            server: request.server,
            wire,
            class,
            rcode: u16::from(rcode.code()),
        });
    }
}

fn build_local_answer(query: &[u8], records: &[IpAddr], rcode: DnsRcode) -> Option<Vec<u8>> {
    let records: Vec<WireRecord> = records
        .iter()
        .map(|ip| WireRecord {
            rtype: if ip.is_ipv4() { 1 } else { 28 },
            ttl_secs: LOCAL_TTL_SECS,
            address: Some(*ip),
        })
        .collect();
    wire::build_answer(query, &records, rcode).ok()
}

/// Query types used by the service tests.
#[cfg(test)]
fn a_query(name: &str, id: u16) -> Vec<u8> {
    wire::build_query(
        &DnsQuery {
            name: name.to_string(),
            qtype: nexus_dns::DnsType::A,
        },
        id,
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DnsProxyPolicy, UpstreamConfig};
    use crate::dns_status::UnevaluablePolicy;
    use nexus_dns::DnsUnifiedConfig;

    fn config_with_hosts(hosts: Vec<(String, IpAddr)>) -> DnsFileConfig {
        let mut unified = DnsUnifiedConfig::default();
        unified.upstream = vec!["127.0.0.1:5399".to_string()];
        unified.hosts = hosts;
        DnsFileConfig {
            unified,
            mesh_hosts: Vec::new(),
            proxy: DnsProxyPolicy {
                unmatched: UnmatchedPolicy::Auto,
                unevaluable: UnevaluablePolicy::Proxied,
            },
            upstream: UpstreamConfig {
                servers: vec!["127.0.0.1:5399".parse().expect("test upstream")],
                attempt_timeout_ms: 50,
                attempts_per_server: 1,
                total_budget_ms: 50,
                edns_udp_size: 0,
                tcp_fallback: false,
                tcp_timeout_ms: 100,
                cache_max_entries: 0,
                cache_max_ttl_secs: 1,
                negative_ttl_secs: 0,
                max_inflight: 1,
            },
        }
    }

    fn start(hosts: Vec<(String, IpAddr)>) -> DnsServiceHandle {
        let status = Arc::new(DnsStatus::new(DnsStatusSnapshot::disabled()));
        DnsService::start(config_with_hosts(hosts), None, status).expect("service starts")
    }

    fn request(wire: Vec<u8>) -> DnsRequest {
        DnsRequest {
            client: "127.0.0.1:40000".parse().expect("client"),
            server: "127.0.0.1:53".parse().expect("server"),
            wire,
        }
    }

    fn wait_for(mut predicate: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if predicate() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        false
    }

    #[test]
    fn constants_are_frozen() {
        assert_eq!(DNS_REQUEST_QUEUE, 256);
        assert_eq!(DNS_REPLY_QUEUE, 256);
        assert_eq!(TCP_WORKER_QUEUE, 32);
        assert_eq!(TICK_MS, 5);
        assert_eq!(RECLAIM_INTERVAL_SECS, 60);
        assert_eq!(JOIN_TIMEOUT, Duration::from_secs(2));
    }

    #[test]
    fn local_hosts_query_round_trip() {
        let handle = start(vec![(
            "host.example".to_string(),
            "10.1.2.3".parse().expect("host ip"),
        )]);
        handle
            .submit(request(a_query("host.example", 0x4242)))
            .expect("submit");
        let reply = handle
            .rx
            .recv_timeout(Duration::from_secs(2))
            .expect("reply");
        assert_eq!(reply.rcode, 0);
        assert_eq!(reply.class, DnsClass::Hosts);
        let question = wire::parse_question(&a_query("host.example", 0x4242)).expect("question");
        let parsed = wire::parse_response(&reply.wire, &question).expect("valid response");
        assert_eq!(
            parsed.records[0].address,
            Some("10.1.2.3".parse().expect("host ip"))
        );
        assert_eq!(&reply.wire[0..2], &0x4242u16.to_be_bytes());

        assert!(wait_for(
            || handle.status.snapshot().counters.queries_total == 1
        ));
        let snapshot = handle.status.snapshot();
        assert_eq!(snapshot.service, DnsServiceState::Running);
        assert!(snapshot.enabled);
        assert!(snapshot.classes.hosts);
        assert!(!snapshot.classes.proxy_classifier);
        assert!(snapshot.classes.upstream);
        assert!(snapshot.fake_ip.capacity > 0);
    }

    #[test]
    fn malformed_short_query_is_dropped_and_counted() {
        let handle = start(Vec::new());
        handle.submit(request(vec![0u8; 5])).expect("submit");
        assert!(handle.rx.recv_timeout(Duration::from_millis(200)).is_err());
        assert!(wait_for(|| {
            handle.status.snapshot().counters.malformed_queries == 1
        }));
    }

    #[test]
    fn bad_header_returns_formerr_and_is_counted() {
        let handle = start(Vec::new());
        // 12-byte header with QDCOUNT=0 → BadHeader.
        let mut wire = vec![0u8; 12];
        wire[0..2].copy_from_slice(&0x7788u16.to_be_bytes());
        handle.submit(request(wire)).expect("submit");
        let reply = handle
            .rx
            .recv_timeout(Duration::from_secs(2))
            .expect("reply");
        assert_eq!(reply.rcode, 1);
        assert_eq!(&reply.wire[0..2], &0x7788u16.to_be_bytes());
    }

    #[test]
    fn queue_full_and_service_down_map_to_request_errors() {
        let (tx, rx) = sync_channel::<DnsRequest>(1);
        let req = request(a_query("q.example", 1));
        try_submit(&tx, req.clone()).expect("first fits");
        assert_eq!(
            try_submit(&tx, req.clone()),
            Err(DnsRequestError::QueueFull)
        );
        drop(rx);
        assert_eq!(try_submit(&tx, req), Err(DnsRequestError::ServiceDown));
    }

    #[test]
    fn shutdown_exits_without_hanging_and_marks_failed() {
        let mut handle = start(Vec::new());
        let status = Arc::clone(&handle.status);
        let thread = handle.thread.take().expect("thread");
        drop(handle); // drops the only request sender → worker disconnects
        let deadline = Instant::now() + Duration::from_secs(2);
        while !thread.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(thread.is_finished(), "DNS thread must exit within 2 s");
        thread.join().expect("thread joins");
        assert_eq!(status.snapshot().service, DnsServiceState::Failed);
    }

    #[test]
    fn startup_rejects_proxied_policy_without_proxy_yaml() {
        let mut config = config_with_hosts(Vec::new());
        config.proxy.unmatched = UnmatchedPolicy::Proxied;
        let status = Arc::new(DnsStatus::new(DnsStatusSnapshot::disabled()));
        let error = DnsService::start(config, None, status).expect_err("must reject");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn startup_reports_real_classes_and_upstream_servers() {
        let handle = start(Vec::new());
        let snapshot = handle.status.snapshot();
        assert_eq!(snapshot.service, DnsServiceState::Running);
        assert_eq!(snapshot.config_generation, 1);
        assert_eq!(snapshot.upstream.plaintext, true);
        assert_eq!(snapshot.upstream.servers.len(), 1);
        assert_eq!(snapshot.upstream.servers[0].addr, "127.0.0.1:5399");
        assert_eq!(snapshot.proxy_policy.unmatched, UnmatchedPolicy::Auto);
        assert!(!snapshot.proxy_policy.default_proxied);
        assert_eq!(snapshot.counters.queries_total, 0);
    }
}

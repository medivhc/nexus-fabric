//! DNS service status snapshot (`GET /localapi/v0/dns/status`).
//!
//! Mirrors `nat_status`: the DNS service publishes one process-wide snapshot at
//! assembly time, and LocalAPI reads it without probing. The first publisher
//! wins (D-impl-9); a second DNS service instance never overwrites the first.
//!
//! The snapshot fields are the frozen §6.5 shape. `to_json` renders the `dns`
//! block of §4.10.2; LocalAPI only adds `verdict` around it (C11).

use std::sync::{Mutex, OnceLock};

use serde_json::{Value, json};

/// `[dns].unmatched` policy (§4.4 / §4.6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnmatchedPolicy {
    /// Proxy when a usable outbound exists, otherwise upstream.
    Auto,
    /// Always proxy (startup `CONFIG` failure without a usable outbound).
    Proxied,
    /// Always resolve upstream.
    Upstream,
}

impl UnmatchedPolicy {
    /// Stable string form used by config and status JSON.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Proxied => "proxied",
            Self::Upstream => "upstream",
        }
    }
}

/// `[dns].unevaluable` policy (§4.4 / §4.6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnevaluablePolicy {
    /// Conservative default: proxy rules that need unloaded data count as proxied.
    Proxied,
    /// Explicit opt-in: treat them as upstream.
    Upstream,
}

impl UnevaluablePolicy {
    /// Stable string form used by config and status JSON.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Proxied => "proxied",
            Self::Upstream => "upstream",
        }
    }
}

/// DNS service lifecycle state (§6.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsServiceState {
    /// Thread running and serving queries.
    Running,
    /// Thread exited or failed to start.
    Failed,
    /// DNS subsystem not enabled (`dns.toml` absent or TUN disabled).
    Disabled,
    /// Request queue full / in-flight limit reached.
    Overloaded,
}

impl DnsServiceState {
    /// Stable string form for status JSON.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Failed => "failed",
            Self::Disabled => "disabled",
            Self::Overloaded => "overloaded",
        }
    }
}

/// Which DNS classification stages are actually configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsClassStates {
    /// `[dns].hosts` non-empty.
    pub hosts: bool,
    /// `[dns.mesh.hosts]` non-empty.
    pub mesh: bool,
    /// A `proxy.yaml` domain classifier was built.
    pub proxy_classifier: bool,
    /// At least one upstream server is configured.
    pub upstream: bool,
}

/// Effective proxy policy plus startup rule counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsProxyPolicyStatus {
    /// `[dns].unmatched`.
    pub unmatched: UnmatchedPolicy,
    /// `[dns].unevaluable`.
    pub unevaluable: UnevaluablePolicy,
    /// Total rules declared in `proxy.yaml`.
    pub rules: usize,
    /// Rules whose data was not loaded (`geosite` / `rule_set`).
    pub unevaluable_rules: usize,
    /// Effective unmatched verdict (`auto` resolved at startup).
    pub default_proxied: bool,
}

/// Per-server upstream health.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamServerStatus {
    /// Server address as configured (`host:port`).
    pub addr: String,
    /// Successful responses.
    pub ok: u64,
    /// Failed attempts (timeout / rcode / TCP fallback failure).
    pub fail: u64,
    /// Consecutive failures; `>= degraded_after` moves the server back.
    pub consecutive_failures: u32,
    /// Last success in monotonic ms since DNS service start.
    pub last_ok_ms: Option<u64>,
    /// Last failure reason.
    pub last_error: Option<String>,
}

/// Upstream aggregate status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamStatus {
    /// `"ok" | "degraded" | "failed" | "disabled"`.
    pub state: String,
    /// Plaintext UDP/53 is the only transport in this run (always true).
    pub plaintext: bool,
    /// Configured servers in declaration order.
    pub servers: Vec<UpstreamServerStatus>,
    /// Last aggregate error (`budget-exhausted`, ...).
    pub last_error: Option<String>,
}

/// DNS counters shown by `/dns/status` (§4.10.2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DnsCounters {
    /// Queries accepted from the dataplane.
    pub queries_total: u64,
    /// Queries dropped before classification (no txid / no question).
    pub malformed_queries: u64,
    /// Upstream cache hits.
    pub cache_hits: u64,
    /// Upstream cache misses.
    pub cache_misses: u64,
    /// Same-server resends.
    pub upstream_retries: u64,
    /// Server switches.
    pub upstream_failovers: u64,
    /// TCP fallbacks attempted.
    pub tcp_fallbacks: u64,
    /// TCP fallbacks that failed.
    pub tcp_fallbacks_failed: u64,
    /// Queries rejected because `max_inflight` was reached.
    pub overloaded: u64,
    /// `geosite` / `rule_set` classifications.
    pub classify_unevaluable: u64,
}

/// Fake-IP pool status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FakeIpStatus {
    /// `[dns].fake_ip_enabled`.
    pub enabled: bool,
    /// Currently allocated mappings.
    pub allocated: usize,
    /// Pool host capacity.
    pub capacity: u32,
    /// Allocation failures (pool exhausted).
    pub exhausted: u64,
}

/// Immutable view of the DNS service state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsStatusSnapshot {
    /// DNS subsystem enabled (`dns.toml` present and TUN enabled).
    pub enabled: bool,
    /// Lifecycle state.
    pub service: DnsServiceState,
    /// Config generation (1 at startup; reload requires restart).
    pub config_generation: u64,
    /// Configured classification stages.
    pub classes: DnsClassStates,
    /// Proxy policy in effect.
    pub proxy_policy: DnsProxyPolicyStatus,
    /// Upstream aggregate.
    pub upstream: UpstreamStatus,
    /// Service counters.
    pub counters: DnsCounters,
    /// Fake-IP pool.
    pub fake_ip: FakeIpStatus,
}

impl DnsStatusSnapshot {
    /// Snapshot for a process without a DNS service (`enabled=false`).
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            service: DnsServiceState::Disabled,
            config_generation: 0,
            classes: DnsClassStates {
                hosts: false,
                mesh: false,
                proxy_classifier: false,
                upstream: false,
            },
            proxy_policy: DnsProxyPolicyStatus {
                unmatched: UnmatchedPolicy::Auto,
                unevaluable: UnevaluablePolicy::Proxied,
                rules: 0,
                unevaluable_rules: 0,
                default_proxied: false,
            },
            upstream: UpstreamStatus {
                state: "disabled".to_string(),
                plaintext: true,
                servers: Vec::new(),
                last_error: None,
            },
            counters: DnsCounters::default(),
            fake_ip: FakeIpStatus {
                enabled: false,
                allocated: 0,
                capacity: 0,
                exhausted: 0,
            },
        }
    }

    /// Render the `dns` object of §4.10.2 (LocalAPI adds `verdict`).
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "enabled": self.enabled,
            "service": self.service.as_str(),
            "source": "dataplane",
            "config_generation": self.config_generation,
            "classes": {
                "hosts": self.classes.hosts,
                "mesh": self.classes.mesh,
                "proxy_classifier": self.classes.proxy_classifier,
                "upstream": self.classes.upstream,
            },
            "proxy_policy": {
                "unmatched": self.proxy_policy.unmatched.as_str(),
                "unevaluable": self.proxy_policy.unevaluable.as_str(),
                "rules": self.proxy_policy.rules,
                "unevaluable_rules": self.proxy_policy.unevaluable_rules,
                "default_proxied": self.proxy_policy.default_proxied,
            },
            "upstream": {
                "state": self.upstream.state.clone(),
                "plaintext": self.upstream.plaintext,
                "servers": self.upstream.servers.iter().map(|s| json!({
                    "addr": s.addr.clone(),
                    "ok": s.ok,
                    "fail": s.fail,
                    "consecutive_failures": s.consecutive_failures,
                    "last_ok_ms": s.last_ok_ms,
                    "last_error": s.last_error.clone(),
                })).collect::<Vec<_>>(),
                "last_error": self.upstream.last_error.clone(),
            },
            "queries_total": self.counters.queries_total,
            "malformed_queries": self.counters.malformed_queries,
            "cache_hits": self.counters.cache_hits,
            "cache_misses": self.counters.cache_misses,
            "upstream_retries": self.counters.upstream_retries,
            "upstream_failovers": self.counters.upstream_failovers,
            "tcp_fallbacks": self.counters.tcp_fallbacks,
            "tcp_fallbacks_failed": self.counters.tcp_fallbacks_failed,
            "overloaded": self.counters.overloaded,
            "classify_unevaluable": self.counters.classify_unevaluable,
            "fake_ip": {
                "enabled": self.fake_ip.enabled,
                "allocated": self.fake_ip.allocated,
                "capacity": self.fake_ip.capacity,
                "exhausted": self.fake_ip.exhausted,
            },
        })
    }
}

/// Shared mutable status handle owned by the DNS service.
#[derive(Debug)]
pub struct DnsStatus {
    inner: Mutex<DnsStatusSnapshot>,
}

impl DnsStatus {
    /// Wrap an initial snapshot.
    #[must_use]
    pub fn new(initial: DnsStatusSnapshot) -> Self {
        Self {
            inner: Mutex::new(initial),
        }
    }

    /// Read a consistent copy.
    #[must_use]
    pub fn snapshot(&self) -> DnsStatusSnapshot {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Mutate in place (service thread only; tests may drive it directly).
    pub(crate) fn update(&self, f: impl FnOnce(&mut DnsStatusSnapshot)) {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut guard);
    }
}

static PUBLISHED: OnceLock<std::sync::Arc<DnsStatus>> = OnceLock::new();

/// Publish the process-wide status handle. First publisher wins (D-impl-9).
pub fn publish(status: std::sync::Arc<DnsStatus>) {
    let _ = PUBLISHED.set(status);
}

/// Read the published snapshot; `None` when no DNS service was published.
#[must_use]
pub fn snapshot() -> Option<DnsStatusSnapshot> {
    PUBLISHED.get().map(|s| s.snapshot())
}

/// Process-wide cache view for `/dns/cache` (owner thread refreshes it).
static PUBLISHED_CACHE: OnceLock<
    std::sync::Arc<std::sync::Mutex<Vec<crate::dns_upstream::CacheEntryView>>>,
> = OnceLock::new();

/// Publish the cache handle. First publisher wins (D-impl-9).
pub fn publish_cache(
    cache: std::sync::Arc<std::sync::Mutex<Vec<crate::dns_upstream::CacheEntryView>>>,
) {
    let _ = PUBLISHED_CACHE.set(cache);
}

/// Read the published cache entries (empty when no service was published).
#[must_use]
pub fn cache_entries() -> Vec<crate::dns_upstream::CacheEntryView> {
    PUBLISHED_CACHE
        .get()
        .and_then(|h| h.lock().ok())
        .map(|guard| guard.clone())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn running_snapshot() -> DnsStatusSnapshot {
        DnsStatusSnapshot {
            enabled: true,
            service: DnsServiceState::Running,
            config_generation: 1,
            classes: DnsClassStates {
                hosts: true,
                mesh: true,
                proxy_classifier: true,
                upstream: true,
            },
            proxy_policy: DnsProxyPolicyStatus {
                unmatched: UnmatchedPolicy::Auto,
                unevaluable: UnevaluablePolicy::Proxied,
                rules: 3,
                unevaluable_rules: 1,
                default_proxied: true,
            },
            upstream: UpstreamStatus {
                state: "ok".to_string(),
                plaintext: true,
                servers: vec![UpstreamServerStatus {
                    addr: "127.0.0.1:15353".to_string(),
                    ok: 1,
                    fail: 0,
                    consecutive_failures: 0,
                    last_ok_ms: Some(1),
                    last_error: None,
                }],
                last_error: None,
            },
            counters: DnsCounters {
                queries_total: 2,
                malformed_queries: 1,
                cache_hits: 1,
                cache_misses: 1,
                upstream_retries: 0,
                upstream_failovers: 0,
                tcp_fallbacks: 0,
                tcp_fallbacks_failed: 0,
                overloaded: 0,
                classify_unevaluable: 1,
            },
            fake_ip: FakeIpStatus {
                enabled: true,
                allocated: 1,
                capacity: 131_072,
                exhausted: 0,
            },
        }
    }

    #[test]
    fn snapshot_matches_frozen_fields() {
        let status = DnsStatus::new(running_snapshot());
        let snap = status.snapshot();
        assert_eq!(snap, running_snapshot());
        assert_eq!(snap.service.as_str(), "running");
        assert_eq!(snap.proxy_policy.unmatched.as_str(), "auto");
        assert_eq!(snap.proxy_policy.unevaluable.as_str(), "proxied");
        assert_eq!(snap.upstream.servers[0].addr, "127.0.0.1:15353");
        assert_eq!(snap.counters.classify_unevaluable, 1);
        assert_eq!(snap.fake_ip.capacity, 131_072);
    }

    #[test]
    fn update_is_visible_to_snapshot() {
        let status = DnsStatus::new(running_snapshot());
        status.update(|s| {
            s.counters.queries_total = 9;
            s.service = DnsServiceState::Overloaded;
            s.fake_ip.allocated = 2;
        });
        let snap = status.snapshot();
        assert_eq!(snap.counters.queries_total, 9);
        assert_eq!(snap.service, DnsServiceState::Overloaded);
        assert_eq!(snap.fake_ip.allocated, 2);
    }

    #[test]
    fn disabled_snapshot_is_zeroed() {
        let snap = DnsStatusSnapshot::disabled();
        assert!(!snap.enabled);
        assert_eq!(snap.service.as_str(), "disabled");
        assert_eq!(snap.upstream.state, "disabled");
        assert!(snap.upstream.servers.is_empty());
        assert_eq!(snap.counters, DnsCounters::default());
        assert_eq!(snap.config_generation, 0);
    }

    #[test]
    fn to_json_renders_frozen_dns_block() {
        let v = DnsStatus::new(running_snapshot()).snapshot().to_json();
        assert_eq!(v["enabled"], true);
        assert_eq!(v["service"], "running");
        assert_eq!(v["source"], "dataplane");
        assert_eq!(v["config_generation"], 1);
        assert_eq!(v["classes"]["proxy_classifier"], true);
        assert_eq!(v["proxy_policy"]["unmatched"], "auto");
        assert_eq!(v["proxy_policy"]["rules"], 3);
        assert_eq!(v["proxy_policy"]["unevaluable_rules"], 1);
        assert_eq!(v["upstream"]["plaintext"], true);
        assert_eq!(v["upstream"]["servers"][0]["addr"], "127.0.0.1:15353");
        assert_eq!(v["queries_total"], 2);
        assert_eq!(v["classify_unevaluable"], 1);
        assert_eq!(v["fake_ip"]["capacity"], 131_072);
    }

    /// D-impl-9: a second publish never overwrites the first. This is the only
    /// test that touches the process-wide slot, so ordering is irrelevant.
    #[test]
    fn publish_first_wins() {
        let first = std::sync::Arc::new(DnsStatus::new(running_snapshot()));
        let second = std::sync::Arc::new(DnsStatus::new(DnsStatusSnapshot::disabled()));
        publish(first.clone());
        publish(second);
        let published = snapshot().expect("first publish registered");
        assert_eq!(published, running_snapshot());
        assert_eq!(published.service, DnsServiceState::Running);
    }
}

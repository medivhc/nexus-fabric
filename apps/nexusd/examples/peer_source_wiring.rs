//! E4 driver for `product.peer-source-wiring` (AC16).
//!
//! ```text
//! cargo run --quiet -p nexusd --example peer_source_wiring -- --json
//! ```
//!
//! No network, no TURN: the assembly under test is the real
//! `nexus::network::build_session_manager_with_discovery` (empty `[[peers]]`,
//! `mdns=None`) plus the real `PeerSourceFeed` / `NatSwitching`, with fake
//! `RelayTrigger` / `RelayAddressBook` / `RelayConnProvider` doubles. The feed
//! is driven one explicit tick at a time so the trace is deterministic.
//!
//! Frozen trace (AC16): `[{1,1,0,0}, {2,1,1,0}, {3,1,1,0}, {4,2,1,1}]`.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use nexus_discovery::PeerId as DiscoveryPeerId;
use nexus_discovery::lsa::Lsa;
use nexusd::nat_relay::{
    RelayAddressBook, RelayConn, RelayConnProvider, RelayConnSink, RelayError, RelayTrigger,
};
use nexusd::nat_switch::NatSwitching;
use nexusd::peer_source::{
    PeerSourceConfig, PeerSourceFeed, PeerSourceStatus, PeerSourceStatusSnapshot,
};
use serde_json::json;

/// In-memory address book (no file, no shared directory).
#[derive(Default)]
struct FakeBook {
    entries: Mutex<HashMap<[u8; 32], SocketAddr>>,
}

impl FakeBook {
    fn set(&self, peer: &str, addr: SocketAddr) {
        let mut id = [0u8; 32];
        for (i, chunk) in peer.as_bytes().chunks_exact(2).enumerate() {
            let s = std::str::from_utf8(chunk).expect("hex chunk");
            id[i] = u8::from_str_radix(s, 16).expect("hex byte");
        }
        self.entries.lock().expect("book").insert(id, addr);
    }
}

impl RelayAddressBook for FakeBook {
    fn relay_addr(&self, peer: &[u8; 32]) -> Option<SocketAddr> {
        self.entries.lock().ok()?.get(peer).copied()
    }
    fn reload(&self) -> std::io::Result<()> {
        Ok(())
    }
    fn publish(&self, peer: [u8; 32], addr: SocketAddr) -> std::io::Result<()> {
        self.entries.lock().expect("book").insert(peer, addr);
        Ok(())
    }
}

type SinkList = Vec<Weak<dyn RelayConnSink>>;

/// Fake relay: records trigger calls, returns `Ok(addr)` immediately and keeps
/// the established map current (so `established_relay_addr` is truthful).
#[derive(Default)]
struct FakeRelay {
    calls: Mutex<Vec<(nexus_fabric::PeerId, SocketAddr)>>,
    established: Mutex<HashMap<[u8; 32], SocketAddr>>,
    sinks: Mutex<HashMap<[u8; 32], SinkList>>,
}

impl RelayTrigger for FakeRelay {
    fn established_relay_addr(&self, peer: &nexus_fabric::PeerId) -> Option<SocketAddr> {
        self.established.lock().ok()?.get(&peer.0).copied()
    }

    fn established_peer_ids(&self) -> Vec<nexus_fabric::PeerId> {
        let mut out: Vec<nexus_fabric::PeerId> = self
            .established
            .lock()
            .expect("established")
            .keys()
            .map(|k| nexus_fabric::PeerId(*k))
            .collect();
        out.sort_by_key(|p| p.0);
        out
    }

    fn trigger_relay(
        &self,
        peer: nexus_fabric::PeerId,
        peer_relayed: SocketAddr,
    ) -> Result<SocketAddr, RelayError> {
        self.calls.lock().expect("calls").push((peer, peer_relayed));
        self.established
            .lock()
            .expect("established")
            .insert(peer.0, peer_relayed);
        Ok(peer_relayed)
    }
}

impl RelayConnProvider for FakeRelay {
    fn subscribe(&self, peer: nexus_fabric::PeerId, sink: Arc<dyn RelayConnSink>) {
        self.sinks
            .lock()
            .expect("sinks")
            .entry(peer.0)
            .or_default()
            .push(Arc::downgrade(&sink));
    }

    fn unsubscribe(&self, peer: nexus_fabric::PeerId, sink: &Arc<dyn RelayConnSink>) {
        let live = {
            let mut g = self.sinks.lock().expect("sinks");
            let target = Arc::downgrade(sink);
            if let Some(list) = g.get_mut(&peer.0) {
                list.retain(|w| !Weak::ptr_eq(w, &target));
            }
            let live = g.get(&peer.0).map(|l| l.len()).unwrap_or(0);
            if live == 0 {
                g.remove(&peer.0);
            }
            live
        };
        if live == 0 {
            self.established
                .lock()
                .expect("established")
                .remove(&peer.0);
        }
    }

    fn established_relay(&self, _peer: &nexus_fabric::PeerId) -> Option<RelayConn> {
        None
    }

    fn established_peers(&self) -> Vec<nexus_fabric::PeerId> {
        Vec::new()
    }

    fn subscribed_peers(&self) -> Vec<nexus_fabric::PeerId> {
        let mut out: Vec<nexus_fabric::PeerId> = self
            .sinks
            .lock()
            .expect("sinks")
            .keys()
            .map(|k| nexus_fabric::PeerId(*k))
            .collect();
        out.sort_by_key(|p| p.0);
        out
    }

    fn sink_count(&self, peer: &nexus_fabric::PeerId) -> usize {
        self.sinks
            .lock()
            .expect("sinks")
            .get(&peer.0)
            .map(|l| l.iter().filter(|w| w.strong_count() > 0).count())
            .unwrap_or(0)
    }
}

fn peer(hex: &str) -> nexus_fabric::PeerId {
    let mut id = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let s = std::str::from_utf8(chunk).expect("hex chunk");
        id[i] = u8::from_str_radix(s, 16).expect("hex byte");
    }
    nexus_fabric::PeerId(id)
}

fn lsa(hex: &str, ip_last: u8) -> Lsa {
    Lsa {
        node_id: DiscoveryPeerId(hex.to_string()),
        vip: "10.99.0.1".to_string(),
        incarnation: 1,
        seq: 1,
        capabilities: 0,
        locator: Some(format!("udp://10.0.0.{ip_last}:19010")),
        neighbors: Vec::new(),
    }
}

/// One trace line (frozen field names/order in the JSON output).
#[derive(Clone, Copy)]
struct TraceLine {
    tick: u32,
    subscribed_peers: usize,
    trigger_attempts_total: u64,
    trigger_capacity_parked_total: u64,
}

fn trace_line(tick: u32, snap: &PeerSourceStatusSnapshot) -> TraceLine {
    TraceLine {
        tick,
        subscribed_peers: snap.subscribed_peers,
        trigger_attempts_total: snap.trigger_attempts_total,
        trigger_capacity_parked_total: snap.trigger_capacity_parked_total,
    }
}

fn sources_from(snap: &PeerSourceStatusSnapshot) -> Vec<&'static str> {
    let mut out = Vec::new();
    if snap.sources_paired > 0 {
        out.push("paired");
    }
    if snap.sources_static > 0 {
        out.push("static");
    }
    if snap.sources_lsa > 0 {
        out.push("lsa");
    }
    if snap.sources_mdns > 0 {
        out.push("mdns");
    }
    if snap.sources_n1 > 0 {
        out.push("n1");
    }
    out
}

fn run() -> serde_json::Value {
    let a_hex = "aa".repeat(32);
    let b_hex = "bb".repeat(32);
    assert!(a_hex < b_hex, "A must sort before B");
    let self_hex = "cc".repeat(32);
    let self_id = peer(&self_hex);

    // 1. Real assembly: network.toml with peer_id + [vpi] only (no [[peers]]).
    let network_toml = format!(
        "peer_id = \"{self_hex}\"\n[vpi]\ninterface = \"nexus0\"\naddress = \"10.200.0.1\"\nmtu = 1200\n"
    );
    let (_config, sessions, hub) = nexus::network::build_session_manager_with_discovery(
        &network_toml,
        None,
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
        nexus::network::DiscoveryParams {
            mdns: None,
            lsa_stale_after: Duration::from_secs(90),
        },
    )
    .expect("assembly");

    // 2. Feed + fake trigger/book + a real NatSwitching with a fake provider.
    let book = Arc::new(FakeBook::default());
    let relay = Arc::new(FakeRelay::default());
    let driver =
        nexus_fabric::Driver::new_server("127.0.0.1:0".parse().expect("bind")).expect("driver");
    let local = nexus_nat_traversal::LocalCandidates {
        host: nexusd::nat_switch::gather_host_candidates(&driver),
        srflx: None,
        srflx_stun: None,
        srflx_turn: None,
        nat_type: nexus_connectivity::nat::NatType::Unknown,
    };
    let sw = NatSwitching::new(
        driver,
        self_id,
        local,
        Vec::new(),
        Arc::new(nexus_nat_wireup::SystemPunchClock::new()),
    );
    sw.attach_relay_provider(Arc::clone(&relay) as Arc<dyn RelayConnProvider>);
    let status = Arc::new(PeerSourceStatus::default());
    status.set_state("running");
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut feed = PeerSourceFeed::new(
        Arc::clone(&sw),
        Arc::clone(&relay) as Arc<dyn RelayTrigger>,
        book.clone(),
        sessions,
        Vec::new(),
        Arc::clone(&hub),
        self_id,
        PeerSourceConfig::default(),
        Arc::clone(&status),
        stop,
    );

    // 3. Tick sequence (AC16).
    let base = Instant::now();
    let mut trace: Vec<TraceLine> = Vec::new();

    // tick 1: hub has only A, book empty -> subscribe A, no trigger.
    hub.upsert_lsa(lsa(&a_hex, 2), base);
    hub.note_lsa_heard(&DiscoveryPeerId(a_hex.clone()), base);
    feed.tick(base + Duration::from_millis(1));
    trace.push(trace_line(1, &status.snapshot()));

    // before tick 2: publish A's relayed address.
    book.set(&a_hex, "10.9.0.1:5000".parse().expect("addr"));
    std::thread::sleep(Duration::from_millis(50));

    // tick 2: A becomes a candidate -> one trigger spawned.
    feed.tick(base + Duration::from_millis(2));
    trace.push(trace_line(2, &status.snapshot()));

    // wait (without ticking) until the fake report lands (max 2s).
    let deadline = Instant::now() + Duration::from_secs(2);
    while status.snapshot().trigger_ok_total == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }

    // tick 3: drain the Ok report -> trigger_ok_total=1; B not injected yet.
    feed.tick(base + Duration::from_millis(3));
    trace.push(trace_line(3, &status.snapshot()));

    // before tick 4: B appears through discovery and publishes an address.
    hub.upsert_lsa(lsa(&b_hex, 3), base + Duration::from_millis(4));
    hub.note_lsa_heard(
        &DiscoveryPeerId(b_hex.clone()),
        base + Duration::from_millis(4),
    );
    book.set(&b_hex, "10.9.0.2:5000".parse().expect("addr"));
    std::thread::sleep(Duration::from_millis(50));

    // tick 4: B subscribed then parked on capacity (A holds the slot).
    feed.tick(base + Duration::from_millis(5));
    let snap = status.snapshot();
    trace.push(trace_line(4, &snap));

    let sources = sources_from(&snap);
    let expected_trace = [
        TraceLine {
            tick: 1,
            subscribed_peers: 1,
            trigger_attempts_total: 0,
            trigger_capacity_parked_total: 0,
        },
        TraceLine {
            tick: 2,
            subscribed_peers: 1,
            trigger_attempts_total: 1,
            trigger_capacity_parked_total: 0,
        },
        TraceLine {
            tick: 3,
            subscribed_peers: 1,
            trigger_attempts_total: 1,
            trigger_capacity_parked_total: 0,
        },
        TraceLine {
            tick: 4,
            subscribed_peers: 2,
            trigger_attempts_total: 1,
            trigger_capacity_parked_total: 1,
        },
    ];
    let trace_ok = trace.len() == expected_trace.len()
        && trace.iter().zip(expected_trace.iter()).all(|(got, want)| {
            got.tick == want.tick
                && got.subscribed_peers == want.subscribed_peers
                && got.trigger_attempts_total == want.trigger_attempts_total
                && got.trigger_capacity_parked_total == want.trigger_capacity_parked_total
        });

    let mut failed: Vec<&str> = Vec::new();
    if !trace_ok {
        failed.push("step_trace");
    }
    if snap.subscribed_peers != 2 {
        failed.push("subscribed_peers");
    }
    if !sources.contains(&"lsa") {
        failed.push("subscribed_sources_contains_lsa");
    }
    if snap.trigger_attempts_total != 1 {
        failed.push("trigger_attempts_total");
    }
    if snap.trigger_ok_total != 1 {
        failed.push("trigger_ok_total");
    }
    if snap.trigger_capacity_parked_total != 1 {
        failed.push("trigger_capacity_parked_total");
    }
    if snap.trigger_parked_peers != 1 {
        failed.push("trigger_parked_peers");
    }

    // Teardown: feed first (guards drop), then the switch monitor.
    feed.shutdown();
    sw.shutdown();

    json!({
        "verdict": if failed.is_empty() { "PASS" } else { "FAIL" },
        "failed_checks": failed,
        "subscribed_peers": snap.subscribed_peers,
        "subscribed_sources": sources,
        "subscribed_sources_contains_lsa": sources.contains(&"lsa"),
        "trigger_attempts_total": snap.trigger_attempts_total,
        "trigger_ok_total": snap.trigger_ok_total,
        "trigger_capacity_parked_total": snap.trigger_capacity_parked_total,
        "trigger_parked_peers": snap.trigger_parked_peers,
        "panic": false,
        "step_trace": trace
            .iter()
            .map(|t| json!({
                "tick": t.tick,
                "subscribed_peers": t.subscribed_peers,
                "trigger_attempts_total": t.trigger_attempts_total,
                "trigger_capacity_parked_total": t.trigger_capacity_parked_total,
            }))
            .collect::<Vec<_>>(),
    })
}

fn main() {
    let json_mode = std::env::args().any(|a| a == "--json");
    let outcome = std::panic::catch_unwind(run);
    match outcome {
        Ok(value) => {
            if json_mode {
                println!("{value}");
            } else {
                println!("peer-source wiring: {}", value["verdict"]);
            }
            if value["verdict"] != "PASS" {
                std::process::exit(1);
            }
        }
        Err(_) => {
            let value = json!({
                "verdict": "FAIL",
                "panic": true,
                "error": "driver panicked",
            });
            if json_mode {
                println!("{value}");
            } else {
                eprintln!("peer-source wiring: FAIL (panic)");
            }
            std::process::exit(1);
        }
    }
}

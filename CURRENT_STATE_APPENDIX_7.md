# Nexus Fabric Current State — Deep Audit Continuation VII

> Continues `CURRENT_STATE_APPENDIX_6.md` after section 114.
> Source baseline: `48918863e70ef8589fbca6075c7ec11ca07e85a3` on `master`.
> This file remains staging material for the canonical `CURRENT_STATE.md`; findings here are source-derived current-state facts, not target-architecture decisions.

## 115. macOS joins Android/iOS in the documentation-only platform-adapter class

The directory-level check that was still pending in section 114 is now complete.

`crates/nexus-platform-macos/src/` contains only `lib.rs`, and that file itself contains only crate documentation plus `#![forbid(unsafe_code)]`. It defines no module, type, function or native bridge.

The crate description says the adapter includes system-managed networking and file projection, but those capabilities are not implemented in the current crate body.

The platform source classification is therefore now sharper:

- Linux: broad concrete runtime implementation;
- Windows: substantive adapter modules exist;
- macOS: documentation/skeleton only;
- Android: documentation/skeleton only;
- iOS: documentation/skeleton only.

This is stronger than merely saying platform parity is uneven: three of the five OS-specific crates currently advertise capabilities in prose that have no executable implementation in those crates.

## 116. `nexus-ingress` is a real portable protocol/classification layer, not the owner of interception I/O

`nexus-ingress` has meaningful executable behavior and a clean boundary.

It provides neutral `FlowContext` construction for:

- SOCKS5;
- HTTP proxy;
- virtual packet interface;
- native API.

All of those map to the `internet-access` Network Resource while preserving `FlowOrigin`.

It also contains a real incremental SOCKS5 state machine with:

- RFC 1928 greeting/method negotiation;
- optional RFC 1929 framing;
- CONNECT request parsing;
- IPv4/IPv6/domain address parsing;
- explicit rejection of BIND and UDP ASSOCIATE in this state machine;
- no network I/O inside the crate.

The credential handling boundary is important: the RFC 1929 state machine validates framing but does not itself authorize username/password values; authorization remains an upper-layer policy concern.

So the current role is:

- protocol decode/state machine: **Implemented**;
- neutral flow classification: **Implemented**;
- platform interception / listener ownership: **not owned here**;
- Core Planner invocation: **explicitly not owned here**.

This supports the architecture invariant `network_depends_on_ingress = false`: ingress creates neutral inputs rather than becoming a private part of the Network domain runtime.

## 117. `nexus-proxy-config` has evolved into a much broader typed config surface than its early P0 wording suggests

The config crate is substantial and pure. It contains an internal deterministic YAML-subset parser and typed validation; it performs no file or network I/O.

Current typed configuration covers more than the early direct/relay proxy P0:

### 117.1 Rule surface

`RuleKind` currently includes:

- domain suffix;
- exact domain;
- IP CIDR;
- GEOIP;
- GEOSITE;
- rule set;
- source port;
- destination port;
- process name;
- MATCH fallback.

Actions are still deliberately narrow: the current action kind is `select_outbound`.

### 117.2 Group surface

`GroupKind` includes:

- selector;
- urltest;
- load_balance;
- relay chain.

### 117.3 Outbound config vocabulary

`OutboundKind` currently accepts:

- direct;
- relay;
- Shadowsocks;
- VMess;
- Trojan;
- SOCKS5;
- AnyTLS;
- VLESS;
- Hysteria2.

`OutboundConfig` contains protocol-specific fields for SS method/password, Trojan ALPN/cert/header behavior, obfs plugin fields, VLESS UUID/flow/TLS/servername, AnyTLS/Hysteria2 SNI, Hysteria2 port range/bandwidth/obfs fields, etc.

The config vocabulary is therefore much broader than the set of protocols currently reachable from the daemon forwarding path. This distinction is critical: **parseable/configurable does not mean production-forwardable**.

## 118. `nexus-proxy` is a real rule/policy engine, but it is not the same thing as the daemon's concrete outbound forwarder

`nexus-proxy` implements a portable proxy decision layer around `FlowContext`.

The crate contains:

- rule compilation and ordered matching;
- domain/IP/port/process matchers;
- GEOIP/GEOSITE/rule-provider injected data;
- selector/urltest/group resolution logic;
- typed proxy errors;
- injected `LinkActivator` integration for connectivity decisions.

Its own documentation is explicit that this rule engine is **not** a second system-level Core Planner. It is a domain-local per-flow decision component.

It is also explicit that URL-test consumes injected/offline `LinkMeasurement` rather than initiating real network probes itself.

This means there are at least two proxy-related ownership layers in the repository:

1. `nexus-proxy`: rule/group/outbound-selection semantics;
2. `apps/nexusd::proxy_fwd::ProxyEngine`: concrete packet forwarding/dialing for the daemon dataplane.

They should not be collapsed into one implementation when describing current production reachability.

## 119. The daemon's concrete ProxyEngine supports only a subset of the configured outbound vocabulary

`apps/nexusd/src/proxy_fwd.rs` gives a much narrower production forwarding set than `nexus-proxy-config`.

The daemon `ProxyEngine` currently recognizes concrete dial configurations for:

- Shadowsocks, but only `chacha20-ietf-poly1305` in this path;
- Trojan plaintext;
- Trojan TLS when selected configuration fields trigger TLS;
- SOCKS5.

The same function explicitly returns `None` for:

- Direct;
- Relay;
- VMess;
- AnyTLS;
- VLESS;
- Hysteria2.

For those protocols, comments state that fuller adapters/handshakes are required and that this simple daemon dial path does not support them.

The engine selects the **first usable outbound in the config**, rather than demonstrating that the full `nexus-proxy` rule/group decision graph is used here for each forwarded packet.

This produces an important current-state split:

- `proxy.yaml` can describe many protocol kinds;
- standalone protocol crates may implement substantial mechanics;
- the normal nexusd packet forwarding engine currently consumes only SS/Trojan/SOCKS5 dial configs in its inspected production path.

Any capability table must therefore have separate columns for config support, protocol implementation and daemon forwarding reachability.

## 120. Several outbound protocol crates are substantive implementations even when nexusd does not route traffic through them

The production reachability restriction above does not mean the unsupported daemon kinds are empty stubs.

### 120.1 VMess

`nexus-outbound-vmess` explicitly says it does not connect to a real server. It implements a self-contained AEAD adapter using ChaCha20-Poly1305 and deterministic key derivation from UUID material, plus an `OutboundAdapter` handoff.

Its own source says E4 is encrypt→decrypt self-consistency rather than real server interoperability.

Therefore VMess is best classified as:

- local protocol/crypto model: **Implemented**;
- real VMess server dial/interoperability: **not implemented by this crate**;
- nexusd proxy-forwarding reachability: **not wired in the inspected path**.

### 120.2 VLESS

`nexus-outbound-vless` is much deeper. It implements request/response header mechanics, UUID parsing, addon encoding, TCP/UDP/Mux command representation, lazy response-header consumption, UDP-over-TCP framing and XTLS-Vision padding/state-machine behavior over an already established byte stream.

The key boundary is “already established byte stream”: this crate contains protocol semantics but does not by itself prove the daemon constructs the complete outer transport/TLS path for production proxy flows.

And `proxy_fwd.rs` currently excludes VLESS from its concrete dial config.

### 120.3 Hysteria2

`nexus-outbound-hysteria2` is also substantial. The root source exports a QUIC/H3 client stack, authentication, frames, Salamander obfuscation, TLS verification modes and a synchronous quinn-proto-based driver.

Its own boundary is explicit: Brutal fixed-rate congestion control, port hopping, complete H3, and product server implementation are not present.

Despite this protocol depth, nexusd `ProxyEngine` currently marks Hysteria2 unsupported in the inspected simple forwarding path.

The repository therefore demonstrates a recurring implementation pattern:

> a protocol can be deeply implemented and scenario-testable while still not be connected to the product's currently dominant packet-forwarding composition root.

## 121. `nexus-proxy-transport` contains another stale same-file claim and represents a separate path use case

`nexus-proxy-transport` is not the same abstraction as `ProxyEngine` egress forwarding. Its root documentation describes QUIC/Fabric transported **over** proxy CONNECT-style transports: proxy connection first, then length-framed datagram semantics implementing `nexus_fabric::UdpTransport`.

It includes concrete support for:

- SOCKS5 CONNECT;
- Shadowsocks transport;
- Trojan transport;
- Trojan TLS transport.

This is a **per-link path-layer proxy transport**, intended to let Fabric/QUIC run through a proxy, rather than the per-flow Internet proxy egress path in nexusd.

A useful same-file drift was found here. The `Socks5ProxyConfig` comment says no SOCKS5 outbound exists in `nexus-proxy-config` and even says `OutboundKind` has no `Socks5` variant. That statement is now false: current `nexus-proxy-config::OutboundKind` explicitly contains `Socks5`.

So this file contains a historical comment that was not updated when the shared config vocabulary gained SOCKS5.

Current interpretation:

- proxy transport framing/handshakes: **Implemented**;
- Fabric-over-proxy transport mechanism: **Implemented at adapter level**;
- relationship to current PathManager/N1 product composition: must be traced independently;
- its comment about missing SOCKS5 shared config: **stale and contradicted by current source**.

## 122. Updated proxy capability matrix

| Capability | Config model | Protocol/mechanism source | nexusd concrete ProxyEngine path |
|---|---|---|---|
| Direct | yes | connectivity path exists elsewhere | no in `proxy_fwd` dial selection |
| Relay | yes | connectivity/relay mechanisms exist elsewhere | no in `proxy_fwd` dial selection |
| Shadowsocks | yes | substantive outbound + proxy transport | **yes**, chacha20-ietf-poly1305 in inspected path |
| Trojan | yes | substantive outbound + proxy transport + TLS transport | **yes**, plaintext/TLS variants |
| SOCKS5 | yes | ingress + proxy transport; daemon dialer | **yes** |
| VMess | yes | local AEAD/self-consistency adapter | **no** |
| AnyTLS | yes | separate outbound crate exists | **no** |
| VLESS | yes | substantial protocol-over-stream implementation | **no** |
| Hysteria2 | yes | substantial QUIC/H3 implementation | **no** |

This table is intentionally not a verification table. “yes” here means the corresponding source/config mechanism is present; it does not upgrade the route to revision-bound Verified without matching evidence.

## 123. Revised high-priority remaining work after the proxy/platform pass

The exhaustive audit is now increasingly about composition reachability rather than discovering top-level crate purpose.

Highest-value remaining items are:

1. trace whether `nexus-proxy` rule/group selection is actually on the same nexusd hot path as `proxy_fwd::ProxyEngine`, or whether production currently uses a simplified first-usable-outbound path;
2. trace `nexus-proxy-transport` into PathManager/N1/Fabric callers to distinguish implemented adapter from product-reachable fallback;
3. inspect the remaining outbound crates (Shadowsocks, Trojan, AnyTLS) at the same protocol-vs-wireup granularity;
4. inspect concrete Windows module implementations and product usage;
5. inspect Linux platform source tree systematically and build a concrete per-capability parity table;
6. finish Scheduler product reachability and Workspace Intelligence detachment checks;
7. merge appendices into the canonical `CURRENT_STATE.md`, replacing earlier contradicted statements instead of preserving stale text as parallel truth.

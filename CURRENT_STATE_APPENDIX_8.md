# Nexus Fabric Current State — Deep Audit Continuation VIII

> Continues `CURRENT_STATE_APPENDIX_7.md` after section 123.
> Source baseline: `48918863e70ef8589fbca6075c7ec11ca07e85a3` on `master`.
> This file remains staging material for the canonical `CURRENT_STATE.md`; findings here are source-derived current-state facts, not target-architecture decisions.

## 124. Scheduler is product-reachable, but it is a manually-ticked local registry rather than an autonomous task scheduler

A deeper read of `apps/nexus/src/main.rs`, `apps/nexus/src/schedule_cli.rs` and `crates/nexus-scheduler` changes the precision of the Scheduler baseline.

The scheduler mechanism itself is substantial:

- `ScheduleSpec::At` and `Every`;
- deterministic registration/cancellation/listing;
- due-time calculation;
- snapshot/restore;
- failed submission leaves an entry due for retry;
- successful `At` becomes `Fired`;
- successful `Every` advances `next_run_secs` by the interval.

The CLI composition is also real. `nexus schedule at|every|list|cancel|tick` is routed before the daemon/LocalAPI command path and executes in process. Its registry is persisted to `$NEXUS_HOME/schedule.json` or `~/.nexus/schedule.json`. Corrupt JSON is returned as an error instead of being silently reset, and state replacement uses a same-directory temporary file followed by rename.

However two boundaries are critical.

### 124.1 There is no autonomous scheduler loop in this product path

The current product entry exposes an explicit `schedule tick` command. The scheduler advances only when that command is invoked by some external actor. The inspected CLI composition does not own a background timer/thread/process that periodically calls `tick`.

Therefore:

- scheduling state machine: **Implemented**;
- CLI registration/list/cancel/manual tick: **Wired**;
- local snapshot persistence: **Wired**;
- autonomous periodic ticking: **not wired in the inspected product path**.

An `Every` entry therefore describes repeat semantics **when tick is called**, not proof that Nexus itself wakes up and executes it periodically.

### 124.2 The default CLI submit callback does not execute a Task

`apps/nexus/src/schedule_cli.rs::make_submit()` currently returns a synthetic id:

```text
Ok(format!("task-{}", intent.resource))
```

The source explicitly states that this callback “生成 task id，不做执行路径”. It does not call N3 Task submission, N2 resource execution, a shell command runner, or a daemon service.

Consequently a successful `schedule tick` currently means:

1. an entry was due;
2. the in-process callback returned a generated task-id string;
3. scheduler state advanced and was persisted.

It does **not** mean the scheduled command actually ran.

This is a major distinction for CURRENT_STATE:

> The repository has a real deterministic scheduler and durable local CLI registry, but scheduled execution is not production-closed. Current CLI ticking acknowledges a synthetic submission rather than invoking the Task execution pipeline.

## 125. Proxy has two separate product-reachable runtimes with materially different semantics

The proxy subsystem is another case where “the proxy runtime” is not one implementation.

Current source exposes at least two product-reachable owners:

### 125.1 Foreground `nexus proxy`

`apps/nexus/src/main.rs::run_proxy` is a long-running foreground listener by default. It binds a TCP address (default `127.0.0.1:1080`), loads `proxy.yaml`, initializes builtin obfuscation plugins, repeatedly accepts clients and calls `nexus::proxy_serve_once`.

Its session path is roughly:

```text
TCP listener
  -> SOCKS5 or HTTP handshake
  -> neutral FlowContext
  -> nexus-proxy::ProxyService rule engine
  -> selected outbound tag
  -> SessionOwner
  -> concrete outbound protocol implementation
  -> byte relay
```

This is a real product data-plane command, not merely an E4 driver.

### 125.2 Daemon TUN `ProxyEngine`

`nexusd::Dataplane` has a different proxy path:

```text
TUN packet
  -> daemon classifier
  -> Classification::Proxy
  -> nexusd::proxy_fwd::ProxyEngine
  -> TCP/UDP forwarder
```

`ProxyEngine` parses `proxy.yaml`, but its current outbound selection function walks `config.outbounds` and returns the **first outbound kind it knows how to realize**. It is not the same per-flow `nexus-proxy::ProxyService` route decision used by foreground `nexus proxy`.

This difference is architectural, not just an implementation detail:

- foreground proxy: rules/groups decide a specific tag for each `FlowContext`;
- daemon proxy-forwarder: current inspected selection is a supported-outbound scan rather than the foreground rule-engine decision chain.

Therefore the repository currently has two product proxy semantics that share configuration types but do not share the same top-level routing/execution owner.

## 126. Foreground `nexus proxy` is much more protocol-complete than the daemon ProxyEngine

Earlier audit text correctly said that VMess/AnyTLS/VLESS/Hysteria2 do not enter the **daemon `ProxyEngine`**. That statement must not be generalized to the whole product.

`apps/nexus/src/lib.rs::proxy_serve_once` proves that the foreground proxy path has accumulated significantly broader real outbound wiring.

### 126.1 Inbound multiplexing is real SOCKS5 + HTTP on one listener

The first received byte selects handshake family:

- `0x05` -> `nexus_ingress::Socks5Handshake`;
- otherwise -> `HttpProxyHandshake`.

The implementation preserves bytes already pipelined after SOCKS5 negotiation. For HTTP forward-proxy input, it preserves the rewritten origin-form request prefix plus post-header buffered bytes before entering the upstream relay.

This means the foreground product runtime is no longer accurately described as only a “SOCKS5 listener”, despite stale comments still using that phrase.

### 126.2 Rule-engine routing is wired here

After handshake, the runtime:

1. parses `proxy.yaml`;
2. constructs `nexus_proxy::ProxyService`;
3. calls `route(&flow, None)`;
4. finds the exact configured outbound whose tag matches `decision.selected_outbound_tag`;
5. establishes that outbound.

This is a concrete product consumer of `nexus-proxy`; the crate is therefore not scenario-only.

### 126.3 Known foreground outbound support

Source inspection confirms real product code for:

- **Direct** — real TCP connect to the requested destination and bidirectional relay;
- **Shadowsocks** — real node TCP connection, configured cipher, encrypted request header and framed encrypted relay;
- **Trojan** — real TCP + rustls TLS, SNI/ALPN/certificate policy, configurable header format and relay;
- **AnyTLS** — TLS session handshake, stream open, PSH/FIN/heartbeat framing and relay;
- **VLESS** — actual request handshake, optional TLS and bidirectional relay;
- **Hysteria2** — QUIC connection, minimal H3 authentication, TCP proxy stream and relay.

This is materially broader than `nexusd::proxy_fwd::ProxyEngine`.

### 126.4 Important partial-support boundaries remain

The broader foreground support must still be stated precisely:

- VMess has a substantive adapter/AEAD implementation, but its own crate explicitly says it does not connect to a real server; the foreground proxy path has an explicit deferred/failure branch rather than a real VMess data-plane tunnel.
- Relay outbound is explicitly deferred in the inspected foreground match arm.
- VLESS XTLS-Vision has framing/state-machine code in its crate, but the foreground path explicitly says the splice/direct transition is not implemented; Vision configuration is therefore only partially realized.
- Hysteria2 foreground wiring handles the TCP-proxy use case. The crate supports QUIC DATAGRAM primitives, but this TCP ingress arm explicitly says UDP relay is not yet composed; port hopping and Brutal CC are also not production-wired here.

The correct status must be per protocol **and** per runtime.

## 127. Daemon ProxyEngine is narrower and bypasses several richer protocol adapters

`apps/nexusd/src/proxy_fwd.rs` currently realizes these outbound shapes:

- Shadowsocks, restricted in this path to `chacha20-ietf-poly1305`;
- Trojan plaintext;
- Trojan TLS when the current TLS trigger fields are set;
- SOCKS5.

It explicitly skips/returns no dial config for:

- Direct;
- Relay;
- VMess;
- AnyTLS;
- VLESS;
- Hysteria2.

It also selects the first usable supported outbound in config order. Thus a configuration that is meaningful for `nexus proxy` can have materially different behavior when consumed as daemon TUN proxy configuration.

A particularly important consequence is that protocol support cannot be represented by a single boolean table such as “VLESS: implemented”. At minimum it needs columns for:

- config parser recognizes it;
- protocol adapter implements it;
- foreground ProxyService path wires it;
- daemon TUN ProxyEngine wires it;
- current-revision scenario/evidence status.

Without those dimensions, the current repository will be over-described.

## 128. `nexus-proxy-transport` is a third proxy-related mechanism whose product attachment remains unproven

`nexus-proxy-transport` is neither the foreground per-flow proxy egress nor `nexusd::ProxyEngine`.

Its purpose is per-link transport:

```text
proxy CONNECT/session
  -> connected TCP-like stream
  -> 2-byte datagram framing
  -> nexus_fabric::UdpTransport
  -> Fabric QUIC unchanged above it
```

The implementation includes SOCKS5, Shadowsocks, Trojan and Trojan-TLS transport adapters.

Current composition evidence is asymmetric:

- `apps/nexus/Cargo.toml` does **not** directly depend on `nexus-proxy-transport`; the foreground proxy implementation instead uses outbound protocol crates directly.
- `apps/nexusd/Cargo.toml` **does** depend on `nexus-proxy-transport`.
- In the inspected `nexusd` assembly/dataplane/proxy-forwarding paths, no attachment of these transports to `FabricConn::connect_with_transport` has yet been identified.

Therefore the safe status is:

- per-link proxy transport mechanism: **Implemented**;
- declared nexusd dependency: **yes**;
- normal daemon/N1/PathManager product wiring: **unproven in the inspected composition paths**.

A manifest dependency alone is not enough to upgrade this to Wired.

## 129. Windows autostart integration contains a concrete migration inconsistency

The Windows platform adapter `TaskSchedulerAutostart` is a real implementation. It invokes `schtasks.exe` to create/query/delete an ONLOGON task and constructs a command line from the executable path plus caller-provided arguments.

However the current caller has moved.

`nexus autostart install` runs inside the `nexus` CLI and calls:

```text
std::env::current_exe()
reg.install(&exe, &["serve", "--addr", "127.0.0.1:7898"])
```

So the scheduled executable is now the current `nexus` binary.

But the current `nexus` command dispatcher does not expose a `serve` command. Its own help and dispatch table route command families such as `proxy`, `schedule`, `network`, `use`, `task`, etc.; `serve` belongs historically to `nexusd`.

The platform adapter's own unit test still models the old form:

```text
"D:\nexusd.exe" serve --addr 127.0.0.1:7898
```

This indicates a migration regression at the integration boundary:

> `nexus autostart install` can construct/register a Task Scheduler entry whose executable is `nexus`, while its arguments still target the historical `nexusd serve` interface.

Source inspection therefore predicts that the registered task launches an unsupported CLI command. This is a high-confidence current-state defect, but it has **not** been runtime-verified on Windows in this audit and should be labeled accordingly.

This finding also illustrates why platform-adapter unit tests alone are insufficient: the adapter can be locally correct while the product caller supplies a stale executable/argument pairing.

## 130. `nexus proxy --tun` currently opens a TUN capability; it is not the foreground rule-engine TUN data plane

The foreground proxy command has a `--tun` option, which could easily be read as “run the same ProxyService over TUN”. Current code does not do that.

When `--tun` is present, `run_proxy` calls `tun_proxy_real_open`, prints the result and returns. The source comment is explicit that success reports adapter metadata and the handle is then released by `Drop`.

The long-running `proxy_serve_once` loop is the TCP-listener path, not this `--tun` branch.

Therefore:

- foreground SOCKS5/HTTP proxy data plane: **Wired**;
- foreground real TUN open/capability probe: **Wired as an open/metadata path**;
- foreground TUN -> ProxyService -> outbound long-running pipeline: **not established by this command path**.

The actual long-running TUN owner remains `nexusd::Dataplane` in the inspected product topology.

## 131. Correction: literal Cargo workspace omission does not by itself prove resolved non-membership

The previous continuation established three facts about `nexus-workspace-intel`:

1. `crates/nexus-workspace-intel` physically exists and has a real Cargo package;
2. `apps/nexus` has a path dependency on it;
3. `policies/architecture.toml` registers it;
4. the root `[workspace].members = [...]` literal list of 50 entries does not include it.

Those facts are all source-confirmed.

However the stronger wording “therefore `cargo test --workspace` cannot include it” is not justified from the manifest text alone. Cargo can resolve packages under a workspace root through path dependency/workspace discovery rules, and this audit has not executed `cargo metadata` against the exact baseline revision.

The canonical baseline must therefore use the narrower, evidence-safe wording:

> The root manifest has **50 explicit member entries** and omits `nexus-workspace-intel` from that literal list, while an explicit member (`apps/nexus`) depends on it and architecture policy registers it. The machine-resolved Cargo workspace package set remains **Unknown** until `cargo metadata` is captured for the baseline revision.

This is an example where source structure creates a drift signal, but runtime/tooling resolution is needed before making a coverage claim.

## 132. Same-file and cross-generation proxy comments contain additional stale statements

The deeper proxy read found several documentary statements that no longer describe the executable body around them.

### 132.1 Foreground proxy comment under-describes its outbound arms

Immediately before the outbound match, `proxy_serve_once` still says roughly that Trojan/VMess data-plane tunnels are outside the frozen batch and fail structurally. The executable body below it now contains a substantial real Trojan TLS relay and later AnyTLS/VLESS/Hysteria2 product arms. VMess remains deferred, but Trojan no longer does.

### 132.2 “SOCKS5 data plane” label now under-describes the inbound

`run_proxy` comments call the command a real SOCKS5 data plane, while `proxy_serve_once` now multiplexes SOCKS5 and HTTP proxy handshakes on the same listening socket.

### 132.3 `nexus-proxy-transport` still carries obsolete config assumptions

As already recorded, its source says shared `OutboundKind` has no SOCKS5 variant and that Trojan TLS is postponed, while current config has `Socks5` and the crate exports a TLS Trojan implementation.

These are not harmless historical notes: they directly affect how an auditor infers protocol reachability. The canonical current-state document should prefer the executable match arms and current typed configuration over these comments.

## 133. Updated runtime-ownership map after Scheduler and Proxy tracing

The product now has an even clearer split between mechanisms and owners:

| Capability | Product owner/path | Current closure |
|---|---|---|
| scheduled registry | `nexus schedule ...` local CLI | durable local state, manual tick |
| scheduled execution | synthetic `make_submit()` callback | not real Task execution |
| foreground proxy | `nexus proxy` -> `ProxyService` -> protocol arms | real SOCKS5/HTTP listener and several real outbounds |
| TUN proxy | `nexusd::Dataplane` -> `ProxyEngine` | real TCP/UDP forwarder, narrower protocols and different selection semantics |
| Fabric-over-proxy link | `nexus-proxy-transport` | mechanism implemented; daemon attachment not proven |
| Windows autostart | `nexus autostart` + platform adapter | adapter real; current executable/`serve` integration inconsistent |

The dominant architectural issue is no longer merely “some features are unfinished”. It is that multiple generations are often individually substantial but **their authoritative product owner is different by command/runtime**.

For the final CURRENT_STATE merge, feature statements should therefore answer all of these questions explicitly:

1. What mechanism exists?
2. Which executable/composition root owns it?
3. Is it actually invoked automatically or only by an explicit command/scenario?
4. Does another product runtime implement the same capability differently?
5. What is the strongest current revision-bound evidence?

That structure will prevent the final document from collapsing a large set of separately-realized mechanisms into one fictional unified runtime.

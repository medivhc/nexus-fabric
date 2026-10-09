# CURRENT_STATE source map — N1 / NAT / Workspace extension

> Reviewed source revision: `e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573`.
>
> This file extends `CURRENT_STATE_SOURCE_MAP.md` with source-line anchors for the last ownership edges needed by the canonical rewrite.

## N1 packet runtime

| Current-state fact | Source anchor |
|---|---|
| `VpiPump` is a concrete VirtualPacketInterface ↔ per-peer connection data plane with uplink routing, per-peer downlink workers, restart supervisors and bounded shutdown caveat | [`crates/nexus-network/src/n1/pump.rs` L1-L27](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-network/src/n1/pump.rs#L1-L27), [`L100-L254`](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-network/src/n1/pump.rs#L100-L254) |
| Pump routing is explicit static IPv4 longest-prefix mapping to peer identity; no route means drop/count | [`crates/nexus-network/src/n1/pump.rs` L38-L126](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/crates/nexus-network/src/n1/pump.rs#L38-L126) |
| `AutoMeshController` is another foreground composition owner around `VirtualSubnetTunnel`; it owns reconnect state, optional LAN/bootstrap discovery and punch driving | [`apps/nexus/src/mesh.rs` L1-L27](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/mesh.rs#L1-L27), [`L116-L230`](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexus/src/mesh.rs#L116-L230) |

## Daemon flow-session integration

| Current-state fact | Source anchor |
|---|---|
| `Dataplane::enable_flow_sessions()` exists but defaults are `flow_mgr: None` / `flow_chain_deps: None` | [`apps/nexusd/src/dataplane.rs` L218-L278](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/dataplane.rs#L218-L278) |
| The flow-session chain currently builds an in-memory registry with two synthetic providers and a default network policy before creating the flow `SessionManager` | [`apps/nexusd/src/dataplane.rs` L255-L319](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/dataplane.rs#L255-L319) |
| N1/proxy injection updates only upstream-availability flags for this establisher | [`apps/nexusd/src/dataplane.rs` L321-L336](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/dataplane.rs#L321-L336) |

## NAT switching

| Current-state fact | Source anchor |
|---|---|
| `NatSwitching` composes `PunchManager`, `PathLink` and `QualityMonitor`, and its file explicitly states normal `nexusd main.rs` does not instantiate it because daemon TURN client/config/credentials are not yet present | [`apps/nexusd/src/nat_switch.rs` L1-L24](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/nat_switch.rs#L1-L24) |
| Relay registration can trigger background punching; a migrated direct connection is registered as a candidate and PathManager hysteresis, not punch success alone, decides promotion | [`apps/nexusd/src/nat_switch.rs` L133-L221](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/nat_switch.rs#L133-L221) |
| Production traffic lookup returns whichever PathLink marks active: direct or relay | [`apps/nexusd/src/nat_switch.rs` L223-L242](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/nat_switch.rs#L223-L242) |

## Workspace local lifecycle and sync

| Current-state fact | Source anchor |
|---|---|
| `WorkspaceManager` production module owns Linux FUSE mounting, shared FsContentStore CAS, per-workspace state-root anchors, optional auto-commit and explicit shutdown; it does not describe sync lifecycle ownership | [`apps/nexusd/src/workspace.rs` L1-L13](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/workspace.rs#L1-L13), [`L233-L258`](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/workspace.rs#L233-L258) |
| Commit serializes `fs.commit()` and state-root anchor update but explicitly documents a crash window between durable CAS commit and anchor rewrite | [`apps/nexusd/src/workspace.rs` L126-L166](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/workspace.rs#L126-L166) |
| Fabric Workspace sync is a separate adapter; connection acquisition remains caller-owned and passive routing requires caller consumption of unclaimed/accepted streams | [`apps/nexusd/src/sync_transport.rs` L1-L24](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/sync_transport.rs#L1-L24) |
| Sync reuses an existing active Fabric connection, stream type `0x03`, 64 KiB frame bound and 30 s receive deadline | [`apps/nexusd/src/sync_transport.rs` L27-L42](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/sync_transport.rs#L27-L42), [`L75-L170`](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/sync_transport.rs#L75-L170) |
| Server-side peer identity is explicitly not trustworthy in current Fabric P0; `SyncAuthorizer` is mechanism-ready but production enforcement awaits client authentication | [`apps/nexusd/src/sync_transport.rs` L172-L211](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/sync_transport.rs#L172-L211) |
| Authorized serve rejects non-members before serving commit/object data | [`apps/nexusd/src/sync_transport.rs` L213-L255](https://github.com/medivhc/nexus-fabric/blob/e6ccf8b8d0ad1abb1db0b723149dcf3b9ccca573/apps/nexusd/src/sync_transport.rs#L213-L255) |

## Merge rule

These anchors should replace broad prose-only claims in the canonical `CURRENT_STATE.md`. In particular:

- N1 must distinguish the `VpiPump`/AutoMesh foreground shape from the daemon `Dataplane + N1MeshBridge` shape.
- NAT must distinguish implemented switching machinery from normal daemon activation.
- Workspace must distinguish local FUSE/CAS lifecycle from the separately implemented Fabric sync adapter and from the unresolved server-side authenticated peer identity boundary.

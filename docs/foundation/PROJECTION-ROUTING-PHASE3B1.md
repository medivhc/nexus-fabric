# Phase 3b-1 决策记录：统一路由 + 本地出口

**日期**: 2026-09-30
**状态**: 已决策（用户："按照你的想法决策 需要考虑长远"）
**对应设计**: `docs/foundation/DESIGN.md` §6.4

## 决策（5 项，含长远调整）

### 1. `RouteTarget` 放 `nexus-domain`（调整原提案）

原提案：放 `nexus-projection` 内。
长远调整：`RouteTarget` 是规则引擎与投影层之间的**契约类型**。
规则引擎未来可能独立成 policy crate，若 `RouteTarget` 在 projection 内，
规则引擎就要依赖投影层——依赖方向反了。
`nexus-domain` 已有 `FlowContext`，是中立领域类型所在地。

```rust
// crates/nexus-domain/src/lib.rs
pub enum RouteTarget {
    MeshPeer { peer: String },  // P0 用 String；与 fabric PeerId 对齐是后续
    Egress { peer: String },    // peer = "self" 表示本地出口
    Drop,
}
```

### 2. `Router` trait 接受 `RouteRequest`（为 P1 预留）

```rust
pub struct RouteRequest<'a> {
    pub packet: &'a [u8],
    pub domain: Option<&'a str>,  // P0=None；P1 DNS 劫持填充，不改 trait
}

pub trait Router: Send + Sync {
    fn route(&self, req: &RouteRequest) -> RouteTarget;
}
```

决策流水线在 `nexus-projection/src/routing.rs`：
`UnifiedRouter { fib: FibChecker, rules: Box<dyn RuleEngine> }`

### 3. `RuleEngine` trait 放 `nexus-domain`，P0 实现最小版

```rust
// nexus-domain
pub trait RuleEngine: Send + Sync {
    fn decide(&self, req: &RouteRequest) -> RouteTarget;
}
```

P0：`nexus-projection` 内 `SimpleRuleEngine`（IP/CIDR/端口规则）。
P1+：完整版（域名/geoip/进程）可独立实现，不改 trait。

### 4. `egress.rs`：UDP NAT，连接跟踪表协议无关设计

`nexus-projection/src/egress.rs`：
- `EgressNat`：5 元组 → (源 peer, 出口 socket) 映射
- P0 只实现 UDP；表结构兼容 TCP（key 都是 5 元组）
- 超时回收：UDP 120s（可配置）

### 5. API：Builder 模式

```rust
Projection::new(tun, config)
    .with_router(router)      // P0 新增
    .with_egress(config)      // P0 新增（UDP NAT 开关）
```

### 6. E4 验收

- `fabric-egress-basic`：TUN 包 → 规则匹配 → Egress{self} → UDP NAT → 回包验证
- `fabric-egress-remote`：TUN 包 → Egress{peer} → 对端 NAT → 回包（mock peer）

## 长远演进路径

- 3b-2：Egress{peer} 跨节点 + 回包 + 跳数防环（`RouteTarget` 不变）
- 3b-3：DNS 劫持 → `RouteRequest.domain` 填充 → 域名规则（trait 不变）
- L4 中继后：TCP NAT（`egress.rs` 表结构已兼容）
- 完整规则引擎：实现 `RuleEngine` trait 即可替换 `SimpleRuleEngine`

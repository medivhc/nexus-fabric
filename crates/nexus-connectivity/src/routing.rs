#![allow(deprecated)] // §12.57 退役模块：内部实现允许自引用
//! 多跳动态路由（Distance Vector，P1.1 PRODUCT §12.6）。
//!
//! 本模块是 v9 CLI 产品线运行时（frozen）的路由骨架：
//! - **距离矢量（Bellman-Ford 简化版）**：节点只知道"到目的地经谁、代价多少"，
//!   通过邻居间周期性交换路由通告（`RoutingAdvertisement`）逐步收敛；
//! - **水平分割（Split Horizon）**：从邻居 X 学到的路由，不再通告回 X，
//!   防简单计数到无穷；
//! - **逻辑时钟**：路由超时由显式 `now_tick: u64` 推进，不 sleep、不 tokio、
//!   不 spawn——纯同步纯函数骨架，真实 UDP/socket 留 TODO；
//! - **TTL 防环路**：每个可转发包带 `ttl: u8`（初始 64），每跳 -1，到 0 丢弃。
//!
//!
//! 事件通道语义：路由增/改/过期事件由 RoutingTable::apply_advertisement /
//! expire_stale 的返回值（Vec<RoutingEvent>）暴露；转发与 TtlExceeded 事件由
//! MultihopRouter 内部累积，通过 events() / take_events() 消费。
//! 边界（PRODUCT §12.6 冻结）：
//! - <=3 跳线性/小网状拓扑；不做完整 Bellman-Ford 全量迭代、不做 poison reverse；
//! - 不跨子网、不接加密、不做真实 TUN/socket（纯内存 mock）。
//!
//! 错误面独立：`RoutingError` 是本模块自有类型化 enum，不依赖 `ConnectivityError`
//! 的字符串匹配（与 §12.5 静态路由的 `NO_ROUTE_TO_DST` 字符串错误解耦）。

use std::collections::HashMap;

/// 路由相关结构化错误（delivery 层自有错误面，类型化，不以 panic/日志代替）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingError {
    /// 路由表中没有到 dst 的条目（与 §12.5 语义对齐，但本模块独立 enum）。
    NoRouteToDst {
        /// 目标虚拟 IP。
        dst: String,
    },
    /// TTL 耗尽仍未到达目的地（防无限循环）。
    TtlExceeded {
        /// 目标虚拟 IP。
        dst: String,
        /// 已经过的跳数。
        hops: u32,
    },
    /// 输入包字段非法（空 src/dst 等）。
    InvalidPacket {
        /// 可诊断原因。
        message: String,
    },
    /// 转发目标不是直连邻居（骨架期由上层校验；路由表只保证 next_hop 是已学路由，
    /// 不强制 next_hop 必须在 direct_peers 集合内——本变体供上层显式校验时使用）。
    NotADirectPeer {
        /// 被校验的对端虚拟 IP。
        peer: String,
    },
}

impl core::fmt::Display for RoutingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoRouteToDst { dst } => write!(f, "NO_ROUTE_TO_DST: no route to {dst}"),
            Self::TtlExceeded { dst, hops } => {
                write!(f, "TTL_EXCEEDED: packet to {dst} expired after {hops} hops")
            }
            Self::InvalidPacket { message } => write!(f, "ROUTE_INVALID_PACKET: {message}"),
            Self::NotADirectPeer { peer } => {
                write!(f, "ROUTE_NOT_A_DIRECT_PEER: {peer} is not a direct peer")
            }
        }
    }
}

impl std::error::Error for RoutingError {}

// ---------- 路由表条目与通告 ----------

/// 路由表条目：到某虚拟 IP 的下一跳、代价、最后刷新时间（逻辑 tick）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    /// 目标虚拟 IP。
    pub destination: String,
    /// 下一跳虚拟 IP（直连邻居）。
    pub next_hop: String,
    /// 代价（直连=1，每多一跳 +1）。
    pub cost: u32,
    /// 最后刷新 tick（由 apply_advertisement / add_direct_peer 写入）。
    pub last_updated_tick: u64,
}

impl RouteEntry {
    /// 构造一条路由条目。
    #[must_use]
    pub fn new(
        destination: impl Into<String>,
        next_hop: impl Into<String>,
        cost: u32,
        last_updated_tick: u64,
    ) -> Self {
        Self {
            destination: destination.into(),
            next_hop: next_hop.into(),
            cost,
            last_updated_tick,
        }
    }
}

/// 路由通告：发给邻居的 (dst, cost) 列表（邻居视角的距离矢量视图）。
pub type RoutingAdvertisement = Vec<(String, u32)>;

// ---------- 路由事件（Worker 只发事件，Owner 状态机消费） ----------

/// 路由/转发过程的结构化事件（可重放、可 explain）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingEvent {
    /// 新增一条路由。
    RouteAdded {
        /// 目标虚拟 IP。
        dst: String,
        /// 下一跳。
        next_hop: String,
        /// 代价。
        cost: u32,
    },
    /// 已有路由的代价/下一跳更新。
    RouteUpdated {
        /// 目标虚拟 IP。
        dst: String,
        /// 旧代价。
        old_cost: u32,
        /// 新代价。
        new_cost: u32,
    },
    /// 路由超时被删除。
    RouteExpired {
        /// 被删除的目标虚拟 IP。
        dst: String,
    },
    /// 本节点作为中间转发节点，把包转发给下一跳。
    PacketForwarded {
        /// 原始源虚拟 IP。
        src: String,
        /// 最终目标虚拟 IP。
        dst: String,
        /// 实际转发到的下一跳。
        next_hop: String,
        /// 转发后剩余 TTL。
        ttl: u8,
    },
    /// TTL 耗尽丢弃。
    TtlExceeded {
        /// 目标虚拟 IP。
        dst: String,
        /// 已经过跳数。
        hop_count: u32,
    },
}

// ---------- 路由表 ----------

/// 单节点距离矢量路由表。
///
/// 纯数据结构：所有方法同步、无 I/O、无 spawn。时间由显式 `now_tick` 推进。
#[derive(Debug, Clone)]
/// 已退役（§12.57）：距离矢量路由已被 `nexus-discovery` FIB 取代。
/// 保留用于历史测试，新代码请勿使用。
#[deprecated(
    since = "0.1.0",
    note = "retired by §12.57; use nexus-discovery FIB instead"
)]
pub struct RoutingTable {
    /// 本节点虚拟 IP（用于判断本地交付）。
    local_virtual_ip: String,
    /// dst -> 路由条目。
    entries: HashMap<String, RouteEntry>,
    /// 直连邻居集合（cost=1，永久有效，不参与超时）。
    direct_peers: HashMap<String, u64>,
}

impl RoutingTable {
    /// 为本节点虚拟 IP 新建空路由表。
    #[must_use]
    pub fn new(local_virtual_ip: impl Into<String>) -> Self {
        Self {
            local_virtual_ip: local_virtual_ip.into(),
            entries: HashMap::new(),
            direct_peers: HashMap::new(),
        }
    }

    /// 本节点虚拟 IP。
    #[must_use]
    pub fn local_virtual_ip(&self) -> &str {
        &self.local_virtual_ip
    }

    /// 注册一个直连邻居（cost=1，在 `now_tick` 时刻"刷新"）。
    ///
    /// 直连邻居同时写入 `entries[peer] = { next_hop: peer, cost: 1 }`，
    /// 便于转发路径统一查表；超时不会删除直连条目（直连由链路层维护）。
    pub fn add_direct_peer(&mut self, peer_virtual_ip: impl Into<String>, now_tick: u64) {
        let peer = peer_virtual_ip.into();
        self.direct_peers.insert(peer.clone(), now_tick);
        self.entries.insert(
            peer.clone(),
            RouteEntry::new(peer.clone(), peer.clone(), 1, now_tick),
        );
    }

    /// 直连邻居数量（供 E4 断言/统计）。
    #[must_use]
    pub fn direct_peer_count(&self) -> usize {
        self.direct_peers.len()
    }

    /// 直连邻居视图。
    #[must_use]
    pub fn direct_peers(&self) -> Vec<&str> {
        self.direct_peers.keys().map(String::as_str).collect()
    }

    /// 是否为直连邻居。
    #[must_use]
    pub fn is_direct_peer(&self, peer: &str) -> bool {
        self.direct_peers.contains_key(peer)
    }

    /// 应用来自 `from_peer` 的路由通告（距离矢量合并）。
    ///
    /// 规则见 PRODUCT §12.6：
    /// 1. 跳过 `dst == from_peer` 的条目（对端自身由 `add_direct_peer` 维护）；
    /// 2. `candidate = cost_via + 1`；
    /// 3. 本地无 → 新增；
    /// 4. 本地有且 `next_hop == from_peer` → 刷新时间戳（cost 变了就更新 + RouteUpdated）；
    /// 5. 本地有但 `candidate < existing.cost` → 切下一跳 + RouteUpdated；
    /// 6. 其他情况保持不动。
    ///
    /// 返回本次应用产生的事件序列（RouteAdded / RouteUpdated）。
    pub fn apply_advertisement(
        &mut self,
        from_peer: &str,
        adv: &[(String, u32)],
        now_tick: u64,
    ) -> Vec<RoutingEvent> {
        let mut events = Vec::new();
        for (dst, cost_via) in adv {
            // 水平分割的接收侧护栏：不对 from_peer 本身再学一条经 from_peer 的路由。
            if dst == from_peer {
                continue;
            }
            // 自己也不该通过邻居学到"自己"。
            if dst == &self.local_virtual_ip {
                continue;
            }
            let candidate = cost_via.saturating_add(1);

            match self.entries.get_mut(dst) {
                None => {
                    self.entries.insert(
                        dst.clone(),
                        RouteEntry::new(dst.clone(), from_peer.to_string(), candidate, now_tick),
                    );
                    events.push(RoutingEvent::RouteAdded {
                        dst: dst.clone(),
                        next_hop: from_peer.to_string(),
                        cost: candidate,
                    });
                }
                Some(existing) => {
                    if existing.next_hop == from_peer {
                        // 同下一跳：刷新时间戳；cost 变了就更新并发 RouteUpdated。
                        existing.last_updated_tick = now_tick;
                        if existing.cost != candidate {
                            let old = existing.cost;
                            existing.cost = candidate;
                            events.push(RoutingEvent::RouteUpdated {
                                dst: dst.clone(),
                                old_cost: old,
                                new_cost: candidate,
                            });
                        }
                    } else if candidate < existing.cost {
                        // 更优路径经 from_peer：切换下一跳。
                        let old = existing.cost;
                        existing.next_hop = from_peer.to_string();
                        existing.cost = candidate;
                        existing.last_updated_tick = now_tick;
                        events.push(RoutingEvent::RouteUpdated {
                            dst: dst.clone(),
                            old_cost: old,
                            new_cost: candidate,
                        });
                    }
                    // 否则保持原条目。
                }
            }
        }
        events
    }

    /// 查找到 `dst` 的路由条目。
    #[must_use]
    pub fn lookup(&self, dst: &str) -> Option<&RouteEntry> {
        self.entries.get(dst)
    }

    /// 路由表快照（调试/断言用）。
    #[must_use]
    pub fn entries(&self) -> &HashMap<String, RouteEntry> {
        &self.entries
    }

    /// 生成发给 `neighbor` 的路由视图（执行水平分割：不把 next_hop == neighbor 的
    /// 条目发回去——即从 neighbor 学到的路由不再通告回 neighbor）。
    ///
    /// 注意：直连邻居自身（`entries[neighbor]` 这种 next_hop == neighbor == dst
    /// 的自反条目）也会被跳过，因为它对 neighbor 来说就是"自己"，无意义。
    #[must_use]
    pub fn advertise_to(&self, neighbor: &str) -> RoutingAdvertisement {
        self.entries
            .values()
            .filter(|e| e.next_hop != neighbor)
            .map(|e| (e.destination.clone(), e.cost))
            .collect()
    }

    /// 超时删除：删除 `now_tick - last_updated_tick > ticks_to_live` 的非直连条目。
    ///
    /// 直连邻居条目永不超时（由链路层维护）。返回被删除的事件序列。
    pub fn expire_stale(&mut self, now_tick: u64, ticks_to_live: u64) -> Vec<RoutingEvent> {
        let expired: Vec<String> = self
            .entries
            .iter()
            .filter(|(dst, e)| {
                // 直连条目（dst == next_hop == 自己直连的对端）永不超时。
                if self.direct_peers.contains_key(*dst) {
                    return false;
                }
                now_tick.saturating_sub(e.last_updated_tick) > ticks_to_live
            })
            .map(|(dst, _)| dst.clone())
            .collect();
        let mut events = Vec::new();
        for dst in &expired {
            self.entries.remove(dst);
            events.push(RoutingEvent::RouteExpired { dst: dst.clone() });
        }
        events
    }
}

// ---------- 可转发包与转发决策 ----------

/// 内存 mock 可转发包（TODO：接入真实 IP 头解析后替换为字节流视图）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutablePacket {
    /// 源虚拟 IP。
    pub src: String,
    /// 目标虚拟 IP。
    pub dst: String,
    /// 剩余 TTL（初始 64，每跳 -1）。
    pub ttl: u8,
    /// 负载（不解释，原样转发）。
    pub payload: Vec<u8>,
}

impl RoutablePacket {
    /// 构造一个新包，TTL 固定初始值 64（PRODUCT §12.6）。
    #[must_use]
    pub fn new(
        src: impl Into<String>,
        dst: impl Into<String>,
        payload: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            src: src.into(),
            dst: dst.into(),
            ttl: 64,
            payload: payload.into(),
        }
    }
}

/// 转发决策。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardDecision {
    /// 本地交付（dst == 本节点）。
    DeliverLocal,
    /// 转发给下一跳（包的 TTL 已减一）。
    ForwardTo {
        /// 下一跳虚拟 IP。
        next_hop: String,
        /// 转发后的剩余 TTL。
        ttl: u8,
    },
    /// 丢弃（无路由 / TTL 0 已在错误里表达，这里保留给上层显式 drop 用）。
    Drop,
}

// ---------- 多跳路由器 ----------

/// 多跳路由器：组合路由表 + 转发函数，累积路由/转发事件。
///
/// 纯同步纯函数：`forward` 只查路由表并返回决策，不真正发包；
/// 真实 UDP/socket 发送由 Composition Root 在拿到 `ForwardTo` 后完成（TODO）。
/// 已退役（§12.57）：见 `RoutingTable`。
#[deprecated(
    since = "0.1.0",
    note = "retired by §12.57; use nexus-discovery FIB instead"
)]
pub struct MultihopRouter {
    /// 路由表。
    table: RoutingTable,
    /// 累积事件流（供 Owner 状态机消费；`take_events` 取走）。
    events: Vec<RoutingEvent>,
}

impl MultihopRouter {
    /// 为本节点虚拟 IP 新建空路由器。
    #[must_use]
    pub fn new(local_virtual_ip: impl Into<String>) -> Self {
        Self {
            table: RoutingTable::new(local_virtual_ip),
            events: Vec::new(),
        }
    }

    /// 只读路由表。
    #[must_use]
    pub fn table(&self) -> &RoutingTable {
        &self.table
    }

    /// 可变路由表（用于 add_direct_peer / apply_advertisement / expire_stale）。
    pub fn table_mut(&mut self) -> &mut RoutingTable {
        &mut self.table
    }

    /// 累积事件流只读视图。
    #[must_use]
    pub fn events(&self) -> &[RoutingEvent] {
        &self.events
    }

    /// 取走并清空事件流（Owner 消费）。
    pub fn take_events(&mut self) -> Vec<RoutingEvent> {
        std::mem::take(&mut self.events)
    }

    /// 决策如何处理一个收到的包。
    ///
    /// `now_tick` 仅用于在需要时记录事件时间相关上下文；本函数不修改路由表时间戳
    /// （超时由上层显式调 `expire_stale` 推进，避免转发热路径副作用）。
    ///
    /// 规则（PRODUCT §12.6）：
    /// 1. dst 为空 / src 为空 → `InvalidPacket`；
    /// 2. dst == 本节点 → `DeliverLocal`；
    /// 3. ttl == 0 → `TtlExceeded` + 事件；
    /// 4. 查表命中 → `ForwardTo { next_hop, ttl: packet.ttl - 1 }` + `PacketForwarded` 事件；
    /// 5. 未命中 → `NoRouteToDst`。
    pub fn forward(
        &mut self,
        packet: &RoutablePacket,
        _now_tick: u64,
    ) -> Result<ForwardDecision, RoutingError> {
        if packet.dst.is_empty() {
            return Err(RoutingError::InvalidPacket {
                message: "dst virtual ip is empty".to_string(),
            });
        }
        if packet.src.is_empty() {
            return Err(RoutingError::InvalidPacket {
                message: "src virtual ip is empty".to_string(),
            });
        }

        // 本地交付。
        if packet.dst == self.table.local_virtual_ip {
            return Ok(ForwardDecision::DeliverLocal);
        }

        // TTL 耗尽防环路。
        if packet.ttl == 0 {
            let hops = 64u32.saturating_sub(packet.ttl as u32);
            self.events.push(RoutingEvent::TtlExceeded {
                dst: packet.dst.clone(),
                hop_count: hops,
            });
            return Err(RoutingError::TtlExceeded {
                dst: packet.dst.clone(),
                hops,
            });
        }

        // 查表。
        let entry = self
            .table
            .lookup(&packet.dst)
            .ok_or_else(|| RoutingError::NoRouteToDst {
                dst: packet.dst.clone(),
            })?;

        let next_hop = entry.next_hop.clone();
        let new_ttl = packet.ttl.saturating_sub(1);
        self.events.push(RoutingEvent::PacketForwarded {
            src: packet.src.clone(),
            dst: packet.dst.clone(),
            next_hop: next_hop.clone(),
            ttl: new_ttl,
        });
        Ok(ForwardDecision::ForwardTo {
            next_hop,
            ttl: new_ttl,
        })
    }
}

#[cfg(test)]
#[allow(deprecated)] // 历史测试：退役模块的回归覆盖
mod tests {
    use super::*;

    /// 构造 4 节点线性拓扑的初始直连状态。
    /// A=10.0.0.1 -- B=10.0.0.2 -- C=10.0.0.3 -- D=10.0.0.4
    fn build_line_routers() -> (
        MultihopRouter,
        MultihopRouter,
        MultihopRouter,
        MultihopRouter,
    ) {
        let mut a = MultihopRouter::new("10.0.0.1");
        let mut b = MultihopRouter::new("10.0.0.2");
        let mut c = MultihopRouter::new("10.0.0.3");
        let mut d = MultihopRouter::new("10.0.0.4");
        a.table_mut().add_direct_peer("10.0.0.2", 0);
        b.table_mut().add_direct_peer("10.0.0.1", 0);
        b.table_mut().add_direct_peer("10.0.0.3", 0);
        c.table_mut().add_direct_peer("10.0.0.2", 0);
        c.table_mut().add_direct_peer("10.0.0.4", 0);
        d.table_mut().add_direct_peer("10.0.0.3", 0);
        (a, b, c, d)
    }

    #[test]
    fn direct_peer_has_cost_one() {
        let mut a = MultihopRouter::new("10.0.0.1");
        a.table_mut().add_direct_peer("10.0.0.2", 0);
        let e = a.table().lookup("10.0.0.2").expect("direct route");
        assert_eq!(e.cost, 1);
        assert_eq!(e.next_hop, "10.0.0.2");
        assert!(a.table().is_direct_peer("10.0.0.2"));
        assert!(!a.table().is_direct_peer("10.0.0.3"));
    }

    #[test]
    fn learns_two_hop_route_from_neighbor_advertisement() {
        let mut a = MultihopRouter::new("10.0.0.1");
        let mut b = MultihopRouter::new("10.0.0.2");
        a.table_mut().add_direct_peer("10.0.0.2", 0);
        b.table_mut().add_direct_peer("10.0.0.1", 0);
        b.table_mut().add_direct_peer("10.0.0.3", 0);

        // B 通告给 A："我到 10.0.0.3 的代价是 1（直连）"。
        let adv = b.table().advertise_to("10.0.0.1");
        // 水平分割：B 不应把 10.0.0.1（next_hop==10.0.0.1）通告回 A。
        assert!(adv.iter().all(|(dst, _)| dst != "10.0.0.1"));
        let events = a.table_mut().apply_advertisement("10.0.0.2", &adv, 1);
        // A 应学到 10.0.0.3，cost = 1+1 = 2。
        let e = a.table().lookup("10.0.0.3").expect("learned route");
        assert_eq!(e.cost, 2);
        assert_eq!(e.next_hop, "10.0.0.2");
        assert!(
            events
                .iter()
                .any(|ev| matches!(ev, RoutingEvent::RouteAdded { .. }))
        );
    }

    #[test]
    fn cheaper_cost_replaces_route() {
        let mut a = MultihopRouter::new("10.0.0.1");
        // 先经 B 学到 C，cost=4（模拟旧的更贵路径）。
        a.table_mut().entries.insert(
            "10.0.0.3".to_string(),
            RouteEntry::new("10.0.0.3", "10.0.0.2", 4, 0),
        );
        // 从邻居 E=10.0.0.5 收到更优通告：到 C 代价 1 → 经 E 后 A 代价 2。
        let events =
            a.table_mut()
                .apply_advertisement("10.0.0.5", &[("10.0.0.3".to_string(), 1)], 1);
        let e = a.table().lookup("10.0.0.3").expect("rerouted");
        assert_eq!(e.cost, 2);
        assert_eq!(e.next_hop, "10.0.0.5");
        assert!(events.iter().any(|ev| matches!(
            ev,
            RoutingEvent::RouteUpdated {
                old_cost: 4,
                new_cost: 2,
                ..
            }
        )));
    }

    #[test]
    fn split_horizon_does_not_readvertise_back_to_learned_neighbor() {
        // A 从 B 学到 C。
        let mut a = RoutingTable::new("10.0.0.1");
        a.add_direct_peer("10.0.0.2", 0);
        a.entries.insert(
            "10.0.0.3".to_string(),
            RouteEntry::new("10.0.0.3", "10.0.0.2", 2, 0),
        );
        // A 通告给 B 时，不应包含 next_hop == 10.0.0.2 的条目（即 10.0.0.3）。
        let adv = a.advertise_to("10.0.0.2");
        assert!(
            adv.iter().all(|(dst, _)| dst != "10.0.0.3"),
            "split horizon must not readvertise route learned from B back to B: {adv:?}"
        );
    }

    #[test]
    fn advertisement_skips_from_peer_self_entry() {
        let mut a = RoutingTable::new("10.0.0.1");
        a.add_direct_peer("10.0.0.2", 0);
        // B 通告自己 (10.0.0.2, 0)——A 应跳过，不重复插入。
        let events = a.apply_advertisement("10.0.0.2", &[("10.0.0.2".to_string(), 0)], 1);
        assert!(
            events.is_empty(),
            "self entry must be ignored, got {events:?}"
        );
        let e = a.lookup("10.0.0.2").expect("still direct");
        assert_eq!(e.cost, 1);
    }

    #[test]
    fn stale_route_expires_after_ttl() {
        let mut a = RoutingTable::new("10.0.0.1");
        a.add_direct_peer("10.0.0.2", 0);
        a.entries.insert(
            "10.0.0.3".to_string(),
            RouteEntry::new("10.0.0.3", "10.0.0.2", 2, 0),
        );
        // ttl=5；now=10 → 间隔 10 > 5，过期。
        let events = a.expire_stale(10, 5);
        assert!(
            a.lookup("10.0.0.3").is_none(),
            "non-direct route must expire"
        );
        // 直连条目不过期。
        assert!(a.lookup("10.0.0.2").is_some());
        assert!(
            events
                .iter()
                .any(|ev| matches!(ev, RoutingEvent::RouteExpired { dst } if dst == "10.0.0.3"))
        );
    }

    #[test]
    fn packet_ttl_decrements_to_zero_triggers_ttl_exceeded() {
        let mut router = MultihopRouter::new("10.0.0.1");
        router.table_mut().add_direct_peer("10.0.0.2", 0);
        // 构造一个 ttl=0 的包（模拟已经经过 64 跳）。
        let pkt = RoutablePacket {
            src: "10.0.0.9".to_string(),
            dst: "10.0.0.2".to_string(),
            ttl: 0,
            payload: vec![1, 2, 3],
        };
        let err = router.forward(&pkt, 0).expect_err("ttl must be exhausted");
        assert!(matches!(err, RoutingError::TtlExceeded { .. }));
        assert!(
            router
                .events()
                .iter()
                .any(|ev| matches!(ev, RoutingEvent::TtlExceeded { .. }))
        );
    }

    #[test]
    fn no_route_returns_no_route_to_dst() {
        let mut router = MultihopRouter::new("10.0.0.1");
        router.table_mut().add_direct_peer("10.0.0.2", 0);
        let pkt = RoutablePacket::new("10.0.0.1", "10.0.0.99", b"hi");
        let err = router.forward(&pkt, 0).expect_err("no route");
        assert!(matches!(err, RoutingError::NoRouteToDst { dst } if dst == "10.0.0.99"));
    }

    #[test]
    fn local_delivery_short_circuits_before_lookup() {
        let mut router = MultihopRouter::new("10.0.0.1");
        // 故意不注册任何路由，但包 dst 就是自己。
        let pkt = RoutablePacket::new("10.0.0.2", "10.0.0.1", b"hi");
        let decision = router.forward(&pkt, 0).expect("local delivery");
        assert_eq!(decision, ForwardDecision::DeliverLocal);
    }

    #[test]
    fn empty_src_or_dst_returns_invalid_packet() {
        let mut router = MultihopRouter::new("10.0.0.1");
        // dst 为空。
        let pkt_empty_dst = RoutablePacket {
            src: "10.0.0.2".to_string(),
            dst: String::new(),
            ttl: 64,
            payload: b"hi".to_vec(),
        };
        let err = router
            .forward(&pkt_empty_dst, 0)
            .expect_err("empty dst must fail");
        assert!(matches!(err, RoutingError::InvalidPacket { .. }));

        // src 为空。
        let pkt_empty_src = RoutablePacket {
            src: String::new(),
            dst: "10.0.0.99".to_string(),
            ttl: 64,
            payload: b"hi".to_vec(),
        };
        let err = router
            .forward(&pkt_empty_src, 0)
            .expect_err("empty src must fail");
        assert!(matches!(err, RoutingError::InvalidPacket { .. }));
    }

    #[test]
    fn worse_cost_from_another_neighbor_does_not_replace_better_route() {
        let mut a = RoutingTable::new("10.0.0.1");
        // 直连 B。
        a.add_direct_peer("10.0.0.2", 0);
        // 直连 C。
        a.add_direct_peer("10.0.0.5", 0);
        // 先经 B 学到 D：B 到 D cost=2 -> A 到 D cost=3。
        a.apply_advertisement("10.0.0.2", &[("10.0.0.4".to_string(), 2)], 1);
        let e = a.lookup("10.0.0.4").expect("A learns D via B");
        assert_eq!(e.cost, 3);
        assert_eq!(e.next_hop, "10.0.0.2");

        // 再从另一个邻居 C(10.0.0.5) 收到更差的通告：C 到 D cost=4 -> A 候选 cost=5。
        let events = a.apply_advertisement("10.0.0.5", &[("10.0.0.4".to_string(), 4)], 2);
        // 不应产生 RouteUpdated（更差路径不替换）。
        assert!(
            events.is_empty(),
            "worse-cost advertisement must not replace, got {events:?}"
        );
        let e = a.lookup("10.0.0.4").expect("route still present");
        assert_eq!(e.cost, 3, "better cost must be preserved");
        assert_eq!(e.next_hop, "10.0.0.2", "better next-hop must be preserved");
    }
    #[test]
    fn four_node_line_converges_after_three_rounds() {
        let (mut a, mut b, mut c, mut d) = build_line_routers();

        // 邻居集合（按节点索引 0=A,1=B,2=C,3=D）。
        let neighbors: [Vec<&str>; 4] = [
            vec!["10.0.0.2"],
            vec!["10.0.0.1", "10.0.0.3"],
            vec!["10.0.0.2", "10.0.0.4"],
            vec!["10.0.0.3"],
        ];

        // 3 轮通告：每轮先快照所有节点"对每个邻居"的 advertise_to 视图（不可变借用），
        // 再统一按 (src, dst, adv) 投递（可变借用），避免同时持有两个 router 的可变引用。
        /// 一条 (src, dst, adv) 通告投递。
        type Delivery = (String, String, Vec<(String, u32)>);
        for tick in 1..=3u64 {
            // 不可变阶段：收集所有 (src, dst, adv) 三元组。
            let deliveries: Vec<Delivery> = [
                (&a, &neighbors[0]),
                (&b, &neighbors[1]),
                (&c, &neighbors[2]),
                (&d, &neighbors[3]),
            ]
            .into_iter()
            .flat_map(|(r, ns)| {
                ns.iter().map(move |n| {
                    (
                        r.table().local_virtual_ip().to_string(),
                        n.to_string(),
                        r.table().advertise_to(n),
                    )
                })
            })
            .collect();

            // 可变阶段：按目标节点投递。
            for (src, dst, adv) in deliveries {
                match dst.as_str() {
                    "10.0.0.1" => {
                        a.table_mut().apply_advertisement(&src, &adv, tick);
                    }
                    "10.0.0.2" => {
                        b.table_mut().apply_advertisement(&src, &adv, tick);
                    }
                    "10.0.0.3" => {
                        c.table_mut().apply_advertisement(&src, &adv, tick);
                    }
                    "10.0.0.4" => {
                        d.table_mut().apply_advertisement(&src, &adv, tick);
                    }
                    other => panic!("unexpected neighbor {other}"),
                }
            }
        }

        // 收敛后 A 到 D：next_hop=B(10.0.0.2)，cost=3。
        let a_to_d = a.table().lookup("10.0.0.4").expect("A learns D");
        assert_eq!(a_to_d.cost, 3);
        assert_eq!(a_to_d.next_hop, "10.0.0.2");
        // 对称：D 到 A。
        let d_to_a = d.table().lookup("10.0.0.1").expect("D learns A");
        assert_eq!(d_to_a.cost, 3);
        assert_eq!(d_to_a.next_hop, "10.0.0.3");
    }

    #[test]
    fn packet_forwarded_three_hops_with_decrementing_ttl() {
        let (mut a, mut b, mut c, mut d) = build_line_routers();
        // 收敛路由（手动预置 3 跳路由，避免依赖通告顺序）。
        a.table_mut().entries.insert(
            "10.0.0.4".to_string(),
            RouteEntry::new("10.0.0.4", "10.0.0.2", 3, 0),
        );
        b.table_mut().entries.insert(
            "10.0.0.4".to_string(),
            RouteEntry::new("10.0.0.4", "10.0.0.3", 2, 0),
        );
        c.table_mut().entries.insert(
            "10.0.0.4".to_string(),
            RouteEntry::new("10.0.0.4", "10.0.0.4", 1, 0),
        );

        // A 发包（初始 ttl=64）。
        let pkt = RoutablePacket::new("10.0.0.1", "10.0.0.4", b"payload");
        let d1 = a.forward(&pkt, 0).expect("A forwards");
        let (b_next, ttl_after_a) = match d1 {
            ForwardDecision::ForwardTo { next_hop, ttl } => (next_hop, ttl),
            other => panic!("A must forward, got {other:?}"),
        };
        assert_eq!(b_next, "10.0.0.2");
        assert_eq!(ttl_after_a, 63);

        // B 收到 ttl=63 的包。
        let pkt_b = RoutablePacket {
            ttl: ttl_after_a,
            ..pkt.clone()
        };
        let d2 = b.forward(&pkt_b, 0).expect("B forwards");
        let (c_next, ttl_after_b) = match d2 {
            ForwardDecision::ForwardTo { next_hop, ttl } => (next_hop, ttl),
            other => panic!("B must forward, got {other:?}"),
        };
        assert_eq!(c_next, "10.0.0.3");
        assert_eq!(ttl_after_b, 62);

        // C 收到 ttl=62 的包。
        let pkt_c = RoutablePacket {
            ttl: ttl_after_b,
            ..pkt.clone()
        };
        let d3 = c.forward(&pkt_c, 0).expect("C forwards");
        let (d_next, ttl_after_c) = match d3 {
            ForwardDecision::ForwardTo { next_hop, ttl } => (next_hop, ttl),
            other => panic!("C must forward, got {other:?}"),
        };
        assert_eq!(d_next, "10.0.0.4");
        assert_eq!(ttl_after_c, 61);

        // D 本地交付，看到 ttl=61。
        let pkt_d = RoutablePacket {
            ttl: ttl_after_c,
            ..pkt.clone()
        };
        let d4 = d.forward(&pkt_d, 0).expect("D delivers");
        assert_eq!(d4, ForwardDecision::DeliverLocal);
    }
}

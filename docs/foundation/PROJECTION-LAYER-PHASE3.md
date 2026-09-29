# 投影层 Phase 3 决策记录

**日期**: 2026-09-30
**状态**: 已决策（用户确认"按照你的想法继续"）
**对应设计**: `docs/foundation/DESIGN.md` §6（阶段 3）

## 背景

阶段 1（会话层 FabricConn）✅、阶段 2（路径层 PathManager）✅ 均已达到
Candidate Completion。阶段 3 实现投影层：应用无需修改，用标准 socket API，
地基在底下做自由高速传输。

DESIGN.md §6 有三部分：L3 隧道、语义入口、进程 QoS。

## 决策

### 1. 范围：先 L3 隧道

先做 **L3 隧道**（TUN 抓 IP 包 → 封装进 fabric 数据报 → 对端解封装注入 TUN）。
语义入口（SOCKS5/HTTP → fabric 流）做 3b，进程 QoS（平台相关）后置。

**理由**：L3 隧道是投影层的基础；语义入口可复用 `nexus-ingress` 已有解析器；
进程 QoS 涉及 `/proc/net/tcp` / WFP 平台相关，复杂度高，独立成 phase。

### 2. Crate 结构：新建 `nexus-projection`

新建独立 `nexus-projection` crate，拥有 TUN 设备 + 封装/解封装循环。

**理由**：投影（设备管理、包封装）与代理规则是独立变化维度；
现有 `nexus-proxy/tun.rs` 只做路由决策，不建设备。

### 3. TUN 设备：复用现有能力

`nexus-projection` 内建 `TunDevice` trait；Linux 实现复用
`nexus-platform-linux::TunVpi` 的 FFI 经验（见 knowledge `tun-dataplane`）。

**理由**：P3.2 已验证 Linux `/dev/net/tun` via ioctl 可用；不重复造轮子。
E4 用 loopback mock，E5 真机需权限（`cap_net_admin`）。

### 4. API 形态：sync（零 Tokio）

延续 fabric/path 的决策：sync API，仓库保持零 Tokio。

### 5. 验收场景

- `fabric_projection_basic`：TUN 包 → fabric 数据报 → 对端 TUN，
  loopback 验证包完整（IP 头 + 载荷一致）。
- `fabric_projection_roam`：TUN 传输中路径切换（复用 PathManager），
  验证包不丢、顺序不错。

## Knowledge 检索（2026-09-30 开工前）

- `tun-dataplane` (2026-09-21)：Linux `/dev/net/tun` ioctl；Windows wintun
  0.14 无 `WintunFreeAdapter`；E4 确定性闭环 + E5 真机两级验证；
  `UdpCarrier::receive_into` 非阻塞 WouldBlock → Ok(0) 是契约。
- `virtual-subnet-pitfalls` (2026-09-19)：scenario expect 路径必须与
  example JSON 顶层字段一致（先手动跑确认）；测试类型补 `Default`。

## 后续步骤（Contract-First）

1. `crates/nexus-projection/MODULE.md`（不变量、API、Deletion Test）
2. `scenarios/product/fabric_projection_basic.toml` + `fabric_projection_roam.toml`
3. Red Evidence（BLOCKED）
4. 冻结（Contract Hash）
5. 实现

## 风险

- TUN 设备创建需要 `cap_net_admin`；E4 用 mock TUN（内存环形缓冲），
  真机 E5 才用真实设备。
- IP 包封装格式需定义（简单起见：原始 IP 包直接作为 fabric datagram 载荷，
  对端直接注入 TUN；不做额外头部）。

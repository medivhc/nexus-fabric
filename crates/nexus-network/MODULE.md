# nexus-network Module Contract

## Responsibility

实现 InternetAccess Network Domain Runtime，消费 Policy/Plan/Session/Delivery/DNS 结果执行网络会话。

## Non-Responsibilities

不拥有 nexus-ingress；不把透明代理或 TUN 当成领域核心。

## Inputs

- 仅接受公开类型、DTO、trait、事件或稳定协议对象。
- 输入必须可被结构化验证；不得依赖未声明的全局隐式状态。

## Outputs

- 结构化 Result / Event / DTO。
- 失败必须保留可诊断原因，不以日志文本代替错误类型。

## Allowed Dependencies

- `nexus-domain`
- `nexus-policy`
- `nexus-planner`
- `nexus-session`
- `nexus-delivery`
- `nexus-dns`

## Forbidden Dependencies

- `engineering/` 下的 Harness/Plugin。
- 未在 `policies/architecture.toml` 声明的 Nexus 内部 crate。
- Portable 模块中的平台专有 Framework/API。
- 通过“便利”依赖绕过公开领域边界。

## Invariants

- nexus-network 不编译依赖 nexus-ingress。
- Ingress 与 Network Runtime 由 Composition Root 同时装配。

## Side Effects

- 仅允许 Responsibility 所需且在架构层中明确归属的副作用。
- 新增副作用前必须更新本契约和 Scenario/Policy（如影响外部行为）。

## Public API

### 冻结契约（remote P0 扩展，scenarios/product/remote_internet_access_flow.toml）

- `pub trait NetworkTransport`：注入的帧通道，避免 network -> transport 依赖边（架构允许依赖仅 domain/policy/planner/session/delivery/dns）；由组合根以 `transport::FrameStream` 适配装配。
  - `pub fn send_frame(&mut self, payload: &[u8]) -> Result<(), NetworkError>`
  - `pub fn recv_frame(&mut self) -> Result<Vec<u8>, NetworkError>`
- `pub struct NetworkSession`：InternetAccess 远程网络会话（PRODUCT §2/§6）。
  - `pub fn establish(transport: Box<dyn NetworkTransport>, request: &[u8]) -> Result<Self, NetworkError>`
    在已认证的帧通道上发送请求帧并接收响应帧；成功提取 HTTP 状态码后进入 Active。
  - `pub fn phase(&self) -> NetworkPhase`
  - `pub fn response_status(&self) -> Option<&str>`
- `pub enum NetworkPhase { Connecting, Active, Closed }`
- `pub enum NetworkError { Transport, Unauthorized, Closed }`

冻结语义：网络会话必须显式建立（establish 完成请求/响应往返后才 Active）；未通过认证的请求不得进入业务处理（W7）。

### 常规要求

- 默认最小 surface：`private -> pub(crate) -> pub`。
- Public API 变更必须保持结构化、可版本化并有调用方验证。

## Verification

最低：

```text
cargo check -p nexus-network
cargo clippy -p nexus-network --all-targets -- -D warnings
```

如果该模块影响产品行为，还必须映射 Integration/Scenario Evidence。

## Performance Budget

未定义性能预算的路径不得宣称“性能完成”。进入 hot path 后必须在 Contract 中增加 baseline、noise tolerance、warning threshold 与 blocking threshold。

## Observability

稳定结构化字段优先于自由文本；如涉及 Session/Provider/Path/Workspace，应携带对应 correlation id。

## Recovery Semantics

任何持久状态或长期任务都必须定义 crash 后的 reconcile 行为。无持久状态的纯模块应保持可重建。

## Platform Constraints

平台专有代码只允许存在于 `nexus-platform-*` 或 Composition Root。Portable crate 必须通过相应 portability gate。

---

# N1 Universal Connectivity 装配契约（M1–M7）

> Contract 阶段产物（Contract-First 阶段 A）。依据：
>
> - 产品定义基线：《Nexus Distributed Workspace 产品白皮书》v1.0（§6 统一连接与网络能力）
> - 技术设计基线：《Nexus 统一系统设计规范 v9》（Final Design Baseline，§1/§5/§8/§10/§12/§24）
> - 冲突裁决：产品概念以白皮书为准；系统架构与实现术语以 v9 规范为准。
>
> 本节是 **N1 Universal Connectivity** 的工程装配契约，**不是**新产品、不新增顶层领域模型。
> TUN、Packet Tunnel、Proxy、Relay、Multipath 均为执行机制（v9 §1）。
> 本文件上半部分的 InternetAccess 契约保持冻结，不受本节影响。

## N1 定位

- 本装配实现 v9 闭环中的 `nexus-network Runtime` 一段：
  `Create Network Session → Connectivity Establishment → Transport → VirtualPacketInterface`。
- 连接服务于资源使用（白皮书 §6.1）：本层向上提供可达状态、质量信息、失败原因与恢复事件；
  不独立做业务 Provider 选择（同 nexus-connectivity 的 Non-Responsibilities）。
- `nexusd` 只是内部 Composition Root；正式产品 CLI 是 `nexus`（M6）。

## M1–M7 冻结条款

### M1 范围

首期只做 VirtualPacketInterface 单播 IP 互通（节点间）。
Out of scope：广播/组播、DNS 劫持、系统代理（后置，不在本契约验收内）。

### M2 承载

- IP 包 → `FabricConn` unreliable datagram（`send_datagram`/`recv_datagram`）；内层 TCP 自己重传，语义正确。
- Link 保活/对端握手 → 可靠双向流（`open_bi`/`accept_bi`）。
- 这是 Transport Datagram/Stream 的执行机制选择，不改变 Transport 语义。

### M3 对端寻址（Identity ≠ Locator）

- 节点身份 = `PeerId`（ed25519 公钥，见 `docs/foundation/DESIGN.md` §8.1）；地址是 Locator。
- 首期：静态配置（`PeerId` + 已知 locator）；mDNS 同子网自动发现（`MdnsDiscovery`，
  见 nexus-discovery D1–D6）；LSA 暂不携带 locator（动线协议扩展后置）。
- locator→identity 映射属 Network Resource 领域信息，经 `NetworkPlanExtension`/Resource 配置表达，
  不在本 crate 内自建第二套注册表。

### M4 连接模型（Plan ≠ Session；Connection ≠ Session）

- 每个 Network Session 中，每对端**一个** `Connection`（`FabricConn` 多路复用全部流/数据报），
  按 `PeerId` 索引，与 UDP 地址解耦（`rebind()` 不换 CID，见 nexus-fabric S2/S3）。
- 此处的 Connection 是"Session 中实际建立的传输实例"（v9 §9），不是产品级 Session 的替代；
  不得出现与白皮书 Session（某次实际资源使用的上下文）同名异义的新概念。

### M5 漫游与重规划（Connectivity Evaluation ≠ Establishment）

- Link State 观测：keepalive 心跳超时（主；可靠双向流上的 ping/pong，见 `n1/link.rs`）+
  keepalive 流错误（辅）→ `discovery.resolve` → `rebind()`。
  （requirement-change C-3：原"socket 错误 + 周期重探测"措辞与实现不符，按实际触发器修正；行为未变。）
- 平台网络变更通知（Android/桌面）后置。
- 持续建连失败**只报告事实**，由 Session Runtime 反馈 Core Planner 生成替代 Plan（v9 §8.2）；
  本层不自行替换业务 Provider、不自建第二套 Planner。

### M6 命令面

- `nexus network`：N1 装配的启停/配置（新命令，经 Application API）。
- `nexus connectivity status/links/candidates/probe`：第一公民诊断入口（v9 §24；`connectivity` 已存在，`network` 新增）。
- CLI/GUI/SDK 只经 Application API 工作，不直接访问 Planner 内部状态或平台特权 API。

### M7 验收（E4）

`scenarios/product/n1_connectivity_roam.toml`：真机双节点（netns 隔离），VPI 子网内 TCP 传文件，
中途改一端 underlay 地址，断言传输不中断且 CID 不变。

## 引用的 v9 不变量

- `Identity ≠ Locator`、`Plan ≠ Session`、`Policy ≠ Path`、
  `Connectivity Evaluation ≠ Establishment`、`Connectivity ≠ Transport`、
  `Virtual Packet Interface ≠ TUN`、`Planner ≠ Estimator/Scheduler`（v9 §3；仓库 AGENTS.md §9）。
- 建连时序：`Resolve Candidate Providers → Plan Placement + Path → Create Session →
  Establish Connectivity → Execute`；禁止先对所有候选打洞再定 Plan。
- 全系统唯一 Core Planner；领域特定数据只进类型化、版本化的 `NetworkPlanExtension`。
- Connectivity/Transport 是共享 Delivery Infrastructure；禁止反向依赖 Workspace/Compute/Service 业务逻辑。
- Portable Core 禁止直接调用平台 API；`LinuxTunAdapter`（`TunVpi`）只存在于 `nexus-platform-linux`；
  跨平台统一抽象是 `VirtualPacketInterface`（`nexus-platform`），不是 Linux TUN（v9 §12）。
- `nexus-network` 不编译依赖 `nexus-ingress`；Ingress 与 Network Runtime 由 Composition Root 同时装配
  （既有不变量，保持）。

## 依赖（Allowed Dependencies 增补）

既有（保持）：`nexus-domain`、`nexus-policy`、`nexus-planner`、`nexus-session`、
`nexus-delivery`、`nexus-dns`。

N1 装配新增：

- `nexus-platform`（仅复用 `VirtualPacketInterface` trait；Deletion Test：自建同形 trait 会被删除，
  必须复用已存在的统一抽象）。`policies/architecture.toml` 同步增加该边（本契约提交一并修改）。
- `nexus-fabric`（`FabricConn`/`FabricListener`）、`nexus-path`（`FallbackChain`/`race_connect`）、
  `nexus-discovery`（`AggregateDiscovery::resolve`）：**经注入 trait 消费，不新增架构边**。
  遵循本 crate 既有 `NetworkTransport` 注入先例（"避免 network -> transport 依赖边"）；
  具体实现由 Composition Root 装配。

## Deletion Test（新增抽象）

- `VirtualPacketInterface`：已存在（`nexus-platform`），**复用**，不新增。
- `TunVpi`（LinuxTunAdapter）：已存在（`nexus-platform-linux`），**复用**，不新增。
- N1 会话/连接表（`PeerId → Connection` + 生命周期）：若删除，Session 生命周期语义与裸连接 map 混杂，
  "建连失败反馈 Planner"失去唯一 Owner；独立变化维度成立，允许新增（确切名称实现阶段冻结）。
- Link 观测器（keepalive 心跳超时主 + 流错误辅 → `rebind`）：若删除，观测逻辑散落，"观测 vs 执行"边界消失；
  允许新增（实现阶段冻结）。
- 注入 trait（Transport / Establishment / Discovery 三件）：理由 = 依赖反转（AGENTS.md §12 明确允许），
  避免 `nexus-network` 反向依赖 delivery 层以下的具体实现。

## Public API（拟冻结，实现阶段正式冻结）

- 复用（不重新定义）：`nexus_platform::VirtualPacketInterface`、
  `nexus_fabric::{FabricConn, FabricListener, PeerId}`（经注入 trait）。
- 新增（最小 surface，`pub` 前必须过 API 面评审）：
  - N1 会话/连接表：按 `PeerId` 索引的单 Connection 管理；`dial` 走注入的 Establishment；
    `inbound` 走 `FabricListener`。
  - Link 观测器：keepalive 心跳超时（主）/ 流错误（辅）→ `rebind`；失败事件结构化上报
    （携带 `connection_id`/`peer_id`，不以日志文本代替错误类型）。
- 冻结语义：`rebind()` 不改变 `ConnectionId`（沿用 nexus-fabric S2/S3）；建连失败事件必须保留可诊断原因，
  支持 `Retry`/`Fallback`/`Abort`/`Escalate` 四类处置判定。

## 诚实边界

- 首期 Linux only（E4 在 xc-pc-linux netns；其他平台 VPI 适配器存在但装配 E4 未做；
  Android 需 Underlay Bypass，首期不做）。
- mDNS 只同子网；跨网靠静态配置或 Relay。
- 信任模型：预共享 `peer_id`（静态配置）；无 PKI、无握手认证——后置。
- Relay 本期只用于 Establishment fallback；传输中 Relay 断了的重建后置。
- 建立失败只报告失败事实，不自行替换业务 Provider（v9 §8.2）。
- 不宣称与公网 ss/trojan 服务互操作（沿用既有边界）；VMess 不做（standing）。
- E4 驱动必须走生产路径（知识条目 `e4-must-use-production-path`）：example 只做外部可观察操作
  （发包、等统计、读 JSON），禁止"上帝之手"直接调内部函数补状态。
- netns 测试必须先拉起 lo（知识条目 `os-assemble-lo-unshare`）。

## Verification（本契约）

- Contract 阶段：本 MODULE.md 增补 + `scenarios/product/n1_connectivity_roam.toml` +
  Red Evidence（旧实现上 BLOCKED）→ contract hash 冻结。
- 实现阶段：E4 `product.n1-connectivity-roam` 在 xc-pc-linux 真机（netns 双节点）PASS；
  独立 8 维 Review；full verify。

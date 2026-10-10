# nexus-plugin — MODULE

## Responsibility

混淆传输插件机制（DESIGN §7 首期）：进程内 trait + 接口版本化 + 编译期
静态注册。GFW 会升级探测，混淆手段必须能热插拔而不动核心——这是本 crate
存在的第一原因，不是通用扩展性。

## Non-Responsibilities

- 路径提供方 / 选路策略插件点（DESIGN §7.1 的另两个点，后置，不预留 trait）。
- 出站协议（ss/trojan/vmess）的拨号路径改造（后置；本期只定义钩子签名）。
- 动态库加载（`dlopen`，后置）。

## Inputs

- `TcpStream`（已建立的出站连接）+ `ObfsParams`（插件参数，如密钥）。
- 二进制启动时的显式注册调用。

## Outputs

- `ObfuscateTransport` trait：`name()` / `api_version()` /
  `wrap(stream: TcpStream, params: &ObfsParams) -> io::Result<Box<dyn ObfuscatedStream>>`
- `ObfuscatedStream: Read + Write + Send`（混淆后的字节流）。
- `PluginRegistry`：`register()`（版本硬校验+重名拒绝）/ `get(name)` / `names()`。
- 内置插件：`plain`（直通，默认）/ `xor`（演示混淆，key 来自 params）。

## Allowed Dependencies

- `std` only（零 Tokio，与全仓库一致）
- 零第三方依赖（首期）

## Forbidden Dependencies

- `tokio`, `async-std`, 任何 async runtime
- `libloading` / 动态库加载（后置）
- `nexus-outbound-*`（依赖倒置：出站 crate 未来依赖本 crate，本 crate 不反向依赖）

## Invariants

**S1（插件点唯一）**：首期只开放混淆传输插件点；路径提供方、选路策略
不设 trait、不预留注册表。

**S2（版本硬校验）**：`OBFUSCATE_API_VERSION: u32 = 1`；`register()` 时
`plugin.api_version() != OBFUSCATE_API_VERSION` → 拒绝并返回
`PluginError::IncompatibleApiVersion { name, got, expected }`；同名重复注册 →
`PluginError::DuplicatePlugin(name)`。版本检查是注册的前置条件，
运行时不再检查。

**S3（静态注册）**：编译期显式注册——各插件 crate 暴露
`register(&mut PluginRegistry)`（本 crate 的 `builtin::register_all`），
由二进制在启动时调用；无运行时动态发现。

**S4（流语义）**：`wrap` 失败 → 返回 `io::Error`，本层**不自动回退**
（回退到直连是调用方的决策）；`ObfuscatedStream` 不得改变连接语义
（仍是同一条 TCP 连接的字节流，只是字节被变换）。

**S5（sync）**：全同步 std API，零 tokio。

**S6（可观测）**：`names()` 列出已注册插件；计数 `wrap_ok` / `wrap_err`
（按插件名）。

**S7（dial 方向独立）**：拨号集成对读/写方向使用独立的 wrapped handle；
插件的 Read 变换与 Write 变换必须相互独立（不得在两个方向间共享可变
状态）。单个 wrapped handle 只在单一方向上使用时，其变换位置从 0 开始
连续（xor 的 rpos/wpos 模型）。违反此条的插件在 dial 集成下行为未定义。

## Side Effects

- 无（纯内存注册表 + 流变换）。

## Public API

- `pub const OBFUSCATE_API_VERSION: u32 = 1`
- `pub struct ObfsParams<'a> { pub key: &'a [u8] }`（`xor` 用；`plain` 忽略）
- `pub trait ObfuscateTransport: Send + Sync { fn name(&self) -> &'static str; fn api_version(&self) -> u32; fn wrap(&self, stream: TcpStream, params: &ObfsParams) -> io::Result<Box<dyn ObfuscatedStream>>; }`
- `pub trait ObfuscatedStream: Read + Write + Send {}`
- `pub struct PluginRegistry`：`new()` / `register(&mut self, plugin: Arc<dyn ObfuscateTransport>) -> Result<(), PluginError>` / `get(&self, name: &str) -> Option<Arc<dyn ObfuscateTransport>>` / `names(&self) -> Vec<&'static str>`
- `pub enum PluginError { IncompatibleApiVersion { name, got, expected }, DuplicatePlugin(&'static str) }`
- `pub mod builtin`：`pub fn register_all(&mut PluginRegistry)`（注册 `plain` + `xor`）

## Verification

- E4 `product.plugin-obfs-echo`：TCP 回显穿过 `xor` 插件；断言线字节 ≠ 明文
  （混淆生效）且回显解密后 == 明文（语义正确）。
- 单元测试：版本拒绝、重名拒绝、xor 往返、plain 直通。

## Performance Budget

- `xor` 插件：per-byte 单次异或，原地变换，无额外分配（wrap 后零拷贝路径）；
  `plain`：零开销（直接透传）。

## Observability

- 计数：`plugin_wrap_ok{name}` / `plugin_wrap_err{name}`。

## Recovery Semantics

- `wrap` 失败 → 调用方收到 `io::Error`；注册表状态不变（失败的插件不进表）。

## Platform Constraints

- 纯 std + TCP，无平台相关代码。

## Dial Wiring — 插件接入真实拨号（P1–P6）

> 本期（二期）：把混淆插件接到 ss/trojan 的真实 outbound TCP dial 上。
> 接线点唯一（P1）；失败语义延续 S4（不自动回退明文，防降级攻击）。

### P1（统一接线点）

`dial.rs` 提供两个同步 std 入口：

- `dial_with_obfs(addr: SocketAddr, obfs: Option<&str>, params: &ObfsParams)
  -> io::Result<Box<dyn ObfuscatedStream>>`
  ＝ `wrap_stream(TcpStream::connect(addr)?, obfs, params)`。
- `wrap_stream(stream: TcpStream, obfs: Option<&str>, params: &ObfsParams)
  -> io::Result<Box<dyn ObfuscatedStream>>`
  ＝ 在**全局注册表**按名查插件并 `wrap`；`obfs=None` → 用 `plain`
  （零变换，直通）。

拨号站点（`apps/nexus` 的 ss/trojan arm）从 `OutboundConfig` 取出
`(obfs, obfs_key)` 后调用；本 crate 不感知 `OutboundConfig`
（依赖倒置：出站侧依赖本 crate，本 crate 不反向依赖）。

**方向独立 handle**：需要双向中继的拨号点必须先 `try_clone` 出独立的
raw handle 再各自 `wrap_stream`——写方向的所有字节（握手/请求头 +
中继数据）走同一个 wrapped handle，读方向走另一个；两个方向的变换位置
各自从 0 开始连续、不交错（S7）。

### P2（配置）

`OutboundConfig` 新增（`nexus-proxy-config`）：
- `obfs: Option<String>` — 插件名；`None` = plain 直通。
- `obfs_key: Option<String>` — 插件参数 key（如 xor 的 key 材料）；
  需要 key 的插件在 key 缺失/空时 `wrap` 失败（显式错误，不回退）。

未知插件名 → `wrap_stream`/`dial_with_obfs` 返回
`io::ErrorKind::NotFound`（dial 直接失败，硬校验，不静默回退）。

### P3（失败语义）

`dial_with_obfs` 任一步失败（connect / 未知插件 / wrap）→ 整个 dial 返回
`io::Error`；**不自动回退到 plain**（S4 延续）。调用方（`apps/nexus`）
映射为 `NexusError::ConnectivityEstablishmentFailed`。

### P4（注册表接线）

全局单例：`static GLOBAL: OnceLock<Mutex<PluginRegistry>>`；
`global_registry() -> &'static Mutex<PluginRegistry>` 懒初始化并注册
builtin（plain/xor）；二进制可在启动时显式调 `init_builtin_plugins()`
（幂等）。`dial_with_obfs`/`wrap_stream` 内部取全局注册表。

### P5（可观测）

- `dial_ok(plugin) -> u64`：计数 `obfs_dial_ok{plugin}`。
- `dial_err(plugin, reason) -> u64`：计数
  `obfs_dial_err{plugin,reason}`，`reason ∈ {connect, unknown_plugin, wrap}`；
  `plugin="-"` 表示 connect 阶段失败（尚无插件名）。
- wrap 层复用注册表现有的 `wrap_ok`/`wrap_err`（S6）。

### P6（零回归）

`obfs=None` 时走 `plain`：逐字节直通；未配置 obfs 的现有 outbound
行为逐字节一致（现有单测全过）。

### 范围说明（诚实边界）

- vmess：本期无真实 dial（`proxy_serve_once` 的 Vmess arm 仍为
  `ConnectivityEstablishmentFailed`，data-plane deferred）；只加配置字段
  （前向兼容），不接 dial。待 vmess 真实 dial 落地后再接。
- UDP dial 混淆后置；dlopen 动态加载后置（仍是静态注册）；
  规则引擎按策略选插件后置（只做 per-outbound 静态配置）。
- E4 只有 Linux 真机（沙箱 TCP loopback 不可用 → SKIP）。

## Deletion Test

**问题**：如果删除 `nexus-plugin`，会破坏哪个独立变化维度？

**回答**：混淆手段的热插拔维度。没有它，新增一种混淆要改核心拨号代码；
有它，新增混淆 = 新 crate 实现 `ObfuscateTransport` + 一行注册，核心零改动。
删除它只会失去"不动核心换混淆"的能力，直连 TCP 和出站协议本身不受影响。

**反例**：如果混淆手段永远不变（只有一种），则该 crate 可删除。
但 DESIGN §7.3 明确 GFW 会升级探测，抽象成立。

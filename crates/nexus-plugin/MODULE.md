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

## Deletion Test

**问题**：如果删除 `nexus-plugin`，会破坏哪个独立变化维度？

**回答**：混淆手段的热插拔维度。没有它，新增一种混淆要改核心拨号代码；
有它，新增混淆 = 新 crate 实现 `ObfuscateTransport` + 一行注册，核心零改动。
删除它只会失去"不动核心换混淆"的能力，直连 TCP 和出站协议本身不受影响。

**反例**：如果混淆手段永远不变（只有一种），则该 crate 可删除。
但 DESIGN §7.3 明确 GFW 会升级探测，抽象成立。

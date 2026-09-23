# nexus-platform-windows Module Contract

## Responsibility

实现 Windows 平台 Capability Adapter：

- **VirtualPacketInterface**（wintun 窄 C ABI，运行时动态加载）。
- **SystemProxyController**（PRODUCT §13）：读写 `HKCU\...\Internet Settings`
  的 `ProxyEnable`(DWORD) / `ProxyServer`(REG_SZ)，并经
  `InternetSetOption(INTERNET_OPTION_SETTINGS_CHANGED + REFRESH)` 广播刷新。
- **AutostartRegistrar**（PRODUCT §13）：经 `schtasks.exe` 注册/移除/查询
  “当前用户 ONLOGON 启动 nexusd”的计划任务（非 Windows 服务）。

能力声明为静态常量（wintun 的能力面），由组合根 `apps/nexus-platform-host`
的 `vpi-capabilities` 命令暴露给 E4 验证；驱动/内核对象的真实创建只在显式
Adapter API 中发生。

## Non-Responsibilities

- 不依赖 higher-level domain runtime，不包含业务策略。
- 不含加密、路由、UDP 承载（`conn.Bind` 等价物属 `nexus-connectivity`）。
- 不实现 Workspace Access / Lifecycle / Attribution（能力缺失时由上层走
  `PlatformError::Unavailable`，本模块不静默降级）。

## Inputs

- 仅接受公开类型、DTO、trait、事件或稳定协议对象。
- 输入必须可被结构化验证；不得依赖未声明的全局隐式状态。

## Outputs

- 结构化 `Result<T, PlatformError>` / 能力声明 DTO。
- 失败保留可诊断原因（Windows 错误码映射为 `PlatformError::Io`），不以日志
  文本代替错误类型。

## Allowed Dependencies

- `nexus-platform`（仅此一个 Nexus 内部 crate）。
- 运行时动态加载 `wintun.dll`（LoadLibraryW/GetProcAddress，不静态链接、
  不提交二进制；签名包由部署环境自 wintun.net 提供）。
- 内核函数仅手写 `extern "system"` 窄绑定（LoadLibraryW/GetProcAddress/
  FreeLibrary），不引入第三方 crate。

## Forbidden Dependencies

- `engineering/` 下的 Harness/Plugin。
- 未在 `policies/architecture.toml` 声明的 Nexus 内部 crate。
- Portable 模块中的平台专有 Framework/API。
- 通过“便利”依赖绕过公开领域边界。

## Invariants

- 只实现 `nexus-platform` capability traits；能力缺失显式返回
  `PlatformError::Unavailable`。
- `unsafe` 只允许存在于 `wintun.rs` 与 `wininet_proxy.rs`（注册表 advapi32 与
  wininet 窄 FFI）两个模块，每处带 Safety Invariant 注释；`autostart.rs` 经
  `std::process::Command` 调用 `schtasks.exe`（安全 Rust，无 unsafe）；
  其余模块 `#![deny(unsafe_op_in_unsafe_fn)]` 且不扩散 unsafe。
- WinINET 代理写路径：改注册表后必须成对调用
  `INTERNET_OPTION_SETTINGS_CHANGED` + `INTERNET_OPTION_REFRESH`，缺一不生效；
  提供方不缓存“已刷新”状态，每次 apply 都广播。
- 自启任务名前缀固定 `nexus-`；临时测试任务名必须带 `nexus-test-` 前缀，
  install/remove 幂等（已存在则覆盖创建，remove 不存在视为成功）。
- 生命周期守卫顺序固定：`WintunEndSession` → `WintunCloseAdapter` →
  `WintunFreeAdapter`；`Drop` 按此顺序执行，不 panic。
- 包长边界：receive 拷贝前校验目标缓冲；send 前校验包长
  `(0, MAX_PACKET_SIZE]`，越界返回 `PlatformError::Invalid`。

## Side Effects

- 创建/打开 wintun 网络适配器与数据会话（系统级对象）；仅经公开 Adapter API
  发生，`vpi-capabilities` 只读不创建。
- 新增副作用前必须更新本契约和 Scenario/Policy（如影响外部行为）。

## Public API

- 默认最小 surface：`private -> pub(crate) -> pub`。
- 公开：`WintunVpiAdapter`（open/create）、`capabilities()`、
  `mtu()`、`backend()`、`MAX_PACKET_SIZE`。
- 公开（PRODUCT §13）：`WinInetSystemProxy`（实现 `SystemProxyController`：
  `snapshot()`/`apply(enabled,server)`/`refresh()`）；`TaskSchedulerAutostart`
  （实现 `AutostartRegistrar`：`install(exe,args)`/`remove()`/`status()`）。
  自启固定任务名常量与 `nexus-test-` 前缀规则公开可见。

## Verification

最低：

```text
cargo check -p nexus-platform-windows
cargo clippy -p nexus-platform-windows --all-targets -- -D warnings
cargo test -p nexus-platform-windows
```

E4 映射：`scenarios/platform/virtual_packet_interface.toml`（经
`nexus-platform-host vpi-capabilities --json` 驱动）。真实驱动收发为部署环境
可选 smoke（需管理员 + 已安装签名 wintun 驱动），不进入 harness 门禁。

## Performance Budget

`receive`/`send` 进入 hot path 前须在 Contract 中增加 baseline/noise
tolerance/warning/blocking 四要素；当前未定义预算的路径不得宣称“性能完成”。

## Observability

稳定结构化字段优先于自由文本；涉及 Session/Provider/Path 应携带对应
correlation id。

## Recovery Semantics

无持久状态；Adapter/Session 为显式资源，`Drop` 负责确定性释放；进程崩溃后
wintun 驱动自动回收会话（内核对象），无持久状态需 reconcile。

## Platform Constraints

平台专有代码只允许存在于 `nexus-platform-*` 或 Composition Root。Portable
crate 必须通过相应 portability gate。

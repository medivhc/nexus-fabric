# 07 · 源码注释错误总清单（注释与代码实际行为不符）

> 本文仅依据仓库 e6ccf8b 的源代码与机器配置（.rs/Cargo.toml/*.toml）撰写，未采信任何叙述性文档；结论行号均可复核。
>
> 收录范围：`//`、`///`、`//!` 注释（含 USAGE 帮助文本）与代码实际行为矛盾之处。每条含：位置、注释原文、代码事实、不符点。每条均经分片回验并由 Organizer 独立复核（复核过程见 08）。
> 严重度：**high** = 注释描述的连接状态/流程/不变量与实现矛盾，会直接误导接线或调用判断；**medium** = 能力/字段语义/参数描述过时或错误；**low** = 名称失效、计数遗漏、措辞重复、编码损坏。
>
> 汇总：high 2 条、medium 9 条、low 9 条；另经复核**剔除 1 条误报**（见第 5 节），附录记录 2 类"非注释错误但行为异常"。

---

## 1. HIGH（2 条）

### H1 · apps/nexusd/src/lib.rs:23 — acceptance 持久化自称"尚未接到 daemon 产品路由"，实际已接线
- **注释原文**：`/// N3-1 acceptance persistence, not yet connected to daemon product routes.`
- **代码事实**：
  - `apps/nexusd/src/main.rs:756`：`let tasks = nexusd::task_service::LocalTaskService::open_with_sessions(config_root, sessions);`（serve_localapi 内构造）
  - `apps/nexusd/src/task_http.rs:201`：精确路由 `POST /localapi/v1/task`，经 LocalTaskService→ProviderService 执行
  - `apps/nexusd/src/task_service_provider.rs:19,85`：ProviderService 持有 `FileTaskAcceptanceStore`
- **不符点**：acceptance 账本已经挂到 daemon 产品路由，"not yet connected"为过时描述，会让读者以为 N3 读口不可达。
- 注：该路由的 **Submit 分支确实是 stub**（见 06 第 4 节第 8 条），但 Get/Cancel/ReadLogs/Artifacts 真实可达——不能以 Submit 未落地反推"整条路由未连接"。

### H2 · apps/nexus/src/lib.rs:39-40 — n3_acceptance 自称"尚未连接到产品命令"，实际是 task/artifact 命令族核心 codec
- **注释原文**：`/// N3-1 composition adapters; not connected to product commands yet.`
- **代码事实**：
  - `apps/nexus/src/task_localapi.rs:221`：`crate::n3_acceptance::decode_dto(&body)` 解码 daemon 响应；`:325/:329/:332/:339` 用 `n3_acceptance::sha256` 做 digest 校验
  - `apps/nexus/src/task_cli.rs:129`：`decode_dto::<SubmitTaskRequest>` 解码提交请求
  - `apps/nexus/src/task_provider_grant/linux.rs:2`、`io.rs:243`、`audit.rs:57`；`artifact_download_fs.rs:3`、`artifact_download.rs:4`；`n2_identity.rs:27`
- **不符点**：该模块的 decode_dto/sha256/parse_canonical_json/new_task_id 已深度进入产品命令路径，"not connected"不成立。

---

## 2. MEDIUM（9 条）

### M1 · apps/nexusd/src/watcher.rs:12-13 — 宣称配置变更"热生效"，主线程实际只打日志
- **注释原文**：`//! | proxy.yaml / dns.toml 内容变更 | 热生效（规则、记录类纯数据） |`；`//! | network.toml 内容变更 | 热生效（peer 列表等…） |`
- **代码事实**：`apps/nexusd/src/main.rs:599-601`：`Ok(watcher::ReloadEvent::Applied { files }) => { eprintln!("[nexusd] config hot-reloaded: {files:?}"); }`，无任何配置回注调用。
- **不符点**：注释承诺运行时热更新，实际运行中子系统保持旧配置、必须重启。

### M2 · apps/nexus/src/main.rs:74 — USAGE 称 artifact 完整下载未装配，Linux 下已完整实现
- **注释原文**：`artifact get <id> --output <path>        N3 完整下载尚未装配（不修改输出）`
- **代码事实**：`apps/nexus/src/task_cli.rs:173-241`（`#[cfg(target_os="linux")]`）：probe（:185）→ 循环分页 GetArtifact 并校验 record/next_offset（:198-222）→ EOF 复验（:224-238）→ `receiver.finish()`（:239），真实写输出。
- **不符点**：Linux 下分页下载 + 持久接收器已装配（daemon GetArtifact 对已 accepted 任务真实可达）；非 Linux 分支（:243 起）确为 stub。帮助文本以全平台口径写"未装配"，对 Linux 过时。

### M3 · apps/nexus/src/subnet_cli.rs:5 — 文件头称"真实 TUN 留 P3-2"，--tun 已接真实数据面
- **注释原文**：`进程内装配（MeshCarrier mock carrier，真实 TUN 留 P3-2）`
- **代码事实**：`subnet_cli.rs:635`（Windows）/`:650`（Linux）`subnet_up_tun` → `assemble_real_tunnel`（:597-628）：`UdpCarrier::bind` + `WintunVpiAdapter::create` / `TunVpi::create`（/dev/net/tun）。
- **不符点**：默认 `subnet up` 仍走 mock，但 `--tun` 路径真实 TUN 已落地，文件头 blanket 表述滞后。

### M4 · crates/nexus-connectivity/src/health_check.rs:12 — 模块头自称"不读取真实墙钟"，HealthMonitor 直接读 Instant
- **注释原文**：`` - `now_ms` 为注入的逻辑时钟（调用方传入），本模块不读取真实墙钟；``
- **代码事实**：`health_check.rs:277` `let started_at = Instant::now();`；`:304` `started_at.elapsed().as_millis()`；`:369 elapsed_ms`。
- **不符点**：该不变量只对纯状态机 `HealthChecker` 成立；同模块公开类型 `HealthMonitor` 读真实单调时钟。

### M5 · crates/nexus-connectivity/src/health_check.rs:14 — 模块头把"定时探测线程"列为 TODO，spawn 已实现
- **注释原文**：`- 真实定时探测线程 / 真实网络探测 / 超时判定留 TODO。`；`:18` 描述未来"按 probe_interval_ms 起一个有 Owner 的定时任务（CancellationToken + JoinSet）"
- **代码事实**：`health_check.rs:263 pub fn spawn(...)`；`:285 thread::spawn` 内 `cvar.wait_timeout(interval)` 循环调 `probe.probe`；`:339 cancel` / `:344 shutdown` 协作 join。
- **不符点**：有 Owner 的定时探测线程已实现（仅"真实网络探活 I/O"仍经注入 HealthProbe 未落地），模块头把已实现项捆入 TODO。

### M6 · crates/nexus-connectivity/src/smart_retry.rs:17 — 模块头自称"不做真实 sleep/不调度真实任务"，execute 真睡
- **注释原文**：`` 纯内存、纯同步、纯逻辑骨架；不做真实 sleep / 不调度真实任务；``
- **代码事实**：`smart_retry.rs:422 pub fn execute<...>(&mut self, op: F)`，按 next_delay_ms 用 `std::thread::sleep` 真实阻塞重试（:417 注释自述）。
- **不符点**：公开 execute 就是真实阻塞调度器，模块头描述只适用于纯函数 decide。

### M7 · crates/nexus-connectivity/src/graceful_exit.rs:17 — 模块头把"真实 drain 等待"列为 TODO，drain_real 已实现
- **注释原文**：`` - 真实网络通知对端 / 真实 drain 等待线程留 TODO。``
- **代码事实**：`graceful_exit.rs:329 pub fn drain_real<F: Fn() -> u32>(&mut self, active: F)`，:330-343 按约 20ms 轮询 active() 并 advance，直到退出或超过 grace period。
- **不符点**：真实 drain 等待循环已实现（仅"网络通知对端"未落地）。

### M8 · crates/nexus-proxy-transport/src/lib.rs:43-48 — 注释称 OutboundKind 无 Socks5 变体，实际已有且生产接线
- **注释原文**：`no existing SOCKS5 *outbound* structure was found in nexus-proxy-config (OutboundKind has no Socks5 variant; SOCKS5 there is inbound/ingress only)… wiring it into the shared outbound config is deferred…`
- **代码事实**：`crates/nexus-proxy-config/src/lib.rs:321` `/// SOCKS5 出站（RFC 1928；P3 新增…）` `Socks5,`；parse 支持 "socks5"（:354 附近）；`apps/nexusd/src/proxy_fwd.rs:91` 已接线。
- **不符点**："has no Socks5 variant"为假，属陈旧注释。

### M9 · apps/nexus/src/observability.rs:391-411 — platform_capabilities 输出硬编码清单，不探测实际能力
- **注释/语义**：函数名与 `platform capabilities` 命令暗示列出当前可用平台能力
- **代码事实**：函数体返回固定 `json!`：capabilities 6 项、platform_adapters 列出含三个空壳 crate（macos/android/ios）；不探测实际编译适配器，且漏列 `nexus-platform/src/lib.rs:132 SystemProxyController`、`:145 AutostartRegistrar`。
- **不符点**：输出会被读为"已编译/已接线能力"真相，实际是静态文案（与 observability 全文件硬编码演示数据同性质）。

---

## 3. LOW（9 条）

| # | 位置 | 注释/代码不符点 |
|---|---|---|
| L1 | apps/nexus/src/main.rs:6-13 | 头部注释列 7 个有 daemon 路由的观察命令；`localapi_client.rs:303-308` 另有 `workspace commit`（→/localapi/v0/workspace/commit/）为第 8 个，计数遗漏。 |
| L2 | apps/nexus/src/main.rs:845-850 | parse_command 内 session watch 分支为 dead code：main.rs:294 已把 session* 全部截入 session_cli，该分支永不执行。 |
| L3 | apps/nexus/src/main.rs:50-53 | USAGE 不完整：未列 `session seed`（session_cli.rs:306 已实现）、`grant revoke`、`resource export/import`（resource_cli.rs:604,704 已实现）。 |
| L4 | apps/nexusd/src/main.rs:294-295 | 同一函数 run_dataplane 上方两条近乎重复的 doc 注释并排（第二条多"或收到关闭信号"）。 |
| L5 | crates/nexus-proto/src/lib.rs:3 | 自称"定义 wire/control contract 的 portable schema 边界与代码生成占位接口"，整文件 7 行零 pub item、全仓零引用（能力夸大；另引用不可读的 MODULE.md）。 |
| L6 | crates/nexus-transport/src/lib.rs:3 | 自称提供 Stream/Datagram/Multiplexing/Connection Reuse/Backpressure，实际仅 TCP u32BE FrameStream（能力夸大）。 |
| L7 | crates/nexus-outbound-trojan/src/lib.rs:241 | `TrojanAdapter::new(tag, locator, _password)` 静默丢弃密码、无注释说明；与 :318/:333 真实需要密码的 TLS 配置形成契约落差。 |
| L8 | crates/nexus-service/src/lib.rs:20 | `ServicePhase` 列 Connecting/Active/Closed，但 connect（:83-92）收 READY 后直返 Active，Connecting 从不构造、亦无 close()。 |
| L9 | crates/nexus-platform-linux/src/assemble.rs:6,76,116,144,236 | 注释含 UTF-8 替换字符"�等"（原文疑为"幂等"），事务不变量注释不可读；代码逻辑正常。 |

---

## 4. 检索与复核方法（保证每条可复核）
- 各分片通读责任源码后，用 `rg -n "尚未|not yet|deferred|not installed|留 P|TODO|stub|未实现|placeholder"` 回扫，逐条与生产代码（排除 `#[cfg(test)]`）比对。
- high 与 medium 全部条目由 Organizer 独立回读源码行复核（结果逐条记录于 08 第 3 节）。
- 诚实声明类注释（如 path `send_heartbeat_stub`、projection `on_path_event`、planner :98-99 extension 限制、schedule_cli:6 只生成 id、sync_transport:193 待 client-auth）经核对与代码一致，**不收录**。

## 5. 经复核剔除的误报（1 条）
- **原 Shard A H1（apps/nexus/src/main.rs:66）**：USAGE 文本 `task submit … N3 提交（完整执行接线尚未装配）`。初判"CLI 已接线→注释错误"。复核后**剔除**：CLI 侧确已接线（main.rs:231→task_cli::run→HTTP POST），但 daemon 侧 Submit 恒返回 Unsupported（task_service_provider.rs:229），"**完整执行**接线尚未装配"按端到端口径属实，是诚实警示而非错误。

## 6. 附录：非注释错误，但复核中发现的行为异常（供修正参考）
- **退出码异常**：`apps/nexus/src/node_cli.rs:151,164,178,191`（参数缺失/pubkey 非法/写失败/trust store 错误）与 `apps/nexus/src/grant_cli.rs:147`（--not-after 非法值）失败分支均 `return 0`；按 `control_service.rs:72-74` 所述"协议/参数错误 exit 1"契约，这些分支应为 exit 1，机器消费者按退出码会误判成功。

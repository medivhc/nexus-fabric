# Nexus 用户手册（按源代码函数体实证，HEAD ced3b7a）

> 本文**只依据源代码与机器配置撰写**（HEAD = `ced3b7a9ed801f38ee816135700889978ff0e0b6`），未采信任何 .md 文档；命令行为均来自参数解析代码与处理函数函数体，不来自帮助文本字面意思。每条结论带 `文件:行号`。
>
> 阅读约定：🚫 = 硬编码不可用/占位；🎭 = 固定演示数据，不反映真实状态；🐧 = 仅 Linux；🪟 = 仅 Windows。

---

## 0. 构建与启动（从 Cargo.toml / main.rs 事实）

- 构建：`cargo build --release`（Rust edition 2024，rust-version 1.85；工具链 cargo/rustc 1.99，需 `export PATH="$HOME/.cargo/bin:$PATH"`）。产出三个二进制：`nexus`、`nexusd`、`nexus-platform-host`。
- 启动守护进程：`nexusd <config-folder>`（如 `nexusd /etc/nexus/`，`apps/nexusd/src/main.rs:286-296`）。配置夹内文件缺失即不启用对应子系统：`daemon.toml`（LocalAPI 地址）、`network.toml`、`proxy.yaml`、`dns.toml`、`workspace.toml`。兼容旧入口 `nexusd serve --addr|--socket`（:848）。
- LocalAPI 默认地址：Unix socket `$XDG_RUNTIME_DIR/nexus-localapi.sock`（无 XDG_RUNTIME_DIR 时 `temp/nexus-<uid>/0700/nexus-localapi.sock`）；非 unix 平台 TCP `127.0.0.1:18080`（`localapi_client.rs:146-158`）。Bearer token 存 `<node_dir>/localapi.token`（0600）。
- 全局约定：`--json` 可出现在任意位置（`main.rs:127`）；`--addr <ip:port>`/`--socket <path>` 指定 daemon 位置（:166-198）。**用法错误 → exit 2**；**业务失败也通常 exit 0**（FAIL JSON 打 stdout）；daemon 连不上 → `DAEMON_UNREACHABLE` FAIL JSON，exit 0。

---

## 1. CLI 命令全解析

顶层分派共 **26 个关键字**（`main.rs:200-359` 实际 argv 分支）。

### 1.1 身份与配对

#### `nexus node init [--force]`
- 处理：`node_cli.rs:81-107`。生成 X25519 seed hex 写入 N2Store 键 `node/identity`，目录 0700、文件 0600；已存在且无 `--force` → 幂等返回已有 id。
- 输出：`--json` → `{"verdict":"PASS","node_id":"<hex32>","initialized":<bool>}`；人读 `node initialized: <id>`。失败 exit 1。

#### `nexus node trust --provider <id> --pubkey <hex64>`
- 处理：`node_cli.rs:120-213`，写 TrustStore。pubkey 非 64 hex → `BAD_PUBKEY` FAIL JSON（exit 0）。

#### `nexus pair invite --dir <d> [--name]` / `pair join --dir <d> <code> [--addr ip:port] [--name]` / `pair list` / `pair remove <peer-id-hex>`
- invite（`pair_cli.rs:178`）：生成 ed25519 identity（identity.toml 0600）→ 打印配对码（含 16B 一次性 token，5 分钟有效）→ 前台 bind `0.0.0.0:18443` 等对端加入，验 token 后签名 `sign(sk, token||peer_id)` 回 PairAccept，写 `peers/<hex>.toml`。
- join（:429）：**`--addr 必填`**（mDNS 未实现，:391-397）；30s connect 超时；验回包 peer_id 与签名后写 peers 文件。
- 帧格式：u16 BE 长度前缀，上限 64 KiB（:601-632）。

### 1.2 准入服务与资源授权

#### `nexus provider serve --bind <ip:port> [--once]`
- 处理：`provider_cli.rs:13-49` → `n2_admission::serve_forever`（`n2_admission.rs:696`）。前台常驻 TCP 服务：并发上限 64，每连接跑双向挑战-应答握手 + grant 判定（见 §3 端到端流程）。缺 `--bind` exit 2。

#### `nexus grant add|revoke|del|list`
- 处理：`grant_cli.rs`，对本机 N2Store grant 记录的 CRUD（客户端侧资源授权）。`grant add` 写 `Grant{resource, principal, ops, not_after}`（:74,80）。

#### `nexus resource list|show|publish|revoke|export|import`
- 处理：`resource_cli.rs`，对 N2Directory/资源广告的本地文件操作：list 扫目录、publish 写记录（:238 广告 locators = `[service tcp endpoint, n2adm://control]`）、revoke 删、export/import 打包拷贝。

#### `nexus use <resource>`
- 处理：`use_cli.rs:298` → `SessionManager.open`（:311）→ 跨机准入握手 → 成功后 `probe_endpoint`（纯 TCP connect 探测，:485）→ `SessionManager.complete`（:357）。Deny 时返回带自身 principal 的 `AUTH_DENIED` JSON（:375-389）。未知资源 → UnsupportedCapability。

### 1.3 会话与计划

#### `nexus session list|close|seed`（本地 N2Store 操作）/ `session watch <id>`（转发 daemon）
- list/close/seed：session_cli 直接操作本机 N2Store sessions。
- watch：GET `/localapi/v0/session/watch?session=<id>`（🎭 演示数据，见 §2）。

#### `nexus plan <resource>`（纯本地预览）/ `plan explain <resource>`（转发 daemon）
- `plan <r>`：`plan_cli.rs:140-299` 纯本地 N2Directory::open + preview()，不建连，输出 `plan{...}` + `trace{selected,considered[]}`。
- `plan explain`：GET `/localapi/v0/plan/explain?resource=<r>`（🎭 演示数据）。

### 1.4 子网与组网

#### `nexus subnet up --config <path> [--state <path>] [--encrypt-state] [--tun] [--foreground] [--tun-name nexus0] [--listen <ip:port>] [--attempts 10]`
- 缺 `--config` → stderr `error: subnet up requires --config <path>` exit 2（`main.rs:548-551`）。
- **不带 --tun/--foreground**：`subnet_cli.rs:527-613` 只写状态文件（`--state` 默认 `$NEXUS_HOME/subnet.json` 或 `~/.nexus/subnet.json`），不发网络握手。配置含 bootstrap 但非 foreground → `BOOTSTRAP_REQUIRES_FOREGROUND`（:536）。
- **`--tun`**：`subnet_up_tun`（🪟 :1167 wintun / 🐧 :1185 /dev/net/tun）真实建 TUN + UDP carrier；失败 → `{"verdict":"TUN_ERROR",...}` exit 0。
- **`--foreground`**：`main.rs:625-697` 常驻前台循环；删除状态文件即优雅退出。配 `[[subnet.bootstrap]]`（必填 `network_psk`/`network_psk_file`）时先跑 bootstrap-join 入网（字节流程见 §3.2）。

#### `nexus subnet status` / `subnet leave`
- status（`subnet_cli.rs:680-718`）：读状态文件并自动识别加密格式（NEXDP1/Windows DPAPI、NEXSEC1/Linux AEAD）；文件不存在 → `{"verdict":"DOWN",...}`；解密失败 → `STORE_ERROR`。
- leave（:721）：删除状态文件。

#### `nexus subnet punch <peer_vip> <targets...> --config <path> --listen <ip:port>`
- 处理：`subnet_punch`（:1223-1330），真实 UdpCarrier bind → 打洞（attempts 上限，每次 10ms 轮询）；peer 不在配置 → `PEER_NOT_FOUND`；结果写回状态文件。

#### 🐧 `nexus network up --config <toml>` / `network status [--config <toml>]`
- up（`network.rs:309-322`）：真实建 /dev/net/tun、配 ip/mtu/up、dial peers、起 VpiPump；按 Enter/Ctrl-C 退出。非 Linux → stderr `nexus network up is Linux-only in this build` exit 2。
- status（:458-472）：恒 `daemon:false`（诚实标注未接 daemon）；有 --config 时解析打印 peer_id/interface/vpi/peers/routes。

### 1.5 任务（N3 瘦客户端）

#### `nexus task submit <resource> --cmd <c> [--in <f>] [--out <f>] [--workdir <dir>]` / `task show|cancel|logs <id> [--follow]` / `task artifacts <id>`
- 处理：`task_cli.rs` → `task_localapi::execute`（`task_localapi.rs:175-200`）= 真实 HTTP POST `/localapi/v1/task`（Bearer token，loopback）到 daemon。
- **注意**：daemon 侧 Submit 恒返回 `UNSUPPORTED_CAPABILITY`（`task_service_provider.rs:229`）——提交**不会真正执行**；show/cancel/logs/artifacts 读取已 accepted 任务的真实持久化数据。

#### `nexus artifact get <task-id> <artifact> [--out <path>]`
- 🐧（Linux）：`task_cli.rs:173-241` 真实分页下载 + 校验接收器写文件；其它平台分支为占位。

### 1.6 调度

#### `nexus schedule at <unix_ts> --resource <r> -- <cmd...>` / `every <secs> --resource <r> -- <cmd...>` / `list` / `cancel <id>` / `tick`
- 处理：`schedule_cli.rs:119-210`，读写状态 JSON（默认 `~/.nexus/schedule.json`，临时文件+rename 原子写）。缺时间戳/非整数/缺 --resource → 各自 stderr exit 2。
- 🚫 **只登记任务计划、不实际执行**：tick 只推进状态机生成 task id，不跑命令。错误名 `INVALID_SCHEDULE / SCHEDULE_NOT_FOUND / SUBMIT_FAILED / STATE_ERROR`，均 exit 0。

### 1.7 代理

#### `nexus proxy [--addr ip:port] [--config path]`（默认 127.0.0.1:1080）
- 绑定 SOCKS5 listener → READY JSON → 初始化 plain/xor 混淆插件 → 每会话打一条 JSON。

#### `nexus proxy run <service|internet-access|compute|workspace> [--endpoint ip:port] [--relay ip:port] [--direct ip:port] [--token t]`
- 无 --endpoint → 进程内内存 flow；有 --endpoint → 真实 TCP flow；未知资源 → `UNKNOWN_RESTATE` FAIL。

#### `nexus proxy host <resource> --addr <ip:port>`（默认 127.0.0.1:8787）/ `proxy relay --addr <ip:port>`（默认 8788）/ `proxy speedtest` / `proxy bufferbloat-test --proxy <ip:port> [--duration 10] [--threshold 100]`
- host：逐连接 AUTH 门控服务循环。relay：DIAL + 双向字节中继单会话。speedtest：loopback 延迟自检。bufferbloat：空载基准 vs 打满上行对比，阈值判定。

#### 🪟 `nexus system-proxy status|set|clear|e2e` / `autostart install|remove|status`
- 非 Windows 恒返回 `{"code":"UNSUPPORTED",...}` exit 0（`main.rs:1619,1687`）。Windows 下经注册表/Task Scheduler 改系统代理与开机自启。

### 1.8 配置文件操作

#### `nexus config get|set|list --dir <path> [--file]`
- 白名单文件名：`daemon.toml / network.toml / proxy.yaml / dns.toml`（`main.rs:1299`）。目录不存在 exit 1；不在白名单 → `error: unknown config file` exit 2。set 从 stdin 读入、临时文件+rename 原子写。

### 1.9 状态/观察命令（转发 daemon，注意数据性质）

| 命令 | 路由 | 数据性质 |
|---|---|---|
| `nexus status` | GET /localapi/v0/status | 🎭 演示数据（聚合快照） |
| `nexus dns status` / `dns cache` | /dns/status, /dns/cache | 🎭 固定 example.com 解析 |
| `nexus session watch <id>` | /session/watch | 🎭 每次新建 sess-1/2/3 |
| `nexus connectivity status` | /connectivity/status | 🎭 硬编码 203.0.113.53:51820 |
| `nexus plan explain <r>` | /plan/explain | 🎭 硬编码 p1/p2 provider |
| `nexus platform capabilities` | /platform/capabilities | 🎭 字面量数组 |
| `nexus workspace commit <id>` 🐧 | /workspace/commit/<id> | 真实（有副作用） |
| `nexus dataplane stats`（无 CLI 直接入口，走 daemon） | /dataplane/stats | 真实计数器（无数据面装配时全 0） |

🚫 **CLI 本地硬编码 UNSUPPORTED（不触网、exit 0）**：`connectivity candidates/probe/links`、`dns resolve/providers`、`workspace heads/conflicts/cache`、`compute jobs`、`diagnose`（`localapi_client.rs:258-267,358`）——输出形如 `{"verdict":"FAIL","error":{"code":"UNSUPPORTED","command":"..."}}`。
🚫 `nexus run <r> -- <cmd>`：`main.rs:384-401` 固定返回 `{"code":"UNSUPPORTED","feature":"run-with-command","layer":"N3"}`，不执行任何命令。
（不带 `--` 的 `nexus run <resource>`：service 类会真实起 loopback TcpListener 做 CONNECT/READY 握手，`lib.rs:669+`。）

### 1.10 task-provider grant（provider 侧 operator 授权）🐧
`nexus task-provider grant add|revoke|list --config <dir> [--resource <name>] [--self|--principal ed25519:<64hex>] [--not-after <unix>]`（`task_provider_grant.rs:50-131`）。
- 🐧 非 Linux 恒 FAIL `local operator grants require Linux`（:171）。
- 副作用：读 `<config>/task-api.toml`（仅允许 provider+workspace 两字段）；add/revoke 写授权 + audit journal；仅允许 Use operation。

---

## 2. daemon API 全解析（nexusd LocalAPI，13 个路由）

**统一规则**（`apps/nexusd/src/main.rs`）：
- 所有路由要求 `Authorization: Bearer <token>`，常量时间比较；失败 → **401** `{"verdict":"FAIL","error":{"code":"UNAUTHORIZED",...}}`（:1114-1122）。
- 非 GET 方法访问 v0 → **405**（:1104-1112）；未匹配路径 → **404**（:1187-1195）。
- **业务错误也是 HTTP 200**，body 为 `{"verdict":"FAIL","error":{"code","message"}}`（:1197-1201）。
- 响应统一 `HTTP/1.1 <status> ... Content-Type: application/json ... Connection: close`。

### 2.1 v0 GET 路由（12 个）

| 路径 | 实际处理 | 数据性质 |
|---|---|---|
| `/localapi/v0/status` | 聚合 dns+connectivity+plan+capabilities 快照（obs.rs:416） | 🎭 演示 |
| `/localapi/v0/dataplane/stats` | 读全局转发计数器：mesh_forwarded/proxy_forwarded/direct_forwarded/dropped/dns_answered/qos_dropped 等（dataplane.rs:1418） | 真实（无装配全 0） |
| `/localapi/v0/dns/status` | 对硬编码 example.com 做一次内存解析，恒返回 `93.184.216.34`（obs.rs:38-50,109） | 🎭 演示 |
| `/localapi/v0/dns/cache` | 导出正/负缓存快照（obs.rs:138） | 🎭 演示 |
| `/localapi/v0/session/watch?session=<id>` | 每次调用新建 sess-1/2/3 假会话（obs.rs:201） | 🎭 演示 |
| `/localapi/v0/n2/session/list` | 从 N2Store 重放的 SessionManager 列真实会话；未装配 → `N2_UNAVAILABLE`（main.rs:175） | 真实 |
| `/localapi/v0/n2/session/attach?session=<id>` | attach 真实会话；缺参 → `BAD_REQUEST`（main.rs:202） | 真实 |
| `/localapi/v0/plan/explain?resource=<r>` | 硬编码 p1/p2 跑 planner；非 internet-access → NotFound（obs.rs:309） | 🎭 演示 |
| `/localapi/v0/connectivity/status` | 硬编码连 `203.0.113.53:51820` 两次（obs.rs:271） | 🎭 演示 |
| `/localapi/v0/platform/capabilities` | 字面量数组（obs.rs:391） | 🎭 演示 |
| `/localapi/v0/workspace/mounts` 🐧 | 真实 FUSE workspace 状态（main.rs:1042） | 真实（仅 Linux 编译） |
| `/localapi/v0/workspace/commit/<id>` 🐧 | 提交 FUSE workspace（唯一有副作用的 GET）；未启用 → `WORKSPACE_DISABLED`（main.rs:1062） | 真实（仅 Linux 编译） |

### 2.2 v1：`POST /localapi/v1/task`（唯一路由）
严格前置（`task_http.rs:200-272`）：路径必须逐字匹配、Content-Type 必须 `application/json`、body ≤ 1 MiB、鉴权三连（loopback + Bearer + TokenAuthority.valid()）；违反依次返回 400/401/405/413。

请求体（`crates/nexus-control-api/src/task/wire.rs:2-85`）：`{"schema_version":1,"operation":"<op>", ...}`，六个 operation：

| operation | 请求字段 | 服务端实际行为 |
|---|---|---|
| `SubmitTask` | `request`：SubmitTaskRequest（command/cwd/environment/limits/outputs/idempotency_key 等） | 🚫 **恒拒**：`UNSUPPORTED_CAPABILITY "Submit requires real capacity..."`（task_service_provider.rs:229） |
| `GetTask` | `task_id` | 读真实持久化任务，返回 TaskView |
| `CancelTask` | `task_id` | 取消任务 + 返回 TaskView |
| `ReadTaskLogs` | `task_id`, `stream`:stdout\|stderr, `offset`, `max_bytes`(≤65536) | 返回日志页（**bytes 为 0-255 整数 JSON 数组，非 base64**） |
| `ListTaskArtifacts` | `task_id` | 产物记录列表 |
| `GetArtifact` | `artifact_id`, `offset`, `max_bytes` | 分页读取：`{record, offset, bytes, next_offset, eof}`，要求产物状态为 Published |

响应：成功 200 `{schema_version:1, verdict:"PASS", "task"|"logs"|"artifact":...}`；失败 200 `{verdict:"FAIL", error:{code, reason, retryable, task_id}}`。响应体 >2 MiB → 413。
平台前提：非 Linux 整体不可用（task_service.rs:81-85）；Linux 还必须存在 `config_root/task-api.toml`（0600、仅 provider+workspace 两字段），否则 `UNSUPPORTED_CAPABILITY "task-api.toml is absent"`。

---

## 3. 端到端典型流程（从代码可达路径归纳）

### 3.1 节点加入 → 准入 → 授权 → 使用（真实函数链）
1. **配对**：A 跑 `nexus pair invite --dir <d>` 打印配对码（带外发给 B）；B 跑 `nexus pair join --dir <d> <code> --addr <ip:port>`（pair_cli.rs:178,429）。配对码 = A 的 ed25519 公钥 + 一次性 16B token。
2. **B 发布资源**：`nexus resource publish`（resource_cli.rs:238，广告含 `n2adm://control` 准入 locator）。
3. **B 预置授权**：`nexus grant add --resource <r> --principal ed25519:<A的公钥哈希> --ops use`（grant_cli.rs:74,80）。
4. **B 起准入服务**：`nexus provider serve --bind 0.0.0.0:18443`（n2_admission.rs:696）。
5. **A 使用资源**：`nexus use <resource>`（use_cli.rs:298）→ TCP 连 B 准入端口 → B 发 challenge_b+pubkey（n2_admission.rs:371）→ A 签名回请求帧（:832）→ B 验签（:600）+ 查 grant 表（:481）→ B 签 challenge_a 回 admit/deny（:516）→ A 验 B 签名（:862）+ 过 TrustStore（:896）→ A 拿到 endpoint 后纯 TCP 探测（use_cli.rs:485）→ 会话建立。
6. **数据面**：准入响应的 endpoint 为明文 tcp://host:port；后续隧道由 VirtualSubnetTunnel 驱动（mesh.rs:27），代理出口由 nexusd ProxyEngine 按 proxy.yaml 选择（proxy_fwd.rs:109）。

### 3.2 bootstrap-join 入网（subnet 新节点）
- 前提：客户端 `subnet up --foreground` 且配置 `[[subnet.bootstrap]]`（必填 network_psk）；服务端配 `[subnet.bootstrap_server]`（subnet_cli.rs:761-785,306-308）。
- 线上字节：外层 4 字节 magic `nxb:`（0x6E 0x78 0x62 0x3A，`discovery/bootstrap_join.rs:21`）。
- 客户端发 JoinInit（tag=0x10）：`eph_pub[32](X25519) ‖ static_pub[32] ‖ requested_vip(可选) ‖ client_nonce u64BE`（:181-198）。
- 服务端回 JoinReply（tag=0x11）：`eph_pub[32] ‖ static_pub[32] ‖ assigned_vip ‖ lease_secs u32 ‖ hb_interval_ms u32 ‖ refresh_interval_ms u32 ‖ server_nonce u64`（:199-216）。
- 错误帧 tag=0x12：code u8（AuthFailed/BadVip/VipConflict/NotBootstrap/RateLimited/MalformedFrame）+ message。VIP 租约落盘 `node_dir/data/bootstrap/vip-leases.json`。

### 3.3 任务提交（实际不可用，供理解）
`nexus task submit ...` → HTTP POST 到 daemon → daemon 完成所有鉴权与授权检查后在 `task_service_provider.rs:229` 返回 `UNSUPPORTED_CAPABILITY`。已 accepted 的任务可用 `task show/logs/artifacts` 查询。

---

## 4. 演示数据/占位速查（重要）

| 类别 | 命令/路由 | 实际行为 |
|---|---|---|
| 🎭 演示数据 | status、dns status/cache、session watch、connectivity status、plan explain、platform capabilities（经 daemon） | 硬编码快照，多次调用会重建但不反映真实状态 |
| 🚫 CLI 本地拒 | connectivity candidates/probe/links、dns resolve/providers、workspace heads/conflicts/cache、compute jobs、diagnose、run -- cmd | 固定 UNSUPPORTED JSON，不触网 |
| 🚫 服务端拒 | POST /localapi/v1/task 的 SubmitTask | 恒 UnsupportedCapability |
| 🪟 仅 Windows | system-proxy、autostart | 非 Windows 固定 UNSUPPORTED |
| 🐧 仅 Linux | network up、task-provider grant、artifact get 完整下载、workspace mounts/commit | 其它平台不编译或失败 |
| 未接入 | nexus-platform-host（58 行薄壳）、web-gateway（example 进程） | 无生产装配 |

## 5. 退出码速查
- `0`：成功；**以及大多数业务失败**（FAIL JSON 打 stdout 或 stderr）。
- `1`：部分本地错误（config 目录不存在、pair remove 多/零匹配、node trust 写失败等）。
- `2`：用法错误（缺参、未知选项/子命令、unknown config file、network up 非 Linux）。
- HTTP：401 未授权 / 405 方法不对 / 400 路由格式错 / 413 body 超限 / 404 未匹配路径；业务失败仍 HTTP 200。

# 08 · 复核记录（回源核验日志总文档）

> 本文仅依据仓库 e6ccf8b 的源代码与机器配置（.rs/Cargo.toml/*.toml）撰写，未采信任何叙述性文档；结论行号均可复核。
>
> 本文件记录两层复核：①5 个分片各自"读码→写文档→回源复核"的过程（含修正项）；②Organizer 的跨分片交叉核验与裁决（含剔除误报、降级）。

---

## 1. 分片复核汇总（各 shard 回源方法与修正）

### Shard A（apps/nexus，49,184 行）
- **回源方法**：main.rs/lib.rs（11,841 行分 6 段）/n2_store/n2_admission 等大文件全部读完；中小文件全文读；完成度判定用 `rg "UnsupportedCapability|deferred|not in this batch|尚未|not installed"` 回扫生产代码；dead 判定全仓搜调用点。
- **关键修正**：
  1. task 命令：初稿疑"空转/未装配"→ 修正为 implemented thin client（main.rs:231 实调 task_cli::run，非 run_unavailable）。
  2. observability：初稿疑"真实 daemon 状态"→ 修正为硬编码演示数据。
  3. daemon 路由计数：采信"7 个"→ 修正为 8 个（workspace commit）。
  4. lib.rs:11738 注释初拟记错误 → 回验与 run_unavailable 一致，撤销。
- **留待跨片**：daemon 侧 TaskApplicationService 是否未装、daemon 是否真调 observability（见第 2 节，均已由 Shard B/Organizer 闭环）。

### Shard B（apps/nexusd + compute/workspace/workspace-intel/platform-host，39,553 行）
- **回源方法**：main.rs（1,390 行分段）、task_store/runtime_store/requester_store/capacity/artifacts/executor* 全部读完；13 项结论逐条回源；dead 判定全仓 rg。
- **关键修正**：
  1. `0xabu8` 初疑语法错误 → 实为 `0xab`+后缀 `u8`，合法。
  2. Submit 初判"task-api.toml 即可端到端跑通"→ 修正为三重不可达（Submit stub + 空白名单 + capacity None + open_existing 不 provision）。
  3. task_http v1 与 v0 路由初疑重叠 → 修正为正交（/localapi/v1/ 前缀分流）。
- **测试计数澄清**：src 内 `#[test]` = 242；含 examples/tests/test_support 共 256（Organizer 复核，零 tokio::test）。

### Shard C（connectivity/projection/network/path/dns/ingress，47,677 行）
- **回源方法**：每 crate ≥5 个关键结论回读；projection 的 lib.rs/tcp.rs/egress.rs/semantic.rs 分段读完；stub/dead 判定全仓验证调用方。
- **关键修正**：
  1. projection 行数沿用 14,364 → 实测 src 11,397（差额 examples 约 2,967 行）。
  2. health_check/smart_retry/graceful_exit 初判"纯空转骨架"→ 回读发现生产 runner（spawn/execute/drain_real）已存在、模块头注释未同步，据此改判并产出 4 条 medium。
  3. virtual_subnet 中文注释乱码 → `file` 报 UTF-8，判为读取端显示问题，不计。
- **遗留**：encryption.rs:301-983 帧细节未逐字读完（核心密码学路径与 KDF 已确认）；projection examples 未逐行（不进生产）。

### Shard D（proxy/outbound/nat 15 成员，25,385 行）
- **回源方法**：小行数 crate（vmess 220/ss 461/trojan 502/proto 7/transport 94）逐行读完；全仓 rg 核验每个 crate 的 Cargo 依赖与源码真实使用（D-7 表）；6 个 OutboundAdapter 实例化点全仓核查。
- **关键结论**：6 个 adapter 在 apps/*/src 生产零实例化（仅 examples）；nexusd proxy_fwd 仅 SS/Trojan/Socks5 可拨号；无生产硬编码凭据（字面量全在 test/example）。

### Shard E（核心域/平台/harness 24 成员，38,537 行）
- **回源方法**：先 wc/rg 普查；5 个空壳与小 crate 逐行读；每 crate ≥5 结论回读、stub/完成度 100% 回验；harness 命令/gate/场景逐条对照 toml 与代码。
- **关键修正**：
  1. nexus-fabric 初判"顶层聚合"→ 修正为底层 QUIC/mTLS 会话层。
  2. performance_budgets 初疑跑基准 → 实为只校验 toml 键，降 partial。
  3. 277 场景初疑多为静态契约 → 实测 276 个有 command、1 个异 schema 孤儿。

---

## 2. Organizer 跨分片交叉核验（逐条结论与处置）

### 2.1 独立基线（不依赖分片）
- 核实 HEAD=e6ccf8b、工作区干净；从根 Cargo.toml 确认 51 个 members 并逐一分配分片。
- 独立采集：每成员测试数、stub 宏数、workspace 内部依赖边（scratch-organizer.md）、机器配置清单（harness.toml、policies/、configs/、277 场景）。

### 2.2 高信号结论亲验（全部 PASS）
| 结论 | 出处 | 核验结果 |
|---|---|---|
| nexusd 生产转发仅 SS/Trojan/Socks5，四富协议映射 None | apps/nexusd/src/proxy_fwd.rs:93-98 | PASS（:92 注释自陈简单 dial 不支持，属自认缺口） |
| N3 Submit 硬编码 Unsupported | task_service_provider.rs:228-230 | PASS |
| daemon high 注释错误（lib.rs:23） | main.rs:756 + task_http.rs:201 | PASS |
| CLI high 注释错误（lib.rs:39） | task_localapi/task_cli/task_provider_grant 等多处 | PASS |
| health_check 模块头过时 | health_check.rs:12,14 vs :263,277 | PASS |
| Socks5 变体注释失实 | proxy-transport:43-48 vs proxy-config:321 | PASS |
| Trojan adapter 丢弃密码 | outbound-trojan:241-249 | PASS |
| platform_capabilities 硬编码 | observability.rs:391-411 | PASS |
| 退出码异常 | node_cli:151-191；grant_cli:147 | PASS（行为异常，移入 07 附录） |
| N3 wire 客户端/服务端一致性 | task_localapi.rs:175-200 ↔ task_http.rs:215-245 | PASS（Bearer+JSON，服务端三重鉴权） |

### 2.3 裁决：剔除/降级
- **剔除 1 条误报**：Shard A 原 H1（main.rs:66 task submit 帮助文本）——"完整执行接线未装配"端到端口径成立（daemon Submit stub），非注释错误（详见 07 第 5 节）。
- **降级 2 条**：Shard A 原 H2（artifact 帮助，仅 Linux 下过时）high→medium（M2）；原 H3（subnet TUN 头部，默认路径仍 mock）high→medium（M3）。
- **不并入 07**：Shard B M2（Submit 表面契约）其内部注释诚实，本质是"声明未落地"，归入 06 第 4 节而非注释错误。

### 2.4 零遗漏核对
- 矩阵成员计数：3 apps + 47 crates + 1 harness = 51，与根 Cargo.toml members 逐一对应；分片归属 1+5+6+15+24 = 51，无未审计成员。
- 非成员 Rust：fuzz/（独立 cargo-fuzz workspace，fuzz/Cargo.toml 注释自述非根成员）；engineering/evidence-schema（.json+.md）、plugins（仅 .md，未读）、verifiers（3 个 .py，已由 Shard E 概括）。

---

## 3. 仍无法确认的点（如实记录）
1. 真机 Linux 上 netlink/route 装配、TUN/FUSE 创建的真实成功路径——单测为纯函数报文构造，未实跑（红线禁止全量 test；未做真机验证）。
2. 276 个 `[when].command` 场景在本机是否实际 PASS——仅核实执行器逻辑与断言机制，未运行 `verify --full`。
3. task_executor_tests 的 child-process fixture 是否真连本机 Docker daemon（代码走 /var/run/docker.sock，沙盒是否存在该 sock 未验证）。
4. nexus-dns 线上 Resolver 的真实注入实现：全仓只见注入点（lib.rs:158），未见真实 DNS server 实现，源码中无法确认。
5. nexus-proto 空壳是"待建"还是"废弃"，源码无法区分。
6. `.githooks/*.sh` 在真实 git 事件中的执行效果；nexus-delivery 列入 portable_core 的产品意图。
7. `data/n3/tasks` 目录树是否由外部部署脚本预建（属运维/叙述性文档范畴，按口径不采信）。

## 4. 复核边界声明
本次复核为**静态源码 + 机器配置**层面：未运行全量测试、未启动任何服务、未修改仓库文件；少量结论（OS 副作用、端到端场景、Docker 依赖）需在真机/CI 上二次验证，已在第 3 节逐项列明，未以推测充当事实。

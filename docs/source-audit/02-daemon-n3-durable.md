# 02 · daemon 与 N3 durable 任务片区 源码审计

> 本文仅依据仓库 e6ccf8b 的源代码与机器配置（.rs/Cargo.toml/*.toml）撰写，未采信任何叙述性文档；结论行号均可复核。

## 片区范围与行数总表

| 成员 | .rs 行数 | 说明 |
|---|---|---|
| apps/nexusd | 28,877 | daemon 组合根（main.rs 1,390 行 + 任务系统/数据面/workspace/recovery 等） |
| crates/nexus-compute | 1,933 | N3 纯域契约层 |
| crates/nexus-workspace | 7,550 | CAS 内容工作区引擎 |
| crates/nexus-workspace-intel | 1,135 | 非权威访问智能层 |
| apps/nexus-platform-host | 58 | 能力转储薄壳二进制 |
| **合计** | **39,553** | |

---

## 1. apps/nexusd（28,877 行）

### 1.1 实际职责（从代码推断）
daemon 是进程级组合根：启动后解析 config 目录、做 boot reconcile、拉起一条 TUN 数据面线程、一条手写 HTTP/1.1 LocalAPI 线程、一条配置 watcher 线程、（Linux）FUSE workspace 挂载与 N2 session sweeper。对外只暴露一个 TCP LocalAPI（默认 `127.0.0.1:18080`，config.rs:131-133），承载 v0 只读状态查询与一条 v1 任务路由。

### 1.2 启动流程（main.rs，全部读完）
- `main()` main.rs:257：子命令分发——`nexusd <config>` → `run_daemon`；`nexusd serve [--addr|--socket]` → `serve_resource`（main.rs:848，兼容形态，unix socket 默认 0600 harden main.rs:1026-1032，Windows named pipe 未实现）。
- `run_daemon` main.rs:386：
  1. `ConfigDir::new` main.rs:387；注册 SIGTERM/SIGINT main.rs:399,695。
  2. `config::load` main.rs:402 → `LoadedConfig{daemon, network_toml, proxy_yaml, dns_toml, workspace_toml}`。
  3. `recovery::boot_reconcile(state_dir, orphan_mountpoints)` main.rs:441，打印一行 JSON。
  4. `ensure_n2_session_manager` main.rs:461 + `spawn_n2_session_sweeper`（30s 周期 main.rs:66-108）。
  5. **T3 门禁**：proxy/network/workspace 三者皆无 → exit 1 main.rs:465-473。
  6. `assembly::build_dataplane_config` main.rs:479；`assembly::assemble_n1` main.rs:490-507（失败降级为 None）。
  7. `tun_enabled()` 时 `run_dataplane` 线程 main.rs:514-534。
  8. `serve_localapi` 线程 main.rs:541-546。
  9. Linux：`WorkspaceManager::start` main.rs:571-587；`watcher::spawn` main.rs:591。
  10. 主循环 `ev_rx.recv_timeout(500ms)` main.rs:594-613；关闭走 `shutdown_sequence` main.rs:616,630。

### 1.3 对外服务面（LocalAPI，逐端点）
- 监听器：手写 TCP HTTP/1.1，bearer token 常量时间比较（`bearer_authorized` main.rs:1208，`constant_time_eq` main.rs:1224）；token 文件 `<config>/localapi.token`（0600、64 hex，`assembly::load_localapi_token` assembly.rs:280-341）。
- **先 task_http::dispatch** main.rs:1091：仅当 target 前缀 `/localapi/v1/` 才处理；dispatch 内唯一路由 `POST /localapi/v1/task`（task_http.rs:201，严格 POST/JSON/bearer+local_transport+TokenAuthority 三重鉴权 task_http.rs:243，body ≤1MiB task_http.rs:11）。
- v0 GET 路由表 main.rs:1148-1196：
  - `/localapi/v0/status` → `nexus::observability::status()` main.rs:1149
  - `/localapi/v0/dataplane/stats` → 计数快照（mesh/proxy/direct/dropped/dns/qos）main.rs:1151-1168
  - `/localapi/v0/dns/status`、`/dns/cache` main.rs:1170-1173
  - `/localapi/v0/session/watch?session=` main.rs:1174
  - `/localapi/v0/n2/session/list`、`/n2/session/attach?session=` main.rs:1177-1178
  - `/localapi/v0/plan/explain?resource=` main.rs:1179
  - `/localapi/v0/connectivity/status`、`/platform/capabilities` main.rs:1181-1184
  - `/localapi/v0/workspace/mounts`（linux，全局 `WORKSPACE_MGR` main.rs:36-38,1042）main.rs:1186
  - `/localapi/v0/workspace/commit/<id>`（linux，`workspace_commit` main.rs:1062-1082）
  - 其余 404 main.rs:1187。
- **实现深度结论**：v0 全部为只读转调 `nexus::observability::*`（外部 crate）；v1 任务路由的 `Get/Cancel/ReadLogs/ListArtifacts/GetArtifact` 真实落到 ProviderService（task_service_provider.rs:233-330），唯 `Submit` 硬编码拒绝（见下）。

### 1.4 N3 durable 任务全链路
**持久化层（文件即事实，全部读完）**
- `task_store.rs`：`FileTaskAcceptanceStore`，唯一文件 `<root>/acceptance-v1.json`（task_store.rs:355），root=`<config>/data/n3/tasks`（task_service_provider.rs:54）；0700 私有、非符号链接（task_store.rs:116）；`acceptance.lock` flock（task_store.rs:280-313,535）；写为 tmp+fsync+rename+dir sync 原子发布（task_store.rs:463）；`transact` 校验"accepted 记录不可删改"(task_store.rs:626-636)+幂等重放(task_store.rs:637-655)。非 linux 全 Err UnsupportedCapability(task_store.rs:62-71)。**implemented。**
- `task_runtime_store.rs`：`task-runtime-v1.json`（task_runtime_store.rs:21），`RuntimeImage{journals:Vec<RuntimeJournal>}`，事件乐观追加不可删改（task_runtime_store.rs:308），Prepare/StartIntent 时回查容量门禁（task_runtime_store.rs:325-332）。**implemented。**
- `task_requester_store.rs`：requester 侧镜像+取消 outbox（`requester-v1.json`），**生产无调用方**（rg 全仓仅自身+测试+lib.rs:37 re-export）。**dead（生产）。**
- `task_sessions.rs`：`TaskSessionBridge` 把 N2 resource Session 与 Task 绑定/独占校验（task_sessions.rs:75,132,154），boot reconcile 重放 cleanup intents（task_sessions.rs:228），close_confirmed 触发 SessionManager close+N2 Disposed（task_sessions.rs:258）。仅在 `open_with_sessions` 生产路径被构造（task_service_provider.rs:102）。**implemented。**
- `task_capacity.rs`：显式 operator 预算账本（`CapacityBudget{cpu,mem,pids,storage,disk,slots}` task_capacity.rs:39；`ProviderCapacityPolicy` task_capacity.rs:71；demand 推算 task_capacity.rs:131）。`verify_capacity_for_start` 要求 capacity image 非 None，否则 Err "real execution requires explicitly provisioned capacity"（task_capacity.rs:565-567）；`provision_capacity` 仅接受 fresh-empty root（task_capacity.rs:475），生产 open_existing 路径永不调。**逻辑 implemented，但生产恒无 policy → 容量门禁恒拒。**

**执行后端**
- `task_executor.rs`：`LinuxTaskExecutor`，`verify_environment` 要求 image 在 `self.images` 白名单（task_executor.rs:78-91）、limits 硬约束（task_executor.rs:92-100）、真调 docker `GET /info` 校验 OSType/seccomp/mem/cpu（task_executor.rs:102+）、`GET /images/{digest}/json` 校验；`run` task_executor.rs:163。**关键：生产 `LinuxTaskExecutor::open(&root, Vec::new())`（task_service_provider.rs:87）传入空白名单。**
- `task_executor_docker.rs`：**真 Docker Engine API 客户端**——UnixStream 连 `/var/run/docker.sock`（task_executor_docker.rs:24），手写 HTTP v1.45，exec_create/start/inspect/kill/archive（tar 80MiB 上限）/quiesce(kill -KILL -1+ps 轮询)（task_executor_docker.rs:68,114,148,166,178,198,312）。**不是空转/Unsupported。**
- `task_executor_run.rs`：create 容器（Entrypoint `/bin/sleep`、Cmd `["2147483647"]`、User 65534、NetworkMode none、readonly rootfs、Tmpfs /work、ro bind /input）（task_executor_run.rs:25-45），helper `cp -R /input/. /work/` 后回灌校验 digest，再 `exec_create(container, contract.request.command, ...)`（task_executor_run.rs:86-88）——**真正任务命令经 docker exec 跑，容器本体是 sleep 占位**；drain stdout/stderr frame、50ms 轮询 exec_inspect、publish engine/started/exit/reaped 证明 JSON、超时/取消处理、archive work tree、stage_outputs。ContainerGuard Drop 兜底 docker.stop（task_executor_run.rs:271）。
- `task_executor_recovery.rs`：boot 时对每个已存 task `reconcile`——重新 inspect Docker 容器、按 durable handle 比对、回灌 sealed 证据（task_executor_recovery.rs 全文）。**真实冷恢复。**
- `task_executor_logs.rs`：`executions-v1/<sha256(task)[7:]>/` 下 stdout/stderr 追加文件 + `logs-v1.json` 权威(sizes/truncated/sealed) + owner/start/logs lock（flock+dev/ino 绑定，task_executor_logs.rs:84-153）。
- `task_executor_results.rs`：`sealed_results` 要求 Exited+Confirmed+sealed logs+exit-proof+reaped 证明+work-tree tar+outputs-v1.json 逐输出回读一致（task_executor_results.rs:10-157）。
- `task_executor_archive.rs`：严格 tar(ustar/PAX/GNU) 解析，拒绝逃逸、≤65536 文件、仅取 work/ 子树。
- `task_capacity_recovery.rs`：begin/finish_capacity_owner_recovery + release_capacity_from_executor，仅 has_capacity_policy 时非 no-op（task_capacity_recovery.rs:164-170）。

**artifacts**
- `task_artifacts.rs`：`FileTaskArtifacts`，catalog `artifacts-v1.json` + content-sha256-v1 blob（task_artifacts.rs:24,131-152）。读侧 `get/list/logs/logs_registered` 带 identity 校验(principal==记录者 && workspace 匹配 task_artifacts.rs:419)+deny 审计 journal(task_artifacts.rs:429-443)，页 1..65536（task_artifacts.rs:446）——**已被 ProviderService 接线**。`publish`(task_artifacts.rs:84) 交付 finalized **生产无调用方**（rg `.publish(` 仅测试/无关）。无 delete API（task_artifacts.rs:69 注释 GC 待后续）。
- `snapshot_store.rs`：内容强命名 store + snapshot-roots catalog(staged/retained/tombstones)；`verify_inputs/prepare_inputs` 被 executor run/reconcile 调用；`collect_garbage/stage_snapshot/retain` 生产调用方待查（疑似仅测试/外部 CLI）。
- `artifact_fs.rs`：私有权威 IO helper（0700/O_NOFOLLOW|O_CLOEXEC/dev+ino 绑定/checksum envelope/atomic rename）。
- `artifact_download.rs`：5 行纯 re-export `pub use nexus::artifact_download::ArtifactDownload;`（requester 侧接收，非本 daemon 生产路径）。

**关键判定：N3 执行链路生产不可达（三重）**
1. `Submit` 在 task_service_provider.rs:229-231 硬编码 `Err(UnsupportedCapability("Submit requires real capacity, Session and authenticated input transport; not assembled"))`。
2. `executor.run()` 全仓仅测试调用（rg 确认），生产只调 `executor.reconcile`（task_service_provider.rs:94）。
3. 即使 run 被调，approved_images 为空 + capacity image 为 None，必在门禁处拒。
→ **N3 provider 当前是"只读回放/查询服务"**：能 Get/Cancel/ReadLogs/ListArtifacts/GetArtifact 已 accepted 的 task，但不能新提交、不能真跑。

### 1.5 assembly / dataplane / nat_switch / proxy_fwd / recovery / watcher / workspace
- `assembly.rs`：纯装配胶水——`parse_mesh_cidrs`(assembly.rs:27，从 network.toml [vpi.routes] 派生，不硬编码 10/8)、`assemble_n1`(assembly.rs:87，后台尽力 dial)、`build_dataplane_config`(assembly.rs:129，mesh/bypass/QoS/boost/dns)、`assemble_n2_session_manager`(assembly.rs:220，journal replay+torn tail discard+reconcile)、`load_localapi_token`(assembly.rs:280)、`join_with_timeout`(assembly.rs:355)。**implemented。**
- `dataplane.rs`(1,877 行)：`Dataplane` TUN 包处理——DNS 短路、分类(mesh/bypass/proxy/direct)、QoS(cake)、flow session、stats 全局句柄(dataplane.rs:1409)。`process_one`(dataplane.rs:423)。**但生产注入的 DNS resolver 全是 stub**：`StubUpstreamResolver` 恒 Err "stub upstream not configured"(dataplane.rs:1428-1435)、`StubMeshResolver` 恒 None(dataplane.rs:1439-1444)、`StubProxyClassifier` 恒 true(dataplane.rs:1446-1451)。`enable_flow_sessions`(dataplane.rs:253) **生产无调用**。
- `run_dataplane`(main.rs:302)：TunRsDevice::create 失败即 return（数据面禁用，LocalAPI 仍服务 main.rs:319-324）；`set_n1_sender`(main.rs:340)、`ProxyEngine::new` 成功则 `set_proxy_engine`(main.rs:346-349)。
- `nat_switch.rs`(290)：完整 NAT 切换栈(PunchManager+PathLink+QualityMonitor)，**但文件头自述 main.rs 不实例化**(nat_switch.rs:19-22)，rg 确认无 `NatSwitching::new` 调用方。**dead（生产）。**
- `proxy_fwd.rs`(256)+`proxy_fwd/{tcp_relay,udp_relay,ss_std}.rs`(1,251)：`ProxyEngine`，支持 ss(chacha20-ietf-poly1305)/trojan(明文/TLS)/socks5 出站选择(proxy_fwd.rs:55-106)，TCP smoltcp 终结→dial→中继、UDP 中继回包重构 IP。AnyTLS/VLESS/Hysteria2/Vmess/Direct 返回 None 不支持(proxy_fwd.rs:93-98)。**implemented 且经 set_proxy_engine 接线。**
- `recovery.rs`(750)：boot reconcile——sessions.json/links.json 原子替换、损坏文件 quarantine 保留取证(recovery.rs:397-420)、orphan FUSE 挂载清理(recovery.rs:428-447)、run.marker。测试覆盖 roundtrip/corrupt/orphan/幂等。**implemented。**
- `watcher.rs`(199)：2s 轮询 5 个固定配置文件 mtime+size，分类 Hot/NeedsRestart/Rejected。**Hot 分支主线程只 eprintln（见 07-B M1），未回注运行子系统。**
- `workspace.rs`(682，linux)：FUSE workspace 挂载——`WorkspaceManager::start`(workspace.rs:352) open-or-create CAS+state_root 锚文件、mount_projected_workspace、auto-commit 线程(workspace.rs:178)、shutdown 时 warn 脏数据不静默提交(workspace.rs:489-496)、挂载点冲突校验(workspace.rs:250-310)。无 /dev/fuse 则 disabled 不 fallback(workspace.rs:354-362)。经全局 `WORKSPACE_MGR` 暴露 /workspace/mounts 与 /workspace/commit。**implemented。**
- `sync_transport.rs`(275)：fabric QUIC bi-stream(type 0x03)上的 `WorkspaceTransport` 实现 + 成员授权 `serve_sync_authorized`。**生产无调用方**（rg 全仓仅自身+测试）。**dead（生产）。**

### 1.6 依赖（apps/nexusd/Cargo.toml）
path 依赖：nexus、nexus-control-api、nexus-session、nexus-network、nexus-fabric、nexus-proxy-config/transport、nexus-outbound-{trojan,anytls,vless,hysteria2}、nexus-projection、nexus-connectivity、nexus-dns、nexus-path、nexus-nat-{traversal,wireup,quality}、nexus-storage、nexus-flow-session、nexus-workspace、nexus-compute、nexus-platform 等。第三方：toml、serde_json(std)、signal-hook、chacha20poly1305/hkdf/sha1（ss AEAD）。**不依赖 nexus-workspace-intel。**

### 1.7 实现度判定
**partial**。证据：启动/数据面/LocalAPI/workspace/recovery 真实（main.rs:441,541；dataplane.rs:423；workspace.rs:352）；但 N3 Submit stub(task_service_provider.rs:229)、Docker executor 生产不可达、DNS upstream stub(dataplane.rs:1428)、flow sessions 未 enable、hot-reload 空转(main.rs:599)、sync_transport/nat_switch/requester_store dead。

### 1.8 stub / 空转 / 硬编码清单
- `task_service_provider.rs:229-231`：Submit 恒 `Err(UnsupportedCapability(...not assembled))`。
- `task_service_provider.rs:87`：`LinuxTaskExecutor::open(&root, Vec::new())` 空镜像白名单。
- `task_service_provider.rs:55-79`：强制 open_existing，不 provision provider 目录（注释自述）。
- `dataplane.rs:1428-1435`：StubUpstreamResolver 恒 Err；`:1439-1444` StubMeshResolver 恒 None；`:1446-1451` StubProxyClassifier 恒 true。
- `main.rs:599-601`：Applied 仅 eprintln，不回注配置。
- `proxy_fwd.rs:188-190`：`is_usable_target` 恒 true（`#[allow(dead_code)]`，测试辅助）。
- `proxy_fwd.rs:181-183`：`has_dial_config` 恒 true（`#[allow(dead_code)]`）。

### 1.9 测试
- `#[test]` 总数：**242**（`rg -c "#\[test\]" apps/nexusd/src/` 求和）；`#[tokio::test]` 0。
- 测试实际覆盖（读测试代码后概括）：recovery roundtrip/corrupt-quarantine/orphan-mount 幂等(recovery.rs:553-749)；watcher hot/reject/needs-restart(watcher.rs:147-198)；workspace.toml 解析/挂载点冲突/无 fuse disabled(workspace.rs:514-681)；acceptance ledger 不可删改/幂等重放/原子发布；runtime store 乐观追加；executor 的 lease/dev-ino 绑定、child-process fixture 观察 container alive、owner crash 后重复提交被拒(task_executor_tests.rs:695,754)；capacity witness 释放；artifacts catalog/deny 审计；executor archive tar 严格解析。多数 durable 测试用 child-process SIGKILL 注入崩溃边界。

---

## 2. crates/nexus-compute（1,933 行）

### 2.1 实际职责
N3 的**纯域契约层**——不含任何 OS 调用，提供 accepted task 的状态机、runtime 事件重放、requester 镜像、artifact 注册校验。被 nexusd 的文件持久层包裹。

### 2.2 关键类型/入口
- `task.rs`：`AcceptedTask`(task.rs:10)、`AcceptanceLedger`(task.rs:32)、`TaskOwner<S>::accept_verified`(task.rs:181)、`accepted`(task.rs:321)。
- `task_runtime.rs`：`RuntimeAction`(task_runtime.rs:15)、`RuntimeEvent`/`RuntimeJournal`/`RuntimeState`/`RuntimeUpdate`(task_runtime.rs:70-91)、`replay`(task_runtime.rs:123)、`record_event`(task_runtime.rs:172)。
- `task_requester.rs`：requester 只读镜像 + 取消投递 intent。
- `task_artifact.rs`：artifact 注册与 log 注册事实校验。
- `lib.rs`：`ComputePhase{Submitting,Active,Closed}`(lib.rs:24) 等冻结契约。

### 2.3 依赖
纯类型层，依赖 nexus-domain（任务错误/ID/Digest）；被 apps/nexusd（task_store/task_runtime_store/task_executor 等）与 apps/nexus 依赖。

### 2.4 实现度
**implemented**。证据：`accept_verified`(task.rs:181) 与 `replay`(task_runtime.rs:123) 有完整状态转移逻辑，被 nexusd `TaskOwner::new`(task_service_provider.rs:85) 与 `FileTaskRuntimeStore` 调用。

### 2.5 stub/空转
无 `unimplemented!/todo!`。注释自称"no OS calls"(lib.rs:14)与代码一致。

### 2.6 测试
`task_runtime_session_tests.rs`(201)、`task_requester_tests.rs`(224) + lib.rs:136 mod tests；覆盖状态机转移与 requester 镜像。

---

## 3. crates/nexus-workspace（7,550 行）

### 3.1 实际职责
CAS（内容寻址）工作区引擎：commit/head/merge/conflict/sync(serve+exchange)/snapshot/gc/cache，并提供 FUSE projection 适配。

### 3.2 关键类型/入口
- `lib.rs`：`WorkspaceId/CommitId/AuthorId`(lib.rs:52-61)、`Workspace<S:ContentStore>`(lib.rs:1363)、`init`(lib.rs:1435)、`open`(lib.rs:1473)、`commit_pending`(lib.rs:1658)、`commit_changes/commit_with_deletes`(lib.rs:1685,1698)、`read_from_head/list_head_paths`(lib.rs:1751,1778)、`reconcile_journal`(lib.rs:1797)、`merge_heads`(lib.rs:1837)、`resolve_conflict`(lib.rs:2064)、`exchange_heads`(lib.rs:2167)、`sync_with_remote(_opts)`(lib.rs:2313,2322)、`serve_sync`(lib.rs:2559)、`WorkspaceTransport` trait(lib.rs:3269)。
- `snapshot.rs`(314)、`gc.rs`(1,225)、`cache.rs`(439)、`projection_adapt.rs`(137，导出 `WorkspaceProjection` lib.rs:43)。

### 3.3 依赖
依赖 nexus-storage（ContentStore/FsContentStore）、nexus-domain；被 apps/nexusd（workspace.rs:23-25 import Workspace/WorkspaceProjection/NativeApiWorkspaceAccess）与 apps/nexus 依赖。

### 3.4 实现度
**implemented**。证据：`Workspace::init/open/commit` 被 nexusd workspace.rs:399-417 真实调用并挂载；merge/conflict/sync 有完整测试模块（lib.rs:3335-3890 remote_session/access/sync_shallow/sync_conflict）。

### 3.5 stub/空转
无 `unimplemented!/todo!`。其 `WorkspaceTransport` trait 的生产 fabric 适配在 nexusd::sync_transport（但该适配本身 dead，见 1.5）。

### 3.6 测试
lib.rs 内联 5 个测试模块（access_provider/workspace_access/sync_transport/sync_shallow/sync_conflict）+ gc/cache 模块测试；覆盖 commit/merge/sync/conflict 语义。

---

## 4. crates/nexus-workspace-intel（1,135 行）

### 4.1 实际职责
非权威、可丢失重建的访问智能层：AccessTrace→WorkspaceGraph→WorkingSetEstimator→PrefetchScheduler；只读依赖 workspace manifest，绝不参与正确性判断（lib.rs:1-22 自述，与代码一致）。

### 4.2 关键类型/入口
`lib.rs:33-40` 导出 `to_snapshot`、`WorkingSetEstimator/ScoredPath/TaskContext`、`WorkspaceGraph`、`PrefetchScheduler/PrefetchPlan`、`Profile`、`IntelStore/IntelSnapshot`、`AccessTrace/AccessEvent`。模块：delivery/estimator/graph/prefetch/profile/store/trace。

### 4.3 依赖
依赖 nexus-domain（`ResourceDeliveryRequest` lib.rs:36 re-export）；**仅被 apps/nexus 依赖**（apps/nexus/Cargo.toml:36），**nexusd 不依赖本 crate**。

### 4.4 实现度
**implemented（库）**——estimator/graph/prefetch 逻辑完整且自带测试；但在本 daemon 片区内 **orphaned（无调用方）**，实际消费者是 CLI。

### 4.5 stub/空转
无 `unimplemented!/todo!`。

### 4.6 测试
estimator/graph/prefetch/store 模块内联测试（trace→graph→estimate→prefetch 链路）。

---

## 5. apps/nexus-platform-host（58 行）

### 5.1 实际职责
薄壳二进制：`vpi-capabilities`（feature=`platform-windows`）把 `WintunVpiAdapter::capabilities()` 拼成静态 JSON 打印；无该 feature/无子命令时打印 `"nexus-platform-host: repository-contract bootstrap"`（main.rs:24）。

### 5.2 关键代码
`main()` main.rs:19；`print_vpi_capabilities` main.rs:30（全 `concat!` 字面量拼装，零第三方依赖）；`bool_json` main.rs:53。Cargo.toml features：platform-linux/windows/macos/android/ios（全部 optional，default=[]）。

### 5.3 实现度
**stub（薄壳/占位）**。证据：无 daemon、无监听、无装配；default 分支仅一行 println；唯一有逻辑的分支是静态能力转储，不创建驱动对象（注释自述 main.rs:9-10）。

### 5.4 测试
无 `#[test]`。

---

## 6. 片区内跨 crate 调用主干

```
nexusd::main (run_daemon)
 ├─ config::load → assembly::{build_dataplane_config, assemble_n1, assemble_n2_session_manager}
 ├─ run_dataplane (main.rs:302) → dataplane::Dataplane::new
 │     ├─ set_n1_sender (Option<dyn N1Sender>)         [mesh 真发]
 │     ├─ set_proxy_engine (proxy_fwd::ProxyEngine)    [proxy 真转发]
 │     └─ DNS = Stub{Upstream,Mesh,ProxyClassifier}   [stub，不真解析]
 ├─ serve_localapi (main.rs:749)
 │     ├─ task_http::dispatch → POST /localapi/v1/task
 │     │     └─ LocalTaskService::execute → ProviderService::execute
 │     │           ├─ Get/Cancel/ReadLogs/ListArtifacts/GetArtifact → 真
 │     │           └─ Submit → 硬编码 UnsupportedCapability
 │     └─ v0 GET → nexus::observability::* / workspace_* (全局 WORKSPACE_MGR)
 ├─ WorkspaceManager::start (linux) → nexus_workspace::{Workspace::init/open,
 │      NativeApiWorkspaceAccess, WorkspaceProjection} → FUSE mount
 ├─ recovery::boot_reconcile → nexus_session/nexus_connectivity 记录
 └─ watcher::spawn → 主线程只打日志，不回注

nexus-compute (纯类型) ← 被 nexusd::task_store/task_runtime_store/task_executor 包裹成文件持久层
nexus-workspace (CAS 引擎) ← 被 nexusd::workspace 接线；其 WorkspaceTransport 的 fabric 适配
     = nexusd::sync_transport（dead，无生产调用）
nexus-workspace-intel ← 仅 apps/nexus 依赖，nexusd 不碰
```

## 7. 片区小结

**真实能力**：daemon 启动/优雅关闭/boot reconcile 完整；TUN 数据面对 mesh(proxy) 真发、proxy_fwd 真转发；LocalAPI v0 只读与 v1 任务查询/取消/读日志/取产物真实可达；FUSE workspace 挂载与 CAS commit 真实；N3 durable 持久层（acceptance ledger + runtime journal + logs + artifacts catalog + capacity witness）工程严谨——原子写、flock、dev/ino 绑定、崩溃注入测试齐全；Docker Engine API 客户端是真实现。

**最大缺口**：N3 端到端"提交并真跑"不可达——Submit 硬编码 stub、executor.run 生产无调用方、镜像白名单为空、容量账本未 provision；DNS upstream/mesh resolver 是 stub；flow session、workspace fabric sync、NAT 切换、requester outbox 在 daemon 内全部 dead 或未接线；配置 hot-reload 只打日志。**当前 nexusd 的 N3 实质是"已 accepted 任务的只读回放/查询面"，不是可执行任务的生产者。**

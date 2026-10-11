# Review Evidence — review-g11-ice-fix-qoder-r1

**Verdict: COMMENTED** （0 FAIL / 5 WARN / 3 PASS，按 SKILL.md「最差维度决定 verdict」）
Round 1，`previous_review_id: null`（本轮为首轮，无上一轮维度可比，`dimension_changes` 为空）。

---

## 0. 评审对象与独立性

| 项 | 值 |
|---|---|
| 被审工作树 | `E:\nexus-fabric-g11`（未提交改动，6 个文件） |
| source_revision | `0576cb73a802256604088f6accd4917b245c3945`（master，两台宿主一致） |
| diff 规模 | `git diff --stat`：6 files changed, **323 insertions(+), 102 deletions(-)** |
| changed_crates | `nexus-web-gateway` |
| reviewer | 独立执行者：QoderCN agent session `e58b828003f28f0fd371bf461e820d18` / agent `c2283260c5da99a5d2076c04`；model: **unknown-bound-by-app**（不披露底层模型）；与被审补丁的作者无关 |
| 写入范围 | 仅 `.evidence/review-g11-ice-fix-qoder-r1/`（`/.evidence` 在 .gitignore:3，写案卷不改变 working_tree_digest） |
| 只读约束 | 6 个被审文件未改动、未 commit/push、未 reset/checkout；实验全部在 Linux 宿主的副本上做 |

### 宿主与工具链版本

```
$ uname -srm          (实验宿主)  Linux 5.15.0-139-generic x86_64
$ rustc -V                      rustc 1.98.1 (48a229cea 2026-09-01)
$ cargo -V                      cargo 1.98.1 (797e8a9bc 2026-08-05)
$ git --version                 git version 2.25.1
target triple (harness 报告)     x86_64-unknown-linux-gnu, toolchain_version 1.98.1

$ uname -s (Windows 评审宿主)   x86_64 / MINGW64 (Git Bash)
$ git --version                 git version 2.46.0.windows.1
```

实验目录：`/work/nexus-dev/review-g11-qoder`（E: 工作树的 tar 管道整树拷贝，含 `.git`）与
`/work/nexus-dev/g11-mut/{m0,m1,m2,m3,m4,m5,diag,diag2,inst2,l6,l7}`；
`CARGO_TARGET_DIR=/work/nexus-dev/target-g11-review`（**故意偏离任务给的 `/work/nexus-dev/target`**，原因见 §4 更正-1）。
原始日志：`/work/nexus-dev/review-g11-qoder-baseline{,2}.log`、`/work/nexus-dev/g11-mut/results{,2..9}.txt`。

### 证据绑定（digest / contract_hash）

`nexus-harness status` 在 Linux 副本上实际跑通：

```
contract_hash          9c44e9351f04ba1d2afc3a924954d4ad7710c97e
configuration_digest   29adba1e5e453ec0a83395928f2a63bc903e32de
platform_capability…   711a114fe73b9bf0c371c2a2809389611af3ba8a
working_tree_digest    bedf96bba32756a1ad785c1d155a01c75fc4944b   <-- 见下方说明
source_revision        0576cb73a802256604088f6accd4917b245c3945
verdict                UNKNOWN（"no evidence recorded; run nexus-harness verify --fast"）
```

* **contract_hash = `9c44e935…`**：我按 `engineering/nexus-harness/src/env.rs:147` 的算法
  （`scenarios/<dir>/<file>.toml`，目录名与文件名各自排序，`"scenarios/{d}/{n}\n{内容}"` 用 `\n===\n` 连接，
  喂给 `git hash-object --stdin`）独立复算，结果与 harness 逐字节一致 → 可信。
  任务里提到的 `8de98ae132401f6837fcbf5f4df363ebfcfe1f82` **不是本树的 contract_hash**；
  它的来源已查明：`/work/gateway-file-module/.evidence/verify-c327a6da9351/{summary.json,metadata.json}`
  （文件模块工作树，同 HEAD `0576cb7` 但工作区有 16 个改动文件、scenario 集不同）。
  本补丁 `git diff --stat -- scenarios policies` 为空，不触碰契约集，故引用 8de98ae1 会把本 Review 绑到别人的契约上，已改用实测值。
* **working_tree_digest = `2f1d4c3e66b6978a06642328acedc769078c30a8`**（案卷采用值）：
  harness 的算法是 `git hash-object --stdin` over `trim(git status --porcelain)`（env.rs:106 + env.rs:45-59 的 `.trim()`）。
  我在 Windows 原树、Linux 副本、以及 round-9 干净重测三处都得到同一个 `2f1d4c3e…`，
  porcelain 均为那 6 行 ` M`。harness 输出的 `bedf96bb…` 是**调用它的那条 `cargo run -q -p nexus-harness`
  自身改动了 `Cargo.lock`** 之后的一刻测得（7 行 porcelain），不代表被审的 E: 工件；
  该值在此公开，便于与 verify 案卷对账。

---

## 1. 基线（被审补丁本身）

```
cargo clean -p nexus-web-gateway && cargo test -p nexus-web-gateway --offline --no-fail-fast
  → test result: ok. 24 passed; 0 failed     (lib，含 2 条新 G11 单测)
  → test result: ok. 21 passed; 0 failed     (tests/gateway_e2e.rs)
  → cargo exit: 0
```

两条新单测（`gateway::tests::concrete_listen_addr_advertises_only_the_bound_address`、
`gateway::tests::unspecified_listen_addr_widens_bind_and_candidates`）与两条新 e2e
（`loopback_bound_gateway_advertises_only_loopback_candidates`、
`wildcard_bound_gateway_advertises_all_routable_interfaces`）全绿；
既有契约测试 `unspecified_listen_addr_derives_concrete_page_addr`（gateway_e2e.rs:171）仍绿。

```
cargo fmt --check -p nexus-web-gateway   → 干净（exit 0）
cargo clippy -p nexus-web-gateway --all-targets → 无 warning/error（workspace 设了 warnings=deny，Cargo.toml:70-71）
```

**pre-patch 复现**（`m0`＝副本内 6 文件 `git checkout -- .` 回到 0576cb73）：

```
lib:  22 passed; 0 failed
e2e:  running 20 tests → 7 passed; 13 failed
      失败原因全部是 "peer 0 should connect" / "no control channel open"（gateway_e2e.rs:204/308/349/414/455/508/559/639/732/832/918/1170）
      而旧测试 ice_advertises_multiple_host_candidates ... ok      ← 特性坏掉时它是绿的
```

这与任务背景（gateway-ci 连红、12+ 条 e2e 报同样两个症状）一致，也证明被删的那条「ICE 回归测试」是零断言的空测试。

---

## 2. 变异实验（真能证伪吗？）

每个变异都在独立副本上做，**跑前先 `cargo clean -p nexus-web-gateway`**（原因见 §4）。
所有变异都写成 warning-free 形式（`x && false` / 改比较常量），以免 `warnings = deny` 把「编译失败」伪装成「测试失败」。

| ID | 变异（打回去的东西） | 位置 | lib 结果 | e2e 结果 | 判定 |
|---|---|---|---|---|---|
| **M1** | 具体 IP 也通告全网卡：`candidate_ips: vec![listen_ip]` → `routable_iface_ips(listen_ip)` | gateway.rs:99 | `concrete_listen_addr_…` **FAILED** @gateway.rs:1656 | **14 FAILED / 7 passed**，含新测试 `loopback_bound_…` @gateway_e2e.rs:1278，其余 13 条复现 "peer 0 should connect"/"no control channel open" | **被杀死**（且精确复现历史红） |
| **M2** | 只通告 0.0.0.0：`candidate_ips: ifaces.clone()` → `vec![listen_ip]` | gateway.rs:108 | `unspecified_…` **FAILED** @gateway.rs:1679（"0.0.0.0 leaked into candidates"） | `wildcard_bound_…` **FAILED** @gateway_e2e.rs:1332 | **被杀死**（单测+e2e 双杀） |
| **M3** | 模拟「只有 lo 的机器」：`same_family && false && …` | gateway.rs:59 | `unspecified_…` **FAILED** @gateway.rs:1675（"an offer must never be candidate-less"） | `wildcard_bound_…` **FAILED** @1332 | **被杀死**，但杀它的是「主机的网卡状态」→ 见 WARN-T1 |
| **M4** | 删掉兜底：`if added == 0` → `if added == 1_000_000` | gateway.rs:1611 | 24 passed | **21 passed** | **存活变异** → 兜底分支零覆盖（WARN-T2） |
| **M5** | M3+M4（空候选集 **且** 无兜底） | 59 + 1611 | `unspecified_…` FAILED @1675 | `wildcard_bound_…` **FAILED** @gateway_e2e.rs:1308，SDP 里一条 `a=candidate:` 都没有（`m=application 9 UDP/DTLS/SCTP`） | **被杀死**（`!addrs.is_empty()` 确实守住了「answer 永不空候选」这条不变量） |

结论：**任务点名的两个变异（M1「具体 IP 也通告全网卡」、M2「只通告 0.0.0.0」）都会变红**，
且 M1 同时打红新单测与新 e2e 并复现历史 12 条红；修复与新测试都是 load-bearing 的。
唯一存活的是 M4（兜底分支），M5 说明「空集合」这一后果仍由 e2e 守着。

### 2.1 分支语义实测（ice_bind_plan）

在被审代码里临时插桩 `eprintln!` 后直接打印（`l7` 副本，`-- --nocapture`）：

```
V6PROBE listen=::      total=23 link_local=14 page=2408:840d:9330:8b70:…  v4=0  v6=23
V6PROBE listen=0.0.0.0 total=9  link_local=0  page=172.168.12.97          v4=9  v6=0
INST Gateway::start listen=0.0.0.0 cands=9 no_routable=false   → wildcard e2e 该次 PASS
PROBE listen=0.0.0.0 raw_count=9 plan_count=9  page=172.168.12.97 no_route=false
```

主机实况：`ip -4 -o addr | grep -c 'scope global'` = 9；`ip -6 addr` 有 6 个 global + 多个 fe80；
getifaddrs 在测试进程里 `Ok total=48 loopback_flagged=2 routable_v4=9 routable_v6=25`。

核对结果：具体 IPv4/具体 IPv6/未指定 IPv4/未指定 IPv6/族匹配/`is_unspecified()`/`is_multicast()`/
去重/全 loopback（M3 模拟）→ **语义自洽，三分支覆盖完整**；`no_routable_interface` 分支可达且必要
（wildcard bind 的 socket 确实能收 127.0.0.1 的包，兜底不违反 G11）。
实测唯一诚实问题：**`::` 通配时 23 条候选里 14 条是无 scope-id 的 fe80 link-local**（WARN-E3）。

---

## 3. 逐条问题（带 文件:行号）

### contract-consistency — WARN

* **WARN-C1｜USER_MANUAL.md:39-43**：补丁删掉了 `note: listen_addr is unspecified; binding the WebRTC UDP socket to {udp_ip}`
  与旧 `warning: no non-loopback network interface found`（全仓 `grep -n "note:" src/gateway.rs` 已无命中，只剩 gateway.rs:344 一条 warning），
  但手册「### 2. 启动」仍在教操作员去日志里找这两行 → **写了没做（实为删了还写着）**。
  同一文件 FAQ 段（USER_MANUAL.md:126-133）却把新 warning 逐字抄对了，说明这纯属漏改。
* **WARN-C2｜USER_MANUAL.md:21**：「填 `"0.0.0.0:8443"` 会监听所有网卡，网关自动挑选一个可路由的网卡 IP 用于 WebRTC」
  —— 补丁后未指定地址是**绑族内通配 + 通告全部可路由网卡**，不是「挑选一个」。
* **WARN-C3｜MODULE.md:49-50**：Allowed Dependencies 仍写 getifaddrs 用于「`listen_addr` 为 `0.0.0.0` 时派生可路由的
  **WebRTC UDP 地址**」；补丁后 UDP 绑定地址是通配地址，getifaddrs 只派生**候选集合 + page_ip**。
* **WARN-C4｜requirements.toml:18（REQ-002）**：acceptance 是无条件的「多网卡机器上所有非 loopback IP 都成为 ICE host candidate」，
  补丁后仅在 `listen_addr` 未指定时成立；具体绑定时刻意只通告一个 IP。新测试注释（gateway_e2e.rs:1291-1292）自称
  「REQ-002 intent」，但需求文本未同步。注：该文件的 title/acceptance 本身就串行错位
  （REQ-002 标题「身份偏好持久化」配 ICE 验收，REQ-003「访问认证」配 candidate 迁移），**属既有问题，不记在本补丁账上**；
  本补丁需要做的只是把 ICE 那条验收加上「未指定 listen_addr」前置条件。
* **WARN-C5｜G11 只覆盖「启动那一刻」的网卡状态**：候选集合冻结在 `Shared.host_candidate_ips`（gateway.rs:191，
  于 gateway.rs:341 一次性算出，gateway.rs:1604 每会话只读）。运行期新起的 tun/EasyTier 地址永远不会被通告；
  反之网卡被摘掉/重编号后，通告的仍是 G11 禁止的「socket 收不到」的地址。
  补丁前 `create_session` 每会话重新枚举（虽绑错地址），**这一层运行期自愈能力是被本补丁删掉的**。
  收益却不成立：`create_session` 每浏览器会话才跑一次，不是热路径，省一次 getifaddrs 无意义。
  代码内部注释（gateway.rs:189-191「Computed once at startup」）承认了该假设，但 MODULE.md G11 与 USER_MANUAL 均未告知
  「网络变化需重启网关」→ **做了没写**。
* 逐字核对通过的部分：MODULE.md:79-84 的 G11 四条表述与 gateway.rs:93-116/37-61 一一对应；
  `page_addr` 契约未破坏（gateway.rs:362 + GatewayHandle 文档 gateway.rs:272-282，e2e gateway_e2e.rs:171 实测绿）；
  USER_MANUAL.md:131 的新 warning 文本与 gateway.rs:343-348 完全一致。

### edge-coverage — WARN

* **WARN-E1｜兜底分支无覆盖**：M4 存活（24+21 全绿）。gateway.rs:1611-1620 的
  「unspecified → loopback_for / 否则 udp_addr」这个选择逻辑没有任何测试跑到。
* **WARN-E2｜getifaddrs 失败被吞成「没有网卡」**：gateway.rs:38-40 把 `Err` 变成 `Vec::new()`，
  于是 gateway.rs:343-348 的告警把「枚举失败」误报成「这台机器根本没有可路由网卡，必须改网络或换节点」；
  又因为集合冻结在启动时（WARN-C5），一次瞬态枚举失败会**永久**把该网关降级成只通告 loopback。
* **WARN-E3｜IPv6**：`::` 通配实测通告 23 条 IPv6 候选，其中 **14 条 fe80 link-local 无 scope-id**，
  对端无 zone 不可达；`::` 绑定在 Linux 默认 `bindv6only=0` 下还收 IPv4，而候选里一条 IPv4 都没有 →
  IPv4 浏览器在 `listen_addr=::` 下永远连不上。G11 文本（MODULE.md:79-84）与 USER_MANUAL.md:126-133
  都只讲 IPv4/「族内通配」，未描述 dual-stack 与 link-local 语义。
  判定：**不阻塞本补丁** —— 该过滤器集合是从被删代码原样继承的，且它没有违反 G11 本身
  （`::` 绑定的 socket 确实能收到 fe80 包），修它需要 scope-id/族策略的独立决策，属遗留问题。
* 通过的边界：空输入（无网卡/全 loopback，M3 实测走 no_routable_interface + 兜底）、
  非法/多余地址（multicast、unspecified、跨族、重复地址均被过滤）、
  并发（`host_candidate_ips` 为 Arc<Shared> 里的不可读写字段，事件循环外只读，无锁序问题）、
  「offer 永不空候选」在 5 条路径上逐一核过（见 §2 表 M5 与 §2.1）。

### api-surface-minimization — PASS
新增项 `IceBindPlan` / `routable_iface_ips` / `ice_bind_plan` / `Shared.host_candidate_ips` 全为私有；
整个 diff 唯一的 `pub` 增量是测试工装字段 `tests/common/mod.rs:393 pub answer_sdp`。无 pub(crate)→pub 走私。

### dependency-boundary — PASS
`Cargo.toml`/`Cargo.lock` 零改动；getifaddrs 仍在 MODULE.md:41-53 允许清单内；
`policies/architecture.toml:306-309`（`allowed_internal_dependencies = []`）未被触碰；
`src/cert.rs:42-48` 经逐行核对 + `cargo fmt --check` 干净，**确认只有格式**（`fingerprint_sha256` 的链式调用换行），无行为变化。

### error-handling-quality — WARN
* **WARN-ER1｜gateway.rs:1605** `if let Ok(candidate) = Candidate::host(…) { … }` 静默丢弃每条候选的转换错误；
  这条循环现在是「启动计划 → SDP」之间唯一的关卡，被拒的候选不留痕迹，只有全灭才会惊动兜底。
* **WARN-ER2｜gateway.rs:38-40** 见 WARN-E2（错误上下文丢失，且给出误导性的运维结论）。
* 通过项：非测试代码没有新增 `unwrap/expect/panic!`（`git diff -U0 -- src | grep '^+'` 里两条 `.expect`
  都在 `#[cfg(test)]`（gateway.rs:1642）之内，即 gateway.rs:1653 与 1668）；兜底失败仍返回类型化
  `GatewayError::Rtc("host candidate: …")` 带上原始错误文本
  （gateway.rs:1617-1618），没有把内部细节塞给用户可见层。

### test-quality — WARN
* **WARN-T1｜gateway.rs:1675-1677**（新单测里最硬的一条断言）`assert!(!plan.candidate_ips.is_empty())`
  断言的是**主机有没有网卡**，不是代码对不对：M3（模拟 lo-only 机器）把它打红，
  而该状态恰是代码注释与 `no_routable_interface` 字段明确支持的合法状态
  ——同一个测试在 gateway.rs:1689 还读这个标志位，自己跟自己矛盾。
  在无路由网卡的环境（受限 netns/部分 CI 沙箱）里，**这条单测会在正确的代码上失败**。
* **WARN-T2｜gateway.rs:1611-1620** 兜底分支为存活变异（M4），新测试没覆盖自己引入的这条新代码路径。
* **WARN-T3｜gateway_e2e.rs:1337-1341** 把「网关启动时的网卡快照」与「测试体里第二次 getifaddrs 快照」做
  `assert_eq!(addrs.len(), iface_ips.len())` 精确相等比较；在容器/veth 频繁增删的机器上两次快照可以合法地不同。
  （注：我这次会话里看到的「wildcard e2e 时红时绿」**不是这条**，是我的实验装置污染，见 §4；
  插桩后的干净复跑里该测试是绿的，所以这条只按「潜在脆弱断言」记，不按实际失败记。）
* **WARN-T4**：没有任何测试覆盖 IPv6/`::` 路径（§2.1 的 14 条 link-local 是我临时插桩才测出来的）。
* 通过项（很重要）：新测试确实能证伪 —— M1/M2/M5 三种「改坏」分别打红新单测与新 e2e，
  而被删除的旧测试在特性坏掉时是绿的（§1 m0 实测）；e2e 用 `browser.peers[0].connected`
  （由 `Event::ChannelOpen`/ICE connected 置位，tests/common/mod.rs:361-371）做真连通断言，不是数日志；
  `host_candidate_addresses()` 以 `typ` 关键字定位地址字段，不依赖前导字段个数；
  测试没有依赖随机数/时钟（`drive_all(Duration::from_secs(5))` 是超时上限而非 sleep 断言）。

### complexity-control — PASS
`IceBindPlan` 通过 Deletion Test（删掉它会把 bind/candidate/page/warning 重新散回两处，正是缺陷成因）；
`create_session` 净删掉约 25 行重复枚举（gateway.rs:1596-1609）；无新 trait、无 async runtime。
两处鸡毛蒜皮不值得改：`no_routable_interface` 恒等于 `ifaces.is_empty()`（gateway.rs:105）、
`ifaces.clone()`（gateway.rs:108）只为绕过 page_ip 派生的 move。

### observability — WARN
* **WARN-O1**：补丁净删了启动期唯一一条「ICE 实际用哪个地址」的信息（旧 gateway.rs:341-353 的 `note:`），
  而新代码在健康路径上**一个字都不打印** —— 偏偏候选集合现在一生只算一次，出问题时最想查的正是它。
  这条信息也没有补进日志（只在异常时打 warning）。
* **WARN-O2**：告警仍走 `eprintln!`（gateway.rs:344）而非 MODULE.md:120-122 承诺的 `tracing`（既有风格，本补丁延续）；
  候选被拒（gateway.rs:1605）不带 session_id/node_id，无法 replay 定位。

---

## 4. 公开更正（我自己先前说过的错话）

1. **更正-1：「补丁后的树跑 e2e 仍有 13 条红」——错，是我的实验装置错。**
   第一次跑（`CARGO_TARGET_DIR=/work/nexus-dev/target`，任务指定值）打印 `Finished ... in 0.07s` 且
   跑了 `ice_advertises_multiple_host_candidates`（补丁已删除的测试名）——那是**别的目录留下的陈旧测试二进制**。
   我一开始把它读成「补丁没修好」，是错的。改用独立 target 目录 + `cargo clean -p` 后，被审补丁 **24 lib + 21 e2e 全绿**。
   副作用：`/work/nexus-dev/target` 被多个 workspace 共享时，同名包（`gateway_e2e-17c5ebd4967ae45c`）的
   fingerprint/dep-info 互相顶掉，跑出来的是别人编译的产物。**后续任何 Review 在同仓多副本做变异，必须
   每副本 `cargo clean -p <crate>` 或一副本一 target 目录。**
2. **更正-2：round 1–2 的 M1/M2/M3/M5 的 e2e 结论作废并重做。** 同一污染机制让
   m5/m3 的 rlib 被链进别的副本，导致 `wildcard_bound_…` 在所有变异里都报「answer advertised no host candidate」，
   一度看起来像「补丁本身有 bug」或「新 e2e 不稳定」。round 7（每步 clean 重建）给出的才是本文引用的最终数据。
3. **更正-3：「wildcard e2e 时好时坏是 flaky」——不成立。** 插桩显示 `Gateway::start listen=0.0.0.0 cands=9`
   且该次测试 PASS（§2.1）。失败全部来自陈旧产物。WARN-T3 只作为「理论上脆弱的断言」保留，不作为实测失败。
4. **更正-4：任务给的 contract_hash 参考值 `8de98ae1…` 与本树不符**，来源是 `/work/gateway-file-module` 的
   verify 案卷（不同工作树/不同 scenario 集）。本树 harness 实测 contract_hash = `9c44e935…`，与我独立复算一致，案卷采用实测值。
5. **更正-5：harness 报的 `working_tree_digest=bedf96bb…` 不是被审工件的 digest**（调用 harness 的 `cargo run`
   自己改了 `Cargo.lock`）。被审 E: 工作树的 digest 为 `2f1d4c3e…`，三处独立复算一致。

---

## 5. 阻塞项与非阻塞建议

**blocking_issues: 无。** 补丁修的是它声称要修的东西，可证伪、可复现、fmt/clippy/test 在
rustc 1.98.1 / x86_64-linux 上全绿，未违反 MODULE.md 任何一条 Invariant（G5/G6/G11 均通过），
未扩大 API 面或依赖面。按 SKILL.md，verdict 由最差维度决定：存在 WARN 无 FAIL ⇒ **COMMENTED**，
记录在案即可进入 `verify --full`。

非阻塞建议（8 条，已写入 summary.json 的 `non_blocking_suggestions`，前 3 条为我最想提的）：

1. 修 **WARN-T1**：把 gateway.rs:1675-1677 改成 `assert_eq!(plan.candidate_ips.is_empty(), plan.no_routable_interface)`
   ——既保住「不通告 0.0.0.0」的语义，又不会在 lo-only 主机上对正确的代码报假红。
2. 修 **WARN-C1/C2/C3**：把 USER_MANUAL.md:39-43 的 `note:`/旧 warning 段落删掉或改写为实际会打印的那一条，
   并把「网关只通告 socket 真能收包的地址」这一句同步进 MODULE.md:49-50 的依赖理由；
   这三处是本补丁自己引入的文档债，改起来是纯文本。
3. 就 **WARN-C5 + WARN-E1/E2** 做一次决定：要么每会话（或定时）重算 `ice_bind_plan`
   （getifaddrs 不在热路径，代价可忽略，同时顺手覆盖运行期网卡变化与枚举瞬态失败），
   要么把兜底抽成可测函数并补一条单测、同时在 MODULE/USER_MANUAL 里写明「网络变化需重启网关」。
   现状是「代码注释承认了冻结假设、契约与运维文档都没说、且该假设下最关键的兜底分支无人测」。

### 复现命令（Linux）

```bash
# 1. 整树搬运（保留 .git，HEAD=0576cb73），porcelain 与 Windows 完全一致
cd /e && tar -cf - nexus-fabric-g11 | gzip -1 \
  | ssh appen@10.144.144.4 'mkdir -p /work/nexus-dev/review-g11-qoder && tar -xzf - -C /work/nexus-dev/review-g11-qoder --strip-components=1'

# 2. 基线（务必一副本一 target 或每次 clean，否则会拿到陈旧产物）
cd /work/nexus-dev/review-g11-qoder
export CARGO_TARGET_DIR=/work/nexus-dev/target-g11-review
cargo clean -p nexus-web-gateway && cargo test -p nexus-web-gateway --offline --no-fail-fast   # 24 + 21 全绿

# 3. 变异（示例 M1：把 G11 的不变量改回旧行为）
cp -a /work/nexus-dev/review-g11-qoder /work/nexus-dev/g11-mut/m1 && cd /work/nexus-dev/g11-mut/m1
python3 - <<'PY'   # 注意：工作树是 CRLF，多行锚点必须用 universal-newlines 读
p='crates/nexus-web-gateway/src/gateway.rs'; s=open(p,encoding='utf-8').read()
o='candidate_ips: vec![listen_ip],'; assert s.count(o)==1
open(p,'w',encoding='utf-8',newline='\n').write(s.replace(o,'candidate_ips: routable_iface_ips(listen_ip),'))
PY
cargo clean -p nexus-web-gateway && cargo test -p nexus-web-gateway --offline --no-fail-fast   # lib 1 红 + e2e 14 红
```

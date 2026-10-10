# Code Intelligence —— 独立 Review 后续待办（round 3 判定 `COMMENTED`，0 阻塞）

来源案卷：`.evidence/review-qoder-independent-3088dfe/`（审查者 `qoder-independent-session-828e3f6b`，
第 3 轮 = AGENTS.md §19.1 的上限轮，无需第 4 轮）。
被验 revision：`3088dfe`（代码在 `95dc9ca`）；结论级 Linux 证据 `verify-qoder-xc-c9bc84e20690`。

本文件的作用是把待办**落到有承载体的地方**（round 2 我犯的错就是只写在提交说明里，
下一轮没有承载体）。逐条都带 `文件:行` 或明确的验收动作，便于后续按 Contract-First 单独开工。

## 优先四条（审查者建议先做，按依赖顺序）

1. **`gates.rs:404-411` affected 分析的 git 失败 fail-open**
   `git diff --name-only HEAD` 与 `porcelain()` 双双 `unwrap_or_default()` ⇒ git 失败时变更集为空 ⇒
   `affected-tests` 门输出 "no affected crates changed" 并 **PASS**。同一缺陷类刚在 `code_intel`
   侧被堵（`Repo::porcelain_result()` 现在已在手边），门侧还留着。
   验收：改用 `porcelain_result()`，git 失败时门输出 `UNKNOWN` 并写明原因；补一条失败注入测试。

2. **`env.rs:133` `dirty_state()` 的 `None` 分支零测试**
   结构性修复（`Option<bool>` + 序列化 `null`）已由审查者核对调用点，但 None 分支没有回归保护，
   且审查者也无法在不破坏 `.git` 的前提下触发它。
   验收：把 git 调用做成可注入（或在 `Repo` 上加一个 test-only 构造器），断言
   `dirty_state() == None` 时 `Bindings` 不产出 `false`。

3. **诊断条目形状补一条 E4**
   当前 deterministic 夹具里没有任何会产生诊断的文件 ⇒ 提案 §16.4 的结构化承诺只有代码 + 单测为证。
   做法：夹具内加一个稳定产生诊断的源文件（例如语法错误，或 `#[deny(...)]` 命中项）。
   ⚠️ 属**契约扩展**：新增夹具文件会改变 RA 对该 workspace 的分析面，必须先跑全部 15 个场景回归，
   再冻结新场景的期望（新 Red Evidence → 新场景 → 实现，不能反向）。

4. **`snapshot.workspace_root` 取消双含义**
   `mod.rs:98` 早期失败路径写 `"."`，`mod.rs:156` 成功路径写真实 scope —— 两个值语义不同却共用一个字段名，
   而 MODULE.md 的"字段可得性规则"没写这条。
   做法（择一）：早期失败**省略**该字段并在 MODULE.md 写明"未确定作用域时不出现"，
   或改成 `workspace_root` + `workspace_root_provisional` 两个显式字段。属契约面变更，要走 Contract-First。

## 其余八条

5. **symlink 越界形态跨宿主固化**：目前只有 xc-pc-linux 手工实测（`xc-verify.log:53-54`），审查者未在
   Windows 独立复现（无特权建符号链接）。做法：加 `#[cfg(unix)]` 的 E2 测试，用 `std::os::unix::fs::symlink`
   在 temp 目录里构造"workspace 内链接指向 workspace 外文件"，断言归一化判定拒绝。
6. **notification 溢出缺端到端断言**：`push_notification` 有单元测试，但没有"假 server 连发 >256 条 ⇒
   `provider.dropped_notifications` 入账并出现在 envelope"的端到端证据。可用 `LspSession::for_tests()` 扩展。
7. **容量口径要写进 MODULE.md**：256MiB 是"再序列化后的近似线上字节"，而 `serde_json::Value` 的堆占用
   通常数倍于此；审查者建议同时把上限降到 32–64MiB 量级。属契约数值变更（会影响超大 workspace 的行为）。
8. **`read_frame` 返回消耗字节数**，去掉 `dispatch_stream` 为统计体积对每条消息重复 `serde_json::to_string`
   的热路径成本（要动 `read_frame` 签名与 8 处测试调用点）。与第 7 条同源：改完上界才不再是近似值。
9. **崩溃/超时路径附带 stderr 尾部**：`stderr_tail` 目前唯一调用点是 `rust_analyzer.rs:118`（initialize 失败）。
   需先定截断长度与是否进 `provider` 字段 —— 契约扩展。
10. **`policies/quality.toml` 机器化声明"权威门禁宿主"**：现在只在 `DEVELOPMENT.md` §11.1 散文里。
    本轮刻意不改（Protected 路径，改 gate 语义需独立 Contract-First + 新 Red Evidence）。
    本文件即为"机器可见待办"的承载体。
11. **PR 合并顺序必须钉住**：`fix/apps-nexus-clippy-gates`（master + `0839d2e` + `179a435`）先合，
    特性分支再 rebase 掉那两笔；否则 §16.11 的 Linux 绿实际上依赖特性分支自带产品域改动，
    而产品认证代码的评审结论会被特性评审覆盖。审查者指出：现在的拆分只是"另开分支复制"，
    特性分支历史里仍在。
    该分支已在 xc-pc-linux 上**独立自证**（与特性分支无关，可在合入前单独评审）：
    分支内 `engineering/nexus-harness/src/code_intel` 文件数 = 0；diff 只有
    `apps/nexus/src/{n2_identity.rs,task_localapi.rs,task_provider_grant/audit.rs}` 共 10+/9−；
    `cargo clippy --workspace --all-targets -- -D warnings` exit 0；
    `cargo test -p nexus --lib` 192/0/2；`cargo test -p nexus-harness` **56/0**（master 基线，
    证明不依赖 Code Intelligence 也全绿）；`verify --fast --json` **overall PASS，9/9 门 PASS**，
    Evidence `verify-qoder-xc-7c926d27ccaa` @`179a435`，跑完工作树 0 行改动。
12. **Windows 侧两项结构性障碍**（产品域/平台待办，不属本模块契约）：`nexus-platform-linux` 无条件依赖
    `fuser`(libfuse)，`apps/nexus/examples/discovery_mdns.rs` 使用 Unix-only `std::os::fd`。
    后果：`verify --fast` 在 Windows 上结构性不可能通过，Windows 只能作冒烟宿主。
    标准解法：`fuser` 改 `cfg(target_os = "linux")` 门控；example 用 `[[example]] required-features`/`target` 门控。

## 仍未满足的流程项

- **模型绑定**：用户要求独立 Review 用 `qwen3.8-flash`，可用的独立执行者不接受 `model` 参数，
  故三轮案卷均记 `model=unknown`；会话独立性成立（非实现会话）。
- `verify --full`：round 3 判 `COMMENTED` 后按 `nexus-review` 语义可进入，正在 xc-pc-linux 上执行；
  结果追加到 `.agents/green-evidence-code-intelligence.txt`。
- 推送与 PR：用户至今未授权，`fix/windows-cfg-portability` 与 `fix/apps-nexus-clippy-gates` 都只在本地。

## 合并前置（推送时新发现，2026-10-10）

推送 PR #10 时发现 **`origin/master` 已从本分支基点 `8ba9fea` 前进 45 个提交到 `66b6b78`**，
其中与本工作重叠的部分：`apps/nexus/src/{lib.rs +467, main.rs +120, subnet_cli.rs +1241, mesh.rs, node_cli.rs}`、
`engineering/nexus-harness/{Cargo.toml +1, src/run_scenario.rs +118}`、`policies/{architecture.toml +6, dependencies.toml +102}`、
新增 `scenarios/product/bootstrap_join.toml`。因此：

- 产品域 PR #10 需要 rebase 到当前 master 后**重跑** `cargo clippy --workspace --all-targets -- -D warnings`
  与 `cargo test -p nexus --lib`（已在本 PR 里以评论承诺）。它改的三个文件不在 master 变更清单里，
  预计不冲突。
- 特性分支 `fix/windows-cfg-portability` 推之前**必须** rebase 到 `66b6b78`，重点处理
  `engineering/nexus-harness/Cargo.toml`（双方都改）与 `policies/*`（Protected 路径已变），
  rebase 后现有 Evidence（绑定 `3088dfe`）一律作废，需在 `66b6b78` 基线上重新产出 fast/full 与 15 场景。
- 另需补一次**纯 master 的 `verify --full` 对照**：本分支上 `verify --full` 唯一 FAIL 是
  `product-scenarios`（约 20 条 `product.n3-*` 自带 "master Red" 标注 + `daemon-workspace-mount`/
  `n1-connectivity-roam` 真设备语义）。目前的"与本模块无关"依据是文件归属与仓库自述，
  不是对照实验；补上对照才能把它从"判断"升级成"证明"。
- harness 可观测性缺陷（顺带发现，属本模块邻近范围）：`verify_id = hash(rev|configuration_digest|contract_hash)`
  不含 verification level，所以 `--fast` 与 `--full` 写进**同一个** `.evidence/verify-<id>/` 目录并互相覆盖，
  `--full` 的结果把 `--fast` 那份 gates 快照冲掉了。修法要么把 level 进 id，要么目录分层；属 Evidence 契约变更，
  走独立 Contract-First 周期。

## 合并前置（推送时新发现，2026-10-10）

推送 PR #10 时发现 **`origin/master` 已从本分支基点 `8ba9fea` 前进 45 个提交到 `66b6b78`**，
与本工作重叠的部分：`apps/nexus/src/{lib.rs +467, main.rs +120, subnet_cli.rs +1241, mesh.rs, node_cli.rs}`、
`engineering/nexus-harness/{Cargo.toml +1, src/run_scenario.rs +118}`、`policies/{architecture.toml +6, dependencies.toml +102}`、
新增 `scenarios/product/bootstrap_join.toml`。因此：

- 产品域 PR #10 需要 rebase 到当前 master 后**重跑** `cargo clippy --workspace --all-targets -- -D warnings`
  与 `cargo test -p nexus --lib`（已在本 PR 评论里承诺）。它改的三个文件不在 master 变更清单里，预计不冲突。
- 特性分支 `fix/windows-cfg-portability` 推之前**必须** rebase 到 `66b6b78`，重点处理
  `engineering/nexus-harness/Cargo.toml`（双方都改）与 `policies/*`（Protected 路径已变）；
  rebase 后现有 Evidence（绑定 `3088dfe`）一律作废，需在 `66b6b78` 基线上重新产出 fast/full 与 15 个场景。
- 需补一次**纯 master 的 `verify --full` 对照**：本分支上唯一 FAIL 是 `product-scenarios`
  （约 20 条 `product.n3-*` 自带 "master Red" 标注 + `daemon-workspace-mount` / `n1-connectivity-roam`
  真设备语义）。目前"与本模块无关"的依据是文件归属与仓库自述，不是对照实验。
- 顺带发现的 harness 缺陷：`verify_id = hash(rev|configuration_digest|contract_hash)` **不含 verification
  level** ⇒ `--fast` 与 `--full` 写进同一个 `.evidence/verify-<id>/` 并互相覆盖（本次 full 把 fast 的
  gates 快照冲掉了，目录名仍是 `verify-qoder-xc-c9bc84e20690`）。修法要么把 level 进 id，要么目录分层；
  属 Evidence 契约变更，走独立 Contract-First 周期。

# nexus-web-gateway 文件面配置接线 · 独立评审 r13

评审对象：`E:\nexus-fabric-m0`，分支 `feature/gateway-file-service-contracts`，提交
`290c6f4a7c4d36e53daf6143fff804eb0fccaf57`（父 `89b7047`）。
评审者未参与实现，不采信任何提交说明或案卷结论，一切自己跑。

**实际模型标识**：`qmodel_latest`（运行时给我的就是这一串；环境行原文 `Model: qmodel_latest`。
更细的底层型号我不知道，也不猜。）

## 0. 宿主与工具链（评审者自己的）

| | 值 |
|---|---|
| Windows 宿主 | `MINGW64_NT-10.0-19045 SH-YF-CX-PC`，Git Bash `3.4.10-2e2ef940.x86_64` |
| Windows rustc / cargo | `rustc 1.95.0 (59807616e 2026-04-14)` / `cargo 1.95.0 (f2d3ce0bd 2026-03-21)` |
| Windows git | `git version 2.46.0.windows.1` |
| Linux 门禁宿主 | `ssh appen@10.144.144.4` = `xc-pc-linux`，`Linux 5.15.0-139-generic #149~20.04.1-Ubuntu SMP Wed Apr 16 08:29:56 UTC 2025 x86_64` |
| Linux rustc / cargo | `rustc 1.98.1 (48a229cea 2026-09-01)` / `cargo 1.98.1 (797e8a9bc 2026-08-05)` |
| Linux git / python | `git version 2.25.1` / `python3 3.8.10`（**无 tomllib**，本轮用 `tomli`） |

Windows 侧**没有**用来编译 `nexus-web-gateway`（`ssh2 0.9.6` 的 `userauth_pubkey_memory` 被 cfg 门卡住，
这是既有事实，本轮未去推翻它）；Windows 只做读文件与 grep。**所有编译/测试/探针/TOML 证据都来自真机
Linux**，未使用 WSL 出任何结论。

隔离方式（自建，未复用他人树）：

```
git clone --no-hardlinks --branch m0-verify /work/m0-origin.git /work/r13-audit
# 每条 cargo 命令都带： CARGO_TARGET_DIR=/work/r13-target
```

克隆里的 `refs/heads/m0-verify = 290c6f4a7c4d...`，与被评审 HEAD 逐字相同（先核对再开跑）。
冷编译约 23 s（依赖已在共享 target 里预热过一轮）；长命令走 `nohup` + 日志轮询，
本轮遇到 0 次 `Connection closed`。

## 1. Q1：补上来的对象到底有没有杀伤 —— **有杀伤（但是标签型杀伤）**

### 1.1 复跑 MC07（实测）

配方：`crates/nexus-web-gateway/src/config.rs:493` 的 `self.validate()?;`（`file_engine()` 第一句）
改成 `if false { self.validate()?; }`。

| 阶段 | 命令 | 实际输出 |
|---|---|---|
| 基线 | `cargo test -p nexus-web-gateway --lib` | `running 83 tests` / `test result: ok. 83 passed; 0 failed` |
| 变异 | 同上 | `test result: FAILED. 82 passed; 1 failed`，失败项 `config::tests::an_inconsistent_enabled_table_cannot_launch_an_engine` |
| 基线 | `cargo run -q -p nexus-web-gateway --example gateway_file_contract -- --case config --json` | `"invalid_table_yields_no_engine":true`（19 个布尔全 true） |
| 变异 | 同上 | `"invalid_table_yields_no_engine":false`；`diff` 两份 JSON **只有 1 行不同**，其余 18 个布尔一个没动 |

⇒ 实现者声称的「0 红 0 翻转」被这条新对象**实测推翻**：1 条单测红 + 1 条期望翻转，且翻转是孤立的
（没有连带噪声）。单测在 `config.rs:692`，期望在 `scenarios/product/gateway_file_config.toml:119`。
跑完 `git checkout --` 还原，`git status --porcelain | wc -l` = 0。

### 1.2 反向问题：`files limits` 会不会被别的分支凑出来 —— **不会**

`grep -rn "files limits" crates/ scenarios/` 在 `src/` 下的**产生点只有 1 处**：

- `crates/nexus-web-gateway/src/config.rs:261` —— `format!("files limits: {e}")`，`FilesConfig::validate`
  委托 `FileLimits::validate` 的唯一包装。

`file_service.rs` 里这个标签出现 **0 次**，所以引擎原文不可能自带它；相邻两个包装点
`files.roots: `（`config.rs:501`）与 `file engine: `（`config.rs:505`）都不含该子串。
其余命中全是注释或断言（`config.rs:592/696/709`、探针 `:78/1708/1763`、`MODULE.md:123`、场景注释 `:116`）。
⇒ 「缝其实没检验时仍然绿」这条路被堵住了，层标签断言是**单义**的。

### 1.3 为什么只给「有杀伤」而不给「结实」：红是词法的，不是行为的（W-1）

`FileEngine::new` 自己在 `file_service.rs:1414` 调 `limits.validate()?`。于是删掉缝之后，
一张不合法的开启态表**仍然起不出引擎**——observable 的接受/拒绝没变，变的只有错误前缀
（`files limits:` → `file engine:`）。这条对象钉住的是「哪一层答的话」，钉不住「缝不存在会不会放行」。

缝真正不可替代的那半是 `config.rs:237` 的**配置层专属下界** `MIN_FILE_LOCKOUT_WINDOW_SECS`
（`config.rs:33` = 1；引擎层故意不设下界，见 `config.rs:231-233` 注释），而它**从未被从 `file_engine()`
这个入口跑过**：探针的 `sub_second_window_rejected_by_config` 直接调 `base_config(c).validate()`
（`gateway_file_contract.rs:1712`），新补的这条用的故障是 `chunk_bytes = 0`（引擎层也拒）。

建议（不改代码，只登记）：把 `invalid_table_yields_no_engine` 与同名单测的故障换成
`files.lockout_window_secs = 0`。那时删缝 ⇒ `SandboxRoot::open` 成功 ⇒ `FileEngine::new` 放行 ⇒
`Ok(Some(engine))` ⇒ 期望翻 false、单测走 `Ok(_) => panic!`。红就变成行为性的，且对错误串措辞免疫。
**这个变体本轮未跑，该建议部分不构成实测。**

### 1.4 顺手抓到的案卷形状问题（W-3）

探针 `main()`（`gateway_file_contract.rs:84-103`）**永远返回 `ExitCode::SUCCESS`**，
`dispatch()` 只要不 Err 就无条件塞 `"verdict":"PASS"`（`:125`）。变异跑里 `MUT_PROBE_EXIT=0`，
看着像「没杀伤」——本轮我自己就被这个形状误导过一次，靠 diff JSON 才发现翻转。
⇒ 凡引用探针做绿证，必须落**逐字段值 diff**，不能只落 verdict / 退出码。

## 2. Q2：现时态宣称与实现是否逐条对上 —— **对上，无 FAIL；一处措辞过界（W-2）**

### 2.1 「`Gateway::start` 还没消费 `file_engine()`」是**真**的（实测）

```
grep -rn "file_engine\|FileEngine" crates/nexus-web-gateway/src --include=*.rs | grep -v src/config.rs
```

命中全部落在 `file_service.rs`：结构体定义（`:1388`）、`impl`（`:1408`）与它**自己的**
`#[cfg(test)]` 夹具（`:2878` 起 40+ 处 `FileEngine::new`）。**`.file_engine()` 的调用点为 0**；
`gateway.rs:295 pub fn start(cfg: GatewayConfig)` 里没有。`http.rs`/`protocol.rs`/`mesh.rs` 无一命中。

三处新写的句子都**如实**挂着这半：`PRODUCT.md:3388`「仍未证的那半：`Gateway::start` 还没消费
`file_engine()`」；`MODULE.md:102-105`「**"拒启动"目前成立在构造缝上**」；`requirements.toml:121`
「**尚未证的那半**……M2 接线时必须补」。⇒ 没有出现「现时态宣称但其承载体不存在」，
**本条不报 FAIL**。

### 2.2 过界的那句：「唯一构造入口」没带限定词（W-2）

- `PRODUCT.md:3386`：「`GatewayConfig::file_engine()` 是唯一构造入口且关断时返回 `None`」
- `MODULE.md:101`：「`GatewayConfig::file_engine()` 是唯一构造入口——先 validate，关断时返回 `None`」
- `requirements.toml:121`：「`GatewayConfig::file_engine()` 是唯一构造入口，先 validate 再逐根 `SandboxRoot::open`」

而 `lib.rs:20` 是 `pub mod file_service;`，`file_service.rs:1409` 是 `pub fn new(limits, roots, token)`：
crate 外可以直接构造，绕过 `config.rs:237` 那条配置层下界。所以字面的「唯一」不成立，
也不 structural（没有 `pub(crate)`、没有 sealed trait）；它只在「唯一**从 GatewayConfig 出发**的
构造入口」这个读法下为真。该句的**承载体**（`config.rs:493→501→505` 的先 validate 再逐根 open 顺序）
是存在的，所以按 WARN 不按 FAIL。建议措辞：「配置面上唯一从 `GatewayConfig` 出发的构造入口」。

### 2.3 自报数字复核（N-2）

逐文件 `grep -c '^field = '`：auth_throttle 27 / capability_negotiation 7 / config 21 /
download_page 10 / list_pagination 6 / quota_backpressure 16 / sandbox_symlink 9 /
sftp_boundary 15 / upload_no_replace 5 / upload_resume 9 ⇒ **合计 125**，与 `PRODUCT.md` 的
`9+6+10+5+9+27+16+7+15+21 = 125` 一致；`gateway_file_config.toml` 的 21 与 REQ-014 的
「21 条期望，E4」一致（21 = 探针 19 个布尔 + `verdict` + `case`）。
`MODULE.md:106-115` 点名的 10 条单测**逐个存在**（`grep -c "fn <名字>()"` 全 = 1；
`config.rs` 总 `#[test]` 数 25，另 15 条不属本契约）。

**我没有**跑 harness 的 E4 逐字段对账（`verify --full` 的 `product-scenarios` 门）。我只做到：
还原后的树上 10 个 case 全部跑通，且 observed-false 布尔与场景 `equals = false` 的条数**逐一吻合**
（sftp 6/6、capability 4/4、auth 1/1、download 1/1、list 1/1、resume 1/1，config/quota/sandbox/no-replace
皆 0/0）。⇒ 「10 条场景跑绿」我**只复验了布尔子集**，其余部分不构成我的实测。

## 3. Q3：requirements.toml 缺陷的处置是否闭环 —— **闭环**

### 3.1 ① 修复前失败 / 修复后通过（Linux 上 tomli 实测）

父版从 `/work/m0-origin.git` 的 `git show 290c6f4^:crates/nexus-web-gateway/requirements.toml` 取出。

```
PARSE_FAIL parent 290c6f4^  TOMLDecodeError Expected newline or end of document after a statement (at line 89, column 577)
PARSE_OK   head   290c6f4   top_keys=['req']  n_req=14
```

行列与实现者声称的 **line 89 col 577 逐字吻合**。成因也可见：父版第 89 行是一条长度 1237 的 basic
string，col 550-640 处是 `...只数"四处"的旧写法已作废）...` ——内嵌的 ASCII 双引号提前终止了字符串。

### 3.2 ② 修复没有引入新问题（逐条扫）

- 修复后 14/14 条 `acceptance` 全是 literal string：`grep -c "^acceptance = '"` = 14，
  `grep -c 'acceptance = "'` = **0**（没有一条留在 basic string）。
- 解析后逐条扫正文：**没有任何一条 acceptance 含 `'` 或 `\`**
  （`ids_with_apostrophe_or_backslash = []`）。⇒ literal 语义与原 basic string 完全等价，
  既没丢转义，也不存在定界符撞车。
- 14 条全有 `acceptance` 键（`acceptance_missing = []`）；`REQ-014` 仍 `status = "doing"` / `P0`，
  没有被顺手改成 enforced。

### 3.3 ③ 「本地 9 道门」的成因陈述与 harness 源码一致（去源码数门，不信文档）

`verify --fast` 的门集 = `commands.rs:270` **硬塞**的 `whitespace_gate` + `config.declared_gates("fast")`；
后者读 JSON pointer `/verification/fast/gates`（`engineering/nexus-harness/src/config.rs:84-95`），
在 `policies/quality.toml:20-27` 声明 8 条：

```
format, check, clippy, architecture-delta, dependency-delta,
resource-type-neutrality, affected-tests, selected-properties
```

⇒ **1 + 8 = 9 道**，与「本地 9 道门」吻合。`[verification.full]`（`quality.toml:30-45`）14 条里也没有
requirements 校验。`grep -rn requirements engineering/nexus-harness/src/*.rs` = **0 命中**，
`.githooks/*.sh` 亦 0 命中。`validate-requirements` 的引用者只有
`.github/workflows/gateway-ci.yml`（`:25` job + `:38` 执行 `tools/validate-requirements.py`）与文档/工具。
⇒ 「requirements 校验不是本地一道门，只有 CI 校验」这句**成立**。

### 3.4 ④ 实现者没有在本片里偷偷改 harness（实测）

`git show --stat 290c6f4` 的 11 个文件里 `engineering/` 与 `.githooks/` **一个都没有**；
`git show --name-only 290c6f4 | grep -Ei "harness|gates|\.githooks"` ⇒ `NONE`。
建议以知识条目落档（同提交新增 `.agents/knowledge/entries/2026-10-14-requirements-toml-invisible-quote-and-ci-only-gate.md`，+56 行），
是待办而非顺手实现。

### 3.5 变异表的树号是个不可达 stash 对象（W-4）

REQ-014 与变异表写「MC01–MC13（13 条配方，**树 fa2f81d** 实测全数有杀伤）」：

```
git log -1 fa2f81d          → fa2f81d WIP on feature/gateway-file-service-contracts: 89b7047 ...
git merge-base --is-ancestor fa2f81d HEAD → 非祖先
git rev-list --count fa2f81d..HEAD        → 2
（全新克隆 /work/r13-audit 内）
git cat-file -t fa2f81d     → commit        ← 对象今天还在
git for-each-ref            → 只有 refs/heads/m0-verify, refs/remotes/origin/m0, refs/remotes/origin/m0-verify
```

⇒ `fa2f81d` 是 **stash 提交**；可达性补测（决定性）：在克隆与 bare origin 上
`git for-each-ref --contains fa2f81d` **双双返回空**，且
`git merge-base --is-ancestor fa2f81d refs/remotes/origin/m0` rc=1 ⇒ 它确实不被任何 ref 包含，
只是裸仓库里残留的对象，一次 `git gc --prune=now` 就让「MC01–MC13 全数有杀伤」永久失去可复现载体。
另外它的基座是 `89b7047`（= 被评审提交的**父**提交），也就是「全数有杀伤」是在改动尚未落成提交之前量的。
建议：在当前提交树上重跑整张表并把树号换成提交号（或给 stash 打一个可达 ref）。
**我只复跑了 MC07 一条，其余 12 条未复跑，本条不构成对「全数」的验证。**

### 3.6 评审期间通道 ref 动过一次（N-7，实测；不影响结论）

克隆时我在脚本里打过 `REF check`：`refs/heads/m0-verify` = `290c6f4a7c4d…`，与 Windows HEAD 逐字相同。
评审末段再查 bare origin ⇒ 通道已推进到 `d71e007 docs(gateway): 把第十二片的复验数字锚回落地提交 290c6f4`
（提交时间 09:50:43，就在我的克隆前后），`290c6f4` 是其祖先，且
`git diff --stat 290c6f4..refs/heads/m0-verify` = **只有 `.agents/green-evidence-…txt` +22 行**
（代码、探针、场景、契约零改动）。我的 `/work/r13-audit` 全程停在 `290c6f4`，所以下面的印证是独立的：

那条新日志自报 `cargo test --lib 83 passed; 0 failed` 与 `verify --fast 9 门全 PASS`，
与我**自己**量到的基线（83 passed; 0 failed）和 9 道门（whitespace + 8 declared）**吻合**——
这是相互印证，不是我继承它的数字。但它**没有动 `requirements.toml`**，也就**没有**重跑变异表，
所以 W-4 仍然成立。

## 4. 结论

**verdict = COMMENTED**（无 FAIL）。

- Q1：**有杀伤**——MC07 实测 1 条单测红 + `invalid_table_yields_no_engine` 期望翻转，且翻转孤立；
  层标签在 `src/` 下唯一产生点 `config.rs:261`，凑不出来。但这条杀伤是**词法**的（W-1：`FileEngine::new`
  自己复检 limits），缝唯一的价值（配置层专属下界）没有对象从缝跑过。
- Q2：三处新写的现时态句子与实现逐条对上，「`Gateway::start` 还没消费 `file_engine()`」实测为真
  （零调用点），且三处都如实挂着这半 —— 没有「宣称有、承载体没有」，**不报 FAIL**。
  唯一过界是「唯一构造入口」缺限定词（W-2）。
- Q3：**闭环**——①line 89 col 577 修复前后实测对比成立；②14/14 转 literal string 且无一条含 `'`/`\`，无损；
  ③9 道门 = whitespace + 8 条 declared fast，无 requirements 门，成因陈述与 harness 源码一致；
  ④harness 未被改动，建议登记为待办。

FAIL 0 条 / WARN 4 条（W-1 词法杀伤、W-2「唯一」措辞、W-3 探针 PASS 无含义、W-4 变异表树号不可达）/
NOTE 7 条（N-1…N-7，其中 N-7 是评审期间 `m0-verify` 通道 ref 动过一次，已核实与我评审的树无关）。

未跑成（明确不作证据）：MC01–MC06、MC08–MC13 共 12 条配方；workspace 级 9 道门整体；
harness 的 E4 逐字段对账；Windows 侧编译该 crate（本就编不动，也未尝试、未出结论）。

## 5. 工作树卫生

评审全程只读业务代码/场景/文档；写入仅限 `.evidence/review-gateway-file-r13/`（本文件 +
`review.json` + `summary.json`）。Linux 克隆变异后已 `git checkout --` 还原（`status --porcelain` 行数 0）。

复现用的两份脚本留在 Linux 侧：`/work/r13-mutate.py`（施加 MC07 的两种变体）、
`/work/r13c.py`（10 case 跑 + 场景对账 + requirements 扫描）；日志
`/work/r13-log`、`/work/r13-baseline-lib.log`、`/work/r13-mut-lib.log`、
`/work/r13-probe-base.json`、`/work/r13-mut-probe.json`、`/work/r13-req-parent.toml`、
`/work/r13-stage.log`。

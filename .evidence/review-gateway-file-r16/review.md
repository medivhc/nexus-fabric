# 独立评审 r16 —— `41fe3c5`（代码+契约）/ `4ffe8db`（案卷）

**verdict：COMMENTED**（0 FAIL / 2 WARN / 4 NOTE）

## 0. 本卷的宿主、工具链与树来源（自证）

| 侧 | 实测 |
|---|---|
| 本地（读码） | Windows 11 / win32 + Git Bash，工作树 `E:/nexus-fabric-m0`，`git branch --show-current` = `feature/gateway-file-service-contracts`。本轮**只**在 `.evidence/review-gateway-file-r16/` 下写文件，业务码/场景/文档一字未动。 |
| 门禁（编译/跑测试） | 真 Linux 机 `ssh appen@10.144.144.4`（**不是 WSL**，同机 WSL 一律不作结论来源）。`rustc 1.98.1 (48a229cea 2026-09-01)` / `cargo 1.98.1 (797e8a9bc 2026-08-05)` / `git version 2.25.1` / `Python 3.8.10`。 |
| 树 | **本评审者自己从零建**：`git clone --no-hardlinks --branch m0-verify /work/m0-origin.git /work/r16-audit` → HEAD `4ffe8db09bf43b9d259f68ef89907f2584526b2a`，`git status --porcelain | wc -l` = 0。没有复用 `/work/r15-audit`、`/work/mm7`。 |
| target | `CARGO_TARGET_DIR=/work/r16-target`（隔离，冷编译后台跑，日志 `/work/r16-bootstrap.log`，`Finished test profile in 23.62s`）。 |
| cargo 怎么执行 | 一律 `ssh appen@10.144.144.4` → `cd /work/r16-audit && CARGO_TARGET_DIR=/work/r16-target cargo …`；变异表用 `nohup … python3 /work/r16-harness-r16.py > /work/r16-mut.log` 后台跑再轮询，不前台挂 ssh。 |
| 配方 | `/work/r16-harness-r16.py` = 入库脚本 `crates/nexus-web-gateway/tools/mutation-gateway-file-config.py` 的**副本**（原文件未改），尾部追加本评审者自己设计的 MC23/MC24/MC25，并把 RECIPES 过滤成 `MC01, MC21, MC22, MC23, MC24, MC25`。打印 `anchor precheck ok: 6 recipes`，跑完 `MC99_restored` 与 baseline 逐字节一致（脚本自带 restore 断言）。 |
| 判据 | 红单测名单 + 逐字段 JSON diff。**不用**探针退码，也不用 harness 的 "PASS" 字样（r13 W-3）。 |
| 实际模型标识 | `qfmodel`（运行时给什么写什么，不猜不编）。 |

---

## 1. Q1 —— ③"边界值可用"在下界那一侧补得够不够

### 1.1 我自己设计的三条下界配方（实现者没有这两条），实测**都杀得掉**

| 配方 | 改动（`file:line`） | 实测结果 |
|---|---|---|
| **MC23_r16_window_floor_ge** | `src/config.rs:237` `if self.lockout_window_secs < MIN_FILE_LOCKOUT_WINDOW_SECS` → `<=`（把合法值 1 一起误杀） | **1 红** `config::tests::sub_second_window_is_rejected_at_the_config_layer`；probe config：`frozen=27 flips=1 missing=25`，`FLIP verdict want="PASS" got="FAIL"` |
| **MC24_r16_idle_floor_ge** | `src/config.rs:247` `if self.idle_timeout_secs < 1` → `<= 1` | **0 红**（`lib: test result: ok. 86 passed; 0 failed`）；probe config：`frozen=27 flips=1 missing=0`，`FLIP idle_floor_rejected_by_config_layer want=true got=false` |
| **MC25_r16_engine_floor_1s** | `src/file_service.rs:193` `if self.lockout_window.is_zero()` → `< Duration::from_secs(1)`（引擎那条收紧到"至少 1 秒"） | **3 红** `file_service::tests::expired_locks_are_reclaimed_instead_of_escalating_to_the_global_window` / `lockout_rearms_after_expiry_and_flood_arms_are_not_exempt` / `lockout_requires_failures_inside_one_window`；probe auth-throttle：`flips=1 missing=25`，`FLIP verdict want="PASS" got="FAIL"` |

**结论（Q1 前半）：下界那一侧不是"根本没对象"，不构成 FAIL。** 两种"把合法边界值一起误杀"的写法都被抓住，抓住方式与上界那一族同形（off-by-one → 某格 true→false）。

但**形状与上界不对称**，这条判 **W-1**（见 §1.2）。

### 1.2 W-1（WARN）：下界的"边界可用"是**并进已有格**的，于是 idle 那半既没有单测、翻掉的那格名字又说反话

- 被并进去的位置：
  - `crates/nexus-web-gateway/examples/gateway_file_contract.rs:1731` `let floor_is_usable = base_config(on_files.clone()).validate().is_ok();`（`on_files.lockout_window_secs` 在 `:1726` 就设成 `MIN_FILE_LOCKOUT_WINDOW_SECS`，所以这格确实测的是边界值本身，实现者那句主张**在这半成立**）→ 并入 `:1740-1743` 的合取 `json!(rejected_sub_second && floor_is_usable)`，落到冻结期望 `sub_second_window_rejected_by_config`（`scenarios/product/gateway_file_config.toml:93`）。
  - `crates/nexus-web-gateway/examples/gateway_file_contract.rs:1758-1764` `idle_floor_is_usable`（`idle_timeout_secs = 1`）→ 并入 `:1769-1772` 合取，落到 `idle_floor_rejected_by_config_layer`（`scenarios/product/gateway_file_config.toml:108`）。
- 实测暴露的两处缺口：
  1. **idle 下界没有任何单测承载体**：MC24 下 `--lib` 是 `86 passed; 0 failed`。上界那一族有 `src/config.rs:603-604`、`:781-783` 两处"边界本身必须可用"断言 + `:786` 专门那条 `both_duration_ceilings_leave_the_boundary_value_usable`；下界只有 idle 缺，窗口那半靠 `config.rs:604` 兜着（MC23 因此红）。
  2. **翻掉的那格名字会误导复读者**：MC24 的证据行是 `FLIP idle_floor_rejected_by_config_layer want=true got=false`。字面读起来是"这条下界不再生效"，实际发生的却是"这条下界**过严**、把合法值 1 误杀"。一格同时携带"拒得对"与"边界可用"两个命题（正是 r12 那一族"一格两件事"的形状，只是这次打在命名层）。上界既然为此**新加了两个专用格**（`window_ceiling_boundary_is_usable` / `idle_ceiling_boundary_is_usable`，`gateway_file_contract.rs:1792-1799`），下界却没有对称的两格。
  3. 附带：MC23 的 field 层证据**不是**"翻自己那一格"，而是 `missing=25` + `verdict` 翻 FAIL（夹具在更早的 `validate()` 处就起不来，27 个 field 根本没被报出来）。所以案卷里"这 25 个每一个都至少被一条配方以'翻自己那一格'的方式打过"这句，对**下界的边界可用**这一族是**打折扣的**：MC23 打中的是红名单+整体状态，不是那格。
- **ask（不改判定，只补形状）**：加 `window_floor_boundary_is_usable` / `idle_floor_boundary_is_usable` 两格（或至少给 idle 补一条 `validate().is_ok() at 1` 的单测，对称 `config.rs:603-604` 的写法），并给这两格各配一条配方（MC23/MC24 现成可用）。

### 1.3 W-2（WARN）："两层判定集合相同、删任一侧不改判定"这句**在下界那对写过界**，该限定

这句话有 6 处，我逐处看了上下文口径：

| 位置 | 口径 | 判定 |
|---|---|---|
| `crates/nexus-web-gateway/src/config.rs:788`（`both_duration_ceilings_leave_the_boundary_value_usable` 注释内） | 只说"上界"这一对 | **精确**（两层都是 `> 24h`，`config.rs:242/252` vs `file_service.rs:216/222`，同集合） |
| `crates/nexus-web-gateway/MODULE.md:180` | 主语是"24 h 这条**两层各写一次**" | **精确** |
| `scenarios/product/gateway_file_config.toml:116` | 紧跟在 `:119/:123` 两条 `*_ceiling_boundary_is_usable` 之前 | **精确**（ceiling-scoped） |
| `gateway_file_contract.rs:1780`（6c 段） | "上界写成 `>=`" | **精确** |
| **`crates/nexus-web-gateway/MODULE.md:122`** | 段落主语是**"窗口的两条界"**（`:120`），随后写"因为两层的判定集合相同，删任一侧都不改变'拒什么值'" | **过界**：窗口下界那一对是 `config.rs:237 < 1`（`u64` 秒）vs `file_service.rs:193 is_zero()`（`Duration`），**不是同一个集合** |
| **`crates/nexus-web-gateway/examples/gateway_file_contract.rs:1716`** | 块标题 `:1712` 是"6) 窗口**两侧界**"，块内含下界那格（`:1742`），随后写"配置层与引擎层这两道界的判定集合相同，删掉任一侧都还是拒" | **同样过界** |

- 我的实测怎么支持这个判法：**MC25** 把引擎那条从 `is_zero()` 收紧成 `< 1s`，`--lib` 立刻 3 条红 + auth-throttle 整体状态翻 FAIL —— 说明引擎侧的下界**在引擎自己的定义域（毫秒）里是一条真正在起作用的规则**，两侧在那域内不可互换。反过来，MC01（删配置层那条 `< MIN`）在实现者与我两棵树上都是 1 红 + `sub_second_window_rejected_by_config` 翻 false，而"0 秒仍然被拒"（引擎 `is_zero()` 兜着），所以**"删任一侧不改判定"只在"配置层能表达的定义域 = 整秒"内成立**。
- 该不该限定：**该**，且是两行文字的事，不动设计。`src/config.rs:585-586` 已经把真实原因写清了（"引擎层故意没有下界（时间夹具要毫秒窗口），配置层必须有"），只是 `MODULE.md:122` 与 `gateway_file_contract.rs:1716` 那两句没把范围接上。建议写法："24h 这一对两层同集合；下界这一对**在配置层能表达的整秒定义域内**同集合，引擎那条是 `is_zero()`，毫秒窗口引擎照收（`file_service.rs:193`）——所以引擎下界不是配置下界的副本，删它会红 3 条时间夹具单测。"
- 不给 FAIL 的理由：两处过界的句子**都不是**在主张可观测的行为差异（①可诊断性那一半它自己已降级成"R15A 能骗过的只有这一件"），限定之后宣称仍然成立；且残差已登记在案卷 `#39`（要拿结构承载体 `ConfigBound{knob}` 才能真正钉层身份）。

---

## 2. Q2 —— 复算材料与可达性（第三方口径）

### ① 可达性（不是"对象存在"）

```
$ cd /work/r16-audit && git branch --contains 41fe3c5 ; git branch --contains 4ffe8db
* m0-verify
* m0-verify
$ git --git-dir=/work/m0-origin.git for-each-ref --contains 41fe3c5 --format='%(refname)'
refs/heads/m0-verify
$ git --git-dir=/work/m0-origin.git for-each-ref --contains 4ffe8db --format='%(refname)'
refs/heads/m0-verify
```
两个提交都**可达**于活动 ref `m0-verify`。`4ffe8db` 同时是该 ref 的 tip（我的 clone HEAD）。

### ② 我自己树里跑出来的日志 vs 入库日志（逐行对答案）

跑法：`cd /work/r16-audit && CARGO_TARGET_DIR=/work/r16-target python3 /work/r16-harness-r16.py`，日志 `/work/r16-mut.log`。比对脚本把 `finished in X.XXs` 归一化后逐行等值比较：

```
IDENTICAL MC00_baseline                     4 行 / 4 行
IDENTICAL MC01_window_floor_off             7 / 7
IDENTICAL MC21_window_ceiling_off_by_one    7 / 7
IDENTICAL MC22_idle_ceiling_off_by_one      8 / 8
IDENTICAL MC99_restored                     4 / 4
```
关键行（我这棵，非引用实现者）：baseline `ok. 86 passed; 0 failed`、`probe config : frozen=27 flips=0 missing=0`；MC21 → 1 红 `both_duration_ceilings_leave_the_boundary_value_usable` + `FLIP window_ceiling_boundary_is_usable want=true got=false`；MC22 → 2 红（多 `idle_time_bounds_are_rejected_at_the_config_layer`）+ `FLIP idle_ceiling_boundary_is_usable`。**入库日志的 MC00/MC01/MC21/MC22/MC99 五段可第三方复现，无出入。**

**未跑成（不构成证据）**：我没有重跑全部 22 条（预算），只跑了 baseline + 上述 5 条 + 我自己的 3 条。其余 16 条（MC02–MC20）的逐行结果本轮**不背书也不质疑**。

### ③ 只靠仓库文件重算覆盖率

```
$ grep -c '^field = ' scenarios/product/gateway_file_config.toml        → 27
$ grep -c 'equals = true' scenarios/product/gateway_file_config.toml    → 25
非布尔 equals 的 field = ['verdict', 'case']            # 剔除理由可自证
入库日志里出现的不同 FLIP 字段名 = 25
25 条断言里从未被任何配方翻过的 = 0（空集）
FLIP 名单里不属于场景的字段 = 0
```
- "27 field / 25 断言 / `verdict`+`case` 剔除"这句**自证成立**，第三方只靠仓库就能算出来。
- "25 条每一个都至少被一条配方以翻自己那一格的方式打过"这句在**入库日志内部**也自证成立（25 个不同字段名 = 25 条断言，交集完整）。但按 §1.2 第 3 点，这句的**外延**有个实现者没写的边界：MC23 这类"改严"的杀伤是 `missing=25 + verdict 翻`，不是"翻自己那一格"；也就是说这句只覆盖**入库那 22 条**，不是"任何下界改法都能翻到格"。判 NOTE-2，不判 WARN（口径没被写反，只是没穷尽）。
- 截断死角（NOTE-3）：`run()` 打印用 `reds[:14]` / `fl[:14]`（`tools/mutation-gateway-file-config.py` 尾部）。我在入库日志里查了所有 `frozen=… flips=N missing=M` 行：**没有一行 N>14，也没有一行 M>0**，所以本轮日志**没有**被截断藏掉的格；这句"只能信我"的死角目前不存在。潜在脆弱性保留：MC19/MC20 那类一改全红的配方若翻到 15 格以上，日志会静默截断，建议改成全量打印或打印 `…(+K more)`。

### ④ 四个计数

| 声明 | 我的复现命令 | 实测 | 结论 |
|---|---|---|---|
| `--lib` 86 | 我这棵 baseline（§2②） | `test result: ok. 86 passed; 0 failed` | ✓ |
| config 场景 27 条 | `grep -c '^field = ' scenarios/product/gateway_file_config.toml` | 27 | ✓ |
| E4 合计 131 = 104 + 27（`.agents/green-evidence-gateway-file-service-m1.txt:1922`） | `for f in scenarios/product/gateway_file_*.toml; do echo "$(grep -c '^field = ' $f) $f"; done` | auth-throttle 27 + capability 7 + download 10 + pagination 6 + quota 16 + symlink 9 + sftp 15 + upload_no_replace 5 + resume 9 = **104**；`gateway_file_config` = **27**；`gateway_file_resource_accounting` = 11 **被正确排除**（第十三片契约先行，仍 RED） | ✓ 完全可由仓库文件重算，加法自洽（104+27=131） |
| FILE_MANIFEST 声明 225 = 表内实数 | `grep '^| ' FILE_MANIFEST.md \| wc -l` = 226，其中表头 `| Path | Purpose |`（`:111`）1 行 → **225**；`grep '^| ' \| grep -v '^| Path' \| awk -F'\|' '{print $2}' \| tr -d '` ' \| sort -u \| wc -l` = 225 | 225 | ✓ 无漂移 |
| （顺手多核一层）225 行是否都真存在 | `comm -23 <manifest 路径> <git ls-files>` | **恰好 2 行不在索引**：`.evidence/.gitignore`、`.evidence/README.md`；`ls` 实测磁盘上也不存在 | NOTE-4：这 2 行 `FILE_MANIFEST.md:75-79` **已自己写明**是基线遗留（`5694faa` 取消跟踪），"按表内行数比按 `git ls-files` 多 2"，如实标注没静默改数。披露与我的实测**数字相符**，不立案。 |

---

## 3. NOTE 汇总

- **N-1**：③ 拆成三件的写法本身站得住。`MC21/MC22` 与两格 `*_ceiling_boundary_is_usable` 在**评审者的树、评审者的 target** 上复现（§2② IDENTICAL），实现者这一件是补对了的——r15 的 R15B 形状（"越界要拒"那几格对 off-by-one 是盲的）确实被闭合。
- **N-2**：见 §2③ 第 2 点——"翻自己那一格"这句的外延应加半句限定（改严类杀伤走 `missing`+整体状态）。
- **N-3**：harness 的 `[:14]` 截断本轮未咬到（实测无 `flips>14`、无 `missing>0`），属潜在脆弱性。
- **N-4**：FILE_MANIFEST 的 2 个幽灵行已由 `FILE_MANIFEST.md:75-79` 自行披露，与本评审者实测一致（多出正好 2）。

## 4. 本轮没做/不背书的

- 没重跑 22 条全表（只跑 baseline + MC01/MC21/MC22 + 自设 MC23/MC24/MC25）。
- 没重跑 clippy、`verify --fast` 9 门、`contract_hash 21a1554a…`、`working_tree_digest`——本轮判据只用"红单测名单 + 逐字段 JSON diff"，这些数字本轮**不背书也不质疑**。
- 没有以任何 WSL 结果作 Linux 门禁结论。
- Windows 侧不能编译该 crate（`src/ssh_client.rs` 的 ssh2 cfg 门），故所有编译/测试证据均来自 `appen@10.144.144.4`。
- 工作树卫生：`git status --porcelain` 除 `.evidence/review-gateway-file-r16/` 外必须为 0（本卷最后一节命令已核）。

# nexus-fabric 第十二片再续 · 独立评审 r15

评审时间：2026-10-14。被评提交：`8b07af8`（test）+ `c88f15d`（docs），通道 `ssh://appen@10.144.144.4/work/m0-origin.git` 的 `m0-verify` = `c88f15d`。

## 0. 本卷的宿主与工具链（自己声明，便于别人复算我的复算）

| 侧 | 用途 | 版本 |
|---|---|---|
| Windows（本机 `E:\nexus-fabric-m0`） | 只读代码与案卷、写本卷；**不产出任何编译/测试结论** | `rustc 1.95.0 (59807616e 2026-04-14)` / `cargo 1.95.0 (f2d3ce0bd 2026-03-21)` / `git version 2.46.0.windows.1`；python 只有商店占位符，不可用 |
| Linux `ssh appen@10.144.144.4`（xc-pc-linux，x86_64-unknown-linux-gnu） | 唯一的编译/测试/变异证据来源；**没有用同机 WSL** | `rustc 1.98.1 (48a229cea 2026-09-01)` / `cargo 1.98.1 (797e8a9bc 2026-08-05)` / `git version 2.25.1` / `Python 3.8.10`（有 `tomli`、无 `tomllib`） |

cargo 一律 `CARGO_TARGET_DIR=/work/r15-target`。**树是我自己从零建的**：

```
git clone --no-hardlinks --branch m0-verify /work/m0-origin.git /work/r15-audit
# HEAD = c88f15d，跑前 `git status --porcelain | wc -l` = 0
```

没有用 `/work/r14-audit`，没有用 `/work/mm7`，没有用实现者的任何目录（除了只读地 clone 那个 origin）。

**实际模型标识**：运行时给我的标识是 `qfmodel`，照抄，不猜不编。

判据口径按本链规矩执行：杀伤只看**红单测名单 + 逐字段 JSON diff**；探针退码与 harness 的 `PASS` 字样一律不算证据（r13 W-3）。

## 1. verdict

**COMMENTED**：0 FAIL / 1 WARN / 4 NOTE。
两笔提交里我**没有找到站不住的数字**（第 3 节逐条实测）。唯一的 WARN 是 Q2 打出来的：新补的层标签对象在**复合变异**下仍可存活——层标签的钉法还是词法的，这是本链第三次抓同一形状，只是这次要两处同改才能打中，所以降级为 WARN 而不是 FAIL。

## 2. Q1「第三方可重算」这句现在是不是真的 —— 答：**是，三件事全部实测通过**

### ① 入库脚本能不能在我自己的克隆里原样跑起来：**能**

```
cd /work/r15-audit && CARGO_TARGET_DIR=/work/r15-target timeout 620 \
  python3 crates/nexus-web-gateway/tools/mutation-gateway-file-config.py
```

实际输出（`/work/r15-orig.log`，我的树 `c88f15d`）：

```
anchor precheck ok: 20 recipes
=== MC00_baseline  [baseline] ===
  lib: test result: ok. 85 passed; 0 failed; ... finished in 1.20s
  red tests (0):
  probe config       : frozen=25 flips=0 missing=0
  probe auth-throttle: frozen=27 flips=0 missing=0
=== MC01_window_floor_off  [MUTATED] ===
  lib: test result: FAILED. 84 passed; 1 failed; ...
  red tests (1):
    config::tests::sub_second_window_is_rejected_at_the_config_layer
  probe config       : frozen=25 flips=1 missing=0
    FLIP sub_second_window_rejected_by_config         want=true   got=false
  probe auth-throttle: frozen=27 flips=0 missing=0
=== MC02_window_ceiling_off  [MUTATED] ===
  ...（同样与入库日志逐字一致）
```

- 脚本头部的跑法（clone 命令 + `CARGO_TARGET_DIR` + 相对路径 + "隔离 target" 警告）**够用**，我照抄就跑起来了，没有补任何它没写的步骤。
- 20 条 anchor 预检全过（`anchor precheck ok: 20 recipes`，与入库日志第 22 行逐字一致）——`c88f15d` 相对 `8b07af8` 只动文档，anchor 没有被自己的文档提交打断。
- **它跑完了整张表**：我原以为会被 `timeout 620` 截在 MC02/MC03（第一次轮询时确实只看到 3 行），最后一次查 `/work/r15-orig.log` 是 **22 行 = baseline + MC01–MC20 + MC99_restored**，末尾是还原后的 `85 passed / flips=0`。
- **逐行对答案（`python3 /work/r15-diff.py`，比较入库日志与我的重放）**：

```
committed rows: 22  my rows: 22
tags only in committed: []
tags only in mine: []
MISMATCH rows: []
common rows identical: 22
```

  比较的是每行的 `test result` 词（ok/FAILED）、红单测名单、`FLIP` field 名单、`missing` 计数——**22 行全等**。也就是说第三方只靠仓库（脚本 + 场景）在我的树、我的 target、我的 rustc 上重算，得到的整张表与实现者入库的那张**逐行一致**；不只是 MC20/MC07 三条样本。
- 顺带一条可复现性提醒（**不立案**，因为脚本自己就要求一次性克隆）：跑的过程中树必然是脏的（我在中途读到 `git status --porcelain` = 1，那是 harness 正把变异写在 `config.rs` 上，属设计如此）；我这棵树跑到 `finally` 边界后被 timeout 收掉，收尾实测 0。若在中途被硬杀，变异会留在树上，重算者按脚本头部用隔离克隆即可，跑完 `git checkout -- .`。

### ② 只靠入库日志能不能重算出"25 个 field 里 23 个是断言、这 23 个每条都至少被一行翻过"：**能**

命令（在我的克隆里，脚本 `python3 /work/r15-recompute.py`，只用两个文件：`.agents/mutation-log-gateway-file-config.txt` + `scenarios/product/gateway_file_config.toml`）：

```
config fields with equals: 25
non-bool equals: [('verdict', '"PASS"'), ('case', '"config"')]
flip lines: 35 distinct names: 23
flip names NOT in scenario: []
scenario fields never flipped: ['verdict', 'case']
rows: 23 zero-kill recipes: ['MM']
```

读法：
- field 定义**不缺**：`frozen()` 需要的 `field =` / `equals` 就在场景里，25 个，日志里 `frozen=25` 与之吻合。
- `verdict` / `case` 的归类**不是只靠日志头部的一句话**：这两个正是 `equals` 值非布尔的字段（`"PASS"`、`"config"`），第三方可以从场景文件自己推出来，日志第 15–17 行的说明只是把这个口径写明。所以"23 个是断言"可重算。
- 23 个不同翻转名单**全部**能在场景里找到同名 field（`flip names NOT in scenario: []`），且除 `verdict`/`case` 外**没有任何 field 一次都没翻**（`scenario fields never flipped` 只剩那两个）→ "这 23 条每条至少被一行翻过"**成立**。
- `zero-kill recipes: ['MM']` 是我解析器把最后一行 `=== MM RUN DONE ===` 当成了一行，不是案卷的问题；按"红名单 + 逐字段 diff"数，20 条配方行没有一行是零杀伤 → 入库日志的"20 条配方没有一条是零杀伤"**成立**。

结论：**"第三方可重算"这句现在是直的**（脚本 + 原始输出 + 场景定义三件都在库里，缺一样都不行）。

### ③ 复跑 2–3 条与入库日志对答案：**三条全对，0 处不一致**

我用自己的驱动（`/work/r15-mut.py`，函数是从入库脚本复制的，但配方与步长是我选的）在 `/work/r15-audit`（`c88f15d`）跑：

| 配方 | 入库日志（`8b07af8`） | 我的实测（`c88f15d`） | 一致 |
|---|---|---|---|
| MC19 | 1 红 `idle_time_bounds_are_rejected_at_the_config_layer`；1 翻 `idle_floor_rejected_by_config_layer` | 同 | ✓ |
| **MC20** | 1 红 `idle_time_bounds_...`；1 翻 `idle_ceiling_rejected_by_config_layer` | 同 | ✓ |
| **MC07** | 2 红 `an_inconsistent_enabled_table_cannot_launch_an_engine` / `blank_credential_and_alias_are_refused_at_the_construction_seam`；3 翻 `invalid_table_yields_no_engine` / `blank_token_yields_no_engine` / `blank_alias_yields_no_engine` | 逐字同 | ✓ |
| baseline / restored | 85 passed 0 failed，`frozen=25/27 flips=0` | 同 | ✓ |

MC20 就是 r14 自己设计的 NEW20 等价物，在**评审者的树、评审者的 target**上仍然是 1 红 1 翻，不是我信实现者的话。

## 3. 计数滚齐的复核（怕"新错话"，逐条自己数）

| 声明 | 我的实测 | 结论 |
|---|---|---|
| 场景 `product.gateway-file-config` 25 条期望 | `grep -c "^field = " scenarios/product/gateway_file_config.toml` = 25 | ✓ |
| auth-throttle 27（E4 加数之一） | 同法 = 27 | ✓ |
| E4 合计 `9+6+10+5+9+27+16+7+15+25 = 129` | 加法自洽（=129），且与上一版 127 的差正好是本次 +2 条期望；其余 8 个加数是往片的数，本轮**未逐条重新推导** | ✓（含边界声明） |
| `config.rs` 的 12 条单测（REQ-014 承载体名单） | 从 MODULE.md 那段括号里正则抽出名单 = 12 个名字，12 个都能在 `src/config.rs` 找到 `fn <名字>(` | ✓（注意：`config.rs` 全文共有 27 个 `#[test]`，"12 条"是点名子集，句子后面就是名单，读法无歧义） |
| `--lib` 85 passed | 我的树 baseline 实测 85 passed / 0 failed | ✓ |
| FILE_MANIFEST 223，双口径一致 | `grep -c '^| `' = 223 ✓；把表头也含进去的 `awk '/^\| /{n++} END{print n}'` = 224，而 FILE_MANIFEST.md:87 自己写明旧口径因把表头算进去才 224、现已改用带反引号的 pattern ⇒ 我一开始怀疑的那条"错话"是我用错口径，**撤回，不立案** | ✓ |
| 219 → 223（+4 行：r14 案卷 2 + 脚本 + 日志） | 4 个文件确实各占一行，且差值 = 4 | ✓ |

## 4. Q2 新补的对象会不会又是一条"只红在词法层"的对象 —— 答：**会，实测打中一次（WARN-1）**

### WARN-1：`idle_*_rejected_by_config_layer` 一族仍是"词法层标签"，把标签复制到另一层就活下来

被攻击对象：
- `crates/nexus-web-gateway/examples/gateway_file_contract.rs:1749-1772`（6b 段：`rejected_idle_floor && idle_floor_is_usable` / `rejected_idle_ceiling = 串含 files.idle_timeout_secs && to_limits().validate().is_err()`）
- `crates/nexus-web-gateway/src/config.rs:755-782`（单测 `idle_time_bounds_are_rejected_at_the_config_layer`，断言的也是 `err.contains("files.idle_timeout_secs")`）
- 配置层那两条界：`src/config.rs:247-256`；引擎层同规则：`src/file_service.rs:199-203`（下界）与 `:222-226`（上界）

**我的配方 R15A（层迁移 + 标签复制，两处同改）**：
1. `config.rs` 删掉 `if self.idle_timeout_secs > MAX_FILE_WINDOW_SECS { ... }` 整块（配置层不再答话）；
2. `file_service.rs` 引擎那条消息改成 `"idle_timeout must be <= 24h (files.idle_timeout_secs): an unbounded window cannot be represented..."`（**保留** `file_service.rs:5225` 既有单测钉的子串，另把配置层的标签文字搬过来）。

**实测输出（`/work/r15-mut.log`）**：

```
=== R15A_layer_migration_with_label_copy  [MUTATED] ===
  lib: test result: ok. 85 passed; 0 failed; ...
  red tests (0):
  probe config       : frozen=25 flips=0 missing=0
  probe auth-throttle: frozen=27 flips=0 missing=0
  KILL: reds=0 flips=0 -> SURVIVED
```

行为确实变了：`files.idle_timeout_secs = 86401` 现在是由**引擎表**答的话，错误串从 `files.idle_timeout_secs must be <= 24h` 变成 `files limits: idle_timeout must be <= 24h (files.idle_timeout_secs): ...`（包裹前缀不同、发出者不同）。而新补的两条期望、新加的那条单测**全绿**——`idle_ceiling_rejected_by_config_layer` 里的 `&& c.to_limits().validate().is_err()` 这一半只证明"引擎也在拒"，完全不证明"配置层在拒"，所以它对"谁答话"没有鉴别力。r14 W-1 的教训（"委托让引擎替配置层答话"）在这里只补了**正向**一半，没补**反向**一半。

**判定：条件性有杀伤**。单点变异（= 入库的 MC20 / MC19）本族各 1 红 1 翻，实测确认（第 2 节 ③）；要两处同改（删配置层 + 把标签文字搬到引擎消息）本族与那条新单测才一起失效。按本链口径（红名单 + 逐字段 diff）这不是零杀伤表里的行，是**我没写进表的一条存活变异**，所以记 WARN 不记 FAIL。同形状的 `lockout_window` 一族（`over_24h_window_rejected_by_config` 等）继承同一个弱点，因为它们同样只断言"串里含配置层标签"。

**建议的最小修法（不替实现者动手，写在这儿）**：给这两条 field 各加**反向一半**——断言引擎自己的检查消息里**不含**配置层标签，例如
`!c.to_limits().validate().unwrap_err().contains("files.idle_timeout_secs")`；
标签一旦搬到引擎层，field 立刻翻。这比把标签写得更花哨更省，且能同时护住 `lockout_window` 那族。

（对下界 `R15A'` = 删 `src/config.rs:247-250` + 把标签搬到 `file_service.rs:199-203` 那条消息，我**未跑**——预算取舍，只说"同形风险"，不当实测结论。）

### NOTE-1：上界那条 field 缺"边界本身可用"的一半，floor / ceiling 不对称

**我的配方 R15B**：`src/config.rs:252` 的 `>` 改成 `>=`（把合法的 24h 整点也拒掉，真实行为变化）。

```
=== R15B_ceiling_off_by_one  [MUTATED] ===
  lib: test result: FAILED. 84 passed; 1 failed;
  red tests (1): config::tests::idle_time_bounds_are_rejected_at_the_config_layer
  probe config       : frozen=25 flips=0 missing=0
  KILL: reds=1 flips=0 -> KILLED
```

field 层 **0 翻**，杀伤全靠那条新单测里的 `edge.validate().is_ok()`（`src/config.rs:780-782`）。对照下界那条 field 是 `rejected_idle_floor && idle_floor_is_usable`（带"1 秒可用"，`gateway_file_contract.rs:1754-1767`）——上界没有对应的"24h 本身可用"。入库日志对 MC20 写的"1 红 1 翻"没撒谎（口径是红名单+diff 的并集），但读者别把那条 field 当成能钉边界。按口径不构成 WARN：有杀伤。

### NOTE-2：探针不早退的改法——**没有**造出伪杀伤，但三态合成一个值是事实，且已声明

**我的配方 R15C**：只在 `GatewayConfig::from_json_str`（`src/config.rs:370-375`）里加一句 `if !input.contains("files") { return Err(...) }` ——不碰 `absent` 缺省逻辑、不碰 `enabled` 判定、不碰 `file_engine()`，只让"没有 files 字面量的 JSON"解析不过。

```
=== R15C_parse_gate_only  [MUTATED] ===
  red tests (1): config::tests::absent_files_section_is_disabled
  probe config       : frozen=25 flips=2 missing=0
    FLIP absent_section_is_disabled    want=true got=false
    FLIP disabled_yields_no_engine     want=true got=false
  KILL: reds=1 flips=2 -> KILLED
```

第三种状态（解析不过）确实被记成 `false`：`legacy` 是 `None` → `is_some_and` → 两格 false。**但**：
1. 它没有把"什么都没算"伪装成"指名杀伤"——同一条变异让对应单测 `absent_files_section_is_disabled` 一起红，两条通道同向，不存在 field 翻而行为没变的伪证；
2. 这个合并是**写在代码注释里的**（`examples/gateway_file_contract.rs:1556-1563`："解析不过 / 关断态起出了引擎 / 关断态构造报错，三种都算这格为假"），不是我读出来的暗示；
3. 相对改法之前是**净改善**：原先 `map_err(...)?` 早退时，MC11 这类变异让探针整段不出 JSON（`probe config: NO JSON`），按 r13 W-3 的口径根本不配当杀伤证据；现在给出逐字段名单。入库日志 MC11 行 2 翻、MC05/MC12 行各 2 翻，就是这条改善的实物。

残留问题只是**归因精度**：名单上这两格 false 不能告诉第三方"是关断规则坏了"还是"是解析坏了"（三因一值）。判：**有杀伤、无伪杀伤**，归因 ambiguity 记 NOTE。想要更细就得把两格拆成三格（parse ok / section disabled / no engine），本轮不建议实现者动。

### NOTE-3：本表对 `product.gateway-file-auth-throttle` 的 27 格 0 杀伤

入库日志每一行都写 `probe auth-throttle: frozen=27 flips=0` ——20 条配方没有一条翻过那 27 格里的任何一格。案卷的覆盖率句子里已明确限定"场景 product.gateway-file-config 25 个 field"（`.agents/mutation-log-gateway-file-config.txt:15-17`），所以**不是错话**；但既然 harness 每次都探两条 case，把"本表不覆盖 auth-throttle 面"这句话也写进日志头部，第三方重算时不会误读成 52 格里 23 格有杀伤。

## 5. 我实际做了什么 / 什么没做

做了：自建克隆 + 自建 target；**原样跑完入库脚本的全表**（预检 20/20 + baseline + MC01–MC20 + restored 共 22 行），并与入库日志逐行对答案（22 行全等）；用自己的驱动跑 baseline、MC19、MC20、MC07、R15A、R15B、R15C 共 8 行并逐行还原；用只读脚本从入库日志+场景文件重算覆盖率；复核 25/27/129/12/85/223 六个计数。
没做（不构成证据，也不当结论用）：`verify --fast` 九道门；第十三片 `resource-accounting` 那条 RED；下界同形变体 R15A'（只写为风险推断）；FILE_MANIFEST 其余 8 个加数的逐条重推；对 `auth-throttle` 面另设配方。
未改任何业务代码/场景/文档；`E:\nexus-fabric-m0` 除 `.evidence/review-gateway-file-r15/` 外保持 clean。

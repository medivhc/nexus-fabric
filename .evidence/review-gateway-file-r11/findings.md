# review-gateway-file-r11 — findings（第 11 轮独立评审）

评审对象：案卷「追加：M1 第十一片」的 `D 轮（r10 回来之后的落地，全部重新实测）` 子节与「D 轮变异表」。
**本轮内对象移动了三次**：开局 = 已推送的 `a0ce15f`（70 单测 / c5d0918 口径的 14 行表）；中途实现方新增两条
单测（`expired_source_locks_are_reclaimed_…`、`source_ledger_budget_forgives_…`），案卷改口「唯一口径 = 最终树
`d0ace31`，72 条单测」，表扩到 18 行，N14 由 5 红改 6 红。我对**两棵树分别实测**，所以每个数都注明属哪一棵。
共享验证通道 `/work/m0-verify` 实测仍指向 `a0ce15f`（`git -C /work/m0-verify rev-parse HEAD`），新树是我
scp 工作文件自建等价树（`git hash-object` = `cb826f8e06c84ed36e677a99e491780ae4c04500`，与工作树 blob 逐字节相同）。
案卷行号按我最后一次读取标注（该文件仍在被编辑，整体下移约 11 行），**引用以引文为准**。

## 0. 实测底账（评审方亲跑，宿主 xc-pc-linux，rustc/cargo 1.98.1）

| 声明 | 评审方实测 | 结论 |
|---|---|---|
| 70 passed / 0 failed（a0ce15f） | 自有克隆 `/work/r11-qoder` ⇒ `70 passed; 0 failed` | 复现 |
| 72 passed / 0 failed（最终树） | 快照 cb826f8e ⇒ `72 passed; 0 failed` | 复现 |
| clippy --all-targets 零诊断 | exit 0、无输出 | 复现 |
| 9 条场景全 PASS / 103 期望（auth-throttle 26） | 逐条 `scenario run` ⇒ 9/9 PASS；`grep -c '^[[expect]]'` = 26+7+10+6+16+9+15+5+9 = 103 | 复现 |
| verify --fast 9 门全 PASS、evidence dir `verify-404018b6b95c` | 我自己的克隆跑出同一 id（内容定位）与 9/9 PASS | 复现 |
| contract_hash `2219448e…`、working_tree_digest `a76f554f…`、dirty=false | `status --json` 逐字相同；**并按 env.rs:188-216 自己重拼 303 个 toml（426043 B）`git hash-object --stdin` ⇒ 同一 hash** | 复现（非循环论证） |
| FILE_MANIFEST 声明 210 | `awk '/^\| /{n++}'` = 211，减表头 = 210 | 复现 |
| 83.1% / 85.33 / 68.33 / 17.07 / 0.67 / 128 / 26 | 逐式复算 0.8311、85.333、68.333、17.067、0.667、5120/40=128、⌈1029/40⌉=26 | 复现，且契约明写「算术而非实测」 |
| selected-properties 偶发红 = `env::tests::digests_deterministic_and_sha1_length`，根因 `working_tree_digest()` 退化 `tree-unknown` | 我在 a0ce15f 上 10 个并行周期中 1 次红，panic 在 env.rs:317、`left:"tree-unknown"`、`right:a76f554f…`；`-- --test-threads=1` 4 轮全绿 | **复现**（实现方 1/3+1/8，我 1/10，同数量级小样本） |
| `.githooks/pre-commit` 第 4 关字典序取 r9 | `ls -1d .evidence/review-* \| sort \| tail -1` ⇒ `review-gateway-file-r9`（我建好 r11 目录后仍是 r9）；`sort -V` ⇒ r10/r11 | 复现 |

## 1. R10-W-1 是否真闭上：**闭上（状态半），且零杀伤力是自报如实、不是掩盖**

- `arm_source`（file_service.rs:1026-1035）返回值语义现在是「**有没有落下状态**」（单源锁或全局窗口）；
  唯一返回 false 的条件是 `lock_until` 取不到 `until`（:1026-1028）。doc :1021-1025 明确把它与
  「这次是不是该按锁定处理」（那句承诺属于 `lock_until`，恒真）拆开——这正是 r10 要求的「一个 bool 不兼职两个意思」。
- 额度耗尽分支改成条件销账：`:1006-1008 if self.arm_source(skey, now) { self.source_failures.remove(&skey); }`。
  `source_failures.remove` 全仓只有这一处（grep：:785 初始化 / :858 decay retain / :995 insert / :1007 remove）。
- **终态与 pair 侧同口径**（按存活组合而非返回值核）：pair 侧 :946-947 先落桶行、:961-968 只有拿到 `until` 才写锁，
  取不到时超限桶行保留 ⇒ 下一条失败当场再试；源侧现在同样保留账本行 ⇒ 同一条大路。两支 `None` 都 `return true`（:957、:1013）。
- `None if source_failures.len() >= max_buckets` 那支（:987-992）**丢弃返回值是安全的**：该分支上根本没有该地址的
  账本行可销（它被设计为不建行），返回值唯一用途就是门销账；且无论锁是否落地都上报「已锁」⇒ fail-closed 方向不变；
  `None` 时既不插账本行也不插锁行 ⇒ 内存不增长。最坏后果（同地址下一次带正确令牌被放行）与 pair 侧 `None` 完全同形。
- 杀伤力我复跑：**D1_always_clear_ledger ⇒ 70 全绿 + 26 条期望零翻转**（a0ce15f）、**72 全绿 + 0 翻转**（快照）。
- 可达性我独立否证了「能构造出红对象」这条路：:798-801 的回退把 `None` 要求推到「`now` 距平台上界不足一小时」；
  :214-227 封 24h、:1414 `FileEngine::new` 走 `validate()?`，**没有任何配置或调用序列能逼出该分支** ⇒ 不是 FAIL。
- 案卷 :1033-1041 与 :1216-1222 都把它写成「**没有红对象**……不许读成修掉了某个运行时问题」，G15 未证事项同步。
  ⇒ 这一条是本轮我最想找 FAIL 而找不到的地方：它的「未证」登记得比我预期更严。

## 2. R10-W-2（harness flake + 证据覆写）的处置定性：**成立，未把没做的写成做完**

定位我复现（§0 末行）；覆写机制静态核实：evidence.rs:126-162 目录 = `verify-<按 bindings 的 id>`，
`write_json` 对 summary/gates/metadata 无条件覆写 ⇒ 同树复跑必然销毁前一次 FAIL 的取证。三条待办
(digest 静默降级 / 证据覆写 / pre-commit 字典序) 都在新知识条目的 (1)(2)(3) 段并进了 index.json
（`hsh-digest-sentinel-flake-001`，JSON 我 parse 过）。案卷 :1121-1123 写「本轮不修 nexus-harness」——没说成修过。
唯一措辞可挑：两处频率（1/3、1/8 vs 我的 1/10）都是小样本，别读成稳态率（→ R11-N-4）。

## 3. 两条 R10-N-4 新对象：**有效，因果干净，杀伤力实测**

- 夹具合法：`lockout_after: 4` + `max_failures_per_source: 4` 过 G12 两条交叉界（:242-246、:248-256）；
  第一版 9/4 确实被 `validate` 拒——我 checkout `fbcac2e` 复现了那次红：单测 `69 passed; 1 failed`（正是漂移那条），
  探针 stdout 只剩 `{"verdict":"FAIL","error":"CONFIG_INVALID: max_failures_per_source must be >= lockout_after…"}`。
- 因果：最后那次 authenticate 的主体在单测里是 `dual`、探针里是 `bystander`，**整段从没失败过** ⇒ 它的 (主体,源)
  桶行与 pair 锁都不存在；该夹具总共 8 条失败、表远未满（1024）⇒ 全局窗口不可能武装 ⇒ THROTTLED 只能来自源锁。
  `throttle_source_locks() == 2` + `throttle_source_ledgers() == 0` 钉「两种写法各一份额度、武装即销账」。
- 变异：**N14（source_key 不吃地址）⇒ a0ce15f 上 5 红 + 6 翻转；快照上 6 红 + 6 翻转**，红名单含
  `address_representation_drift_arms_two_independent_source_locks`，快照上还多含新加的 `expired_source_locks_are_reclaimed_…`。
  ⇒ G16「谁做归一化这两条会红」是实测。

## 4. 变异实测（评审方在两棵树上亲跑，每支跑完 `git checkout --` 复原，最终 `git status` 归零）

| 变异 | 实现方声明 | 评审方实测 | 判定 |
|---|---|---|---|
| baseline | 70/72 全绿、26 期望零翻转 | a0ce15f 70 全绿 + 0 翻转；快照 72 全绿 + 0 翻转 | 复现（探测器有效） |
| E 关纵深防御那支 | 全绿 + 0 翻转 | 70 全绿 + 0 翻转（a0ce15f） | 复现 |
| P8 关空地址守卫 | 1 红 + 1 翻转 | 1 红（empty_transport_address…）+ 1 翻转（empty_source…） | 复现 |
| D1 无条件销账 | 0 红 + 0 翻转 | 70/72 全绿 + 0 翻转 | 复现（R10-W-1 零红对象为真） |
| M10b 关锁定预检 | 11 红 + 11 翻转 | **两棵树都 11 红 + 11 翻转**，名单逐条对上（含两条新测试不依赖预检，故未变 13） | 复现 |
| N14 source_key 常量 | 5 红（旧树）/6 红（新树）+ 6 翻转 | 5 + 6 / 6 + 6 | 复现，**数字归属见 R11-W-1** |
| M17 源账本不衰减 | 1 红 + 0 翻转 | 1 红 = `source_ledger_budget_forgives_…` | 复现（那条测试确有杀伤力） |
| M18 源锁过期不回收 | 1 红 + 0 翻转 | 1 红 = `expired_source_locks_are_reclaimed_…` | 复现 |
| P1/P2/P3/P4/P5/P6/P7/N13/M15/M16 | 各行自报 | **未复跑**（轮次预算） | 不作判定（R11-N-2） |
| F 绕开 token_eq | r10 在 8a67e85 代跑 | 未复跑；与 r10 案卷一致 | 采信 r10 实测 |

## 5. WARN-1：实测数字未随「唯一口径」树滚动，最要紧的一处写在**契约文件**里

`crates/nexus-web-gateway/requirements.toml:89`（REQ-010 acceptance）不带树限定地写「把源摘要改成不吃地址 ⇒
**实测 5 条单测红 + 6 条期望翻转**」，而案卷 :1076-1078 宣布唯一口径 = `d0ace31`（72 条），其 N14 行是 **6 红 + 6 翻转**。
两个数都真实（我分别实测），缺的是限定语 ⇒ 后来人按契约核会核不上。同类：案卷 :1230「本批不受它影响：gateway 的
**70** 条单测」（同段 103 条期望对得上当前树）、:1037-1038 的 D1 那格带「复验树 c5d0918」限定但被表头的「不再引用」
规则孤立。正面记账：实现方**在本轮内已自行修好**另两处——:945-949 滚动链追到 72、:1218-1219 未闭事项改成
「c5d0918 上 5 红 / 最终树 6 红」双树并记，这正是 r9 R9-N-7 要求的写法；剩下这三处同理收口即可。
判 WARN 不判 FAIL：无运行时影响，且同段已有正确的双树写法作对照。

## 6. WARN-2：`source` 这条串的依赖面三处数成三样，且宣称「一次登记齐」

- file_service.rs:1796（close_session doc）与 gateway_file_contract.rs:974（探针注释）：说**三处**（归属、单源额度、per-peer 配额，漏源锁）；
- MODULE.md:363-364（G16 前提段）：说**四件事**（配额、单源额度、源锁、归属，漏两层键摘要半）；
- 案卷 :984-985：换一份名单（归属、单源额度、per-peer 配额、摘要键，漏源锁）并加一句「**一次登记齐**」。
真实消费点是**五个**：`source` 还是 `identity_key` 的一半（:820-826），被 :877 `is_locked`、:903 `record_failure`、
:1148 `succeed` 使用 ⇒ 表示漂移同样把**单个身份的 pair 侧额度翻倍**（两种写法 = 两个桶 = 2×`lockout_after` 才武装），
这一格不在任何清单里，也没有机验对象（新两条钉的是归属与源额度）。G16 这条的功能就是「M2 接线时逐处核」的清单，
少一处 = 前提没登记齐，与 r9 R9-W-1 抓的原缺陷同形。代码无缺陷（五个消费点行为一致），故 WARN。

## 7. NOTE

1. **N-1** 案卷 :1052 D0 段「25 条期望全 MISSING」——`fbcac2e` 自带 **26** 条 `[[expect]]`（含漂移那条），探针确无字段
   dump ⇒ MISSING 应为 26。机制与「1 条单测红」我复现无误。
2. **N-2** D 轮表 18 行中 10 行本轮未独立复跑（P1/P2/P3/P4/P5/P6/P7/N13/M15/M16）；已复跑 8 行零分歧。
3. **N-3** 案卷 :914-920 的 `d0ace31` 那组 bindings（`verify-e6f5aabdd251`、`3fa1185a…`）**评审通道拿不到**
   （`/work/m0-verify` = a0ce15f）⇒ 目前只有实现方自证。落地前推一次 `refs/heads/m0-verify`。
4. **N-4** flake 频率两处都是小样本（实现方 2/11、我 1/10），机制核实（env.rs:144-153 `write-tree` 失败 ⇒
   `unwrap_or_else` 成 `tree-unknown`），别把频率当稳态率读。

## 8. 契约 ↔ 代码 交叉核对（本轮未再发现「契约说了代码没做」）

四张表上界逐张核：buckets（:936-947 准入后 insert）、locked（:962-964 满则升级）、source_failures（:987 满则不建行、
:995 insert）、source_locks（arm_source :1030-1034 唯一插入点）；`arm_source` 调用点只有 :990 与 :1006。
「在源锁表还有位置时不升级」= MODULE.md:281-292 / PRODUCT.md:3322-3325 / REQ-010 与代码逐字一致。
两支全局升级共用 `global_locked_until` 槽且直写不取 max：MODULE.md:291-297 已写进正文，覆盖方向恒为延长（成立）。
「同形性只管返回值与审计行」：两分支 `record` 入参与错误码/消息字面量相同（:1802、:1813）、审计行在 `insert` 之前
（:1811-1816），doc :1779-1786 自己承认多一次 insert、时序不背书——口径一致。
G12 那句「缩小节流表的小夹具必须同时缩小这道额度」我按新夹具正面验证（9/4 被拒、4/4 通过）。
REQ-010 说「未知与不属于自己在返回值与审计行**四格**上逐字同形」，实际 `record` 有六个入参（六格全同）⇒ 契约是
代码的下界，不判缺陷，登记备查。
R9-N-9 的「六处硬编码」计数确实删了（知识条目改成「每一个……故意不写数量」）。
新知识条目按 FILE_MANIFEST.md:58 声明不进清单，无需 +1；r11 案卷两行需在落地时进清单。

## 9. 判定

**0 FAIL / 2 WARN / 4 NOTE ⇒ COMMENTED，可合并。**
本轮没有任何一条自报数字被我证伪：能复跑的全对上（含两棵树各一遍），复跑不到的（10 行变异、新树 verify）我明确记为
「未复跑 / 不可复核」而不是猜。R10-W-1 与 R10-W-2 的处置都真的闭上了该闭的部分，且两处「零杀伤力」是自报如实并把
未证登记进契约——这是本链十一轮里第一次连「负结果」都由评审方独立量出来。两条 WARN 都是文档收口：一处是契约文件里
缺限定语的实测数，一处是 M2 接线清单少一个消费点。落地前请补第三件事：把最终树推到 `refs/heads/m0-verify`，
否则案卷新口径那段仍是只有实现方自己能证。

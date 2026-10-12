# 独立评审案卷 —— 网关文件服务，第 7 轮（r7）

**被评审对象**：`crates/nexus-web-gateway` 认证节流器（`Throttle`）的一处安全语义变更 ——
(1) 节流桶/溢出计数按 `lockout_window` 衰减（R4-W-6 的 owner 裁决），(2) 身份键由"两半各裁 128 B
的裁剪标签"改为 SHA-256 定长摘要（R6-NOTE-4 的 owner 裁决），以及它与 G15 / PRODUCT §18.2 /
`requirements.toml` REQ-010 / 5 条节流单测 / 探针 `auth_throttle` / 9 条场景期望的一致性。
**不复审 r1-r6 已闭环的东西**（预算、审计环、路径解析、时钟边界、`validate()` 语料、准入检查），
除非本批把它们改坏了 —— 结论：没有改坏（见 §9）。

**宿主 / 工具链（本评审）**：Windows 11 x64（win32）+ Git Bash，**纯静态阅读**。
**未编译**：`nexus-web-gateway` 依赖 `ssh2` 0.9.6，其 `userauth_pubkey_memory` 受
`cfg(any(unix, vendored-openssl, openssl-on-win32))` 门控且本机无 cl.exe/nasm，因此我没有跑过
任何单测 / clippy / harness / 场景；实现方在 `xc-pc-linux` 上的实测（61 单测、clippy 零诊断、
9 场景 90 期望、`verify --fast` 9 门）我**未复现**，也未被用作任何"我能读到的东西"的替代证明。
本轮所有判据是**纸面可复算**的：字节计数、集合基数、窗口边界算术、以及"删掉某行还有没有断言变红"。
**我唯一独立复算成功的实现方数字是 `contract_hash`**（方法与结果见 §6.4）。

**标记约定**：`[读]` = 我读代码得出；`[算]` = 我自己按夹具算出来；`[核]` = 我用工具在仓内实测（grep/awk/git）。

**绑定信息（我自己在仓内核到的）**：
- 分支 `feature/gateway-file-service-contracts`，HEAD `175e115`，工作树未提交（6 个文件 M）`[核]`。
- 三棵验证树 `b968081` / `a9fad4d` / `1ab58b1` 都是 `git stash create` 型提交（父 = `175e115` + 一个
  index 提交），`git diff <tree> -- crates/nexus-web-gateway/src .../examples MODULE.md scenarios PRODUCT.md`
  **对三棵树全部为空**，且两两之间只差 `.agents/green-evidence-gateway-file-service-m1.txt`
  （b968081→a9fad4d +84 行，a9fad4d→1ab58b1 +6/-4）⇒ 案卷"三棵树的代码/契约字节相同、差异只在本文字"**成立** `[核]`。
- `contract_hash` 复算 = `e166ea79359b6559165e6b6af263fc3b74c5ee79`（与案卷一致），见 §6.4。

**Verdict：COMMENTED** —— 0 FAIL / 6 WARN / 12 NOTE。代码的判定方向没有被改坏（fail-closed 仍可达、
内存上界仍成立、锁内正确口令仍被拒、摘要键确实消除了裁剪碰撞）；本批的问题集中在
**"衰减换来的可用性，代价落在猜测率上，而这半边代价没有任何契约句或期望钉住"**、
**"两条被注释/文档描述成'机制'的东西实际不可达或零杀伤力"**、以及**"散文侧三处漂移"**。
`[核]` 本卷的杀伤力结论与率结论**大部分已在同一台 Windows 宿主上真跑过**（仓外 std-only 复算台，
方法/忠实性自检/效力边界见 §5.6）；最初只靠纸面推演的 R7-W-1、R7-W-2、R7-W-3 已升级为实测，
而**我最初判错的 R7-W-6（"武装侧零余量"）被实测否证，降级为 R7-N-11** —— 这条自我纠偏也写进案卷。

| 编号 | 级别 | 一句话 |
|---|---|---|
| R7-W-1 | WARN | 桶位从一次性消耗品变成每窗口可回收的"额度池"，默认参数下引擎的**可记录失败速率上界 = 85.33 次/秒**，不低于 PRODUCT 自己引用的 84.4 次/秒零节流锚点；两侧契约都只登记了"慢滴者不锁"这一每身份代价 |
| R7-W-2 | WARN | 删掉 `Throttle::forget` 的两行 ⇒ 61 单测 + 90 期望**全绿**；而 `:901` 注释写着 "(asserted by the probe)"，`:906` 给出的"不可被利用"理由对"成功→失败到锁定→close"这条序列为假 |
| R7-W-3 | WARN | `record_failure:846` 的"锁表满 ⇒ 升级全局窗口"分支经 `authenticate` **结构不可达**（附证明），但 `:843` 注释与 G15 都把它写成第二道 fail-closed 机制，且全仓没有一条正向断言 |
| R7-W-4 | WARN | MODULE.md:160 对被删方案的记忆描述为假（"裁剪只让项数有界"），且与同片 `file_service.rs:742-744` 的正确表述互相矛盾；PRODUCT 没有重复这句话 ⇒ 两份契约在裁决理由上不一致 |
| R7-W-5 | WARN | `requirements.toml:89` REQ-010 acceptance 仍写"随会话回收清零"，与本批明写的不对称（闲置回收**不**清）相反，也没有"按窗口衰减"；该文件不在 `contract_hash` 覆盖集内，门禁看不见这条漂移 |
| R7-W-6 | ~~WARN~~ **已降级** | 原判"三处时间夹具武装侧零余量"——**被自己的实测否证**（复算台把窗口压到 1 ms 仍能武装 ⇒ 本机余量 ≥100×）。改记为 R7-N-11 |
| R7-W-7 | WARN | 摘要键的归因残余（节流表不再保存可读身份，唯一归因面审计环把 principal 裁到 256 B）只登记在案卷自述里，G15 / PRODUCT 一句未提；长身份面上"谁被锁了"连近似归因都给不出 |
| R7-N-1 | NOTE | `file_service.rs:835` 注释"60 条单测照样全绿"与本批实际 61 不一致；变异表 M8"RED 3 条"按实测应为"5 条测试 + 3 条冻结期望（只坏单桶阈值时）/ 23 项断言（两处阈值都坏时）" |
| R7-N-2 | NOTE | `contract_hash` 对**行尾**敏感：同一内容在 Windows 脏树（CRLF）上我算得 `c3e352b7…`，归一到 LF 才复现 `e166ea79…`；案卷没声明"只在 LF 树上可复算" |
| R7-N-3 | NOTE | MODULE.md:173 病句"既是对话被锁的时长" |
| R7-N-4 | NOTE | 场景注释"（否则下一条会因'从未武装'而空转成立）"不成立：合成式第一项就是 `armed_before`；实测 M5 下两条期望**同时**红 |
| R7-N-5 | NOTE | "不同源不受牵连"在单测里有两根柱子（`:2821` + `:3166`，案卷自称 `:3166` 无杀伤力是**说少了**），但在 90 条期望里 **0 根**：M6 实测红的全是未冻结字段 |
| R7-N-6 | NOTE | 长度前缀性质（M3）实测只有 1 根柱子（`t6 :3160`），契约面零期望 |
| R7-N-7 | NOTE | `FileLimits.max_throttle_buckets` 字段文档 `:121-123` 仍是旧语义"oldest buckets are merged into the global bucket"，本批之后三处都对不上 |
| R7-N-8 | NOTE | `identity_key` 对调用方可控长度不设上界（任意长 principal ⇒ O(len) 摘要）；量级不足以立案，但应随 `files` 配置接线处理 |
| R7-N-9 | NOTE | 身份键字节精确、无 NFC/NFD/大小写归一 ⇒ 同一自然人可造任意多桶（在表满之前不受 fail-closed 约束），与 R7-W-1 同向 |
| R7-N-10 | NOTE | §18 的产品面**没有被任何门禁跑过**：`harness.toml` 给 9 条 `gateway_file_*` 场景要求的 artifact 种类是 `ReviewRun`，而 `gates.rs:675-683` 对它直接返回 BLOCKED（"not yet supported"）；`requirements.rs:107` 又只解析 `### 18.1` ⇒ 本批改写的 §18.2/§18.3 散文（含 R7-W-5 那条漂移）在门禁面是**盲区** |
| R7-N-11 | NOTE | （原 R7-W-6）三处时间夹具依赖真实墙钟、`Throttle` 六处硬编码 `Instant::now()`，而 `sweep_idle(now)` 已示范可注入时钟；实测本机余量 ≥100×，但 llvm-cov 插桩运行会放大约 20×（本仓知识条目已有先例），且这三处没登记进任何 flaky 面；案卷"余量 4×、2×"只说了静置侧 |
| R7-N-12 | NOTE | 本卷 §5.6 的实测产物在**仓外会话目录**，下一位评审者无法复算 ⇒ 建议把两条"0/59 全绿"的配方固化成仓内 `#[test]`（`forget` 与升级分支各自钉一条），或把复算台落进 `examples/`/`fuzz/` |

---

## 1. 问题 A —— 摘要键的正确性

### 1.1 旧裁剪键的碰撞对，我自己构造并核过 `[读]+[算]`

被删的写法是 `bounded_label(principal, 128)` + `bounded_label(source, 128)` 组成元组键，
`bounded_label`（现存于 `file_service.rs:1113-1122`，仍服务审计环）的实现是：
`s.len() <= max` 原样返回，否则在 char boundary 前截断并 `format!("{}…[+{}B]", &s[..end], s.len()-end)`。

碰撞条件因此是 **前 128 字节相同 且 被丢弃的字节数相同**（后者由总长决定）：
- `P_v = "b"×128 ++ "aaaa"`（长 132）与 `P_f = "b"×128 ++ "bbbb"`（长 132）：
  `bounded_label` 两边都得到 `"b"×128 ++ "…[+4B]"` ⇒ **同一键**。探针 `e5`（`examples:616-618`）用的正是这一对。
- 单测夹具（`:3129-3132`）用 `"b"×200 ++ "aaaa"` / `++ "bbbb"`（都长 204）⇒ 都截成 `"b"×128 ++ "…[+76B]"` ⇒ 同键。
  我核过这条夹具**同时满足**两条条件（前缀与总长），所以它测的是摘要而不是"字符串不等"，与案卷自述一致。
- 反向核对：若只让前缀相同而总长不同（`"b"×128++"a"` vs `"b"×128++"aaaa"`），旧键**不**碰撞（`+1B` vs `+4B`）。
  `[算]` 所以旧面是 `256 × 长度类` 的碰撞族，不是"任意前缀相同"，案卷措辞准确。

新键 `identity_key`（`:755-762`）= `sha256(u64le(len(P)) ‖ P ‖ u64le(len(S)) ‖ S)`：上面两对在字节层面不同 ⇒ 摘要不同（无碰撞假设下）⇒ 定向锁定面消除 `[读]`。

### 1.2 长度前缀是否真挡住拼接歧义（含多字节）`[算]`

挡住了，且对 UTF-8 也成立。论证：把 `f(P,S) = [8B len(P)] [P] [8B len(S)] [S]` 看作一段字节串，
它是**自解析**的——前 8 字节唯一确定 `len(P)`，接着按该长度切出 `P`，再 8 字节确定 `len(S)`，剩余长度必须等于
`len(S)`。所以 `f(P,S) = f(P',S')` ⇒ `len(P)=len(P')` ⇒ `P=P'` ⇒ `S=S'`。用**字节数**（`str::len()`）而非
`chars().count()` 正是自解析所需要的，没有语义问题。旧写法确实有 `("ab","c")` 与 `("a","bc")` 这类免费碰撞，
单测 `:3155-3162` 把这一对钉住了（我核过杀伤力：去掉前缀后 `update("ab")++update("c")` 与
`update("a")++update("bc")` 的输入字节完全相同 ⇒ `is_locked("a","bc")` 变 true ⇒ `:3160` 红）。
`:3166` 那条 `("ab","bc")` 自己承认无杀伤力（三条两半都不同的字符串在没有前缀时也不会撞到它）——
**如实登记，可接受**。

### 1.3 读写点一致性（找"仍在用别的键形式"的路径）`[读]`+`[核]`

`grep` 全仓 `bounded_key` 零命中；`Throttle` 的四个读写点全部 `Self::identity_key`：
`is_locked:798`、`record_failure:818`、`succeed:858`、`forget:909`。`grep "HashMap<(String"` 零命中 ⇒
没有残留的元组键容器。`record_failure:819` 的容量判定与 `:846` 的升级判定用的都是 `HashMap::len()`（物理行数），
而它们都紧跟在同一个 `now` 的 `decay` 之后 ⇒ 那一刻"物理 == 存活"，读写口径不会在这里打架（见 §3.2）。

`identity_key` 之外还有一处"身份比较"：`authenticate:1421-1425` 的 `held_by_peer` 按**原始 source 字符串相等**
数会话。这与摘要不冲突（字符串相等 ⇔ 摘要相等，非密码学性质），只是口径不同；无缺陷，登记备查。

### 1.4 `succeed`/`forget` 用会话记录的串，`record_failure` 用当场给的——会不会不同人不同键？`[读]`

不会。会话里的 `principal`/`source` 是 `authenticate:1442-1443` 用 `to_string()` 原样存的**未裁剪全串**，
`close_session:1467` 把它交给 `forget`，与 `record_failure` 吃的原始串同源 ⇒ 摘要一致。
审计侧的裁剪（`record:2375` `bounded_label(principal, 256)`）是**单向显示**，从不回流进节流器（我按 `record`
的调用点逐个看过：入参只做展示字段）。所以"审计里裁到 256 B 之后与摘要键用的原始串是否同一个人"——
**是同一个人在两个不同精度下的两次记录，判定不受影响；受影响的是归因，见 R7-W-7**。

---

## 2. 问题 B —— 衰减的强度：慢滴是否买到**新的**猜测预算

**结论：买到了。** 不是"慢滴专属"，而是**倍率恰好等于 `lockout_after`**：每身份每窗口的
可持续有信息量猜测数从旧语义的 **1** 条抬到新语义的 **`lockout_after-1` = 4**（绝不触发锁定的策略）
或 **`lockout_after` = 5**（接受被锁的策略）`[算]+[核]`。
下面先给纸面算术（默认参数取 `FileLimits::default()`：`lockout_after=5`、`lockout_window=60s`、
`max_throttle_buckets=1024`，`file_service.rs:144-146`；旧语义性质取 r4 案卷 §二(2) 的事实描述
"buckets 自身永不衰减，只有 succeed/forget 会删"），再给复算台的实测对照（§5.6）。

### 2.1 逐身份的可持续"信息量猜测"率

先确认一个边界性质，它让算术干净 `[读]+[算]`：某身份在第 `lockout_after` 条失败处上锁，
`locked[key] = arm + w`、`buckets[key].last = arm`，于是
`is_locked` 判 false 的时刻（`now ≥ arm+w`）与 `decay` 丢掉该桶的时刻（`now-last ≥ w`）**同一刻**
（`stale:689` 用 `>=`，`retain:779` 用 `>`，`is_locked:803` 用 `>` —— 三个谓词互补无空隙）。
又因为锁定期内 `authenticate:1380-1383` **先短路、不记失败**，锁定期间没有任何刷新。

| 攻击策略 | 新语义（每身份） | 旧语义（每身份，首个窗口之后） |
|---|---|---|
| 尽量不触发锁定 | `lockout_after-1 = 4` 条 / 窗口 ⇒ 0.0667 条/s ⇒ **5760 条/天** | 只在**第一个窗口内**能做到 4 条；此后计数粘住，第二窗口第一条就触阈值上锁 ⇒ 稳态 **1 条/窗口** |
| 接受被锁 | `5` 条 / 窗口（一轮 5 连击 ⇒ 锁 60s ⇒ 桶同时作废 ⇒ 下一轮又是 5 连击，周期恰 = 60s）⇒ 0.0833 条/s ⇒ **7200 条/天** | `1` 条 / 窗口（计数粘住，锁到期后第一条立刻重新上锁）⇒ **1440 条/天** |

`[核]` 复算台实测（`lockout_after=5`、窗口 200 ms、64 行、6 个窗口）：
新语义"绝不锁定"策略 **4.00 条/行/窗口**（6 个窗口 0 次锁定）、"接受被锁" **5.00 条/行/窗口**；
旧语义实测均值 1.50 与 1.67 ⇒ 扣除第一窗口的爆发后**稳态都是 1.00 条/行/窗口**
（`(256+5×64)/6 = 96.0`、`(320+5×64)/6 = 106.7`，与我实测的两个均值逐位吻合）。
⇒ **倍率 = 4×（不锁策略）～ 5×（被锁策略），与 `lockout_after` 完全挂钩**：
每身份预算从"每窗口 1 条"变成"每窗口 `lockout_after` 条"。

### 2.2 聚合上界与 PRODUCT 自己引用的锚点

`principal` 由调用方自报（G15 的两层键里唯一不可伪造的是 `source`，而桶是按**对**分的，
一个源地址可以开满整张表 `[读]`），所以真正有意义的是**整台引擎每秒能记下多少条失败**：

```
[算] 不触发锁定的聚合上界 = (max_throttle_buckets × (lockout_after-1) + (lockout_after-1)) / lockout_window
                          = (1024×4 + 4) / 60 s = 4100/60 = 68.27 次/秒
    接受锁定的聚合上界     = (1024 × 5) / 60 s = 5120/60 = 85.33 次/秒
    旧语义同口径           = 1024 × 1 / 60 s = 17.07 次/秒
```

PRODUCT.md:3312 在本条里给的**唯一速率锚点**是"V1 是零节流：实测 84.4 次认证/秒"。
`[算]` 新语义下节流器的聚合上界 85.33 次/秒**不低于**这个"零节流"数字（101%），退一步用"绝不触发锁定"
的策略也有 68.27 次/秒（81%）。旧语义把它压在 17.07 次/秒（20%）。
⇒ **"有界计数"这句仍然为真，但它约束的是内存与单身份累计，不构成任何聚合猜测率上界；
本批把这个率抬了 5 倍，而契约（MODULE G15:182-185 / PRODUCT §18.2:3319-3321）只登记了
"按窗口节奏慢滴的攻击者不会被锁死"这一每身份侧的代价。** 换句话说：文档没有"说过比代码更强的话"
在**锁内正确口令**这类判定上，但在**代价的完整度**上说少了。

### 2.3 全局窗口（fail-closed）的经济性 `[算]`

- 武装一次的成本：先在同一窗口内灌满 1024 个**活**桶（= 1024 条新身份失败），再 5 条新身份失败 ⇒
  1029 条；按 84.4 次/s 约 12.2 s。
- 武装期间 `is_locked` 对**所有**主体短路 ⇒ **没有任何失败能被记录** ⇒ `global_last` 不推进 ⇒
  窗口到点时 `global` 必然满足 `now-global_last ≥ w` 而被 `decay:787-793` 归零 ⇒
  "重新武装必须再攒满 `lockout_after` 条"**成立**（G15:175-176 / PRODUCT:3319 这句话我核为真）。
- 合法用户被拒的占空比：`[算]` 结构上等于 `w / (w + rows/rate)`（武装期 = 一个窗口，放行期 = 把
  `max_throttle_buckets` 行重新灌满所需的时间）。按 PRODUCT 引用的 84.4 次/s 折算
  = `60 / (60 + 1029/84.4) = 83.1%`；`[核]` 复算台实测（rows=1024、after=5、窗口 200 ms、in-process
  高速注入）新语义 **96.9%** 被拒（584925 拒 / 18511 放行）、旧语义 **99.8%**（663978 / 1117）——
  两者都极高，差别只在"攻击者停手后能否自愈"。
  ⇒ **可用性方向确实改善了**（旧语义是 99.8% 且停手后仍不自愈）；代价是 §2.1/§2.2 的猜测率方向。
  **但这两个数（83.1%~96.9% 与 85.33/s）在仓内任何地方都不存在**：r4 那个"94%"是本批从 MODULE 里
  删掉的（`git diff` 可见整句被删），删掉实测数字时没有换上任何新的量——无论是实测还是可复算的表达式。

### 2.4 "说过比代码更强的话"了吗？逐句判定 `[读]`

| 句子 | 判定 |
|---|---|
| G15:158-159 计数与表项**有界**（不得随伪造会话线性增长） | 真（§3.2 给出不变量证明） |
| G15:164-165 共用一个桶需要 SHA-256 碰撞 / 长度前缀挡拼接 | 真（§1.1、§1.2） |
| G15:166 锁定窗口内正确口令不得绕过 | 真，但**不全面**：`close_session` 能把窗口抹掉（R7-W-2） |
| G15:167-170 表满时必须 fail-closed（全局窗口对所有主体生效） | 真，但**只有一条路径实际可达**（R7-W-3） |
| G15:171-176 桶与溢出计数都随窗口衰减；停止注入一个窗口内自愈；重新武装须再攒满 `lockout_after` 条 | 真 |
| G15:178-180 读侧报存活值、内存上界由写侧回收保证 | 真（§3.3） |
| G15:182-183 代价二："同一窗口内 `lockout_after` 条"，慢滴者不会被锁死 | 真，但**低估**（§2.1/§2.2：不是"慢滴"这一支，是整条聚合率被抬 5 倍） |
| G15:160-161 "裁剪只让**项数**有界、标签本身仍按调用方给的长度分配" | **假**（R7-W-4） |
| PRODUCT:3317-3319 洪水不能永久占位，也不能无限续期 | 真 |
| PRODUCT:3311-3313 "有界计数（V1 是零节流：实测 84.4 次认证/秒…）" | 字面真，但按 §2.2 读起来像"节流把该率压下去了"——**没压下去** |

---

## 3. 问题 C —— fail-closed 面是否被削弱

### 3.1 表满 → 全局窗口这条路径仍然可达、仍然 fail-closed `[读]+[算]`

可达性没有被衰减破坏，两个夹具都把它跑出来了：单测 `throttle_fails_closed_when_the_table_is_full`
（`:3940-3977`，max=8 / after=3）与 `lockout_rearms_...`（`:2994-2997`，max=8 / after=2）；
探针 `e4`（`examples:505-552`，8 行 + 3 条 `rot`）与产品尺寸的 `e`（`:580-610`，1024 行 + 溢出）。
按 §2.3 的量，默认参数下武装成本约 1029 条失败，**在**机器能力之内。
fail-closed 方向也仍然成立：`:810` 的全局判定不再要求"不在 buckets 里"（r3 R3-NEW-2 的成果没被本批改坏）。

### 3.2 内存上界仍然成立，而且比我预期的更紧（顺带给出一条不可达性证明）`[算]`

不变量：**每次 `record_failure` 的 `decay` 之后，`locked.len() ≤ buckets.len() ≤ max_throttle_buckets`**。
- 右半：`:819` 的写入门禁 `buckets.len() >= max_buckets && !contains(key)` 使新行只在 `len < max` 时才产生；
  已存在键的 `insert` 不增行。`decay` 在同一 `now` 之前刚跑过，所以那一刻 `len()` 就是物理行数，
  物理行数不可能超过 `max` ⇒ `[算]` 物理 ≤ 1024，行 = 32 B 键 + `BucketState{usize,Instant}` 16 B，
  含 HashMap 开销粗估 ≤ 70 KiB（**粗估，不是实测 RSS**，也不该被读成实测）。
- 左半：每条锁都是"某身份第 `lockout_after` 条失败"那一次调用里写的，`locked[k]=t+w`、`buckets[k].last=t`，
  两者死亡条件逐字等价（§2.1），`succeed` 只在 `is_locked==false` 时才可能跑到（`:1380` 预检在前），
  而那要求该锁已死（死亡即被下一次 `decay` 清掉），`forget` 两行都删 ⇒ 不存在"活锁但桶没了"的窗口
  ⇒ `L ≤ B`。
  **推论（R7-W-3 的证明）**：`locked.len() >= max_buckets` 要成立，必须 `B = L = max`，
  即所有在册行**都带着活锁**；而行内身份在锁定期被 `authenticate` 短路、行外身份走溢出分支 ⇒
  **`:846` 的升级分支经 `authenticate` 不可达**。它只有两种触及方式：(a) 直接调 `pub fn record_failure`
  绕过预检（只有单测这么干），(b) `locked.retain` 坏掉（M9 变异，正是新单测 `:3173-3226` 抓的东西）。
  所以新单测的 premise（"死锁项占位 ⇒ 个体锁定被偷偷换成全体 fail-closed"）是**成立的**，
  但成立的方式是"它是唯一能让该分支活着的路径"，而不是"它是产品路径上的第二道门"。

结论：**C 的两个问题都是"没有削弱"**（可达、有界），但"表满 ⇒ 全局窗口"这句话的**实现机制只剩一条**
（溢出计数），文档/注释按两条写。

### 3.3 "读侧报存活值、内存上界由写侧保证"在代码里站不站得住 `[读]+[核]`

站得住，且我把四个读侧访问器逐个核了：`buckets:866`、`failure_count:877`、`global:887` 都是
`Instant::now()` + `stale` 过滤；`is_locked:796` / `globally_locked:895` 只做 `until > now` 比较，
过期项一律判 false ⇒ **读侧偏差不可能把"没锁"读成"锁了"，也不可能反过来**（方向安全，`:799-801` 的说法准确）。
`decay` 只在写侧跑（`:817`）⇒ 物理行的回收确实由写侧负责，且上界来自 §3.2 的门禁而不是回收。

**探针/场景有没有把存活值误当内存上界断言？有一处口径需要点破** `[算]`：场景
`gateway_file_auth_throttle.toml:35-38` 的注释"节流状态有界：不随伪造会话数线性增长"对应
`throttle_entries_bounded = buckets() <= max_throttle_buckets`（`examples:585-588`），
现在的比较对象是**存活值**。我核了它的杀伤力还在：把 `:819` 的容量门禁删掉 ⇒ 3072 条新身份失败全部建行 ⇒
存活值 2048 > 1024 ⇒ 红；把门禁写成 `> max`（off-by-one）⇒ 1025 > 1024 ⇒ 也红。
但它**测不到**"死行占位"这一类内存问题（那已由 `locked.retain` + 桶回收覆盖，且新单测钉住）。
⇒ 不是缺陷，是"这句话的射程变了"，建议在期望注释里写清"存活行 ≤ cap（物理行由 :819 写侧门禁保证，不在观测面）"。

---

## 4. 问题 D —— `close_session` 的 `forget` 是否成为解锁路径

### 4.1 可达序列（我按代码逐帧走了一遍）`[读]+[算]`

```
t0  authenticate(P, Q, 正确令牌) -> 成功，succeed(P,Q) 清桶，sessions[id] = FileSession{P,Q}   (:1407, :1438-1449)
t1  authenticate(P, Q, 错令牌) × lockout_after（同一窗口内）-> record_failure 写 locked[P,Q]  (:1385, :842-852)
t2  authenticate(P, Q, 正确令牌) -> THROTTLED（锁生效）                                       (:1380)
t3  close_session(id) -> forget(P,Q)：buckets.remove + **locked.remove** -> 锁没了            (:1467, :908-912)
t4  authenticate(P, Q, 正确令牌) -> OK
```

`[算]` 序列**可达**，不需要任何额外特权，只需要 t0 那次成功认证（即**必须已经持有正确令牌**），
且 t3 需要知道 t0 拿到的会话号（会话号是 `next_session` 顺序自增，`:1436-1437`，从 0 起 ⇒ 若 wire 层
不把 `close_session` 与会话归属绑定，会话号是可猜的；引擎侧 `close_session(&mut self, session: u64)` 今天
**没有任何归属检查**，这是 M2 接线前提，与 r2 N-8 同一条面）。

### 4.2 它算不算"绕过锁定"？`[算]`

不算密码学意义上的绕过：t0 已经证明调用方知道令牌，而"锁定"防的是**猜测令牌的人**；同时
`forget` **不**清 `global_locked_until` ⇒ 表满/溢出入群那条 fail-closed 大路**无法**用会话拆除解除。
所以真正被 `forget` 影响的只有"个体锁"与"个体计数"，而个体锁只有在持有令牌时才谈得上被"提前解除"。

### 4.3 但 `forget` 的注释说法**不准确**（三处）`[读]+[算]`

1. `:901` "the table grows with connection churn (**asserted by the probe**)" —— 探针里那条
   `state_cleared_after_close`（`examples:569-575`）跑的是 `auth → close → 再 auth 成功`，而 `auth` 成功时
   `succeed` 已经清过桶 ⇒ 探针**没有**断言 `forget` 做的事。**变异：把 `:909-911` 两行删空** ⇒
   我逐条推演了 6 条节流单测（`:2799/:2947/:3076/:3124/:3173/:3941`）、`state_cleared_after_close`、
   `throttle_entries_bounded`、e5/e6 的全部判据 ⇒ **全绿** `[算]`。零杀伤力（R7-W-2）。
2. `:906` "今天两条都不可被无令牌者利用（开 session 必须先过一次成功认证，**而那次成功已经清过桶**）"
   —— 括号里的理由是**假**：`succeed` 清的是 t0 之前的账，t1 又新攒了一条锁。正确的理由是
   "必须先持有正确令牌才可能有会话"，即**结论对、论据错**，而这段注释正是 r5 之后被专门重写过一轮的那段。
3. `:900` 第一句 "Called on session teardown" 与 `:903-906` 的"只有显式 `close_session` 才清、
   闲置回收不清"自相矛盾（`sweep_idle:1493-1498` 确实不调 `forget`）。
   `[核]` 全仓也没有任何一条断言"闲置回收**不**解锁"——`sweep_idle` 出现的三处测试
   （`:3570-3592`、`:3935`）都在预算/审计面上。⇒ 这条**被写成"有意"的安全不对称**，两侧都无测。

**修法（不阻塞，写进 §8）**：把 `forget` 的注释改成真实理由 + 明写"个体锁可被会话拆除提前解除、
全局窗口不可"；补一条单测钉住"close_session 会解锁（当前语义，产品决定）"，
再补一条钉住"sweep_idle 不会解锁"；两者对 `Throttle::new(...)` 直接构造即可，不需要时间夹具。

---

## 5. 问题 E —— 测试与探针的杀伤力（逐条手推）

### 5.1 6 条节流单测 `[算]`

| 测试 | 夹具 | 我的逐帧手推 | 杀伤力判定 |
|---|---|---|---|
| `lockout_refuses_even_the_correct_token_and_stays_bounded` `:2799-2829` | default（5/60s/1024） | 5 连击第 5 条 THROTTLED ✓；正确令牌短路 ✓；`10.0.0.2` 不同源 → 成功（M6/M7 的唯一单测杀手）✓；3072 条伪造 → 1024 行 + 5 条溢出后全局窗口武装，其余 2043 条在预检处短路 ⇒ `buckets() ≤ 1024` ✓ | **有**。删容量门禁 ⇒ 2048/3072 存活行 ⇒ 红；删 `source` 半 ⇒ `:2821` 红 |
| `lockout_rearms_after_expiry_and_flood_arms_are_not_exempt` `:2946-3073` | max=8 / after=2 / w=300ms | 阶段 1 `repeat` 2 连击锁上→正确令牌拒→睡 600ms→再 2 连击重新锁上 ✓（锁与桶同刻死，第 1 条新失败 count=1）。阶段 2：`repeat` 行仍在窗口内 ⇒ 12 条 flood 只能占 7 个行 ⇒ flood7=第 1 条溢出、flood8=第 2 条 ⇒ `global=2 ≥ 2` 武装 ✓；`:3003` 断言表满（8 行 = repeat + flood0..6）✓ 且 flood0 自身未锁（count=1）✓；`:3007` flood0 正确令牌被全局窗口拒 ✓（旧豁免逻辑下这里 ACCEPTED ⇒ 真有杀伤力）。睡 600ms 后 `!globally_locked` ✓、`:3027` late-comer 进得来 ✓、`:3036` `throttle_overflow()==0`（读侧过滤）✓、`:3041` `throttle_failures()==0` ✓、`:3042-3049` post-flood 落自己桶（1 行 1 条）✓、`:3054-3071` 重灌 7 行 + 攒 2 条溢出才重新武装 ✓ | **有**，且是 M1/M2/M4/M5 的主杀手。逐条核：删桶回收 ⇒ `:3043`（期望 0，实得 1）与 `:3048`（期望 1，实得 0）双红；删全局归零 ⇒ `:3036`/`:3059` 红；删读侧过滤 ⇒ `:3041` 实得 9 红 |
| `lockout_requires_failures_inside_one_window` `:3075-3121` | default max / after=3 / w=200ms | 3 轮各 1 条、间隔 300ms：每轮 `decay` 丢旧桶 ⇒ count 恒 1 ⇒ AUTH_DENIED ✓；反向同窗口 3 连击 ⇒ 第 3 条上锁 → THROTTLED ✓；正确令牌仍 THROTTLED ✓ | **有**：M1（不回收桶）下第 3 轮 count=3 ⇒ 第一次就 THROTTLED ⇒ `:3096` 红（案卷"第三轮第一条直接锁定"与我算的一致） |
| `throttle_identity_keys_do_not_collide_on_prefix_or_concatenation` `:3123-3170` | `Throttle::new(16,3,60s)` / `(16,2,60s)` | base=200 个 'b'，victim/forged 各 204 B ⇒ 旧键同标签 `"b×128…[+76B]"` 碰撞 ✓；三条伪造各 3 连击（9 行不触容量、`locked.len()` 3<16 ⇒ 不升级、无全局）✓ ⇒ `is_locked(f)` ✓ / `!is_locked(victim)` ✓；victim 自己 1 条 ⇒ `record_failure` 返回 false ✓（旧键下 count 4 ≥ 3 → true ⇒ 红）；`buckets()==4` ✓、`failure_count()==3×3+1=10` ✓；拼接面 `("ab","c")` vs `("a","bc")` ✓；`u.buckets()==1` ✓、`u.failure_count()==2` ✓ | **有**：M3（丢长度前缀）、M7（丢主体半）都红；`:3166` 那条自认无杀伤力 ✓ |
| `expired_locks_are_reclaimed_instead_of_escalating_to_the_global_window` `:3172-3225` | max=2 / after=2 / w=200ms | first、second 各 2 连击 ⇒ `locked.len()` 0→1（判 `0<2` 插入）、1→2（判 `1<2` 插入）⇒ 两条个体锁、无全局 ✓；`:3200` 前提 `!globally_locked` ✓；睡 400ms ⇒ 两条锁与两行桶同时死；third 2 连击：第 1 条 `decay` 清掉两条死锁 ⇒ len(B)=0 ⇒ 建行；第 2 条 count=2 ⇒ `locked.len()=0 < 2` ⇒ 走个体锁 ✓；`:3209` `!globally_locked` ✓；`:3213` third 正确令牌 THROTTLED ✓；`:3220` first 正确令牌 OK ✓（M9：`retain` 恒真 ⇒ `locked.len()=2 ≥ 2` ⇒ 升级全局 ⇒ **`:3209` 与 `:3220` 双红**；`:3213` 在 M9 下仍真，因为全局窗口对 third 同样判 THROTTLED） | **有**。这是本批把"零杀伤力变异"变成"可红"的那条，与案卷自述一致 |
| `throttle_fails_closed_when_the_table_is_full` `:3940-3977` | max=8 / after=3 / w=60s | 8 条建满（每条 count=1，不锁）✓；`rot` 3 连击走溢出 ⇒ `global=3 ≥ 3` 武装 ✓；`:3956` 武装前 `overflow()==0` ✓；`:3970` `brand-new` + 正确令牌 → THROTTLED ✓（旧 fail-open 写法这里 Ok） | **有**（M5）。M2 在此 GREEN —— 案卷如实记了 GREEN ✓ 诚实 |

### 5.2 探针 `e`/`e3`/`e4`/`e5`/`e6` 的夹具算术 `[算]`

- `e`（`examples:461-479`）：default。1 + 4 + 1 = 6 次，第 6 次 count=5 ⇒ THROTTLED ✓
  ⇒ `first_denial_code=AUTH_DENIED`、`sixth_attempt_code=THROTTLED` 两条期望非空转。
- `e3`（`:484-502`）：`1..=64` 观测循环在第 5 次首次 THROTTLED ⇒ `attempt_of_throttle=5`，
  随后正确令牌仍 err ⇒ `locked_after_attempts=6` ✓ 与期望 `= 6` 一致；这条是**观测**而非硬编码 ✓。
- `e4`（`:505-552`）：max=8/after=3（60s 窗口）。8 条建满 + 3 条 `rot` 溢出 ⇒ `overflow()>=3` 且武装 ✓；
  `in_table_correct`（`p0`，count=1，在表里）在全局窗口下 THROTTLED ✓ ⇒ 旧豁免逻辑下红 ✓。
- `e5`（`:611-648`）：**取值时机我核对了**——`throttle_buckets()` / `throttle_failures()` 在受害者
  成功认证**之前**读（`:627-628`），此时 `{forged:5, victim:1}` ⇒ `[2, 6]` 且
  `6 == lockout_after+1` ✓；若在成功之后读，`succeed` 删 victim 行 ⇒ `[1, 5]` ⇒ 合成式**变红**而不是空转，
  所以注释里"判据就空转了"这句口径应改成"判据就恒不成立"（与 R7-N-4 同类小瑕疵）。
  `victim_code_after_forged_prefix == "ACCEPTED"` 的杀伤力：旧裁剪键下 = THROTTLED ⇒ 红 ✓；
  且在"M7 摘要忽略主体半"变异下 = THROTTLED ⇒ **契约面也能杀 M7**（案卷只把 M7 记在单测上，低估了自己）。
- `e6`（`:649-682`）：max=4/after=2/w=100ms。flood0..3 建满 4 行 ⇒ flood4 溢出 global=1（不武装）、
  flood5 溢出 global=2 ⇒ **武装** ✓ `armed_before=true`；睡 400ms ⇒ `lapsed/table_empty/overflow_zero`
  三个都是**读侧过滤**即可成立（我核过：删掉 `decay` 它们也真 ⇒ 这三项**无杀伤力**）；`admitted` 同理；
  真正有杀伤力的是 `healed`（`buckets()==1`：有衰减 ⇒ fresh-failure 落自己的行；无衰减 ⇒ 表仍满 ⇒
  走溢出 ⇒ 存活值 0 ≠ 1）⇒ **合成式整体可杀 M1** ✓，案卷自述"红的是这条自证而不是静默空转"成立。

### 5.3 4 条新场景期望是否空转 `[算]+[核]`

`[核]` `grep -c '^\[\[expect\]\]' scenarios/product/gateway_file_auth_throttle.toml` = **13**（案卷 9→13 ✓），
4 条新增是 `throttle_identity_prefixes_are_separate_buckets`、`victim_code_after_forged_prefix`、
`flood_armed_before_quiet_window`、`throttle_flood_self_heals_after_quiet_window`。逐条判非空转：
- 前两条：对**变更前实现**（裁剪键）红，对 M6/M7 类变异红 ⇒ 非空转 ✓。
- 第 3 条：单独就是 `armed_before`，红/绿由夹具决定 ⇒ 非空转 ✓。
- 第 4 条：合成式含 `armed_before`，删衰减 ⇒ `healed` 项红 ⇒ 非空转 ✓。
- 场景注释说"先记录洪水确实武装…否则下一条会因'从未武装'而空转成立"——`[算]` **该理由不成立**，
  下一条的合成式第一项就是 `armed_before`；第 3 条的真实价值是**定位**（区分"没武装"与"没自愈"），
  案卷末尾那句"没有它，'自愈'会因为'从未武装'而空转成立"（`green-evidence` 第 528-530 行附近）也是同一处口径错。→ R7-N-4。

### 5.4 变异表 M0-M9 复核 `[核]`（复算台实测，见 §5.6）

| 案卷声称 | 我的复核（实测优先于推演） |
|---|---|
| M1 decay 不回收桶 → RED 两条 | **成立但低记**：实测 3 个单元红（`t2_rearms`、`t3_requires_one_window`、**`t5_expired_locks`**——案卷没料到 M1 也会打红第 5 条测试）+ 场景 `throttle_flood_self_heals…` 红（`healed` 项）；案卷漏记契约面那一条 |
| M2 溢出时钟不推进 → RED `lockout_rearms`、GREEN `fails_closed_when_table_full` | **成立**（该测试无静置，如实记 GREEN ✓，我复现同为 GREEN）；额外：契约面 `self_heals` 也红（`overflow_zero` 项） |
| M3 丢长度前缀 → RED identity 键测试 | **成立**；`[核]` 实测**只有 1 条断言红**（`t6` 的 `("ab","c")` vs `("a","bc")` 那一段），其余 5 条测试与 13 条契约断言全绿 ⇒ **契约面对长度前缀完全失明** → R7-N-6。另注：红点在 `:3160`，**不在**案卷引用的 `:3166` |
| M4 读侧不按窗口过滤 → RED `lockout_rearms` | **成立**（`:3041` 实得 9）；额外 `e6.table_empty` 与 `e6.overflow_zero` 也红 ⇒ 场景也杀（案卷未记） |
| M5 全局窗口从不武装 → RED 两条 | **成立**；实测 t2 4 条断言 + `t_full` 2 条 + 4 条冻结期望红（`full_fail_closed`、`product_fails_closed`、e6 两条） |
| M6 摘要忽略源半 → RED `lockout_refuses_even…` | **柱子比案卷说的多一根、但契约面仍是 0** `[核]`：实测红 `t1 :2821` **与** `t6 :3166`（后者注释自称"只是回归护栏"，其实正是 M6 的柱子——案卷**低估**了它）；13 条契约断言**全绿**（唯一同形的 `other_source_still_admitted` 未冻结）⇒ R7-N-5 |
| M7 摘要忽略主体半 → RED identity 键测试 | **成立**；实测 3 条测试 + **6 条契约断言**红（`full_fail_closed`、`product_fails_closed`、e5 两条、e6 两条）⇒ 案卷把 M7 只记在单测面，**低估自己** |
| M8 计数永不触达阈值 → "RED 3 条" | **数字要分两种改法** `[核]`：只把 `:842`（单桶阈值）改假 ⇒ **5 条测试 + 3 条冻结期望红**，`t_full` **不**红（它测的是 `:825` 那道 `global >= lockout_after`）；把 `:825` 与 `:842` 都改假 ⇒ 再加 `t_full` 与 4 条期望红（23/59）。⇒ 案卷"RED 3 条"是**下界而非精确数**，且没说明变异覆盖面 |
| M9 过期锁不回收 → 第一版全绿，补测后 RED | **成立**：实测**只有** `t5` 的 `:3209` 与 `:3220` 两条红（`:3213` 在全局窗口下仍真）；13 条契约断言全绿 ⇒ 这条性质**只有 1 条单测、0 条场景** |
| M0 `record_failure` 内冗余窗口守卫 → 全绿 | **成立**：`decay` 与守卫用同一 `now`、同一谓词 ⇒ 分支结构不可达；仓内注释 `:833-836` 的表述与我读到的代码一致 ✓ |
| （案卷未列的两条，我补跑） | **删 `:910-911`（`forget` 变空）→ 0/59 全绿**（R7-W-2 由推演升为实测）；**删 `:846-847` 升级分支 → 0/59 全绿**，且定向实验给出"经 `authenticate` 永不触发、绕过预检必触发"（R7-W-3 实测） |

### 5.5 时间夹具：假红还是假绿？`[算]+[核]`

我把每条断言按"抖动会把哪一侧推过边界"分类：
- **只会假红、不会假绿**：所有"必须锁定 / 必须武装 / 必须 ≤/== 某小值"的断言，抖动只会让计数**更少**，
  于是这些断言变红；`lockout_requires_failures_inside_one_window` 的反向段（同窗口 3 连击必须锁）同属此类。
- **抖动免疫**（对 M1 类变异始终红）：跨窗口不累计那一侧——变异让计数**永久累加**，与抖动方向无关。
⇒ 结论与案卷自述一致（"红的是这条自证而不是静默空转"），**没有假绿**。

但**假红面**被案卷的"余量 4×、2×"掩盖了：那两个倍数说的是**静置侧**；**武装侧**要求
`e6` 6 次认证 / `lockout_requires` 3 次认证 / `lockout_rearms` 2 次溢出失败分别落在 100/200/300 ms 内。
根因是 `Throttle` 的六个时刻全是硬编码 `Instant::now()`（`:797/816/867/878/888/897`），
而 `FileEngine::sweep_idle(now)`（`:1480`）已经示范了"把时钟做成参数"。

`[核]` **复算台实测（这一条把我最初的"零余量"判断改掉了）**：把三种仓内夹具的形状（6 次连续注入、
3 次连续注入、2 次连续注入）在窗口 `100 / 20 / 4 / 1 ms` 下逐个跑，**四种窗口全部照样武装**
⇒ 说明本机这段连续调用的耗时 < 1 ms，`e6` 的 100 ms 窗口有 **≥100× 的实际余量**，
`lockout_requires` 的 200 ms 对 3 次调用同样如此。**所以"武装侧零余量"这个说法我收回**：
复算台在 1 ms 窗口下都没有跑不出武装，可见正常负载下这段根本不是瓶颈。
真正剩下的风险是**长尾**：一次 >100 ms 的调度停顿（并发测试线程抢占、或 llvm-cov 插桩运行——
本仓知识条目 `coverage-run-flaky-timing-test` 记过同类放大：同一条时序敏感测试单独跑 3/3 绿、
插桩跑挂，耗时在 0.43 s / 2.64 s / 9.80 s 之间摆动）。
⇒ 结论：夹具设计可用，方向仍是"只假红不假绿"；但 (a) 案卷那句"余量 4×、2×"应改成
"实测静置侧 4×，武装侧在本机 ≥100×"（**别把我这个数当成 CI 保证**），
(b) 仍建议按 R7-N-11 把时钟做成参数、或把这三处登记成已知时序敏感面，
因为 ≥100× 是**我这台机器 in-process 循环**的观测，不是被门禁保证的性质。

### 5.6 变异复算台：**已在 Windows 宿主上真跑**（方法、忠实性自检、实测结果与效力边界）

**为什么能跑** `[核]`：`nexus-web-gateway` 本身在本宿主编不出来（`ssh2` 0.9.6 的 `userauth_pubkey` 受
`cfg(unix | vendored-openssl | openssl-on-win32)` 门控，本机无 `perl`/`make`/`cc`，`Cargo.lock` 无
`openssl-sys`；我试了 `--features ssh2/openssl-on-win32`，`Cargo.lock` 被改后立刻 `git checkout` 还原，
仓内文件未受影响），但**被评审的那个单元不需要它**。于是把 `Throttle` 连同引擎侧判定顺序一起搬出来，
做成一份独立可执行程序：

```
路径（仓外，不入仓）：C:\Users\xiangcui\AppData\Roaming\...\sessions\...\c2283260c5da99a5d2076c04\r7rig
工具链：cargo 1.95.0 / rustc 1.95.0，`cargo build --offline`（sha2 0.10.9 + digest + generic-array 走本机 registry）
调用：r7rig.exe all     → 18 个变异 × 59 条断言   ｜  r7rig.exe rates → 率、占空比、可达性、时间余量
```

**装了什么** `[核]`：(1) `file_service.rs:669-913` 的 `BucketState`/`IdentityKey`/`stale`/`Throttle`
（`decay`/`identity_key`/`record_failure`/`is_locked`/`succeed`/`forget`/四个读侧访问器/`lock_until`），
变异分支一律以 `if m(...)` **加在原语句之外**，`mut=none` 走的就是仓内那条路径；
(2) 六条节流单测的夹具与**每一条断言**逐字转录（46 条）；(3) 探针 `auth_throttle` 的
**7 条已冻结期望 + 2 条未冻结字段**，再加 e5 的 2 条、e6 的 2 条 ⇒ 契约侧 13 条全数复刻；
(4) `authenticate` 的判定顺序（`:1380` 预检短路 → 比令牌 → `:1385` 记失败 / `:1407` 清桶）、
`close_session:1467` 走 `forget`、`sweep_idle:1493-1498` **不**走 `forget`；
(5) 两个"变更前"基线开关：`M_OLD_SEMANTICS`（桶不衰减 + `global` 随窗口归零）与
`M_TRUNCATED_LABEL_KEY`（两半各裁 128 B 的标签键 + 无长度前缀的拼接）；
(6) 一个 `compared` 计数器，只在**令牌真的被比较**时 +1 ⇒ 用来量"攻击者拿到信息量的猜测数"
（被预检短路的尝试不计数）。

**忠实性自检** `[核]+[算]`：`mut=none` 下 **59 条断言全绿**。这不等于"复算台 == 本仓"，
只等于"我转录的夹具没有把期望值抄反"（抄错任何一条，基线当场红）。三处旁证：
(a) 绝不锁定策略实测 256.0 = 64 行 × 4 条/窗口，与 `lockout_after-1` 严格吻合；
(b) 接受被锁策略实测 320.0 = 64 × 5；
(c) 旧语义那一支实测 106.7 恰等于我纸面推演的 `(320 + 5×64)/6`。三条独立算式落在同一份代码上。

**变异实测结果**（`[核]`，红 = 该断言在该变异下不成立）

| 变异（开关 ↔ 仓内行） | 红的单测断言 | 红的**已冻结期望** | 判读 |
|---|---|---|---|
| `M_OLD_SEMANTICS`＝变更前的衰减 | t2 7、t3 1、t5 2 | `throttle_flood_self_heals_after_quiet_window` | 新断言**非空转**：桶不衰减时确实红 |
| `M_TRUNCATED_LABEL_KEY`＝变更前的键 | t6 4（含 `:3160` 拼接段） | `throttle_identity_prefixes_are_separate_buckets`、`victim_code_after_forged_prefix` | 摘要键这条裁决有 E4 背书，**且这是唯一背书**（其余 11 条期望全绿） |
| M1 `:780-781` 桶回收 no-op | t2 6、t3 1、**t5 2** | `self_heals`（`healed` 项） | 案卷 M1 记"红 2 条测试"，实测**还连带 `expired_locks`**（`:3209/:3220`）⇒ 案卷低估自己的测试 |
| M1b `stale()` 恒假 | t2 7、t3 1、t5 2 | `self_heals` | 同上，另 `:3041` 红（"读侧存活值"口径被拆穿） |
| M2 `:824` 不推进 `global_last` | t2 4 | `self_heals` | 案卷声称的 "`fails_closed_when_the_table_is_full` GREEN" **实测为真**（诚实） |
| M3 丢两段长度前缀 | t6 **仅 1 条**（`:3160`） | **无** | 长度前缀只有一根柱子且在单测里 ⇒ R7-N-6 |
| M4 读侧不按窗口过滤 | t2 2（`:3036/:3041`） | `self_heals` | "读侧报存活值"确有测 ✓（案卷未记契约面，属低估） |
| M5 `:825` 恒假（从不武装） | t2 4、t_full 2 | `throttle_full_fail_closed`、`product_engine_fails_closed_when_flooded`、e6 两条 | fail-closed 的柱子最多，健康 |
| M6 摘要少喂 source | t1 `:2821` + **t6 `:3166`** | **无**（只有未冻结的 `other_source_still_admitted` 会红） | 案卷称 `:3166` "自认无杀伤力"**是错的**：它正是 M6 的第二根柱子；而**契约面对 M6 全绿** ⇒ R7-N-5 |
| M7 摘要少喂 principal | t2 4、t6 3、t_full 3 | `full_fail_closed`、`product_fails_closed`、e5 两条、e6 两条 | 案卷把 M7 只记在单测上，**低估**：契约面有 6 条期望会红 |
| M8a `:842` 恒假 | t1 2、t2 2、t3 2、t5 2、t6 2 | `sixth_attempt_code`、`correct_token_bypasses_lockout`、`locked_after_attempts` | 案卷"RED 3 条"实为 **5 条测试 + 3 条期望**；`t_full` 确实不红（它测的是 `global` 那道比较）⇒ 变异覆盖面的解释成立 |
| M8b `:825`+`:842` 都恒假 | 上述 + t2 4、t_full 2 | 上述 + `full_fail_closed`、`product_fails_closed`、e6 两条 | 23/59 红 |
| M9 `:779` 过期锁不回收 | **只有 t5 的 `:3209` 与 `:3220`** | **无** | 案卷"补测试后 RED"成立 ✓；同时证明这条性质**只有 1 条单测、0 条场景** |
| **删 `:910-911`（`forget` 变空）** | **无** | **无** | **0/59 全绿 ⇒ R7-W-2 从推演升级为实测** |
| **删 `:846-847` 升级分支** | **无** | **无** | **0/59 全绿 ⇒ R7-W-3 的"无正面覆盖"实测成立**；定向实验另证：经 `authenticate` 触发升级 = **false**，绕过预检直接 `record_failure` = **true** |
| 删 `:819` 容量门禁 | t1 1（`buckets=3073`）、t2 5、t_full 3 | `full_fail_closed`、`entries_bounded`（2049）、`product_fails_closed` | "有界"这句确有杀伤力 ✓ |
| `:819` 写成 `>`（off-by-one） | t1 1（`buckets=1025`）、t2 2、t_full 3 | `entries_bounded`（1025）、`full_fail_closed` | off-by-one 也红 ✓（§3.3 的推演被证实） |

**率、占空比与可达性实测**（`[核]`；夹具：`lockout_after=5`，窗口 200 ms，表 64 行或 1024 行。
**绝对值不可外推到产品**——复算台是 in-process 循环，吞吐约 15 万次/s；可比的是**比率与结构**）

```
绝不锁定策略（每行每窗口喂 4 条）：新语义 256.0 条/窗口，6 个窗口 0 次锁定
                                  旧语义 96.0 条/窗口，6 个窗口里 5 个出现锁定 ⇒ 该策略在旧语义下不可持续
接受被锁策略（每行每窗口喂 5 条）：新语义 320.0 条/窗口；旧语义 106.7 ⇒ 稳态比率 320/64 = 5.0×
                                  ⇒ §2.1 的"倍率 = lockout_after"由推演变实测
持续洪水的拒止占空比（1024 行 / w=200ms / 4s）：新语义 96.9%（拒 584925 / 放行 18511）
                                               旧语义 99.8%（拒 663978 / 放行 1117）
                                               ⇒ 结构：拒止期 = 一个窗口，放行期 = rows/rate 的补表时间
"每窗口只补 1 条溢出失败"能否续期：0/6 轮 ⇒ G15:175-176 与 PRODUCT:3319 那句"必须再攒满 lockout_after 条"实测为真
解锁路径（§4.1 四步）：锁定成立=true ｜ close_session 之后正确令牌被放行=**true** ｜ sweep_idle 之后仍被拒=true
                       ⇒ "不对称确实存在"与"close_session 确实解锁"都实测成立
武装侧时间余量：窗口 100/20/4/1 ms 下 6 次连续注入都能武装（复算台每次数微秒）
                       ⇒ 只证明"判定逻辑不吃这点余量"，不证明仓内 e6 不假红（见下面边界第 2 条）
```

⇒ **R7-W-1 的实测支撑**：新语义把"绝不锁定"从旧语义的**不可持续**（4 条终身、随即被锁）变成
**稳态 4 条/行/窗口**，把"接受被锁"从 1 条/行/窗口抬到 5 条/行/窗口（**5.0×**）；
而在同一份夹具里换来的可用性收益只有 **99.8% → 96.9%（3 个百分点）**。
代价与收益的这个不对称，就是 R7-W-1 要求登记却没登记的那句话。

**效力边界（引用本台结果时必须带上，不许越界读）**
1. 跑的是**我摘录的实现 + 我转录的夹具**，不是本仓的 61 单测与 90 条期望：`record()` 审计落账、
   `max_sessions`/`max_browser_sessions` 准入、`.part` 文件、`constant_time_eq` 的真实实现都不在内。
   所以"0/59 全绿"的严格读法是：**"在我复刻的 46 条单测断言 + 13 条契约断言里，没有任何一条的通过与否
   依赖这一行"**。要把它升格为对全仓的陈述，还差 55 条与节流无关的单测——我 `grep` 核过全仓只有 `:1467`
   一处调用 `forget`、只有 `:846` 一处写升级分支，所以这个外推我判断成立，
   但**请实现方在 Linux 上把 M-forget-removed 与 M-escalation-removed 两行配方真跑一次以闭合**。
2. 复算台里 6 次注入在 1 ms 窗口内也完得成，**不能**据此说仓内 e6 不会假红，也不能反过来用
   "100 ms ≥100× 余量"去否定长尾风险：真探针每次 `authenticate` 还多一次审计落账，且与
   `cargo test` 其余线程并发、还吃 `SandboxRoot::open` 的文件系统开销，llvm-cov 插桩运行按本仓
   知识条目 `coverage-run-flaky-timing-test` 会把耗时放大约 20×。R7-N-11 讲的是这个登记缺口。
3. 占空比那两行的绝对注入次数（60 万条）是本机吞吐，不是产品能力；可外推的只有结构与比率。
4. 复算台与它打印的开关语义都是我写的；**开关如果和案卷描述的改法不一致，本表全部作废**——
   每个开关都写了它对应仓内哪一行、改成什么，可逐条核对。

---

## 6. 问题 F —— 案卷与数字自洽（全部 `[核]`，方法披露）

| 案卷声称 | 我实测 | 结论 |
|---|---|---|
| "61 单测（`cargo test --lib`）" | `grep -c '#\[test\]'` 逐文件：file_service 36 + config 15 + protocol 6 + cert 2 + gateway 2 = **61** | **一致** ✓（`tests/gateway_e2e.rs` 另有 21 条，不属 --lib，口径正确） |
| "90 条期望 / 9 场景" | 9 个 `gateway_file_*.toml` 的 `[[expect]]` 分别 13/7/10/6/16/9/15/5/9 = **90** | **一致** ✓ |
| "auth-throttle 13 条" | 13 | **一致** ✓ |
| "sftp-boundary 15 条" | 15 | **一致** ✓ |
| "`58 → 61`，本批新增 3 条单测" | `[核]` `git show HEAD:.../*.rs` 逐文件求和 = **58**（file_service 33 + config 15 + protocol 6 + cert 2 + gateway 2）；工作树 = **61**（file_service 36）；`git diff HEAD` 里新增的 `#[test]` 恰为 3 条（`lockout_requires_failures_inside_one_window`、`throttle_identity_keys_do_not_collide_on_prefix_or_concatenation`、`expired_locks_are_reclaimed_instead_of_escalating_to_the_global_window`） | **一致** ✓（58 与 r6 落地提交报的数字对得上，+3 也对得上；我最初按 diff 片段数成 2 条是**我这边看漏**，订正记录在此，避免下一轮误引） |
| "`contract_hash` `e166ea79…`（只覆盖 scenarios/**/*.toml）" | 我按 `engineering/nexus-harness/src/env.rs:187-216` 的定义（`scenarios/<子目录>/*.toml` 按名排序、`"scenarios/{d}/{n}\n" + 原文`、`\n===\n` 连接、`git hash-object --stdin`）复算：**用 HEAD 树**得 `8f510129cd7d9bef054d2324a4517fc534ab9806`（= r6 案卷数字 ✓ 说明方法对）；**用本批内容（把 auth_throttle.toml 按 `.gitattributes text=auto` 归一成 LF）** 得 `e166ea79359b6559165e6b6af263fc3b74c5ee79` = **案卷数字一致** ✓ | **复算成功** ✓（420070 字节，+939 相对 HEAD） |
| 同上，Windows 脏树（CRLF） | 同一内容不归一直接算得 `c3e352b7d87298826c144b8e40d13d7d803d6846` | ⇒ `contract_hash` **对行尾敏感**；案卷未声明"只在 LF 树可复算"，而 harness 用 `read_to_string` 读**裸字节**（`env.rs:205-208`）⇒ 在 Windows 上跑 verify 会得到不同的 contract_hash，`requirement-change: <hash>` 锚点随宿主行尾配置漂移 → R7-N-2（这是 provenance 面的真问题，值得单独一条知识条目） |
| "三棵树 b968081 / a9fad4d / 1ab58b1 代码与契约字节相同，差异只在本文字" | `git diff --stat` 两两之间只动 `.agents/green-evidence-...txt`；`git diff <tree> -- src/ examples/ scenarios/ MODULE.md PRODUCT.md` 全空 | **一致** ✓ |
| "9 门全 PASS / clippy 零诊断 / 实测 94%→（已删）" | 本机不可编译，**未复现**；我不把它们当作任何可读事实的替代证明，也不复述为"已验" | 不采信、不反驳（按 AGENTS 口径如实声明） |

`[核]` 顺带：`grep -rn IDENTITY_LABEL_MAX_BYTES` 全仓只剩 r6 案卷里的历史引用，代码/文档无残留 ✓；
`grep -rn 84.4` 只有 PRODUCT:3312 一处（V1 时代数字，本批未重新测量）。

---

## 7. 发现明细（按严重级）

### WARN

**R7-W-1（代价登记不完整：聚合猜测率）**
定位：`crates/nexus-web-gateway/src/file_service.rs:764-794`（`decay`）、`815-855`（`record_failure`）、
`crates/nexus-web-gateway/MODULE.md:182-185`、`PRODUCT.md:3319-3321`。
`[算]` 默认参数下节流器允许的可记录失败速率上界：不触发锁定 68.27 次/s、接受锁定 85.33 次/s，
而旧语义为 17.07 次/s；PRODUCT 唯一的速率锚点是 84.4 次/s（"零节流"）。契约只写了"慢滴不会被锁死"
这一每身份侧代价，没写"表位回收把 `max_throttle_buckets × lockout_after / lockout_window` 变成
**每窗口可续的额度池**"这一聚合侧代价，也没有任何期望测它；同时 r4 的实测"94% 拒止"整句被删，
没有替换数字（我算的对应值是 83.1%）。**这不是"文档说过比代码更强的话"，而是代码的代价比文档大。**
修法：G15 与 PRODUCT 各加一句聚合口径（可直接写我上面那个表达式），并把它标为未测；
或者加一条探针字段 `throttle_aggregate_guess_rate`（按"每窗口灌 `max_buckets × (lockout_after-1)` 条失败
且不武装"的夹具统计记录下来的失败条数），让这句话有可红对象；
根治方案是给 `source` 单独设一道限额（现在整张表按"对"分桶，一个源就能占满 1024 行）。

**R7-W-2（`forget` 零杀伤力 + 注释理由不实）** 见 §4.3。定位：`file_service.rs:900-912`、
`1458-1477`、`1480-1500`；`examples/gateway_file_contract.rs:569-575`。
`[算]` 删掉 `forget` 两行 ⇒ 61 单测 + 90 期望全绿；`sweep_idle` 不清锁这条"有意的不对称"两侧都无测。

**R7-W-3（升级分支不可达，但被写成机制）** 见 §3.2 的证明。定位：`file_service.rs:843-851`、
`MODULE.md:167-170`。修法：照 r4 对 R3-N-1 的先例，明写"经 `authenticate` 不可达，仅在
`locked` 回收失效（M9 类缺陷）或直接使用 pub API 时可达 —— 保留作纵深防御"，并把 G15 的
"表满时 fail-closed"改成"表满时由**溢出计数**升级为全局窗口（`locked` 占满是同一后果的第二道保险）"。

**R7-W-4（对被删方案的历史描述为假，且与同片注释冲突）**
定位：`MODULE.md:159-161` vs `file_service.rs:739-744`、被删的 `bounded_key`/`IDENTITY_LABEL_MAX_BYTES`。
`[读]` `bounded_label(principal, 128)` 恰恰**封住了标签字节数**（128 + `…[+NB]` 标记），所以旧方案
是"项数 ≤1024 且每行 ≤ ~300 B"，不是"只有项数有界"；Rust 侧注释写的 "bounded the *labels* while still
allocating a `String` per half per bucket" 才是对的。摘要键的真实收益是每行 ~300 B → ~48 B 的**常数**收益
（外加消除定向锁定面），把常数收益说成"从无界变有界"会让下一次评审把 R5-W-4 误判为"本批才闭合"。
修法：G15 那句话改成与 `:742-744` 同一口径。

**R7-W-5（requirements 侧漂移，门禁看不见）**
定位：`crates/nexus-web-gateway/requirements.toml:89`（REQ-010 acceptance）vs
`file_service.rs:903-907`、`MODULE.md:171-178`。
`[读]` acceptance 仍写"（会话+源）两层键…**随会话回收清零**"：(a) "会话回收"清的是 `close_session`，
闲置回收**不**清（本批刚在注释里强调这是有意的）；(b) 新的"按窗口衰减"没进 acceptance；
(c) "会话+源"应为"主体+源"。`[核]` `env.rs:187-216` 的 contract_hash 只覆盖 `scenarios/**/*.toml`
⇒ requirements.toml 的漂移不会改变任何哈希、不会被任何门禁抓。修法：acceptance 改写为
"（主体+源）成对键（定长摘要）节流；桶与溢出计数按 `lockout_window` 衰减；显式 `close_session` 清该对的
在途状态，闲置回收不清"。

**R7-W-6 —— 撤销（原判被实测否证，降级为 R7-N-11）**
我最初判"三处时间夹具在武装侧零余量"。复算台实测否证了它：把窗口从 100 ms 一路压到 **1 ms**，
6 次连续注入**照样武装**（`armed_before=true`），说明本机这段调用的耗时 < 1 ms、`e6` 实际余量 ≥100×。
⇒ 撤回"零余量"与"案卷的说法读者会低估"两处措辞；残留的部分（墙钟依赖、时钟不可注入、
未登记 flaky 面、案卷余量口径只写静置侧）记为 **R7-N-11**，方法与数据见 §5.5 与 §5.6。
（按 AGENTS 的口径，评审者自己被判据驳回的判断也要留痕，不能只留对的那一半。）

**R7-W-7（归因残余没进契约）**
定位：`file_service.rs:739-762`（表里只剩摘要）、`1101-1109`（注释只说"节流键不走裁剪"）、
`2375`（审计 `bounded_label(principal, 256)`）、`MODULE.md:157-188`（通篇未提归因）。
`[算]` 两条 principal 若前 256 B 相同且总长相同，在审计环里**渲染成同一串**（`…[+NB]` 标记里的 N 也相同），
而它们的摘要不同 ⇒ 是两个桶。于是"谁被锁了"在长身份面上失去近似归因；反向也成立：
审计里看着同一条的两行，可能来自两个不同桶。案卷自述把这条登记为"显式取舍"，但**取舍没写进 G15/PRODUCT**
——按 r6 NOTE-4 的先例（当时正是因为"碰撞族没写进契约"才立案），这条同样应该进契约面。
修法：G15 加一句"节流表不保存可读身份；归因依赖审计环，其 principal 有 `AUDIT_FIELD_MAX_BYTES` 截断，
长身份只能归因到'前 256 字节 + 长度'这一近似类"。

### NOTE

- **R7-N-1** 三处案卷/注释数字：`file_service.rs:835` "60 条单测" 应为 61 `[核]`（36+15+6+2+2）；
  变异表 M8"计数永不触达阈值 → RED 3 条"偏保守 `[算]`（我按"单桶阈值比较恒假"理解时至少 4 条确定红，
  见 §5.4 该行）；案卷正文"探针 e5/e6 的时间夹具余量 4×、2×"只描述静置侧（见 R7-N-11）。
  三处都不影响判定。**58 → 61 与"新增 3 条单测"我核为正确**
  （订正过程见 §6 表倒数第三行，我自己初查时看漏了一个 hunk，如实记录）。
- **R7-N-2** `contract_hash` 对行尾敏感（§6 复算细节）。建议：把"归一化后复算"的方法写进案卷，
  或在 `env.rs` 的 contract_hash 里对内容做 `\r\n → \n` 归一（那属于 harness 侧改动，本轮只登记）。
- **R7-N-3** `MODULE.md:173` 病句："既是对话被锁的时长" ⇒ 应为"身份被锁的时长"。
- **R7-N-4** `scenarios/product/gateway_file_auth_throttle.toml:67-69` 与案卷末尾对 `flood_armed_before_quiet_window`
  的"防空转"说法不成立（合成式已含 `armed_before`）；真实作用是定位。`e5` 侧注释"取值时机"那句同型
  （取晚了的后果是恒不成立，不是空转，见 §5.2）。
- **R7-N-5** `[算]` **"不同源不受牵连"这条性质在 61 单测里只有 `:2821` 一处断言，在 90 期望里没有断言。**
  我逐条枚举了引用 source 维度的断言：单测 `:2821`（`authenticate("attacker","10.0.0.2",s3cret).is_ok()`）
  与 `:3155-3166`（同一 source 下比较主体/拼接，不比 source）；其余夹具（`lockout_rearms` 的 flood0..7、
  `expired_locks`、`throttle_fails_closed`、`e4`、`e5`、`e6`）都是**同一身份配同一源**，source 半被丢弃
  也观察不到差别。⇒ **删掉 `:2821`（或让 `identity_key` 少喂 source 半）⇒ M6 在单测面与场景面同时全绿**。
  探针侧唯一能杀 M6 的字段 `other_source_still_admitted`（`examples:560-561`）**未被任何期望冻结**，
  而 `e5` 的两个合成式（`throttle_identity_prefixes_are_separate_buckets`、
  `victim_code_after_forged_prefix`）在"摘要忽略 source"下仍然真（forged/victim 的 principal 不同，
  且二者与 `"10.0.0.10"` 的长度前缀组合互不相等，我逐字节核过）⇒ 契约面对 M6 是瞎的。
  同族：本批新增的 `throttle_rows_before_victim_success`（`:633-636`）也未冻结（R3-N-4 欠账 +1）。
  修法：给 `other_source_still_admitted` 补一条 `[[expect]] equals = true`（1 行，且立刻让 M6 在 E4 面可红）。
- **R7-N-6** 长度前缀性质（M3）只有单测，无 E4 期望。
- **R7-N-7** `file_service.rs:121-123` `max_throttle_buckets` 字段文档："beyond that, oldest buckets are
  merged into the global bucket" `[读]` 本批之后三处失真：进溢出人群的不是"oldest buckets"（是按对新建的行）、
  不是"merged"（另立全局计数）、过期桶是**被遗忘**而非被并入。
- **R7-N-8** `identity_key:755-762` 对调用方可控长度无上界 `[算]`：1 MB principal × 84.4 次/s ≈ 84 MB/s
  摘要开销（SHA-256 量级下 <5% 单核），不足以立案；但"未认证者可决定的 CPU"这句在 G15 里没有条目，
  建议随 `files` 配置接线（M1 剩余项）一起处理。
- **R7-N-9** 身份键字节精确、无 Unicode 归一/大小写/尾空格处理 `[算]`：同一自然人可造任意多桶
  （NFC/NFD 两份、尾空格若干），在表满之前不受 fail-closed 约束 ⇒ 与 R7-W-1 同向，属于"per-source 限额缺失"
  的同一根因；另 `source` 的可信性仍是**前提**（`MODULE.md` 里"source 必须是不可被对端影响的传输地址"
  这句在 G15 重写后没有随附引用，摘要键不改变这个前提）。
- **R7-N-10** `[核]` **§18 的产品面没有被任何门禁跑过**，而本批恰恰动了产品面两处：
  (a) `harness.toml:65-67` 把 `scenario:product.gateway-file-*` 配成
  `required_artifact_kinds = ["ReviewRun"]`、`min_actor_independence = "L2"`，而
  `engineering/nexus-harness/src/gates.rs:675-683` 的实现是：**artifact_kinds 里出现了 "ReviewRun"
  就直接 `GateResult::blocked(..., "ReviewRun not yet supported")`**（紧接的
  `:685-689` 那条"Scenario verdict is PASS"分支因此永不执行）。全仓 `grep -rn '"ReviewRun"'`
  只有 harness 的测试夹具与这一段实现，`engineering/evidence-schema/evidence.schema.json` 的枚举里也没有
  ReviewRun ⇒ **9 条 `gateway_file_*` E4 场景在 `verify` 里全部判 BLOCKED**，不是 PASS。
  (b) `engineering/nexus-harness/src/requirements.rs:106-120` 的 `product_section_has_items` 只解析
  `### 18.1`（`PRODUCT.md:3290-3299`，条目齐全 ✓），
  而 `crates/nexus-web-gateway/requirements.toml:79/89/97` 三条 REQ 的 `product = "PRODUCT.md#18"` 指的是
  整个 §18 —— 于是本批改写的 **§18.2「鉴权与节流」（`PRODUCT.md:3311-3322`）与 §18.3 平台分级表**
  **不在任何门禁的解析范围内**。⇒ 直接后果：R7-W-5（`requirements.toml:89` 的"随会话回收清零"漂移）
  既不在 contract_hash 里（只覆盖 `scenarios/**/*.toml`），也不在 `product_section_has_items` 的检查面里。
  本轮不把它升级成 WARN，因为它是 harness 侧既有形状、不是本批引入；但案卷里"场景跑绿 = 产品契约被机器
  核过"这句要按上面两条打折。修法（一行）：`requirements.rs:107` 改成
  `format!("### {}.", section + 1)` 并把标题定位从"精确匹配"放宽为 `starts_with("### 18.")`。
- **R7-N-11**（由 R7-W-6 降级而来）三处时间夹具依赖真实墙钟：`examples/gateway_file_contract.rs:653-682`
  （w=100 ms）、`src/file_service.rs:3083-3113`（w=200 ms）、`2958-3071`（w=300 ms），而 `Throttle`
  六处硬编码 `Instant::now()`（`:797/816/867/878/888/897`），`FileEngine::sweep_idle(now)` 已示范可注入时钟。
  `[核]` 复算台实测：窗口压到 1 ms 时 6 次连续注入照样武装 ⇒ 本机余量 ≥100×，**所以我原判的
  "武装侧零余量"不成立并已撤回**；仍然成立的两点：(a) 案卷"余量 4×、2×"只报了静置侧，
  读者无法判断武装侧有多少余量（应把两侧都写出来，并注明是推算还是实测）；
  (b) llvm-cov 插桩运行会把耗时放大约 20×（本仓知识条目 `coverage-run-flaky-timing-test` 的先例），
  ≥100× 不是被门禁保证的性质。修法：把窗口做成参数（`decay(now)` 已有，缺的是读侧四访问器与
  `is_locked`/`record_failure` 内部的 `Instant::now()`），或按 `coverage-run-flaky-timing-test` 的格式
  登记"auth-throttle 的 3 处判据依赖真实时钟"。
- **R7-N-12** 本卷 §5.6 的实测产物在**仓外会话目录**（`…/sessions/…/c2283260c5da99a5d2076c04/r7rig`），
  下一位评审者拿不到、也无法复算 ⇒ 案卷里"0/59 全绿"这类结论对**本仓门禁**是不可复核的。
  `[读]` AGENTS 第 4 关要求"测试杀死评审者设想的每一个 bug"，仓库侧的补法有两种：
  (a) 把两条"全绿"配方固化成仓内 `#[test]`——`close_session 解除个体锁` 与
  `个体锁只能由锁表占满触发（经 authenticate 不可达）`，都用 `Throttle::new(...)` + 直接
  `record_failure`/`forget`，**不需要时间夹具**；(b) 若希望保留"红/绿可复算"的机器证据，
  把复算台落进 `crates/nexus-web-gateway/examples/` 或 `fuzz/` 并登记进 `FILE_MANIFEST.md`。

---

## 8. 给下一片的整改清单（按可操作性）

1. G15 + PRODUCT 各加一句聚合口径：`max_throttle_buckets × lockout_after / lockout_window` 是**默认参数下
   可记录失败的速率上界**（本批算得 85.33 次/s），并明写它未被测（R7-W-1）。
2. 把 r4 的"94% 拒止"换成新的可复算量（我算的持续洪水占空比 ≈ 83.1%，武装成本 ≈ 1029 条/窗口），
   或加一条期望（R7-W-1）。
3. 给 `source` 设一道独立限额或让全局窗口按"每源"武装，否则 1024 桶 = 一个 IP 的额度池（R7-W-1 / R7-N-9）。
4. `forget`：注释改成真实理由；补两条无时间依赖的单测（"close_session 解除个体锁"、"sweep_idle 不解除"）
   —— 直接用 `Throttle::new(...)` + `record_failure` + `forget`，不需要 sleep（R7-W-2）。
5. `record_failure:843-851` 的升级分支：注释与 G15 改口径为"纵深防御，经 authenticate 不可达（附本卷 §3.2 证明）"
   （R7-W-3）。
6. `MODULE.md:159-161` 与 `:173` 两句改写（R7-W-4 / R7-N-3）。
7. `requirements.toml:89` acceptance 改写（R7-W-5）。
8. 时间夹具：可注入时刻或放大武装侧窗口；并在 `.agents/knowledge` 登记 flaky 面（R7-W-6）。
9. G15 补归因残余一句（R7-W-7）。
10. 数字订正：`:835` 60→61、`max_throttle_buckets` 字段文档、案卷 M8/新增单测计数、
    场景与案卷的"防空转"口径（R7-N-1/-4/-5/-7）。
11. `contract_hash` 的行尾敏感性进知识条目；本批落地提交前确认 `git add` 后（normalized LF）
    harness 报的仍是 `e166ea79…`（R7-N-2）。

---

## 9. 本轮**没有**重审的部分（以及为什么不重复审）

- 预算/在途/终端优先（R1-R4 已闭环，本批未触碰 `SendBudget`；`git diff` 里 `file_service.rs` 的全部改动
  都在 `Throttle`、`AUDIT` 常量注释、`FileEngine::throttle_*` 访问器与节流测试区 `[核]`）。
- 路径解析/symlink/TOCTOU、`.part` 命名、审计环结构与 root 归属：本批未改。
- `lock_until` 的 `checked_add` 与 r6 NOTE-2 的回退分支：本批未改；R7 的衰减**不依赖**该分支，
  且我在 §3.2 用到 `lockout ≤ 24 h` 已由 `validate():199` 保证。
- `Throttle` 的 `derive(Default)`（r4 R4-N-5）：本批未修，也**没有**因为桶衰减而变得更危险或更安全
  （`Default` 下 `lockout=0` ⇒ `stale(0,·,·)` 恒真 ⇒ 计数恒为 1，与 r4 描述同构）。仍按 r4 的登记携带。
- `close_session` 的归属检查（r2 N-8）：本批未改签名；R7-W-2 只在"它能解锁"这一新语义面上提，
  不重开"谁能关谁的会话"。

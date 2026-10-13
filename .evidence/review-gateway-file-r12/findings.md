# review-gateway-file-r12 — 独立评审 findings（第 12 轮，重派）

被审树：`/work/r12-audit` @ `6e7bd0959c053ca930a34bbba467ec8254e1f66d`（= `m0-verify` 通道 ref，实测相等），宿主 `xc-pc-linux`（rustc/cargo 1.98.1 / x86_64-unknown-linux-gnu）。
上一位评审者在第 24 步被模型中断、没有产出任何案卷；本轮是其重派，我只复用它的克隆与 target 目录（省编译），所有数字都由我自己重跑。Windows 侧无法编译本 crate（ssh2 0.9.6 的 `userauth_pubkey_memory` 受 `cfg(any(unix, vendored-openssl, openssl-on-win32))` 门控，本机无 cl.exe/nasm），故不存在任何 Windows 数字。

**verdict：COMMENTED（0 FAIL / 1 WARN / 3 NOTE）** — 范围只覆盖 r11 两条 WARN 的落地是否诚实。

---

## 必答三问

### Q1 消费点到底几处：**五处，没有第六处**

我自己 grep `source` 的全部读写点（`crates/nexus-web-gateway/src/file_service.rs`）：

| # | 消费点 | 位置 |
|---|---|---|
| 1 | per-peer 会话配额 `held_by_peer = sessions.values().filter(\|s\| s.source == source).count()` | :1737-1741 |
| 2 | 单源额度源账本 `charge_source` → `source_key` → `source_failures` | :983-1000 |
| 3 | 源锁 `is_locked` 里的 `source_locks.get(&skey)` 与 `arm_source` | :894-897 / :1005 |
| 4 | `close_session` 归属 `if s.source != source` | :1810 |
| 5 | `(主体,源)` 两层摘要键的源半 `identity_key` | :820-826，调用点 :877 / :903（并经 :906 进源侧）/ :1148 |

第六处候选两个，都判**不算**（这里的取舍必须给理由，不能含糊）：
- **审计行/会话记录**：`record(session, principal, root, action, rel, result_code)` 的六格入参**不含 source**（:2710-2717）；全文件 `grep -n '\.source\b'` 的读点只有 :1738 与 :1810——`FileSession.source` 的**存储**本身就是消费点 1 与 4 的前件，不是独立的第三个读点。
- **错误消息回显** `peer {source:?}`（:1745）：只把调用方自己申报的串回显给它，不产生任何跨请求状态，也就无所谓"表示漂移改变这一处的额度/门槛"。计成消费点会稀释清单里真正需要 M2 逐处核的条目。

四份文本一致性：MODULE.md:363-379（"五件事"/"现在五处共用它"）、requirements.toml:89（"五个消费点——…；只数四处的旧写法已作废"）、file_service.rs:1797-1800（doc："五个消费点；r11 R11-W-2 抓到早先这里数成三处"）、gateway_file_contract.rs:974-975（探针注释同五点）；漂移单测注释 :3875-3877 也写五点并点名 r11。名单同构（REQ-010 的"源账本"= G16 的"单源失败额度"= `source_failures` 同一张表），无互相矛盾。

### Q2 "pair 侧门槛翻倍"这一格：**被过度声称，判 WARN（已实测，非纸面）**

有界变异实测（按任务书授权，只动 `Throttle::identity_key` 喂 source 的那半，跑完 `git checkout --` 复原）：
把 `h.update((source.len() as u64).to_le_bytes()); h.update(source.as_bytes());` 换成 `let _ = source; h.update(b"source-blind");` ⇒

- `cargo test -q --lib -p nexus-web-gateway` ⇒ 69 passed / **3 failed**：
  `throttle_identity_keys_do_not_collide_on_prefix_or_concatenation`（红在 :3537 那句 `源地址同样不得被并进同一条键`）、
  `lockout_refuses_even_the_correct_token_and_stays_bounded`（:3181）、
  `address_representation_drift_arms_two_independent_source_locks`（红在 :3915 `两种写法各自武装一道源锁` left 0 / right 2）。
- `nexus-harness scenario run product.gateway-file-auth-throttle` ⇒ FAIL，`assertion = other_source_still_admitted`；dump 里另有 `address_representation_drift_splits_the_source_budget = false`（**2 条**期望变 false，harness 在第一条停下所以只点名一个）。

判定分两层：
1. **机制被真钉住了**：契约点名的两条对象确实都因"摘要不吃 source"而红 ⇒ 这一半不是过度声称，案卷说"既有对象、继承关系"是对的。
2. **数量后果没有被钉住**：没有任何对象断言"同一地址两种写法 ⇒ 单身份两个桶 ⇒ 需 2×`lockout_after` 条失败才武装 pair 锁"。漂移单测刻意把最后一跳换成从没失败过的主体 `dual`（:3929-3934 注释明写"让『是谁把这次请求拒了』没有第二种解释"），它在摘要不吃 source 时红在**源锁**那一格，且原因是两个写法被并进同一个 pair 桶后**提前**武装、把源额度短路——那是"门槛翻倍"的**反面**。冻结期望 `other_source_still_admitted` 用的是两条**不同**地址（10.0.0.1/10.0.0.2）和一个布尔准入判定，既不涉写法漂移也不数到阈值。

因为案卷 `.agents/green-evidence-gateway-file-service-m1.txt:1159-1163` 已明写"把它们当那一格的证据是**继承关系，不是点名覆盖**"（自述层诚实、代码无缺陷）⇒ WARN 而非 FAIL；但 requirements.toml:89 作为后来人据以核对的契约文本，写"这两格都有**机验对象**"并用"⇒"把翻倍当结论交付，不带那句 hedge。

**处方（要什么样的断言才钉得住）**：夹具 `Throttle::new(buckets, lockout_after=3, window, max_source_failures 足够大)`；对**同一 principal** P 交替喂 `S1="2001:db8::1"` / `S2="[2001:db8::1]:44337"` 共 `2*(lockout_after-1)=4` 条失败，断言 (1) `!is_locked(P,S1) && !is_locked(P,S2)`（单身份总门槛是 2×lockout_after）；(2) 再补 `lockout_after` 条只打 S1 ⇒ `is_locked(P,S1)` 而 `!is_locked(P,S2)`（两桶独立武装 ⇒ 翻倍是加数不是取 max）；(3) `buckets()==2`（内存口径接 G15 代价 (3) 的地址数）。契约面再补一条同名冻结期望（探针里把 `lockout_after` 与 `max_failures_per_source` 错开，避免像现在这样被源锁抢答）。

### Q3 绑定与数字：**全部对上**

- `cargo test -q --lib -p nexus-web-gateway` ⇒ **72 passed / 0 failed**；独立数：`grep -c '#[test]'` cert 2 + config 15 + file_service 47 + gateway 2 + protocol 6 = **72**。
- `scenario run product.gateway-file-auth-throttle` ⇒ PASS，message 明写 **all 26 expectations held**（evidence_id `scenario-cdae8a846961`）。
- 九条 `gateway_file_*` 场景期望求和 26+7+10+6+16+9+15+5+9 = **103**（我逐文件 grep 相加）。
- `status --json` ⇒ contract_hash **2219448ed81870cbf67d1b4bd6cf93c63e5c51f4**、dirty_state false、toolchain 1.98.1 x86_64-unknown-linux-gnu、source_revision 6e7bd09、working_tree_digest c3a99b03ef73f711e41bfe328cf07315468252df。案卷那句"72/26/103/2219448e…"在这棵树上成立。
- 通道 ref：`git -C /work/m0-origin.git rev-parse m0-verify` = `6e7bd095…` = `/work/r12-audit` HEAD ⇒ "通道 ref 恒等于分支 HEAD" 已验，r11 R11-N-3 的"只有实现方自己能证"那段已消除。
- 纪律项：`git diff d0ace31 HEAD -- crates/nexus-web-gateway/src crates/nexus-web-gateway/examples scenarios` 滤掉 `//`/`///` 行后 **剩 0 行**（diffstat 14 增 10 删全是注释）⇒ 被量树 D072 的数字对当前 HEAD 仍可引用。

---

## 发现

### R12-W-1（WARN）契约把"pair 侧门槛翻倍"当已机验事项，实际只机验到机制
- 位置：`crates/nexus-web-gateway/requirements.toml:89`（末段"这两格都有机验对象…⇒ 漂移也会把单个身份的 pair 侧额度翻倍"）；对照 `MODULE.md:363-372`、`src/file_service.rs:3495-3545` / `:3873-3935`、`scenarios/product/gateway_file_auth_throttle.toml:100-104`。
- 复现：见 Q2 的变异配方与红名单（`git checkout -- crates/nexus-web-gateway/src/file_service.rs` 复原）。
- 处方：见 Q2。M2 接线前必须补点名断言，或在契约里把"⇒ 翻倍"改写为"机制已机验，翻倍是推论"。

### R12-N-1（NOTE）案卷把"PRODUCT §18.2 本来没写计数"记成"已对齐成五处"
- 位置：`.agents/green-evidence-gateway-file-service-m1.txt:1161-1163` vs `PRODUCT.md:3333-3345`。
- 实测：`grep -n '五个\|五处\|四处\|三处\|四个用途' PRODUCT.md` ⇒ 0 命中；§18.2 只写归属/空地址/不归一化三条，无消费点数字（不与五点矛盾，但也没有"改成五处"这回事）。
- 复现：`sed -n '3333,3345p' PRODUCT.md`。

### R12-N-2（NOTE）变异表只写结果不写配方，红数无法归因
- 位置：`.agents/green-evidence-gateway-file-service-m1.txt:1103-1105`（N13 行"RED 1 条 + 1 翻转"）。
- 实测：我在 6e7bd09 上跑"整半不吃 source"得 **3 红 + 2 false**；若配方是"只去长度前缀"则不同源串仍是不同键 ⇒ 漂移两条不会红。红数由配方决定，表里没有配方。建议每行补"替换前/替换后"两行字面量（案卷已有 /work/mm3-5.py 的锚点断言，摘要写进去即可）。判为**不可比**，不计入与案卷的分歧。

### R12-N-3（NOTE）R11-W-1 已落地，残余只是限定语形式
- 位置：`requirements.toml:89`、`MODULE.md:200`、`MODULE.md:305-309`（G15 代价 (5)）、案卷 `:1043-1045` / `:1088-1091` / `:1310-1312` / `:1318-1324`。
- 已核：契约改成"最终复验树 6+6（70 条那棵树是 5+6，多的那条正是后来新增的源锁过期回收测试）"；D1_always_clear_ledger 的 70/72 两写各自标树；原先无树的"70 条单测"已滚成 72；表头声明旧表属 70 条那棵树且不再引用。我在 6e7bd09 实测 72 全绿，与"最终树"口径自洽。
- 建议：契约里的树限定带短 sha（`d0ace31` / `c5d0918`）——案卷在 `.agents/` 下、不进 `contract_hash`，重编号后描述性限定会先失去指代。

---

## r11 两条 WARN 的处置判定

- **R11-W-1 → verified**：数字补了树限定，四处（契约 + 案卷三处）都在；我没有再找到不带树的旧数。
- **R11-W-2 → verified_with_residual**：五点名单统一到四份文本且与我的独立枚举一致，"一次登记齐"作废并改写；残余 = R12-W-1（机验强度分层没进契约）+ R12-N-1（PRODUCT 那句）。

## 合入决定

可合入（COMMENTED），blocking 为空。新增 1 WARN + 3 NOTE 全是契约/文本措辞与机验分层，无运行时缺陷、无绑定不符、无数字对不上。R12-W-1 的处方最迟 M2 接线前完成。

## 本轮未实测（诚实边界）

`verify --fast` 9 门与 evidence dir（案卷自报 verify-e6f5aabdd251 / ecaeaaa 那遍）未跑；clippy 未在 6e7bd09 重跑；contract_hash 取 harness 自报值、未按 `env.rs:188-216` 独立重算；D 轮 18 行只由我复跑 1 行（且配方不同 ⇒ 不可比）；N14 的 5+6 历史值沿用 r11 实测。以上一律读作"未复核"，不背书。

## 复原声明

我在 `/work/r12-audit` 只改过 `crates/nexus-web-gateway/src/file_service.rs`（变异），已 `git checkout --` 还原；离场实测 `git rev-parse HEAD` = 6e7bd09、`git status --porcelain`（含 `--untracked-files=all`）= **空**、`git diff --stat` = 0 行、未 push。未触碰 `/work/m0-verify`、`/work/m0-flake`、`/work/nexus-dev*target`；Windows 侧 `E:\nexus-fabric-m0` 一个字节没改。远端留下一份不在仓库里的转储 `/work/r12-scen.log`（已 `rm`）。本份案卷写在 `.evidence/review-gateway-file-r12/`——实测 `.gitignore:3` 的规则 `/.evidence` 会把这条路径整体忽略（`git check-ignore -v` 证实），所以它不进 `git status`；历史各轮（含 r11）的案卷是被 `git add -f` 强行纳入版本控制的，若要随分支携带 r12 这两份，实现方同样需要 `-f`（这是仓库既有约定，不是本轮的改动）。

---
name: harness-digest-sentinel-flake
description: nexus-harness 的 selected-properties 门偶发红不是时间夹具，而是并行测试并发调 git 时 working_tree_digest() 静默退化成哨兵 tree-unknown；附 harness 证据覆写与 pre-commit 第 4 关字典序两条同日实测
metadata:
  type: reference
---

2026-10-13 在 xc-pc-linux 上实测（rustc/cargo 1.98.1，树 `c5d0918`，`CARGO_TARGET_DIR=/work/nexus-dev/target`，
`CARGO_INCREMENTAL=0`），三条都属于 harness/门禁自身、不是 gateway 的缺陷：

**(1) `verify --fast` 的 `selected-properties` 门间歇 FAIL —— 红的是 harness 自己的单测**
- 门 = `cargo test -p nexus-harness`（`engineering/nexus-harness/src/gates.rs:280`）。
- 复现配方（**必须强制重建**才容易中）：`touch engineering/nexus-harness/src/env.rs` 然后
  `cargo test -p nexus-harness`；本轮 3 周期中 1、8 周期中 1。对照组：加 `-- --test-threads=1`
  连跑 4 轮（同样强制重建）**全绿** ⇒ 竞争面是并行测试之间。
- panic：`env.rs:317` `assertion left == right failed: working_tree_digest 两次取值不一致`，
  `left: "tree-unknown"`、`right: "c1f6c3ed…"`。也就是**同一函数两次调用之间 git 调用失败**，
  返回值走了降级哨兵分支。
- 该测试（`env::tests::digests_deterministic_and_sha1_length`）本身就是"哨兵不得算作一次确定
  取值"的守卫（它的注释明写早先版本被 `assert_eq!(f(), f())` 两次同哨兵蒙过去），所以红是
  **守卫正常工作**；真正的缺陷在生产路径：**取不到就静默发 `tree-unknown`，而这个值会被当作
  指纹写进 evidence 的 bindings**。
- 与已立案的 dirty `working_tree_digest` **内容盲**（分支 `fix/nexus-harness-evidence-binding`，
  待合入）是同一函数的两个独立缺陷：一个"算出来但对内容不敏感"，一个"有时算不出来却照发"。
- 别把它误诊成时间夹具：本仓那三类真墙钟夹具在
  [[nexus-web-gateway-verification-host]] 与 `2026-09-30-coverage-run-flaky-timing-test` 里。
  我第一次就猜错了对象（猜成 `run_parallel_keeps_order_and_verdicts` 的 sleep 交错），是
  `--test-threads=1` 对照组把它否掉的。

**(2) 同 bindings 的 `verify` 覆写上一份证据 ⇒ 偶发失败的取证面丢失**
- 证据目录是内容定位的（`verify-<按 bindings 算出的 id>`），`write_evidence` 无条件覆写
  `summary.json`/`gates.json`（`engineering/nexus-harness/src/evidence.rs:128-162`）。
- 后果：FAIL 的那一次只要后来复跑一次绿，目录里剩下的就只有 PASS。本轮两位操作者各中一次
  FAIL，两次都在复跑后失去了诊断。
- 修法方向：写前检测已有记录并按序落 `verify-<id>-N.json`，或把 `gates[].detail` 的原始输出
  尾巴另存 `gate-logs/<gate>.txt`。

**(3) `.githooks/pre-commit` 第 4 关取"最新 review 目录"用的是字典序**
- `ls -1d .evidence/review-* | sort | tail -1`：字典序下 `…-r10` 排在 `…-r9` **之前**，
  所以第 10 轮案卷落盘之后，门认可的是 **r9**（本机实测：`sort` ⇒ r9，`sort -V` ⇒ r10）。
- 修法方向：`sort -V`，或直接按 `summary.json` 里的 `review_round` 取最大值。
- 沟通口径：提交说明里要写清"本提交通过的是哪一案卷"，别让读者以为他点名的那一轮被门看过。

相关：[[nexus-web-gateway-verification-host]]、[[nexus-harness-contract-hash-scope]]、
[[feedback-independent-review-artifact-rules]]、[[nexus-standing-authorizations]]

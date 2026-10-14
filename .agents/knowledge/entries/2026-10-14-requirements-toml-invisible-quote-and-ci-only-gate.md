---
name: requirements-toml-invisible-quote-and-ci-only-gate
description: requirements.toml 自 REQ-010 起就不是合法 TOML（acceptance 串里嵌未转义的 ASCII 双引号），因为本地 9 门不校验它、只有 CI 校验且 CI 日志读不到；附修复口径与本地可跑的校验配方
metadata:
  type: reference
---

2026-10-14 在 xc-pc-linux 上实测（host python 3.8.10 + `tomli`，被校验文件为分支
`feature/gateway-file-service-contracts` 的树 `ec3e069`）：

**(1) 事实：`crates/nexus-web-gateway/requirements.toml` 解析失败**
- `tomli.load` ⇒ `TOMLDecodeError: Expected newline or end of document after a statement
  (at line 89, column 577)`。line 89 就是 `REQ-010` 的 `acceptance`。
- 跑真正的校验脚本（`crates/nexus-web-gateway/tools/validate-requirements.py`）⇒
  `ERROR: parse error: ... / FAILED: 1 error(s) / exit code: 1`。
- 原因不是罕见语法，而是一个habit：**中文行文里用的 ASCII 双引号 `"…"` 直接写进了
  TOML basic string**（`acceptance = "…断言"交替喂…"…"`）。串内的 `"` 必须转义，
  否则解析器在第一个内层引号处就终止该语句。REQ-010 有 8 个内层引号，我新加的 REQ-014
  带了 10 个——是同一个习惯第二次写进来才被发现。

**(2) 为什么它活了这么久（这条比缺陷本身更重要）**
- 门禁集不覆盖它：`nexus-harness verify --fast` 的 9 门是 whitespace / format / check /
  clippy / architecture-policy / dependency-governance / resource-type-neutrality /
  affected-tests / selected-properties，**没有 requirements 校验**。
- 唯一校验它的是 `.github/workflows/gateway-ci.yml:25` 的 `validate-requirements` job，
  而本仓库匿名 API 取不到 CI 日志（见 [[reference-nexus-fabric-github]]），
  所以我这边没有任何一条路径真的解析过这个文件——它坏了多少个提交都没人知道。
- 本地也跑不动那个脚本：脚本用了 `tomllib`（需 python ≥3.11）和模块级 `list[str]`
  注解（需 ≥3.9），xc-pc-linux 的 python 是 3.8.10，直接执行会
  `ModuleNotFoundError: tomllib` / `TypeError: 'type' object is not subscriptable`。
  ⇒ "脚本存在"不等于"脚本可跑"，更不等于"有门在跑它"。

**(3) 修复口径（本次已落地）**
- 把 14 条 `acceptance = "…"` 全部改成 TOML **literal string** `acceptance = '…'`
  （改前先确认文本里没有 `'` 和 `\`，本次 14 条全部满足，`skipped = none`）。
  literal string 里 `"` 无特殊含义，中文行文里的引号因此不会再破语法；
  代价是串内不再有转义语义（本文件不需要）。
- 改完 `validate-requirements.py` 输出 `OK: requirements.toml valid`。
- `contract_hash` **不受影响**：哈希只覆盖 `scenarios/**/*.toml`
  （见 [[nexus-harness-contract-hash-scope]]），requirements/MODULE/PRODUCT 都在哈希外。

**(4) 本地校验配方（python 3.8 可用，无需升级）**
把脚本源码读进来、前置 `from __future__ import annotations`、把 `import tomllib`
替换成 `import tomli as tomllib`，再 `exec`；`sys.argv` 指向待校验文件。
本次用的 shim 落在 host `/work/vrshim.py`（临时文件，未入库）。同一 shim 对修复前后的
两个文件分别给出 exit=1 与 exit=0，这就是这条缺陷的 RED 与 GREEN。

**(5) 结转**
- 给 nexus-harness 提第 4 条门：**requirements.toml 校验应进 `verify` 的门禁集**
  （现在它是 CI-only，等价于本地永远绿）。与已有的三条（digest 静默降级、
  evidence 覆写、pre-commit 第 4 关字典序）同批立案，见任务 #36。
- 推广一句：**任何只被"外部系统"读、不被本地门读的文件都会腐烂**。写文档型契约时先问
  "谁解析它，解析器在我这边跑不跑"，答不出来就顺手加一个本地校验对象。

相关：[[nexus-harness-contract-hash-scope]]、[[nexus-web-gateway-verification-host]]、
[[feedback-independent-review-artifact-rules]]、[[reference-nexus-fabric-github]]

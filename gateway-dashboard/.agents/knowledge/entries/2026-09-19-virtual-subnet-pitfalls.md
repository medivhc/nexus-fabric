---
id: vsub-pitfall-001
date: 2026-09-19
module: nexus-connectivity
category: implementation-pitfall
task_type: feature
---

# 虚拟子网组网 P0 实现踩坑记录

## 问题 1：scenario expect 路径嵌套错误

**现象**：product-scenarios gate 失败，报 `expect product.virtual-subnet-tunnel.subnet.cidr failed (actual: <missing>)`。

**原因**：`run_scenario` 函数把结果嵌套在 `result` 字段中（`vec![("result".to_string(), result)]`），但 scenario 的 expect 路径是直接写的 `subnet.cidr`，没有 `result.` 前缀。

**修复**：把结果字段直接放到 `extra` Vec 的顶层，不要嵌套在 `result` 里。

**教训**：新增 scenario 命令时，先手动跑一次 `nexus-harness run <subcommand> --json`，确认 JSON 结构与 scenario expect 路径一致。

## 问题 2：MemoryCarrier 缺少 Default impl

**现象**：clippy 报 `method \`new\` is never used` / `this function takes \`&self\` but trait \`Default\` was not implemented`。

**原因**：为 MemoryVpi 实现了 Default，但 MemoryCarrier 只写了 `new()` 方法，没写 `Default` impl。

**修复**：补一个 `impl Default for MemoryCarrier { fn default() -> Self { Self::new() } }`。

**教训**：测试工具类型如果写了 `new()`，就顺手把 `Default` 也加上，避免 clippy 警告。

## 问题 3：rsplitn 已被 rsplit_once 替代

**现象**：clippy 报 `using \`rsplitn\` followed by \`nth(1)\` is slower and less readable than \`rsplit_once\``。

**原因**：Rust 1.52+ 引入了 `str::rsplit_once()`，比 `rsplitn(2, '.').nth(1)` 更直观。

**修复**：直接用 `cargo clippy --fix --allow-dirty` 自动修复。

**教训**：写完代码先跑 `cargo clippy --fix`，自动修复小问题，不要手动一个个改。

## 问题 4：PowerShell 转义地狱

**现象**：用 PowerShell 做字符串替换时，反引号、单双引号嵌套非常容易出错。

**原因**：PowerShell 的转义规则和 Unix shell 完全不同，多行字符串中的引号很容易破坏语法。

**修复**：对于复杂的字符串替换，直接用 Python 或写个临时脚本文件，不要硬写在命令行里。

**教训**：PowerShell 命令行只做简单操作，复杂的文本处理写临时 .ps1 或 .py 文件。

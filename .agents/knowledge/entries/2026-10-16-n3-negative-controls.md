---
id: n3-neg-ctrl
title: 拒绝测试必须排除更早的无关失败
tags: [n3, authorization, test-review, localapi]
module: apps/nexusd
severity: high
source: review
date: 2026-10-16
related: [n3-localapi-mutual-auth-boundaries]
---

## 问题描述

外部主体对尚未上传完整的记录调用 Seal，即使实现遗漏 owner 检查，也可能因内容不完整返回错误；单独的 `is_err()` 无法证明授权边界有效。客户端响应矩阵也有同类风险：mock peer 默认使用 HTTP/1.0 时，所有非法 DTO 都可能被更早的 HTTP framing 校验拒绝。

## 根因分析

负例同时含多个非法条件，测试只观察最终失败，没有证明请求或响应已到达要检验的分支。

## 解决方案

授权负例先建立合法业务前提：真实授予两个主体相同资源的 Use，owner 上传完整内容后，foreign Seal 必须精确返回 AuthDenied，且原输入与预算保持；再由 owner 成功执行相同 Seal。重复 Staged 操作也要覆盖，防止幂等快捷路径绕过授权。

响应矩阵先用相同 HTTP framing、凭据和合法 DTO 完成正控，再每次只改变一个字段；确认实际请求到达指定 operation 后才统计该分支的负例。修正测试工具时保留旧日志，旧的前置拒绝不得重命名为 DTO 验证通过。

辅助探针修正后还必须核对正式测试文件。N3-12 集成时，辅助 peer 已使用 HTTP/1.1，正式矩阵的 Handler 却仍沿用 Python 默认 HTTP/1.0；正式用例的 31 个子例因此在 DTO 校验前失败。正式 fixture 显式声明 HTTP/1.1 后，原 71 个子例在相同产品二进制上通过，独立复验确认所有断言和目标阶段不变。保留原冻结哈希，以独立审计的机械映射记录修正；分别标明历史完整运行和修正后的定向复验，不能将它们写成一次新的完整运行。

## 预防措施

每个权限、完整性或状态负例明确写出唯一非法条件、精确错误语义和合法对照。未知字段、重复 key、非 canonical manifest 等输入要重算其他绑定，避免 digest 不一致遮蔽目标校验。辅助流程在 Stub 前置失败时只属于 RED，不算恢复或并发流程通过。

## 参考

- N3-12 SNAPSHOT-STAGING-CONTRACT §§2、3、5、7、9。
- `test-review-branch-task-n312-staging-2026-10-12/r9`。
- `n312-cli-implementation/peer-only.stderr.log` 的 HTTP/1.0 前置拒绝记录。
- 独立审计 `protocol-fixture-equivalence-review-20261018` 与正式矩阵修正的 SHA 映射。

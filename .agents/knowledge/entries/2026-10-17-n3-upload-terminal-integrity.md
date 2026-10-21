---
id: n3-final-pin
title: 上传成功出口必须重新验证原始输入
tags: [n3, snapshot, integrity, localapi]
module: apps/nexus
severity: high
source: review
date: 2026-10-17
related: [n3-neg-ctrl]
---

## 问题描述

客户端发送完所有 blob 后等待 Seal 响应。此时本地 bundle 被修改，提供方仍能合法返回 Staged；如果客户端直接输出 PASS，就遗漏了请求期间的输入完整性约束。Begin 返回已有 Staged、Cancelling 或 Cancelled 等快捷路径也有相同风险。

## 根因分析

发送前或发送分片时的验证只证明那个时刻的输入有效，不能覆盖后续网络等待。合法的远端响应也不能证明请求方本地文件仍属于原 bundle。

## 解决方案

所有上传成功出口在收到并验证最终响应后，再通过原目录和文件绑定检查 bundle 的允许条目、权限、原 inode、metadata、manifest 与全部 blob 内容。内容校验按固定缓冲流式执行。发现变化返回 INPUT_INTEGRITY_FAILED，并保留已经取得的原 UploadId，供查询或取消使用。

## 预防措施

评审时枚举每个成功出口和网络等待阶段，覆盖幂等快捷返回。验证使用相同合法响应的正控，再在等待窗口分别修改内容、权限、原 inode 或条目；仅检查上传前损坏不能覆盖这个时序。

## 参考

- `docs/N3-12-SNAPSHOT-STAGING-CONTRACT.md` 的 bundle 不可变约束。
- 独立代码评审 `review-n312-cli-n312-cli-impl-r1` 的 R1-01 与 Seal 复现。
- `r1-repair-20261017` 的最终真实客户端探针：8 个正控、80 个篡改拒绝；该组件证据不代替完整 E4。

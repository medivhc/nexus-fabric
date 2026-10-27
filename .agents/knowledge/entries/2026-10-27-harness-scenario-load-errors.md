---
id: gate-loaderr
title: 场景加载错误必须进入门禁结果，日志不能替代失败传播
tags: [harness, scenario, verification, fail-closed]
module: engineering/nexus-harness
severity: high
source: debug
date: 2026-10-27
---

## 问题描述

场景文件无法读取、TOML 非法或声明不符合已有 schema 时，加载入口打印错误后返回合法子集。门禁只看到子集，可能把整个非法场景组判为 PASS；非法文件是唯一文件时，也会误走空组 PASS。

## 根因分析

加载失败的信息没有随加载结果传递，门禁无法区分“没有声明场景”和“场景声明存在但无法加载”。打印 stderr 不会改变机器可读 Gate verdict。

## 解决方案

内部加载器同时收集合法场景和错误。门禁先检查错误，汇总失败路径后返回 FAIL；真正空组按 MODULE 的既有规则返回 UNKNOWN。缺少可选子目录仍属于无声明。目录查询的兼容入口继续打印诊断并返回合法子集，未扩展其外部接口。

## 预防措施

回归同时覆盖非法文件独占场景组、与合法声明混合、跨选中目录、错误版本/ID、无效 UTF-8 和目录读取失败。合法静态场景的 UNKNOWN、非 TOML 文件、未选目录作为独立对照。

空组的期望必须来自正式 MODULE，不能把旧实现的 PASS 当作契约。本次独立测试评审 R1 指出了这一点；R2 通过后冻结 11 项测试，旧实现为 9 FAIL / 2 PASS，修复后为 11 PASS。测试文件 SHA-256 为 `f707e9d8059eb6ce2ad0494d49a8ad28005b5d68c8debb92552ca86547d28790`。

## 参考

- `engineering/nexus-harness/MODULE.md`：Gate 实现状态。
- `docs/e2e-test-system-contract.md`：§2、§4、§4b。
- `engineering/nexus-harness/src/scenario_load_tests.rs`。
- `docs/CODE-INTELLIGENCE-KNOWN-ISSUES.md`：E1 的已修复范围和查询兼容边界。

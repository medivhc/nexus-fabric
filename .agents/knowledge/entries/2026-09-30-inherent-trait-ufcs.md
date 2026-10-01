---
id: inherent-trait-ufcs-001
title: trait 方法与 inherent 方法同名时方法解析优先 inherent——必须用 UFCS 或泛型界调用 trait 版本
tags: [rust-pitfall, method-resolution, trait, api-design]
module: nexus-discovery
severity: medium
source: review
date: 2026-09-30
related: []
---

## 问题描述

`nexus-discovery` 的 D1 契约引入 `trait Discovery { fn resolve(&self, peer: &PeerId) -> Vec<SocketAddr>; }`，
而 `StaticDiscovery` 早已冻结了一个 inherent 方法
`resolve(&self, peer: &PeerId) -> Result<SocketAddr, DiscoveryError>`（remote P0）。
两者同名不同签名。直接写 `x.resolve(&peer)` 时，Rust 方法解析**永远优先 inherent 方法**，
trait 方法即使在作用域内也不会被选中——调用者以为调的是 trait 版本，实际拿到的是 `Result` 版，
类型不匹配时才暴露，语义混淆时则静默。

## 根因分析

Rust 方法调用的方法解析顺序：inherent 方法优先于任何 trait 方法（与 trait 是否在作用域内无关）。
这是语言规则，不是 lint 能抓的风格问题。当冻结 API 不能改名时，同名 trait 方法必然产生二义性。

## 解决方案

本阶段采用（已写入 MODULE.md D1 冻结契约）：
- 不改名（改名会破坏冻结 API）；
- trait 方法必须经 UFCS 显式调用：`Discovery::resolve(&x, &peer)`，或经泛型界调用；
- 在 trait 定义处用文档注释明确记录该二义性及调用方式；
- E4 example 中实际使用 UFCS 调用，作为可执行的用法示例。

## 预防措施

- 新增 trait 方法前，全局搜索同名 inherent 方法（`grep -rn "fn <name>"`）。
- 若同名不可避免：契约中明确记录解析规则 + UFCS 调用约定，不要"顺手改名"破坏冻结 API。
- Review 时把"新增 pub trait 方法是否与现有 inherent 方法同名"加入检查项（api-surface-minimization 维度）。

## 参考

- `crates/nexus-discovery/src/lib.rs`：`trait Discovery` 定义处的注释
- MODULE.md D1「命名调和」节
- Review `ecd906541620`（feature/discovery 第 1 轮）

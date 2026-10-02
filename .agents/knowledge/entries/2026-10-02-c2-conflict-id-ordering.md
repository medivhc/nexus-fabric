---
id: c2-conflict-id-ordering
date: 2026-10-02
module: nexus-workspace
category: implementation-pitfall
task_type: feature
---

# Conflict ID 必须与 local/remote 顺序无关

## 问题/模式描述

C2-P5 实现 D7（先 resolve 者赢）时，`conflict_id_of(base, local, remote, paths)` 按传入顺序哈希。
A 端 merge 时 local=H_A、remote=H_B；B 端 merge 时 local=H_B、remote=H_A，
双端算出不同的 conflict id，`apply_remote_resolutions` 按 id 匹配永远命中不了，
D7 规则静默不生效（测试 `first_resolver_wins_converges` 在 `adopted_remote_resolution` 断言失败）。

## 原因分析

conflict 的"身份"是三元组 (base, {local, remote}, paths)，local/remote 只是视角差异。
任何按顺序哈希 id、按顺序比较三元组、按顺序比较 merge parents 的代码，
都会在双端视角互换时失效。共三处需要顺序无关：
1. `conflict_id_of` 哈希前对 (local, remote) 排序；
2. `apply_remote_resolutions` 的三元组防御性检查用排序后比较；
3. merge commit parents 验证用集合（排序后）比较。

## 解决方案

`conflict_id_of` 内对 local/remote 按字符串排序后参与哈希（`nexus-conflict-v1` 格式不变，
只是 local/remote 取排序后的值）。另两处同样排序后比较。

## 教训/可复用要点

- 分布式协议中任何"身份"（id、匹配键）都必须规范化（canonicalize），不能依赖某端的视角顺序。
- 防御性检查如果与 id 的规范化方式不一致，会制造新的静默失败——检查与 id 用同一规范化。

---
id: trojan-late-guard-client-payload
date: 2026-10-28
module: apps/nexus
category: implementation-pitfall
task_type: bugfix
---

# 首包判别守卫必须在「客户端已发载荷」时失效

## 问题/模式描述

fixes-5 的 Trojan post-success 守卫（`late fallback response discarded`）把 success
之后到达、以 `HTTP/` 开头的首个下行块当作 fallback 丢弃并失败会话。它从未在客户端
发出载荷后关闭，于是正确密码节点上的明文 HTTP 全部失败：源站的 `HTTP/1.1 200`
被当成 fallback，客户端收到 0 字节。

## 原因分析

守卫的前提是「客户端尚未载荷」（只有 fallback 会对 Trojan 头自行应答），代码注释也
这么写，但实现只在第一块下行到达后才清除守卫，没有把「读到客户端载荷」作为清除
条件。interop 矩阵的格子用 echo 载荷（首字节不是 `HTTP/`），HTTPS 的首字节是 TLS
ServerHello，所以只有「等 CONNECT 应答后才发请求的明文 HTTP 客户端」会撞上，长期
未被发现。

## 解决方案

客户端载荷（`n > 0`；FIN 不算）被读到时关闭守卫，并把守卫期间暂存的首包前缀
（< 5 字节）先于后续字节入队。回归测试：`apps/nexus/tests/trojan_late_guard.rs`
（明文 HTTP、暂存前缀按序交付、半关闭不冲刷、守卫对静默客户端仍生效）。

## 教训/可复用要点

- 「按首包内容判别」的守卫必须写清楚适用前提，并把前提失效的事件（这里是客户端
  载荷）显式接成清除条件，而不是只靠「首块已处理」。
- 互操作矩阵的 echo 载荷覆盖不到协议层误判：对内容敏感的守卫要补一条真实应用协议
  （明文 HTTP）的回归。
- 关闭守卫时要处理守卫已暂存的字节（顺序与去留），并区分 0 字节读（FIN）与真实载荷。

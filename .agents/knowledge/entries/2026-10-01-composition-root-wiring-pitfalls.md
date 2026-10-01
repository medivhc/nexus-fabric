---
id: composition-root-wiring-pitfalls
date: 2026-10-01
module: nexusd
category: implementation-pitfall
task_type: feature
---

# Composition Root 接线踩坑

## signal-hook 的 flag::register 是 safe fn

`apps/nexusd` 有 `#![forbid(unsafe_code)]`，一度担心 signal 处理需要 unsafe。
实测 `signal_hook::flag::register(SIGTERM, &flag)` 是 safe 函数（0.3 版），
可直接用，无需 unsafe 块。

## mesh CIDR 不要硬编码，要从 N1 路由派生

`[vpi.routes]` 的 subnet 列表就是天然的 mesh CIDR 来源。
`Ipv4Net` 只有 `prefix_len()` 没有 network 地址 accessor，
加了 `network_addr()`（纯新增）。

## network.toml 改动 → NeedsRestart 是对的

mesh CIDR 从 network.toml 派生后，任何 network.toml 变更都可能影响路由，
保守按 NeedsRestart 处理（§13.6）。proxy.yaml/dns.toml 内容变更仍 Hot。

## E4 的 dial 失败是预期的

`assemble_n1` 对 peer 做 best-effort dial，无真实对端时 warn 不失败。
E4 里这是正常路径（`Timeout (degraded, continuing)`），不要当成失败。

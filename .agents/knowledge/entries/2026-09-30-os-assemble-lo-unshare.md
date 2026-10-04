---
id: os-assemble-lo-unshare
title: unshare(CLONE_NEWNET) 后必须拉起 lo，否则本地交付失败
tags: [netns, tun, udp, e4]
module: nexus-platform-linux
severity: high
source: debug
date: 2026-09-30
related: ["tun-rs-device-impl"]
---

## 问题描述

P3.x OS 装配 E4：example 内部 `unshare(CLONE_NEWNET)` 进隔离 netns，
建 TUN、配 IP、加路由全部成功，但 UDP 自发自收（bind 10.99.0.1 → send 到自己）
超时失败。沙箱和真机都复现。

## 根因分析

`unshare(CLONE_NEWNET)` 后的新 netns 里 `lo` 是 DOWN 状态。
内核对 TUN 自身地址（10.99.0.1）的本地交付路径依赖 lo UP；
lo DOWN 时包被路由出 TUN 设备（如石沉大海），recv 超时。
send 能成功（不报错），只有 recv 超时——容易误判为"网络不通"。

手动用 `ip netns exec` 测试时因事先 `ip link set lo up` 而没暴露问题；
example 自己 unshare 的路径没拉 lo，踩坑。

## 解决方案

example 在 unshare 后先 `set_link_up(lo_ifindex)`，再建 TUN。
标准 netns 实践：新 netns 第一件事就是拉起 lo。

## 预防措施

- 任何 `unshare(CLONE_NEWNET)` / `ip netns` 测试，断言前先确认 lo 已 UP。
- E4 驱动的环境准备（netns、lo、TUN）要显式化，不要假设内核默认状态。
- send 成功 + recv 超时的组合，优先查本地交付路径（lo 状态），不是路由。

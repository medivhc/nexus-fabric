---
id: ice-candidate-bind-set-001
title: ICE host candidate 集合必须 ⊆ UDP socket 实际能收包的地址；绑具体 IP 就只通告那个 IP
tags: [webrtc, ice, udp-bind, sdp, ci-false-green, test-strength]
module: nexus-web-gateway
severity: high
source: debug
date: 2026-10-11
related: ["e5-realnet-source-ip-selection", "datachannel-label-routing-001"]
---

## 问题描述

`crates/nexus-web-gateway` 在 master 上 `gateway-ci` 连红 5 次（exit 101）：所有 DataChannel
e2e 报 `peer 0 should connect` / `no control channel open`，ICE 永远连不上。

引入者：`b39226d fix(web-gateway): advertise all interface IPs as ICE host candidates`
（2026-10-10 02:07）——`create_session` 无条件把**所有非 loopback 网卡 IP** 通告为 host
candidate，而共享 UDP socket 绑的是 `listen_addr` 的**具体 IP**（测试与本机部署都是 `127.0.0.1`）。

## 根因分析

OS 层事实：**绑定到具体 IP 的 UDP socket 收不到发往其它网卡 IP 的数据报**。于是 SDP 里
多出来的候选地址是"可达性谎言"——浏览器往 172.168.12.97 发包，socket 只监听 127.0.0.1，
永不受理。绑定与候选集是两个必须同时决定的量，把它们分开写就必然漂移。

放大成"5 次假绿"的是 CI 形态（`.github/workflows/gateway-ci.yml`，`3a3f9eb8` 之前）：
1. 步骤最后一句是 `echo`，从未把 cargo 退出码传出去，`STATUS` 只写进 `build-status.json` 制品；
2. 统计口径用 `grep -c` 数 `--format json` 的行，而 `--format json` 是 **nightly-only**，
   stable 下测试二进制启动即报错、输出零行 ⇒ `grep -c` 得 0 且被 `|| true` 吞掉退出码。
"测试有没有跑过"与"作业红不红"被彻底解耦。

再放大的是**零断言的回归测试**：`ice_advertises_multiple_host_candidates` 只 `println!` 网卡
数量，没有任何断言，因此即便在 exit 码被正确传播后也不会红（真断言是修好后补的两条，含真连通）。

## 解决方案

把绑定与候选集合成一个不变量（MODULE.md G11），由纯函数 `ice_bind_plan()` 一次算出：

- 给定具体 `listen_addr` → 绑该 IP **且只通告该 IP**；
- 未指定 `listen_addr` → 绑**族内通配地址**（这是"真能收到所有网卡包"的前提）并通告全部可路由网卡 IP；
- `0.0.0.0` 这类未指定地址**不得进 SDP**；`page_addr` 仍必须是可路由的具体地址（0.0.0.0 监听下
  实测仍能派生出 `172.168.12.97:18443`，原测试继续守住）。

## 预防措施

- Review 见到"从网卡枚举生成候选/端点列表"的代码，先问：**这个列表里的每个地址，当前 socket
  都能收到发往它的包吗？** 绑定地址与通告地址必须是同一个决策的两种输出，不能各自计算。
- 通配绑定的族语义：`::` 通配时 IPv4-only 浏览器会拿到零候选（dual-stack 语义需单独证）。
- 枚举网卡 IP 要看 `IFF_UP`，并拒绝无 scope-id 的 `fe80::`——评审实测放行过 15+ 条 docker/veth/tun
  的 fe80 进 SDP。
- 反假绿三条：CI 步骤必须 `exit ${PIPESTATUS[0]}`；不要用"日志行数统计"代替退出码；不要用
  nightly-only flag 作为 stable 作业的判定输入。
- 反假测试两条：断言"连通"而不是断言"候选条数 > N"；不要用与实现同逻辑的辅助函数
  （如自写的 `routable_ipv4s()`）比长度——那是循环论证，改坏仍绿。把不变量抽成纯函数
  （输入伪造网卡表 + 绑定地址，输出候选集）单测，才是可杀变异的形态。
- 修好后该不变量是**硬约束区**：变异实验 M09 一次让 22 条测试红，可作为"测试强度是否足够"的基线。

## 参考

- `crates/nexus-web-gateway/docs/FILE-MODULE-VERIFICATION-2026-10-10.md` §4.1、§4.2、§8
- `crates/nexus-web-gateway/docs/FILE-MODULE-REVIEW-2026-10-11.md` §4（硬约束区）、§3（IPv6/候选质量）
- commits：`b39226d`（引入）、`3a3f9eb8`（CI 传播退出码）、`8e0ff70`/`30af714`（grep 在 `bash -e` 下的退出码坑）
- `crates/nexus-web-gateway/MODULE.md` 不变量 G11

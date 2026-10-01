---
id: e5-realnet-source-ip-selection
date: 2026-10-01
module: nexus-network
category: implementation-pitfall
task_type: test
---

# E5 真实网络测试：同机双节点时内核源 IP 选择陷阱

## 问题/模式描述

E5 真实网络验收中，Node A 和 Node B 都在 xc-pc-linux 同一台机器上（不同真实接口）。
B 漫游时调用 `rebind()`（产品代码，客户端用 `0.0.0.0:0` wildcard 绑定），
期望内核按路由选择新的源 IP。但实测发现：当目标是本机地址（如 172.168.12.97）
时，内核选择源 IP = 目标 IP 自身（本地交付优化），而非期望的另一接口 IP。

## 原因分析

1. Linux 内核对**本地目标**（local delivery）有特殊源地址选择逻辑：
   发送到本机已配置的 IP 时，源地址常选为目标地址本身（路由无需出接口）。
2. `ip route ... src <ip>` 策略路由提示对本地交付**无效**（实测验证）。
3. 产品代码 `cmd_rebind` 对客户端硬编码 wildcard（`0.0.0.0:0`），test 类型任务不可改。

## 解决方案

接受源 IP 可能不变，但**源端口必变**（wildcard 绑定得随机端口）。
QUIC 迁移由 4-tuple（源 IP:port）变化触发，端口变化已足够触发对端被动迁移。
测试断言（CID 不变、rebind 发生、哈希匹配、stall 预算）依然有效，
迁移机制与 E4 相同。

## 教训/可复用要点

- 同机多节点测试时，**不要假设 wildcard 绑定的源 IP 会按直觉选择**；
  对本地目标，内核可能选源=目标。
- 验证 QUIC 迁移只需 4-tuple 变化，**端口变化亦可**，不必强求 IP 变化。
- 如需强制源 IP 变化，应使用**不同机器**（或 Docker 容器经网桥，使目标非本地），
  而非策略路由（对本地交付无效）。
- 测试前用 `python3 + socket` 做最小源 IP 选择实验（5 分钟），避免在大测试中才发现。

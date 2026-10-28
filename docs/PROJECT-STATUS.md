---
doc-id: nexus-project-status
layer: L2
owner: coordinator
last-verified: 2026-10-06
verified-against: b9ae124
note: 沙盒本地 HEAD (222e49c) 滞后；b9ae124 系真机核实的 github master 最新状态，本地无法独立验证
status: historical
---

> 注：本文为 2026-10-06 时点快照；协议互操作与项目状态的现行结论见
> `docs/protocols/interop/MATRIX.md` 与 Nexus Feature 看板。

# Nexus 项目状态（2026-10-06）

> 本文档按 `docs/DOCUMENTATION-ARCHITECTURE.md` 纳入保鲜体系。
> `verified-against` 指向 github master 最新 commit（b9ae124，真机核实）；
> 沙盒本地 HEAD (222e49c) 滞后，基于该 commit 的事实（hash 存在性、测试数字）
> 在本地无法独立验证，以真机核实为准。
> 不确定的状态写"待确认"，不编造。

## 项目简介

Nexus 是一个 clean-room 实现的 Rust 网络 substrate + 分布式工作空间，
对应产品白皮书 v1.0 的三层能力：

- **N1 Universal Connectivity** —— 自由、高速、节点互联的网络地基
  （QUIC-like 会话层、路径层四级回退、NAT 穿透）
- **N2 Universal Resource Access** —— 统一资源访问
  （发现、授权、访问、撤销闭环：`nexus use <resource>`）
- **N3 Distributed Workspace** —— 分布式工作空间
  （Task / Snapshot / Artifact）

## 基线文档

| 文档 | 角色 | 位置 |
|---|---|---|
| 产品白皮书 v1.0 | **产品定义基线**（概念冲突以它为准） | `docs/baselines/whitepaper-v1.0-product.md` |
| v9 统一系统设计规范 | **技术设计基线**（架构术语以它为准） | `docs/baselines/v9-design-spec.md` |
| PRODUCT.md | 用户可观察能力与失败语义（仓库内契约） | 本仓库（⚠️ §11 缺三新协议产品语义，见审计 P1） |
| ARCHITECTURE.md | 核心模型、依赖方向与不变量（仓库内契约） | 本仓库 |

## 各层状态

### N1：Final PASS（最后确认 2026-10-04 前）

- 12 个逻辑 bug 全修，`be361f9` 真机 full verify：第一轮 2 时序 flake，
  重跑后 **22 gate 全 PASS**（Evidence `3d8046e2d8da`）—— **Final PASS 可宣称**
- 之后 N1 无大改动；如有回归以最新 verify 证据为准

### 出站协议：VLESS / AnyTLS / Hysteria2 全链路打通（2026-10-05 → 10-06）

- **crate 实现**：三个协议 clean-room 实现并合入 master
  （`08363b9` AnyTLS / `0a4c0db` VLESS / `57a34b4`+`55c839f` Hysteria2）
- **配置接入**：`e6fedba` —— `nexus-proxy-config` 解析/校验/注册，字段对齐 meow-rs/Clash
- **数据面打通**：`740a7b3`（AnyTLS: TLS+auth+中继）/ `4180979`（VLESS: 握手+中继）
  / `2d018c4`（Hysteria2: QUIC+H3 认证+TCP over stream）
- **独立评审闭环**：实现 → 独立评审（0 FAIL/12 WARN）→ 修 5 WARN（`ec88cb2`：
  握手 10s 超时 fail-closed、VLESS 非法 UUID 拒绝测试、删死 `close_notify`、
  Hy2 Drop 自动发 CONNECTION_CLOSE、`obfs` 枚举校验）
  → 独立复审确认 → 修 NEW_WARN_1（AnyTLS dead `send_close_notify`，`67a75ff`）
  → 修 NEW_COMMENTED_1（`obfs: none` 别名对齐，`b9ae124`）
- **测试**：anytls 23 / vless 32 / hysteria2 50 / proxy-config 34，
  `cargo test -p nexus --lib` 165/165，全过
- **Hysteria2 Salamander 已实现**（`obfs.rs` BLAKE2b-256/XOR/salt + 测试，driver 已接线）
- ⚠️ **诚实边界**：均为 mock server 验证，**无真实服务端互操作证据，不得宣称兼容或可用**

### N2：P0 完成，P1 21 项择优组合已合并

- P0-0 → P0-6 全部合入 master，每阶段走完实现 → E4 真机验证 → 独立评审 → 合 master
- P1：mimo/bunny 双轨独立实现 21 项后逐条评审择优，组合分支
  `3d13781 feature(n2): merge P1 21-item combination into github master` 已合入
- P1 评审发现的 FAIL 已修复（以 git log 为准）

### N3：分布式工作空间，推进中

- 按白皮书 v1.0 / v9 规范推进；Task / Snapshot / Artifact 模型与契约阶段已做
  （`docs/N3-MODEL-CONTRACT.md`、`docs/contracts/n3-task-v1.schema.json`、
  `scenarios/product/n3-*.toml`；细节待确认）
- **不得宣称 N3 已可用**

### 文档体系：架构设计 + 全量审计刚完成（2026-10-06）

- `docs/DOCUMENTATION-ARCHITECTURE.md`：四层文档体系（契约/操作/决策/导航）+
  保鲜机制（frontmatter / STALE 扫描 / 季度 audit / 生成式索引），独立评审 COMMENTED 后定稿
- `docs/DOC-AUDIT-2026-10-06.md`：126 份文档审计（83 保留 / 9 过时 / 23 可删 / 11 待定）
- `.agents/skills/nexus-multiagent`：多 Agent 协作编排 skill（AGENTS.md §29 的编排层补充）
- 本次 P0 清理：重写本文件、清理 13 份伪状态计划文档（5 份版本库内 `git rm` 删除，
  8 份从未入仓、物理删除）、删 `ENVIRONMENT.md`

## 诚实边界（verified vs sketched）

- 三新协议（anytls/vless/hysteria2）：实现+接入+数据面完成，但**无真实服务端互操作**，
  不得宣称兼容或可用；VLESS Vision splice、WS/gRPC 传输、Hy2 UDP 装配尚未实现
- 其余协议（ss/trojan/vmess/wireguard 等）多为草稿；
  trojan over TLS 仅 1 个真实日本节点握手成功
- TUN 已完成（数据面合入 master）；Linux TPROXY 前端 + TUN 生产链已按
  tproxy-completion run 验收（E4+E5，S1–S10）；IPv4-only；Windows/macOS TPROXY 仍不在范围
- TPROXY UDP 回包源端口仍为透明监听端口（非原始目的地端口）：冻结 spec §9.1/§9.4
  冲突已裁决（S2），修复走 follow-up run tproxy-udp-reply-origdst
- 互联网 NAT 穿透未实现（当前跨 NAT 靠 Direct → Proxy → TURN 回退链）
- 未验证的实现不得描述为兼容或可用；任一 gate FAIL 不得宣称 Final PASS

## 明确暂缓（不主动开工）

- Android 统一 VPN 入口
- VMess 协议
- TUIC / WireGuard（用户已明确取消）

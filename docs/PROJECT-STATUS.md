# Nexus 项目状态（2026-10-03）

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
| PRODUCT.md | 用户可观察能力与失败语义（仓库内契约） | 本仓库 |
| ARCHITECTURE.md | 核心模型、依赖方向与不变量（仓库内契约） | 本仓库 |

## 各层状态

### N1：Final PASS

- master `d2291fb`：12 个逻辑 bug 全修，`verify --full` 21 PASS / 0 FAIL / 1 UNKNOWN
  （UNKNOWN 为 coverage 时序 flake，已有接受先例），Evidence `verify-325c8e5e294c`
- 后续 W1（watcher 优雅关闭根治）+ W2（架构死代码清理）合入，
  `be361f9` 真机 full verify：第一轮 2 时序 flake，重跑后 **22 gate 全 PASS**，
  Evidence `3d8046e2d8da` —— **Final PASS 可宣称**

### N2 P0：实现完成，P0 已修复合入，P1 评审修复中

- P0-0 → P0-6 全部合入 master（`84861b5`），每阶段走完
  实现 → E4 真机验证 → 独立评审 → 合 master
- 7 条完成标志达成 6 条；第 7 条在 E4 双机环境 11/11 PASS，
  bare 单机 full verify 241/247（6 个需双机的 n2 场景失败，环境限制非代码问题）
- **免费模型横评 Round 4**（mimo-v2.6 + space-bunny 独立评审，逐条验真）：
  P0 必修 6 条已修完合入 master；P1 21 条、P2 17 条 —— 修复进行中（见下）
- 完整评审报告：`~/workspace/n2-p0-review-round4.md`（工作区，未入仓）

当前修复轨道（`84861b5` 之后；P0 分支已合 master）：

| 轨道 | 范围 | worktree |
|---|---|---|
| P0 修复（我方） | 6 条 P0（含服务端身份校验安全项） | 已合 master（`0d46486`） |
| P1 修复（mimo） | 21 条 P1 | `track-n2-p1-mimo` → `n2/p1-fix-mimo` |
| P1 修复（bunny） | 21 条 P1（独立，用于对比修复质量） | `track-n2-p1-bunny` → `n2/p1-fix-bunny` |

### N3：模型与契约阶段，运行实现未开工

- 首期范围：指定可信 Linux Provider 执行 Windows 用户/Agent 的固定项目输入，
  交付真实日志、退出码和 Artifact；先用 Linux 请求方 E4，再做 Windows→Linux E5。
- 模型：TaskOwner 归 Compute，Snapshot 归 Workspace，Artifact 登记归 Compute；
  标识符/版本化 DTO 归 Domain，现有 SessionManager 保持唯一 Session Owner。
- 契约入口：PRODUCT §17、ARCHITECTURE §12、`docs/N3-MODEL-CONTRACT.md`、
  `docs/contracts/n3-task-v1.schema.json`、22 个 `scenarios/product/n3-*.toml`。
- 本阶段不包含 Task 执行器或 E4 verifier；旧实现上的 Red / 冻结清单见
  `.evidence/red-n3-model-v1/`。N2 安全收口、真实隔离/配额和全套 E4/E5 为后续前置。
- **不得宣称 N3 已可用**；快速静态门禁通过不代表任务闭环 PASS。

## 诚实边界（verified vs sketched）

- 协议实现（ss/trojan/vmess/vless/hy2/wireguard）多为草稿，
  hysteria2/anytls 未实现；除 1 个真实日本节点 trojan over TLS 握手成功外，
  未做系统互操作测试 —— **不得宣称兼容**
- N2 P0 的双向认证当前只防被动冒名，无保密性/前向安全（已声明，P1 项）
- 未验证的实现不得描述为兼容或可用；任一 gate FAIL 不得宣称 Final PASS

## 明确暂缓（不主动开工）

- Android 统一 VPN 入口
- VMess 协议

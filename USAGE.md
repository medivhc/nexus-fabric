# Nexus 用户手册

> Nexus 统一 Resource Fabric 控制面用户手册

## 目录

1. [概述](#概述)
2. [构建与安装](#构建与安装)
3. [快速开始](#快速开始)
4. [CLI 命令参考](#cli-命令参考)
5. [核心概念](#核心概念)
6. [架构概览](#架构概览)
7. [开发流程](#开发流程)

---

## 概述

Nexus 是一个统一的个人动态资源运行时（Resource Fabric），把网络访问、Service、Workspace、Compute 与设备能力统一建模为 Resource。

核心流程：
```
Resource + Intent
    ↓
Resolve Candidate Providers
    ↓
Core Planner
    ↓
Create Session
    ↓
Establish Connectivity
    ↓
Execute
    ↓
Observe + Adapt
    ↓
Persist / Recover
```

---

## 构建与安装

### 前置要求

- Rust 1.95+（推荐 rustup 安装）
- Cargo
- Git

### 构建

```bash
# 克隆仓库
git clone <repo-url>
cd nexus

# 构建 debug 版本
cargo build

# 构建 release 版本
cargo build --release
```

构建产物位置：
- CLI：`target/debug/nexus.exe`
- Daemon：`target/debug/nexusd.exe`
- Harness：`target/debug/nexus-harness.exe`

---

## 快速开始

### 1. 查看状态

```bash
# 总体状态（人读视图）
nexus status

# 总体状态（JSON 机器可读）
nexus --json status
```

### 2. 诊断

```bash
# 统一诊断
nexus diagnose
```

### 3. 查看平台能力

```bash
# 平台能力清单
nexus platform capabilities
```

---

## CLI 命令参考

### 全局选项

| 选项 | 说明 |
|------|------|
| `--json` | 原样打印 observability 快照 JSON（机器可读） |
| 默认 | 渲染人读文本视图 |

### exit 语义

| 退出码 | 说明 |
|--------|------|
| 0 | 业务成功；NexusError 领域拒绝（verdict=FAIL，请求已被处理） |
| 2 | 用法/解析错误（缺参、未知命令） |

---

### 状态与诊断

#### `nexus status`

显示系统总体状态。

```bash
nexus status
nexus --json status
```

#### `nexus diagnose`

统一诊断，检查各个子系统的健康状态。

```bash
nexus diagnose
```

#### `nexus platform capabilities`

显示当前平台支持的能力清单。

```bash
nexus platform capabilities
```

---

### Connectivity（连接子系统）

#### `nexus connectivity status`

显示当前连接状态。

```bash
nexus connectivity status
```

#### `nexus connectivity candidates`

列出候选 Provider。

```bash
nexus connectivity candidates
```

#### `nexus connectivity probe <target>`

探测目标可达性。

```bash
nexus connectivity probe example.com:443
```

#### `nexus connectivity links`

显示活动链路。

```bash
nexus connectivity links
```

---

### DNS 子系统

#### `nexus dns status`

显示 DNS 子系统状态。

```bash
nexus dns status
```

#### `nexus dns resolve <name>`

解析域名。

```bash
nexus dns resolve example.com
```

#### `nexus dns providers`

列出 DNS Provider。

```bash
nexus dns providers
```

#### `nexus dns cache`

显示 DNS 缓存。

```bash
nexus dns cache
```

---

### Workspace（工作区）

#### `nexus workspace heads <workspace>`

显示 Workspace Head Set。

```bash
nexus workspace heads my-workspace
```

#### `nexus workspace conflicts <workspace>`

显示未合并冲突。

```bash
nexus workspace conflicts my-workspace
```

#### `nexus workspace cache <workspace>`

显示 Workspace 缓存状态。

```bash
nexus workspace cache my-workspace
```

---

### Compute（计算）

#### `nexus compute jobs`

显示 Compute 任务。

```bash
nexus compute jobs
```

---

### Plan 与 Session

#### `nexus plan explain <resource>`

展示 Plan 决策过程。

```bash
nexus plan explain internet-access
```

#### `nexus session watch <session-id>`

观察 Session 状态。

```bash
nexus session watch sess-12345678
```

---

## 核心概念

### Resource（资源）

Nexus 把所有东西都建模为 Resource：
- Network（网络访问）
- Service（服务）
- Workspace（工作区）
- Compute（计算）
- Devices（设备）

### Provider（提供方）

每个 Resource 可以有多个 Provider，系统会根据策略选择最优的。

### Session（会话）

Session 是一次资源使用的生命周期：
```
Allocating → Active → Draining → Disposed
```

### Connectivity（连接）

连接子系统负责建立和维护到 Provider 的连接。

---

## 架构概览

```
┌─────────────────────────────────────────────────────────────┐
│                     CLI / Daemon                            │
├─────────────────────────────────────────────────────────────┤
│                     Core Planner                            │
├──────────┬──────────┬──────────┬──────────┬─────────────────┤
│ Network  │ Service  │ Workspace│ Compute  │   Presence      │
├──────────┴──────────┴──────────┴──────────┴─────────────────┤
│              Connectivity / Transport                       │
├─────────────────────────────────────────────────────────────┤
│                     Platform Layer                          │
│        (Linux TUN / Windows / macOS / Android / iOS)       │
└─────────────────────────────────────────────────────────────┘
```

---

## 开发流程

### 标准验证流程

```bash
# 快速验证
nexus-harness verify --fast

# 全量验证
nexus-harness verify --full
```

### 独立 Review

所有代码变更必须经过独立 Review：
1. Fast Verify 通过后
2. 独立执行者做八个维度审查
3. Verdict = APPROVED / COMMENTED 后才能提交
4. 最多迭代 3 轮

### 知识库

项目知识库位于 `.agents/knowledge/`，沉淀了：
- 踩坑记录
- 实现模式
- 架构决策

---

## 更多资源

- [PRODUCT.md](PRODUCT.md)：产品契约
- [ARCHITECTURE.md](ARCHITECTURE.md)：架构设计
- [DEVELOPMENT.md](DEVELOPMENT.md)：开发指南
- [AGENTS.md](AGENTS.md)：Agent 工程方法论

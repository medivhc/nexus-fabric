---
id: subnet-cli-toml
date: 2026-09-21
module: apps/nexus
category: implementation-pattern
task_type: feature
---

# P3.1 子网 CLI 与 TOML 配置（nexus subnet up/status/leave）

## 问题/模式描述
- CLI 需要用户可用的 subnet 命令族 + 配置格式；状态跨进程（CLI 单次命令语义）需本地文件。
- 配置校验必须先于装配（不变量），错误要结构化 CONFIG_ERROR（exit 0）。

## 原因分析
- `EncryptionConfig` 定义在 `crates/nexus-connectivity/src/encryption.rs:570`，virtual_subnet.rs 是 `use crate::encryption::...`（私有 use，非 re-export）→ 外部路径应为 `nexus_connectivity::encryption::EncryptionConfig`。
- harness fast verify 只跑 git-diff affected 场景：**未跟踪的新场景文件不计数**，只有 Full 才全量跑 → 新 E4 场景靠 Full 拿权威证据（example 手动比对先行）。
- 并行会话合入 batch3 占用了 PRODUCT §12.15 → 我的小节重编号 §12.16（锚点/requirement 引用/注释同步改）。

## 解决方案
- apps/nexus/src/subnet_cli.rs：serde Deserialize 的 SubnetConfig + 私有 validate（cidr/vip/peer/next_hop/egress）+ assemble（MeshCarrier mock）+ up/status/leave + JSON 状态文件（NEXUS_HOME/~/.nexus/subnet.json，--state 覆盖）。
- main.rs 接线 `subnet up/status/leave`（进程内 SDK，同 run 路径）；E4 example subnet_cli.rs 全闭环 15 断言。

## 教训/可复用要点
- crate 层零 I/O；配置校验/状态文件全在 Composition Root（apps）。
- 新依赖 serde(derive)+toml 0.8 在 apps 层，过 dependency gate（纯 Rust、无平台依赖）。
- 跨会话并行合入 master 时，PRODUCT 小节号可能被占用 → 提交前检查重号并重编号，同步 requirement 锚点。
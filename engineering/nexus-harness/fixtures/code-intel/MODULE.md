# MODULE: code-intel-fixture（Code Intelligence 语义查询夹具）

## Purpose

为 `nexus-harness code ...` 与 `nexus-harness context ...` 提供**确定性**的 Rust 语义查询面。
它是独立 cargo workspace root（`Cargo.toml` 里显式 `[workspace]`，并被根 workspace `exclude`），
因此 rust-analyzer 从这里启动时只加载这 3 个源文件，冷启动结果可重现；
生产 crate 不得依赖它（提案 §2：Code Intelligence 只存在于 Engineering Plane）。

## Public API

`Egress`、`RelayEgress`、`TcpEgress`、`UdpEgress`、`Scheduler`、`PROBE_READY`。

- `Egress` 是一个 trait，有三个 impl（`implementations` 的计数锚点）。
- `Scheduler` 上的 `tick` 是 `hover` / `definition` 的单点锚。
- `dispatch_dyn` 是 `callees` 的动态分派锚。
- `PROBE_READY` 是常量锚。
- `diagnostic_probe.rs` 里的 `probe_type_mismatch` 故意留**一处**类型错误，供诊断条目形状 E4 使用。

## Frozen anchors（改动必须重走契约阶段）

行/列号是契约的一部分，E4 场景以 `<path>:<line>:<col>`（1-based）引用：

- `src/transport.rs:9:8` = trait `Egress` 的 `send`（`references` 计数 = 7）
- `src/transport.rs:64:8` = 动态分派点（`callees`）
- `src/lib.rs:9:21` = `pub use transport::{Egress, ..}`（re-export 穿透 `definition`）
- `src/lib.rs:23:12` = `pub fn tick`（`callees` / `hover`）

新增 `mod` 声明只能挂在 `src/lib.rs` **末尾**，否则上面两个 `lib.rs` 锚点会整体下移。

## Non-Responsibilities

不承载任何产品语义；不被根 workspace 编译；不引入外部依赖（`[dependencies]` 保持为空是有意的，
它保证冷启动可重现）。它的存在不构成对 rust-analyzer 结果质量的承诺——承诺由 E4 场景逐条钉。

## Verification

本模块自身不是被验证对象，验证面在它自己的场景包里：
`scenarios/engineering/code_intelligence_*.toml`（E4，见 `engineering/nexus-harness/MODULE.md`）。
其中 `engineering.code-intelligence-context-anchors` 用本目录作为 `context` 的语义作用域，
依据就是"本目录是 cargo workspace root"这一条（`context` 只在 workspace root 上跑语义层，
理由见 nexus-harness MODULE.md 的 `context` 契约）。

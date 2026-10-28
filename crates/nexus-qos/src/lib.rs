//! 用户态包调度与令牌桶（跨栈共享叶）。
//!
//! - `cake`：CAKE-like 调度器（per-flow DRR 公平队列 + 三级严格优先级 + per-egress
//!   令牌桶整形）；
//! - `bucket`：令牌桶限流基元与类型化错误面。
//!
//! 边界：不含 I/O、不读时钟（`now: Duration` 由调用方注入）、不解析配置、不持久化。
//! 定义自 `nexus-connectivity` 下沉（2026-10-28，P3），由 `nexus-connectivity` /
//! `nexusd` / `nexus-harness` 消费；叶子身份与无环判据见
//! `docs/adr/0001-dual-stack-boundary.md` §共享叶判据。

pub mod bucket;
pub mod cake;

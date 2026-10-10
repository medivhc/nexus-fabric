//! 诊断形状夹具：本文件**故意**包含一处类型错误，给 `code diagnostics` 提供
//! 可被 E4 场景断言的条目形状（见 MODULE.md「诊断条目字段映射」与
//! `scenarios/engineering/code_intelligence_diagnostics_item_shape.toml`）。
//!
//! 冻结约束（改本文件必须重走契约阶段）：
//!
//! - 只留**一处**错误。诊断条数不进入契约（它随 rust-analyzer 的分析面变化），
//!   但多留一处会让 `results.0` 落在哪条上变得不确定。
//! - 不得引用 `Egress` / `send` / `Scheduler` / `tick` 等被行号锚点或计数引用的
//!   符号，否则 `references` / `symbol` / `callers` / `callees` 场景的结果集会变。
//! - 只能通过 `lib.rs` **末尾**的 `mod diagnostic_probe;` 挂进模块树：插到中间会挪动
//!   `lib.rs:9:21`（`pub use transport::{Egress, ..}`）与 `lib.rs:23:12`（`pub fn tick`）
//!   这两个已冻结的行列锚点。

/// 返回类型与表达式类型不一致：rust-analyzer 的 pull diagnostics 必然把它归为
/// `DiagnosticSeverity::Error`（= 1），也就是 DTO 里的 `qualified_name == "error"`。
pub fn probe_type_mismatch() -> u32 {
    "not-a-u32"
}

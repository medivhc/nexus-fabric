//! Workspace Intelligence（v9 §21）：非权威、可丢失重建的访问智能层。
//!
//! ```text
//! AccessTrace ──► WorkspaceGraph ──► WorkingSetEstimator ──► PrefetchScheduler
//!      │                │                     │                        │
//!      │           静态 containment      Snapshot/Profile/Graph/   只定"预取什么/
//!      │           + 观测共现            Trace/TaskContext/Cache    何时/并发/预算"
//!      │                                                        │
//!      └───────── IntelStore（独立 JSON，可整体删除） ───────────┘
//!                                                              │
//! 缺失对象 ──► ResourceDeliveryRequest ──► Core Planner（选 Provider/Path）
//! ```
//!
//! # Deletion Test（v9 §5 / 仓库 AGENTS.md §12）
//!
//! 删除本 crate（含 `IntelStore` 的持久化文件）后：
//! - `nexus-workspace` 的正确性不受任何影响（权威 DAG/HeadSet/Journal 零依赖本 crate）；
//! - 所有智能状态可从新的访问轨迹重建（trace → graph → estimate → prefetch）。
//!
//! 本 crate 对 `nexus-workspace` 只有**只读**依赖（读 manifest 路径建静态图），
//! 绝不参与正确性判断；`nexus-workspace` 反向零依赖本 crate。

#![forbid(unsafe_code)]

pub mod delivery;
pub mod estimator;
pub mod graph;
pub mod prefetch;
pub mod profile;
pub mod store;
pub mod trace;

pub use delivery::to_snapshot;
pub use estimator::{CacheState, EstimatorInput, ScoredPath, TaskContext, WorkingSetEstimator};
pub use graph::{EdgeKind, WorkspaceGraph};
pub use nexus_domain::ResourceDeliveryRequest;
pub use prefetch::{PrefetchBudget, PrefetchItem, PrefetchPlan, PrefetchScheduler};
pub use profile::Profile;
pub use store::{IntelSnapshot, IntelStore};
pub use trace::{AccessEvent, AccessTrace};

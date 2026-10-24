//! 透明前端共享组件（TUN 与 TPROXY 共用）。
//!
//! - `decision`：5 元组决策缓存（spec §9.13，TUN 与 TPROXY 共用）。
//!
//! 本模块是 delivery core：只接收 driver 传入的 `now_millis`，不读系统时钟。

pub mod decision;

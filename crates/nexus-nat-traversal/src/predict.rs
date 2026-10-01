//! P3 可预测性检测 + 有界 spray 计划。
//!
//! **Track B 实现**。本文件为 stub：只给出形状，函数体 `todo!()`。

use std::net::IpAddr;

use crate::{PortSample, Predictability, PunchPredictor, SprayPlan};

/// Track B 实现：基于 Δ 稳定性的有界端口预测器。
#[derive(Debug, Default)]
pub struct BoundedPredictor;

impl PunchPredictor for BoundedPredictor {
    fn assess(&self, _samples: &[PortSample]) -> Predictability {
        todo!(
            "Track B: sequential_delta_predictable / random_delta_unpredictable / too_few_samples_unpredictable"
        )
    }

    fn plan(&self, _p: &Predictability, _target_ip: IpAddr, _k: u8) -> Option<SprayPlan> {
        todo!("Track B: spray_bounded_by_k")
    }
}

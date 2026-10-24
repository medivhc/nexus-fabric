//! P3 有界端口预测（合同 v1.1 冻结规则）。
//!
//! - `assess`：最近至多 8 个样本；至少 3 个有效样本；`target` 去重 ≥2；
//!   `observed_from` 一致；`port != 0`；连续 Δ 全相等且 `|Δ| <= 8` →
//!   `Predictable{base_port: 最后样本端口, delta}`；否则 `Unpredictable`。
//! - `plan`：只对 Predictable 返回 Some；`2K+1` 个端口，K 上限 32，跳过 0。

use std::net::{IpAddr, SocketAddr};

use crate::{PortSample, Predictability, PunchPredictor, SprayPlan};

/// spray 半径 K 上限（合同冻结：32）。
const MAX_SPRAY_K: u8 = 32;
/// 最少有效样本数。
const MIN_SAMPLES: usize = 3;
/// 最多纳入判定的样本数。
const MAX_SAMPLES: usize = 8;
/// 稳定 Δ 上限（默认 `max_stable_delta`）。
const MAX_STABLE_DELTA: i32 = 8;

/// 预测计划（core 方向修正使用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PredictionPlan {
    Spray(SprayPlan),
    MappingProbe {
        target: SocketAddr,
        count: u8,
        interval_ms: u64,
    },
    None,
}

#[derive(Debug, Default)]
pub struct DefaultPredictor;

impl DefaultPredictor {
    fn usable(samples: &[PortSample]) -> Vec<PortSample> {
        let tail = &samples[samples.len().saturating_sub(MAX_SAMPLES)..];
        let Some(first_obs) = tail.first().map(|s| s.observed_from) else {
            return Vec::new();
        };
        tail.iter()
            .copied()
            .filter(|s| s.port != 0 && s.observed_from == first_obs)
            .collect()
    }

    fn uniform_delta(samples: &[PortSample]) -> Option<i32> {
        let distinct_targets = {
            let mut t: Vec<SocketAddr> = samples.iter().map(|s| s.target).collect();
            t.sort();
            t.dedup();
            t.len()
        };
        if distinct_targets < 2 {
            return None;
        }
        let delta = samples[1].port as i32 - samples[0].port as i32;
        if delta.abs() > MAX_STABLE_DELTA {
            return None;
        }
        let uniform = samples
            .windows(2)
            .all(|w| w[1].port as i32 - w[0].port as i32 == delta);
        uniform.then_some(delta)
    }
}

impl PunchPredictor for DefaultPredictor {
    fn assess(&self, samples: &[PortSample]) -> Predictability {
        let usable = Self::usable(samples);
        if usable.len() < MIN_SAMPLES {
            return Predictability::Unpredictable;
        }
        match Self::uniform_delta(&usable) {
            Some(delta) => Predictability::Predictable {
                base_port: usable[usable.len() - 1].port,
                delta,
            },
            None => Predictability::Unpredictable,
        }
    }

    fn plan(&self, p: &Predictability, target_ip: IpAddr, k: u8) -> Option<SprayPlan> {
        let Predictability::Predictable { base_port, delta } = p else {
            return None;
        };
        let k = k.min(MAX_SPRAY_K);
        let center = base_port.wrapping_add(*delta as u16);
        let k_i32 = i32::from(k);
        let mut ports = Vec::with_capacity(2 * k_i32 as usize + 1);
        for i in -k_i32..=k_i32 {
            let port = center.wrapping_add(i as u16);
            if port != 0 {
                ports.push(port);
            }
        }
        Some(SprayPlan { target_ip, ports })
    }
}

/// 组合根/测试使用的方向决策 helper（不读全局状态）。
pub fn default_plan(
    local_symmetric: bool,
    remote_symmetric: bool,
    hint: Option<crate::PredictionHint>,
    remote_reflexive: Option<SocketAddr>,
    predictor: &dyn PunchPredictor,
    k: u8,
    probe_count: u8,
    probe_interval_ms: u64,
) -> PredictionPlan {
    if local_symmetric && remote_symmetric {
        return PredictionPlan::None;
    }
    if local_symmetric {
        return match remote_reflexive {
            Some(target) => PredictionPlan::MappingProbe {
                target,
                count: probe_count,
                interval_ms: probe_interval_ms,
            },
            None => PredictionPlan::None,
        };
    }
    if remote_symmetric {
        let (Some(hint), Some(target)) = (hint, remote_reflexive) else {
            return PredictionPlan::None;
        };
        let p = Predictability::Predictable {
            base_port: hint.base_port,
            delta: hint.delta,
        };
        return match predictor.plan(&p, target.ip(), k) {
            Some(spray) => PredictionPlan::Spray(spray),
            None => PredictionPlan::None,
        };
    }
    PredictionPlan::None
}

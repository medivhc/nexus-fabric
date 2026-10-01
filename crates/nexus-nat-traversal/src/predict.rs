//! Track B 实现：有界端口预测（合同 P3 冻结规则）。
//!
//! - `assess`：至少 3 个样本；连续两两 Δ 相等 →
//!   `Predictable{base_port: 最后一个样本端口, delta}`；否则 `Unpredictable`。
//! - `plan`：只对 `Predictable` 返回 `Some`；
//!   `ports` 以 `base+delta`（u16 回绕）为中心向两侧扩展 K 个，
//!   总数 `<= 2*K+1`，K 上限 32。

use std::net::IpAddr;

use crate::{PortSample, Predictability, PunchPredictor, SprayPlan};

/// spray 半径 K 上限（合同 P3 冻结：32）。
const MAX_SPRAY_K: u8 = 32;

/// 最少样本数（合同 P3 冻结：3）。
const MIN_SAMPLES: usize = 3;

#[derive(Debug, Default)]
pub struct DefaultPredictor;

impl DefaultPredictor {
    /// 若所有连续两两 Δ 相等则返回该 Δ，否则 `None`（含样本不足）。
    fn uniform_delta(samples: &[PortSample]) -> Option<i32> {
        if samples.len() < MIN_SAMPLES {
            return None;
        }
        let first = samples[1].port as i32 - samples[0].port as i32;
        let uniform = samples
            .windows(2)
            .all(|w| w[1].port as i32 - w[0].port as i32 == first);
        uniform.then_some(first)
    }
}

impl PunchPredictor for DefaultPredictor {
    fn assess(&self, samples: &[PortSample]) -> Predictability {
        match Self::uniform_delta(samples) {
            Some(delta) => Predictability::Predictable {
                base_port: samples[samples.len() - 1].port,
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
        // 中心 = base + delta，u16 回绕语义（`as u16` 对负 delta 做 mod 2^16）。
        let center = base_port.wrapping_add(*delta as u16);
        let k_i32 = i32::from(k);
        let mut ports = Vec::with_capacity(2 * k_i32 as usize + 1);
        for i in -k_i32..=k_i32 {
            ports.push(center.wrapping_add(i as u16));
        }
        Some(SprayPlan { target_ip, ports })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn predictor() -> DefaultPredictor {
        DefaultPredictor
    }

    fn samples(ports: &[u16]) -> Vec<PortSample> {
        ports
            .iter()
            .enumerate()
            .map(|(i, &port)| PortSample {
                port,
                at_ms: i as u64 * 100,
            })
            .collect()
    }

    #[test]
    fn wraparound_center_and_window() {
        // 回绕：base=65534, delta=1 → 中心=65535；base=65535, delta=1 → 中心=0。
        let p = predictor();
        let plan = p
            .plan(
                &Predictability::Predictable {
                    base_port: 65535,
                    delta: 1,
                },
                std::net::IpAddr::from([192, 0, 2, 1]),
                2,
            )
            .unwrap();
        assert_eq!(plan.ports, vec![65534, 65535, 0, 1, 2]);
    }

    #[test]
    fn zero_delta_is_predictable() {
        // 端口保持（cone 行为）→ Δ 全 0 → Predictable。
        let p = predictor().assess(&samples(&[40000, 40000, 40000]));
        assert_eq!(
            p,
            Predictability::Predictable {
                base_port: 40000,
                delta: 0
            }
        );
    }

    #[test]
    fn k_zero_gives_single_port() {
        let p = predictor();
        let plan = p
            .plan(
                &Predictability::Predictable {
                    base_port: 1000,
                    delta: 5,
                },
                std::net::IpAddr::from([192, 0, 2, 1]),
                0,
            )
            .unwrap();
        assert_eq!(plan.ports, vec![1005]);
    }
}

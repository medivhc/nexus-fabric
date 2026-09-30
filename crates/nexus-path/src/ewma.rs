//! EWMA（指数加权移动平均）实时预测，第 1 层。
//!
//! 预测是打分的输入，不是独立模块（DESIGN §4.6, R2）。
//! 无样本时 [`Ewma::value`] 返回 `None`（unknown，S7），不编造分数。
//!
//! 趋势降权（第 2 层）、历史模式（第 3 层）后置，不上 ML。

/// 指数加权移动平均。
///
/// - `alpha`：新样本权重，钳位到 `(0, 1]`。`alpha = 1.0` 时退化为"只用最新样本"；
///   `alpha` 越小，历史权重越大、越平滑。
/// - 首个样本直接作为初值（无偏置启动），之后按 `alpha * sample + (1 - alpha) * prev` 更新。
#[derive(Debug, Clone)]
pub struct Ewma {
    alpha: f64,
    value: Option<f64>,
}

impl Ewma {
    /// 创建 EWMA。`alpha` 钳位到 `(0, 1]`；非有限值（NaN/Inf）钳位为 `1.0`。
    pub fn new(alpha: f64) -> Self {
        let alpha = if alpha.is_finite() {
            alpha.clamp(f64::MIN_POSITIVE, 1.0)
        } else {
            1.0
        };
        Self { alpha, value: None }
    }

    /// 喂入一个瞬时分数样本，返回更新后的平滑值。
    ///
    /// 非有限样本（NaN/Inf）被忽略（不更新、不返回），避免污染平滑值。
    pub fn update(&mut self, sample: f64) -> f64 {
        if !sample.is_finite() {
            // 保持上次值；若从未有有效样本，返回 NaN 明确表示 unknown。
            return self.value.unwrap_or(f64::NAN);
        }
        let next = match self.value {
            Some(prev) => self.alpha * sample + (1.0 - self.alpha) * prev,
            None => sample,
        };
        self.value = Some(next);
        next
    }

    /// 当前平滑值；`None` = 尚无有效样本（S7 unknown）。
    pub fn value(&self) -> Option<f64> {
        self.value
    }

    /// 当前 alpha（钳位后）。
    pub fn alpha(&self) -> f64 {
        self.alpha
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_then_smooths() {
        let mut e = Ewma::new(0.5);
        assert_eq!(e.value(), None);
        // 首个样本 = 初值
        assert_eq!(e.update(100.0), 100.0);
        assert_eq!(e.value(), Some(100.0));
        // 0.5*50 + 0.5*100 = 75
        assert_eq!(e.update(50.0), 75.0);
        assert_eq!(e.value(), Some(75.0));
    }

    #[test]
    fn alpha_clamped_to_unit_interval() {
        assert_eq!(Ewma::new(0.0).alpha(), f64::MIN_POSITIVE);
        assert_eq!(Ewma::new(-1.0).alpha(), f64::MIN_POSITIVE);
        assert_eq!(Ewma::new(2.0).alpha(), 1.0);
        assert_eq!(Ewma::new(f64::NAN).alpha(), 1.0);
        assert_eq!(Ewma::new(f64::INFINITY).alpha(), 1.0);
        // alpha=1.0: 只用最新样本
        let mut e = Ewma::new(1.0);
        e.update(100.0);
        assert_eq!(e.update(50.0), 50.0);
    }

    #[test]
    fn non_finite_sample_ignored() {
        let mut e = Ewma::new(0.5);
        // 无有效样本时，非有限样本不建立值
        assert!(e.update(f64::NAN).is_nan());
        assert_eq!(e.value(), None);
        e.update(100.0);
        // 有值后，非有限样本不污染
        assert_eq!(e.update(f64::INFINITY), 100.0);
        assert_eq!(e.value(), Some(100.0));
    }

    #[test]
    fn follows_climbing_sequence_downward() {
        // RTT 爬升 -> 瞬时分数下降，EWMA 必须跟随下降（path_predict_ewma 的核心）。
        let mut e = Ewma::new(0.3);
        let samples = [190.9, 119.6, 109.6, 104.8, 102.0]; // RTT 10->50->100->200->500ms
        let mut prev = f64::INFINITY;
        for s in samples {
            let v = e.update(s);
            assert!(v < prev, "EWMA should decrease: {v} < {prev}");
            prev = v;
        }
    }
}

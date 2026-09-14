# Product Scenarios

`scenarios/` 是产品级 E4 验证契约的唯一权威入口。

目录：

- `product/`：稳定产品能力。
- `regression/`：真实 bug 的最小复现。
- `platform/`：平台差异与降级路径。

新 Feature 必须先在 Contract Phase 提交 Scenario，并在旧实现上获得 FAIL/BLOCKED Red Evidence；随后 expectation 被冻结，Implementation Phase 不得静默修改。

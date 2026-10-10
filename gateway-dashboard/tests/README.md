# Cross-Crate Tests

这里放跨 crate 的 integration / regression / concurrency 测试资源与共享 fixture。

约束：

- 单 crate 行为优先放在 crate 自己的 tests。
- 产品行为优先进入 `scenarios/`，作为 E4 Contract。
- 真实 bug 的复现可以同时拥有 regression test 与 `scenarios/regression/`。
- 并发测试必须覆盖 cancellation、shutdown、terminal outcome race 和 crash recovery 边界。

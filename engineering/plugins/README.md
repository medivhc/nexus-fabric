# Harness Plugins

Harness Plugin 只适配已有工具，不重写工具本身。

预期插件类别：

```text
cargo
git
architecture-policy
dependency-governance
test-runner
coverage
fuzz
concurrency
benchmark
observability-replay
platform-build
```

Plugin contract：

1. 输入必须结构化。
2. 输出必须包含 `schema_version`、status/verdict、duration、artifacts。
3. 执行失败必须显式传播。
4. Plugin 不得把工具错误吞掉后返回 PASS。
5. Plugin 不得直接修改受保护的 Product/Scenario expectation。

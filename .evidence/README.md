# Evidence Store

此目录只保存 Harness 生成的验证证据，不手工维护 PASS。

推荐布局：

```text
.evidence/
└── verify-<id>/
    ├── summary.json
    ├── checks.json
    ├── tests.json
    ├── scenarios.json
    ├── architecture.json
    ├── benchmark.json
    ├── traces.json
    └── metadata.json
```

Evidence 必须绑定 revision、working-tree digest、config digest、feature set、target triple、toolchain、Harness schema 和 platform capability digest。任何相关输入变化后旧证据应变为 STALE。

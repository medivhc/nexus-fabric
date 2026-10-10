# Evidence Schema

这里定义 Harness 与 CI 共享的机器可读 Evidence Schema。

规则：

- Schema 必须显式版本化。
- 不兼容变更必须提升 `schema_version`。
- Evidence Freshness 由 revision/config/feature/target/toolchain/platform-capability digest 共同决定。
- 旧 Schema Evidence 可以保留用于审计，但不能被新版 Harness 无条件当作 fresh PASS。

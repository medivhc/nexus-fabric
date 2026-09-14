# Plugin Contract

最小输出：

```json
{
  "schema_version": 1,
  "plugin": "cargo-check",
  "status": "PASS",
  "duration_ms": 123,
  "artifacts": [],
  "diagnostics": []
}
```

合法 status：

```text
PASS
FAIL
BLOCKED
UNKNOWN
```

`STALE` 属于 Evidence Freshness 层，不由单个工具插件自行判断最终 Verdict。

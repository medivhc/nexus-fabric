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

## 例外：内嵌 provider 形态的 `code-intelligence`

`nexus-harness code <verb> --json` 是本契约的**内嵌 provider** 形态，不是独立
plugin：它的 `verdict` 只取 `PASS / FAIL / BLOCKED`，字段名与本契约不同
（`command` 代替 `plugin`、`verdict` 代替 `status`、`results`/`snapshot` 代替
`artifacts`、`error`/`budget`/`continuation` 代替 `diagnostics`），并额外携带
`provider` 进程内计数（`ready` / `restart_count` / `write_requests_refused` /
`dropped_notifications`）。逐字段映射与差异原因见同目录 `README.md`
《`code-intelligence` 类别的当前形态》。

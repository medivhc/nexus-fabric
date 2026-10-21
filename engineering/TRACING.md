# Nexus tracing design

## Goal

Add request/session/path-level causal tracing without turning log text into domain semantics or introducing reverse dependencies from domain crates into diagnostics.

The design follows the existing `nexus-diagnostics` contract: structured fields are stable; correlation identifiers are explicit; typed `Result`/DTO values remain the source of truth for failures.

## Architecture

Use the Rust `tracing` ecosystem as the in-process instrumentation API.

- Instrumentation: `tracing::{span, event, instrument}` in crates that own the operation being observed.
- Initialization: only Composition Roots (`nexusd`, later `nexus`) install a subscriber.
- Formatting/filtering: `tracing-subscriber` with `EnvFilter`; default human-readable output, optional JSON output.
- Export: keep the instrumentation API exporter-neutral. Add `tracing-opentelemetry` + OTLP only when a collector is deployed; domain crates must not depend on OpenTelemetry.
- Errors: emit error metadata as fields, but preserve typed errors as the program contract. Never require parsing log text to determine outcome.

Dependency direction:

```text
business/domain crates --(tracing events/spans)--> tracing facade
                                              |
                                              v
                         Composition Root installs subscriber
                                              |
                     +------------------------+----------------------+
                     |                                               |
              fmt/json layer                                optional OTLP layer
                                                                     |
                                                               OTel Collector
```

`nexus-diagnostics` owns shared observability vocabulary and helpers, not business state. It may expose stable field names, correlation context DTOs, and subscriber construction that does not depend on business crates.

## Correlation model

Every long-lived or cross-component operation should carry the identifiers that already exist in the domain model. Do not generate unrelated IDs when a stable domain identifier is available.

Canonical fields:

| Field | Meaning |
| --- | --- |
| `session.id` | Nexus session correlation ID |
| `resource.id` | Resource being acted on |
| `provider.id` | Selected/attempted provider |
| `plan.id` | Plan snapshot/version |
| `path.id` | Network/path candidate or selected path |
| `workspace.id` | Workspace/task workspace |
| `operation` | Stable operation name |
| `outcome` | `ok`, `cancelled`, `failed`, `degraded`, etc. |
| `error.code` | Stable typed error/category code |

High-cardinality values belong in span/event fields, not metric labels.

## Span boundaries

Create spans around ownership/lifecycle boundaries, not every function call.

Recommended initial spans:

- `daemon.run`: process/config-root lifetime.
- `config.reload`: load -> validate -> apply, including generation/hash.
- `session.run`: create/attach -> plan -> execute -> terminal outcome.
- `plan.evaluate`: policy + candidate selection.
- `path.connect`: candidate/path attempt including transport and endpoint class.
- `proxy.request`: ingress -> route selection -> outbound establishment.
- `workspace.task`: task dispatch/reconcile lifecycle.

Child spans should inherit the parent correlation context. Background threads/tasks must explicitly enter or instrument the parent span rather than relying on thread-local logging context.

## Event levels

- `ERROR`: operation failed and requires operator/actionable investigation.
- `WARN`: degraded/fallback/retry/rejected configuration; operation may continue.
- `INFO`: lifecycle transitions and externally meaningful decisions.
- `DEBUG`: decision details useful for diagnosis.
- `TRACE`: packet/frame/loop-level information; disabled by default and sampled/filtered narrowly.

Do not put packet contents, credentials, proxy secrets, tokens, or user payloads into spans/events.

## Runtime configuration

Phase 1 subscriber contract:

```text
NEXUS_LOG=info,nexus_network=debug,nexus_connectivity=trace
NEXUS_LOG_FORMAT=compact|json
```

If `NEXUS_LOG` is absent, default to `info`; `TRACE` must never be globally enabled by default. JSON output is intended for machine collection and preserves structured fields.

Phase 2 OTLP contract, only after a collector is part of deployment:

```text
NEXUS_OTEL_EXPORTER=otlp
OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4317
OTEL_SERVICE_NAME=nexusd
```

Exporter failure must not crash the daemon or block a data-plane hot path. Use bounded/non-blocking export and expose dropped telemetry as a counter/event.

## Migration plan

### Phase 0 — coverage/evidence baseline

Land the coverage workflow in the same observability change so instrumentation changes have a regression signal. The initial line threshold is deliberately modest (60%) and should ratchet upward; it must never be lowered merely to make CI green.

### Phase 1 — local structured tracing

1. Add `tracing` to workspace crates that emit spans/events.
2. Add `tracing-subscriber` to Composition Roots only.
3. Put subscriber/bootstrap helpers and shared field vocabulary in `nexus-diagnostics` if reuse is needed.
4. Initialize tracing at the beginning of `nexusd::main` before subsystem assembly.
5. Migrate `eprintln!` sites incrementally, starting with daemon startup/shutdown, N2 session lifecycle, dataplane creation/failure, config reload, and proxy/path establishment.
6. Add tests for filter parsing/defaults and a writer-backed subscriber test proving required correlation fields are emitted.

Acceptance criteria:

- daemon behavior is unchanged when no tracing environment variables are set;
- no domain failure semantics depend on log strings;
- at least one end-to-end daemon path emits nested spans containing `session.id` or the relevant correlation identifier;
- secrets/payloads are absent from trace snapshots.

### Phase 2 — distributed trace propagation

Define a transport-neutral `TraceContext { traceparent, tracestate }` DTO at protocol boundaries; propagate W3C Trace Context through Nexus control/protocol messages where a remote hop represents the same logical operation. Do not inject propagation into arbitrary user traffic.

Acceptance criteria:

- client/daemon/remote-agent spans for one Nexus operation share one trace;
- context survives async/thread boundaries;
- malformed/untrusted incoming trace context is rejected or replaced safely.

### Phase 3 — OpenTelemetry export and sampling

Add OTLP in Composition Roots behind a feature/config flag. Use parent-based sampling; always retain errors and important terminal events where the SDK permits, while aggressively sampling hot packet/frame spans.

Suggested production policy:

- lifecycle/control-plane spans: 100% initially;
- connection/path attempts: head sample 10-100% depending on volume;
- packet/frame spans: disabled by default, temporary targeted diagnostics only.

## Testing strategy

Tracing tests should assert structure, not prose:

1. subscriber bootstrap accepts valid filters and falls back safely on invalid/missing configuration;
2. representative span records canonical correlation fields;
3. child task/thread instrumentation preserves the parent span;
4. redaction test covers known secret-bearing configuration values;
5. exporter disabled/unreachable does not change operation success/failure;
6. high-volume trace-level instrumentation benchmark stays below an explicit disabled-path overhead budget.

## Coverage policy

`scripts/coverage.sh` is the single local/CI entrypoint. It uses `cargo-llvm-cov` across the workspace with all features, writes `target/coverage/lcov.info` plus `summary.txt`, and fails below `NEXUS_COVERAGE_MIN_LINES` (default 60).

CI uploads the report as evidence for every PR and `master` push. The threshold is a floor, not a target; once the baseline is observed, raise it monotonically and consider adding changed-lines coverage separately so legacy gaps do not discourage well-tested new code.

Coverage exclusions should be semantic and rare: generated code, vendored code, or platform code that cannot execute on the CI target. Never exclude a file solely because it has poor coverage.

# FILE MANIFEST

本包实现《Nexus 统一系统设计规范 v9》中的“统一仓库目录契约”。

文件数（不含本清单）：194

> 2026-10-10：原声明值 137 与表内实际行数（148）已不一致（既有漂移，含
> `scenarios/engineering/bench_gate_verdicts.toml` 等未登记项）。本次登记
> Code Intelligence 的 18 个新文件时一并改为与表内行数一致，并补登该缺口。
>
> 2026-10-10（第二轮，独立 Review round 1 整改）：补登 `code_intelligence_callees`、
> `code_intelligence_read_only_counters`、`code_intelligence_scope_violation`、
> `code_intelligence_budget_count` 四个场景与 `.agents/green-evidence-code-intelligence.txt`，
> 声明值同步为表内行数。
>
> 2026-10-10（第三轮，独立 Review round 2 整改）：补登
> `code_intelligence_scope_escape.toml`（目标用 `..` 逃出 `--workspace`）与
> `code_intelligence_workspace_escape.toml`（`--workspace` 根逃出仓库，须在 spawn 前被拒），
> 声明值 172 -> 174。注意 `.evidence/review-*` 与 `verify-*` 目录由 `.gitignore` 排除，
> 不进本清单；Review 案卷因此只在本机可见，需要分享时得显式 `git add -f`。
>
> 2026-10-10（第四轮，独立 Review round 3 判 `COMMENTED`）：补登
> `.agents/code-intelligence-followups.md`（12 条后续待办的承载体，避免"待办只写在提交说明里"），
> 声明值 174 -> 175。
>
> 2026-10-10（第五轮，round 3 待办 3 落地）：补登
> `scenarios/engineering/code_intelligence_diagnostics_item_shape.toml`（诊断条目形状的 E4）
> 与其夹具 `engineering/nexus-harness/fixtures/code-intel/src/diagnostic_probe.rs`
> （刻意留一处类型错误；`lib.rs` 只在**末尾**挂 `mod diagnostic_probe;`，否则会挪动
> `lib.rs:9:21` / `lib.rs:23:12` 两个冻结锚点），声明值 175 -> 177。
> 本轮先跑出新场景的 Red（`scenario-edf5bdf1d4b8`，夹具文件尚不存在 ⇒ `verdict` 期望落空），
> 再加夹具转 Green——契约先行，不是先看输出再补期望。
>
> 2026-10-11（Phase 2-4 开工）：登记 `.agents/code-intelligence-phase-2-4-plan.md`，声明值 177 -> 178。
>
> 2026-10-12（测试盲评 round 2 打回后二次修订）：selftest 字段清单 30 -> 32、补缓存命中回放契约与 status 默认值场景，场景总数 26 -> 27，声明值 193 -> 194。
> 2026-10-12（测试用例盲评打回后重写）：4 条 daemon 场景改为逐条钉契约字段值并新增 1 条未知参数场景，场景总数 25 -> 26，声明值 192 -> 193。
> 2026-10-12（daemon 与结果缓存开工，契约先行）：登记设计计划、4 条新 E4 场景与 Red Evidence，声明值 186 -> 192；Code Intelligence 场景总数由 21 增至 25。
> 2026-10-11（独立 Review round 2 整改）：登记 `.agents/red-evidence-mcp-round2.txt`，声明值 185 -> 186。
> 2026-10-11（Phase 2/3/4 契约与实现）：新增夹具 `MODULE.md`、`code_intel/mcp.rs` 与
> 5 个场景（context 语义锚点 3 条、MCP 2 条），声明值 178 -> 185；
> Code Intelligence 场景总数由 16 增至 21（Phase 2 三条、Phase 3 两条）。
>
> 既有缺口（非本次引入，保留待仓库所有者裁决）：`.evidence/.gitignore`、
> `.evidence/README.md` 两行来自基线（`7d2e643`），但这两个文件已在
> `5694faa`（"untrack generated .evidence artifacts"）中被取消跟踪，磁盘上也不
> 存在，因此按"表内行数"统计的值比按 `git ls-files` 口径多 2。本清单未按
> `git ls-files` 口径校准，此处如实标注差异而不是静默改数。

| Path | Purpose |
|---|---|
| `.agents/code-intelligence-phase-2-4-plan.md` | 提案 §15 Phase 2/3/4 的工作计划与判据（含多语言/冷启动的实测证据与逐项做/不做的判断台账） |
| `.agents/code-intelligence-followups.md` | 独立 Review round 3（`COMMENTED`）的 12 条后续待办，逐条带 `文件:行` 与验收动作；作为"机器可见的待办承载体" |
| `.agents/green-evidence-code-intelligence.txt` | Green Evidence record（Code Intelligence E4 场景全 PASS，正文记录其绑定的 source_revision） |
| `.agents/red-evidence-code-intelligence.txt` | Red Evidence record（Code Intelligence 契约阶段 9/9 FAIL） |
| `.agents/red-evidence-mcp-round2.txt` | Red Evidence record（MCP stdout 通道泄漏、PASS 分支不可探针、`--provider-binary` 静默丢弃的修前实测） |
| `.agents/provider-daemon-and-result-cache-plan.md` | Provider daemon 与结果缓存的设计与实施计划（授权范围、生命周期护栏、两层缓存定义、验收判据） |
| `.agents/red-evidence-daemon.txt` | Red Evidence record（daemon 命令面与缓存字段实现前的四条红灯，含 evidence_id） |
| `scenarios/engineering/code_intelligence_daemon_lifecycle.toml` | E4：daemon 显式生命周期与跨命令复用（selftest 13 探针、probe_count 钉死） |
| `scenarios/engineering/code_intelligence_daemon_explicit_only.toml` | E4：`--no-daemon` 下 session_source=in-process，证明 CLI 不自动拉起 daemon |
| `scenarios/engineering/code_intelligence_cache_disabled.toml` | E4：`--no-cache` 下 cache.disabled=true 且 tier=miss，键绑定仍可见 |
| `scenarios/engineering/code_intelligence_daemon_command_surface.toml` | E4：daemon 未知子命令 BLOCKED，且 declined 输出仍带 authority 与 daemon.running |
| `scenarios/engineering/code_intelligence_daemon_unknown_flag.toml` | E4：daemon 未知启动参数 BLOCKED（参数不接受即失败，不静默忽略） |
| `scenarios/engineering/code_intelligence_daemon_status_defaults.toml` | E4：无 daemon 时 status 仍报契约默认值（不钉 verdict，避免环境依赖） |
| `.agents/skills/README.md` | Project-level agent skill index |
| `.agents/skills/nexus-contract-first/SKILL.md` | Project-level agent skill |
| `.agents/skills/nexus-evidence/SKILL.md` | Project-level agent skill |
| `.agents/skills/nexus-multiagent/SKILL.md` | Project-level agent skill |
| `.agents/skills/nexus-selfrepair/SKILL.md` | Project-level agent skill |
| `.agents/skills/nexus-task/SKILL.md` | Project-level agent skill |
| `.evidence/.gitignore` | Evidence store contract |
| `.evidence/README.md` | Evidence store contract |
| `.githooks/README.md` | Machine-enforced git gate hooks (documentation) |
| `.githooks/commit-msg` | Machine-enforced git gate hook |
| `.githooks/hook-common.sh` | Machine-enforced git gate hook (shared helpers) |
| `.githooks/install.ps1` | Hook installer (Windows/PowerShell) |
| `.githooks/install.sh` | Hook installer (POSIX) |
| `.githooks/pre-commit` | Machine-enforced git gate hook |
| `.githooks/pre-push` | Machine-enforced git gate hook |
| `.gitattributes` | Repository contract/documentation |
| `.gitignore` | Repository contract/documentation |
| `ARCHITECTURE.md` | Repository contract/documentation |
| `Cargo.lock` | Repository contract/documentation |
| `Cargo.toml` | Rust package/workspace manifest |
| `DEVELOPMENT.md` | Repository contract/documentation |
| `PRODUCT.md` | Repository contract/documentation |
| `README.md` | Repository contract/documentation |
| `apps/nexus-platform-host/Cargo.toml` | Rust package/workspace manifest |
| `apps/nexus-platform-host/MODULE.md` | Module Contract |
| `apps/nexus-platform-host/src/main.rs` | Minimal compile/bootstrap source |
| `apps/nexus/Cargo.toml` | Rust package/workspace manifest |
| `apps/nexus/MODULE.md` | Module Contract |
| `apps/nexus/src/main.rs` | Minimal compile/bootstrap source |
| `apps/nexusd/Cargo.toml` | Rust package/workspace manifest |
| `apps/nexusd/MODULE.md` | Module Contract |
| `apps/nexusd/src/main.rs` | Minimal compile/bootstrap source |
| `benches/README.md` | Repository contract/documentation |
| `crates/nexus-auth/Cargo.toml` | Rust package/workspace manifest |
| `crates/nexus-auth/MODULE.md` | Module Contract |
| `crates/nexus-auth/src/lib.rs` | Minimal compile/bootstrap source |
| `crates/nexus-compute/Cargo.toml` | Rust package/workspace manifest |
| `crates/nexus-compute/MODULE.md` | Module Contract |
| `crates/nexus-compute/src/lib.rs` | Minimal compile/bootstrap source |
| `crates/nexus-connectivity/Cargo.toml` | Rust package/workspace manifest |
| `crates/nexus-connectivity/MODULE.md` | Module Contract |
| `crates/nexus-connectivity/src/lib.rs` | Minimal compile/bootstrap source |
| `crates/nexus-control-api/Cargo.toml` | Rust package/workspace manifest |
| `crates/nexus-control-api/MODULE.md` | Module Contract |
| `crates/nexus-control-api/src/lib.rs` | Minimal compile/bootstrap source |
| `crates/nexus-delivery/Cargo.toml` | Rust package/workspace manifest |
| `crates/nexus-delivery/MODULE.md` | Module Contract |
| `crates/nexus-delivery/src/lib.rs` | Minimal compile/bootstrap source |
| `crates/nexus-diagnostics/Cargo.toml` | Rust package/workspace manifest |
| `crates/nexus-diagnostics/MODULE.md` | Module Contract |
| `crates/nexus-diagnostics/src/lib.rs` | Minimal compile/bootstrap source |
| `crates/nexus-discovery/Cargo.toml` | Rust package/workspace manifest |
| `crates/nexus-discovery/MODULE.md` | Module Contract |
| `crates/nexus-discovery/src/lib.rs` | Minimal compile/bootstrap source |
| `crates/nexus-dns/Cargo.toml` | Rust package/workspace manifest |
| `crates/nexus-dns/MODULE.md` | Module Contract |
| `crates/nexus-dns/src/lib.rs` | Minimal compile/bootstrap source |
| `crates/nexus-domain/Cargo.toml` | Rust package/workspace manifest |
| `crates/nexus-domain/MODULE.md` | Module Contract |
| `crates/nexus-domain/src/lib.rs` | Minimal compile/bootstrap source |
| `crates/nexus-ingress/Cargo.toml` | Rust package/workspace manifest |
| `crates/nexus-ingress/MODULE.md` | Module Contract |
| `crates/nexus-ingress/src/lib.rs` | Minimal compile/bootstrap source |
| `crates/nexus-measurement/Cargo.toml` | Rust package/workspace manifest |
| `crates/nexus-measurement/MODULE.md` | Module Contract |
| `crates/nexus-measurement/src/lib.rs` | Minimal compile/bootstrap source |
| `crates/nexus-network/Cargo.toml` | Rust package/workspace manifest |
| `crates/nexus-network/MODULE.md` | Module Contract |
| `crates/nexus-network/src/lib.rs` | Minimal compile/bootstrap source |
| `crates/nexus-planner/Cargo.toml` | Rust package/workspace manifest |
| `crates/nexus-planner/MODULE.md` | Module Contract |
| `crates/nexus-planner/src/lib.rs` | Minimal compile/bootstrap source |
| `crates/nexus-platform-android/Cargo.toml` | Rust package/workspace manifest |
| `crates/nexus-platform-android/MODULE.md` | Module Contract |
| `crates/nexus-platform-android/src/lib.rs` | Minimal compile/bootstrap source |
| `crates/nexus-platform-ios/Cargo.toml` | Rust package/workspace manifest |
| `crates/nexus-platform-ios/MODULE.md` | Module Contract |
| `crates/nexus-platform-ios/src/lib.rs` | Minimal compile/bootstrap source |
| `crates/nexus-platform-linux/Cargo.toml` | Rust package/workspace manifest |
| `crates/nexus-platform-linux/MODULE.md` | Module Contract |
| `crates/nexus-platform-linux/src/lib.rs` | Minimal compile/bootstrap source |
| `crates/nexus-platform-macos/Cargo.toml` | Rust package/workspace manifest |
| `crates/nexus-platform-macos/MODULE.md` | Module Contract |
| `crates/nexus-platform-macos/src/lib.rs` | Minimal compile/bootstrap source |
| `crates/nexus-platform-windows/Cargo.toml` | Rust package/workspace manifest |
| `crates/nexus-platform-windows/MODULE.md` | Module Contract |
| `crates/nexus-platform-windows/src/lib.rs` | Minimal compile/bootstrap source |
| `crates/nexus-platform/Cargo.toml` | Rust package/workspace manifest |
| `crates/nexus-platform/MODULE.md` | Module Contract |
| `crates/nexus-platform/src/lib.rs` | Minimal compile/bootstrap source |
| `crates/nexus-policy/Cargo.toml` | Rust package/workspace manifest |
| `crates/nexus-policy/MODULE.md` | Module Contract |
| `crates/nexus-policy/src/lib.rs` | Minimal compile/bootstrap source |
| `crates/nexus-proto/Cargo.toml` | Rust package/workspace manifest |
| `crates/nexus-proto/MODULE.md` | Module Contract |
| `crates/nexus-proto/src/lib.rs` | Minimal compile/bootstrap source |
| `crates/nexus-registry/Cargo.toml` | Rust package/workspace manifest |
| `crates/nexus-registry/MODULE.md` | Module Contract |
| `crates/nexus-registry/src/lib.rs` | Minimal compile/bootstrap source |
| `crates/nexus-service/Cargo.toml` | Rust package/workspace manifest |
| `crates/nexus-service/MODULE.md` | Module Contract |
| `crates/nexus-service/src/lib.rs` | Minimal compile/bootstrap source |
| `crates/nexus-session/Cargo.toml` | Rust package/workspace manifest |
| `crates/nexus-session/MODULE.md` | Module Contract |
| `crates/nexus-session/src/lib.rs` | Minimal compile/bootstrap source |
| `crates/nexus-storage/Cargo.toml` | Rust package/workspace manifest |
| `crates/nexus-storage/MODULE.md` | Module Contract |
| `crates/nexus-storage/src/lib.rs` | Minimal compile/bootstrap source |
| `crates/nexus-transport/Cargo.toml` | Rust package/workspace manifest |
| `crates/nexus-transport/MODULE.md` | Module Contract |
| `crates/nexus-transport/src/lib.rs` | Minimal compile/bootstrap source |
| `crates/nexus-workspace/Cargo.toml` | Rust package/workspace manifest |
| `crates/nexus-workspace/MODULE.md` | Module Contract |
| `crates/nexus-workspace/src/lib.rs` | Minimal compile/bootstrap source |
| `engineering/evidence-schema/README.md` | Repository contract/documentation |
| `engineering/evidence-schema/evidence.schema.json` | Machine-readable schema |
| `engineering/nexus-harness/Cargo.toml` | Rust package/workspace manifest |
| `engineering/nexus-harness/MODULE.md` | Module Contract |
| `engineering/nexus-harness/fixtures/code-intel/Cargo.toml` | Rust package manifest (code-intelligence fixture, standalone workspace) |
| `engineering/nexus-harness/fixtures/code-intel/src/lib.rs` | Rust source (fixture: re-export/cfg/probe) |
| `engineering/nexus-harness/fixtures/code-intel/src/transport.rs` | Rust source (fixture: trait + multi-impl + generic dispatch) |
| `engineering/nexus-harness/fixtures/code-intel/src/diagnostic_probe.rs` | Rust source (fixture: 刻意一处类型错误，供诊断条目形状 E4 断言) |
| `engineering/nexus-harness/fixtures/code-intel/MODULE.md` | 夹具自身的模块契约（context 的语义候选只从这里取，反引号标识符即候选） |
| `engineering/nexus-harness/src/main.rs` | Minimal compile/bootstrap source |
| `engineering/nexus-harness/src/env.rs` | Rust source (harness CLI) |
| `engineering/nexus-harness/src/config.rs` | Rust source (harness CLI) |
| `engineering/nexus-harness/src/gates.rs` | Rust source (harness CLI) |
| `engineering/nexus-harness/src/scenario.rs` | Rust source (harness CLI) |
| `engineering/nexus-harness/src/evidence.rs` | Rust source (harness CLI) |
| `engineering/nexus-harness/src/code_intel/mcp.rs` | Rust source (MCP stdio 薄适配：tools/list + tools/call 映射到 8 个只读 verb，含 selftest) |
| `engineering/nexus-harness/src/code_intel/mod.rs` | Rust source (Code Intelligence CLI 层：参数/预算/snapshot/envelope) |
| `engineering/nexus-harness/src/code_intel/dto.rs` | Rust source (Code Intelligence 语言中立 DTO 与错误码) |
| `engineering/nexus-harness/src/code_intel/lsp.rs` | Rust source (JSON-RPC/LSP framing、只读白名单、有界会话) |
| `engineering/nexus-harness/src/code_intel/provider.rs` | Rust source (CodeIntelligenceProvider 契约与 binary 解析) |
| `engineering/nexus-harness/src/code_intel/rust_analyzer.rs` | Rust source (rust-analyzer provider：生命周期/就绪收敛/语义映射) |
| `engineering/nexus-harness/src/commands.rs` | Rust source (harness CLI) |
| `engineering/plugins/README.md` | Repository contract/documentation |
| `engineering/plugins/plugin-contract.md` | Repository contract/documentation |
| `fuzz/README.md` | Repository contract/documentation |
| `fuzz/fuzz_targets/README.md` | Repository contract/documentation |
| `harness.toml` | Machine-readable contract/policy/scenario |
| `policies/architecture.toml` | Machine-readable contract/policy/scenario |
| `policies/dependencies.toml` | Machine-readable contract/policy/scenario |
| `policies/deny.toml` | Machine-readable contract/policy/scenario (cargo-deny executor config) |
| `policies/quality.toml` | Machine-readable contract/policy/scenario |
| `scenarios/README.md` | Repository contract/documentation |
| `scenarios/engineering/bench_gate_verdicts.toml` | Machine-readable contract/policy/scenario |
| `scenarios/engineering/code_intelligence_budget_count.toml` | Machine-readable contract/policy/scenario |
| `scenarios/engineering/code_intelligence_budget_truncation.toml` | Machine-readable contract/policy/scenario |
| `scenarios/engineering/code_intelligence_callees.toml` | Machine-readable contract/policy/scenario |
| `scenarios/engineering/code_intelligence_callers.toml` | Machine-readable contract/policy/scenario |
| `scenarios/engineering/code_intelligence_definition.toml` | Machine-readable contract/policy/scenario |
| `scenarios/engineering/code_intelligence_diagnostics_advisory.toml` | Machine-readable contract/policy/scenario |
| `scenarios/engineering/code_intelligence_context_anchors.toml` | Machine-readable contract/policy/scenario |
| `scenarios/engineering/code_intelligence_context_no_fake_semantics.toml` | Machine-readable contract/policy/scenario |
| `scenarios/engineering/code_intelligence_context_scope_guard.toml` | Machine-readable contract/policy/scenario |
| `scenarios/engineering/code_intelligence_diagnostics_item_shape.toml` | Machine-readable contract/policy/scenario |
| `scenarios/engineering/code_intelligence_mcp_handshake.toml` | Machine-readable contract/policy/scenario |
| `scenarios/engineering/code_intelligence_mcp_real_query.toml` | Machine-readable contract/policy/scenario |
| `scenarios/engineering/code_intelligence_hover.toml` | Machine-readable contract/policy/scenario |
| `scenarios/engineering/code_intelligence_implementations.toml` | Machine-readable contract/policy/scenario |
| `scenarios/engineering/code_intelligence_provider_unavailable.toml` | Machine-readable contract/policy/scenario |
| `scenarios/engineering/code_intelligence_read_only_counters.toml` | Machine-readable contract/policy/scenario |
| `scenarios/engineering/code_intelligence_scope_escape.toml` | Machine-readable contract/policy/scenario |
| `scenarios/engineering/code_intelligence_scope_violation.toml` | Machine-readable contract/policy/scenario |
| `scenarios/engineering/code_intelligence_symbol.toml` | Machine-readable contract/policy/scenario |
| `scenarios/engineering/code_intelligence_workspace_escape.toml` | Machine-readable contract/policy/scenario |
| `scenarios/engineering/code_intelligence_write_method_denied.toml` | Machine-readable contract/policy/scenario |
| `scenarios/engineering/harness_status_verdicts.toml` | Machine-readable contract/policy/scenario |
| `scenarios/engineering/harness_verify_fast_evidence.toml` | Machine-readable contract/policy/scenario |
| `scenarios/platform/virtual_packet_interface.toml` | Machine-readable contract/policy/scenario |
| `scenarios/platform/workspace_projection_fallback.toml` | Machine-readable contract/policy/scenario |
| `scenarios/product/internet_access_flow.toml` | Machine-readable contract/policy/scenario |
| `scenarios/product/resource_session_lifecycle.toml` | Machine-readable contract/policy/scenario |
| `scenarios/product/workspace_offline_merge.toml` | Machine-readable contract/policy/scenario |
| `scenarios/regression/crash_recovery.toml` | Machine-readable contract/policy/scenario |
| `scenarios/regression/session_outcome_exactly_once.toml` | Machine-readable contract/policy/scenario |
| `tests/README.md` | Repository contract/documentation |
| `tests/concurrency/README.md` | Repository contract/documentation |
| `tests/integration/README.md` | Repository contract/documentation |
| `tests/regression/README.md` | Repository contract/documentation |

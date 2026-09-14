# FILE MANIFEST

本包实现《Nexus 统一系统设计规范 v9》中的“统一仓库目录契约”。

文件数（不含本清单）：137

| Path | Purpose |
|---|---|
| `.agents/skills/README.md` | Project-level agent skill index |
| `.agents/skills/nexus-contract-first/SKILL.md` | Project-level agent skill |
| `.agents/skills/nexus-evidence/SKILL.md` | Project-level agent skill |
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
| `engineering/nexus-harness/src/main.rs` | Minimal compile/bootstrap source |
| `engineering/plugins/README.md` | Repository contract/documentation |
| `engineering/plugins/plugin-contract.md` | Repository contract/documentation |
| `fuzz/README.md` | Repository contract/documentation |
| `fuzz/fuzz_targets/README.md` | Repository contract/documentation |
| `harness.toml` | Machine-readable contract/policy/scenario |
| `policies/architecture.toml` | Machine-readable contract/policy/scenario |
| `policies/dependencies.toml` | Machine-readable contract/policy/scenario |
| `policies/quality.toml` | Machine-readable contract/policy/scenario |
| `scenarios/README.md` | Repository contract/documentation |
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

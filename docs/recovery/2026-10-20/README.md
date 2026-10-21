# 2026-10-20 代码恢复归档

本目录保留10月20日的取证快照，原manifest及payload不变。10月21日已补齐其下列缺项并集成活跃N3-12代码，当前状态见[后续恢复记录](../2026-10-21/README.md)。

本目录保存能核对来源的历史源码，供后续恢复使用。它不是已装配的 N3-12 发布版，也不证明已找回10月19日最终工作树。当前功能请看[功能总结](../../N3-RECOVERY-FUNCTION-SUMMARY.md)。

## 阅读方式

- [canonical-export-manifest.json](canonical-export-manifest.json)：15个完整文件的字节数与 SHA-256 精确匹配10月17日部分历史清单。payload位于 `sources/exact/`，原路径追加 `.txt`。
- [unverified-code-export-manifest.json](unverified-code-export-manifest.json)：40个完整中间代码候选（包含同一路径的不同版本），位于 `sources/candidates/`，带内容哈希后缀。它们未通过最终历史哈希确认；其中有测试 RED 基线和仅格式化派生版本，不能当作最终实现。
- 每项 `repo_path` 是原仓库路径，`archive_path` 是归档路径，`sha256/bytes` 核对实际保存的字节。来源 thread/turn/item 与源记录哈希仅为取证标识；不包含原始对话、命令脚本、凭证或构建产物。
- 所有源码副本以 `.txt` 保存，不自动写回原路径。缺少基线或补丁原文的片段不伪装成完整源码；缺口仍留在清单中。恢复前先核实完整契约、最终源码/测试和来源，再按原冻结要求重建验证，不可把中间骨架当成生产实现。

## 当时仍缺的历史文件（现已补齐）

这只是27项部分历史清单中的12项；其他 backend/CLI/freeze、N3-11 lease、N3-12 TTL/expiry 与 N3-13材料的最终完整性也没有证明。

- `apps/nexusd/src/main.rs`
- `apps/nexusd/src/task_http.rs`
- `apps/nexusd/src/task_provider_command.rs`
- `apps/nexusd/src/lib.rs`
- `crates/nexus-control-api/src/lib.rs`
- `crates/nexus-control-api/tests/snapshot_contract.rs`
- `apps/nexusd/tests/n3_snapshot_staging_binary.py`
- `engineering/verifiers/n3_snapshot_staging.py`
- `apps/nexusd/src/snapshot_staging_tests/authority.rs`
- `apps/nexusd/src/snapshot_staging_tests/core.rs`
- `apps/nexusd/src/snapshot_staging_tests/pressure.rs`
- `apps/nexusd/src/snapshot_staging_tests/recovery.rs`

## 验证范围

[verification.json](verification.json)与同目录原生 Check/Affected/Fast/E4 JSON验证的是活跃构建的N3-11/Fabric集成代码，非本目录候选。旧提交 `a97cfc0b63766a585d0194cebf5568be3092f92a` 的本地对象/远端 Git 与 GitHub API均未取得；历史根及子代理记录可恢复部分原文，但若 `fileChange` 仅保留路径、原始patch缺失或输出截断，则继续标缺。没有根据记忆补造源码，也没有执行历史命令。

后续需要原工作区的完整 Git bundle/patch/源码备份来核对最终版本；在此之前保留本目录原字节与缺口。真实 Full、Windows→Linux E5及完整 Submit 产品链路未验收。

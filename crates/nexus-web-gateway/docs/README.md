# nexus-web-gateway 文档索引

网关模块的 canonical 文档位置（SPEC §2 F2）。

- `requirements.toml`：需求跟踪（TOML，CI 校验）
- `tools/validate-requirements.py`：需求校验脚本
- `tools/gen-dashboard.py`：看板生成脚本

## 2026-10-10/11 网关文件服务这一轮的案卷

入口是复盘文档，其余三份是它下面的证据/评审/设计件。

- `docs/GATEWAY-FILE-SERVICE-RETROSPECTIVE-2026-10-11.md`：**总索引** —— 本轮收获、
  文档地图、产物清单、已固化决策（D0-D8）、M0-M4 计划与三次进度快照（§5b/§5c/§5d）。
- `docs/FILE-MODULE-VERIFICATION-2026-10-10.md`：文件模块 V1 + ICE 候选修复（G11）的
  实现与自验证案卷，含**两处公开更正**（把 Windows 编译阻塞与 CI 红混为一谈、
  对 harness digest 机制的错指）。
- `docs/FILE-MODULE-REVIEW-2026-10-11.md`：同一变更的 18 角度独立评审汇总
  （16 FAIL / 1 WARN / 1 COMMENTED，P0-1..P0-12）。**不是** `.evidence` Review 案卷，
  不能被提交门禁引用。
- `docs/GATEWAY-FILE-SERVICE-DESIGN-V2.md`：文件服务重做设计 rev2.1（对齐
  N3-4/N3-9 Artifact 契约）。§14 是上一轮 8 条 CHANGES_REQUESTED 的处置表。

**读这四份文件时必须知道的三件事**：

1. **V1 代码不在本仓库**。案卷里大量引用的 `crates/nexus-web-gateway/src/file.rs`、
   前端文件面板、REQ-005..009 那套实现从未合入任何分支，只作为反证留在会话产物目录
   （`plan-artifacts/file-module-attempt.patch` + `snapshot/`，未入库）。因此文中所有
   `file.rs:NN` 定位在本仓库里**点不开**，需要复核得取那份 patch。
2. **M0 契约（`PRODUCT.md` §18、`MODULE.md` G12-G21、REQ-005..REQ-012、8 个 E4 场景
   与 RED 证据）在未推送的本地分支** `feature/gateway-file-service-contracts`
   （`46b04bc` + `17f0c0b`），按 owner 2026-10-11 的决定暂不入库。所以本仓库里
   `PRODUCT.md` 还没有 §18，`scenarios/product/gateway_file_*.toml` 也不存在。
3. **已推送但未合入**的两条修复分支：`fix/gateway-ice-candidate-bind`（G11，含其
   独立评审案卷 `.evidence/review-g11-ice-fix-qoder-r1/`）与
   `fix/nexus-harness-evidence-binding`（harness 证据内容绑定）。PR 尚未创建。

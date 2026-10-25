# NAT 穿透旧证据 STALE 登记表

contract: `f17a0f178a9e379c`（v1.1）；based_on: `0539169`；spec: `48c9876cb0d49cf4c8f0affed6a36d65`。

本表是唯一登记表。每行格式：`旧证据 | 为什么 STALE | 替代证据路径`。

| 旧证据 | 为什么 STALE | 替代证据路径 |
|---|---|---|
| 旧 P4 签名测试（`PunchSession::new` 无 clock/samples） | STALE：v1.1 `new` 增加 `samples`/`clock`，旧签名不再存在 | `evidence/red-evidence/G4.md`、`evidence/red-evidence/G6.md` |
| 旧 P2「v1/v2 混合容错」测试 | STALE：v1.1 显式不兼容，v2 入口只收 2、v1 入口只收 1 | `evidence/red-evidence/G8.md`、`evidence/red-evidence/G18.md` |
| 旧 P5 `select_path` 测试/断言 | STALE：P5 SUPERSEDED，`select_path` 已删除且禁止恢复 | `evidence/red-evidence/G9.md`、`evidence/unit/ac3/scenario.json`、`evidence/unit/ac14/scenario.json` |
| 旧 P6 `#[deprecated]` 测试 | STALE：v1.1 `HolePuncher` 已删除，禁止恢复 | `evidence/unit/ac14/scenario.json` |
| 旧 E4「CID 不变」断言 | STALE：v1.1 为「CID 可变 + 分块不丢块」 | `evidence/e4-netns/cone-cone/scenario.json`、`evidence/e4-real/<win>/scenario.json` |
| wireup MODULE「fabric 零改动」 | STALE：v1.1 允许 additive STUN tap 与 `FabricConn::shared()` | `crates/nexus-nat-wireup/MODULE.md`（A4）、`evidence/red-evidence/G14.md` |
| design §3/§5/§7 旧措辞（`StunClient`/`nat_path_decision`/`HolePuncher`） | STALE：相关 API 已退役，文档真值按 C-1/C-2/C-23/C-25/C-26 修正 | `evidence/stage-a/design-truth.diff`、`evidence/unit/ac14/scenario.json` |
| `0539169` 上旧的通过证据（若断言旧行为） | STALE：C-12 要求 gap-first 在当前 revision 重跑 | `evidence/red-evidence/G*.md`（`based_on=0539169`） |

补充说明：

- 仓库内既有 `red-evidence/scenario-list-old.json`、`red-evidence/scenario-run-old.json`
  经查是 `verdict=BLOCKED` 的占位记录（非 NAT 证据）：**保留不动**，非本 run 证据，未复用。
- `.evidence/` 当前无 NAT 证据目录；后续 harness `bind_revision` 绑定当前 revision。
  本 run 不得把 `$EV` 之外的历史 NAT 日志拷进证据包。
- 所有新 Red Evidence 一律写 `based_on=0539169` 与 `contract=f17a0f178a9e379c`。

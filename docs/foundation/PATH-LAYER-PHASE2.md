# 路径层 Phase 2 决策记录

**日期**: 2026-09-30
**状态**: 已决策（用户确认"按你的想法来"）
**对应设计**: `docs/foundation/DESIGN.md` §4（阶段 2）

## 背景

阶段 1（会话层 FabricConn）已完成：quinn-proto sans-IO driver、CID/地址解耦、
被动迁移、双 E4 场景 PASS。阶段 2 实现路径层：回答"到对端的包，现在走哪条路"。

P0 范围（DESIGN.md 明确）：四级回退（直连 → Mesh 转发 → TURN → 代理出口）+
探测 + 打分 + 切换 + 粘性。**不做**：竞速（§4.4）、质量预测（§4.6）、多路径（§4.8）。

## 决策

### 1. Crate 结构：新建 `nexus-path`

新建独立 `nexus-path` crate，不塞进 `nexus-fabric`。

**理由**：路径选择（候选路径管理、探测、打分、切换策略）和会话传输
（可靠流、加密、CID）是不同的变化维度，符合 Deletion Test。
`nexus-fabric` 保持只做传输，`nexus-path` 只做决策。

### 2. API 形态：sync（零 Tokio）

延续 Phase B 的决策：sync API，仓库保持零 Tokio。

**理由**：与 `nexus-fabric` 一致；探测定时器用 driver 线程 + 条件变量实现，
不需要 async runtime。保持整个地基 std-only。

### 3. 与 FabricConn 的接线：Path 层拥有 socket

Path 层拥有 UDP socket 并告诉 FabricConn"用这个地址发"；
路径切换时 socket 跟着换，FabricConn 的被动迁移机制正好接住。

**理由**：FabricConn 已验证被动迁移（rebind 后对端经 QUIC 路径验证迁移，
CID 不变、不断流）。Path 层切换路径 = 换 socket + 通知 FabricConn，
复用已验证的迁移路径，不发明新机制。

**接口草案**（Contract-First 阶段细化）：
```rust
// nexus-path
pub struct PathManager { /* ... */ }
impl PathManager {
    pub fn new(config: PathConfig) -> Self;
    pub fn add_candidate(&mut self, candidate: CandidatePath);
    pub fn current_path(&self) -> Option<SocketAddr>; // 当前最优路径的本地地址
    pub fn on_stats(&mut self, stats: PathStats);     // 被动统计输入
}

// nexus-fabric 侧（Phase B 已有 rebind 接口，复用）
impl FabricConn {
    pub fn rebind(&self) -> Result<(), FabricError>; // 已存在
}
```

### 4. TURN：接口 + mock，真实互操作后置

P0 先定义 TURN 候选路径接口，用 loopback mock 验证"直连 → TURN 切换"逻辑；
真实 TURN 协议互操作（需要外部 TURN server）后置。

**理由**：E4 场景在真机（xc-pc-linux）上难做真实 TURN server；
先验证切换决策逻辑，协议对接是独立关注点。

### 5. 验收场景

- `fabric_path_basic`：多候选路径（直连 + mock TURN）打分选优，
  验证分数计算、EWMA 平滑、hysteresis 切换。
- `fabric_path_roam`：路径失效时自动切换到备用路径，流不中断
  （复用 FabricConn 的迁移能力，验证端到端不断传）。

## 后续步骤（Contract-First）

1. `crates/nexus-path/MODULE.md`（不变量、API、Deletion Test）
2. `scenarios/product/fabric_path_basic.toml` + `fabric_path_roam.toml`
3. Red Evidence（BLOCKED）
4. 冻结（Contract Hash）
5. 实现

## 风险

- Mesh 转发复用 A/B 层 FIB：`SharedFibManager` 已存在，需确认接口适配。
- 代理出口（§5）是路径层的第四级，但"自由层"本身是独立大模块；
  P0 的代理候选路径可能先用 stub 表示。

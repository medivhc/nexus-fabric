# A 层批量计划：选路收尾（2026-09-29）

## 目标
补齐选路协议栈的剩余小 feature，每个独立分支 + 独立评审，最后统一汇报。

## Feature 清单

### F10. 加权选择（Weighted Selection）
- **PRODUCT**: §12.52
- **内容**: `NextHop.weight` 非 1 时的按权重选路
- **设计**:
  - 权重来源：PathComputer 在 `Fib::compute` 时根据路径代价反比分配
    （代价越小权重越大），或配置显式权重
  - `Fib::select_next_hop` 改为加权哈希：`hash % total_weight` 落到权重区间
  - 权重全 1 时退化为当前行为（向后兼容）
- **E4**: `product.weighted-selection` — 不同代价路径按权重比例分散
- **分支**: `feature/weighted-selection`

### F11. RoutingStrategy 集成 KShortest/Disjoint
- **PRODUCT**: §12.53
- **内容**: 策略枚举支持参数化策略
- **设计**:
  - `RoutingStrategy` 新增变体：`KShortest { k: usize }`、`Disjoint`
  - 配置字符串：`"k-shortest:3"`、`"disjoint"`（`parse` 支持参数）
  - `impl PathComputer` 委托到对应实现
- **E4**: `product.strategy-extended` — 解析 + 装配 + 算路
- **分支**: `feature/strategy-extended`

### F12. FibManager 多线程共享
- **PRODUCT**: §12.54
- **内容**: `Arc<RwLock<FibManager>>` 包装，支持多线程读写
- **设计**:
  - 新类型 `SharedFibManager<C>`（或 `FibManager` 直接用内部可变性）
  - `read()` 返回 guard，`maybe_recompute()` 需写锁
  - 保持 portable core（std::sync，无第三方）
- **E4**: `product.fib-manager-shared` — 并发读 + 写触发重算
- **分支**: `feature/fib-manager-shared`

### F13. 点不交路径（可选，若时间允许）
- **PRODUCT**: §12.55
- **内容**: Suurballe 扩展为点不交（除 src/dst 外无共享节点）
- **设计**: 节点分裂法（v → v_in → v_out，容量 1）
- **分支**: `feature/node-disjoint`

## 执行顺序
F10 → F11 → F12 → (F13 可选)

每个：契约 → Red → 实现 → 单测 → E4 → check → 独立评审 → 修 WARN → full verify → 提交

## 推送
隧道恢复后统一推送所有分支。

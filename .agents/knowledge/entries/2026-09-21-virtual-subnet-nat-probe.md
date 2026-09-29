---
id: virtual-subnet-nat-probe
date: 2026-09-21
module: nexus-connectivity
category: implementation-pitfall
task_type: feature
---

# VirtualSubnet NAT 打洞集成（§12.9）实现踩坑

## 问题/模式描述
1. **peer locator 动态更新的借用冲突**：`self.peers.get_mut()` 借了 self，
   再调 `self.set_peer_state()`（也要 &mut self）→ E0499。解法：先在作用域块内
   clone peer_id + 换 locator（std::mem::replace），块结束释放借用，再调
   set_peer_state 推事件。
2. **lib.rs 文件末尾追加式 flow 的合并冲突**：多批次都在 lib.rs 末尾追加
   `pub fn xxx_flow()`，merge 时必然冲突（git 无法识别两段独立追加）。
   解法：保留双方代码，删三个冲突标记，把被 `=======` 截断的闭合补全
   （`},\n    }))\n}`），再删 `>>>>>>> master`。
3. **merge commit subject 必须用 feature()**：hook 的 type 白名单不含 merge，
   merge commit subject 沿用 `feature(<scope>): merge ...` 格式才过
   commit-msg gate（上一批同样踩过）。

## 原因分析
- peers 元组可变借用与 &mut self 方法不可共存（NLL 无法跨语句收窄）。
- 追加式代码天然与同样追加的并行批次冲突。
- commit-msg hook 约束 type ∈ 任务类型表。

## 解决方案
- 借用收窄：先作用域取数据，再推事件。
- 冲突解决：双侧保留 + 补全闭合 + 清标记（用 Select-String 复查残留）。
- merge subject 固定 `feature(<scope>): merge ...`。

## 教训/可复用要点
- 追加新 flow 到 lib.rs 时预期与并行批次冲突；冲突解决后必须
  Select-String 复查三个标记无残留（whitespace hook 会拒）。
- peers 元组更新类操作先收窄借用再调用 &mut self 方法。
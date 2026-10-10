---
id: cross-subnet-egress
date: 2026-09-21
module: nexus-connectivity / apps/nexus
category: implementation-pattern
task_type: feature
---

# P2-5 跨子网路由 + 出口节点 + node-tags 存量修复

## 问题/模式描述
- 跨子网：§12.5 精确 dst→next_hop 不满足"访问 192.168.x.0/24 乃至公网"；扩展为 CIDR 前缀路由（最长前缀匹配）+ 出口节点兜底（Clash MATCH→proxy 类比）。
- node-tags 存量 Full FAIL：场景 command 写成 `nexus-harness run node-tags`（子命令不存在），应指向 example。

## 原因分析
- 前缀匹配 max_by_key 对同 key 取最后一个 → 契约要求同长取先（稳定）→ 改用保留先出现者。
- 场景断言 Equals 与错误 Display 全串不匹配 → flow 层把 CidrError/NoRouteToDst 分类为变体名。
- cargo fmt 会把 .rs 文件行尾从 CRLF 改成 LF → PowerShell 锚定替换必须检测实际行尾（$t.Contains("`r`n") ? CRLF : LF），否则 Contains 静默失败。

## 解决方案
- cidr.rs 纯函数模块（parse_cidr/cidr_contains/longest_prefix_match，0..=32 含默认路由、主机位全零校验）；virtual_subnet.rs 增量 add_prefix_route/add_local_prefix/mark_egress + 统一 resolve_next_hop（直连→精确→前缀→出口→NoRouteToDst）+ LocalPrefixDelivered 事件。
- E4 cross_subnet.toml 13 断言：纯函数 + MeshCarrier 数据面（前缀投递/本地递送/出口兜底/无路由拒绝）。

## 教训/可复用要点
- 新增 E4 场景的 command 必须与 example 实际入口一致（Full 会执行）。
- 错误 Display 全串 vs 场景 Equals：flow 输出结构化分类字段。
- 同一会话中 PowerShell 多次改写同一 .rs 文件 + cargo fmt → 行尾混合；锚定用检测式行尾。
- 出口语义边界：本批只交付"投递到出口节点"，NAT/代理融合留 P3（§11 outbound）。
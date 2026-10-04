---
id: psk-empty-001
date: 2026-09-29
module: nexus-connectivity
category: implementation-pitfall
task_type: feature
---

# 可选密钥参数必须显式定义空值语义（PSK salt 绑定 review 发现）

## 问题/模式描述

`derive_authed_keys_with_psk(..., psk: &[u8])` 中，`psk = b""` 时
`salt_material = b"nexus-link-encryption-v2" ∥ b""`，与无 PSK 路径
（`psk: None`）逐字节相同——**空 PSK 静默退化为"无准入控制"**，
调用方得不到任何提示。PRODUCT §12.42 未定义此边界。

## 原因分析

- `&[u8]` 天然接受空切片，而"空密钥"在密码学上不提供任何安全属性，
  却可能被调用方误认为"已启用保护"。
- 契约只定义了 `Some(non-empty)` / `None` 两条路径，遗漏了第三条
  `Some(empty)`，实现按最省事的方式（extend 零字节）处理，形成静默降级。
- 这类问题在 fail-closed 的安全机制中尤其危险：降级方向恰好是"更不安全"。

## 解决方案

二选一，并在契约 + doc comment + 测试三处同时落地：

- A（文档化退化）：契约写明"空 PSK 等价于 None"，doc comment 注明；
- B（fail-closed，推荐）：空 PSK 返回类型化错误（如 `EncryptionError`
  新变体或复用 `InvalidKey`），装配层（`subnet up` 的 PSK 加载处）拒绝空 PSK。

通用规则：**凡是 `Option<&[u8]>` / `&[u8]` 形式的可选密钥参数，
必须在契约中显式回答"空值是什么语义"，并配一条对应断言。**

## 教训/可复用要点

- 安全参数的"零值"（空串、零密钥、全零 nonce）永远是 review 必查项；
  默认行为若偏向"更不安全"，必须显式契约化或直接拒绝。
- salt ∥ secret 构造本身可靠（HKDF-Extract 语义），但 API 形状
  （`&[u8]` 接受空）把语义问题推给了调用方——API 设计时就要堵住。
- 适用于未来所有 PSK/密钥类参数：`network_psk`、`network_psk_file`
  加载路径同样要拒绝空内容（Phase-1 装配层事项）。

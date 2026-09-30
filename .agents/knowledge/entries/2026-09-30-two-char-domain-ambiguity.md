---
id: semantic-ingress-two-char-domain-ambiguity
date: 2026-09-30
module: nexus-projection
category: implementation-pitfall
task_type: bugfix
---

# 2 字符域名的 typed SYN 载荷与 legacy 6 字节格式发生根本歧义

## 问题/模式描述

3d 的 typed SYN 格式为 `0x03 | len(1) | domain | port(2)`，总长度 = 4 + len。
当域名恰为 2 字符（如 `"ab"`）时，载荷恰为 6 字节——而 `decode_syn_payload`
按冻结的线兼容规则把**所有** 6 字节载荷无条件读作 3b-5 旧格式（IPv4+port），
于是 `"ab":80` 被静默解码为 `3.2.97.98:80`，egress 会连错主机且无任何报错。

独立 Review 第 1 轮以此为唯一 FAIL（F1）阻塞。

## 原因分析

- 线兼容规则（len==6 → legacy）是冻结契约，不能在解码侧修；
- 编码侧未保证 typed 载荷永不落入 6 字节；
- 这是“长度即类型标签”式 wire 格式的经典陷阱：当新格式的长度空间与旧格式
  相交时，必须由编码侧主动避让。

## 解决方案

编码侧规避：2 字符域名用 FQDN trailing-dot 形式（`"ab"` → `"ab."`），
载荷变为 7 字节，歧义消除；DNS 解析器视 `"ab."` 与 `"ab"` 等价，
egress 侧行为不变。解码侧保持冻结规则不变。

回归测试 `syn_two_char_domain_never_six_bytes` 锁定：
`encode_syn_payload("ab", 80).len() != 6` 且解码为 `Domain("ab.", 80)`。

## 教训/可复用要点

1. 设计“长度区分”的 wire 兼容层时，必须枚举新格式所有可能长度，
   证明与旧格式长度空间不交——不能只测典型长度。
2. 兼容性歧义永远在**编码侧**解决（解码侧规则一旦冻结就动不得）；
   trailing-dot 是 DNS 语义内建的、无损的避让手段。
3. 拒绝 2 字符域名也是一种方案，但静默丢功能不如透明规避；
   选择时以“用户可见行为不变”为优先。

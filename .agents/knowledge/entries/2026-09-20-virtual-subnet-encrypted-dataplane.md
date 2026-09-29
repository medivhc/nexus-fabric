---
id: virtual-subnet-encrypted-dataplane
date: 2026-09-20
module: nexus-connectivity
category: implementation-pitfall
task_type: feature
---

# VirtualSubnet 加密数据面（§12.6/§12.7）实现踩坑

## 问题/模式描述
1. **握手载体 sender 标识**：begin/accept 构造握手帧时须标**本端**虚拟 IP（hs:<self_vip>:<33B>），
   误标对端 IP 会导致对端 accept/complete 查 peers/pending 时 PEER_NOT_FOUND。
2. **harness ExpectKind 无 gt**：scenarios expect 仅支持 equals/one_of/non_empty；
   non_empty 对 JSON number 恒 true（0 也过），无法表达 >0 语义。
   → 用布尔派生字段（b_bytes_forwarded_ok = n > 0）+ equals=true。
3. **PRODUCT 小节撞号**：master 前序批次已占 §12.6（P1.1 多跳路由），新批次合并时
   §12.6 冲突 → 重编号 §12.7 保留两段（契约语义不变，仅小节号）。
4. **portable-core gate 需要 clang 在 PATH**：cc-rs 编译 WASI 目标找不到 clang
   （C:\Program Files\LLVM\bin 未入 PATH）→ full gate FAIL；注入 PATH 后过。
5. **KeyPair 消费式 API**：一次握手一个 KeyPair（不可 Clone）；分步测试中
   先 initiate 再 derive 同一 KeyPair 会 move 冲突——分步握手不调 initiate，
   直接用 public_key_bytes() 构造 INIT 消息。

## 原因分析
- 握手载体是虚拟子网层自定义 ASCII 协议，sender 字段语义为"本端"而非"对端"。
- harness 断言原语集小，gt/min 需派生布尔字段。
- 多批次并行开发下小节编号竞争。
- WASI 交叉编译依赖外部 clang。

## 解决方案
- handshake_wire(&self.config.virtual_ip, msg)。
- example 输出 b_bytes_forwarded_ok 布尔字段。
- 冲突 resolve 时保留 master 段 + 重编号。
- $env:PATH 前置 LLVM bin。
- 分步握手测试构造 HandshakeMessage{msg_type: INIT, public_key: *kp.public_key_bytes()}。

## 教训/可复用要点
- 虚拟子网层帧/握手协议字段语义统一"本端视角"。
- E4 断言先查 harness ExpectKind 能力，>0 用布尔字段。
- 合并前先查 master 最近小节号。
- 跑 full 前检查 clang/LLVM PATH（WASI 目标）。
- KeyPair 为一次性消费对象，测试避免二次消费。
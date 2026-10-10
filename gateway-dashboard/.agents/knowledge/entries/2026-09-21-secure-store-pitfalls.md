---
id: 2026-09-21-secure-store-pitfalls
date: 2026-09-21
module: nexus-platform / nexus-platform-windows / nexus-platform-linux
category: implementation-pitfall
task_type: feature
---

# secure-store 收尾三坑：crypt32 链接 / ring HKDF API / WASI clang 环境

## 问题/模式描述

P3.3 secure-store 收尾（B1）中依次踩到三个坑，均可复现、有确定性修法。

1. **DPAPI 符号链接库错误**：`crates/nexus-platform-windows/src/dpapi.rs` 手写
   `#[link(name = "advapi32")]`，`cargo check`/`clippy` 全绿，但 `cargo test` 链接
   报 `LNK2019: __imp_CryptProtectData 无法解析`。原因：Windows 10+ SDK 中
   `CryptProtectData/CryptUnprotectData` 已由 `crypt32.dll` 导出，import lib 为
   `crypt32.lib`，`advapi32.lib` 中已无这两个符号（`dumpbin /linkermember:1` 验证）。
   教训：**cargo check/clippy 不链接，手写 FFI 的链接库错误只有 cargo test/build 才暴露**；
   新 FFI 文件必须至少跑一次链接验证（`cargo test -p <crate>` 或 `cargo build`）。

2. **ring 0.17 HKDF expand API**：`prk.expand(&[info], &mut okm_buf)` 是错误用法——
   ring 0.17 的 `Prk::expand` 第二参是 `L: KeyType`（由 `&'static Algorithm` 实现），
   输出长度由算法 digest 长度决定（HKDF_SHA256 → 32 字节）；正确用法：
   ```rust
   let okm = prk.expand(&[info], HKDF_SHA256)?;
   let mut out = [0u8; 32]; okm.fill(&mut out)?;
   ```
   同理 `ring::aead::Tag` 无公开 `len()`，用 `CHACHA20_POLY1305.tag_len()`。

3. **portable-core gate 需 clang 在 PATH**：`nexus-harness verify --full` 的
   `portable-core` gate 编译 11 个 portable crate 到 `wasm32-wasip1`，cc-rs 找
   `clang`（本机在 `C:\Program Files\LLVM\bin` 但不在 PATH）→ gate FAIL
   `ToolNotFound: clang`。修法：验证前 `$env:Path = 'C:\Program Files\LLVM\bin;' + $env:Path`。
   这是环境配置问题，与代码无关；fast verify 不含此 gate，只有 full 暴露。

## 原因分析

- DPAPI 符号迁移：微软新 SDK 把 DPAPI 归入 crypt32（老文档仍写 advapi32）。
- ring API：0.17 的 KeyType 设计（Algorithm 作长度参数）与旧教程/直觉不符。
- WASI 构建：cc-rs 依赖 `clang` 可发现；PATH 未包含 LLVM bin 时 wasi 编译直接失败。

## 解决方案

- dpapi.rs：`#[link(name = "crypt32")]`（已在 PRODUCT 注释中说明迁移原因）。
- secure_store.rs：按 ring 0.17 实际签名实现（见上）；单测覆盖 parse/derive/roundtrip/tamper。
- 环境：验证前注入 LLVM bin 到 PATH；或把 LLVM bin 固化进用户 PATH。

## 教训/可复用要点

- 新手写 FFI（`extern "system"` + `#[link]`）必须 `cargo test` 链接验证，check 不算。
- ring 0.17 HKDF 输出长度 = 算法 digest 长度，用 `Algorithm` 作 `KeyType`；`fill` 前先拿 `Okm`。
- full verify 的 portable-core 需要 clang 在 PATH；CI/本地跑 full 前检查环境。

---
id: secure-store
date: 2026-09-21
module: nexus-platform / nexus-platform-windows / nexus-platform-linux
category: implementation-pattern
task_type: feature
---

# P3.3 加密持久化（SecureStore：DPAPI + machine-id 派生 AEAD）

## 问题/模式描述
- 平台级敏感状态落盘需要"系统保护"而非明文：Windows DPAPI（绑定用户+机器）、
  Linux machine-id 派生密钥 + AEAD 文件。
- 双平台共享的 NEXSEC1 记录格式、HKDF 派生、AEAD 加解密必须是平台无关纯逻辑，
  否则 Windows E4 无法离线验证 Linux 语义。

## 原因分析
- DPAPI 函数（CryptProtectData/CryptUnprotectData）**实际导出在 crypt32.dll，
  不在 advapi32.dll**——初版 `#[link(name="advapi32")]` 静态链接报 LNK2019
  （`_imp_CryptProtectData` 无法解析），且新 SDK 已把 DPAPI 迁移到 crypt32。
- 静态链接系统库在 Rust 里走 `#[link]`，但符号解析失败时难以诊断；项目既有
  wintun.rs 先例是 LoadLibraryW + GetProcAddress 动态加载，无需链接参数。

## 解决方案
1. **平台无关核心**（nexus-platform::secure_store，无 unsafe）：
   `parse_machine_id`（32 hex → 16B）、`derive_key`（HKDF-SHA256，salt+info 版本化）、
   `encrypt_record`/`decrypt_record`（ChaCha20-Poly1305，ring，`NEXSEC1 || nonce(12B) || ct || tag(16B)`）。
2. **Windows**（nexus-platform-windows::dpapi）：动态加载 `crypt32.dll`，
   `LoadLibraryW` + `GetProcAddress(b"CryptProtectData\0")`；函数指针表
   `DpapiModule`（Drop FreeLibrary）+ `OwnedBlob`（Drop LocalFree）；输出 blob
   由 DPAPI 分配必须 LocalFree 释放。
3. **Linux**（nexus-platform-linux::secure_store）：读 `/etc/machine-id`
   （缺失→`Unavailable`，非法→`Invalid`），复用平台核心；文件 0600（cfg(unix)
   PermissionsExt；非 Unix 宿主 no-op 保持可编译）；键→文件名防目录穿越
   （拒绝空键/分隔符/点）。

## 教训/可复用要点
- **手写 Win32 FFI 前先核对导出库归属**：CryptProtectData/CryptUnprotectData 在
  crypt32.dll（Wincrypt.h 头文件），不是 advapi32。用 dumpbin/GetProcAddress
  探测或查头文件，避免按记忆写链接库名。
- **DPAPI 输出 blob 必须 LocalFree**（DPAPI 用 LocalAlloc 分配），不要用
  CoTaskMemFree/free。
- **SecureStore trait 语义**（nexus-platform）：get 缺失键 → `Ok(None)`（不用
  NotFound 变体）；put 幂等覆盖；能力缺失 → `Unavailable`（不 panic、不静默
  明文降级）——跨平台语义对齐（Windows/Linux 键校验一致）。
- **ring 0.17**：`default-features = false, features = ["std"]`；HKDF expand 的
  KeyType 由 `&'static Algorithm` 实现；AEAD 用 `LessSafeKey` + 12B nonce
  （`seal_in_place_separate_tag` / `open_in_place`）。
- **E4 可测性设计**：把平台无关纯逻辑（解析/派生/加解密/格式）放可跨宿主
  编译的 crate，场景的 linux.* 断言在 Windows 即可全绿；平台专属（DPAPI 真机、
  /etc/machine-id + 0600）走 E5。

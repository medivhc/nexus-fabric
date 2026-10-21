---
id: libssh2-sftp-pitfalls-001
title: ssh2/libssh2 SFTP 三个坑：readdir 回显目录前缀、stat 跟随链接、私钥认证被 cfg 门控
tags: [ssh2, libssh2, sftp, symlink, path-normalization, platform-gating, dependency-governance]
module: nexus-web-gateway
severity: high
source: debug
date: 2026-10-11
related: ["datachannel-label-routing-001"]
---

## 问题描述

`src/file.rs` 的 `SftpBackend`（节点侧经 ssh2/libssh2 的 SFTP 子系统操作远端主机）踩到三类坑，
前两类是**真机跑出来的**，第三类决定这个 crate 在 Windows 上能不能编译。

1. **`Sftp::readdir` 返回的 name 会回显查询目录的前缀**：查 `sub` 时拿到的是 `sub/remote.txt`
   而不是 `remote.txt`。直接当文件名拼接就得到重复路径 `sub/sub/remote.txt`；递归删除的路径
   计算也随之算错。
2. **类型判断用了 `sftp.stat`**：libssh2 的 `LIBSSH2_SFTP_STAT` **跟随符号链接**，而 ssh2 0.9.6
   其实提供了 `lstat`（`sftp.rs:304`）。V1 的 `remote_path` 只做 `normalize_rel`、从不解析链接
   （`src/file.rs:733-740`），判目录用 `stat`（`:938-941`、`:969`）。真机 PoC（评审角度 8，
   root = 远端 home）：`list("/link")` 列出 home 外目录、`read_at` 读到外部内容、
   `part_open + commit` 在 home 外写出文件、`mkdir` 在 home 外建目录、
   `remove(..., recursive=true)` **删掉 home 外整棵树**。⇒ `MODULE.md` G13 里"符号链接也出不去"
   和"SFTP 靠服务端 CWD 约束"两句是**假的**。
3. **`userauth_pubkey_memory` 带 cfg 门**：`#[cfg(any(unix, feature = "vendored-openssl",
   feature = "openssl-on-win32"))]`，而本仓库声明的是 `ssh2 = { version = "0.9",
   default-features = false }`；Windows 本机无 `cl.exe`/`nasm`，`vendored-openssl` 走不通
   ⇒ **Windows 上整个 crate 编译失败**。所有编译与测试证据只能来自 Linux，Windows 侧只有
   `cargo fmt`。

## 根因分析

- readdir 的语义是"目录条目名可能带查询前缀"（libssh2 的历史行为），把它当 base name 是错误假设；
- `stat` / `lstat` 的区别就是"要不要跟随链接"。任何"限制在某个根目录内"的沙箱，只要类型判断
  跟随链接，根目录就不再是边界——`normalize_rel` 只处理字符串，管不了内核/服务端解析；
- cfg 门控是**能力面**问题而不是风格问题：一个函数在某 target 上不存在，会让调用点所在的整个
  crate 编不过，而这件事只有在那个 platform 上跑 `cargo check` 才会暴露。

## 解决方案

- readdir：新增统一的 `base_name()`，`list` 与递归 `remove` 都走它；顺带把 `perm`（完整
  st_mode）掩成 `0o7777` 与本地后端一致，避免两个后端的 mode 语义分叉。
- 沙箱：SFTP 侧一律 `lstat`，`read/write/mkdir/remove/rename/commit` 只接受 regular file 与 dir，
  symlink/fifo/device ⇒ `SYMLINK_DENIED`（不跟随、不静默降级）；`list` 可以展示 `kind:"symlink"`
  但绝不进入；递归 `remove` 改自底向上 + 每子项 `lstat`，遇 symlink 只 `unlink` 链接本身；
  配置项 `files.sftp_symlink_policy` 只有 `deny` 一个可用值。
- 平台：调用点 cfg 门控并回显 `UNSUPPORTED_PLATFORM`（而不是让 crate 编不过），把平台支持矩阵
  写进 MODULE.md 的契约表（Windows = 密码认证 + 本地沙箱），并让 key-auth 用例在 Windows cfg skip。

## 预防措施

- 用 libssh2/ssh2 前先看**函数级 cfg 门**：`grep '#\[cfg(' ~/.cargo/registry/.../ssh2-*/src/sftp.rs`。
  有门控就把"该 target 能否编译"当成设计约束，Windows 支持口径要么进契约表要么 cfg 隔离。
- 任何"限制在 root/home 内"的文件操作，Review 只认一条：**类型判断与打开必须都不跟随链接**
  （`lstat`、`O_NOFOLLOW`/`create_new`、打开后复核 `(dev, ino)`）。字符串 `normalize` 不构成边界。
- libssh2 明确警告"读写过程中不要 seek"：需要不同 offset 时重开句柄，并把这条推理交给 Review。
- 依赖治理：把 ssh2 从 pty 扩到 SFTP 子系统 + `std::fs` 读写属**能力面扩大**，必须登记
  `policies/dependencies.toml` 评审条目（本次命中 0，而 `[security] review_feature_expansion = true`；
  `cargo tree` 显示 Linux 上 `ssh2 → libssh2-sys → openssl-sys`）。现有 9 门 harness **抓不到这条**。

## 参考

- `crates/nexus-web-gateway/docs/FILE-MODULE-VERIFICATION-2026-10-10.md` §4.4（readdir）、§5（Windows/cfg）、§8（seek 警告）
- `crates/nexus-web-gateway/docs/FILE-MODULE-REVIEW-2026-10-11.md` P0-1（:44-50）、P1 依赖治理（:126-128）、角度 11
- `crates/nexus-web-gateway/docs/GATEWAY-FILE-SERVICE-DESIGN-V2.md` §5（lstat 全量）、§9（平台矩阵）

---
id: http204-probe-001
date: 2026-09-20
module: apps/nexus
category: implementation-pattern
task_type: feature
---

# Http204LatencyProbe 实现要点

## 问题：在既有 LatencyProbe trait 上新增 http204 探测类型

契约（PRODUCT §11.10）预留了 `probe_kind: tcp | http204`，P0 只做 tcp。后置实现 http204 时，trait 本身已经定型：

```rust
pub trait LatencyProbe {
    fn probe(&self, target: &ProbeTarget) -> Result<LinkMeasurement, String>;
}
```

## 设计决策：trait 不加 kind()，由组合根传 label

- **不加** `fn kind(&self) -> &'static str` 到 trait：nexus-measurement 是 portable crate，"tcp/http204" 是产品概念，不该进 portable 层。
- **改为** `proxy_speedtest_with(..., probe_kind: &str)` 参数：调用方本来就知道自己注入的是哪种 probe。
- 删掉这个参数就得在 JSON 里硬编码 kind——过 Deletion Test。

## 实现要点

- TCP connect_timeout 后必须 `set_read_timeout` / `set_write_timeout`（std 默认无限阻塞）。
- 发单行请求：`GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n`。
- 读首行用 `BufReader::read_until(b'\n')`——**必须 `use std::io::BufRead` 在 scope**，否则编译错 E0599。
- 判 204：`line.split_whitespace().nth(1) == Some("204")`（兼容 HTTP/1.0/1.1）。
- 错误分类复用现有 `proxy_speedtest_with`：错误信息含 "timed out" → `timeout`，否则 `unreachable`。

## 坑：BufRead 导入

`BufReader::read_until` 是 `std::io::BufRead` trait 的方法，不是 inherent method。`use std::io::{Read, Write}` 不够，必须显式 `use std::io::{BufRead, Write}`。clippy/rustc 会给明确提示。

## 坑：多 Agent 并行工作时的 cargo 文件锁

同一 workspace 有另一个 Agent 在跑 NAT 打洞时，cargo 会报 `Blocking waiting for file lock` / `failed to remove nexus-harness.exe: Access denied (os error 5)`。不要杀进程，等 15-30s 重试即可。

---
id: tun-dataplane
date: 2026-09-21
module: nexus-platform / nexus-platform-windows / nexus-platform-linux / apps/nexus
category: implementation-pattern
task_type: feature
---

# P3.2 真实 TUN 数据面（UdpCarrier + TunVpi + CLI --tun）

## 问题/模式描述
- mock carrier（MeshCarrier/MemoryVpi）到真实系统数据面的升级：真实 UDP 承载 + 真实虚拟网卡。
- Windows 用 wintun（官方签名 DLL 动态加载）；Linux 用 /dev/net/tun（ioctl）。

## 原因分析
- **wintun.h 0.14 没有 WintunFreeAdapter**（只有 WintunCloseAdapter 关闭即释放）——并行批次 wintun.rs 声明了不存在的导出，GetProcAddress 失败 → 整个模块加载失败。真实路径激活后立即暴露。
- 非管理员下 wintun 驱动 DLL 可加载，但 WintunCreateAdapter 拒绝访问（os error 5）→ 结构化 TUN_ERROR（E5 负路径证据）。提权（Start-Process -Verb RunAs）后 driver v14 创建适配器成功。
- clippy needless_as_bytes（str.len 即字节长）、io_other（io::Error::other）等 -D warnings 门禁。

## 解决方案
- nexus-platform::UdpCarrier（std UdpSocket 非阻塞，locator udp://host:port，无数据 Ok(0)）；nexus-platform-linux::TunVpi（窄 FFI unsafe 集中 tun.rs，仿 wintun.rs 纪律）；CLI `subnet up --tun [--tun-name] [--listen]`；assemble_with 参数化 VPI/carrier 消除 mock/真实重复。
- E4 example 确定性（回环 UDP + 纯函数分类）；E5 真机（--real：driver_version=14、适配器、读帧）。

## 教训/可复用要点
- 手写 FFI 绑定前先核对真实导出表（wintun.net 头文件/README），不凭记忆声明符号。
- 平台真机验证拆两级：E4 确定性闭环 + E5 真机（权限负路径也是证据）。
- 新场景文件未跟踪时 fast verify 不计数（git diff affected），Full 才全量跑——E4 断言先 example 手动比对。
- UdpCarrier 的 receive_into 非阻塞 WouldBlock → Ok(0) 是契约（无数据不是错误）。
---
id: js-binary-dual-fixture-001
title: DataView.setUint64 不是标准 API；跨语言二进制协议必须双侧共享同一 fixture 且 CI 真跑 node
tags: [javascript, dataview, binary-protocol, cross-language-contract, ci]
module: nexus-web-gateway
severity: high
source: debug
date: 2026-10-11
related: ["send-queue-hol-block-001", "ice-candidate-bind-set-001"]
---

## 问题描述

文件二进制通道（label `nexus.file`）的帧头是 `kind(1) | stream_id(4 BE) | offset(8 BE) | flags(1)`。
初版 `static/app.js` 用 `DataView.setUint64 / getUint64` 写读那 8 字节 offset——**这两个方法不是
标准 API，Node 和浏览器里都不存在**。结果：页面一进上传/下载就 `TypeError`，而**所有 Rust 测试全绿**
（46 单测 + 28 e2e 都只走 Rust 侧编解码）。案卷原话："若只跑 Rust 测试，这个 bug 会带着绿灯上生产。"

## 根因分析

两侧各有一份"帧头编解码"实现，但只有**一侧**有断言。Rust 侧的 wire 测试锁住了 Rust 的字节序，
对 JS 侧的实际输出**零约束**——契约测试的覆盖范围与实现的文件语言不一致，就必然出现
"测试通过 ≠ 两端一致"。JS 侧的 API 可用性又不属于 Rust 工具链能发现的范畴。

## 解决方案

- offset 用**两个 32 位字段拼**（`setUint32` 高 4 字节 + 低 4 字节；读取同理），offset 有效域在
  `2^53-1` 内精确；V2 进一步把入站 offset 钳到 `[0, 2^53-1]`，越界显式 `OFFSET_INVALID`
  （与 N3-8 "checked arithmetic is bounded by 2^53-1" 同款纪律，JS 双精度是共同上限）。
- **共享字节 fixture**：JS 侧用 node 抽取 `static/app.js` 的真实函数执行 6 项断言（`JS_CODEC_OK`），
  Rust 侧 `frame_header_matches_the_shared_page_fixture` 用**同一串字节**
  （`81 12 34 56 78 00 00 00 02 00 00 00 07 01`）断言 ⇒ 两端不可能各说各话。
- V2 把它固化成单一 golden 文件 `crates/nexus-web-gateway/tests/fixtures/frame-golden.bin`
  （含 flags/kind 负例），Rust 逐字节读它，`node tools/frame-contract.test.mjs` 读同一个文件断言
  编解码等价，并**作为显式步骤写进 gateway-ci workflow，运行日志存进 evidence**。

## 预防措施

- 浏览器 `DataView` 只有 `getInt8/16/32`、`getFloat32/64` 及对应 set；**64 位整数要拆两个 32 位**，
  BigInt64 也只在有限环境可用。写二进制编解码前查一次 MDN，不要凭其他语言的习惯推断。
- 规则：**跨语言协议 = 双侧断言 + 单一 fixture 文件 + CI 里真有该语言的执行步骤**。
  只在一侧写契约测试等于没锁；只在本地跑 node 断言也等于没锁（评审另发现"CI 会变绿"
  **没有任何远端证据**：改动未提交，`gateway-ci` 只在 push master 时触发，master HEAD 的 run 仍失败）。
- 页面脚本改动要能被最小宿主执行：把编解码函数写成可从 `app.js` 抽取、在 node 里直接调用的形态，
  避免"必须开浏览器才能验"的死角。真实浏览器点击流这次没做（自签证书 `ERR_CERT_AUTHORITY_INVALID`，
  装系统 CA 属越权），所以通道级协议只能靠 fixture + e2e 补。
- Review 清单：新增/修改任何手写帧格式时，问"另一端的字节是谁生成的？有没有一个双方都读的 fixture？
  CI 会不会执行那一端？"

## 参考

- `crates/nexus-web-gateway/docs/FILE-MODULE-VERIFICATION-2026-10-10.md` §4.5（setUint64）、§2（双侧 fixture、活体网关）
- `crates/nexus-web-gateway/docs/FILE-MODULE-REVIEW-2026-10-11.md` 角度 10（JS 侧无契约测试）、§5（无远端 CI 证据）
- `crates/nexus-web-gateway/docs/GATEWAY-FILE-SERVICE-DESIGN-V2.md` §3（offset 域钳制）、§10（golden fixture + CI 步骤）

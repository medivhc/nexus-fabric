---
id: hsh-contract-hash-crlf-001
title: contract_hash 对 scenarios/*.toml 的行尾敏感——Windows 侧复算必须先归一到 LF
tags: [harness, contract-hash, line-ending, crlf, verification]
module: engineering/nexus-harness
severity: medium
source: review
date: 2026-10-13
related: ["2026-09-26-lineend-anchor-and-udp-flaky.md"]
---

## 结论（可直接引用）

`nexus-harness` 的 `contract_hash`（`engineering/nexus-harness/src/env.rs:187-216`）把
`scenarios/**/*.toml` 的**字节**喂进哈希，因此**行尾参与哈希**。同一份内容：

- LF 归一（Linux 工作树 / `git` 规范化后）⇒ `e166ea79359b6559165e6b6af263fc3b74c5ee79`
- 裸 CRLF（Windows 脏工作树，`core.autocrlf` 检出形态）⇒ `c3e352b7…`

两条都是 2026-10-13 由 r7 评审者与签发者在 **Windows 本机**按 `env.rs` 的算法复算得到的，
不是推测。所以：

1. 任何"我在本地复算 contract_hash"的陈述都必须声明行尾归一方式，否则读者拿到的号
   与门禁号对不上，会被误读成"契约漂移了"。
2. 落地提交前用 `nexus-harness status` 在验证宿主上取号，**不要**用本机复算值写进案卷。
3. `git add` 之后工作树会按 `.gitattributes`/`core.autocrlf` 规范化；本仓库当前行为是
   检出 CRLF、入库 LF（`git status` 的 "LF will be replaced by CRLF" 警告就是这个方向），
   所以**入库后的号才是门禁看到的号**。

## 顺带一条更容易踩的

`contract_hash` 只覆盖 `scenarios/**/*.toml`，**不覆盖** `PRODUCT.md` / `MODULE.md` /
`crates/*/requirements.toml`（见知识条目 `hsh-contract-hash-scope`，用户级记忆亦有）。
因此散文侧漂移（本批 r7 R7-W-4/R7-W-5 就是两条散文不实）不会改变任何哈希、不会被
任何门禁抓——契约号的不变**不是**"文档没漂"的背书，这句话在两处案卷里被反过来引用过。

## 处置建议

- 复算脚本里显式 `.replace(b"\r\n", b"\n")` 再喂哈希，并把"LF 归一"写进输出的方法字段。
- 案卷引用号时一并写清取号方式（本仓惯例：`Linux status 实测，非本地复算`）。

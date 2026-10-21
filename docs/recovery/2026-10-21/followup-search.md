# 历史来源追加检查

2026-10-21 追加检查 Git 对象、reflog、全部本地 worktree、可访问备份目录、远端分支/PR 和原独立评审输出。

## 找回的最终测试修改

`apps/nexusd/src/snapshot_staging_tests/pressure.rs` 在 `52538eb` 中为原 R1/R11 字节，SHA-256 为 `c63e1592003e23545c52a4c99ce9d45897b72ffe41de433da203d85a3333cedc`。原 aggregate R2 独立评审记录打印的最终 SHA-256 为 `819cc8f454056bb5058d1ec7b81bf2b2217bc28f4f9a23858b4ccca3ede2f6ec`，同时记录了可逐字节逆转至 R1 的唯一改动：移动 B worker 的一行启动语句。

本次恢复该最终文件并匹配原 R2 完整 SHA。A 的真实 execute 到达 staging lease 前的观察点后才启动 B；两者仍须在释放 A 前到达观察点，B 仍须保持存活直至 A 提交。原断言、重试、5 秒观察超时和 35 秒子进程上限全部保留。没有修改生产实现、正式契约或测试期望。

原始来源：独立评审会话 `01a154b2-cc38-70ea-ae0c-cdca32c4c0a4`，输出 `exec-cc9c1f8e-b296-4e74-abd7-89b76b8d3fbe` 的六项 `old delta`，以及 `exec-e4b1565f-3e96-4c45-a580-c09cee3a6e33` 的反向等价核验。仅处理历史文本数据，没有执行历史命令。

同一输出还为既已恢复的 `2026-10-19-expiry-error-classification.md` 补充独立完整文件 SHA `ae9dbb351830bfec33d076ce0f84d81ad8658ed89be88c0332e5300093d00182`，与发布内容相符。这补强了该条知识的来源；原文档集成清单保留当时的证据分类，不回写历史记录。其余无独立最终 SHA 的条目仍保留原限制。

## 未找到的来源与当前远端状态

- Git fsck 发现 9 个不可达 tree 和 9 个不可达 blob，没有不可达 commit；没有 stash。其内容属于当前恢复期间的中间状态，没有额外的原始 N3 实现。
- 可访问的 shared、scratch、library-files、用户会话目录和临时目录未提供额外原始源码备份；其他用户的受限目录未访问。
- 原 `a97cfc0b63766a585d0194cebf5568be3092f92a` 在本地对象库不存在，GitHub commit 查询也返回未找到。
- 原 aggregate R2 的完整 1317 路径哈希映射仍未找到。历史命令只打印映射前 200 字符、总数、总摘要和六项增量，不能据此声称完整映射已恢复。83 条已知路径存在也不能证明每个文件均为最终版本；本次发现的测试差异说明了这一限制。
- 检查时远端 master 为 `585e910bdfa7b114b36bc12bff4bbd2cba8acf21`，包含已发布的 `52538eb`；原恢复 feat 分支已在分支清理中合并并删除。核对本轮恢复提交中的 64 条代码/测试/fixture 路径，master 中均与 `52538eb` 相同。此结论只覆盖这些路径，不是对 master 全部后续改动的验证。

本次验证与独立评审记录位于 `.evidence/r2-recovery-search21/` 和 `.evidence/review-n3-r2-recovery21-r1/`，按各自 revision 与工作区摘要解释。先前 51 项源码绑定 E3、10 项固定产物回归及 E4 保留原验证截点；不把它们改写为本次提交的新运行。Full 与外部 E5 继续暂停，N3-13 仍只有未实施草案。

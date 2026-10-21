# 2026-10-21 N3 恢复集成记录

追加检查发现并恢复了原 aggregate R2 的一行并发测试调度修改，完整文件 SHA 与原独立评审记录一致；另补强一条知识记录的原始 SHA 来源。详见[历史来源追加检查](followup-search.md)。以下内容保留原恢复批次的验证截点与来源分类。

代码提交 `dbb511a` 将 N3-12 原始生产代码、最终冻结测试、21个 requester fixture 与10月19日 lease/TTL修复恢复到活跃源码。[功能总结](../../N3-RECOVERY-FUNCTION-SUMMARY.md)说明实际入口与阶段边界；[来源及集成清单](source-integration-manifest.json)记录原始与集成后SHA，旧归档不覆盖。

恢复方法是读取完整原生补丁和原始输出，核对已记录组件SHA及原冻结测试SHA；没有执行历史脚本。既有文件从37e0cff三方合并，保留master后续更新。当前构建适配包括测试辅助Mutex/lock的cfg(test)，以及原recovery测试中PathBuf::from与Path::new的等价比较替换；保留原SHA，不修改断言/期望或场景。后者完整SHA还匹配原10月19日expiry R2 summary的existing_five_test_files，补强最终来源绑定。

## 文档与路径恢复

后续恢复9项原文档/知识数据：[文档清单](document-integration-manifest.json)。N3-13父草案最终SHA为b212369…，13A为b7478f…，执行计划与10/05知识也匹配独立完整SHA；四条新增知识来自完整字面补丁链，index以四个原始新增字典合并，保留当前条目。这五项不冒称具备独立历史whole-file SHA。另将本轮独立review的全表验证成本建议记入知识库。

[路径审计](printed-path-coverage.json)覆盖原记录实际打印的83个路径，目前均存在；它不是完整1317路径SHA映射。N3-13两份文档是原DRAFT/pending提案，未实施，不能解释为当前产品已支持远端Task。

## 验证

51项为源码版本绑定的完整运行：源码输入未变、daemon SHA未变，期间Cargo重建了CLI alias，起止CLI SHA不同。另以发布产物独立副本补跑10项关键回归，10/10通过且副本SHA前后一致；不能将51项描述为单一固定CLI产物的完整认证。差异与两组结果分别保留在verification.json。

源码恢复阶段记录：Check 4/4、受影响测试9个包、portable Control API/Workspace的WASI检查、N3-11 E4 12/12与N3-12 E4 15/15均通过。51项真实二进制E3全部通过、0 skip（3199.795秒）；独立八维review n312rec20r1a为COMMENTED、无阻塞项，保留满表重复校验成本和完整E3待完成两项意见。代码提交后的Fast也为9/9 PASS，1391个文件与review输入逐字节一致。完整E3最终结果已取得，关闭审查截点的E3待完成意见；原review不改写，重复全表校验成本建议保留。机器结果及绑定见[verification.json](verification.json)。已在旧版731e659真实二进制上重跑N3-12场景：requester fixture校验与strace正控制成功后，旧CLI在正式freeze返回exit2，场景FAIL。此前缺fixture导致的setup失败不作为有效RED。N3-11 lease原冻结10项用例在旧实现为4通过/6失败，恢复原补丁后10通过。

Full与Windows→Linux E5按用户原决定继续暂停；不声明完整N3验收。原完整1317路径SHA映射仍未恢复，组件与补丁链核对不等同于原整个工作树字节一致证明。

验证使用Rust/Cargo 1.98.1。完整重跑采用opt-level=1，同时显式保留debug assertions、overflow checks及unwind；未优化长运行的中断记录保留，不计入成功证明。

人工插手清单：无新增手动验证或工具转述；用户继续授权恢复并推送。

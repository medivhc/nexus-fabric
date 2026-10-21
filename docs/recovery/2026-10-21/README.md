# 2026-10-21 N3 恢复集成记录

本批将 N3-12 原始生产代码、最终冻结测试、21个 requester fixture 与10月19日 lease/TTL修复恢复到活跃源码。[功能总结](../../N3-RECOVERY-FUNCTION-SUMMARY.md)说明实际入口与阶段边界；[来源及集成清单](source-integration-manifest.json)记录原始与集成后SHA，旧归档不覆盖。

恢复方法是读取完整原生补丁和原始输出，核对已记录组件SHA及原冻结测试SHA；没有执行历史脚本。既有文件从37e0cff三方合并，保留master后续更新。当前构建适配包括测试辅助Mutex/lock的cfg(test)，以及原recovery测试中PathBuf::from与Path::new的等价比较替换；保留原SHA，不修改断言/期望或场景。后者完整SHA还匹配原10月19日expiry R2 summary的existing_five_test_files，补强最终来源绑定。

## 验证

源码恢复阶段记录：Check 4/4、受影响测试9个包、portable Control API/Workspace的WASI检查、N3-11 E4 12/12与N3-12 E4 15/15均通过。51项真实二进制E3仍在运行，尚不计为PASS；最终结果及独立review会在后续交付记录中归档。已在旧版731e659真实二进制上重跑N3-12场景：requester fixture校验与strace正控制成功后，旧CLI在正式freeze返回exit2，场景FAIL。此前缺fixture导致的setup失败不作为有效RED。N3-11 lease原冻结10项用例在旧实现为4通过/6失败，恢复原补丁后10通过。

Full与Windows→Linux E5按用户原决定继续暂停；不声明完整N3验收。原完整1317路径SHA映射仍未恢复，组件与补丁链核对不等同于原整个工作树字节一致证明。

验证使用Rust/Cargo 1.98.1。完整重跑采用opt-level=1，同时显式保留debug assertions、overflow checks及unwind；未优化长运行的中断记录保留，不计入成功证明。

人工插手清单：无新增手动验证或工具转述；用户继续授权恢复并推送。

# E4 sketch 协议 bug：mid-stream wrap 位置相关流密码

日期：2026-09-30 ｜ 阶段：插件机制（`feature/plugin-obfs`）

## 现象

`examples/obfs_echo.rs` 按 sketch 实现后实测 hang（xc-pc-linux 真机，
`timeout 60` 才退出；本地沙箱同样 hang）。

sketch 协议（`scenarios/product/plugin_obfs_echo.toml` 注释）：
1. client 经 xor wrap 发 P；
2. server 先从 **raw** 流读 N 字节 W，断言 `W != P`；
3. server 再用 xor 插件 **wrap 同一条流**，读 wrapped → 写 wrapped 回显；
4. client 经 wrapped 读回显。

## 根因（两层）

1. **死锁**：client 发完 P 后即阻塞等回显；server 在第 3 步 `wrapped.read_exact`
   永远等不到数据——字节已在第 2 步被消费，client 也不会再发。双方互等。
2. **keystream 位置错位**（即使数据还在也错）：xor 插件是位置相关的流密码
   （`key[(pos+i) % key.len()]`，读写位置独立计数——这是正确的流密码设计，
   spec 明确要求）。mid-stream wrap 时，新 XorStream 的 rpos 从 0 开始，
   但对端发送方向已用到位置 N，解密必然错位。

## 修正

server 只用 wrapped 的**写方向**（该方向仍在位置 0，合法），回显确定性
明文 P（= W 的解密内容，双方独立构造）；client 经 wrapped 读回显断言
`E == P`。两个 E4 断言（`W != P` 混淆生效、`E == P` 语义正确）保持不变，
且全部变换走真实插件。

## 教训

- **E4 sketch 写"先读 raw 再 wrap 同一条流"时，先问：流密码的位置状态
  允许吗？** 位置相关的流变换（xor、chacha20 流式封装等）wrap 必须发生在
  该方向字节流的起始处；mid-stream wrap 在协议层面即不可实现，不是实现 bug。
- sketch 的 hang/错位在真机和沙箱都复现——这是协议 bug 不是环境问题；
  不要先怀疑环境。
- 修正 sketch 协议不违反"Protected 期望"：toml 冻结的是 `verdict` 的
  `one_of` 门禁，不是注释里的步骤描述；但必须在 commit message 和完工报告
  里明确记录偏差。

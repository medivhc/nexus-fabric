# Concurrency

重点验证：

- CancellationToken 只表达请求停止。
- JoinSet/Reaper 确认真实退出。
- Owner 是 TerminalOutcome 唯一写入者。
- success/failure/cancel race 只有一个 Outcome。

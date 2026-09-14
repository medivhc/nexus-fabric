# Benchmarks

关键 benchmark 必须定义：

```text
baseline
noise tolerance
warning threshold
blocking threshold
```

性能优化优先级：算法 → 架构 → I/O/syscall → batching → allocation/copy → contention → locality → 微优化。

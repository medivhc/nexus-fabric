# Track 1 ↔ Track 2 接口约定（NAT 生产流量切换）

## Track 2 提供（`nexus-nat-quality` crate）

### 核心类型

```rust
// 被测路径（Track 1 为每个连接构造一个）
pub struct MeasuredPath<T: DatagramTransport> {
    pub addr: SocketAddr,       // 对端地址 = PathManager candidate key
    pub kind: PathKind,         // Direct / Turn / Mesh / Proxy
    pub local_addr: SocketAddr, // 本端地址（CandidatePath 用）
    pub cost: f64,              // 相对成本 0..10（打分用）
    pub transport: T,           // 生产用 Arc<FabricConn>
    pub role: ProbeRole,        // Active（1s 探针）| Backup（5s 探针）
    pub forward: Option<mpsc::Sender<Vec<u8>>>, // 非探针 datagram 转交；None=丢弃
}

// 事件接收（Track 1 实现）
pub trait PathEventSink: Send + Sync + 'static {
    fn on_path_event(&self, event: PathEvent); // 主要是 Switched{from,to,reason}
}

// 监控器
impl QualityMonitor<Arc<FabricConn>> {
    pub fn new(pm: Arc<Mutex<PathManager>>, sink: Arc<dyn PathEventSink>) -> Self;
    pub fn add_path(&self, path: MeasuredPath<Arc<FabricConn>>); // 注册候选+启动探针
    pub fn remove_path(&self, addr: &SocketAddr);
    pub fn set_role(&self, addr: &SocketAddr, role: ProbeRole); // 切换后翻转频率
    pub fn start(&self);    // 启动后台线程（幂等）
    pub fn shutdown(&self); // 停止+join（幂等）
    pub fn tick(&self, now_ms: u64); // 单步（测试用；后台线程每 200ms 调一次）
    pub fn path_loss(&self, addr: &SocketAddr) -> Option<f64>;
}
```

### 调用序列（Track 1 的 PathLink）

```
1. 创建 PathManager（Arc<Mutex<>>），配置 20% + 3s（默认即是）
2. 创建 QualityMonitor::new(pm, sink)  // sink = 你的 PathEventSink 实现
3. relay 建连后：add_path(MeasuredPath{ addr: turn_addr, kind: Turn, role: Active, ... })
4. direct 打洞成功后：add_path(MeasuredPath{ addr: direct_addr, kind: Direct, role: Backup, ... })
5. monitor.start()
6. sink.on_path_event(Switched{from, to}) ->
     - 把 active FabricConn 从 from 换成 to
     - monitor.set_role(&to.addr, Active); monitor.set_role(&from.addr, Backup)
```

### 语义保证

- `on_stats` 每 tick 对每个路径调一次：`{rtt_ms: quinn 真实值, loss_rate: 探针滑动窗口, throughput: None}`。
- loss=None（无完成样本）+ rtt=Some → 正常计分；loss=1.0 → missed probe（3 次后 PathManager 自动 failover）。
- 无测量（rtt=None, loss=None）的报告被 PathManager 忽略（S7）。
- 探针帧 25B，wireup 层内部格式，不进冻结 P2 信令合同。
- 后台线程：`shutdown()` 停止；Weak 引用防泄漏；panic 不传播。

### 探针开销

- active 1/s → 75 B/s；backup 1/5s → 15 B/s。可忽略。

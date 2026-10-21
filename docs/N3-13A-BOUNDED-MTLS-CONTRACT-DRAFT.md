# N3-13A：有界 mTLS 传输与可信 peer context 分片草案

日期：2026-10-19。状态：**candidate / pending；不是正式契约、RED、freeze、实现授权或验收**。
任务类型：docs（为后续 feature 的契约阶段准备输入）。父 DRAFT
`docs/N3-13-REMOTE-TASK-CONTRACT.md` 的 SHA-256 为
`b212369db70844268618304101a481af51be93831b03d8d7848f877d5650a37b`，本次不改。
依据：正式 PRODUCT §17、ARCHITECTURE §6/7/12、Fabric/auth/control-api/nexusd MODULE、
N3-MODEL、N3-6、N3-12；独立 `n313-bounded-transport-audit19`、
`n313-contract-consistency19` 及 `n313-contract-refine19/next-step-planning-note.md`。
审计为静态 E1，且一致性审计针对父草案的更早摘要；它们不是对本草案的批准。
API首轮独立审计`n313-t1-api-audit19`对ee0a版本为COMMENTED（仅准许正式契约转写，freeze=false）；
本轮针对F1–F4补设计选择，**F3-B1/B2/B3仍BLOCKED，不标DESIGN_READY_FOR_FORMAL_CONTRACT_WRITING**。

## 1. 最小验收边界与保留依赖

提出两个可分别建立正式契约、RED、测试盲评和 hash 的分片：

| 分片 | 可申请的独立验收 | 必须排除的结论 |
|---|---|---|
| T1a | 明确 opt-in mTLS 的 payload/数量/时间/句柄生命周期边界及不可伪造 peer 证据；真实两进程 **transport E4**，context adapter 的 E2/E3 | 128MiB 总 heap、完整有界 RPC、生产 N3 命令 listener 已可启用、Task 命令生命周期 E4 |
| T1b | 同一确切版本/target/profile 的剩余受控分配、最坏瞬态和回收证明；适用业务 adapter 的完整账本 | 用窗口、RSS 样本或 T1a 成功代替总界证明 |

T1a 不新增 Task 六类 operation、Snapshot 五类 operation/四个状态、schema1 字段、
持久业务状态或生产路由。transport verifier 可以传输固定字节，不增加 Echo/NoOp Task operation。
FabricConn 仍不是资源 Session；可信公钥不等于 Use、接受或 Ready。
T1a 不以 D5/D6/D9 全部定案为前置；**完整 Submit 仍依赖 N3-12 最终验收、D5 唯一容量/
copy handoff、D6 双端 Plan/Session 归属与装配、D9 finalization/pin/GC，以及 D1/2/7/8 和运行中撤权闭环**。
原 22 条 N3 场景和真实 Windows→Linux E5 均保留；本片无 Engine 资格或启动证明。

T1b 不是含糊延期出口：§5 每个未决 bucket 必须逐项得到有限 cardinality、retained allocation、
同时副本、拒绝前瞬态、owner/最长寿命和可核验计数。**在全部适用 bounds、绝对 deadline、
取消唤醒及 owner/reaper 证明闭合以前，生产 N3 命令路由仍禁用**；即使 T1a 独立验收也不豁免。

## 2. 当前 API 事实与收敛的 additive opaque API

以下为当前源码位置，不是拟新增符号已存在的声明：

| 真实入口/状态 | 已核实事实与约束 |
|---|---|
| `crates/nexus-fabric/src/lib.rs:35,67,125,140,345` | 公开低层 Driver/Cmd/ConnShared/StreamShared；ConnConfig 为两个公开字段；已有 connect_mtls/bind_mtls 和 mutual accessor |
| `driver.rs:100,203,208,240` | pub `ConnShared.tx`、`StreamShared.tx/state`、可增长 FIFO、携任意 Vec/String/crypto 的 Cmd；不能透出给新受控句柄 |
| `lib.rs:399,460`；`driver.rs:337,628,646` | write 全量入无界 FIFO；read_deadline 先返回 buffered bytes 再查时钟；无界 mpsc/命令 drain/UDP drain |
| `driver.rs:585,1069,1187,1248` | Drop 无限 join；reaper 未清 accept_q stale id；Finished 被忽略；不是 5s 回收证明 |
| `crates/nexus-nat-wireup/src/channel.rs:130,256` | 真实调用者直接发送旧 Cmd；不能换 Sender 类型或静默收私有 |
| `crates/nexus-control-api/src/task.rs:13,21` | TaskCallContext constructor 只验证字符串，不能认证；必须由真实已认证连接的调用者约束 |

以下为**已选择、可转写正式契约的完整公开签名**，仍是未冻结 DRAFT；不是现有实现或新 Stub。
位置固定在现有 `nexus_fabric` 的 re-export surface；只依赖现有 `FabricIdentity/PeerId/ConnectionId` 和 std。
`BoundedMtlsEndpoint/BoundedMtlsConn/BoundedBiStream/BoundedSendHalf/BoundedRecvHalf/VerifiedPeer`
均为全部字段私有的公开 opaque struct：不提供字段字面量、Default、Clone、Copy、序列化、外部实现入口或 raw 访问。
它们均可 Send+Sync；read/write 使用独占 `&mut`；调用者自行 Arc 包装只共享同一个句柄，不产生新的库内 handle/slot。
下列声明省略实现和 opaque struct 的私有字段；正式 Stub 必须保留私有字段，不能将其变成可任意构造的空 struct。

```rust
use std::{io::ErrorKind, net::SocketAddr, time::{Duration, Instant}};

// 以下值类型均实现 Debug + Clone + Copy + PartialEq + Eq，无 String/Vec/Box。
pub enum BoundedPhase { EndpointInit, Handshake, Accept, Open, Read, Write, Finish, Drain }
pub enum BoundedResource { Connection, Command, Allowlist, IdentityMaterial }
pub enum BoundedError {
    Timeout { phase: BoundedPhase },
    Closed { code: u64 },
    StreamStopped { code: u64 },
    Cancelled,
    CapacityUnavailable { resource: BoundedResource },
    StreamLimit,
    WrongRole,
    InvalidInput,
    SendFinished,
    DrainBeforeFinish,
    AuthenticationRejected,
    TransportFailure { kind: ErrorKind },
    DriverPanicked,
    ShutdownIncomplete,
}
pub struct BoundedIoError { pub transferred: usize, pub cause: BoundedError }
pub enum BoundedDriverExit { Clean, Panicked }
pub struct BoundedShutdownReport {
    pub driver_exit: BoundedDriverExit,
    pub elapsed_since_first_shutdown: Duration,
    pub within_five_seconds: bool,
    pub retained_connection_slots: u8,
}
pub struct BoundedSlotSnapshot {
    pub connection_id: Option<ConnectionId>,
    pub public_handles: u8,
    pub stream_created: bool,
    pub send_fifo_bytes: u32,
    pub recv_fifo_bytes: u32,
    pub send_fifo_high_water_bytes: u32,
    pub recv_fifo_high_water_bytes: u32,
}
pub struct BoundedEndpointSnapshot {
    pub slots: [BoundedSlotSnapshot; 8],
    pub commands_in_use: u8,
    pub waiting_operations: u8,
    pub pending_pumps: u8,
    pub pending_cancels: u8,
    pub accepted_connections: u8,
    pub live_entries: u8,
    pub handle_entries: u8,
    pub shared_entries: u8,
    pub stream_entries: u8,
    pub shutdown_requested: bool,
    pub driver_finished: bool,
}
impl BoundedMtlsEndpoint {
    pub fn bind_client(addr: SocketAddr, identity: &FabricIdentity, deadline: Instant)
        -> Result<Self, BoundedError>;
    pub fn bind_server(addr: SocketAddr, identity: &FabricIdentity, allowed: &[PeerId], deadline: Instant)
        -> Result<Self, BoundedError>;
    pub fn local_addr(&self) -> SocketAddr;
    pub fn local_peer(&self) -> PeerId;
    pub fn connect(&self, peer: PeerId, addr: SocketAddr, deadline: Instant)
        -> Result<BoundedMtlsConn, BoundedError>;
    pub fn accept(&self, deadline: Instant) -> Result<BoundedMtlsConn, BoundedError>;
    pub fn request_shutdown(&self);
    pub fn shutdown(&self, deadline: Instant) -> Result<BoundedShutdownReport, BoundedError>;
    pub fn snapshot(&self) -> BoundedEndpointSnapshot;
}
impl BoundedMtlsConn {
    pub fn id(&self) -> ConnectionId;
    pub fn verified_peer(&self) -> &VerifiedPeer;
    pub fn open_bi(&self, deadline: Instant) -> Result<BoundedBiStream, BoundedError>;
    pub fn accept_bi(&self, deadline: Instant) -> Result<BoundedBiStream, BoundedError>;
    pub fn abort(&self, code: u32);
}
impl VerifiedPeer { pub fn public_key(&self) -> &[u8; 32]; }
impl BoundedBiStream {
    pub fn split(self) -> (BoundedSendHalf, BoundedRecvHalf);
}
impl BoundedSendHalf {
    pub fn write(&mut self, bytes: &[u8], deadline: Instant) -> Result<usize, BoundedIoError>;
    pub fn finish(&mut self, deadline: Instant) -> Result<(), BoundedError>;
    pub fn drain(&mut self, deadline: Instant) -> Result<(), BoundedError>;
}
impl BoundedRecvHalf {
    pub fn read(&mut self, out: &mut [u8], deadline: Instant) -> Result<usize, BoundedIoError>;
}
```

**角色和准入顺序。** bind_client 仅主动 connect，bind_server 仅 accept；反向调用 WrongRole，不发包/建状态。
构造先检查 deadline、allowlist≤64、identity cert/key DER各≤4096 bytes，再复制配置；空allowlist合法但拒绝全部。
随后创建固定槽/通知状态、内部 `StdUdpTransport` 并设 nonblocking、固定scratch、启动唯一driver；配置/系统调用
前后查deadline。到期或失败需撤销构造：未spawn时释放本地状态；已spawn则请求停止并真实join后才返回Err，
不能返回Err却留下无owner线程。其cleanup若超过支持环境5s则该case不得PASS；不是以构造deadline强杀std线程。
初始化不缓存DNS、外部transport或任意用户callback；identity由既有API事先构造，该输入对象本身非本endpoint新分配。
connect 在调用时刻固定 `min(deadline, start+10s)`，依次检查角色/终结/时间 → 非阻塞取得连接槽和普通operation槽
→ 在原槽中构造per-connection crypto/QUIC/共享状态 → 执行命令 → 完成双向认证才发布conn。
8连接或32operation满立即 CapacityUnavailable，不建立等待队列、不在取permit前clone crypto/建reply channel。
除shutdown独立gate外，所有会等待传输进度的公开操作（含half read/write/finish/drain）先取同一32槽中的operation槽，满即拒绝且不复制输入；
不要求必须向driver排command，直接FIFO操作也保持计费。accept 等待前同样取槽，只返回已认证且仍live的原槽；调用者deadline超时
不取消整个listener，但不能返回过期/关闭conn。server首包采用固定scratch预处理，在accept完整QUIC前取连接槽；
拒绝Incoming仍须refuse/ignore消费。connect迟命令带cancel+generation，失败/超时后不创建孤儿，残留仍收费至cleanup。

**唯一所有权。** endpoint唯一拥有driver JoinHandle、socket/config/固定槽账本；没有其他library worker/reaper线程，
不公开转移join所有权的API。conn及流只引用private slot/core，不能持有driver owner/JoinHandle或阻止endpoint关闭。
每conn至多一个conn句柄、一个BiStream或各一个half（split消耗BiStream），无重复split/重组/Clone；
public_handles计数最大3。open/accept_bi先取operation槽，再原子claim lifetime stream位；WrongRole/容量失败不claim，
claim后的超时/失败abort原conn，不能重开第二流。conn保持存活才允许使用其流；conn Drop即sticky abort整个conn。
BiStream未split而Drop、send half未成功drain而Drop、recv half未读到EOF而Drop均abort整个conn并唤醒另一半；
成功drain后的send Drop或已EOF的recv Drop只释放该half。双方完成仍须保留QUIC closing/draining状态至实际reap。
最后句柄不再持slot、map/queue/reply/control全摘除及backing释放后才返槽；close后仍保留conn/half则原槽继续占用。
endpoint Drop可先于这些独立句柄：先request_shutdown、终结全部slot/通知waiter，再真实join；旧句柄只剩有界终结事实，
不能重启driver；其保留槽仍按账本报告。Drop不detach、不转交隐形全局reaper，异常路径也不丢JoinHandle。

首次request_shutdown/shutdown/endpoint Drop发布endpoint sticky位时记录唯一shutdown起点，后续调用不重置。
request_shutdown无分配、幂等、停止新admission并取消全部slot；shutdown可与阻塞connect/accept/halves并发，
最多一个shutdown观察者占用独立固定join-owner gate，第二个并发shutdown返回CapacityUnavailable(Command)，不排队。
request_shutdown与conn.abort不取普通32槽；按§4.1取得唯一短临界区M后分别置1个endpoint sticky bit/每conn sticky bit，
发布谓词再notify所有waiter及driver Condvar；不得只atomic store+notify而省略wait协议。notify不是reap。
shutdown每次最多等待 `min(deadline, now+5s)`，不足则ShutdownIncomplete且
JoinHandle仍留原endpoint；可再次shutdown继续收割，**首次shutdown计时不重置**。确认thread已结束才调用join、
消费真实返回/JoinError，结果报告Clean/Panicked、首次开始至join被消费的elapsed、≤5s标志和仍被外部句柄保留的槽。
已join可复用缓存exit/elapsed并重新读取retained slots形成报告（即使观察deadline已到）；deadline只限制等待，不能阻止收割已结束thread。
Clean且within_five_seconds才满足A7的join部分；Panicked、Incomplete或迟join不能伪装PASS。Drop是最后同步reaper，
若未结束仍等待真实join，可能暴露超过5s的实现故障；没有数学上任意OS调度下的有限Drop保证，也不把阻塞隐瞒成已回收。

**IO精确语义。** 有效deadline为调用者绝对时刻与认证完成+30s的min；除accept等待本身外，
connect/open及所有stream IO超时均sticky abort该conn；取消只影响传输，不写Task终态。
read/write在检查终结/时间后一次最多复制一个≤65536且有空额的前缀；非空write成功为1..len，满时只等待空额/
取消/同一deadline，不保存caller后缀。read非空out时成功1..out.len，**只有recv FIFO空且已收到合法FIN才Ok(0)**；
空out返回InvalidInput，不伪装EOF。空write在终结/时间检查后Ok(0)，不FIN。返回前再次检查deadline/取消：
若本次已有复制/接受进度，不回滚、不用无进度Err隐藏；返回BoundedIoError.transferred明确本次前缀长度（0..len），
cause为实际终止原因。caller必须推进该前缀后处理错误，不能重发整片；write前缀只证明本地接收，abort时不保证送达。
read错误中的前缀已写入out、已消费；其余out不改变。存在cancel/关闭事实时返回已锁定的终止原因，否则到期Timeout，
正常成功不能在返回前时间检查已到期时继续报告Ok；调度发生在最后检查之后不被当作可回退的事务。
finish幂等封住send侧，FIN排在此前所有已接受字节后；它不等待ACK。finish成功后write为SendFinished，
失败/超时不重新开放send。drain须先成功finish，否则DrainBeforeFinish；等待此stream的全部字节及FIN被QUIC确认，
依据 `StreamEvent::Finished`（vendor streams/mod.rs:494）并独立跟踪Stopped/reset/连接错误，
**该事件文档为fully acknowledged OR stopped，不能单独当ACK证明**；收到Stopped返回StreamStopped，不能伪报drain。
该版本成功ACK的实际路径为streams/state.rs:693–725，正式测试必须区分ACK与STOP；不证明对端业务已读/处理。
drain幂等但仍遵守同一deadline；对端不确认则Timeout并abort。recv EOF与send drain分别成立后才允许无损关闭，
不把conn.close或FIN已入本地队列当drain。所有返回错误无任意文本分配；AuthenticationRejected仅用于本端确证的认证拒绝，
未知远端close保留Closed/TransportFailure，不猜测allowlist。错误实现std::error::Error/Display，文本只依固定枚举/数值格式化。

VerifiedPeer仅由完成双向TLS且已核实raw key的private代码构造，并内嵌于原slot；public_key借用原32-byte key，
无公有from/new/From/TryFrom/Deserialize或脱离conn的owned凭证。它证明该连接历史认证事实，不证明当前Use或conn仍live。
snapshot是固定值副本、各字段在同一M临界区一致；send_fifo_bytes含§4.2未提交in-flight前缀，driver_finished为
退出guard完成发布标志而非join证明；slots的None表示空槽，其余字段为0；计数为真实占用/高水位，
**不是total heap计量或新authority**。私有压力计数/allocator探针仍可用于测试，不扩大本公开API。

新句柄不实现到旧 FabricConn/Driver/ConnShared/StreamShared 的转换、Deref 或 raw/shared accessor，
不接受legacy Arc伪装受控连接、不暴露Sender/可写队列；新入口只内部创建Std UDP，无with_transport入口。
同一driver控制流按private profile分支复用，不新建crate/trait/dependency或复制driver；适用S9保持经原UdpTransport收发，
nonblocking在内部StdUdpTransport交给driver前配置，Condvar用于无包时等待/唤醒，不让driver直接持有UdpSocket。
旧默认 connect/bind/connect_mtls/bind_mtls、ConnConfig 字面量、pub Cmd/ConnShared.tx 原样保留；
S3/S4 无损有序/EOF、S5/datagram/QSEQ、S9–S11、旧场景期望不改。新单流限制不作用于旧入口。

trusted context 的后续最短路径为 completed mTLS → opaque peer →
`Principal::from_ed25519_public_key`（`crates/nexus-auth/src/lib.rs:106`）→ 配置 workspace →
`TaskCallContext::from_authenticated`。组合根 helper 私有，拒绝把请求 principal/header、IP、
旧 peer()/零占位值、provider 自身身份传入远端调用。每次真实业务操作仍重读当前 Use、owner/scope 并审计；
T1a 可验证该 helper/真实授权适配器，但不启用 Task/Snapshot dispatch，也不借机增加第二个 context authority。

## 3. T1a 候选预算与生命周期（所有数值 pending 正式冻结）

作用域是**一个 endpoint（一个 owner、一个 driver）**；两进程 verifier 各一个 endpoint。
不是整个 daemon/多个 root 的总界。生产组装必须另限制 endpoint 总数并汇总角色，禁止 requester
每次 connect 新建 driver 从而绕过 8-slot 聚合。所有乘加 checked，溢出在分配前拒绝。

| bucket | 候选硬界与收费/返费时点 |
|---|---|
| connection slot | endpoint 共8；创建完整 QUIC/连接共享状态前取 permit；pending、已认证未 accept、active、closing、draining、reaped 但仍持有旧句柄/回复者均占原槽。所有 map/queue/库内 handle 引用及 backing allocation 释放后才返还；保留旧句柄会使新连接容量拒绝 |
| Incoming | max_incoming=8；附加缓存每条≤16KiB、合计≤128KiB；**不含首包**，另计 UDP scratch。accept 会移出 Incoming，故此 cap 不能代替上行8个生命周期槽；拒绝用 Endpoint refuse/ignore 完整消费状态，不只 drop Incoming |
| stream | 整条连接 lifetime 合计1条 requester 发起 bidi；§4.4规定provider初始remote bidi=1、创建返回立即target→0，requester remote bidi=0；两端uni=0、禁用业务datagram。first free不replenish，应用lifetime claim独立保留；第二条不建app map/queue |
| app FIFO | 每连接 send、recv 各65,536 payload bytes；send的queued+被driver借用但尚未由QUIC确认接收的前缀总占≤65,536；copy scratch不返额度，按§4.2实际accepted n提交head。固定backing不自动扩容，8槽合计1,048,576；另计driver≤65,536 scratch及QUIC同时副本，actual allocation ceiling仍须单列 |
| QUIC payload | 每连接 send_window、receive_window、stream_receive_window 各≤262,144 bytes；send/receive 逻辑 payload 合计8×2×262,144=4,194,304；receive 两层窗口非两个独立payload池，不能将此数当全部 allocator heap |
| crypto reorder | crypto_buffer_size=16,384 **每 packet-number space**，3 spaces 的区间界；连续消息、TLS transcript/cert/output 不属于该界，见§5 |
| mailbox | 每 endpoint 普通 command（排队+执行+未消费 reply）共32个固定槽；命令只持 slot/generation/固定参数，不带用户 Vec/String/crypto/body。配置引用已计费且有界；一个同步 reply 槽/操作，不在取 permit 前创建 channel/等待线程/连接对象 |
| control/Pump | 每 connection 最多1个 pending Pump bit，共8，反复 write/read/finish 合并。Close/cancel 为8个独立 sticky control 槽，Shutdown 为1个 endpoint sticky bit；不挤占32普通槽，唤醒不依赖普通入队成功；计入固定元数据，不能暗建无限优先队列 |
| accepts/maps | accept_q≤8且引用原 connection slot；stream accept≤1/conn。reaper 同时移除 live/handle_map/shared.conns/accept_q、stream map/queue、reply/Pump 残留，generation 避免 stale command 命中新槽；无永久已完成流历史表 |
| config/UDP | allowlist≤64个32-byte key，验证数量后才 clone；身份输入材料/crypto clone 单列账本。一个driver recv scratch=65,536，当前路径单次复制≤65,536；固定初始/最小 MTU=1200、关闭 MTUD/业务 datagram；输出 scratch/copy 的实际capacity另列，不能用1200代替所有握手/拒绝路径分配 |

recv 仅按 app FIFO 剩余空间调用 QUIC chunks.next(max)，满时不读不提前返还 credit；应用 read 后置
coalesced Pump 并唤醒 driver。send 只复制可容纳前缀，partial/Blocked 保序，ACK/window/FIFO 空额变化
唤醒写者；等待不持有 driver 需要的锁。FIN 排在已接受字节后；finish 只表达提交 FIN，**不等于 ACK/drain**。
graceful drain 成功须证明原发送字节/FIN 的协议完成；未完成到期明确 abort/error，不能 finish 后立即 close
又宣称 S4 完整交付。任何 quota/cancel/超时均不把已接受可靠字节静默丢弃并报告成功。

完成 stream 后删除活动 map/accept 引用和可回收 payload；尚在 QUIC retransmit/应用半句柄/reply 的状态继续计费。
connection final cleanup 可把有界失败事实留给旧句柄读取，但旧引用/槽未消失不得当作 memory 已回收；
最后 owner/half Drop 触发取消与清理，不能只 listener Drop 而由遗留 conn 永久维持 driver。

## 4. 绝对时间、公平性和 thread owner

client handshake 总10s从 connect 调用开始（含 admission/命令等待/config crypto 构造），server 从首个
接纳 Initial 的单调时刻起10s；均不按 packet/进度续期。认证后 IO/drain 总30s从完成认证时开始，
即使连接未被 accept、未送首字节也到期。调用者 deadline 与该 cap 取 min；未来 LocalAPI/page 原5s总预算
仍取更小值，不能加30s。每个 read/write/open/accept/drain 入、出和每次复制/循环前查同一时钟，
已缓冲字节/EOF 也不允许过期后返回成功。RPC IO 过期只终止观察与连接，不改已接受 Task 的 outcome/cancel。

候选 driver quantum：普通命令每轮≤16条或2ms、UDP每轮≤32 datagrams或2ms（先到即退出该批）；
每连接每轮 send/recv 各≤64KiB，8槽 round-robin。每项前后检查 clock/control，批次之间执行到期计时器、
取消和 reaper；持续 UDP、command、短 frame 不能无限 drain 到 EAGAIN。正常无包等待为driver自己的Condvar，
最多10ms或下一个timer/deadline（先到为准）；使用sticky work epoch在检查/进入wait时防lost wakeup。
所有socket recv/send均为内部预设nonblocking的StdUdpTransport原trait调用：WouldBlock立即返回调度器，
send不得等待socket可写，最多保留一个固定有界待发datagram、后续重试；其backing/scratch计入账本。
待发占用不能阻塞control/timer/reap；永久写不可用仍可abort并清理，超长packet在受控分配前的界仍须§5证明。
nonblocking设置失败则构造失败，不带着阻塞socket启动driver；不调用外部transport、DNS、用户callback或阻塞文件IO。
2ms是合作式切批预算，不能抢占单次quinn/TLS callback；pump内的event/endpoint-event/transmit循环也必须切批，
每conn每轮事件≤32、transmit≤32次（每次poll_transmit的max_datagrams=1），timer每conn每轮最多一次处理，
不得在callback外围再嵌套无界drain；仅保留原slot内的待处理标志，查clock/control后才进下一次callback。
callback处理一个packet的单次复杂度/输入长度/工作集合，以及mutex临界区不跨IO/callback/wait，是静态可行性审查对象。
测试同时报告轮次延迟和墙钟延迟：支持环境固定负载下
deadline/cancel 服务延迟 warning=50ms、blocking=500ms（不扩大10/30s的成功窗口）；超预算判失败，不重试遮蔽。

endpoint是唯一driver owner兼同步reaper，具体Drop/shutdown/API按§2；没有新增后台worker或可积累reaper队列。
sticky cancel不占32槽，但必须经§4.1唯一短临界区M发布谓词再notify；该锁不跨callback/IO/析构。
waiter持固定operation permit，cancel不创建新通知对象；全退出/poison协议见§4.1，release panic=abort边界见§4.3。
owner仍须消费实际join结果才能报告Reaped，completion/notify不能替代它。
5s是支持环境中的**可观测验收上限**，当前尚无实现证据；不承诺数学上任意OS停调度/OOM/abort的及时回收。
支持环境需在正式场景固定target/toolchain、allocator、quinn/rustls版本、CPU/内存资源与压力fixture规模，并记录实测；
测试宿主不满足约定前提记BLOCKED，满足前提却超时也记BLOCKED/不得PASS，不能事后调整fixture掩盖慢join。

具体障碍：现 `Driver::drop` 无超时 join（driver.rs:585）；run 的命令/UDP无限drain（628/646）、
Shutdown 直接 break 未统一 notify（634）；`UdpTransport` 只有 recv/send/set_read_timeout，**无 cancel/wake 或
send-timeout 保证**（transport.rs:25），旧实现不能约束自定义 adapter 的阻塞，std socket send 也未设有限等待。
mutex/配置构造、quinn/TLS 单次回调和调度饥饿都可能超过候选时限，std JoinHandle 没有安全强杀。

本轮选择§2/本节的内部nonblocking Std UDP + 有限quantum + 原endpoint同步reaper，不保留转交后台reaper/
子进程的未定选项。旧S9 trait/with_transport入口完全不变；新driver仍经trait收发，故与Fabric MODULE:49–55
没有已证实冲突。若后续必须绕开trait直接由driver持UdpSocket，则该处是具体契约冲突，先走requirement-change。
本轮F1/F2/F4的选定机制见§4.1/4.2/4.4；F3具体callback/析构工作界仍未闭合，见§4.3，
不是“代码尚未写所以永远不能freeze”。freeze前需独立静态可行性与测试设计评审能给出有限机制和可证伪A7；
freeze后实现必须实际跑出Clean且≤5s join，再加所有句柄释放后的零残留账本，才可通过A7并进入适用验收。
Incomplete/迟join期间endpoint保有原handle与charge、拒绝新admission；Drop仍同步join，可能暴露故障而阻塞，
不谎称已按时回收。丢handle/detach/进程退出不是回收；测试subprocess kill只隔离故障，不替代库join。

### 4.1 F1：单锁图、等待谓词与异常所有权（设计选择，未实施）

新profile只用一个共享数据mutex **M**：固定8槽元数据、FIFO/head/tail/in-flight标记、32 operation/reply槽、
accept/Pump/control位、计数/终止原因/退出标志都在M下。QUIC/Endpoint/TLS仅driver本地拥有，不共享加锁。
join存储mutex **J** 仅endpoint owner使用，shutdown观察者先以原子CAS取得独立 **G** gate（失败立即容量拒绝）。
锁图选为 **G→M 或 G→J；M与J永不同时持有**。driver/API不取G/J；snapshot只取M；取到JoinHandle后使用
私有RAII join lease持有它，join不持M/J；lease在可展开异常路径也同步join，不能让JoinHandle隐式Drop而detach。
gate释放/cache写入不嵌套M/J。首次shutdown时间和首个terminal reason在M下first-write-wins；后续fault健康位可升级
为异常，但不得覆盖此前已报告IO进度或伪造Task终态。没有基于legacy accepted→state嵌套锁的新增边。

M内仅固定槽索引/checked计数、≤64KiB的一次copy、无分配状态移动；所有分配、Box/Vec/map/TLS析构、
socket recv/send、quinn/rustls/verifier/日志callback、join均在M外。退休payload用Option::take移到driver局部后释放；
pin/in-flight未返回不得退休或复用generation。需要多个更新时一次取M完成，不回调public API，不递归取M。
这给出可审查锁图与有界临界区操作数；不声称任意OS抢占下锁等待有数学时限。

所有阻塞者和driver使用**同一M关联的预建Condvar**。waiter在M下检查：terminal/poison、同一绝对deadline，
再检查自身谓词（reply ready、accept非空、send有空额、recv有字节/EOF、FIN ACK或driver completion）；
若均不成立则 `wait_timeout(M, min(剩余deadline, 10ms))`，原子释放M并等待，醒后重新取M重查，允许伪唤醒。
producer/取消者必须先取得M修改相同谓词，释放M后notify_all；通知即使先于真正阻塞，也不能越过wait的原子
释放/注册窗口。统一work epoch也在M下递增，driver同样在M下check→wait；不依赖一次atomic通知的偶然时序。
预建等待者容量为32个API operation、1个driver、1个shutdown观察者，不额外分配channel/通知节点。
10ms复检是额外延迟兜底，不把30s业务deadline当取消唤醒机制。M外callback返回前，取消者可独立取得M并唤醒API；
driver只在其callback返回后响应，因此F3仍是join阻塞。普通槽满不阻塞取消进入M。

PoisonError一律取into_inner进入**终结专用**路径：不unwrap、不clear_poison后恢复业务、不重建空Ready；
固定8槽/32回复标记为failed/关闭、保留permit及未知in-flight债务、notify全部waiter。故障latch使shutdown不得返回
Clean成功；若driver实际正常返回但发生过poison，shutdown消费join后仍返回DriverPanicked（此变体包括库内panic/
poison故障，不宣称只有driver线程会panic），保存真实join事实供固定诊断测试；若join本身Err则按原Panicked报告。
driver外层退出guard在正常return、Result错误、可展开panic三条路径均先发布terminal并通知，再在M外回收本地
QUIC/TLS/缓冲；cleanup完成后发布completion，owner再实际join。guard不用日志/分配/unwrap制造二次panic；
无法安全析构/二次panic时不得宣称cleanup完成。**panic=abort/OOM/SIGKILL不执行此guard**，见§4.3。

### 4.2 F2：send ring借用不返费，partial提交head（设计选择，未实施）

选定“原ring不pop”机制：设Q为尚未获QUIC接受的ring字节数，L为driver当前借用的head前缀，
`0≤L≤Q≤65536`，L是Q的子集，不能将Q+L重复当两份逻辑payload；scratch实体副本另计≤65536/driver。
driver在M下选择连续有序前缀（ring wrap可按顺序复制两段），记录slot generation/head epoch/L并copy到固定scratch，
**不移动head、不减Q**；释放M后只调用一次QUIC write。app同时只能写tail，空额始终为65536−Q。
callback返回accepted n（0≤n≤L）后，driver取M校验同一pin/generation/head，唯一提交head+=n、Q-=n，
清in-flight标记再唤醒writer；Blocked等价n=0，partial的L−n继续原位留在ring，绝不“放回”而与app refill叠加。
snapshot.send_fifo_bytes=Q，故借用64KiB时仍报告64KiB、app没有空额；收1byte后只允许再填1byte。

cancel可在callback期间将原slot标terminal，但不得清ring/pin、返permit或复用generation；callback返回后仍按实际n
记账，然后以显式abort失败回收剩余字节，不返回drain成功。若callback展开panic而n未知，原Q和pin债务保留，
退出guard终结整个conn并回收，不重试可能已写入的同一前缀。没有M跨QUIC callback，也没有公开raw共享状态。
正式测试须固定交错：Q=65536→借用→app尝试refill→Blocked或n=1→提交，分别验证Q、可写空额、顺序和cancel。

### 4.3 F3：callback清单、支持profile与仍在的真实阻塞

下表位置均为确切当前源码；“机制/未决”不是已经存在的新profile实现。外层每批重查control/clock，STOP/reset/
connection error按顺序锁定sticky失败，不能采集一批Finished便清掉先前失败。driver单线程没有回调并发。

| 具体callback/析构 | 已选择的有限输入/操作机制；仍需闭合的部分 |
|---|---|
| `Endpoint::handle/accept`（endpoint.rs:148/549）与`Connection::handle_event`（connection/mod.rs:1121） | 一次UDP≤65536；每批≤32；Incoming缓存和8-slot admission在前。accept内部先处理首包/缓存（endpoint.rs:665–678），不能在外层插timer；帧迭代长度有packet字节界（connection/mod.rs:2770），但内部CRYPTO/TLS路径仍见下一项 |
| `read_crypto/write_crypto`（connection/mod.rs:2138–2195）→`TlsSession::read_handshake/write_handshake`（crypto/rustls.rs:106/144） | crypto乱序区间16KiB/space已选；**内部read(usize::MAX)循环、write_crypto drain与rustls read_hs/write_hs不可被外层quantum抢占**。rustls quic.rs:404–422先extend/coalesce/process_new_packets，490–499 drain hs_queue；deframer/handshake.rs:164–179先coalesce后单消息cap。尚无本片可复算的累计连续输入/队列节点/单调用工作上界，这是F3-B1 |
| `poll/poll_endpoint_events`（connection/mod.rs:396/414）→`Endpoint::handle_event`（endpoint.rs:106） | 不建全量event Vec；每conn每轮≤32事件/endpoint事件，固定pending位续轮。`StreamsState::poll`（streams/state.rs:845–860）内部可扫描connection_blocked列表；须把有效/残留条目界绑定本profile总一流，不能只看外层pop次数 |
| stream write/read/Chunks finalize/Drop（streams/mod.rs:223/128；streams/recv.rs:288/347–386） | 一次send≤65536，原ring计费按§4.2；recv一次仅取当前FIFO空额、复制一块后提交再续轮；Chunks不跨driver轮次/共享锁，显式finalize；其Drop也会返credit，纳入callback而非假设空析构 |
| `handle_timeout/poll_transmit`（connection/mod.rs:1193/460） | timer表有限，但LossDetection会调用1658/1705，1728扫描sent_packets；ACK路径1497也扫描packet表。单次transmit max_datagrams=1、每轮≤32不限制该map遍历；现send_window不约束所有control/sent-packet节点。节点/重传清单的有限cardinality或可中断扫描方案未定，为F3-B2 |
| `verified_connection_peer/peer_identity`（cert.rs:421–438；crypto/rustls.rs:80–86） | 每conn认证后只提取一次原key；clone整个peer证书Vec后才strict校验，不能用自有identity DER≤4096冒充远端证书拒绝前工作界；依赖B1的证书/节点上界 |
| 关闭/错误/退出的QUIC、TLS、packet map、事件/重传/assembler析构（Connection字段见connection/mod.rs:167–246；PacketSpace见spaces.rs:20–61） | 一次最多退休1 conn、每轮最多8槽，M外drop；但是单个Connection的自动字段drop不能从外部切片/抢占，最终endpoint退出还必须全部真实释放。实际retained节点数量与自定义TLS/allocator析构工作未闭合，为F3-B3；drop完以前不发布Reaped/返费 |

固定候选 **T1a-Linux-v1** 支持profile：x86_64-unknown-linux-gnu、Rust1.85.0、Debian13/glibc2.41、
Linux6.18.55、System allocator、锁定本地quinn-proto0.11.18/rustls0.23.45及源码SHA；这些是后续验证前提，
不是当前宿主已资格化的证据。release沿Cargo.toml:68–72 thin-LTO/1 codegen-unit/**panic=abort**；
debug/unwind仅用于专用panic/poison测试，两者分别记录二进制/配置SHA，不能以debug异常恢复声称release可恢复。
release panic abort/OOM时观察进程退出，A7不能PASS，也不能声称catch_unwind/guard已清理或返回Panicked报告。
普通取消/关闭的Clean≤5s仍须在release真实观察；宿主任意停调度不属于数学保证。

固定压力fixture前提：两真实role进程各1 endpoint，至少4个独占逻辑CPU的总配额、每role可用内存≥2GiB、
nofile≥1024、loopback；合法控制8条连接/每条分块4MiB hash+EOF/ACK；每个压力case只改一个条件，UDP洪泛
以1200-byte、10,000 datagrams/s持续12s、command尝试10,000次/s持续12s，分别运行后再组合；固定seed和单调
时间表由observer记录，不能因join慢而降低负载/补跑抹掉失败。A2 sequential 10,000次回收仍单列，超出以上
profile或宿主无法满足资源前提记BLOCKED，不借此声称全平台资格。fixture数值已选，测试执行/环境摘要仍未做。

**F3结论：BLOCKED，B1/B2/B3均为具体冻结前设计缺口。** 若版本源码能证明这些子工作集有界，需给逐项数值/
推导及独立审查；否则先提出最小vendor输入/节点cap或可续进扫描/析构机制并独立评审，不在本轮实现或假定现API
已有setter。它们是join及时性的前置子界，与T1b有交集，不能以“T1b以后做”绕过；也不要求先有生产GREEN才能freeze。
128MiB总heap仍未证明，外层2ms/5s观察窗口和RSS均不能填补B1–B3。

### 4.4 F4：初始首流credit与future target立即降零（源码支持的设计选择，未实施）

provider TransportConfig初始remote bidi=1、uni=0；requester初始remote bidi=0、uni=0（这是允许**对端发起**的
credit，不妨碍requester根据provider广告open首条）。两端关闭0RTT/early data/tickets/resumption，沿cert.rs:391–413。
driver在`Endpoint::accept`返回原QUIC对象后，**发布到live/handle/shared/accept队列、再喂任何后续event、timer、
stream accept/read/reset或poll_transmit之前**，立即对provider执行 `set_max_concurrent_streams(Dir::Bi, 0)`；
requester创建后同样确认Bi/Uni target=0。此步骤与对象仅归driver本地拥有的构造序列不可交错。

真实机制：Connection::new把config中的remote count初始分配为1（connection/mod.rs:352–358；streams/state.rs:163–166）；
setter（connection/mod.rs:1439–1444）改target，不撤回已广告的首条credit。`set_max_concurrent`→
`ensure_remote_streams`（state.rs:913–916/217–225）计算 `0.saturating_sub(allocated=1)=0`，max_remote保持1；
第一条bidi两半真正free时（989–998）allocated降0，再ensure计算0−0仍0，max_remote仍1，不生成第二条credit。
`queue_max_stream_id`（869–878）即使检查也只能广告原max_remote=1，不会把target=0当“把首条收回”。
set_params（200–213）只处理对端参数/本地发起上限，不重置此remote target。

不能忽略accept内部已处理首包/缓存（endpoint.rs:665–678）：该窗口无app read/reset/free，Initial/Handshake非法
STREAM会拒绝；mTLS禁early data且server flight尚未由driver发送，不能合法完成首条双半并提前recycle；任何认证
前流事件也不分配app句柄。若未来启用0RTT、在accept内新增app操作或改vendor回收顺序，此论证失效，必须重新评审。
应用层仍有独立sticky lifetime claim：仅client.open_bi/server.accept_bi，反角色WrongRole，第二次StreamLimit；
网络中违反credit的第二条由QUIC STREAM_LIMIT_ERROR关闭，不映射成成功app流，也不改变旧默认Fabric多流。
测试须首条完整双半free后再试第二条及first-close/reset/未accept先结束路径，并观察max_remote不增，不能只测并发1。

## 5. 128MiB 的限定账本和强制未决项

父草案128MiB是候选 **gateway controlled heap**，本片不硬承诺，既不等于 RSS 也不等于整个 daemon。
T1a 可验证的 payload 小计为 app FIFO 1MiB + QUIC 两方向逻辑窗口4MiB=5MiB/endpoint，
另逐项计 driver scratch、Incoming额外缓存和固定元数据；无 RPC raw body/DTO 的 T1a 不套用父草案29.125MiB小计。
这些数字不是总heap。len、高水位、allocator retained capacity、库外 caller buffer、kernel socket buffer分别标明。

| T1b 必须闭合的 bucket | 当前可用依据 / 仍未证明的部分 |
|---|---|
| assembler/fragment | 窗口限制逻辑 offset；短/gapped/overlap/重复 frame 的节点、保留底层Bytes与compact瞬态必须按确切vendor版本计，不能把MAX_CHUNKS当所有时刻硬界 |
| packet/control | sent packet map、retransmit/ACK/CRYPTO/CID/event和Vec容量；send_window不限制控制包元数据；inline timer表确为每conn10槽/9类，不能把它误列无界，也不能据此推整个conn有界 |
| TLS/identity | quinn crypto reorder cap不限制rustls连续握手/transcript/cert/hs_queue/output及验证前分配；rustls0.23.45单消息payload≤65535不是总heap界；配置64-key allowlist副本和peer_identity证书clone也计入 |
| container/同步 | 固定32+8+1槽、8连接、stream/handle/reply/map/Arc/Mutex/Condvar、错误文本/统计、backing capacity、allocator rounding、所有同时临时副本；失败和最后句柄保留期不能漏算 |
| RPC adapter（后续） | header16KiB/request1MiB/response2MiB只是raw字节；JSON depth/token/node/string/array、重复key拒绝前分配、canonical/DTO/authority-derived clone和受限response encoder均须有ceiling，不能构造整个响应后才检查len |
| 角色与回收 | endpoint总数/每root/两端分别计费、thread/worker堆对象、关闭中/未知资源和受控reaper队列。持久mirror/outbox/log/audit留存仍属D8，不能假设网络有界就把它们算完 |

证据须固定 quinn-proto0.11.18（本地vendor patch）/rustls0.23.45、target/allocator、配置与输入SHA；
为每 bucket 给出 `count × actual retained capacity × simultaneous copies + transient`、分配前permit和归还proof。
public config 无法表达所需界时，明确最小vendor约束候选与独立评审，或保持 BLOCKED；不虚构现有setter。
测量可反证预算并检验压力行为；一次RSS/allocator峰值不证明所有恶意输入硬界。未证明总界时，结论只能是
T1a所列子界已/未验证，不能写“128MiB足够”或启用生产N3 listener。

## 6. 可观察 AC 与合法正负控制（全部待写测试/执行）

每个case记录 endpoint/connection/generation、两侧真实pid/key、phase、cap/current/highwater/retained、
accepted prefix/hash/EOF、绝对起止时刻、close reason、join完成与未回收charge；计数器来自实际分配/队列迁移，
不是verifier合成状态。仅有公开只读固定快照/聚合计数，无per-packet日志、secret/正文或增长历史列表。

| AC | 可证伪的断言及相同phase正控 |
|---|---|
| A1 身份/context | 正确pin+allowlisted双证书，两端raw key一致，私有helper派生原Principal/配置workspace；逐项仅改pin、证书/签名、allowlist、legacy匿名或自称principal，断言无verified context/未认证应用交付=0。错pin不能用空allowlist遮蔽；握手成功后才测context，constructor成功本身不算认证 |
| A2 准入/回收 | 同endpoint并发8条含未认证/未accept/closing/保留句柄，观测各槽真实存活；第9条无新完整QUIC分配或等待队列。释放一个全部引用并完成cleanup后新合法连接成功；顺序10,000次连接/关闭且不accept时，stale q/map不增长、retained回到固定baseline |
| A3 流寿命 | 同一conn首条bidi正常hash+EOF；完成后第二条、同时第二条、provider主动流、uni/datagram分别拒绝，不建额外app状态。换新连接首流仍成功；不能只测concurrent=1 |
| A4 FIFO/credit | 同一合法连接传≥4MiB固定数据（测试分块生成，不库内整包复制）；暂停接收者直到send FIFO达到65536、recv FIFO达到65536，byte cap始终不越界且partial前缀精确。恢复读取后完整SHA/EOF/无重漏；阻塞时cancel/deadline可唤醒，无锁死或静默丢字节 |
| A5 mailbox/control | 32个实际占用槽及对应reply均计费，第33操作立即CapacityUnavailable(Command)，无新waiter/输入复制；大量write仅≤8 Pump bits。满队列同时abort/request_shutdown仍达控制检查，迟Connect已cancel不得建孤儿；generation旧command不能作用新conn |
| A6 时间/公平 | 合法握手/慢读恢复先成功；独立只变为不完成握手、永不EOF、deadline前后持续1-byte/已buffered数据、持续UDP或command洪泛。10/30s后不再成功；量测服务延迟≤500ms与quantum，不以idle timeout或EAGAIN作为结束条件；其他合法连接仍得到轮转 |
| A7 owner | 分别阻塞read/write/accept/open/reply/drain，abort、request_shutdown/shutdown、conn/未完成half/endpoint Drop均按§2唤醒；无网络回复也能终结。支持环境中唯一driver真实Clean join≤5s且释放全部句柄后账本归零才PASS；保留外部句柄须报告原slot charge；Panicked/Incomplete/迟join/未知均BLOCKED，不以subprocess kill或detach充数 |
| A8 内存子界 | cap−1/cap/cap+1及allocator失败、短/gapped/overlap frames/握手洪泛；检查复制前拒绝、retained/copy计数、无stale metadata。TLS/packet等未决项单列UNKNOWN，不能让A8通过输出总heap PASS |
| A9 当前授权helper | 已认证主体与真实当前grant正控后，仅变foreign owner/workspace、无Use、过期、撤销或audit失败，精确AUTH_DENIED/PERSISTENCE_FAILED且零业务dispatch/authority mutation；两主体都有效Use时仍测owner拒绝。测试不构造Task接受/Engine；运行中Revoked stop/reap仍属完整N3依赖 |
| A10 legacy | 原basic/roam/mutual-auth、S4大流finish+EOF、S5/QSEQ、NAT低层调用编译/行为保持；不将旧write改成partial或可靠队列满就drop。原场景期望及source hash不因新profile更换 |

## 7. 正式路径、旧 binary RED、测试评审与 freeze 边界

本次**不实际修改**以下正式路径。候选下一阶段需按顺序提交：

1. `PRODUCT.md` 增补明确“T1a transport前置/禁用N3路由”的范围；
   `crates/nexus-fabric/MODULE.md` 增加精确opaque API、所有profile参数/错误/owner及AC；
   context helper实际归属若在nexusd则同步 `apps/nexusd/MODULE.md`。`crates/nexus-auth/MODULE.md`、
   `crates/nexus-control-api/MODULE.md` 仅在确有新边界时补说明，不改现有constructor为认证器。
   正式 `docs/N3-13A-BOUNDED-MTLS-CONTRACT.md` 为候选目标；ARCHITECTURE现归属原则可复用，若需要新依赖边先正式评审。
2. 新专用 `scenarios/product/fabric-bounded-mtls.toml`（候选id `product.fabric-bounded-mtls`），
   绑定A1–A8/A10、两真实进程和bucket局限；可信context helper的E2/E3单列，不包装成N3 Task命令E4。
   原 `scenarios/product/fabric-mutual-auth.toml`、basic/roam、22个N3场景保持原expectation。
3. **旧真实binary RED**：选定冻结的旧源码摘要与已有/可复现编译的 `mutual_auth_e4` binary，记录SHA/argv/exit/stdout/stderr。
   候选新增独立 `--bounded-json` 模式；旧 main 在 `examples/mutual_auth_e4.rs:327` 严格拒绝该argv，
   可作为入口能力FAIL RED，但不能冒充A2–A8行为RED。旧 `--json` 必须是同环境合法正控，已有mTLS本来可成功，不能改记为红灯。
   若旧binary缺失或环境不可执行，记录实际BLOCKED，不能用静态符号缺失/编译失败声称runtime RED。
4. **可编译测试分片**：R1 用旧现成Fabric API写有界隔离的slow-reader/单流/连续连接/timeout反例测试，
   尝试复现旧write全收/第二条lifetime stream/过期buffer read；测试必须用process/固定次数/超时兜底避免无限内存。
   R2 新opaque API的测试先用仅提供类型/签名且明确失败的stub编译并运行RED；不修改legacy API来凑stub。
   R3 mailbox/slot/generation/quantum/allocator子界白盒或确定性测试；R4 真实两进程transport E4；
   R5 context helper/真实grant适配器E2/E3。每片记录实际FAIL断言和合法正控；没有观测接口的旧行为写BLOCKED，不能fabricate counter。
5. 测试完成而实现未开始时，按 `.agents/skills/nexus-test-review/SKILL.md` 由独立session/子代理盲评：
   只给正式契约、测试和评审标准；覆盖A1–A10、可编译RED、假设错误实现可被捕获、同phase正控。
   §2签名/配置/错误已选定，待转入正式文件；§4有限IO/锁图/回调切批的静态可行性和支持环境/fixture定案、
   实际旧binary RED与测试评审完成后才能生成**分片Contract Hash**；不要求先写生产实现取得GREEN再冻结。
   freeze manifest含PRODUCT/MODULE/正式doc/scenario/test预期与源码SHA，不把本草案SHA当freeze marker。
6. freeze后才实施T1a，按check→affected→Fast→独立八维Review→适用Full取得candidate evidence；
   T1b的每项剩余证明及RPC adapter另有正式契约/RED/评审/hash，不能因T1a验收就跳过。缺任一步不报Final PASS。

未来验证证据绑定revision、既有dirty全量source摘要、contract/profile/binary/toolchain/target/allocator摘要、
两端非secret配置/公钥、故障phase与observer原始输出；真实两进程是transport E4，只有完整真实CLI/服务/qualified
Engine生命周期才可申请N3 Task命令E4，真实两台Windows/Linux独立观察才是E5。

本轮API收敛的阶段边界如下；“未实现”本身不是无法冻结的循环条件：

| 阶段 | 已定案 / 仍须满足的具体条件 |
|---|---|
| 已可精确转写正式契约 | §2全部公开签名/typed errors/固定快照、非Clone和一次split、原key借用、先permit后分配、部分IO错误含进度、唯一endpoint同步reaper、nonblocking Std-only且保持S9、Incomplete保有owner的结果语义 |
| T1a真实freeze前缺口 | F1/F2/F4的锁图/原ring计费/credit时序及已选支持profile须独立复核；F3-B1 TLS连续处理、B2 packet/control扫描、B3析构工作界未闭合。另须正式Product/MODULE/scenario、真实旧binary和可编译测试RED、独立测试盲评及hash；没有生产GREEN不是循环阻塞理由 |
| freeze后验收门禁 | 实现所有冻结期望、编译/测试/Fast/独立Review/适用Full；A7在固定支持环境真实Clean join≤5s且账本清理。未运行/超时/未知不报PASS，不能反过来要求冻结前已有生产GREEN |
| 生产N3路由仍禁用 | T1b剩余crypto/packet/assembler/实际heap等全部适用bounds和owner闭环未核实；128MiB没有已证明承诺；完整Submit的D5/D6/D9及其他依赖仍保持§1，不被T1a候选API豁免 |

原草案准备证据在 ignored `.evidence/n313-t1-contract-resume19/`；首轮API收敛及ee0a源码快照保留于
`.evidence/n313-api-refine19/`；本轮只编辑本DRAFT并新增其`r2/`输入前后SHA/精确diff/结论，不覆盖首轮。
父草案与正式契约/源码守卫保持；
不运行cargo、网络、Docker、Engine、Harness，不写Stub/实现，不freeze/commit/push。

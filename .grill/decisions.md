# #7 Flow-session — 待拍板问题（grill 已直接决定）

用户全权委托，以下影响走向的问题由 grill 直接定，理由附后。
contract-review 若推翻任一条，需给出推翻理由并回写本文件。

## D1. 新代码落点：`nexus-projection` 新模块（不建新 crate、不进 nexus-fabric）

**决定**：在 `nexus-projection` 内新增 `flow_session` 模块（模块名 develop 可改）。

**理由**：
- 所有集成点都在 projection：`PathLink`（选路+rebind+D1）、`PunchManager`
  （D5 分流）、`FabricTransport`（datagram pump 分流点）、peer 名↔PeerId
  边界映射。
- `nexus-fabric/MODULE.md` 明确"不做路径选择""不做 TUN 投影"——注册表
  （dial 选路）进 fabric 会违反其非职责。
- 新 crate 无独立变化维度（删除测试：删掉它，上层直接调 projection 现有
  件仍能拼出同样功能，只是散落）——不成立新 crate。

## D2. 不动 TUN 数据面线格式（STREAM-over-datagram 保持现状）

**决定**：TUN TCP 中继继续走现有 STREAM 帧（SYN/FIN/RST over best-effort
datagram），#7 不做数据面切换。

**理由**：
- 可靠性已由两端 TCP 栈提供（smoltcp 本地终结 + TcpEgress 重发起，
  丢包由 TCP 重传覆盖）——"文件传输不中断"的关键场景已被覆盖。
- 换线格式 = 双端 lockstep 升级 + 新协议验证，超出"只做启用/接线"范围，
  风险/收益比不成立。如未来要切，应独立立项。

## D3. 流服务分发键：复用 wireup"首帧类型字节"约定，不引入新帧头

**决定**：`register_stream_service(type_byte, handler)`；远端开流后首字节
即服务类型；打洞信令流沿用现有类型字节，与新服务共存。

**理由**：D5 契约已证明该约定可行（responder 按首字节路由、peek 不消费）；
新帧头 = 新协议设计，违反范围约束。

## D4. 上层数据报通道：占用 intent 类型位 `0x03`（SERVICE），bit2-5 后跟服务子 id

**决定**：`0x00/0x01/0x02` 线兼容不动；`0x03` 为上层服务保留，
第二字节为服务子 id。

**理由**：intent 首字节 bit0-1 中 `0b11` 是唯一空闲类型位（`lib.rs:58-63`），
天然扩展点；hop 位（bit2-5）语义保留，未来服务包也可计跳。

## D5. 数据报分流点：在现有 pump 线程内按 intent 分流（不另起消费者）

**决定**：`FabricTransport` 的每 conn pump 在 `recv_datagram` 后直接按首字节
分流进 TUN 收件箱或服务 handler。

**理由**：`recv_datagram` 是阻塞独占队列；另起消费者会竞争/丢包。
单泵内分流是唯一不改变并发语义的方案。

## D6. 注册表键用 `PeerId`，`String` peer 名不出新 API

**决定**：`FlowSessionHub` 所有方法以 `PeerId`（ed25519）为键；
`String` 名只留在 projection 边界（配置/日志/展示）。

**理由**：fabric 层身份已是 `(PeerId, ConnectionId)`（S2）；上层再发明
一套 String 身体会造成双身份映射 bug（D5  responder 用 conn id、
PathLink 用名，已是两套，够多了）。

## D7. 背压 P0 不实现，用"256 KiB 单次写入上界 + 文档"代替

**决定**：不改造 driver 加背压；`SendStream::write` 单次 > 256 KiB 返回
`TooLarge`；Hub 文档强制分块写入。

**理由**：driver 背压 = quinn-proto 流控接线 + API 语义变更（`write` 从
"立即返回"变"可阻塞"），是协议层改动，超出"接线"范围；
256 KiB 上界把最坏内存占用量化、可测（AC11），足够 P0。

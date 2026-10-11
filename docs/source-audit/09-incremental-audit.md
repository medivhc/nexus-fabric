# 09 · 增量审计：e6ccf8b..d50d8fe（53 个提交）

> 本文仅依据仓库源码与机器配置（.rs/Cargo.toml/*.toml）撰写，未采信任何叙述性文档；结论行号均可复核。
>
> 审计范围：HEAD 从 `e6ccf8b` 推进到 `d50d8fe` 之间的 53 个提交，其中 Rust 增量为 59 个文件、+16,062/-200 行。本文是自包含增量文档，与 00–08 配套阅读；对 e6ccf8b 基线的结论不重复展开。

---

## 1. 增量总览

| 主题 | 增量行数 | 落地位置 | 实现度判定 |
|---|---|---|---|
| nexus-web-gateway（新 crate） | +5,335 | crates/nexus-web-gateway/ | **partial**（实现完整、生产零依赖） |
| Code Intelligence API | +4,656 | engineering/nexus-harness/src/code_intel/ + fixtures | **implemented** |
| bootstrap-join 自动入网 | +3,835（connectivity 3,330 + discovery 505） | crates/nexus-connectivity + nexus-discovery | **implemented**（subnet CLI 路径） |
| bootstrap 组合根 codec + CLI 接线 | +2,231 | apps/nexus（bootstrap_codec.rs + subnet_cli.rs + lib.rs） | **implemented** |
| apps/nexusd 接线 | +5/-1 | apps/nexusd/ | implemented（微） |
| CI / dashboard 静态页 / 文档脱敏 | 非 .rs | .github/、dashboard 静态资源 | —（不计入代码审计） |

整体判断：本轮增量是**三个相对独立、质量较高的新子系统**——其中两个已在真实命令路径上接线，一个完整实现但尚未挂进任何生产二进制。没有出现上一轮基线中那种"硬编码演示数据冒充实现"的 stub 模式；风险集中在 web-gateway 的证书校验策略与 REQ-003 流程事故。

---

## 2. nexus-web-gateway（新 crate）

### 2.1 实际职责

浏览器零安装访问 mesh：每个节点内嵌一个 HTTPS 服务（页面 + WSS signaling）加节点侧 WebRTC 端点。浏览器打开 `https://<node>/`，内存生成临时身份，经 WSS + RTCPeerConnection/DataChannel 接入首节点，收到 mesh 节点列表后通过已建立的 mesh 中继 SDP offer 直连其他节点（不依赖外部 signaling 服务）。MVP 服务是 web SSH 终端：浏览器 DataChannel → 目标节点 → 本地 sshd 的 TCP 转发（`crates/nexus-web-gateway/src/lib.rs:1-15`）。

crate 为 std-only、无 async runtime，`#![forbid(unsafe_code)]`（lib.rs:17）。

### 2.2 组件与规模（src 共 3,546 行）

| 文件 | 行数 | 职责 |
|---|---|---|
| gateway.rs | 1,609 | 事件循环、HTTP 路由、WSS 升级、SSH bridge 装箱与 worker 线程 |
| mesh.rs | 442 | InMemoryMeshSignaler、WssMeshSignaler、MeshDataConnection、TLS 连接器 |
| config.rs | 425 | GatewayConfig/IceServer/MeshNodeInfo/SshConfig/TlsConfig |
| cert.rs | 267 | 自签 CA 与节点证书签发 |
| protocol.rs | 287 | BrowserMessage/NodeMessage/SdpPayload/SshAuth 线协议 |
| http.rs | 245 | 静态资源查找表（lookup_asset:181） |
| ssh_client.rs | 177 | SSH 握手/认证 worker |

### 2.3 已实现的安全边界

- `/mesh` 端点 bearer-token 保护：取 `authorization` 头与 `mesh.local_token()` 比较，不匹配即拒（gateway.rs:398-403）；比较为 constant-time（gateway.rs:1391）。
- TLS 由自签 CA 签发节点证书（cert.rs）。

### 2.4 风险点

1. **PermissiveVerifier 无条件信任所有服务端证书**（mesh.rs:224-238）：`verify_server_cert` 直接返回 `Ok(ServerCertVerified::assertion())`，不校验证书链与主机名；仅保留 TLS1.2/1.3 签名校验。即节点间 WSS 互联时不做证书认证，安全性完全依赖"mesh 内网络可达即可信"的假设。设计注释自承 Permissive，但文档（lib.rs:1-15）未向部署者说明这一信任边界。
2. **REQ-003 access authentication 被 revert**：提交 `a95a989` revert 了 `66b6b78`，理由是后者跳过强制 P0 联合评审直接合入 master（commit message："user rule 2026-10-10: REQ-001/002/003 must be reviewed together before implementation starts"），共删 89 行（config.rs 7 / gateway.rs 80 / e2e 2）。当前代码库中除 bearer token 外没有浏览器侧访问认证；该功能需经联合评审后重新实现。

### 2.5 接线状态（关键）

```
grep "nexus-web-gateway" --include=Cargo.toml
  → 仅命中根 Cargo.toml:54（workspace members 清单）与 crate 自身
```

- **没有任何生产二进制依赖 nexus-web-gateway**（apps/nexus 与 apps/nexusd 的 Cargo.toml 均未声明）。
- `Gateway::start` 的唯一非测试调用点是 `crates/nexus-web-gateway/examples/gateway.rs`。
- 测试覆盖良好：20 个 gateway_e2e.rs 端到端用例 + 22 个单测（cert 2 / config 14 / protocol 6）。

**判定：partial**。实现完整、测试充分，但尚未接入生产组装根——属于"可运行 example、未上线服务"状态。

---

## 3. bootstrap-join 自动入网

### 3.1 架构（与上一轮审计的红线一致）

connectivity 不依赖 discovery：外层 `nxb:` 握手帧与内层 `AutoDiscoveryFrame` 的字节编解码抽象为 `BootstrapFrameCodec` trait（bootstrap_server.rs:1-12 注释自陈），具体实现在组合根注入。

- `crates/nexus-connectivity/src/bootstrap_server.rs`（约 1,000 行）：服务端纯逻辑——PSK 会话认证、权威 node_id 派生、VIP 权威分配、复用 Coordinator 在线目录、半开有界防护。全部同步、无 tokio、时钟由 `now_secs` 注入（bootstrap_server.rs:12-16）。
- `crates/nexus-connectivity/src/bootstrap_joiner.rs`：客户端 `BootstrapJoiner` 顺序走 PSK 握手（JoinInit→JoinReply→派生会话密钥→加密 Register→RegisterAck→GetPeers→PeerList），交接 `BootstrapSession`（joiner.rs:1-12）。
- `crates/nexus-discovery/src/bootstrap_join.rs`：字节层——`nxb:` magic（`0x6E 0x78 0x62 0x3A`）与数据面 `0x4E`/`0x68`/`0x70`/`0x01`/明文头两两互斥做确定性分流；Plain 帧（tag 0x10/0x11/0x12，仅 X25519 公钥）与 Secured 密文（首字节探针 == 0x01，长度 ≥38B）显式区分，明确禁止"未知 tag 当密文"的 fallback（bootstrap_join.rs:1-30）。
- `apps/nexus/src/bootstrap_codec.rs`：组合根 `DiscoveryBootstrapCodec` 把 connectivity 解耦类型映射到 discovery 字节格式（与 DiscoveryFibResolver 同构）。

### 3.2 防护参数（真实生效）

- 全局 pending 上限 1024；每 src 60 秒窗口 10 次 JoinInit 速率；pending 握手 TTL 10 秒，到期摘除并回收预分配 VIP（bootstrap_server.rs:24-32）。

### 3.3 分流与生产接线（已核实）

- 分流点已接进数据面：`virtual_subnet.rs:1516-1517` 收到报文先 `strip_prefix(b"nxb:")`，命中即交 bootstrap hook，不进数据管线/不试解密；隧道入口 `:3266-3273` 同样截获。
- hook trait：`BootstrapHook::on_control_datagram` + `periodic`（virtual_subnet.rs:463-490），setter `set_bootstrap_hook`（:605）。
- **生产调用方存在**：`apps/nexus/src/subnet_cli.rs:760-1011` 组装 `ClientBootstrapHook`（:783）并 `tunnel.set_bootstrap_hook(Some(h))`（:889）；服务端 `ServerBootstrapHook` 在 :1011 路径返回。即 bootstrap-join 是 subnet 子命令驱动的真实入网流程，不是死代码。

**判定：implemented**。架构解耦干净、防护参数齐全、CLI 路径接线真实。尚未看到 daemon 常驻进程自动发起入网（joiner 由 CLI 命令驱动），属预期 MVP 形态而非缺口。

---

## 4. Code Intelligence API（harness）

### 4.1 接线

`engineering/nexus-harness/src/main.rs:71`：`"code" => code_intel::run(rest)`——真命令入口。

### 4.2 分层（src 4,022 行）

| 文件 | 行数 | 职责 |
|---|---|---|
| rust_analyzer.rs | 1,463 | LSP 子进程驱动 provider |
| lsp.rs | 998 | JSON-RPC over stdin/stdout |
| mod.rs | 858 | CLI 参数解析、作用域校验、预算裁剪、snapshot 绑定、envelope 拼装 |
| dto.rs | 376 | Budget/CodeIntelError/Failure/ProviderMeta/ResultItem |
| provider.rs | 327 | CodeIntelligenceProvider trait |

### 4.3 边界纪律（代码事实）

- 输出恒带 `authority = "advisory"`，本层不产最终 PASS 权；correctness 仍归 cargo check/clippy/test（mod.rs:5-12）。
- 查询目标在**启动 provider 子进程之前**完成解析与存在性校验，参数错误必须 QUERY_INVALID/FAIL，不允许先起子进程再失败（mod.rs:42-58）。
- 配套场景 `scenarios/engineering/code_intel_write_method_denied.toml`（写方法被拒）。

测试：53 个新测试（mod 17 / lsp 13 / rust_analyzer 11 / dto 6 / provider 6）。

**判定：implemented**。

---

## 5. 对既有审计结论的影响

- 工作区成员数：48 → **49 crates**（新增 nexus-web-gateway）；06 矩阵需补一行（partial）。
- 上一轮"已实现但生产未接线"清单新增一项：nexus-web-gateway（同模式，但测试覆盖好得多，属"待挂线"而非"被遗忘"）。
- 上一轮"多 agent 协作纪律"在本轮有真实案例：REQ-003 跳过 P0 联合评审被 revert——门禁/流程规则在实际起作用。

## 6. 本轮增量的注释与文档问题

- **未发现 high 级注释错误**。
- 一处值得记录的设计偏差（非注释错误）：mesh.rs `PermissiveVerifier` 自承宽松，但 lib.rs 顶部文档（lib.rs:1-15）向读者描述 WebRTC/mesh 接入流程时未提示"节点间 WSS 不校验证书"这一信任假设；部署者需要读 mesh.rs:224 才知道。
- 行为提醒：REQ-003 revert 提交本身是干净的流程纠正，无残留死代码（revert 后 gateway.rs 无悬空调用）。

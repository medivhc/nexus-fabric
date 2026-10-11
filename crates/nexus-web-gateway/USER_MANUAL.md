# Nexus Web Gateway 用户手册

Nexus Web Gateway 是每台 Nexus 节点内嵌的零安装浏览器接入点：打开一个 HTTPS 页面，
浏览器自动生成临时身份加入 mesh，在网页里直接打开节点上的 SSH 终端（真实 SSH
协议只发生在节点与 sshd 之间，浏览器 ↔ 节点之间只传终端字节流）。

## 快速开始

### 1. 准备配置

复制随仓示例配置，改成你的环境：

```bash
cp crates/nexus-web-gateway/examples/gateway.example.json gateway.json
```

需要改动的字段：

| 字段 | 该填什么 |
|---|---|
| `listen_addr` | 网关监听的 HTTPS 地址。填 `"0.0.0.0:8443"` 会监听所有网卡，网关自动挑选一个可路由的网卡 IP 用于 WebRTC；也可以直接填你机器的局域网 IP，如 `"192.168.1.10:8443"`。**不要填 `"127.0.0.1"`**——真实浏览器不会采集 loopback 的 ICE 候选，填了会导致页面永远连不上。 |
| `node_list[].addrs` | 各节点的地址展示（仅展示用）。把示例里的 `10.144.144.x` 换成你机器的实际 IP。 |
| `tls.ips` | 生成自签证书时写入的 IP SAN。把示例里的 `10.144.144.1` 换成你机器的实际 IP，浏览器安装本地 CA 后证书才能完全匹配。 |
| `ssh.target` | 本节点上要连接的 sshd 地址，例如 `"127.0.0.1:22"`。 |
| `mesh.peers` | 第二个节点的 `url` 换成第二台机器的实际 IP。只有单节点时可以把 `peers` 留空。 |

### 2. 启动

```bash
cargo run -p nexus-web-gateway --example gateway -- ./gateway.json
```

启动后会打印类似：

```
Page: https://192.168.1.10:8443/  (download the local CA at https://192.168.1.10:8443/cert ...)
```

如果 `listen_addr` 填了 `0.0.0.0`，启动日志会额外打印一行
`note: listen_addr is unspecified; binding the WebRTC UDP socket to <IP> ...`，
告诉浏览器实际使用的 ICE 地址。若打印的是
`warning: no non-loopback network interface found ...`，说明机器没有可路由网卡，
浏览器将无法连接，必须把 `listen_addr` 改成具体 IP。

### 3. 安装本地 CA 证书

网关使用持久自签根证书（重启不变）。首次打开页面时浏览器会警告证书不受信任：

- 临时访问：点“高级 → 继续前往”。
- 彻底消除警告：打开 `https://<你的网关地址>:<端口>/cert` 下载 `nexus-ca.pem`，
  导入操作系统/浏览器的“受信任的根证书颁发机构”，重启浏览器。

### 4. 使用

打开 `https://<你的网关地址>:<端口>/`：

1. 页面自动加入 mesh，显示节点列表。
2. 点节点的 **Terminal** 按钮。
3. 填写用户名和密码（或粘贴 OpenSSH 私钥）。
4. 连接后即可执行命令；关闭页面即断开，凭证不落盘。

## 配置字段说明

### `listen_addr`

HTTPS/WSS 监听地址，同时决定 WebRTC UDP socket 绑定的 IP。

- `"0.0.0.0:8443"`：监听所有网卡。网关用 `getifaddrs` 枚举本机网卡，挑选第一个
  非 loopback 的 IPv4 地址作为 ICE 主机候选，因此浏览器可以直连。
- 具体 IP，如 `"192.168.1.10:8443"`：网关把 HTTPS 和 WebRTC UDP 都绑定到该 IP。
- ⚠️ `"127.0.0.1"`：**真实浏览器无法使用**（浏览器不采集 loopback ICE 候选）。
  仅用于仓库自动化测试（str0m 测试客户端会采集 loopback 候选）。

### `node_list`

浏览器看到的 mesh 节点清单。每个条目：

- `peer_id`：节点稳定标识（本网关用字符串 id；生产可换 ed25519 公钥 hex）。
- `name`：展示名。
- `addrs`：候选地址，仅用于展示，不参与实际建连路径。
- `services`：服务目录，当前为 `["ssh"]`。

### `ice_servers` 与 TURN

`ice_servers` 是下发给浏览器的 ICE 服务器列表：

- `stun:` 帮助浏览器在 NAT 后收集公网映射地址（srflx）。默认
  `stun:stun.l.google.com:19302`。
- `turn:` 提供中继候选。只有浏览器与网关之间存在对称 NAT、打洞失败时才需要。
  示例默认不配 TURN；如需要，填可用的 TURN 服务器：

  ```json
  {
    "urls": ["turn:turn.example.com:3478"],
    "username": "user",
    "credential": "pass"
  }
  ```

### 中继语义（relay）

- 浏览器与**第一个节点**（首触节点）之间必须能建立 ICE 直连。
- 对其他节点：浏览器先尝试与目标节点直连；若打洞失败（如目标节点在严格 NAT 后），
  SSH 终端会自动经首触节点 + mesh 中继转发，不需要额外配置。
- 中继路径的终端延时会高于直连，但功能一致。若页面提示
  “direct failed — terminal uses relay”，说明该节点正在使用中继。

### `mesh`

`mesh.mode: "wss"` 表示通过各节点网关的 `/mesh` WSS 端点中继信令。

- `token`：本地 `/mesh` 端点要求对端携带的 bearer token。
- `peers`：要连接的其他网关，每个含 `peer_id`、`url`（`wss://主机:端口/mesh`）、
  `token`（对端网关的 token）。

多节点部署时，每个节点的 `node_list` 应包含全部节点。

### `ssh`

- `target`：本节点上要连接的 sshd 地址（`127.0.0.1:22`）。
- `max_terminals`：每个浏览器会话同时打开的终端上限。
- `idle_timeout_secs`：终端空闲多少秒后自动断开。

## 常见问题

- **页面一直停在 “P2P ICE 失败”**：先看 `listen_addr`。网关只通告**自己的 UDP socket
  真能收包**的地址（G11）：`listen_addr=127.0.0.1` 时只通告 loopback（本机测试可用，
  远程浏览器连不上）；`listen_addr=<某网卡IP>` 时只通告那个 IP；要让局域网/网格都能连，
  填 `0.0.0.0`（绑通配地址并通告全部可路由网卡）或直接填那块网卡的 IP。
  确认访问的是 `https://<可路由IP>:<端口>/` 而不是 `https://0.0.0.0:.../`；
  启动日志出现 “`listen_addr` is unspecified and no non-loopback network interface was found”
  说明这台机器根本没有可路由网卡，必须改网络或换节点。
- **浏览器证书警告**：下载 `/cert` 安装本地 CA，并把机器 IP 加入 `tls.ips`
  后重新启动网关（证书会重新生成并持久化）。
- **节点列表为空**：访问地址的 host 必须是网关所在机器的可路由 IP；`0.0.0.0`
  不是可访问的地址。
- **弱网抖动后页面提示“网络波动”**：这是心跳暂时中断的提示。数据通道若仍正常，
  网络恢复后提示会自动消失，无需手动重连。
//! Auto-Mesh Controller（自动挡组网编排器）
//!
//! Phase 1：静态 peer 自动打洞 + 断线自动重连。
//!
//! 本模块是 Composition Root 层（apps/nexus/src/），持有 VirtualSubnetTunnel，
//! 在主循环中驱动：
//!
//! ```text
//!   轮询 recv_and_deliver（收包/处理打洞帧/握手帧）
//!     ↓
//!   对所有 Disconnected/Probing peer 自动发起打洞
//!     ↓
//!   打洞失败 → ReconnectController 指数退避
//!     ↓
//!   到退避时间 → 自动重试打洞
//!     ↓
//!   Connected peer → 定期健康检查（事件流监控）
//! ```
//!
//! 遵循 AGENTS.md §13 结构化并发：本控制器是 Owner，持有隧道；
//! 收到停止信号时循环退出，drop 隧道时自动清理 TUN + UDP socket。

use std::collections::HashMap;
use std::time::{Duration, Instant};

use nexus_connectivity::reconnect::{ReconnectConfig, ReconnectController};
use nexus_connectivity::virtual_subnet::{TunnelPeer, TunnelState, VirtualSubnetTunnel};
use serde_json::{Value, json};

/// 每 peer 的自动维护状态。
struct PeerAutoState {
    /// 静态配置的物理 locator（可能为空，等 Discovery 填充——Phase 2）。
    static_locator: Option<String>,
    /// 重连控制器（指数退避）。
    reconnect: ReconnectController,
    /// 上次打洞/状态变更的时间点。
    last_event_instant: Instant,
    /// 连续 ping 失败次数（Phase 1 简化：用事件流判断，不发真实 ICMP）。
    consecutive_failures: u32,
    /// 是否正在打洞。
    punching: bool,
}

impl PeerAutoState {
    fn new(locator: Option<String>) -> Self {
        // Phase 1 重连配置：1s 起步，指数 2x，上限 60s，无限重试。
        let cfg = ReconnectConfig::new(
            u32::MAX, // max_retries = 无限
            Duration::from_millis(1000),
            Duration::from_secs(60),
            2.0,
        )
        .expect("valid reconnect config");
        Self {
            static_locator: locator,
            reconnect: ReconnectController::new(cfg),
            last_event_instant: Instant::now(),
            consecutive_failures: 0,
            punching: false,
        }
    }

    /// 是否需要尝试打洞（Disconnected 且退避已到）。
    fn should_attempt_punch(&self, tunnel_state: TunnelState) -> bool {
        match tunnel_state {
            TunnelState::Disconnected => {
                // 初始就立即尝试（不等待退避）
                !self.punching
            }
            TunnelState::Failed => {
                // 失败状态：退避到期才重试
                !self.punching && self.reconnect.is_due(now_duration())
            }
            TunnelState::Probing => {
                // 正在打洞中，不重复
                false
            }
            TunnelState::Connected => {
                // 已连接，不需要打洞
                false
            }
            TunnelState::Handshaking => {
                // 握手进行中
                false
            }
        }
    }

    /// 标记打洞开始。
    fn mark_punch_started(&mut self) {
        self.punching = true;
        self.last_event_instant = Instant::now();
    }

    /// 打洞成功。
    fn mark_punch_success(&mut self) {
        self.punching = false;
        self.consecutive_failures = 0;
        self.last_event_instant = Instant::now();
        self.reconnect.on_success(now_duration());
    }

    /// 打洞失败。
    fn mark_punch_failed(&mut self) {
        self.punching = false;
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.last_event_instant = Instant::now();
        self.reconnect.on_attempt_failed(now_duration());
    }

    /// 断线事件。
    fn mark_disconnected(&mut self) {
        self.consecutive_failures = 0;
        self.reconnect.on_disconnect(now_duration());
        self.last_event_instant = Instant::now();
    }
}

/// Auto-Mesh 编排控制器。
///
/// 持有隧道和所有 peer 的自动维护状态，驱动主循环。
pub struct AutoMeshController {
    /// 隧道（Owner）。
    tunnel: VirtualSubnetTunnel,
    /// 每 peer 自动维护状态。
    peers: HashMap<String, PeerAutoState>,
    /// 主循环 tick 间隔。
    tick_interval: Duration,
    /// LAN 组播发现器（可选，None = 纯静态 peer 模式）。
    lan_discovery: Option<LanDiscovery>,
    /// WAN Bootstrap 客户端（可选，None = 不走 bootstrap）。
    bootstrap: Option<BootstrapClient>,
    /// 是否已停止。
    stopped: bool,
    /// 已消费事件游标（增量消费）。
    last_event_index: usize,
}

/// 当前相对 Duration（从 start 起算），用于 ReconnectController。
fn now_duration() -> Duration {
    // 用全局 Instant::now() 即可（ReconnectController 只要求单调）。
    // 这里用一个静态基准点。
    use std::sync::OnceLock;
    static BASE: OnceLock<Instant> = OnceLock::new();
    BASE.get_or_init(Instant::now).elapsed()
}

impl AutoMeshController {
    /// 从隧道创建控制器（纯静态 peer 模式，不启用 LAN 组播发现）。
    pub fn new(tunnel: VirtualSubnetTunnel, tick_interval_ms: u64) -> Self {
        Self::new_with_options(tunnel, tick_interval_ms, None, None)
    }

    /// 从隧道创建控制器，可选启用 LAN 组播自动发现。
    pub fn new_with_lan(
        tunnel: VirtualSubnetTunnel,
        tick_interval_ms: u64,
        lan_config: Option<LanDiscoveryConfig>,
    ) -> Self {
        Self::new_with_options(tunnel, tick_interval_ms, lan_config, None)
    }

    /// 从隧道创建控制器，可选启用 LAN 组播自动发现。
    ///
    /// 注意：assemble_with 把所有 peer 初始标记为 Connected（mock 行为），
    /// AutoMeshController 创建后会把它们重置为 Disconnected，由自动打洞来连接。
    pub fn new_with_options(
        mut tunnel: VirtualSubnetTunnel,
        tick_interval_ms: u64,
        lan_config: Option<LanDiscoveryConfig>,
        bootstrap_config: Option<BootstrapConfig>,
    ) -> Self {
        // 从隧道里读取所有 peer 的 virtual_ip 和 locator
        let peer_list: Vec<(String, Option<String>)> = tunnel
            .peers()
            .iter()
            .map(|(vip, _state)| {
                let vip = vip.to_string();
                let locator = tunnel.peer_locator(&vip);
                (vip, locator)
            })
            .collect();

        let mut peer_map = HashMap::new();
        for (vip, locator) in peer_list {
            // 重置为 Disconnected，让自动打洞来连接
            tunnel.set_peer_state(&vip, TunnelState::Disconnected);
            peer_map.insert(vip.clone(), PeerAutoState::new(locator));
        }
        let lan_discovery = lan_config.map(LanDiscovery::new);
        let bootstrap = bootstrap_config.map(BootstrapClient::new);
        Self {
            tunnel,
            peers: peer_map,
            tick_interval: Duration::from_millis(tick_interval_ms),
            lan_discovery,
            bootstrap,
            stopped: false,
            last_event_index: 0,
        }
    }

    /// 主运行循环。
    ///
    /// 每 tick：
    /// 1. 轮询 recv_and_deliver（非阻塞收包）
    /// 2. 检查所有 peer 状态，对需要打洞的自动发起
    /// 3. 处理打洞结果事件
    /// 4. 检查停止信号（state 文件被删除）
    /// 5. 定期保存状态（如果指定了 save_path）
    pub fn run<F: Fn() -> bool>(&mut self, should_stop: F) {
        self.run_with_save(should_stop, None)
    }

    /// 主运行循环（带状态持久化）。
    pub fn run_with_save<F: Fn() -> bool>(&mut self, should_stop: F, save_path: Option<PathBuf>) {
        let mut buf = [0u8; 65535];
        let mut tick_count: u64 = 0;
        let save_interval_ticks = (10_000 / self.tick_interval.as_millis() as u64).max(1); // 每 10 秒保存一次

        while !self.stopped && !should_stop() {
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            // 1. 轮询收包（非阻塞）
            match self.tunnel.recv_and_deliver(&mut buf, now_secs) {
                Ok(Some((src, n))) => {
                    // 收到数据，对应 peer 是活跃的
                    if let Some(peer) = self.peers.get_mut(&src) {
                        peer.consecutive_failures = 0;
                        peer.last_event_instant = Instant::now();
                    }
                    let _ = n; // 数据已交付给 VPI
                }
                Ok(None) => {
                    // 无数据，正常继续
                }
                Err(e) => {
                    eprintln!("[auto-mesh] recv error: {e}");
                }
            }

            // 2. LAN 组播发现（如果启用）
            if let Some(discovery) = &mut self.lan_discovery {
                let new_peers = discovery.tick();
                for (vip, locator) in new_peers {
                    self.add_discovered_peer(&vip, &locator);
                }
            }

            // 2b. WAN Bootstrap（如果启用）
            if let Some(bootstrap) = &mut self.bootstrap {
                let new_peers = bootstrap.tick();
                for (vip, locator) in new_peers {
                    self.add_discovered_peer(&vip, &locator);
                }
            }

            // 2c. Bootstrap 常驻会话 tick（v2 §6.4）：心跳/刷新/sweep 出站经隧道 send_raw，
            //     新发现 peer 交回打洞。未挂载 hook 时为 no-op。
            let bt = self.tunnel.bootstrap_tick(now_secs);
            for p in bt.peers_added {
                self.add_discovered_peer(&p.virtual_ip, &p.locator);
            }
            // W-GONE：peer 从最新 PeerList 消失 → 降级（不删除隧道 peer）。
            for gone in bt.peers_gone {
                eprintln!("bootstrap: peer {gone} degraded (absent from PeerList)");
            }
            for ev in bt.events {
                eprintln!("bootstrap: {ev}");
            }

            // 3. 检查所有 peer，自动打洞
            self.drive_punches();

            // 4. 检查打洞结果事件
            self.consume_punch_events();

            // 5. 定期保存状态
            tick_count += 1;
            if tick_count % save_interval_ticks == 0 {
                if let Some(ref path) = save_path {
                    self.save_state(path);
                }
            }

            // 6. sleep
            std::thread::sleep(self.tick_interval);
        }

        // 退出前最后保存一次
        if let Some(ref path) = save_path {
            self.save_state(path);
        }
    }

    /// 停止控制器。
    pub fn stop(&mut self) {
        self.stopped = true;
    }

    /// 检查所有 peer，对需要的自动发起打洞。
    fn drive_punches(&mut self) {
        let mut to_punch: Vec<(String, String)> = Vec::new();

        // 先收集需要打洞的 peer（避免借用冲突）
        let peer_vips: Vec<String> = self.peers.keys().cloned().collect();
        for vip in &peer_vips {
            let tunnel_state = self.tunnel.peer_state(vip);
            let needs_punch = match tunnel_state {
                Some(state) => {
                    if let Some(peer) = self.peers.get(vip) {
                        peer.should_attempt_punch(state)
                    } else {
                        false
                    }
                }
                None => true, // 隧道里还没这个 peer，需要 add_peer
            };

            if needs_punch {
                let locator = self.peers.get(vip).and_then(|p| p.static_locator.clone());
                if let Some(loc) = locator {
                    to_punch.push((vip.clone(), loc));
                }
            }
        }

        // 执行打洞
        for (vip, loc) in to_punch {
            // 如果隧道里还没这个 peer，先注册
            if self.tunnel.peer_state(&vip).is_none() {
                let peer = TunnelPeer::new(&vip, &loc);
                if let Err(e) = self.tunnel.add_peer(peer) {
                    eprintln!("[auto-mesh] add_peer {vip} failed: {e}");
                    continue;
                }
            }

            // 标记打洞开始
            if let Some(peer) = self.peers.get_mut(&vip) {
                peer.mark_punch_started();
            }

            // 检查是否该走 Relay 回退（连续失败 >= 3 次）
            let should_fallback_relay = self
                .peers
                .get(&vip)
                .map(|p| p.consecutive_failures >= 3)
                .unwrap_or(false);

            if should_fallback_relay {
                // 查有没有配置 relay locator
                if let Some(relay) = self.tunnel.relay_locator(&vip) {
                    eprintln!(
                        "[auto-mesh] punch failed 3x for {vip}, falling back to relay: {relay}"
                    );
                    if let Err(e) = self.tunnel.fallback_to_relay(&vip, &relay) {
                        eprintln!("[auto-mesh] relay fallback {vip} failed: {e}");
                        if let Some(peer) = self.peers.get_mut(&vip) {
                            peer.mark_punch_failed();
                        }
                    } else if let Some(peer) = self.peers.get_mut(&vip) {
                        peer.mark_punch_success();
                    }
                    continue;
                }
            }

            // 发起打洞
            let targets = vec![loc];
            match self.tunnel.begin_hole_punch_multi(&vip, &targets) {
                Ok(()) => {
                    eprintln!("[auto-mesh] punching {vip} via {:?}", targets[0]);
                }
                Err(e) => {
                    eprintln!("[auto-mesh] punch start {vip} failed: {e}");
                    if let Some(peer) = self.peers.get_mut(&vip) {
                        peer.mark_punch_failed();
                    }
                }
            }
        }
    }

    /// 消费隧道事件流，更新 peer 状态（按游标增量消费）。
    fn consume_punch_events(&mut self) {
        let events = self.tunnel.events();
        if self.last_event_index >= events.len() {
            return;
        }
        let new_events = &events[self.last_event_index..];

        for event in new_events {
            use nexus_connectivity::virtual_subnet::VirtualSubnetEvent;
            match event {
                VirtualSubnetEvent::HolePunchSucceeded { peer_vip, .. } => {
                    eprintln!("[auto-mesh] punch SUCCESS: {peer_vip}");
                    if let Some(peer) = self.peers.get_mut(peer_vip) {
                        peer.mark_punch_success();
                    }
                }
                VirtualSubnetEvent::HolePunchFailed { peer_vip, .. } => {
                    eprintln!("[auto-mesh] punch FAILED: {peer_vip}");
                    if let Some(peer) = self.peers.get_mut(peer_vip) {
                        peer.mark_punch_failed();
                    }
                }
                VirtualSubnetEvent::PeerStateChanged {
                    peer_id,
                    new_state: TunnelState::Disconnected,
                    ..
                } => {
                    if let Some(peer) = self.peers.get_mut(peer_id) {
                        peer.mark_disconnected();
                    }
                }
                _ => {}
            }
        }
        self.last_event_index = events.len();
    }

    /// 生成当前所有 peer 的状态快照（供 status 输出）。
    pub fn snapshot(&self) -> Value {
        let peers: Vec<Value> = self
            .peers
            .iter()
            .map(|(vip, p)| {
                let tunnel_state = self.tunnel.peer_state(vip);
                let state_str = match tunnel_state {
                    Some(TunnelState::Connected) => "Connected",
                    Some(TunnelState::Probing) => "Probing",
                    Some(TunnelState::Handshaking) => "Handshaking",
                    Some(TunnelState::Failed) => "Failed",
                    Some(TunnelState::Disconnected) => "Disconnected",
                    None => "Unknown",
                };

                let stats = self.tunnel.peer_stats(vip);
                let (bytes_tx, bytes_rx) = stats
                    .map(|s| (s.bytes_sent, s.bytes_received))
                    .unwrap_or((0, 0));

                json!({
                    "virtual_ip": vip,
                    "state": state_str,
                    "locator": p.static_locator,
                    "reconnect_attempts": p.reconnect_state_str(),
                    "bytes_tx": bytes_tx,
                    "bytes_rx": bytes_rx,
                })
            })
            .collect();

        json!({
            "auto_mesh": true,
            "tick_interval_ms": self.tick_interval.as_millis(),
            "peers": peers,
        })
    }

    /// 泄露内部隧道引用（供集成方读取 local_locator 等）。
    pub fn tunnel(&self) -> &VirtualSubnetTunnel {
        &self.tunnel
    }

    /// 添加一个被发现的新 peer（LAN 自动发现调用）。
    ///
    /// 如果 peer 已存在，更新其 locator；否则注册到隧道和 peer 表。
    fn add_discovered_peer(&mut self, vip: &str, locator: &str) {
        // 已在 peer 表中？更新 locator
        if let Some(peer) = self.peers.get_mut(vip) {
            peer.static_locator = Some(locator.to_string());
            return;
        }

        // 新 peer：注册到隧道
        let tunnel_peer = TunnelPeer::new(vip, locator);
        if let Err(e) = self.tunnel.add_peer(tunnel_peer) {
            eprintln!("[auto-mesh] add discovered peer {vip} failed: {e}");
            return;
        }
        self.tunnel.set_peer_state(vip, TunnelState::Disconnected);

        // 加入 peer 自动维护表
        self.peers.insert(
            vip.to_string(),
            PeerAutoState::new(Some(locator.to_string())),
        );
        eprintln!("[auto-mesh] added discovered peer: {vip} @ {locator}");
    }
}

/// ReconnectController 没有 pub state()，用 attempt_count 和 next_delay 做粗略展示。
/// 这里给 PeerAutoState 加一个辅助方法。
mod reconnect_ext {
    // ReconnectController 的 state 是私有字段，我们不直接暴露，
    // 只展示 attempt_count。但 attempt_count 也是私有的。
    // 这里简单返回一个描述字符串。
}

// 为 PeerAutoState 加 reconnect_state_str 辅助方法
impl PeerAutoState {
    fn reconnect_state_str(&self) -> &'static str {
        // ReconnectController 的 state 是私有的，我们不暴露细节。
        // 这里基于 punching 和 consecutive_failures 做粗略描述。
        if self.punching {
            "punching"
        } else if self.consecutive_failures > 0 {
            "reconnecting"
        } else {
            "idle"
        }
    }
}

// ============================================================
// Phase 2: LAN 组播自动发现
// ============================================================

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

/// LAN 组播发现配置。
#[derive(Debug, Clone)]
pub struct LanDiscoveryConfig {
    /// 组播地址（默认 239.255.42.99）。
    pub multicast_addr: Ipv4Addr,
    /// 组播端口（默认 25000）。
    pub multicast_port: u16,
    /// 发现广播间隔（毫秒）。
    pub discover_interval_ms: u64,
    /// 邻居超时时间（毫秒），超时未再见到则移除。
    pub peer_timeout_ms: u64,
    /// 本节点虚拟 IP（用于 PRESENCE 帧广播自己的位置）。
    pub virtual_ip: String,
    /// 本节点 UDP 监听端口（隧道数据面端口）。
    pub udp_port: u16,
    /// 本节点 node_id（默认用 virtual_ip）。
    pub node_id: String,
}

impl Default for LanDiscoveryConfig {
    fn default() -> Self {
        Self {
            multicast_addr: Ipv4Addr::new(239, 255, 42, 99),
            multicast_port: 25000,
            discover_interval_ms: 5000,
            peer_timeout_ms: 60_000,
            virtual_ip: String::new(),
            udp_port: 0,
            node_id: String::new(),
        }
    }
}

/// 一个已发现的 LAN 邻居。
#[derive(Debug, Clone)]
#[allow(dead_code)] // node_id 保留供 Phase 3/4 去重和持久化使用
struct DiscoveredLanPeer {
    node_id: String,
    virtual_ip: String,
    /// 物理地址：udp://ip:port
    locator: String,
    /// 最近一次见到的时间。
    last_seen: Instant,
}

/// LAN 组播发现器。
///
/// 每 N 秒向组播地址发 DISCOVER 帧；收到 PRESENCE 帧时记录邻居。
/// 超时未再见到的邻居自动移除。
pub struct LanDiscovery {
    config: LanDiscoveryConfig,
    /// 组播 socket（绑定到组播端口，加入组播组）。
    socket: Option<UdpSocket>,
    /// 已知 LAN 邻居表。
    peers: HashMap<String, DiscoveredLanPeer>,
    /// 上次发 DISCOVER 的时间。
    last_discover: Instant,
}

impl LanDiscovery {
    /// 创建 LAN 发现器（尝试绑定组播 socket；失败则返回 None，降级为纯静态 peer 模式）。
    pub fn new(config: LanDiscoveryConfig) -> Self {
        let socket = Self::bind_multicast(&config).ok();
        if socket.is_none() {
            eprintln!(
                "[auto-mesh] LAN discovery: failed to bind multicast socket, running in static-only mode"
            );
        }
        Self {
            config,
            socket,
            peers: HashMap::new(),
            last_discover: Instant::now(),
        }
    }

    /// 绑定组播 socket：绑定 0.0.0.0:multicast_port，加入组播组。
    fn bind_multicast(config: &LanDiscoveryConfig) -> std::io::Result<UdpSocket> {
        let socket = UdpSocket::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            config.multicast_port,
        ))?;
        // 加入组播组
        socket.join_multicast_v4(&config.multicast_addr, &Ipv4Addr::UNSPECIFIED)?;
        // 设置非阻塞（配合主循环轮询）
        socket.set_nonblocking(true)?;
        Ok(socket)
    }

    /// 构造 DISCOVER 帧。
    fn discover_frame(&self) -> String {
        format!(
            "NXDSC:{}:{}:{}",
            self.config.node_id, self.config.virtual_ip, self.config.udp_port
        )
    }

    /// 构造 PRESENCE 帧（回复给发现者）。
    fn presence_frame(&self) -> String {
        format!(
            "NXPRES:{}:{}:{}",
            self.config.node_id, self.config.virtual_ip, self.config.udp_port
        )
    }

    /// Tick：发发现帧 + 收帧 + 超时清理。
    ///
    /// 返回本次 tick 新发现的邻居列表（locator 格式：udp://ip:port）。
    pub fn tick(&mut self) -> Vec<(String, String)> {
        let mut new_peers = Vec::new();

        // 1. 定期发 DISCOVER（需要 &mut self 因为 last_discover）
        let send_discover =
            self.last_discover.elapsed().as_millis() as u64 >= self.config.discover_interval_ms;
        if send_discover {
            self.last_discover = Instant::now();
            if let Some(socket) = &self.socket {
                let frame = self.discover_frame();
                let mcast_addr = SocketAddr::new(
                    IpAddr::V4(self.config.multicast_addr),
                    self.config.multicast_port,
                );
                if let Err(e) = socket.send_to(frame.as_bytes(), mcast_addr) {
                    eprintln!("[auto-mesh] LAN discover send failed: {e}");
                }
            }
        }

        // 2. 收帧（非阻塞，先收集再处理，避免借用冲突）
        let mut received: Vec<(String, SocketAddr)> = Vec::new();
        if let Some(socket) = &self.socket {
            let mut buf = [0u8; 1024];
            loop {
                match socket.recv_from(&mut buf) {
                    Ok((n, src)) => {
                        let text = String::from_utf8_lossy(&buf[..n]);
                        received.push((text.trim().to_string(), src));
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        eprintln!("[auto-mesh] LAN recv error: {e}");
                        break;
                    }
                }
            }
        }

        // 处理收到的帧（现在可以可变借用 self）
        for (text, src) in received {
            self.handle_frame(&text, src, &mut new_peers);
        }

        // 3. 超时清理
        let now = Instant::now();
        self.peers.retain(|_, p| {
            (now.duration_since(p.last_seen).as_millis() as u64) < self.config.peer_timeout_ms
        });

        new_peers
    }

    /// 处理收到的帧。
    fn handle_frame(&mut self, text: &str, src: SocketAddr, new_peers: &mut Vec<(String, String)>) {
        let parts: Vec<&str> = text.split(':').collect();
        if parts.len() < 4 {
            return;
        }

        match parts[0] {
            // 收到别人的 DISCOVER → 回复 PRESENCE
            "NXDSC" => {
                let node_id = parts[1];
                let virtual_ip = parts[2];
                let udp_port: u16 = parts[3].parse().unwrap_or(0);

                // 记录邻居（用组播源地址 + 对方 udp_port 作为 locator）
                let locator = format!("udp://{}:{}", src.ip(), udp_port);
                self.upsert_peer(node_id, virtual_ip, &locator, new_peers);

                // 回复 PRESENCE 给对方单播
                if let Some(socket) = &self.socket {
                    let presence = self.presence_frame();
                    let _ = socket.send_to(presence.as_bytes(), src);
                }
            }
            // 收到别人的 PRESENCE → 记录邻居
            "NXPRES" => {
                let node_id = parts[1];
                let virtual_ip = parts[2];
                let udp_port: u16 = parts[3].parse().unwrap_or(0);
                let locator = format!("udp://{}:{}", src.ip(), udp_port);
                self.upsert_peer(node_id, virtual_ip, &locator, new_peers);
            }
            _ => {}
        }
    }

    /// upsert 邻居表；新邻居加入 new_peers。
    fn upsert_peer(
        &mut self,
        node_id: &str,
        virtual_ip: &str,
        locator: &str,
        new_peers: &mut Vec<(String, String)>,
    ) {
        // 不记录自己
        if node_id == self.config.node_id || virtual_ip == self.config.virtual_ip {
            return;
        }

        let is_new = !self.peers.contains_key(virtual_ip);
        self.peers.insert(
            virtual_ip.to_string(),
            DiscoveredLanPeer {
                node_id: node_id.to_string(),
                virtual_ip: virtual_ip.to_string(),
                locator: locator.to_string(),
                last_seen: Instant::now(),
            },
        );
        if is_new {
            eprintln!("[auto-mesh] LAN discovered: {virtual_ip} @ {locator}");
            new_peers.push((virtual_ip.to_string(), locator.to_string()));
        }
    }

    /// 返回当前所有已知 LAN 邻居。
    pub fn peers(&self) -> Vec<(String, String)> {
        self.peers
            .values()
            .map(|p| (p.virtual_ip.clone(), p.locator.clone()))
            .collect()
    }
}

// ============================================================
// Phase 3: WAN Bootstrap + 自动 Relay 回退
// ============================================================

/// WAN Bootstrap 配置。
#[derive(Debug, Clone)]
pub struct BootstrapConfig {
    /// 引导服务器 URL（HTTP GET，返回 JSON peer 列表）。
    pub url: String,
    /// 拉取间隔（毫秒）。
    pub interval_ms: u64,
    /// 本节点上报的 virtual_ip。
    pub virtual_ip: String,
    /// 本节点上报的 locator。
    pub locator: String,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            interval_ms: 30_000,
            virtual_ip: String::new(),
            locator: String::new(),
        }
    }
}

/// WAN Bootstrap 客户端：周期性从引导服务器拉取邻居列表。
pub struct BootstrapClient {
    config: BootstrapConfig,
    last_fetch: Instant,
    /// 已知 peer 集合（去重）。
    known_peers: std::collections::HashSet<String>,
}

impl BootstrapClient {
    pub fn new(config: BootstrapConfig) -> Self {
        Self {
            config,
            last_fetch: Instant::now(),
            known_peers: std::collections::HashSet::new(),
        }
    }

    /// 是否该拉取了。
    fn is_due(&self) -> bool {
        self.last_fetch.elapsed().as_millis() as u64 >= self.config.interval_ms
    }

    /// Tick：到间隔就拉取一次，返回新发现的 peer 列表。
    pub fn tick(&mut self) -> Vec<(String, String)> {
        if self.config.url.is_empty() || !self.is_due() {
            return Vec::new();
        }
        self.last_fetch = Instant::now();
        self.fetch_peers()
    }

    /// 从引导服务器拉取 peer 列表。
    fn fetch_peers(&mut self) -> Vec<(String, String)> {
        let mut new_peers = Vec::new();

        // 简单 HTTP GET：从 url 解析 host:port + path
        let url = &self.config.url;
        let without_scheme = url
            .trim_start_matches("http://")
            .trim_start_matches("https://");
        let (host_port, path) = match without_scheme.find('/') {
            Some(idx) => (&without_scheme[..idx], &without_scheme[idx..]),
            None => (without_scheme, "/"),
        };
        let path_with_query = format!(
            "{path}?node={}&locator={}",
            self.config.virtual_ip, self.config.locator
        );

        let addr: std::net::SocketAddr = match host_port.parse() {
            Ok(a) => a,
            Err(_) => {
                // 加端口 80
                let with_port = format!("{host_port}:80");
                match with_port.parse() {
                    Ok(a) => a,
                    Err(e) => {
                        eprintln!("[auto-mesh] bootstrap invalid addr {host_port}: {e}");
                        return new_peers;
                    }
                }
            }
        };

        let mut stream = match std::net::TcpStream::connect_timeout(
            &addr,
            std::time::Duration::from_millis(500),
        ) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[auto-mesh] bootstrap connect failed: {e}");
                return new_peers;
            }
        };
        stream
            .set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .ok();

        let request = format!(
            "GET {path_with_query} HTTP/1.1\r\nHost: {host_port}\r\nConnection: close\r\n\r\n"
        );
        use std::io::Write;
        if let Err(e) = stream.write_all(request.as_bytes()) {
            eprintln!("[auto-mesh] bootstrap write failed: {e}");
            return new_peers;
        }

        use std::io::Read;
        let mut buf = Vec::new();
        if let Err(e) = stream.read_to_end(&mut buf) {
            eprintln!("[auto-mesh] bootstrap read failed: {e}");
            return new_peers;
        }

        let text = String::from_utf8_lossy(&buf);
        // 找 body（\r\n\r\n 之后）
        let body = match text.find("\r\n\r\n") {
            Some(idx) => &text[idx + 4..],
            None => &text[..],
        };

        let body: serde_json::Value = match serde_json::from_str(body) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[auto-mesh] bootstrap parse JSON failed: {e}");
                return new_peers;
            }
        };

        // 解析 peer 列表：期望格式 {"peers": [{"virtual_ip": "10.99.0.x", "locator": "udp://ip:port"}, ...]}
        if let Some(peers) = body.get("peers").and_then(|p| p.as_array()) {
            for peer in peers {
                let vip = peer
                    .get("virtual_ip")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let locator = peer.get("locator").and_then(|v| v.as_str()).unwrap_or("");

                if vip.is_empty() || locator.is_empty() || vip == self.config.virtual_ip {
                    continue;
                }

                if self.known_peers.insert(vip.to_string()) {
                    eprintln!("[auto-mesh] bootstrap discovered: {vip} @ {locator}");
                    new_peers.push((vip.to_string(), locator.to_string()));
                }
            }
        }

        new_peers
    }
}

// ============================================================
// Phase 4: 状态持久化 + 可观察性
// ============================================================
use std::path::PathBuf;

/// Auto-Mesh 持久化状态文件（JSON）。
#[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
pub struct MeshPersist {
    /// 已知 peer 列表。
    pub peers: Vec<PersistedPeer>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct PersistedPeer {
    pub virtual_ip: String,
    pub locator: String,
    pub consecutive_failures: u32,
}

impl AutoMeshController {
    /// 保存 auto-mesh 状态到磁盘（crash 恢复用）。
    pub fn save_state(&self, path: &std::path::Path) {
        let persist = MeshPersist {
            peers: self
                .peers
                .iter()
                .map(|(vip, p)| PersistedPeer {
                    virtual_ip: vip.clone(),
                    locator: p.static_locator.clone().unwrap_or_default(),
                    consecutive_failures: p.consecutive_failures,
                })
                .collect(),
        };

        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        match serde_json::to_string_pretty(&persist) {
            Ok(json) => {
                let tmp_path = path.with_extension("tmp");
                if let Err(e) = std::fs::write(&tmp_path, json) {
                    eprintln!("[auto-mesh] save state failed: {e}");
                    return;
                }
                if let Err(e) = std::fs::rename(&tmp_path, path) {
                    eprintln!("[auto-mesh] rename state failed: {e}");
                }
            }
            Err(e) => eprintln!("[auto-mesh] serialize state failed: {e}"),
        }
    }

    /// 从磁盘恢复 auto-mesh 状态（crash 恢复用）。
    pub fn load_state(&mut self, path: &std::path::Path) {
        let Ok(text) = std::fs::read_to_string(path) else {
            return;
        };

        let persist: MeshPersist = match serde_json::from_str(&text) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[auto-mesh] load state parse failed: {e}");
                return;
            }
        };

        for peer in &persist.peers {
            // 已在 peer 表中？跳过（优先当前状态）
            if self.peers.contains_key(&peer.virtual_ip) {
                continue;
            }

            // 新 peer：注册到隧道
            if peer.locator.is_empty() {
                continue;
            }

            let tunnel_peer = TunnelPeer::new(&peer.virtual_ip, &peer.locator);
            if self.tunnel.add_peer(tunnel_peer).is_ok() {
                self.tunnel
                    .set_peer_state(&peer.virtual_ip, TunnelState::Disconnected);
                let mut state = PeerAutoState::new(Some(peer.locator.clone()));
                state.consecutive_failures = peer.consecutive_failures;
                self.peers.insert(peer.virtual_ip.clone(), state);
                eprintln!(
                    "[auto-mesh] restored peer: {} @ {} (failures={})",
                    peer.virtual_ip, peer.locator, peer.consecutive_failures
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_auto_state_lifecycle_and_backoff() {
        let mut state = PeerAutoState::new(Some("udp://127.0.0.1:9999".into()));
        assert_eq!(state.consecutive_failures, 0);
        assert!(!state.punching);

        // Disconnected -> should attempt punch
        assert!(state.should_attempt_punch(TunnelState::Disconnected));

        // Connected -> should not attempt punch
        assert!(!state.should_attempt_punch(TunnelState::Connected));

        // Mark punch started
        state.mark_punch_started();
        assert!(state.punching);
        assert!(!state.should_attempt_punch(TunnelState::Disconnected));

        // Mark failed -> increment failures, clear punching
        state.mark_punch_failed();
        assert_eq!(state.consecutive_failures, 1);
        assert!(!state.punching);

        // Immediately after failure, failed state waits for backoff
        assert!(!state.should_attempt_punch(TunnelState::Failed));

        // Mark success -> reset failures
        state.mark_punch_success();
        assert_eq!(state.consecutive_failures, 0);
        assert!(!state.punching);

        // Mark disconnected
        state.mark_disconnected();
        assert_eq!(state.consecutive_failures, 0);
        assert!(!state.punching);
        assert!(state.should_attempt_punch(TunnelState::Disconnected));
    }

    #[test]
    fn state_save_and_load_persistence() {
        let tmp_dir = std::env::temp_dir().join(format!("mesh-test-{}", std::process::id()));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let path = tmp_dir.join("mesh_state.json");

        let persist = MeshPersist {
            peers: vec![PersistedPeer {
                virtual_ip: "10.0.0.2".to_string(),
                locator: "udp://127.0.0.1:10001".to_string(),
                consecutive_failures: 2,
            }],
        };

        let json = serde_json::to_string_pretty(&persist).unwrap();
        let tmp_path = path.with_extension("tmp");
        std::fs::write(&tmp_path, &json).unwrap();
        std::fs::rename(&tmp_path, &path).unwrap();

        assert!(path.exists());
        let text = std::fs::read_to_string(&path).unwrap();
        let loaded: MeshPersist = serde_json::from_str(&text).unwrap();
        assert_eq!(loaded.peers.len(), 1);
        assert_eq!(loaded.peers[0].virtual_ip, "10.0.0.2");
        assert_eq!(loaded.peers[0].consecutive_failures, 2);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn consume_punch_events_incremental_cursor() {
        use nexus_connectivity::virtual_subnet::{
            MemoryCarrier, MemoryVpi, VirtualSubnetConfig, VirtualSubnetTunnel,
        };
        let cfg = VirtualSubnetConfig::new("10.0.0.1", "10.0.0.0/24");
        let tunnel = VirtualSubnetTunnel::new(
            cfg,
            Box::new(MemoryVpi::new()),
            Box::new(MemoryCarrier::new()),
        );
        let mut ctrl = AutoMeshController::new(tunnel, 100);
        assert_eq!(ctrl.last_event_index, 0);

        // Before any events
        ctrl.consume_punch_events();
        assert_eq!(ctrl.last_event_index, ctrl.tunnel.events().len());

        // Add a mock peer and simulate event consumption
        let peer_state = PeerAutoState::new(Some("udp://127.0.0.1:10002".into()));
        ctrl.peers.insert("10.0.0.2".to_string(), peer_state);

        // Ensure cursor updates after consume
        ctrl.consume_punch_events();
        assert_eq!(ctrl.last_event_index, ctrl.tunnel.events().len());
    }
}

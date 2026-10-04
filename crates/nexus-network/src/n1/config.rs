//! N1 配置（TOML）：节点身份、对端静态配置、VPI 装配、Link 观测参数。
//!
//! portable core 零第三方依赖，故此处是手写的 TOML **子集**解析器
//! （注释 / `[table]` / `[[array-of-tables]]` / `key = value`，
//! value 支持字符串/整数/布尔/单行数组），只接受 `N1Config` 的已知 schema：
//! 未知表、未知键一律报错（fail-fast，避免拼写错误静默生效）。
//!
//! 示例：
//! ```toml
//! peer_id = "<64 hex ed25519 pubkey>"
//!
//! [[peers]]
//! id = "<64 hex>"
//! addrs = ["10.200.0.2:9000"]
//!
//! [vpi]
//! interface = "nxtun0"
//! address = "10.144.0.1"
//! mtu = 1200
//!
//! [[vpi.routes]]
//! subnet = "10.144.0.0/24"
//! peer = "<64 hex>"
//!
//! [link]
//! probe_interval_ms = 1000
//! heartbeat_timeout_ms = 3000
//! ```

use std::net::{Ipv4Addr, SocketAddr};

use super::link::LinkConfig;
use super::pump::{DATAGRAM_CAP, Ipv4Net, Ipv4Route};
use super::{N1Error, N1PeerId};

/// 静态对端条目（M3 首期：`PeerId` + 已知 locator）。
#[derive(Debug, Clone)]
pub struct N1PeerEntry {
    /// 对端身份。
    pub id: N1PeerId,
    /// 候选 locator（优先级即数组序）。
    pub addrs: Vec<SocketAddr>,
}

/// VPI 装配配置。
#[derive(Debug, Clone)]
pub struct N1VpiConfig {
    /// TUN 接口名（如 `nxtun0`）。
    pub interface: String,
    /// 本节点 VPI 地址。
    pub address: Ipv4Addr,
    /// TUN MTU（必须 ≤ 1200，对齐 fabric datagram 上限）。
    pub mtu: u16,
    /// 静态路由。
    pub routes: Vec<Ipv4Route>,
}

/// N1 完整配置。
#[derive(Debug, Clone)]
pub struct N1Config {
    /// 本节点身份。
    pub peer_id: N1PeerId,
    /// 静态对端。
    pub peers: Vec<N1PeerEntry>,
    /// VPI 装配。
    pub vpi: N1VpiConfig,
    /// Link 观测。
    pub link: LinkConfig,
    /// Boost v1 配置（`[boost]` 缺失时为 `BoostConfig::default()`）。
    pub boost: BoostConfig,
}

/// Network Boost v1 配置（`network.toml [boost]` 小节，可选）。
///
/// 全部字段可选；`[boost]` 小节缺失时整体取 `Default`
///（`enabled = false`，即选路行为与 boost 之前完全一致，B4）。
#[derive(Debug, Clone)]
pub struct BoostConfig {
    /// 是否启用 boost（激进切路参数）。
    pub enabled: bool,
    /// 激进 hysteresis（相对比例）；默认 0.10，必须在 `(0, 1]`。
    pub hysteresis_pct: f64,
    /// 激进保持时间（毫秒）；默认 1000，必须 `> 0`。
    pub switch_hold_ms: u64,
    /// 建连时是否 staggered 竞速。
    pub race_on_connect: bool,
}

impl Default for BoostConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            hysteresis_pct: 0.10,
            switch_hold_ms: 1000,
            race_on_connect: true,
        }
    }
}

/// 生效后的选路参数（纯数据；`nexus-network` 无 `nexus-path` 依赖边，
/// 故不直接构造 `PathConfig`，由消费方映射，B2/B3）。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BoostPathParams {
    /// 生效的 hysteresis（相对比例）。
    pub hysteresis_pct: f64,
    /// 生效的保持时间（毫秒）。
    pub switch_hold_ms: u64,
    /// 建连时是否竞速。
    pub race_on_connect: bool,
}

impl BoostConfig {
    /// B2：映射为生效参数。
    /// - `enabled = true` → 取配置值；
    /// - `enabled = false` → 20% / 3s（与 `nexus-path` `PathConfig::default()` 一致）。
    pub fn path_params(&self) -> BoostPathParams {
        if self.enabled {
            BoostPathParams {
                hysteresis_pct: self.hysteresis_pct,
                switch_hold_ms: self.switch_hold_ms,
                race_on_connect: self.race_on_connect,
            }
        } else {
            BoostPathParams {
                hysteresis_pct: 0.20,
                switch_hold_ms: 3000,
                race_on_connect: self.race_on_connect,
            }
        }
    }
}

impl N1Config {
    /// 解析 TOML 子集；schema 违例返回 `InvalidConfig`（含行号）。
    pub fn parse_toml(text: &str) -> Result<Self, N1Error> {
        Parser::parse(text)
    }
}

// ---------- 解析器 ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Table {
    Root,
    Peers,
    Vpi,
    VpiRoutes,
    Link,
    Boost,
}

struct PartialPeer {
    id: Option<N1PeerId>,
    addrs: Option<Vec<SocketAddr>>,
}

struct PartialRoute {
    subnet: Option<Ipv4Net>,
    peer: Option<N1PeerId>,
}

struct Parser {
    peer_id: Option<N1PeerId>,
    peers: Vec<PartialPeer>,
    vpi_interface: Option<String>,
    vpi_address: Option<Ipv4Addr>,
    vpi_mtu: Option<u16>,
    routes: Vec<PartialRoute>,
    probe_interval_ms: Option<u64>,
    heartbeat_timeout_ms: Option<u64>,
    boost_enabled: Option<bool>,
    boost_hysteresis_pct: Option<f64>,
    boost_switch_hold_ms: Option<u64>,
    boost_race_on_connect: Option<bool>,
}

impl Parser {
    fn parse(text: &str) -> Result<N1Config, N1Error> {
        let mut this = Self {
            peer_id: None,
            peers: vec![],
            vpi_interface: None,
            vpi_address: None,
            vpi_mtu: None,
            routes: vec![],
            probe_interval_ms: None,
            heartbeat_timeout_ms: None,
            boost_enabled: None,
            boost_hysteresis_pct: None,
            boost_switch_hold_ms: None,
            boost_race_on_connect: None,
        };
        let mut table = Table::Root;
        for (idx, line) in logical_lines(text).into_iter().enumerate() {
            let lineno = idx + 1;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some(name) = table_header(line) {
                table = match name {
                    "peers" => {
                        this.peers.push(PartialPeer {
                            id: None,
                            addrs: None,
                        });
                        Table::Peers
                    }
                    "vpi" => Table::Vpi,
                    "vpi.routes" => {
                        this.routes.push(PartialRoute {
                            subnet: None,
                            peer: None,
                        });
                        Table::VpiRoutes
                    }
                    "link" => Table::Link,
                    "boost" => Table::Boost,
                    _ => {
                        return Err(Self::err(
                            lineno,
                            &format!(
                                "unknown table [{name}] (expected peers/vpi/vpi.routes/link/boost)"
                            ),
                        ));
                    }
                };
                continue;
            }
            let (key, val) = split_kv(line).ok_or_else(|| {
                Self::err(lineno, &format!("bad line (expected key = value): {line}"))
            })?;
            this.set_kv(lineno, table, key, val)?;
        }
        this.finish()
    }

    fn err(lineno: usize, msg: &str) -> N1Error {
        N1Error::InvalidConfig(format!("line {lineno}: {msg}"))
    }

    fn set_kv(&mut self, lineno: usize, table: Table, key: &str, val: &str) -> Result<(), N1Error> {
        match table {
            Table::Root => match key {
                "peer_id" => {
                    self.peer_id = Some(
                        N1PeerId::from_hex(&unquote(lineno, val)?)
                            .map_err(|e| Self::err(lineno, &format!("bad peer_id: {e}")))?,
                    );
                    Ok(())
                }
                _ => Err(Self::err(lineno, &format!("unknown root key: {key}"))),
            },
            Table::Peers => {
                let p = self
                    .peers
                    .last_mut()
                    .ok_or_else(|| Self::err(lineno, "[[peers]] entry missing"))?;
                match key {
                    "id" => {
                        p.id = Some(
                            N1PeerId::from_hex(&unquote(lineno, val)?)
                                .map_err(|e| Self::err(lineno, &format!("bad peers.id: {e}")))?,
                        );
                        Ok(())
                    }
                    "addrs" => {
                        p.addrs = Some(
                            parse_str_array(val)
                                .map_err(|e| Self::err(lineno, &format!("bad peers.addrs: {e}")))?
                                .iter()
                                .map(|s| {
                                    s.parse::<SocketAddr>().map_err(|_| {
                                        Self::err(lineno, &format!("bad socket addr: {s}"))
                                    })
                                })
                                .collect::<Result<Vec<_>, _>>()?,
                        );
                        Ok(())
                    }
                    _ => Err(Self::err(lineno, &format!("unknown [[peers]] key: {key}"))),
                }
            }
            Table::Vpi => match key {
                "interface" => {
                    let name = unquote(lineno, val)?;
                    if name.is_empty() || name.len() > 15 {
                        return Err(Self::err(lineno, "vpi.interface must be 1..=15 chars"));
                    }
                    self.vpi_interface = Some(name);
                    Ok(())
                }
                "address" => {
                    let addr: Ipv4Addr = unquote(lineno, val)?
                        .parse()
                        .map_err(|_| Self::err(lineno, "bad vpi.address"))?;
                    self.vpi_address = Some(addr);
                    Ok(())
                }
                "mtu" => {
                    let mtu: u16 = val
                        .parse()
                        .map_err(|_| Self::err(lineno, "bad vpi.mtu (integer expected)"))?;
                    if usize::from(mtu) > DATAGRAM_CAP {
                        return Err(Self::err(
                            lineno,
                            &format!("vpi.mtu must be <= {DATAGRAM_CAP} (fabric datagram cap)"),
                        ));
                    }
                    self.vpi_mtu = Some(mtu);
                    Ok(())
                }
                _ => Err(Self::err(lineno, &format!("unknown [vpi] key: {key}"))),
            },
            Table::VpiRoutes => {
                let r = self
                    .routes
                    .last_mut()
                    .ok_or_else(|| Self::err(lineno, "[[vpi.routes]] entry missing"))?;
                match key {
                    "subnet" => {
                        r.subnet = Some(
                            Ipv4Net::parse(&unquote(lineno, val)?)
                                .map_err(|e| Self::err(lineno, &format!("bad subnet: {e}")))?,
                        );
                        Ok(())
                    }
                    "peer" => {
                        r.peer = Some(N1PeerId::from_hex(&unquote(lineno, val)?).map_err(|e| {
                            Self::err(lineno, &format!("bad vpi.routes.peer: {e}"))
                        })?);
                        Ok(())
                    }
                    _ => Err(Self::err(
                        lineno,
                        &format!("unknown [[vpi.routes]] key: {key}"),
                    )),
                }
            }
            Table::Link => match key {
                "probe_interval_ms" => {
                    self.probe_interval_ms = Some(
                        val.parse()
                            .map_err(|_| Self::err(lineno, "bad link.probe_interval_ms"))?,
                    );
                    Ok(())
                }
                "heartbeat_timeout_ms" => {
                    self.heartbeat_timeout_ms = Some(
                        val.parse()
                            .map_err(|_| Self::err(lineno, "bad link.heartbeat_timeout_ms"))?,
                    );
                    Ok(())
                }
                _ => Err(Self::err(lineno, &format!("unknown [link] key: {key}"))),
            },
            Table::Boost => match key {
                "enabled" => {
                    self.boost_enabled = Some(parse_bool(val).ok_or_else(|| {
                        Self::err(lineno, "bad boost.enabled (true/false expected)")
                    })?);
                    Ok(())
                }
                "hysteresis_pct" => {
                    let v: f64 = val.parse().map_err(|_| {
                        Self::err(lineno, "bad boost.hysteresis_pct (float expected)")
                    })?;
                    if !(v > 0.0 && v <= 1.0) {
                        return Err(Self::err(lineno, "boost.hysteresis_pct must be in (0, 1]"));
                    }
                    self.boost_hysteresis_pct = Some(v);
                    Ok(())
                }
                "switch_hold_ms" => {
                    let v: u64 = val.parse().map_err(|_| {
                        Self::err(lineno, "bad boost.switch_hold_ms (integer expected)")
                    })?;
                    if v == 0 {
                        return Err(Self::err(lineno, "boost.switch_hold_ms must be > 0"));
                    }
                    self.boost_switch_hold_ms = Some(v);
                    Ok(())
                }
                "race_on_connect" => {
                    self.boost_race_on_connect = Some(parse_bool(val).ok_or_else(|| {
                        Self::err(lineno, "bad boost.race_on_connect (true/false expected)")
                    })?);
                    Ok(())
                }
                _ => Err(Self::err(lineno, &format!("unknown [boost] key: {key}"))),
            },
        }
    }

    fn finish(self) -> Result<N1Config, N1Error> {
        let peer_id = self
            .peer_id
            .ok_or_else(|| N1Error::InvalidConfig("missing required: peer_id".into()))?;
        let mut peers = vec![];
        for (i, p) in self.peers.into_iter().enumerate() {
            peers.push(N1PeerEntry {
                id: p
                    .id
                    .ok_or_else(|| N1Error::InvalidConfig(format!("[[peers]][{i}]: missing id")))?,
                addrs: p.addrs.ok_or_else(|| {
                    N1Error::InvalidConfig(format!("[[peers]][{i}]: missing addrs"))
                })?,
            });
        }
        let mut routes = vec![];
        for (i, r) in self.routes.into_iter().enumerate() {
            routes.push(Ipv4Route {
                subnet: r.subnet.ok_or_else(|| {
                    N1Error::InvalidConfig(format!("[[vpi.routes]][{i}]: missing subnet"))
                })?,
                peer: r.peer.ok_or_else(|| {
                    N1Error::InvalidConfig(format!("[[vpi.routes]][{i}]: missing peer"))
                })?,
            });
        }
        Ok(N1Config {
            peer_id,
            peers,
            vpi: N1VpiConfig {
                interface: self.vpi_interface.ok_or_else(|| {
                    N1Error::InvalidConfig("missing required: vpi.interface".into())
                })?,
                address: self.vpi_address.ok_or_else(|| {
                    N1Error::InvalidConfig("missing required: vpi.address".into())
                })?,
                mtu: self.vpi_mtu.unwrap_or(1200),
                routes,
            },
            link: LinkConfig {
                probe_interval: std::time::Duration::from_millis(
                    self.probe_interval_ms.unwrap_or(5000),
                ),
                heartbeat_timeout: std::time::Duration::from_millis(
                    self.heartbeat_timeout_ms.unwrap_or(15000),
                ),
                enable_rebind: true,
                enable_watcher: true,
            },
            boost: BoostConfig {
                enabled: self.boost_enabled.unwrap_or(false),
                hysteresis_pct: self.boost_hysteresis_pct.unwrap_or(0.10),
                switch_hold_ms: self.boost_switch_hold_ms.unwrap_or(1000),
                race_on_connect: self.boost_race_on_connect.unwrap_or(true),
            },
        })
    }
}

/// 去注释（# 外字符串）并按方括号配平合并逻辑行。
fn logical_lines(text: &str) -> Vec<String> {
    let mut out = vec![];
    let mut cur = String::new();
    let mut depth: i32 = 0;
    for raw in text.lines() {
        let line = strip_comment(raw);
        // 方括号深度（字符串内的括号不计——简化：配置 schema 中字符串不含括号）。
        let mut in_str = false;
        let mut esc = false;
        for c in line.chars() {
            if esc {
                esc = false;
                continue;
            }
            if c == '\\' && in_str {
                esc = true;
                continue;
            }
            if c == '"' {
                in_str = !in_str;
                continue;
            }
            if !in_str {
                if c == '[' {
                    depth += 1;
                } else if c == ']' {
                    depth -= 1;
                }
            }
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(line.trim());
        if depth <= 0 {
            out.push(std::mem::take(&mut cur));
            depth = 0;
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

/// 去掉行尾注释（字符串内的 # 保留）。
fn strip_comment(line: &str) -> &str {
    let mut in_str = false;
    let mut esc = false;
    for (i, c) in line.char_indices() {
        if esc {
            esc = false;
            continue;
        }
        if c == '\\' && in_str {
            esc = true;
            continue;
        }
        if c == '"' {
            in_str = !in_str;
            continue;
        }
        if c == '#' && !in_str {
            return &line[..i];
        }
    }
    line
}

/// 解析 `[name]` / `[[name]]` 表头；非表头返回 None。
fn table_header(line: &str) -> Option<&str> {
    let t = line.trim();
    if let Some(inner) = t.strip_prefix("[[").and_then(|s| s.strip_suffix("]]")) {
        return Some(inner.trim());
    }
    if let Some(inner) = t.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        // `[x]` 不是 `[[x]]`（已排除双括号）。
        if !inner.starts_with('[') {
            return Some(inner.trim());
        }
    }
    None
}

/// 切分 `key = value`。
fn split_kv(line: &str) -> Option<(&str, &str)> {
    let (k, v) = line.split_once('=')?;
    Some((k.trim(), v.trim()))
}

/// 解析 `true` / `false`（大小写不敏感，前后空白容忍）。
fn parse_bool(val: &str) -> Option<bool> {
    match val.trim().to_ascii_lowercase().as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// 解析 `"..."` 字符串（支持 `\"` / `\\` 转义）。
fn unquote(lineno: usize, val: &str) -> Result<String, N1Error> {
    let err = || N1Error::InvalidConfig(format!("line {lineno}: string expected, got {val}"));
    let inner = val
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .ok_or_else(err)?;
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some('n') => out.push('\n'),
                _ => return Err(err()),
            }
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

/// 解析 `["a", "b"]` 字符串数组。
fn parse_str_array(val: &str) -> Result<Vec<String>, String> {
    let inner = val
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or_else(|| format!("array expected, got {val}"))?;
    if inner.trim().is_empty() {
        return Ok(vec![]);
    }
    let mut out = vec![];
    let mut cur = String::new();
    let mut in_str = false;
    let mut esc = false;
    for c in inner.chars() {
        if esc {
            cur.push(c);
            esc = false;
            continue;
        }
        if c == '\\' && in_str {
            esc = true;
            cur.push(c);
            continue;
        }
        if c == '"' {
            in_str = !in_str;
            cur.push(c);
            continue;
        }
        if c == ',' && !in_str {
            out.push(unquote_simple(cur.trim())?);
            cur.clear();
            continue;
        }
        cur.push(c);
    }
    if !cur.trim().is_empty() {
        out.push(unquote_simple(cur.trim())?);
    }
    Ok(out)
}

fn unquote_simple(s: &str) -> Result<String, String> {
    s.strip_prefix('"')
        .and_then(|x| x.strip_suffix('"'))
        .map(|x| x.replace("\\\"", "\"").replace("\\\\", "\\"))
        .ok_or_else(|| format!("string expected in array, got {s}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
# 示例配置
peer_id = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"

[[peers]]
id = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
addrs = ["10.200.0.2:9000", "10.200.0.2:9001"]

[vpi]
interface = "nxtun0"
address = "10.144.0.1"
mtu = 1200

[[vpi.routes]]
subnet = "10.144.0.0/24"
peer = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

[link]
probe_interval_ms = 1000
heartbeat_timeout_ms = 3000
"#;

    #[test]
    fn parses_full_config() {
        let c = N1Config::parse_toml(SAMPLE).unwrap();
        assert_eq!(
            c.peer_id.to_hex(),
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
        );
        assert_eq!(c.peers.len(), 1);
        assert_eq!(c.peers[0].addrs.len(), 2);
        assert_eq!(c.vpi.interface, "nxtun0");
        assert_eq!(c.vpi.address, Ipv4Addr::new(10, 144, 0, 1));
        assert_eq!(c.vpi.mtu, 1200);
        assert_eq!(c.vpi.routes.len(), 1);
        assert_eq!(c.vpi.routes[0].subnet.to_string(), "10.144.0.0/24");
        assert_eq!(
            c.link.probe_interval,
            std::time::Duration::from_millis(1000)
        );
        assert_eq!(
            c.link.heartbeat_timeout,
            std::time::Duration::from_millis(3000)
        );
    }

    #[test]
    fn defaults_apply() {
        let bad_id = "peer_id = \"xyz\"\n[vpi]\ninterface = \"n0\"\naddress = \"10.0.0.1\"\n";
        let e = N1Config::parse_toml(bad_id).unwrap_err();
        assert!(e.to_string().contains("peer_id"), "unexpected: {e}");
        let minimal = "peer_id = \"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\"\n[vpi]\ninterface = \"n0\"\naddress = \"10.0.0.1\"\n";
        let c = N1Config::parse_toml(minimal).unwrap();
        assert_eq!(c.vpi.mtu, 1200);
        assert_eq!(
            c.link.probe_interval,
            std::time::Duration::from_secs(5),
            "contract default 5s"
        );
    }

    #[test]
    fn rejects_unknown_keys_and_tables() {
        let bad = "peer_id = \"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\"\n[bogus]\nx = 1\n";
        assert!(N1Config::parse_toml(bad).is_err());
        let bad2 = "peer_id = \"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\"\n[link]\nnope = 1\n";
        assert!(N1Config::parse_toml(bad2).is_err());
    }

    #[test]
    fn rejects_bad_values() {
        // mtu 超过 datagram 上限。
        let bad = "peer_id = \"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\"\n[vpi]\ninterface = \"n0\"\naddress = \"10.0.0.1\"\nmtu = 9000\n";
        let e = N1Config::parse_toml(bad).unwrap_err();
        assert!(e.to_string().contains("1200"), "unexpected: {e}");
        // 非法 peer id。
        let bad2 = "peer_id = \"xyz\"\n[vpi]\ninterface = \"n0\"\naddress = \"10.0.0.1\"\n";
        assert!(N1Config::parse_toml(bad2).is_err());
        // 缺必填。
        let bad3 = "[vpi]\ninterface = \"n0\"\naddress = \"10.0.0.1\"\n";
        assert!(N1Config::parse_toml(bad3).is_err());
    }

    #[test]
    fn comment_inside_string_survives() {
        let toml = "peer_id = \"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\" # 注释\n[vpi] # 表注释\ninterface = \"n0\"\naddress = \"10.0.0.1\"\n";
        assert!(N1Config::parse_toml(toml).is_ok());
    }

    // ---------- Boost v1 (B1/B2) ----------

    const MINIMAL: &str = "peer_id = \"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899\"\n[vpi]\ninterface = \"n0\"\naddress = \"10.0.0.1\"\n";

    #[test]
    fn boost_absent_gives_defaults() {
        // B1: 无 [boost] → default（enabled=false）；B2: 映射回落 20%/3s。
        let c = N1Config::parse_toml(MINIMAL).unwrap();
        assert!(!c.boost.enabled);
        assert_eq!(c.boost.hysteresis_pct, 0.10);
        assert_eq!(c.boost.switch_hold_ms, 1000);
        assert!(c.boost.race_on_connect);
        let p = c.boost.path_params();
        assert_eq!(p.hysteresis_pct, 0.20);
        assert_eq!(p.switch_hold_ms, 3000);
        assert!(p.race_on_connect);
    }

    #[test]
    fn boost_enabled_maps_aggressive_params() {
        // B1+B2: enabled=true → 取配置值（激进 10%/1s）。
        let toml = format!(
            "{MINIMAL}[boost]\nenabled = true\nhysteresis_pct = 0.10\nswitch_hold_ms = 1000\nrace_on_connect = true\n"
        );
        let c = N1Config::parse_toml(&toml).unwrap();
        assert!(c.boost.enabled);
        let p = c.boost.path_params();
        assert_eq!(p.hysteresis_pct, 0.10);
        assert_eq!(p.switch_hold_ms, 1000);
        assert!(p.race_on_connect);
    }

    #[test]
    fn boost_custom_values_and_race_off() {
        let toml = format!(
            "{MINIMAL}[boost]\nenabled = true\nhysteresis_pct = 0.05\nswitch_hold_ms = 500\nrace_on_connect = false\n"
        );
        let c = N1Config::parse_toml(&toml).unwrap();
        let p = c.boost.path_params();
        assert_eq!(p.hysteresis_pct, 0.05);
        assert_eq!(p.switch_hold_ms, 500);
        assert!(!p.race_on_connect);
    }

    #[test]
    fn boost_rejects_bad_values() {
        // hysteresis_pct 超出 (0, 1]。
        for bad in ["0", "-0.1", "1.5"] {
            let toml = format!("{MINIMAL}[boost]\nenabled = true\nhysteresis_pct = {bad}\n");
            let e = N1Config::parse_toml(&toml).unwrap_err();
            assert!(e.to_string().contains("hysteresis_pct"), "unexpected: {e}");
        }
        // switch_hold_ms 为 0。
        let toml = format!("{MINIMAL}[boost]\nswitch_hold_ms = 0\n");
        let e = N1Config::parse_toml(&toml).unwrap_err();
        assert!(e.to_string().contains("switch_hold_ms"), "unexpected: {e}");
        // 非法 bool。
        let toml = format!("{MINIMAL}[boost]\nenabled = yes\n");
        assert!(N1Config::parse_toml(&toml).is_err());
        // 未知键。
        let toml = format!("{MINIMAL}[boost]\nnope = 1\n");
        let e = N1Config::parse_toml(&toml).unwrap_err();
        assert!(
            e.to_string().contains("unknown [boost] key"),
            "unexpected: {e}"
        );
    }

    #[test]
    fn boost_accepts_upper_bound_and_partial_section() {
        // hysteresis_pct = 1.0 是上边界，应被接受（(0, 1] 闭区间右端）。
        let toml = format!("{MINIMAL}[boost]\nenabled = true\nhysteresis_pct = 1.0\n");
        let c = N1Config::parse_toml(&toml).unwrap();
        assert_eq!(c.boost.hysteresis_pct, 1.0);
        // 部分 [boost] 小节：未给字段取默认值。
        let toml = format!("{MINIMAL}[boost]\nenabled = true\n");
        let c = N1Config::parse_toml(&toml).unwrap();
        assert!(c.boost.enabled);
        assert_eq!(c.boost.hysteresis_pct, 0.10);
        assert_eq!(c.boost.switch_hold_ms, 1000);
        assert!(c.boost.race_on_connect);
        // bool 大小写不敏感。
        let toml = format!("{MINIMAL}[boost]\nenabled = TRUE\nrace_on_connect = False\n");
        let c = N1Config::parse_toml(&toml).unwrap();
        assert!(c.boost.enabled);
        assert!(!c.boost.race_on_connect);
    }
}

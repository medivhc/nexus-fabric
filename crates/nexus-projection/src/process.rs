//! Process attribution and QoS marking (S26).
//!
//! At flow-setup time (never per-packet) the local socket's owning process
//! is resolved once and cached as [`FlowLabels`] on the flow state. The
//! [`ProcessAttributor`] trait is the portability seam: the Linux
//! implementation parses `/proc`; other platforms get [`NoopAttributor`]
//! (always unknown). Windows WFP attribution is explicitly out of scope.
//!
//! Deletion test (§12): without this trait, portable flow-setup code would
//! have to call `/proc` directly (breaking the Portable Core rule) or give
//! up attribution on every platform. The trait has multiple real
//! implementations (Linux `/proc`, Noop, future WFP) plus test doubles.

use std::net::SocketAddr;

#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::net::Ipv4Addr;
#[cfg(target_os = "linux")]
use std::path::Path;

/// Transport protocol of the attributed socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

/// Result of attributing one socket to an OS process.
/// `unknown()` (both `None`) means "could not determine" — never an error:
/// attribution is best-effort and must not block flow setup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribution {
    pub pid: Option<u32>,
    pub process_name: Option<String>,
}

impl Attribution {
    pub fn unknown() -> Self {
        Self {
            pid: None,
            process_name: None,
        }
    }
}

/// Portability seam for process attribution (S26).
///
/// Implementations must be total: any failure (missing `/proc` entries,
/// races with exiting processes, unsupported platform) yields
/// [`Attribution::unknown()`], never a panic or an error.
pub trait ProcessAttributor: Send + Sync {
    fn attribute(&self, local: SocketAddr, remote: SocketAddr, proto: Proto) -> Attribution;
}

/// QoS priority class assigned from the process name (S26).
///
/// P0 is marking only: the class travels with [`FlowLabels`] as flow
/// metadata. Per-class queueing/scheduling is out of scope (the session and
/// path layers have no queueing mechanism yet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QosClass {
    High,
    Normal,
    Low,
    Background,
}

/// Exact process-name → [`QosClass`] mapping (S26).
///
/// P0: exact matches only (glob/regex are out of scope). No rule hit, or an
/// unknown process, classifies as [`QosClass::Normal`].
#[derive(Debug, Clone, Default)]
pub struct QosConfig {
    pub rules: Vec<(String, QosClass)>,
}

impl QosConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_rule(mut self, process_name: &str, class: QosClass) -> Self {
        self.rules.push((process_name.to_string(), class));
        self
    }

    pub fn classify(&self, process_name: Option<&str>) -> QosClass {
        let name = match process_name {
            Some(n) => n,
            None => return QosClass::Normal,
        };
        for (rule, class) in &self.rules {
            if rule == name {
                return *class;
            }
        }
        QosClass::Normal
    }
}

/// Per-flow labels: process attribution resolved once at flow setup and
/// cached on the flow state (S26). Never recomputed per packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowLabels {
    pub process_name: Option<String>,
    pub qos_class: QosClass,
}

impl FlowLabels {
    pub fn unknown() -> Self {
        Self {
            process_name: None,
            qos_class: QosClass::Normal,
        }
    }

    /// Attribute the socket owned by `(local, remote)` and classify it.
    pub fn attribute(
        a: &dyn ProcessAttributor,
        qos: &QosConfig,
        local: SocketAddr,
        remote: SocketAddr,
        proto: Proto,
    ) -> Self {
        let attr = a.attribute(local, remote, proto);
        let qos_class = qos.classify(attr.process_name.as_deref());
        Self {
            process_name: attr.process_name,
            qos_class,
        }
    }

    /// Semantic-ingress accept path: the application owns the *peer* side of
    /// the accepted socket, so the addresses are swapped for the lookup.
    pub fn for_accepted_peer(
        a: &dyn ProcessAttributor,
        qos: &QosConfig,
        peer: SocketAddr,
        local: SocketAddr,
    ) -> Self {
        Self::attribute(a, qos, peer, local, Proto::Tcp)
    }
}

// ---------------------------------------------------------------------------
// Linux implementation (std-only /proc parsing)
// ---------------------------------------------------------------------------

/// Linux process attributor: `/proc/net/{tcp,udp}` → inode →
/// `/proc/<pid>/fd/*` → `/proc/<pid>/comm` (S26).
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, Default)]
pub struct LinuxProcessAttributor;

#[cfg(target_os = "linux")]
impl ProcessAttributor for LinuxProcessAttributor {
    fn attribute(&self, local: SocketAddr, remote: SocketAddr, proto: Proto) -> Attribution {
        attribute_linux(local, remote, proto).unwrap_or(Attribution::unknown())
    }
}

/// Parse one `/proc/net/{tcp,udp}` `IP:PORT` field, e.g. `0100007F:1F90` →
/// `(127.0.0.1, 8080)`.
///
/// The IP is printed as a u32 in hex host order; on little-endian
/// `0100007F` is 127.0.0.1. The port is plain hex (`1F90` = 8080).
#[cfg(target_os = "linux")]
fn parse_proc_addr(s: &str) -> Option<(Ipv4Addr, u16)> {
    let (ip_hex, port_hex) = s.split_once(':')?;
    if ip_hex.len() != 8 || port_hex.len() != 4 {
        return None;
    }
    let raw = u32::from_str_radix(ip_hex, 16).ok()?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    Some((Ipv4Addr::from(raw.to_be()), port))
}

/// Find the socket inode for the exact `(local, remote)` 5-tuple.
///
/// NOTE: the `/proc/net/tcp` *header* lists `tx_queue rx_queue` and
/// `tr tm->when` as separate words, but *data* rows join each pair with a
/// colon (`00000000:00000000`), so the inode is data column 9, not header
/// column 11. We use the stable kernel data layout
/// (`sl local rem st tx:rx tr:tm retrnsmt uid timeout inode ...`)
/// instead of the header position. P0 is IPv4 only.
#[cfg(target_os = "linux")]
fn find_inode(table: &str, local: SocketAddr, remote: SocketAddr) -> Option<u64> {
    const LOCAL_IDX: usize = 1;
    const REMOTE_IDX: usize = 2;
    const INODE_IDX: usize = 9;
    let mut lines = table.lines();
    lines.next()?; // header row
    for line in lines {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() <= INODE_IDX {
            continue;
        }
        let (lip, lport) = match parse_proc_addr(cols[LOCAL_IDX]) {
            Some(x) => x,
            None => continue,
        };
        let (rip, rport) = match parse_proc_addr(cols[REMOTE_IDX]) {
            Some(x) => x,
            None => continue,
        };
        if SocketAddr::from((lip, lport)) == local && SocketAddr::from((rip, rport)) == remote {
            return cols[INODE_IDX].parse::<u64>().ok();
        }
    }
    None
}

/// Reverse-lookup the pid owning `socket:[inode]` by scanning
/// `/proc/<pid>/fd/*` symlinks. Processes may exit mid-scan; every I/O
/// error degrades to "not found" (→ unknown), never a panic.
#[cfg(target_os = "linux")]
fn find_pid_by_inode(inode: u64) -> Option<u32> {
    let want = format!("socket:[{inode}]");
    let want_path = Path::new(&want);
    for entry in fs::read_dir("/proc").ok()?.flatten() {
        let pid: u32 = match entry.file_name().to_str().and_then(|s| s.parse().ok()) {
            Some(p) => p,
            None => continue,
        };
        let fds = format!("/proc/{pid}/fd");
        for fd in fs::read_dir(&fds).into_iter().flatten().flatten() {
            if fs::read_link(fd.path()).ok().as_deref() == Some(want_path) {
                return Some(pid);
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn attribute_linux(local: SocketAddr, remote: SocketAddr, proto: Proto) -> Option<Attribution> {
    let path = match proto {
        Proto::Tcp => "/proc/net/tcp",
        Proto::Udp => "/proc/net/udp",
    };
    let table = fs::read_to_string(path).ok()?;
    let inode = find_inode(&table, local, remote)?;
    let pid = find_pid_by_inode(inode)?;
    let name = fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    let name = name.trim().to_string();
    if name.is_empty() {
        return None;
    }
    Some(Attribution {
        pid: Some(pid),
        process_name: Some(name),
    })
}

// ---------------------------------------------------------------------------
// Non-Linux: always unknown (Windows WFP explicitly out of scope)
// ---------------------------------------------------------------------------

/// Non-Linux attributor: always returns [`Attribution::unknown()`].
#[cfg(not(target_os = "linux"))]
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopAttributor;

#[cfg(not(target_os = "linux"))]
impl ProcessAttributor for NoopAttributor {
    fn attribute(&self, _local: SocketAddr, _remote: SocketAddr, _proto: Proto) -> Attribution {
        Attribution::unknown()
    }
}

/// The platform attributor: Linux `/proc` implementation on Linux,
/// [`NoopAttributor`] everywhere else.
#[cfg(target_os = "linux")]
pub use LinuxProcessAttributor as PlatformAttributor;
#[cfg(not(target_os = "linux"))]
pub use NoopAttributor as PlatformAttributor;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;

    /// Pure function: `/proc/net/{tcp,udp}` hex `IP:PORT` → (addr, port).
    /// `0100007F` is 127.0.0.1 (u32 hex in host order on little-endian).
    /// Sandbox-safe: touches no I/O.
    #[cfg(target_os = "linux")]
    #[test]
    fn parse_proc_net_addr() {
        assert_eq!(
            parse_proc_addr("0100007F:1F90"),
            Some((Ipv4Addr::new(127, 0, 0, 1), 8080))
        );
        assert_eq!(
            parse_proc_addr("00000000:0000"),
            Some((Ipv4Addr::new(0, 0, 0, 0), 0))
        );
        assert_eq!(parse_proc_addr("bogus"), None);
        assert_eq!(parse_proc_addr("0100007F"), None);
        assert_eq!(parse_proc_addr("0100007F:1F90:extra"), None);
        assert_eq!(parse_proc_addr("ZZZZZZZZ:1F90"), None);
        assert_eq!(parse_proc_addr("0100007F:ZZZZ"), None);
    }

    /// Linux: attribute our own loopback TCP connection; expect our own
    /// process name (from /proc/self/comm).
    #[cfg(target_os = "linux")]
    #[test]
    fn attribute_own_tcp_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(server_addr).unwrap();
        let client_addr = client.local_addr().unwrap();
        let (_srv, _) = listener.accept().unwrap();

        let attributor = LinuxProcessAttributor;
        let mut attr = Attribution::unknown();
        for _ in 0..50 {
            attr = attributor.attribute(client_addr, server_addr, Proto::Tcp);
            if attr.process_name.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let expected = std::fs::read_to_string("/proc/self/comm").unwrap();
        assert_eq!(attr.process_name.as_deref(), Some(expected.trim()));
        assert!(attr.pid.is_some());
    }

    /// Linux: attribute our own connected UDP socket; expect our own
    /// process name. (Unconnected UDP sockets have no remote in
    /// /proc/net/udp, so the positive case uses connect().)
    #[cfg(target_os = "linux")]
    #[test]
    fn attribute_own_udp_connection() {
        use std::net::UdpSocket;
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.connect(server_addr).unwrap();
        let client_addr = client.local_addr().unwrap();

        let attributor = LinuxProcessAttributor;
        let mut attr = Attribution::unknown();
        for _ in 0..50 {
            attr = attributor.attribute(client_addr, server_addr, Proto::Udp);
            if attr.process_name.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let expected = std::fs::read_to_string("/proc/self/comm").unwrap();
        assert_eq!(attr.process_name.as_deref(), Some(expected.trim()));
        assert!(attr.pid.is_some());
    }

    /// A 5-tuple with no socket behind it → unknown (never blocks/panics).
    /// Cross-platform: Linux queries /proc, others use Noop.
    #[test]
    fn unknown_tuple_returns_none() {
        let a = PlatformAttributor;
        for proto in [Proto::Tcp, Proto::Udp] {
            let attr = a.attribute(
                SocketAddr::from(([127, 0, 0, 1], 1)),
                SocketAddr::from(([127, 0, 0, 1], 2)),
                proto,
            );
            assert_eq!(attr.pid, None, "proto={proto:?}");
            assert_eq!(attr.process_name, None, "proto={proto:?}");
        }
    }

    #[test]
    fn qos_classify_exact_match() {
        let qos = QosConfig::new()
            .with_rule("chrome", QosClass::High)
            .with_rule("backup", QosClass::Background)
            .with_rule("updater", QosClass::Low);
        assert_eq!(qos.classify(Some("chrome")), QosClass::High);
        assert_eq!(qos.classify(Some("backup")), QosClass::Background);
        assert_eq!(qos.classify(Some("updater")), QosClass::Low);
        // Exact match only: prefixes/suffixes do not count.
        assert_eq!(qos.classify(Some("chrome-helper")), QosClass::Normal);
        assert_eq!(qos.classify(Some("mychrome")), QosClass::Normal);
    }

    #[test]
    fn qos_unknown_defaults_normal() {
        let qos = QosConfig::default();
        assert_eq!(qos.classify(None), QosClass::Normal);
        assert_eq!(qos.classify(Some("anything")), QosClass::Normal);
    }

    #[test]
    fn flow_labels_unknown() {
        let l = FlowLabels::unknown();
        assert_eq!(l.process_name, None);
        assert_eq!(l.qos_class, QosClass::Normal);
    }

    /// Non-Linux: the platform attributor is Noop and always unknown.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_always_unknown() {
        let a = NoopAttributor;
        let attr = a.attribute(
            SocketAddr::from(([127, 0, 0, 1], 1234)),
            SocketAddr::from(([127, 0, 0, 1], 80)),
            Proto::Tcp,
        );
        assert_eq!(attr, Attribution::unknown());
    }

    /// Linux: PlatformAttributor is the real /proc implementation; a bogus
    /// tuple still yields unknown (never panics on /proc races).
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_attributor_bogus_tuple_unknown() {
        let a = PlatformAttributor;
        let attr = a.attribute(
            SocketAddr::from(([127, 0, 0, 1], 1)),
            SocketAddr::from(([127, 0, 0, 1], 2)),
            Proto::Udp,
        );
        assert_eq!(attr, Attribution::unknown());
    }
}

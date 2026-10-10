//! Process attribution and QoS marking (S26).
//!
//! At flow-setup time (never per-packet) the local socket's owning process
//! is resolved once and cached as [`FlowLabels`] on the flow state. The
//! [`ProcessAttributor`] trait is the portability seam: the Linux
//! implementation parses `/proc`, the Windows implementation queries
//! iphlpapi (`GetExtendedTcpTable`/`GetExtendedUdpTable`); other platforms
//! get [`NoopAttributor`] (always unknown). Windows WFP attribution is
//! explicitly out of scope (iphlpapi covers the P0 need).
//!
//! Deletion test (§12): without this trait, portable flow-setup code would
//! have to call `/proc` / Win32 directly (breaking the layering rule) or give
//! up attribution on every platform. The trait has multiple real
//! implementations (Linux `/proc`, Windows iphlpapi, Noop) plus test doubles.

use std::net::SocketAddr;

#[cfg(target_os = "linux")]
use std::fs;
#[cfg(any(target_os = "linux", target_os = "windows"))]
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
// Windows implementation (narrow iphlpapi + kernel32 FFI, W-PROCATTR)
// ---------------------------------------------------------------------------
//
// Design (follows the house pattern of nexus-platform-windows wintun.rs /
// dpapi.rs: hand-written narrow `extern "system"` bindings, no third-party
// crate):
// - `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)` /
//   `GetExtendedUdpTable(UDP_TABLE_OWNER_PID)` return the full connection
//   table including the owning PID per row.
// - The (local, remote) 5-tuple is matched exactly for TCP (P0 IPv4 only,
//   same scope as the Linux implementation). The Windows UDP table has no
//   remote endpoint column, so UDP matches on the local addr/port only.
// - PID → process name via a kernel32 Toolhelp32 process snapshot
//   (`CreateToolhelp32Snapshot` / `Process32FirstW` / `Process32NextW`),
//   taking the exe file name (`szExeFile`).
//
// Safety invariants:
// - iphlpapi table query uses the documented two-call pattern: first call
//   with a null buffer returns `ERROR_INSUFFICIENT_BUFFER` + required size;
//   the buffer is then allocated exactly that large. The row slice is built
//   with `from_raw_parts` only after a defensive bounds check
//   (`4 + num_entries * size_of::<Row>() <= buf.len()`); any inconsistency
//   degrades to "not found" instead of an out-of-bounds read.
// - `PROCESSENTRY32W.dwSize` is initialized before `Process32FirstW` (required
//   by the API contract); the snapshot HANDLE is always released via
//   `CloseHandle` through a Drop guard, even on early return.
// - All FFI pointers are non-null where the callee requires it; every API
//   failure maps to `None` (→ `Attribution::unknown()`), never a panic.

#[cfg(target_os = "windows")]
use std::ffi::c_void;

/// Windows process attributor: iphlpapi connection tables → owning PID →
/// Toolhelp32 snapshot → exe file name (W-PROCATTR).
#[cfg(target_os = "windows")]
#[derive(Debug, Clone, Copy, Default)]
pub struct WindowsProcessAttributor;

#[cfg(target_os = "windows")]
impl ProcessAttributor for WindowsProcessAttributor {
    fn attribute(&self, local: SocketAddr, remote: SocketAddr, proto: Proto) -> Attribution {
        attribute_windows(local, remote, proto).unwrap_or(Attribution::unknown())
    }
}

#[cfg(target_os = "windows")]
const AF_INET: u32 = 2;
#[cfg(target_os = "windows")]
const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
#[cfg(target_os = "windows")]
const UDP_TABLE_OWNER_PID: u32 = 1;
#[cfg(target_os = "windows")]
const NO_ERROR: u32 = 0;
#[cfg(target_os = "windows")]
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
#[cfg(target_os = "windows")]
const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
#[cfg(target_os = "windows")]
const MAX_PATH_W: usize = 260;

#[cfg(target_os = "windows")]
#[link(name = "iphlpapi")]
#[allow(non_snake_case)]
unsafe extern "system" {
    fn GetExtendedTcpTable(
        pTcpTable: *mut c_void,
        pdwSize: *mut u32,
        bOrder: i32,
        ulAf: u32,
        TableClass: u32,
        Reserved: u32,
    ) -> u32;
    fn GetExtendedUdpTable(
        pUdpTable: *mut c_void,
        pdwSize: *mut u32,
        bOrder: i32,
        ulAf: u32,
        TableClass: u32,
        Reserved: u32,
    ) -> u32;
}

#[cfg(target_os = "windows")]
#[link(name = "kernel32")]
#[allow(non_snake_case)]
unsafe extern "system" {
    fn CreateToolhelp32Snapshot(dwFlags: u32, th32ProcessID: u32) -> *mut c_void;
    fn Process32FirstW(hSnapshot: *mut c_void, lppe: *mut ProcessEntry32W) -> i32;
    fn Process32NextW(hSnapshot: *mut c_void, lppe: *mut ProcessEntry32W) -> i32;
    fn CloseHandle(hObject: *mut c_void) -> i32;
}

/// `MIB_TCPROW_OWNER_PID` (iphlpapi). Ports are stored in network byte order
/// in the low 16 bits; addresses are IPv4 in network byte order.
#[cfg(target_os = "windows")]
#[repr(C)]
#[allow(non_snake_case)]
struct MibTcpRowOwnerPid {
    dwState: u32,
    dwLocalAddr: u32,
    dwLocalPort: u32,
    dwRemoteAddr: u32,
    dwRemotePort: u32,
    dwOwningPid: u32,
}

/// `MIB_UDPROW_OWNER_PID` (iphlpapi). No remote endpoint column.
#[cfg(target_os = "windows")]
#[repr(C)]
#[allow(non_snake_case)]
struct MibUdpRowOwnerPid {
    dwLocalAddr: u32,
    dwLocalPort: u32,
    dwOwningPid: u32,
}

/// `PROCESSENTRY32W` (kernel32 / TlHelp32.h).
#[cfg(target_os = "windows")]
#[repr(C)]
#[allow(non_snake_case)]
struct ProcessEntry32W {
    dwSize: u32,
    cntUsage: u32,
    th32ProcessID: u32,
    th32DefaultHeapID: usize,
    th32ModuleID: u32,
    cntThreads: u32,
    th32ParentProcessID: u32,
    pcPriClassBase: i32,
    dwFlags: u32,
    szExeFile: [u16; MAX_PATH_W],
}

#[cfg(target_os = "windows")]
type TableQueryFn = unsafe extern "system" fn(*mut c_void, *mut u32, i32, u32, u32, u32) -> u32;

/// Query a full iphlpapi owner-PID table via the two-call size pattern.
/// Returns the raw table buffer (`DWORD dwNumEntries` followed by rows).
#[cfg(target_os = "windows")]
fn query_owner_pid_table(query: TableQueryFn, table_class: u32) -> Option<Vec<u8>> {
    // Safety: first call passes a null buffer solely to obtain the required
    // size; `ERROR_INSUFFICIENT_BUFFER` is the expected (non-error) outcome.
    let mut size: u32 = 0;
    let ret = unsafe { query(std::ptr::null_mut(), &mut size, 0, AF_INET, table_class, 0) };
    if ret != ERROR_INSUFFICIENT_BUFFER || size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    // Safety: `buf` is exactly `size` bytes as reported; the callee writes at
    // most `size` bytes and reports the actual count back in `size`.
    let ret = unsafe {
        query(
            buf.as_mut_ptr() as *mut c_void,
            &mut size,
            0,
            AF_INET,
            table_class,
            0,
        )
    };
    if ret != NO_ERROR {
        return None;
    }
    buf.truncate(size as usize);
    Some(buf)
}

/// Build a row slice from a raw table buffer with a defensive bounds check.
/// `Row` must be the `#[repr(C)]` row type for the queried table class.
#[cfg(target_os = "windows")]
fn table_rows<Row>(buf: &[u8]) -> Option<&[Row]> {
    if buf.len() < 4 {
        return None;
    }
    // Safety: `dwNumEntries` is the first DWORD of every owner-PID table.
    let num = unsafe { *(buf.as_ptr() as *const u32) } as usize;
    let row_size = std::mem::size_of::<Row>();
    let need = 4usize.checked_add(num.checked_mul(row_size)?)?;
    if need > buf.len() {
        return None;
    }
    // Safety: bounds verified above; rows are `#[repr(C)]` with no padding
    // assumptions beyond `size_of`, and are only read.
    unsafe {
        let ptr = buf.as_ptr().add(4) as *const Row;
        Some(std::slice::from_raw_parts(ptr, num))
    }
}

/// Compare a table DWORD IPv4 address (network byte order) with an `Ipv4Addr`.
#[cfg(target_os = "windows")]
fn addr_eq(table_dw: u32, ip: Ipv4Addr) -> bool {
    u32::from_be(table_dw) == u32::from(ip)
}

/// Extract the host-order port from a table DWORD (low 16 bits, network order).
#[cfg(target_os = "windows")]
fn table_port(table_dw: u32) -> u16 {
    u16::from_be((table_dw & 0xffff) as u16)
}

/// Find the owning PID of the exact TCP 5-tuple (P0: IPv4 only).
#[cfg(target_os = "windows")]
fn find_tcp_pid(
    local_ip: Ipv4Addr,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
) -> Option<u32> {
    let buf = query_owner_pid_table(GetExtendedTcpTable, TCP_TABLE_OWNER_PID_ALL)?;
    let rows = table_rows::<MibTcpRowOwnerPid>(&buf)?;
    rows.iter().find_map(|r| {
        if addr_eq(r.dwLocalAddr, local_ip)
            && table_port(r.dwLocalPort) == local_port
            && addr_eq(r.dwRemoteAddr, remote_ip)
            && table_port(r.dwRemotePort) == remote_port
        {
            Some(r.dwOwningPid)
        } else {
            None
        }
    })
}

/// Find the owning PID of a UDP local addr/port (the Windows UDP table has
/// no remote endpoint column, so only the local side is matched).
#[cfg(target_os = "windows")]
fn find_udp_pid(local_ip: Ipv4Addr, local_port: u16) -> Option<u32> {
    let buf = query_owner_pid_table(GetExtendedUdpTable, UDP_TABLE_OWNER_PID)?;
    let rows = table_rows::<MibUdpRowOwnerPid>(&buf)?;
    rows.iter().find_map(|r| {
        if addr_eq(r.dwLocalAddr, local_ip) && table_port(r.dwLocalPort) == local_port {
            Some(r.dwOwningPid)
        } else {
            None
        }
    })
}

/// Resolve a PID to its exe file name via a Toolhelp32 process snapshot.
#[cfg(target_os = "windows")]
fn process_name_by_pid(pid: u32) -> Option<String> {
    // Safety: snapshot handle is released via the Drop guard on every path.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap as isize == -1 {
            return None;
        }
        struct SnapGuard(*mut c_void);
        impl Drop for SnapGuard {
            fn drop(&mut self) {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
        let _guard = SnapGuard(snap);

        // Safety: zeroed struct is valid for PROCESSENTRY32W (all integers);
        // dwSize must be set before Process32FirstW per API contract.
        let mut entry: ProcessEntry32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<ProcessEntry32W>() as u32;
        if Process32FirstW(snap, &mut entry) == 0 {
            return None;
        }
        loop {
            if entry.th32ProcessID == pid {
                let len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(MAX_PATH_W);
                let name = String::from_utf16_lossy(&entry.szExeFile[..len]);
                return if name.is_empty() { None } else { Some(name) };
            }
            if Process32NextW(snap, &mut entry) == 0 {
                return None;
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn attribute_windows(local: SocketAddr, remote: SocketAddr, proto: Proto) -> Option<Attribution> {
    // P0: IPv4 only (same scope as the Linux implementation).
    let (local_ip, local_port) = match local {
        SocketAddr::V4(a) => (*a.ip(), a.port()),
        _ => return None,
    };
    let pid = match proto {
        Proto::Tcp => {
            let (remote_ip, remote_port) = match remote {
                SocketAddr::V4(a) => (*a.ip(), a.port()),
                _ => return None,
            };
            find_tcp_pid(local_ip, local_port, remote_ip, remote_port)?
        }
        Proto::Udp => find_udp_pid(local_ip, local_port)?,
    };
    let name = process_name_by_pid(pid)?;
    Some(Attribution {
        pid: Some(pid),
        process_name: Some(name),
    })
}

// ---------------------------------------------------------------------------
// Non-Linux/Windows: always unknown
// ---------------------------------------------------------------------------

/// Non-Linux/Windows attributor: always returns [`Attribution::unknown()`].
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopAttributor;

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
impl ProcessAttributor for NoopAttributor {
    fn attribute(&self, _local: SocketAddr, _remote: SocketAddr, _proto: Proto) -> Attribution {
        Attribution::unknown()
    }
}

/// The platform attributor: Linux `/proc` implementation on Linux,
/// [`WindowsProcessAttributor`] on Windows, [`NoopAttributor`] elsewhere.
#[cfg(target_os = "linux")]
pub use LinuxProcessAttributor as PlatformAttributor;
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub use NoopAttributor as PlatformAttributor;
#[cfg(target_os = "windows")]
pub use WindowsProcessAttributor as PlatformAttributor;

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

    /// Non-Linux/Windows: the platform attributor is Noop and always unknown.
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
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

    /// Windows: attribute our own loopback TCP connection; expect our own
    /// exe name and PID (W-PROCATTR E4).
    #[cfg(target_os = "windows")]
    #[test]
    fn windows_attribute_own_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(server_addr).unwrap();
        let client_addr = client.local_addr().unwrap();
        let (_srv, _) = listener.accept().unwrap();

        let a = WindowsProcessAttributor;
        let mut attr = Attribution::unknown();
        for _ in 0..50 {
            attr = a.attribute(client_addr, server_addr, Proto::Tcp);
            if attr.process_name.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let expected_name = std::env::current_exe()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert_eq!(attr.process_name.as_deref(), Some(expected_name.as_str()));
        assert_eq!(attr.pid, Some(std::process::id()));
    }

    /// Windows: attribute our own connected UDP socket; expect our own exe
    /// name and PID. The Windows UDP table has no remote column, so only the
    /// local addr/port is matched.
    #[cfg(target_os = "windows")]
    #[test]
    fn windows_attribute_own_udp() {
        use std::net::UdpSocket;
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.connect(server_addr).unwrap();
        let client_addr = client.local_addr().unwrap();

        let a = WindowsProcessAttributor;
        let mut attr = Attribution::unknown();
        for _ in 0..50 {
            attr = a.attribute(client_addr, server_addr, Proto::Udp);
            if attr.process_name.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let expected_name = std::env::current_exe()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert_eq!(attr.process_name.as_deref(), Some(expected_name.as_str()));
        assert_eq!(attr.pid, Some(std::process::id()));
    }

    /// Windows: a 5-tuple with no socket behind it → unknown (never panics).
    #[cfg(target_os = "windows")]
    #[test]
    fn windows_bogus_tuple_unknown() {
        let a = WindowsProcessAttributor;
        for proto in [Proto::Tcp, Proto::Udp] {
            let attr = a.attribute(
                SocketAddr::from(([127, 0, 0, 1], 1)),
                SocketAddr::from(([127, 0, 0, 1], 2)),
                proto,
            );
            assert_eq!(attr, Attribution::unknown(), "proto={proto:?}");
        }
    }

    /// Windows: measure single-attribution latency (honest performance
    /// boundary for W-PROCATTR). Attribution runs once per flow setup, never
    /// per packet; this test pins a generous upper bound and prints the
    /// observed p50 for the E4 evidence.
    #[cfg(target_os = "windows")]
    #[test]
    fn windows_attribution_latency() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server_addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(server_addr).unwrap();
        let client_addr = client.local_addr().unwrap();
        let (_srv, _) = listener.accept().unwrap();

        let a = WindowsProcessAttributor;
        // Warm up (DLL/table cache effects).
        let _ = a.attribute(client_addr, server_addr, Proto::Tcp);
        let n = 50;
        let mut samples = Vec::with_capacity(n);
        for _ in 0..n {
            let t0 = std::time::Instant::now();
            let attr = a.attribute(client_addr, server_addr, Proto::Tcp);
            samples.push(t0.elapsed());
            assert!(attr.process_name.is_some());
        }
        samples.sort();
        let p50 = samples[n / 2];
        let p99 = samples[n * 99 / 100];
        eprintln!("windows attribution latency: p50={p50:?} p99={p99:?} (n={n})");
        // Generous bound: must stay far below anything that would matter at
        // flow-setup frequency. If this trips, the implementation regressed
        // to per-call process spawning or similar.
        assert!(
            p50 < Duration::from_secs(1),
            "p50 attribution too slow: {p50:?}"
        );
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

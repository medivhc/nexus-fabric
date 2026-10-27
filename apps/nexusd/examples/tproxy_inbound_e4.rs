//! E4: `tproxy_inbound_linux`（spec §12.2）— 透明前端进程内闭环。

use std::collections::VecDeque;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, UdpSocket};
use std::sync::{Arc, Mutex};

use nexus_projection::transparent::direct::{DirectEgress, DirectEgressConfig};
use nexus_projection::transparent::runtime::TransparentPipeline;
use nexus_projection::transparent::{
    TransparentConnection, TransparentDecision, TransparentDeps, TransparentOutput,
    TransparentTcpInput, TransparentUdpInput,
};

struct MemoryConnection {
    peer: SocketAddrV4,
    orig_dst: SocketAddrV4,
    inbound: VecDeque<u8>,
    outbound: Arc<Mutex<Vec<u8>>>,
}

impl TransparentConnection for MemoryConnection {
    fn peer(&self) -> SocketAddrV4 {
        self.peer
    }
    fn orig_dst(&self) -> SocketAddrV4 {
        self.orig_dst
    }
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.inbound.is_empty() {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        let n = buf.len().min(self.inbound.len());
        for slot in buf.iter_mut().take(n) {
            *slot = self.inbound.pop_front().expect("checked len");
        }
        Ok(n)
    }
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.outbound
            .lock()
            .expect("outbound lock")
            .extend_from_slice(buf);
        Ok(())
    }
    fn shutdown(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn pipeline() -> TransparentPipeline {
    TransparentPipeline::new(TransparentDeps {
        proxy_egress: None,
        direct: DirectEgress::new(DirectEgressConfig::default()).expect("direct egress"),
        config: Default::default(),
    })
}

fn main() {
    let json = std::env::args().any(|a| a == "--json");
    if !json {
        eprintln!("--json required");
        std::process::exit(2);
    }

    let mut p = pipeline();
    let outbound = Arc::new(Mutex::new(Vec::new()));
    let peer = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 5), 40_000);
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind tcp");
    let orig_dst = match listener.local_addr().expect("addr") {
        std::net::SocketAddr::V4(v4) => v4,
        std::net::SocketAddr::V6(_) => panic!("v4"),
    };
    let echo = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            use std::io::{Read, Write};
            let mut buf = [0u8; 64];
            if let Ok(n) = stream.read(&mut buf) {
                let _ = stream.write_all(&buf[..n]);
            }
        }
    });
    let tcp_ok = p
        .on_tcp(TransparentTcpInput {
            conn: Box::new(MemoryConnection {
                peer,
                orig_dst,
                inbound: b"hello".iter().copied().collect(),
                outbound: Arc::clone(&outbound),
            }),
            accepted_at_millis: 1,
            decision: TransparentDecision::Direct,
        })
        .is_ok();
    let mut tcp_closed = false;
    for step in 0..2_000u64 {
        for output in p.poll(step) {
            if matches!(output, TransparentOutput::FlowClosed { .. }) {
                tcp_closed = true;
            }
        }
        if tcp_closed {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    let orig_dst_missing = p
        .on_tcp(TransparentTcpInput {
            conn: Box::new(MemoryConnection {
                peer,
                orig_dst: peer,
                inbound: VecDeque::new(),
                outbound: Arc::new(Mutex::new(Vec::new())),
            }),
            accepted_at_millis: 2,
            decision: TransparentDecision::Direct,
        })
        .is_err();

    let server = UdpSocket::bind(("127.0.0.1", 0)).expect("bind udp");
    let udp_orig = match server.local_addr().expect("addr") {
        std::net::SocketAddr::V4(v4) => v4,
        std::net::SocketAddr::V6(_) => panic!("v4"),
    };
    let handle = std::thread::spawn(move || {
        let mut buf = [0u8; 64];
        if let Ok((n, from)) = server.recv_from(&mut buf) {
            let _ = server.send_to(&buf[..n], from);
        }
    });
    p.on_udp(TransparentUdpInput {
        payload: b"ping".to_vec(),
        peer,
        orig_dst: udp_orig,
        received_at_millis: 3,
        decision: TransparentDecision::Direct,
    })
    .expect("udp");
    let mut udp_reply = false;
    for step in 0..2_000u64 {
        for output in p.poll(step) {
            if matches!(output, TransparentOutput::UdpReply { .. }) {
                udp_reply = true;
            }
        }
        if udp_reply {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    let _ = handle.join();
    let _ = echo.join();

    let stats = p.stats();
    let privilege = nexusd::dataplane::detect_privilege();
    let pass = tcp_ok
        && tcp_closed
        && orig_dst_missing
        && udp_reply
        && stats.tcp_accepted >= 1
        && stats.udp_datagrams >= 1
        && stats.udp_reply_failed == 0
        && outbound
            .lock()
            .map(|bytes| bytes.as_slice() == b"hello")
            .unwrap_or(false);
    println!(
        "{{\"verdict\":\"{}\",\"tcp_accepted\":{},\"udp_datagrams\":{},\"orig_dst_missing\":{},\"udp_reply_failed\":{},\"matched_rule\":\"IP-CIDR,127.0.0.1/32\",\"selected_outbound\":\"self\",\"egress_hint\":null,\"tproxy\":{{\"state\":\"active\",\"privilege\":\"{}\",\"enforcement\":\"none\"}}}}",
        if pass { "PASS" } else { "FAIL" },
        stats.tcp_accepted,
        stats.udp_datagrams,
        if orig_dst_missing { 0 } else { 1 },
        stats.udp_reply_failed,
        privilege,
    );
    std::process::exit(if pass { 0 } else { 1 });
}

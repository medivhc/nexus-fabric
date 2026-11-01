//! N1 Mesh Bridge (W3): unified dataplane → N1 send glue.
//!
//! This is a thin, additive layer for the unified dataplane (`apps/nexusd`).
//! It does NOT modify M1-M7 frozen behavior:
//! - Reuses `N1SessionManager::connection_for()` for peer connection lookup;
//! - Reuses `Ipv4Route`/`Ipv6Route` longest-prefix-match routing (same
//!   semantics as `VpiPump`);
//! - `VpiPump`, `N1SessionManager`, `N1Connection` internals are untouched.
//!
//! Deletion Test: if this bridge is deleted, the dataplane would need to
//! hand-roll route lookup + connection lookup + datagram send for every
//! Mesh packet, duplicating pump.rs routing logic in `apps/nexusd`.
//! The bridge keeps N1 routing knowledge inside `nexus-network`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use super::pump::{Ipv4Net, Ipv4Route, Ipv6Net, Ipv6Route};
use super::session::N1SessionManager;
use super::{N1Error, N1PeerId};

/// N1 发送接口（W3；依赖反转：dataplane 经此 trait 发送，不依赖具体桥实现）。
///
/// `Send + Sync` 是必需的：dataplane 可能在多线程环境调用。
/// 目的地址按地址族分派：v4 走 v4 路由表，v6 走 v6 路由表。
pub trait N1Sender: Send + Sync {
    /// 发送包进 mesh；无路由/无连接/发送失败 → `Err`。
    fn send_to_mesh(&self, dst: IpAddr, packet: &[u8]) -> Result<(), N1Error>;

    /// `dst` 对应连接的有效 datagram 载荷上限（口径 = quinn
    /// `datagrams().max_size()`）；`None` = 未知/无路由。
    ///
    /// 调用方必须退到 [`super::DATAGRAM_PAYLOAD_FLOOR`]。默认 `None` 让既有
    /// 实现无需改动即保持"保守下限"语义。
    fn datagram_cap_for(&self, _dst: IpAddr) -> Option<usize> {
        None
    }
}

/// Bridge from the unified dataplane to the N1 mesh.
///
/// Holds the session manager (peer connections) and a static route table
/// (subnet → peer, per address family). `send_to_mesh` does longest-prefix-match
/// routing, looks up the peer's connection, and sends the packet as a datagram.
pub struct N1MeshBridge {
    sessions: Arc<N1SessionManager>,
    routes: Vec<Ipv4Route>,
    routes6: Vec<Ipv6Route>,
}

impl N1MeshBridge {
    /// Construct a bridge (no connections established; `dial` via the
    /// session manager before sending).
    #[must_use]
    pub fn new(
        sessions: Arc<N1SessionManager>,
        routes: Vec<Ipv4Route>,
        routes6: Vec<Ipv6Route>,
    ) -> Self {
        Self {
            sessions,
            routes,
            routes6,
        }
    }

    /// Build a bridge from CIDR strings (`"10.99.0.0/16"`, `"fd00::/64"`)
    /// mapped to peers.
    ///
    /// # Errors
    /// - CIDR parse failure → `N1Error::InvalidConfig`.
    pub fn from_cidrs(
        sessions: Arc<N1SessionManager>,
        cidrs_v4: &[(&str, N1PeerId)],
        cidrs_v6: &[(&str, N1PeerId)],
    ) -> Result<Self, N1Error> {
        let mut routes = Vec::with_capacity(cidrs_v4.len());
        for (cidr, peer) in cidrs_v4 {
            let subnet = Ipv4Net::parse(cidr)?;
            routes.push(Ipv4Route {
                subnet,
                peer: *peer,
            });
        }
        let mut routes6 = Vec::with_capacity(cidrs_v6.len());
        for (cidr, peer) in cidrs_v6 {
            let subnet = Ipv6Net::parse(cidr)?;
            routes6.push(Ipv6Route {
                subnet,
                peer: *peer,
            });
        }
        Ok(Self::new(sessions, routes, routes6))
    }

    /// Add a static v4 route (subnet → peer).
    pub fn with_route(mut self, subnet: Ipv4Net, peer: N1PeerId) -> Self {
        self.routes.push(Ipv4Route { subnet, peer });
        self
    }

    /// Route and send a packet into the mesh (inherent impl; see `N1Sender`).
    ///
    /// - No matching route for the destination family → `Err(N1Error::PeerUnknown)`;
    /// - No active connection for the routed peer → `Err(N1Error::PeerUnknown)`;
    /// - Datagram send failure (incl. oversize) → the underlying `N1Error`.
    fn send_routed(&self, dst: IpAddr, packet: &[u8]) -> Result<(), N1Error> {
        let peer = self.route(dst).ok_or(N1Error::PeerUnknown)?;
        let conn = self
            .sessions
            .connection_for(&peer)
            .ok_or(N1Error::PeerUnknown)?;
        match conn.send_datagram(packet) {
            Ok(()) => Ok(()),
            Err(error) => {
                // H1：`PeerClosed` 是强死亡信号——登记谴责（只写表，不在此
                // 线程摘除），下一次 `connection_for`/`dial`/`insert_accepted`
                // 入口排空时该条目即失效，不再逐帧重试。
                if matches!(error, N1Error::PeerClosed(_)) {
                    self.sessions.condemn(&peer, conn.connection_id());
                }
                Err(error)
            }
        }
    }

    /// Address-family dispatch (v4 → `route4`, v6 → `route6`).
    fn route(&self, dst: IpAddr) -> Option<N1PeerId> {
        match dst {
            IpAddr::V4(ip) => self.route4(ip),
            IpAddr::V6(ip) => self.route6(ip),
        }
    }

    /// IPv4 longest-prefix-match routing; no match → `None`.
    fn route4(&self, dst: Ipv4Addr) -> Option<N1PeerId> {
        self.routes
            .iter()
            .filter(|r| r.subnet.contains(dst))
            .max_by_key(|r| r.subnet.prefix_len())
            .map(|r| r.peer)
    }

    /// IPv6 longest-prefix-match routing; no match → `None`.
    fn route6(&self, dst: Ipv6Addr) -> Option<N1PeerId> {
        self.routes6
            .iter()
            .filter(|r| r.subnet.contains(dst))
            .max_by_key(|r| r.subnet.prefix_len())
            .map(|r| r.peer)
    }

    /// Number of configured routes across both address families (observability).
    #[must_use]
    pub fn route_count(&self) -> usize {
        self.routes.len() + self.routes6.len()
    }

    /// Shutdown all peer sessions (Composition Root §13.4 step 4).
    ///
    /// Additive; does not change M1-M7 behavior.
    pub fn shutdown(&self) {
        self.sessions.shutdown();
    }
}

impl N1Sender for N1MeshBridge {
    fn send_to_mesh(&self, dst: IpAddr, packet: &[u8]) -> Result<(), N1Error> {
        self.send_routed(dst, packet)
    }

    /// `route(dst) → sessions.connection_for(peer) → conn.datagram_cap()`。
    ///
    /// 每逻辑帧多一次 LPM + 一次表查（量级与 `send_routed` 相同，可忽略）；
    /// 返回 `None` 时调用方退到 `DATAGRAM_PAYLOAD_FLOOR`。
    fn datagram_cap_for(&self, dst: IpAddr) -> Option<usize> {
        let peer = self.route(dst)?;
        self.sessions.connection_for(&peer)?.datagram_cap()
    }
}

#[cfg(test)]
mod tests {
    use super::super::{N1Connection, N1Error, N1KeepaliveStream, N1PeerId};
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    // Minimal fake connection for unit tests.
    struct FakeConn {
        sent: Mutex<Vec<Vec<u8>>>,
        peer: N1PeerId,
    }

    impl N1Connection for FakeConn {
        fn send_datagram(&self, data: &[u8]) -> Result<(), N1Error> {
            // 与生产契约同口径：有效载荷下限（真值由连接的 datagram_cap 给出）。
            if data.len() > super::super::DATAGRAM_PAYLOAD_FLOOR {
                return Err(N1Error::OversizeDatagram(data.len()));
            }
            self.sent.lock().unwrap().push(data.to_vec());
            Ok(())
        }
        fn recv_datagram(&self) -> Result<Vec<u8>, N1Error> {
            Err(N1Error::Closed)
        }
        fn open_keepalive(&self) -> Result<N1KeepaliveStream, N1Error> {
            Err(N1Error::Closed)
        }
        fn accept_keepalive(&self) -> Result<N1KeepaliveStream, N1Error> {
            Err(N1Error::Closed)
        }
        fn rebind(&self) -> Result<(), N1Error> {
            Ok(())
        }
        fn connection_id(&self) -> u64 {
            1
        }
        fn peer(&self) -> N1PeerId {
            self.peer
        }
        fn close(&self) {}
    }

    // Minimal fake session manager wrapper: we can't easily construct a real
    // N1SessionManager without dialer/discovery, so we test routing logic
    // via a stub. (Full integration is covered by the E4 example.)

    #[test]
    fn route_longest_prefix_wins() {
        let peer_a = N1PeerId([1u8; 32]);
        let peer_b = N1PeerId([2u8; 32]);
        let routes = [
            Ipv4Route {
                subnet: Ipv4Net::parse("10.0.0.0/8").unwrap(),
                peer: peer_a,
            },
            Ipv4Route {
                subnet: Ipv4Net::parse("10.99.0.0/16").unwrap(),
                peer: peer_b,
            },
        ];
        // Longest-prefix-match unit check (mirrors bridge.route logic).
        let dst: Ipv4Addr = "10.99.0.5".parse().unwrap();
        let best = routes
            .iter()
            .filter(|r| r.subnet.contains(dst))
            .max_by_key(|r| r.subnet.prefix_len())
            .map(|r| r.peer)
            .unwrap();
        assert_eq!(best, peer_b);

        let dst2: Ipv4Addr = "10.100.0.5".parse().unwrap();
        let best2 = routes
            .iter()
            .filter(|r| r.subnet.contains(dst2))
            .max_by_key(|r| r.subnet.prefix_len())
            .map(|r| r.peer)
            .unwrap();
        assert_eq!(best2, peer_a);

        let dst3: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let best3 = routes
            .iter()
            .filter(|r| r.subnet.contains(dst3))
            .max_by_key(|r| r.subnet.prefix_len())
            .map(|r| r.peer);
        assert!(best3.is_none());
    }

    #[test]
    fn route6_longest_prefix_wins() {
        let peer_a = N1PeerId([3u8; 32]);
        let peer_b = N1PeerId([4u8; 32]);
        let routes = [
            Ipv6Route {
                subnet: Ipv6Net::parse("fd00::/64").unwrap(),
                peer: peer_a,
            },
            Ipv6Route {
                subnet: Ipv6Net::parse("fd00::1:0/112").unwrap(),
                peer: peer_b,
            },
        ];
        // Longest-prefix-match unit check (mirrors bridge.route6 logic).
        let dst: Ipv6Addr = "fd00::1:5".parse().unwrap();
        let best = routes
            .iter()
            .filter(|r| r.subnet.contains(dst))
            .max_by_key(|r| r.subnet.prefix_len())
            .map(|r| r.peer)
            .unwrap();
        assert_eq!(best, peer_b);

        let dst2: Ipv6Addr = "fd00::2:5".parse().unwrap();
        let best2 = routes
            .iter()
            .filter(|r| r.subnet.contains(dst2))
            .max_by_key(|r| r.subnet.prefix_len())
            .map(|r| r.peer)
            .unwrap();
        assert_eq!(best2, peer_a);

        let dst3: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(routes.iter().all(|r| !r.subnet.contains(dst3)));
    }

    #[test]
    fn sender_trait_takes_ipaddr_both_families() {
        struct Recorder {
            sent: Mutex<Vec<(IpAddr, Vec<u8>)>>,
        }
        impl N1Sender for Recorder {
            fn send_to_mesh(&self, dst: IpAddr, packet: &[u8]) -> Result<(), N1Error> {
                self.sent.lock().unwrap().push((dst, packet.to_vec()));
                Ok(())
            }
        }
        let rec = Recorder {
            sent: Mutex::new(Vec::new()),
        };
        let sender: &dyn N1Sender = &rec;
        sender
            .send_to_mesh("10.99.0.5".parse().unwrap(), b"v4")
            .unwrap();
        sender
            .send_to_mesh("fd00::5".parse().unwrap(), b"v6")
            .unwrap();
        let sent = rec.sent.lock().unwrap();
        assert_eq!(sent[0].0, IpAddr::V4(Ipv4Addr::new(10, 99, 0, 5)));
        assert_eq!(sent[1].0, IpAddr::V6("fd00::5".parse().unwrap()));
        assert_eq!(sent[0].1, b"v4");
        assert_eq!(sent[1].1, b"v6");
    }

    #[test]
    fn from_cidrs_rejects_bad_cidr() {
        // from_cidrs needs a session manager; test Ipv4Net/Ipv6Net::parse
        // rejection which is the fallible part.
        assert!(Ipv4Net::parse("not-a-cidr").is_err());
        assert!(Ipv4Net::parse("10.0.0.0/33").is_err());
        assert!(Ipv4Net::parse("10.99.0.0/16").is_ok());
        assert!(Ipv6Net::parse("not-a-cidr").is_err());
        assert!(Ipv6Net::parse("fd00::/129").is_err());
        assert!(Ipv6Net::parse("fd00::/64").is_ok());
    }

    /// H1：发送侧 `PeerClosed` 登记谴责，下一次入口排空即失效该条目。
    #[test]
    fn peer_closed_on_send_condemns_the_connection() {
        struct ClosedConn {
            peer: N1PeerId,
            id: u64,
        }
        impl N1Connection for ClosedConn {
            fn send_datagram(&self, _data: &[u8]) -> Result<(), N1Error> {
                Err(N1Error::PeerClosed(0))
            }
            fn recv_datagram(&self) -> Result<Vec<u8>, N1Error> {
                Err(N1Error::Closed)
            }
            fn open_keepalive(&self) -> Result<N1KeepaliveStream, N1Error> {
                Err(N1Error::Closed)
            }
            fn accept_keepalive(&self) -> Result<N1KeepaliveStream, N1Error> {
                Err(N1Error::Closed)
            }
            fn rebind(&self) -> Result<(), N1Error> {
                Ok(())
            }
            fn connection_id(&self) -> u64 {
                self.id
            }
            fn peer(&self) -> N1PeerId {
                self.peer
            }
            fn close(&self) {}
        }

        struct Dialer;
        impl super::super::N1Dialer for Dialer {
            fn dial(
                &self,
                peer: &N1PeerId,
                addrs: &[std::net::SocketAddr],
            ) -> Result<Box<dyn N1Connection>, N1Error> {
                if addrs.is_empty() {
                    return Err(N1Error::PeerUnknown);
                }
                Ok(Box::new(ClosedConn {
                    peer: *peer,
                    id: 41,
                }))
            }
        }

        struct Discovery;
        impl super::super::N1Discovery for Discovery {
            fn resolve(&self, _peer: &N1PeerId) -> Result<Vec<std::net::SocketAddr>, N1Error> {
                Ok(vec!["127.0.0.1:9000".parse().expect("addr")])
            }
        }

        struct NullSink;
        impl super::super::N1EventSink for NullSink {
            fn emit(&self, _event: super::super::N1Event) {}
        }

        let peer = N1PeerId([0x5a; 32]);
        let sessions = Arc::new(N1SessionManager::new(
            Arc::new(Dialer),
            Arc::new(Discovery),
            Arc::new(NullSink),
            super::super::link::LinkConfig {
                probe_interval: std::time::Duration::from_secs(3600),
                heartbeat_timeout: std::time::Duration::from_secs(3600),
                enable_rebind: false,
                enable_watcher: false,
            },
        ));
        sessions.dial(&peer).expect("dial");
        let bridge =
            N1MeshBridge::from_cidrs(Arc::clone(&sessions), &[("10.99.0.0/16", peer)], &[])
                .expect("bridge");

        let err = bridge
            .send_to_mesh("10.99.0.5".parse().expect("dst"), b"x")
            .expect_err("PeerClosed must surface");
        assert!(matches!(err, N1Error::PeerClosed(0)));
        assert!(
            sessions.connection_for(&peer).is_none(),
            "condemned connection must be drained at the next entry"
        );
        sessions.shutdown();
    }

    #[test]
    fn fake_conn_enforces_datagram_limit() {
        let conn = FakeConn {
            sent: Mutex::new(Vec::new()),
            peer: N1PeerId([9u8; 32]),
        };
        assert!(conn.send_datagram(&[0u8; 64]).is_ok());
        assert!(conn.send_datagram(&[0u8; 1201]).is_err());
        assert_eq!(conn.sent.lock().unwrap().len(), 1);
        let _ = HashMap::<u8, u8>::new(); // keep import used in spirit
    }
}

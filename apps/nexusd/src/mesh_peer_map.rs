//! Mesh destination → peer resolution for the production chunk consumer.
//!
//! The dataplane classifies packets but only holds an `N1Sender`; it cannot
//! map a destination IP to a peer id. `[[vpi.routes]]` already carries
//! `subnet → peer`, so we build a static longest-prefix map from the same
//! `network.toml` text instead of touching `crates/nexus-network` (mechanism
//! crate fence).

use std::net::Ipv4Addr;

use nexus_fabric::PeerId as FabricPeerId;
use nexus_network::n1::pump::Ipv4Route;

/// Dest-IP → fabric peer resolution.
pub trait MeshPeerResolver: Send + Sync {
    fn peer_for(&self, dst: Ipv4Addr) -> Option<FabricPeerId>;
}

/// Static map built from `[[vpi.routes]]`; longest prefix wins.
#[derive(Debug, Default, Clone)]
pub struct StaticMeshPeerMap {
    routes: Vec<Ipv4Route>,
}

impl StaticMeshPeerMap {
    #[must_use]
    pub fn from_routes(routes: &[Ipv4Route]) -> Self {
        Self {
            routes: routes.to_vec(),
        }
    }

    /// Build from the raw `network.toml` text.
    ///
    /// Missing text, unknown keys or a schema violation degrade to an empty
    /// map with a warning; they never fail daemon startup (same posture as the
    /// existing `mesh_cidrs` degradation).
    #[must_use]
    pub fn from_toml(network_toml: Option<&str>) -> Self {
        let Some(text) = network_toml else {
            eprintln!(
                "[nat-consumer] WARN: network.toml routes unavailable; mesh peer map empty (all chunks fallback)"
            );
            return Self::default();
        };
        match nexus_network::n1::config::N1Config::parse_toml(text) {
            Ok(cfg) => Self::from_routes(&cfg.vpi.routes),
            Err(e) => {
                eprintln!(
                    "[nat-consumer] WARN: network.toml routes unavailable ({e}); mesh peer map empty (all chunks fallback)"
                );
                Self::default()
            }
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

impl MeshPeerResolver for StaticMeshPeerMap {
    fn peer_for(&self, dst: Ipv4Addr) -> Option<FabricPeerId> {
        self.routes
            .iter()
            .filter(|r| r.subnet.contains(dst))
            .max_by_key(|r| r.subnet.prefix_len())
            .map(|r| FabricPeerId(r.peer.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(subnet: &str, peer_byte: u8) -> Ipv4Route {
        Ipv4Route {
            subnet: nexus_network::n1::pump::Ipv4Net::parse(subnet).expect("subnet"),
            peer: nexus_network::n1::N1PeerId([peer_byte; 32]),
        }
    }

    #[test]
    fn longest_prefix_wins() {
        let map = StaticMeshPeerMap::from_routes(&[
            route("10.99.0.0/16", 0x11),
            route("10.99.13.0/24", 0x22),
            route("10.99.13.2/32", 0x33),
        ]);
        assert_eq!(
            map.peer_for(Ipv4Addr::new(10, 99, 13, 2)),
            Some(FabricPeerId([0x33; 32]))
        );
        assert_eq!(
            map.peer_for(Ipv4Addr::new(10, 99, 13, 9)),
            Some(FabricPeerId([0x22; 32]))
        );
        assert_eq!(
            map.peer_for(Ipv4Addr::new(10, 99, 5, 1)),
            Some(FabricPeerId([0x11; 32]))
        );
    }

    #[test]
    fn no_match_returns_none() {
        let map = StaticMeshPeerMap::from_routes(&[route("10.99.13.0/24", 0x22)]);
        assert_eq!(map.peer_for(Ipv4Addr::new(192, 0, 2, 1)), None);
    }

    #[test]
    fn missing_toml_yields_empty_map() {
        let map = StaticMeshPeerMap::from_toml(None);
        assert!(map.is_empty());
        assert_eq!(map.peer_for(Ipv4Addr::new(10, 99, 13, 2)), None);
    }

    #[test]
    fn from_toml_reads_vpi_routes() {
        let toml = "\
peer_id = \"0000000000000000000000000000000000000000000000000000000000000001\"

[[peers]]
id = \"0000000000000000000000000000000000000000000000000000000000000002\"
addrs = [\"127.0.0.1:22022\"]

[vpi]
interface = \"nxp0%d\"
address = \"10.99.13.1\"
mtu = 1200

[[vpi.routes]]
subnet = \"10.99.13.2/32\"
peer = \"0000000000000000000000000000000000000000000000000000000000000002\"
";
        let map = StaticMeshPeerMap::from_toml(Some(toml));
        let peer = map.peer_for(Ipv4Addr::new(10, 99, 13, 2)).expect("route");
        assert_eq!(peer.0[31], 0x02);
    }

    #[test]
    fn invalid_toml_degrades_to_empty_map() {
        let map = StaticMeshPeerMap::from_toml(Some("this is not toml ["));
        assert!(map.is_empty());
    }
}

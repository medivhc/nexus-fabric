//! Portable host-capability traits.

#![forbid(unsafe_code)]

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketInterfaceCapabilities {
    pub packet_ingress: bool,
    pub packet_injection: bool,
    pub ipv4: bool,
    pub ipv6: bool,
    pub route_include: bool,
    pub route_exclude: bool,
    pub dns_override: bool,
    pub mtu_configurable: bool,
    pub per_app_routing: bool,
    pub underlay_bypass: bool,
}

pub trait Clock: Send + Sync {
    fn monotonic_millis(&self) -> u64;
}

pub trait RandomSource: Send + Sync {
    fn fill(&self, output: &mut [u8]) -> Result<(), String>;
}

pub trait SecureStore: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, String>;
    fn put(&self, key: &str, value: &[u8]) -> Result<(), String>;
}

pub trait VirtualPacketInterface: Send {
    fn receive(&mut self, output: &mut [u8]) -> Result<usize, String>;
    fn send(&mut self, packet: &[u8]) -> Result<(), String>;
}

pub trait TransparentIngressProvider: Send {
    fn start(&mut self) -> Result<(), String>;
    fn stop(&mut self) -> Result<(), String>;
}

//! Real TUN device backed by `tun-rs` v2 (S24).
//!
//! `TunRsDevice` implements the [`TunDevice`](crate::TunDevice) trait over a
//! real OS TUN interface. It is the E5 counterpart of [`MockTun`](crate::MockTun):
//! `MockTun` is used for E4 (no privileges needed), `TunRsDevice` is used on
//! real machines (requires CAP_NET_ADMIN/root on Linux).
//!
//! Out of scope (P3.x, frozen 2026-09-29): IP address assignment, routing
//! table and DNS configuration — those are OS-integration concerns handled
//! separately.

use std::io;

use crate::TunDevice;

/// Real TUN device implemented with `tun-rs` v2 (sync API).
///
/// The device is created by [`TunRsDevice::create`] and destroyed when the
/// value is dropped (RAII). Creation fails with an `io::Error` (e.g.
/// `PermissionDenied`) when the process lacks the privileges to create a TUN
/// interface — callers may degrade to SKIP in that case.
pub struct TunRsDevice {
    dev: tun_rs::SyncDevice,
    name: String,
}

impl TunRsDevice {
    /// Create a TUN device.
    ///
    /// `name_pattern` follows the platform convention (`"nxstun%d"` on Linux,
    /// where the kernel picks the first free index). `mtu` is the interface
    /// MTU (e.g. 1500).
    ///
    /// The device is put in non-blocking mode so that [`TunDevice::read`]
    /// returns `io::ErrorKind::WouldBlock` when no packet is available,
    /// matching [`MockTun`](crate::MockTun) semantics.
    pub fn create(name_pattern: &str, mtu: u32) -> io::Result<Self> {
        let mtu: u16 = mtu
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "mtu out of u16 range"))?;
        let dev = tun_rs::DeviceBuilder::new()
            .name(name_pattern)
            .mtu(mtu)
            .build_sync()?;
        #[cfg(unix)]
        dev.set_nonblocking(true)?;
        let name = dev.name()?;
        Ok(Self { dev, name })
    }
}

impl TunDevice for TunRsDevice {
    /// Read one complete IP packet from the device.
    ///
    /// Non-blocking: returns `io::ErrorKind::WouldBlock` when no packet is
    /// available.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.dev.recv(buf)
    }

    /// Write one complete IP packet to the device.
    ///
    /// Returns the number of bytes accepted by the kernel.
    fn write(&mut self, packet: &[u8]) -> io::Result<usize> {
        self.dev.send(packet)
    }

    /// Kernel-assigned device name (e.g. `nxstun0`).
    fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `create` fails without privileges; that is a SKIP, not a FAIL.
    fn try_create() -> Option<TunRsDevice> {
        match TunRsDevice::create("nxstun%d", 1500) {
            Ok(dev) => Some(dev),
            Err(e) => {
                // Unprivileged sandbox: creating a TUN device is impossible.
                eprintln!("SKIP tun_rs_device test (no privilege): {e}");
                None
            }
        }
    }

    #[test]
    fn create_and_name() {
        let Some(dev) = try_create() else { return };
        assert!(!dev.name().is_empty(), "device name must be non-empty");
        assert!(
            dev.name().starts_with("nxstun"),
            "unexpected device name: {}",
            dev.name()
        );
    }

    /// Minimal IPv4/UDP packet builder (20B IP + 8B UDP + payload).
    fn udp_packet(payload: &[u8]) -> Vec<u8> {
        let total = (20 + 8 + payload.len()) as u16;
        let mut pkt = vec![0u8; total as usize];
        pkt[0] = 0x45; // IPv4, IHL=5
        pkt[2..4].copy_from_slice(&total.to_be_bytes());
        pkt[8] = 64; // TTL
        pkt[9] = 17; // UDP
        pkt[12..16].copy_from_slice(&[10, 200, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 200, 0, 2]);
        let mut csum: u32 = 0;
        for w in pkt[..20].chunks_exact(2) {
            csum += u16::from_be_bytes([w[0], w[1]]) as u32;
        }
        while csum >> 16 != 0 {
            csum = (csum & 0xffff) + (csum >> 16);
        }
        pkt[10..12].copy_from_slice(&(!(csum as u16)).to_be_bytes());
        let udp_len = (8 + payload.len()) as u16;
        pkt[20..22].copy_from_slice(&4000u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&5000u16.to_be_bytes());
        pkt[24..26].copy_from_slice(&udp_len.to_be_bytes());
        // UDP checksum 0 = "not computed" for IPv4.
        pkt[28..].copy_from_slice(payload);
        pkt
    }

    #[test]
    fn write_packet_accepted() {
        let Some(mut dev) = try_create() else { return };
        let pkt = udp_packet(b"tun-3c");
        assert_eq!(pkt.len(), 34);
        let n = dev.write(&pkt).expect("kernel must accept the packet");
        assert_eq!(n, pkt.len(), "write must accept the whole packet");
    }

    #[test]
    fn drop_does_not_panic() {
        let Some(dev) = try_create() else { return };
        drop(dev);
    }
}

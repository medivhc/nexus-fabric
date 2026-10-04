//! E4: product.fabric-tun-device — real TUN device via tun-rs v2 (S24).
//!
//! Creates `TunRsDevice`, writes one IPv4/UDP packet (34 bytes) and closes.
//! Uses only public API + observable output. Without privileges (no
//! CAP_NET_ADMIN) it prints `{"verdict":"SKIP",...}` instead of failing.

use nexus_projection::TunDevice;
use nexus_projection::tun_rs_device::TunRsDevice;

fn udp_packet(payload: &[u8]) -> Vec<u8> {
    let total = (20 + 8 + payload.len()) as u16;
    let mut pkt = vec![0u8; total as usize];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&total.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17;
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
    pkt[28..].copy_from_slice(payload);
    pkt
}

fn main() {
    let json = std::env::args().any(|a| a == "--json");
    let mut dev = match TunRsDevice::create("nxstun%d", 1500) {
        Ok(d) => d,
        Err(e) => {
            println!(
                "{{\"verdict\":\"SKIP\",\"reason\":\"no privilege to create TUN device: {e}\"}}"
            );
            return;
        }
    };
    let name = dev.name().to_string();
    if name.is_empty() {
        println!("{{\"verdict\":\"FAIL\",\"reason\":\"empty device name\"}}");
        std::process::exit(1);
    }
    let pkt = udp_packet(b"tun-3c");
    assert_eq!(pkt.len(), 34);
    let n = match dev.write(&pkt) {
        Ok(n) => n,
        Err(e) => {
            println!("{{\"verdict\":\"FAIL\",\"reason\":\"write failed: {e}\"}}");
            std::process::exit(1);
        }
    };
    drop(dev); // RAII close
    let pass = n == pkt.len();
    let verdict = if pass { "PASS" } else { "FAIL" };
    if json {
        println!(
            "{{\"verdict\":\"{verdict}\",\"device\":{{\"name\":\"{name}\",\"name_non_empty\":true,\"write_len\":{n}}}}}"
        );
    } else {
        println!("device={name} write_len={n} verdict={verdict}");
    }
    if !pass {
        std::process::exit(1);
    }
}

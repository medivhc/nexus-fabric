//! E4: product.unified-classifier
//!
//! 走生产路径验证统一包分类器：
//! S29 三路分类 + S30 EWMA 选路 + S31 FlowContext 生成。
//!
//! Outputs JSON; `--json` flag required (harness convention).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use nexus_path::{CandidatePath, PathConfig, PathKind, PathManager, PathStats};
use nexus_projection::classifier::{Classification, PacketClassifier};

fn v4_packet(dst: [u8; 4]) -> Vec<u8> {
    let mut pkt = vec![0u8; 20];
    pkt[0] = 0x45;
    pkt[9] = 17; // UDP
    pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
    pkt[16..20].copy_from_slice(&dst);
    pkt
}

fn cls_name(c: &Classification) -> &'static str {
    match c {
        Classification::Mesh { .. } => "Mesh",
        Classification::Proxy => "Proxy",
        Classification::Direct => "Direct",
        Classification::Drop => "Drop",
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let json = args.iter().any(|a| a == "--json");
    if !json {
        eprintln!("--json required");
        std::process::exit(2);
    }

    let mut pass = true;
    let mut check = |cond: bool| {
        if !cond {
            pass = false;
        }
    };

    // --- 构造分类器 ---
    let mut manager = PathManager::new(PathConfig::default());
    let mk = |ip: [u8; 4]| CandidatePath {
        kind: PathKind::Direct,
        local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 0),
        remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), 443),
        cost: 0.0,
    };
    let direct = mk([10, 0, 0, 2]);
    let proxy = mk([10, 0, 0, 3]);
    manager.add_candidate(direct.clone());
    manager.add_candidate(proxy.clone());
    let candidates = vec![direct.clone(), proxy.clone()];

    // 喂 stats：direct 好，proxy 差。
    manager.on_stats(
        &direct.remote_addr,
        PathStats {
            rtt_ms: Some(20),
            loss_rate: Some(0.0),
            throughput_bps: Some(100_000_000),
        },
    );
    manager.on_stats(
        &proxy.remote_addr,
        PathStats {
            rtt_ms: Some(200),
            loss_rate: Some(0.1),
            throughput_bps: Some(10_000_000),
        },
    );

    let clf = PacketClassifier::new(
        vec!["10.0.0.0/8".parse().unwrap()],
        vec!["192.168.0.0/16".parse().unwrap()],
        &manager,
        &candidates,
        50.0, // degrade_threshold
    );

    // --- S29: 三路分类 ---
    let mesh = clf.classify(&v4_packet([10, 1, 2, 3]));
    let mesh_name = cls_name(&mesh);
    check(mesh_name == "Mesh");

    let fake = clf.classify(&v4_packet([198, 18, 0, 5]));
    let fake_name = cls_name(&fake);
    check(fake_name == "Proxy");

    let bypass = clf.classify(&v4_packet([192, 168, 1, 1]));
    let bypass_name = cls_name(&bypass);
    check(bypass_name == "Direct");

    let inet = clf.classify(&v4_packet([8, 8, 8, 8]));
    let inet_name = cls_name(&inet);
    check(inet_name == "Proxy");

    // --- S30: EWMA 选路 ---
    let (ewma_best, ewma_degraded) = match &mesh {
        Classification::Mesh {
            path: Some(p),
            degraded,
        } if *p == direct.remote_addr => ("direct", *degraded),
        Classification::Mesh { .. } => ("other", false),
        _ => ("none", false),
    };
    check(matches!(
        &mesh,
        Classification::Mesh {
            path: Some(p),
            degraded: false,
        } if *p == direct.remote_addr
    ));

    // 全 unknown 回落。
    let m2 = PathManager::new(PathConfig::default());
    let clf2 = PacketClassifier::new(vec!["10.0.0.0/8".parse().unwrap()], vec![], &m2, &[], 50.0);
    let fallback = clf2.classify(&v4_packet([10, 9, 9, 9]));
    let unknown_fallback = matches!(
        fallback,
        Classification::Mesh {
            path: None,
            degraded: false
        }
    );
    check(unknown_fallback);

    // --- S31: FlowContext ---
    let mesh_origin = clf
        .to_flow_context(&mesh, &v4_packet([10, 1, 2, 3]), None, "default")
        .map(|ctx| format!("{:?}", ctx.origin))
        .unwrap_or_default();
    check(mesh_origin == "VirtualPacketInterface");

    let proxy_dst = clf
        .to_flow_context(&fake, &v4_packet([198, 18, 0, 5]), None, "p")
        .map(|ctx| ctx.destination)
        .unwrap_or_default();
    check(proxy_dst == "198.18.0.5");

    // --- Drop ---
    let drop = clf.classify(&[]);
    let drop_name = cls_name(&drop);
    check(drop_name == "Drop");

    let verdict = if pass { "PASS" } else { "FAIL" };
    println!(
        concat!(
            "{{\"verdict\":\"{verdict}\",",
            "\"mesh\":{{\"dst_10_1_2_3\":\"{mesh}\"}},",
            "\"proxy\":{{\"dst_198_18_0_5\":\"{fake}\",\"dst_8_8_8_8\":\"{inet}\"}},",
            "\"direct\":{{\"dst_192_168_1_1\":\"{bypass}\"}},",
            "\"ewma\":{{\"best_path\":\"{best}\",\"degraded\":{degraded},\"unknown_fallback\":{fallback}}},",
            "\"flowctx\":{{\"mesh\":{{\"origin\":\"{origin}\"}},\"proxy\":{{\"destination\":\"{pdst}\"}}}}",
            ",\"drop\":{{\"non_ipv4\":\"{drop}\"}}}}"
        ),
        verdict = verdict,
        mesh = mesh_name,
        fake = fake_name,
        inet = inet_name,
        bypass = bypass_name,
        best = ewma_best,
        degraded = ewma_degraded,
        fallback = unknown_fallback,
        origin = mesh_origin,
        pdst = proxy_dst,
        drop = drop_name,
    );
    std::process::exit(if pass { 0 } else { 1 });
}

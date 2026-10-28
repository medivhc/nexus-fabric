//! Composition Root 接线 E4：N1/DNS/配置装配验证（无需特权）。
//!
//! 场景 `scenarios/product/composition_root.toml` 的可执行验证：
//! - mesh_cidr_from_config：network.toml [vpi.routes] → mesh_cidrs 派生（R2）；
//! - dns_toml_parsed：dns.toml → DnsUnifiedConfig 字段（R3）；
//! - dns_toml_missing：缺失 → None；非法 → Err（R3）；
//! - n1_assemble_ok：合法配置 → bridge 构造成功，route_count == 1（R1）；
//! - n1_assemble_bad：非法配置 → Err（R1 降级路径）；
//! - hot_reload_classify：network.toml → NeedsRestart；dns.toml → NeedsRestart（R5/Q8）。

use serde_json::json;

use nexusd::assembly;
use nexusd::config::{self, ChangeKind, ConfigDir};

/// 最小合法 network.toml（含 [vpi.routes] 10.200.0.0/24）。
fn network_toml_good() -> String {
    let peer_hex = "aa".repeat(32);
    format!(
        "peer_id = \"{peer_hex}\"\n\
         [[peers]]\n\
         id = \"{peer_hex}\"\n\
         addrs = [\"127.0.0.1:19001\"]\n\
         [vpi]\n\
         interface = \"nexus0\"\n\
         address = \"10.200.0.1\"\n\
         mtu = 1200\n\
         [[vpi.routes]]\n\
         subnet = \"10.200.0.0/24\"\n\
         peer = \"{peer_hex}\"\n"
    )
}

fn write_config_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("nexusd-composition-root-e4");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("network.toml"), network_toml_good()).unwrap();
    std::fs::write(
        dir.join("dns.toml"),
        "[dns]\n\
         upstream = [\"8.8.8.8\", \"1.1.1.1\"]\n\
         fake_ip_enabled = true\n\
         fake_ip_range = \"198.18.0.0/15\"\n\
         mesh_suffix = \"mesh\"\n\
         fake_ip_ttl_secs = 300\n\
         [dns.hosts]\n\
         \"myhost\" = \"10.200.0.5\"\n",
    )
    .unwrap();
    dir
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let json_mode = args.iter().any(|a| a == "--json");
    let out = run();
    if json_mode {
        println!("{}", serde_json::to_string(&out).unwrap());
    } else {
        println!("{out:#}");
    }
}

fn run() -> serde_json::Value {
    let dir = write_config_dir();
    let config_dir = ConfigDir::new(&dir).expect("config dir");
    let loaded = config::load(&config_dir).expect("load");

    // R2：mesh CIDR 来自 [vpi.routes]，不再硬编码。
    let dp_config = assembly::build_dataplane_config(&loaded).expect("build_dataplane_config");
    let mesh_cidrs_ok = dp_config.mesh_cidrs == vec!["10.200.0.0/24".to_string()];
    let hardcoded_absent = !dp_config.mesh_cidrs.contains(&"10.0.0.0/8".to_string());

    // R3：dns.toml 解析。
    let dns = dp_config.dns_config.as_ref().expect("dns_config");
    let dns_upstream_ok = dns
        .upstream
        .servers
        .iter()
        .map(|addr| addr.ip().to_string())
        .collect::<Vec<_>>()
        == vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()];
    let dns_suffix_ok = dns.unified.mesh_suffix == "mesh";
    let dns_hosts_ok = dns.unified.hosts.len() == 1
        && dns.unified.hosts[0].0 == "myhost"
        && dns.unified.hosts[0].1.to_string() == "10.200.0.5";
    // R3：缺失 → None。
    let dns_missing_none = {
        let d2 = std::env::temp_dir().join("nexusd-composition-root-e4-nodns");
        let _ = std::fs::remove_dir_all(&d2);
        std::fs::create_dir_all(&d2).unwrap();
        let cd2 = ConfigDir::new(&d2).expect("config dir 2");
        let loaded2 = config::load(&cd2).expect("load 2");
        let cfg2 = assembly::build_dataplane_config(&loaded2).expect("build 2");
        let _ = std::fs::remove_dir_all(&d2);
        cfg2.dns_config.is_none()
    };
    // R3：非法 → Err。
    let dns_bad_err = config::parse_dns_toml(
        "[dns]\nupstream = [\"9.9.9.9\"]\nfake_ip_range = \"not-a-cidr\"\n",
        None,
        false,
    )
    .is_err();

    // R1：N1 装配成功（dial 尽力而为，无真实对端时 warn 不失败）。
    let n1_ok = match assembly::assemble_n1(
        &network_toml_good(),
        None,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    ) {
        Ok(bridge) => bridge.route_count() == 1,
        Err(_) => false,
    };
    // R1：非法配置 → Err（降级路径）。
    let n1_bad_err = assembly::assemble_n1(
        "[[[unclosed",
        None,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    )
    .is_err();

    // R5：热加载分类。
    let mut loaded_new = loaded.clone();
    loaded_new.network_toml = Some(network_toml_good() + "\n# touch\n");
    let hot_network_restart =
        config::classify_change(&loaded, &loaded_new) == ChangeKind::NeedsRestart;
    let mut loaded_new2 = loaded.clone();
    loaded_new2.dns_toml = Some("[dns]\nupstream = [\"9.9.9.9\"]\n".to_string());
    let hot_dns_is_restart =
        config::classify_change(&loaded, &loaded_new2) == ChangeKind::NeedsRestart;

    let _ = std::fs::remove_dir_all(&dir);

    let pass = mesh_cidrs_ok
        && hardcoded_absent
        && dns_upstream_ok
        && dns_suffix_ok
        && dns_hosts_ok
        && dns_missing_none
        && dns_bad_err
        && n1_ok
        && n1_bad_err
        && hot_network_restart
        && hot_dns_is_restart;

    json!({
        "verdict": if pass { "PASS" } else { "FAIL" },
        "wiring": {
            "mesh_cidrs": dp_config.mesh_cidrs.join(","),
            "mesh_cidrs_hardcoded_absent": hardcoded_absent,
            "dns_upstream": dns
                .upstream
                .servers
                .iter()
                .map(|addr| addr.ip().to_string())
                .collect::<Vec<_>>()
                .join(","),
            "dns_mesh_suffix": dns.unified.mesh_suffix,
            "dns_hosts_count": dns.unified.hosts.len(),
            "dns_missing_is_none": dns_missing_none,
            "dns_bad_is_err": dns_bad_err,
            "n1_assemble_ok": n1_ok,
            "n1_route_count": if n1_ok { 1 } else { 0 },
            "n1_assemble_bad_is_err": n1_bad_err,
            "hot_network_is_restart": hot_network_restart,
            "hot_dns_is_restart": hot_dns_is_restart,
        }
    })
}

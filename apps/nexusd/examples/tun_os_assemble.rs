//! E4: `tun_os_assemble`（spec §9.8）— OsAssemble 干跑计划与失败降级。

use nexus_platform_linux::assemble::{OsAssemble, OsAssembleConfig};

fn main() {
    let json = std::env::args().any(|a| a == "--json");
    if !json {
        eprintln!("--json required");
        std::process::exit(2);
    }
    let config = OsAssembleConfig {
        ifname: "lo".to_string(),
        tun_ip: [10, 99, 0, 1],
        prefixlen: 24,
        subnet: ([10, 99, 0, 0], 24),
        default_route: true,
        dry_run: true,
        log_path: None,
        exclude_dst_cidrs: vec![([203, 0, 113, 10], 32)],
        exclude_egress: vec![(
            ([203, 0, 113, 10], 32),
            nexus_platform_linux::assemble::ExcludeEgress {
                oif: 2,
                gateway: Some([192, 168, 1, 1]),
            },
        )],
    };
    let mut assemble = match OsAssemble::new(config) {
        Ok(a) => a,
        Err(e) => {
            println!(
                "{{\"verdict\":\"FAIL\",\"os_assemble\":{{\"state\":\"failed\",\"reason\":\"{e}\"}}}}"
            );
            std::process::exit(1);
        }
    };
    match assemble.apply() {
        Ok(report) => {
            let pass = report.dry_run && report.excludes_added == 1 && report.default_route_added;
            println!(
                "{{\"verdict\":\"{}\",\"os_assemble\":{{\"state\":\"applied\",\"ifname\":\"lo\",\"default_route\":{},\"excludes\":{},\"dry_run\":{}}}}}",
                if pass { "PASS" } else { "FAIL" },
                report.default_route_added,
                report.excludes_added,
                report.dry_run
            );
            std::process::exit(if pass { 0 } else { 1 });
        }
        Err(e) => {
            println!(
                "{{\"verdict\":\"FAIL\",\"os_assemble\":{{\"state\":\"failed\",\"reason\":\"{e}\"}}}}"
            );
            std::process::exit(1);
        }
    }
}

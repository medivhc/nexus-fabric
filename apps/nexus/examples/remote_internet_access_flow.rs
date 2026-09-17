//! E4 场景驱动：`product.remote-internet-access-flow`
//!
//! Node A 经远程闭环（Discovery -> Plan -> Session -> Connectivity -> Auth -> Network）
//! 访问 Node B 的 InternetAccess 出口，完成一次真实 HTTP 请求/响应帧往返。
//!
//! 运行：`cargo run --quiet -p nexus --example remote_internet_access_flow -- --json`

use nexus::remote_internet_access_flow;

fn main() {
    match remote_internet_access_flow() {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!("remote_internet_access_flow failed: {e}");
            std::process::exit(101);
        }
    }
}

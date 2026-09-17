//! E4 场景驱动：`product.remote-compute-job-flow`
//!
//! Node A 经远程闭环（Discovery -> Plan -> Session -> Connectivity -> Auth -> Compute）
//! 向 Node B 提交计算作业并取回结果，完成一次真实作业/结果帧往返。
//!
//! 运行：`cargo run --quiet -p nexus --example remote_compute_job_flow -- --json`

use nexus::remote_compute_job_flow;

fn main() {
    match remote_compute_job_flow() {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!("remote_compute_job_flow failed: {e}");
            std::process::exit(101);
        }
    }
}

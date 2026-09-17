//! E4 场景驱动：`product.remote-compute-rejected-rollback`
//!
//! 远程计算作业被提供方拒绝（REJECTED 帧）：认证已通过，作业内容不被接受，
//! Owner 唯一提交 Failed(COMPUTE_JOB_REJECTED)，按逆序幂等回滚到 Disposed。
//!
//! 运行：`cargo run --quiet -p nexus --example remote_compute_rejected_rollback -- --json`

use nexus::remote_compute_rejected_rollback;

fn main() {
    match remote_compute_rejected_rollback() {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!("remote_compute_rejected_rollback failed: {e}");
            std::process::exit(101);
        }
    }
}

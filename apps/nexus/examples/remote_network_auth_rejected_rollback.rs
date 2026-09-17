//! E4 场景驱动：`product.remote-network-auth-rejected-rollback`
//!
//! 远程网络会话令牌不匹配：帧流真实建立，但 W7 认证门控在业务帧前拒绝，
//! Owner 唯一提交 Failed(AUTHORIZATION_DENIED)，按逆序幂等回滚到 Disposed。
//!
//! 运行：`cargo run --quiet -p nexus --example remote_network_auth_rejected_rollback -- --json`

use nexus::remote_network_auth_rejected_rollback;

fn main() {
    match remote_network_auth_rejected_rollback() {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!("remote_network_auth_rejected_rollback failed: {e}");
            std::process::exit(101);
        }
    }
}

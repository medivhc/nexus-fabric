use std::io::ErrorKind;
use std::time::Duration;

use nexus_fabric::{Driver, PeerId};
use nexus_nat_wireup::DriverPunchSocket;

#[test]
fn g15_all_attempts_fail_is_timeout() {
    let driver = Driver::new_server("127.0.0.1:0".parse().unwrap()).expect("bind driver");
    let sock = DriverPunchSocket::new(driver, PeerId([1u8; 32]), Duration::from_millis(50));
    let err = sock
        .await_direct(Duration::from_millis(5))
        .expect_err("no attempts -> must fail");
    assert_eq!(
        err.kind(),
        ErrorKind::TimedOut,
        "all failed attempts normalize to TimedOut"
    );
}

use std::process::Command;

#[test]
fn g5_no_system_time_in_core() {
    let src = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
    let out = Command::new("rg")
        .args([
            "-n",
            "SystemTime|Instant::now|thread::sleep|std::thread",
            src,
        ])
        .output()
        .expect("rg available");
    let hits = String::from_utf8_lossy(&out.stdout);
    assert!(
        hits.trim().is_empty(),
        "protocol core must not read system time or sleep:\n{hits}"
    );
}

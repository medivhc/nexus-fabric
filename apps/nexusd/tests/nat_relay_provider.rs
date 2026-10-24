use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn g13_relay_provider_triggers_punch() {
    let dir = std::env::temp_dir().join(format!("nexusd-nat-relay-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("network.toml"),
        "[network]\npeer_id = \"0101010101010101010101010101010101010101010101010101010101010101\"\n\n[network.punch]\nenabled = true\nrelay_provider_enabled = true\n",
    )
    .unwrap();
    let log = dir.join("stderr.log");
    let out = std::fs::File::create(&log).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_nexusd"))
        .arg("serve")
        .arg("--addr=127.0.0.1:0")
        .env("NEXUS_CONFIG_DIR", &dir)
        .stdout(Stdio::null())
        .stderr(out)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(6);
    let mut text = String::new();
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
        text = std::fs::read_to_string(&log).unwrap_or_default();
        if text.contains("[nat-relay] provider_up") {
            break;
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    // Keep the captured stderr for the evidence bundle.
    let mut ev = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
    writeln!(
        ev,
        "\n--- g13 saw provider_up: {} ---",
        text.contains("[nat-relay] provider_up")
    )
    .unwrap();
    assert!(
        text.contains("[nat-relay] provider_up"),
        "production relay provider must log provider_up; stderr:\n{text}"
    );
}

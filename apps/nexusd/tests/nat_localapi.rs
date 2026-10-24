use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn tempdir(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("nexusd-nat-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn get(addr: &str, path: &str) -> (u16, String) {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {TOKEN}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut buf = String::new();
    s.read_to_string(&mut buf).unwrap();
    let status = buf
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = buf
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, body)
}

fn spawn(dir: &std::path::Path) -> std::process::Child {
    let token = dir.join("localapi.token");
    std::fs::write(&token, TOKEN).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    Command::new(env!("CARGO_BIN_EXE_nexusd"))
        .arg("serve")
        .arg("--addr=127.0.0.1:0")
        .env("NEXUS_CONFIG_DIR", dir)
        .env("NEXUS_LOCALAPI_TOKEN_FILE", &token)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn wait_ready(child: &mut std::process::Child) -> String {
    use std::io::{BufRead, BufReader};
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
                if let Some(a) = v["daemon"]["addr"].as_str() {
                    let _ = tx.send(a.to_string());
                    break;
                }
            }
        }
    });
    rx.recv_timeout(Duration::from_secs(12))
        .expect("daemon ready")
}

#[test]
fn g11_localapi_nat_route() {
    let dir = tempdir("nat-route");
    let mut child = spawn(&dir);
    let addr = wait_ready(&mut child);
    let deadline = Instant::now() + Duration::from_secs(5);
    let (mut status, mut body) = get(&addr, "/localapi/v0/connectivity/nat");
    while status == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
        (status, body) = get(&addr, "/localapi/v0/connectivity/nat");
    }
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(status, 200, "NAT snapshot route must exist: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("JSON body");
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["runtime"], "disabled");
    assert!(v["peers"].is_array());
}

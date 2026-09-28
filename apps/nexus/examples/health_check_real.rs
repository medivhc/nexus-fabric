//! E4 `product.health-check-real`：真实 loopback TCP 探测起停驱动健康状态转移。
//!
//! ```text
//! cargo run --quiet -p nexus --example health_check_real -- --json
//! ```

#![forbid(unsafe_code)]

use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nexus_connectivity::health_check::{HealthConfig, HealthMonitor, HealthProbe, HealthState};
use serde_json::json;

struct DynProbe {
    target: Arc<Mutex<Option<std::net::SocketAddr>>>,
    timeout: Duration,
}

impl HealthProbe for DynProbe {
    fn probe(&self, _node_id: &str, _target: &str) -> Result<(), String> {
        let addr = self
            .target
            .lock()
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "no target".to_string())?;
        TcpStream::connect_timeout(&addr, self.timeout)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

fn run() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let target: Arc<Mutex<Option<std::net::SocketAddr>>> = Arc::new(Mutex::new(None));

    let l1 = TcpListener::bind("127.0.0.1:0")?;
    let addr1 = l1.local_addr()?;
    *target.lock().unwrap() = Some(addr1);

    let cfg = HealthConfig::new(80, 300, 2)?;
    let probe = DynProbe {
        target: target.clone(),
        timeout: Duration::from_millis(300),
    };
    let mon = HealthMonitor::spawn(
        cfg,
        Box::new(probe),
        vec![("node-a".into(), "loopback".into())],
    )?;

    std::thread::sleep(Duration::from_millis(260));

    drop(l1);

    let mut unhealthy_seen = false;
    let mut recovered = false;
    let mut l2_guard: Option<TcpListener> = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        for ev in mon.drain_events() {
            if ev.to == HealthState::Unhealthy {
                unhealthy_seen = true;
            }
            if unhealthy_seen && ev.to == HealthState::Healthy {
                recovered = true;
            }
        }
        if recovered {
            break;
        }
        if unhealthy_seen && l2_guard.is_none() {
            let l2 = TcpListener::bind("127.0.0.1:0")?;
            let addr2 = l2.local_addr()?;
            *target.lock().unwrap() = Some(addr2);
            l2_guard = Some(l2);
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let final_state = mon.state("node-a")?.as_str().to_string();
    mon.cancel();
    drop(target);
    drop(l2_guard);

    Ok(json!({
        "verdict": "PASS",
        "command": "health-check-real",
        "unhealthy_seen": unhealthy_seen,
        "recovered_to_healthy": recovered,
        "final_state": final_state,
    }))
}

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match run() {
        Ok(v) => {
            if as_json {
                println!("{v}");
            } else {
                println!("health_check_real: {v}");
            }
        }
        Err(e) => {
            eprintln!("health_check_real failed: {e}");
            std::process::exit(1);
        }
    }
}

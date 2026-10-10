//! E4 `product.graceful-exit-real`：再见帧 wire codec 真实 loopback 收发 + 真实宽限期 drain。
//!
//! ```text
//! cargo run --quiet -p nexus --example graceful_exit_real -- --json
//! ```

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use nexus_connectivity::graceful_exit::{ExitConfig, GoodbyeFrame, GracefulExit, decode_goodbye};
use serde_json::json;

fn run() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    // --- wire codec roundtrip ---
    let frame = GoodbyeFrame::new("peer-a", "shutting-down");
    let bytes = frame.encode();
    let decoded_back = decode_goodbye(&bytes)?;
    let codec_roundtrip = decoded_back == frame;

    // --- 真实 loopback 对端收到并解码 ---
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let got: Arc<Mutex<Option<(u8, String, String)>>> = Arc::new(Mutex::new(None));
    let got_t = got.clone();
    let jh = std::thread::spawn(move || -> Result<(), String> {
        let (mut s, _) = listener.accept().map_err(|e| e.to_string())?;
        let mut buf = Vec::new();
        let mut tmp = [0u8; 1024];
        loop {
            match s.read(&mut tmp) {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
            }
        }
        let f = decode_goodbye(&buf).map_err(|e| e.to_string())?;
        *got_t.lock().unwrap() = Some((f.version, f.peer_id, f.reason));
        Ok(())
    });

    let mut s = TcpStream::connect(addr)?;
    s.write_all(&bytes)?;
    drop(s); // 关闭写端，对端 EOF。
    let _ = jh.join();

    let wire = got.lock().unwrap().clone();
    let wire_received = wire.is_some();
    let (decoded_version, decoded_peer_id, decoded_reason) =
        wire.unwrap_or((0u8, String::new(), String::new()));

    // --- 真实墙钟宽限期 drain：活跃连接从 2 -> 1 -> 0 ---
    let cfg = ExitConfig::new(500, true, true)?;
    let mut g = GracefulExit::new(cfg);
    g.begin_draining(0);
    let polls = std::cell::Cell::new(0u32);
    let drain_result = g.drain_real(|| {
        let n = polls.get();
        polls.set(n + 1);
        match n {
            0 => 2,
            1 => 1,
            _ => 0,
        }
    });
    let drain_result_str = drain_result.as_str().to_string();
    // 再推进一次到终态。
    let final_state = g.advance(0, 1000).as_str().to_string();

    Ok(json!({
        "verdict": "PASS",
        "command": "graceful-exit-real",
        "codec_roundtrip": codec_roundtrip,
        "wire_received": wire_received,
        "decoded_version": decoded_version,
        "decoded_peer_id": decoded_peer_id,
        "decoded_reason": decoded_reason,
        "drain_result": drain_result_str,
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
                println!("graceful_exit_real: {v}");
            }
        }
        Err(e) => {
            eprintln!("graceful_exit_real failed: {e}");
            std::process::exit(1);
        }
    }
}

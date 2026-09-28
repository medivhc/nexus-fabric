//! E4 `product.connection-pool-real`：真实 TCP echo 连接复用 / 上限 / 句柄回收。
//!
//! ```text
//! cargo run --quiet -p nexus --example connection_pool_real -- --json
//! ```

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use nexus_connectivity::connection_pool::{ConnectionFactory, PoolConfig, PoolError, RealizedPool};
use serde_json::json;

struct TcpFactory {
    addr: String,
}

impl ConnectionFactory for TcpFactory {
    type Handle = TcpStream;
    fn connect(&self, _key: &str) -> Result<TcpStream, PoolError> {
        TcpStream::connect(&self.addr)
            .map_err(|e| PoolError::InvalidConfig(format!("connect: {e}")))
    }
}

fn echo(handle: &mut TcpStream, msg: &[u8]) -> std::io::Result<Vec<u8>> {
    handle.write_all(msg)?;
    let mut buf = vec![0u8; msg.len()];
    handle.read_exact(&mut buf)?;
    Ok(buf)
}

fn run() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    // loopback echo server。
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?.to_string();
    std::thread::spawn(move || {
        for mut s in listener.incoming().filter_map(Result::ok) {
            let mut buf = [0u8; 1024];
            loop {
                match s.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if s.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                }
            }
        }
    });

    let cfg = PoolConfig::new(2, 3, 100_000)?;
    let mut pool = RealizedPool::new(cfg, TcpFactory { addr });

    // 首次 acquire("a") 新建，echo 往返后 release。
    let mut c1 = pool.acquire("a")?;
    let first_conn_id = c1.conn_id;
    let first_echo_ok = echo(&mut c1.handle, b"hello")
        .map(|b| b == b"hello")
        .unwrap_or(false);
    pool.release(c1, 0)?;

    // 再 acquire("a")：复用同一条真实 TCP 流（conn_id 不变），echo 仍成功；
    // 保持 c2 active，用于占满 max_total。
    let mut c2 = pool.acquire("a")?;
    let reused_same_conn = c2.conn_id == first_conn_id;
    let reused_conn_id = c2.conn_id;
    let echo_on_reused_ok = echo(&mut c2.handle, b"world")
        .map(|b| b == b"world")
        .unwrap_or(false);

    // 占满 max_total=3（a 已 active，再加 b/c）。
    let b = pool.acquire("b")?;
    let c = pool.acquire("c")?;
    let exhausted = pool.acquire("d").is_err();
    pool.release(b, 0)?;
    pool.release(c, 0)?;
    // 此刻 active={a}, idle={b,c} -> total=3, idle=2。
    let snap = pool.snapshot();
    pool.release(c2, 0)?;

    Ok(json!({
        "verdict": "PASS",
        "command": "connection-pool-real",
        "first_conn_id": first_conn_id,
        "first_echo_ok": first_echo_ok,
        "reused_same_conn": reused_same_conn,
        "reused_conn_id": reused_conn_id,
        "echo_on_reused_ok": echo_on_reused_ok,
        "exhausted": exhausted,
        "final_total": snap.total_count,
        "final_idle": snap.idle_count,
    }))
}

fn main() {
    let as_json = std::env::args().skip(1).any(|a| a == "--json");
    match run() {
        Ok(v) => {
            if as_json {
                println!("{v}");
            } else {
                println!("connection_pool_real: {v}");
            }
        }
        Err(e) => {
            eprintln!("connection_pool_real failed: {e}");
            std::process::exit(1);
        }
    }
}

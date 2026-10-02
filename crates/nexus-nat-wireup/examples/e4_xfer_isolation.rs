//! Minimal isolation: relay-only chunked transfer (no punch, no monitor).
//! If this fails, the transfer framing is broken. If it passes, the
//! interaction with punch/monitor is the culprit.
//!
//! Usage: e4_xfer_isolation

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use nexus_fabric::{Cmd, ConnShared, Driver, StreamShared};
use nexus_turn::TurnSocket;
use nexus_turn::client::{TurnClient, TurnCredentials};
use nexus_turn::server::TurnServer;

fn open_stream(conn: &Arc<ConnShared>) -> io::Result<Arc<StreamShared>> {
    let (tx, rx) = std::sync::mpsc::channel();
    conn.tx
        .send(Cmd::OpenBi {
            conn: conn.id.0,
            reply: tx,
        })
        .map_err(|_| io::Error::new(io::ErrorKind::NotConnected, "driver gone"))?;
    rx.recv_timeout(Duration::from_secs(10))
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "open_bi timeout"))?
        .map_err(|e| io::Error::other(format!("{e:?}")))
}

fn xfer_write(s: &Arc<StreamShared>, data: &[u8]) -> io::Result<()> {
    let mut hdr = (data.len() as u32).to_be_bytes().to_vec();
    hdr.extend_from_slice(data);
    nexus_nat_wireup::channel::write_all_stream(s, &hdr)
}

fn xfer_read(s: &Arc<StreamShared>) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut lenb = [0u8; 4];
    nexus_nat_wireup::channel::read_exact_deadline(s, &mut lenb, deadline)?;
    let len = u32::from_be_bytes(lenb) as usize;
    let mut buf = vec![0u8; len];
    nexus_nat_wireup::channel::read_exact_deadline(s, &mut buf, deadline)?;
    Ok(buf)
}

fn main() {
    let turn = TurnServer::bind(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3478),
        TurnCredentials {
            username: "u".into(),
            password: "p".into(),
            realm: "nexus".into(),
        },
    )
    .expect("turn bind");
    let turn_addr = turn.main_addr();
    std::mem::forget(turn);

    let creds = || TurnCredentials {
        username: "u".into(),
        password: "p".into(),
        realm: "nexus".into(),
    };
    let ca = TurnClient::allocate(turn_addr, creds()).expect("A allocate");
    let cb = TurnClient::allocate(turn_addr, creds()).expect("B allocate");
    let ra = ca.relayed_addr();
    let rb = cb.relayed_addr();
    ca.create_permission(rb).unwrap();
    cb.create_permission(ra).unwrap();

    // Drivers with TURN-only transport.
    let mk_transport = |client: TurnClient, _peer_relayed: SocketAddr| {
        let sock = TurnSocket::new(client);
        // Minimal UdpTransport: TURN only.
        struct T {
            turn: TurnSocket,
        }
        impl nexus_fabric::transport::UdpTransport for T {
            fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
                // 40ms delay like S1
                thread::sleep(Duration::from_millis(40));
                self.turn.send_to(buf, target)
            }
            fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
                self.turn.recv_from(buf)
            }
            fn set_read_timeout(&self, t: Option<Duration>) -> io::Result<()> {
                self.turn.set_read_timeout(t)
            }
            fn local_addr(&self) -> io::Result<SocketAddr> {
                Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            }
        }
        T { turn: sock }
    };

    let drv_a = Driver::new_server_with_transport(Box::new(mk_transport(ca, rb))).unwrap();
    let drv_b = Driver::new_server_with_transport(Box::new(mk_transport(cb, ra))).unwrap();
    let id_a = drv_a.shared().peer_id.unwrap();
    let id_b = drv_b.shared().peer_id.unwrap();

    let drv_b2 = drv_b.clone();
    let accept_h = thread::spawn(move || drv_b2.accept_conn().expect("accept"));
    thread::sleep(Duration::from_millis(100));
    let conn_a = drv_a
        .connect(id_b, rb, Duration::from_secs(15))
        .expect("connect");
    let conn_b = accept_h.join().unwrap();
    let _ = id_a;
    println!("[iso] relay conn up");

    // B: echo batches.
    thread::spawn(move || {
        loop {
            let s = match nexus_nat_wireup::accept_stream_timeout(&conn_b, Duration::from_secs(60))
            {
                Ok(s) => s,
                Err(_) => break,
            };
            println!("[iso] B accepted stream");
            loop {
                match xfer_read(&s) {
                    Ok(buf) => {
                        if xfer_write(&s, &buf).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("[iso] B read err: {e}");
                        break;
                    }
                }
            }
        }
    });

    // A: 3 batches x 10 chunks.
    let mut ok = true;
    for b in 0..3 {
        let s = open_stream(&conn_a).expect("open");
        println!("[iso] A batch {b} stream opened");
        for i in 0..10 {
            let seq = (b * 10 + i) as u64;
            let mut payload = vec![0u8; 1024];
            payload[..8].copy_from_slice(&seq.to_be_bytes());
            xfer_write(&s, &payload).expect("write");
            match xfer_read(&s) {
                Ok(echo) if echo == payload => {}
                Ok(echo) => {
                    eprintln!(
                        "[iso] batch {b} chunk {i} MISMATCH len {} vs {}",
                        echo.len(),
                        payload.len()
                    );
                    ok = false;
                    break;
                }
                Err(e) => {
                    eprintln!("[iso] batch {b} chunk {i} read err: {e}");
                    ok = false;
                    break;
                }
            }
        }
        if !ok {
            break;
        }
        println!("[iso] A batch {b} done");
    }
    println!("isolation verdict: {}", if ok { "PASS" } else { "FAIL" });
    std::process::exit(if ok { 0 } else { 1 });
}

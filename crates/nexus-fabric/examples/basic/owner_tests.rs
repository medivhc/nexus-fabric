//! Frozen example coordination tests; no change to fabric's finish/Drop API.
use super::{
    ConnConfig, DATAGRAMS, FabricConn, FabricListener, STREAM_BYTES, payload, run_with_connect,
    with_server_owner,
};
use nexus_fabric::{FabricError, UdpTransport};
use std::io::{self, Read};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

type Packet = (Vec<u8>, SocketAddr);

#[derive(Default)]
struct Gate {
    closed: bool,
    queued: Vec<Packet>,
}

struct MemoryUdp {
    local: SocketAddr,
    peer: SocketAddr,
    incoming: mpsc::Receiver<Packet>,
    outgoing: mpsc::Sender<Packet>,
    timeout: Duration,
    gate: Arc<Mutex<Gate>>,
    dropped: mpsc::Sender<()>,
}

impl UdpTransport for MemoryUdp {
    fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (packet, source) = self.incoming.recv_timeout(self.timeout).map_err(|_| {
            io::Error::new(io::ErrorKind::TimedOut, "controlled memory transport idle")
        })?;
        assert!(packet.len() <= buf.len());
        buf[..packet.len()].copy_from_slice(&packet);
        Ok((packet.len(), source))
    }

    fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        assert_eq!(target, self.peer);
        let packet = (buf.to_vec(), self.local);
        let mut gate = self.gate.lock().unwrap();
        if gate.closed {
            gate.queued.push(packet);
        } else {
            self.outgoing
                .send(packet)
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "memory peer released"))?;
        }
        Ok(buf.len())
    }

    fn set_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        // Fixed bounded polling is independent of driver-selected timer values.
        Ok(())
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
}

impl Drop for MemoryUdp {
    fn drop(&mut self) {
        let _ = self.dropped.send(());
    }
}

struct EchoFixture {
    owner: FabricListener,
    server: FixtureWorker,
    client: FabricConn,
    recv: nexus_fabric::RecvStream,
    gate: Arc<Mutex<Gate>>,
    deliver: mpsc::Sender<Packet>,
    dropped: mpsc::Receiver<()>,
}

type EchoWorker = thread::JoinHandle<Result<(usize, usize), String>>;

// Own the handle from the first instruction after spawn, including unwinding
// during fixture construction. Keep the client driver alive until peer-close
// has woken the real server and its JoinHandle has been consumed.
struct FixtureWorker {
    worker: Option<EchoWorker>,
    start: mpsc::Sender<bool>,
    client: Option<FabricConn>,
    joined: Option<mpsc::Sender<()>>,
}

impl FixtureWorker {
    fn into_handle(mut self) -> EchoWorker {
        self.worker.take().unwrap()
    }

    fn join(self) -> thread::Result<Result<(usize, usize), String>> {
        self.into_handle().join()
    }
}

impl Drop for FixtureWorker {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = self.start.send(false);
            if let Some(client) = &self.client {
                client.close(0, b"fixture setup cancelled");
            }
            // Admission/start/read have 5s bounds. Once admitted, peer close
            // wakes accept_bi/datagram waiters while client remains owned here.
            let _ = worker.join();
            if let Some(joined) = self.joined.take() {
                let _ = joined.send(());
            }
        }
    }
}

#[derive(Clone, Copy)]
enum SetupFault {
    None,
    BeforeConnect,
    BeforeTraffic,
    MissingDatagram,
}

impl EchoFixture {
    fn new() -> Self {
        Self::new_with_fault(SetupFault::None, None)
    }

    fn new_with_fault(fault: SetupFault, joined: Option<mpsc::Sender<()>>) -> Self {
        let (to_server, server_rx) = mpsc::channel();
        let (to_client, client_rx) = mpsc::channel();
        let (server_drop, dropped) = mpsc::channel();
        let (client_drop, _) = mpsc::channel();
        let server_addr: SocketAddr = "127.0.0.1:30101".parse().unwrap();
        let client_addr: SocketAddr = "127.0.0.1:30102".parse().unwrap();
        let gate = Arc::new(Mutex::new(Gate::default()));
        let owner = FabricListener::bind_with_transport(Box::new(MemoryUdp {
            local: server_addr,
            peer: client_addr,
            incoming: server_rx,
            outgoing: to_client.clone(),
            timeout: Duration::from_millis(1),
            gate: gate.clone(),
            dropped: server_drop,
        }))
        .unwrap();
        let worker_listener = owner.clone();
        let server_gate = gate.clone();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (start_tx, start_rx) = mpsc::channel();
        let (datagrams_tx, datagrams_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let conn = worker_listener
                .accept_timeout(Duration::from_secs(5))
                .map_err(|e| e.to_string())?;
            if !start_rx
                .recv_timeout(Duration::from_secs(5))
                .map_err(|e| e.to_string())?
            {
                return Err("fixture cancelled before stream admission".into());
            }
            let (mut send, mut recv) = conn.accept_bi().map_err(|e| e.to_string())?;
            let mut data = Vec::new();
            let mut buf = [0; 65536];
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let n = recv
                    .read_deadline(&mut buf, deadline)
                    .map_err(|e| e.to_string())?;
                if n == 0 {
                    break;
                }
                data.extend_from_slice(&buf[..n]);
            }
            let _ = datagrams_tx.send(());
            let mut count = 0;
            for _ in 0..DATAGRAMS {
                if conn.recv_datagram().map_err(|e| e.to_string())?.len() == 200 {
                    count += 1;
                }
            }
            // A legal network scheduler can withhold the echo's encrypted
            // packets until after the application has queued bytes and FIN.
            server_gate.lock().unwrap().closed = true;
            send.write(&data).map_err(|e| e.to_string())?;
            send.finish().map_err(|e| e.to_string())?;
            drop((send, recv, conn, worker_listener));
            ready_tx.send(()).map_err(|e| e.to_string())?;
            Ok((count, data.len()))
        });
        let mut server = FixtureWorker {
            worker: Some(server),
            start: start_tx,
            client: None,
            joined,
        };
        if matches!(fault, SetupFault::BeforeConnect) {
            panic!("injected fixture failure before connect");
        }
        let client = FabricConn::connect_with_transport(
            owner.peer_id(),
            &ConnConfig {
                addrs: vec![server_addr],
                handshake_timeout: Duration::from_secs(5),
            },
            Box::new(MemoryUdp {
                local: client_addr,
                peer: server_addr,
                incoming: client_rx,
                outgoing: to_server,
                timeout: Duration::from_millis(1),
                gate: Arc::new(Mutex::new(Gate::default())),
                dropped: client_drop,
            }),
        )
        .unwrap();
        server.client = Some(client.clone());
        if matches!(fault, SetupFault::BeforeTraffic) {
            panic!("injected fixture failure before traffic");
        }
        let (mut send, recv) = client.open_bi().unwrap();
        send.write(&payload()).unwrap();
        send.finish().unwrap();
        let count = if matches!(fault, SetupFault::MissingDatagram) {
            DATAGRAMS - 1
        } else {
            DATAGRAMS
        };
        for i in 0..count as u8 {
            let mut data = vec![0; 200];
            data[0] = i;
            data[199] = i.wrapping_mul(7);
            client.send_datagram(&data).unwrap();
        }
        server.start.send(true).unwrap();
        if matches!(fault, SetupFault::MissingDatagram) {
            datagrams_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            panic!("injected fixture failure with missing datagram");
        }
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        Self {
            owner,
            server,
            client,
            recv,
            gate,
            deliver: to_client,
            dropped,
        }
    }
}

fn release_packets(gate: &Mutex<Gate>, deliver: &mpsc::Sender<Packet>) {
    let mut state = gate.lock().unwrap();
    state.closed = false;
    for packet in state.queued.drain(..) {
        deliver.send(packet).unwrap();
    }
}

fn read_echo(recv: &mut nexus_fabric::RecvStream) -> Result<Vec<u8>, String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut echo = Vec::new();
    let mut buf = [0; 65536];
    loop {
        let n = recv
            .read_deadline(&mut buf, deadline)
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Ok(echo);
        }
        echo.extend_from_slice(&buf[..n]);
    }
}

#[test]
fn retains_real_driver_until_full_mib_and_eof() {
    if in_bounded_child(
        "retains_real_driver_until_full_mib_and_eof",
        Duration::from_secs(15),
    ) {
        return;
    }
    let EchoFixture {
        owner,
        server,
        client,
        mut recv,
        gate,
        deliver,
        dropped,
    } = EchoFixture::new();
    let result = with_server_owner(owner, server.into_handle(), || {
        if dropped.try_recv().is_ok() {
            eprintln!("observed real server transport Drop before client EOF");
            return Err("real server transport dropped before client EOF".into());
        }
        release_packets(&gate, &deliver);
        let echo = read_echo(&mut recv)?;
        assert_eq!(
            echo,
            payload(),
            "S4 requires every byte in its original order"
        );
        Ok(echo.len())
    });
    drop(client);
    assert_eq!(result, Ok((STREAM_BYTES, (DATAGRAMS, STREAM_BYTES))));
    dropped.recv_timeout(Duration::from_secs(5)).unwrap();
}

#[test]
fn legal_retained_owner_control_delivers_full_mib_and_eof() {
    if in_bounded_child(
        "legal_retained_owner_control_delivers_full_mib_and_eof",
        Duration::from_secs(15),
    ) {
        return;
    }
    let EchoFixture {
        owner,
        server,
        client,
        mut recv,
        gate,
        deliver,
        dropped,
    } = EchoFixture::new();
    release_packets(&gate, &deliver);
    let result = read_echo(&mut recv);
    let server_result = server.join().unwrap();
    assert_eq!(result.unwrap(), payload());
    assert_eq!(server_result.unwrap(), (DATAGRAMS, STREAM_BYTES));
    assert!(
        dropped.try_recv().is_err(),
        "real transport remains owned through EOF"
    );
    drop(owner);
    dropped.recv_timeout(Duration::from_secs(5)).unwrap();
    drop(client);
}

#[test]
fn early_owner_release_control_really_destroys_server_transport() {
    if in_bounded_child(
        "early_owner_release_control_really_destroys_server_transport",
        Duration::from_secs(15),
    ) {
        return;
    }
    let EchoFixture {
        owner,
        server,
        client,
        mut recv,
        gate,
        deliver,
        dropped,
        ..
    } = EchoFixture::new();
    assert_eq!(server.join().unwrap().unwrap(), (DATAGRAMS, STREAM_BYTES));
    drop(owner);
    dropped.recv_timeout(Duration::from_secs(5)).unwrap();
    // No echo packet can reach the client before the last driver owner is gone.
    // Opening this gate cannot resurrect a stopped driver to finish the stream.
    release_packets(&gate, &deliver);
    let deadline = Instant::now() + Duration::from_millis(100);
    let mut bytes = 0;
    let mut buf = [0; 65536];
    loop {
        match recv.read_deadline(&mut buf, deadline) {
            Ok(0) => panic!("early driver shutdown unexpectedly delivered full stream EOF"),
            Ok(n) => bytes += n,
            Err(FabricError::Timeout) => break,
            Err(e) => panic!("unexpected negative-control error: {e}"),
        }
    }
    assert!(
        bytes < STREAM_BYTES,
        "negative control must lose the reliable-stream tail"
    );
    drop(client);
}

fn ended_worker(
    result: Result<usize, String>,
) -> (
    thread::JoinHandle<Result<usize, String>>,
    mpsc::Receiver<()>,
) {
    let (ended_tx, ended_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        struct AtExit(mpsc::Sender<()>);
        impl Drop for AtExit {
            fn drop(&mut self) {
                let _ = self.0.send(());
            }
        }
        let _at_exit = AtExit(ended_tx);
        result
    });
    (worker, ended_rx)
}

#[test]
fn server_error_is_joined_and_propagated() {
    let (worker, ended) = ended_worker(Err("injected echo write failure".into()));
    let result = with_server_owner((), worker, || Ok(3usize));
    ended.try_recv().expect("error worker was reaped");
    assert_eq!(result, Err("server: injected echo write failure".into()));
}

#[test]
fn server_panic_is_reaped_and_reported() {
    let (ended_tx, ended_rx) = mpsc::channel();
    let worker = thread::spawn(move || -> Result<usize, String> {
        struct AtExit(mpsc::Sender<()>);
        impl Drop for AtExit {
            fn drop(&mut self) {
                let _ = self.0.send(());
            }
        }
        let _at_exit = AtExit(ended_tx);
        panic!("injected server panic");
    });
    let result = with_server_owner((), worker, || Ok(3usize));
    ended_rx
        .try_recv()
        .expect("panicking worker unwound before coordinator returned");
    assert_eq!(result, Err("server thread panicked".into()));
}

#[test]
fn client_failure_still_consumes_server_failure() {
    let (worker, ended) = ended_worker(Err("injected cleanup failure".into()));
    let error = with_server_owner((), worker, || {
        Err::<usize, _>("injected client failure".into())
    })
    .unwrap_err();
    ended
        .try_recv()
        .expect("failed worker was reaped even when client failed");
    assert!(
        error.contains("injected client failure"),
        "client context lost: {error}"
    );
    assert!(
        error.contains("injected cleanup failure"),
        "server cleanup context lost: {error}"
    );
}

#[test]
fn client_failure_still_consumes_server_panic() {
    let (ended_tx, ended_rx) = mpsc::channel();
    let worker = thread::spawn(move || -> Result<usize, String> {
        let _exit = super::WorkerExit(Some(move || {
            let _ = ended_tx.send(());
        }));
        panic!("injected simultaneous server panic");
    });
    let error = with_server_owner((), worker, || {
        Err::<usize, _>("injected client failure".into())
    })
    .unwrap_err();
    ended_rx
        .try_recv()
        .expect("panic worker must have unwound before returning");
    assert!(
        error.contains("injected client failure"),
        "client context lost: {error}"
    );
    assert!(
        error.contains("server thread panicked"),
        "panic context lost: {error}"
    );
}

#[test]
fn fixture_setup_panics_cancel_and_join_real_workers() {
    if in_bounded_child(
        "fixture_setup_panics_cancel_and_join_real_workers",
        Duration::from_secs(15),
    ) {
        return;
    }
    for fault in [
        SetupFault::BeforeConnect,
        SetupFault::BeforeTraffic,
        SetupFault::MissingDatagram,
    ] {
        let (joined_tx, joined_rx) = mpsc::channel();
        let result =
            std::panic::catch_unwind(|| EchoFixture::new_with_fault(fault, Some(joined_tx)));
        assert!(
            result.is_err(),
            "fault probe must unwind fixture construction"
        );
        joined_rx
            .try_recv()
            .expect("RAII cleanup must consume actual server JoinHandle before unwind completes");
    }
}

struct ChildCleanup {
    child: Child,
    reader: Option<thread::JoinHandle<()>>,
}

impl Drop for ChildCleanup {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

#[test]
fn client_failure_reaps_real_accept_worker_and_preserves_client_error() {
    if in_bounded_child(
        "client_failure_reaps_real_accept_worker_and_preserves_client_error",
        Duration::from_secs(15),
    ) {
        return;
    }
    let (ended_tx, ended_rx) = mpsc::channel();
    let result = run_with_connect(
        |_peer, _config| Err("connect: injected failure before open".into()),
        move || {
            let _ = ended_tx.send(());
        },
    );
    let error = result.unwrap_err();
    assert!(
        error.contains("connect: injected failure before open"),
        "client context lost: {error}"
    );
    // Observe the actual production worker before considering the operation
    // complete. A detached worker with a bounded accept must still fail.
    if ended_rx.try_recv().is_err() {
        ended_rx
            .recv()
            .expect("actual example server exit observer");
        panic!("actual example returned client error before server exit/join");
    }
}

// Process isolation is a last-resort FAIL boundary for deliberately exercised
// old unbounded admission and any fixture cancellation defect. Kill+wait is
// never counted as correct server cleanup. No polling or sleep is involved.
fn in_bounded_child(test: &str, budget: Duration) -> bool {
    const CHILD: &str = "NEXUS_BASIC_TEST_CHILD";
    if std::env::var(CHILD).is_ok_and(|value| value == test) {
        return false;
    }
    let target = format!("owner_tests::{test}");
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &target, "--nocapture"])
        .env(CHILD, test)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut cleanup = ChildCleanup {
        child,
        reader: None,
    };
    let mut stdout = cleanup.child.stdout.take().unwrap();
    let (output_tx, output_rx) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut output = Vec::new();
        let result = stdout.read_to_end(&mut output);
        let _ = output_tx.send((result, output));
    });
    cleanup.reader = Some(reader);
    match output_rx.recv_timeout(budget) {
        Ok((read, bytes)) => {
            read.unwrap();
            let status = cleanup.child.wait().unwrap();
            assert!(
                status.success(),
                "{target} child failed: {}",
                String::from_utf8_lossy(&bytes)
            );
        }
        Err(e) => {
            cleanup.child.kill().unwrap();
            let status = cleanup.child.wait().unwrap();
            panic!(
                "{target}: bounded failure isolation after {budget:?}; killed and waited child {status}: {e}; kill is not successful owner cleanup"
            );
        }
    }
    true
}

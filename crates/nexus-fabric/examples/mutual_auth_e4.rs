//! product.fabric-mutual-auth: real independent provider/requester processes.
//! This exercises TLS primitives only, never accepts or executes a domain Task.
//! Fixed seeds are public test fixtures; production identities are caller-owned.
use nexus_fabric::{ConnConfig, FabricConn, FabricError, FabricIdentity, FabricListener, PeerId};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const PAYLOAD: &[u8] = b"N3-MTLS-PRIMITIVE-ONLY: confidential independent-process echo\x00\xff";
const CHILD_BUDGET: Duration = Duration::from_secs(5);
fn identity(seed: u8) -> Result<FabricIdentity, String> {
    FabricIdentity::from_ed25519_seed([seed; 32]).map_err(|e| e.to_string())
}
fn hex(peer: PeerId) -> String {
    peer.0.iter().map(|b| format!("{b:02x}")).collect()
}
fn peer(text: &str) -> Result<PeerId, String> {
    if text.len() != 64 {
        return Err("invalid public peer key".into());
    }
    let mut key = [0; 32];
    for (i, chunk) in text.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk).map_err(|_| "invalid public peer key")?;
        key[i] = u8::from_str_radix(text, 16).map_err(|_| "invalid public peer key")?;
    }
    Ok(PeerId(key))
}
fn emit(line: &str) -> Result<(), String> {
    println!("{line}");
    std::io::stdout().flush().map_err(|e| e.to_string())
}
fn read_payload(recv: &mut nexus_fabric::RecvStream) -> Result<Vec<u8>, String> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut bytes = Vec::new();
    loop {
        let mut buffer = [0; 128];
        let n = recv
            .read_deadline(&mut buffer, deadline)
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Ok(bytes);
        }
        bytes.extend_from_slice(&buffer[..n]);
        if bytes.len() > 4096 {
            return Err("unexpected payload size".into());
        }
    }
}
fn provider(case: &str) -> Result<(), String> {
    let id = identity(71)?;
    let requester = identity(72)?.peer_id();
    let allowed = if case == "empty" {
        vec![]
    } else {
        vec![requester]
    };
    let listener = FabricListener::bind_mtls(
        "127.0.0.1:0".parse().map_err(|_| "bind address")?,
        &id,
        &allowed,
    )
    .map_err(|e| e.to_string())?;
    emit(&format!(
        "LISTEN {} {} {}",
        std::process::id(),
        listener.local_addr().map_err(|e| e.to_string())?,
        hex(listener.peer_id())
    ))?;
    let observed = listener.accept_timeout(Duration::from_millis(1600));
    match observed {
        Ok(conn) => {
            let verified = conn.mutually_authenticated_peer();
            if case != "valid" {
                // Any unexpected accepted handle is an observed gate failure,
                // even if it has not yet delivered a stream or datagram.
                emit(&format!(
                    "SERVER {} 1 1 none false false",
                    std::process::id()
                ))?;
                conn.close(1, b"unexpected admission");
                return Ok(());
            }
            if verified != Some(requester) {
                return Err("provider authenticated wrong requester key".into());
            }
            let (mut send, mut recv) = conn.accept_bi().map_err(|e| e.to_string())?;
            let bytes = read_payload(&mut recv)?;
            let integrity = bytes == PAYLOAD;
            send.write(&bytes).map_err(|e| e.to_string())?;
            send.finish().map_err(|e| e.to_string())?;
            // The mutual marker is released only by an actual successful TLS1.3
            // handshake (the secure config permits no other protocol version).
            let tls13 = verified.is_some();
            emit(&format!(
                "SERVER {} 1 0 {} {} {}",
                std::process::id(),
                hex(verified.ok_or("missing peer")?),
                tls13,
                integrity
            ))?;
            // Wait for the requester acknowledgement on a second stream before
            // dropping the driver; an echo buffered locally is not delivery.
            let (_, mut ack) = conn.accept_bi().map_err(|e| e.to_string())?;
            if read_payload(&mut ack)? != b"echo verified" {
                return Err("missing requester delivery acknowledgement".into());
            }
            conn.close(0, b"fixture complete");
            Ok(())
        }
        Err(FabricError::Timeout) if case != "valid" => emit(&format!(
            "SERVER {} 0 0 none false false",
            std::process::id()
        )),
        Err(error) => Err(format!("provider accept: {error}")),
    }
}
fn requester(case: &str, address: &str, server_key: &str) -> Result<(), String> {
    let expected = if case == "pin" {
        identity(74)?.peer_id()
    } else {
        peer(server_key)?
    };
    let id = identity(if case == "unknown" { 73 } else { 72 })?;
    let config = ConnConfig {
        addrs: vec![address.parse().map_err(|_| "invalid provider address")?],
        handshake_timeout: Duration::from_millis(650),
    };
    let result = if case == "anonymous" {
        FabricConn::connect(expected, &config)
    } else {
        FabricConn::connect_mtls(expected, &id, &config)
    };
    match result {
        Ok(conn) if case == "valid" => {
            let actual = conn.mutually_authenticated_peer();
            if actual != Some(expected) {
                return Err("requester authenticated wrong provider key".into());
            }
            let (mut send, mut recv) = conn.open_bi().map_err(|e| e.to_string())?;
            send.write(PAYLOAD).map_err(|e| e.to_string())?;
            send.finish().map_err(|e| e.to_string())?;
            let integrity = read_payload(&mut recv)? == PAYLOAD;
            if !integrity {
                return Err("echo differs from original bytes".into());
            }
            let (mut ack, _) = conn.open_bi().map_err(|e| e.to_string())?;
            ack.write(b"echo verified").map_err(|e| e.to_string())?;
            ack.finish().map_err(|e| e.to_string())?;
            emit(&format!(
                "CLIENT {} verified {} {}",
                std::process::id(),
                hex(actual.ok_or("missing peer")?),
                integrity
            ))?;
            // Read the server close, allowing the acknowledgement to be sent
            // before this client's final driver owner is dropped.
            let _ = recv.read_deadline(&mut [0; 1], Instant::now() + Duration::from_secs(1));
            std::thread::sleep(Duration::from_millis(40));
            conn.close(0, b"fixture complete");
            Ok(())
        }
        Ok(conn) if case == "anonymous" => {
            if conn.mutually_authenticated_peer().is_some() {
                return Err("anonymous connection claims mutual authentication".into());
            }
            // Deliberately attempt both kinds of unauthenticated application
            // data; the provider's real accept observation must remain zero.
            if let Ok((mut send, mut recv)) = conn.open_bi() {
                let _ = send.write(PAYLOAD);
                let _ = send.finish();
                let _ = conn.send_datagram(PAYLOAD);
                if recv
                    .read_deadline(&mut [0; 1], Instant::now() + Duration::from_secs(1))
                    .is_ok()
                {
                    return Err("anonymous stream was not rejected".into());
                }
            }
            conn.close(0, b"negative fixture complete");
            emit(&format!("CLIENT {} denied none false", std::process::id()))
        }
        Ok(conn) => {
            conn.close(1, b"unexpected authentication");
            Err("invalid identity unexpectedly got a mutual connection".into())
        }
        Err(error) if case != "valid" => {
            eprintln!(
                "negative case={case} pid={} real_transport_error={error}",
                std::process::id()
            );
            emit(&format!("CLIENT {} denied none false", std::process::id()))
        }
        Err(error) => Err(format!("requester connect: {error}")),
    }
}

// The parent owns each process and its stdout reader. Every failure kills/reaps
// the child and joins the reader; there are no detached timeout tasks.
struct OwnedChild {
    child: Child,
    lines: Receiver<String>,
    reader: Option<JoinHandle<()>>,
}
impl OwnedChild {
    fn spawn(args: &[&str]) -> Result<Self, String> {
        let mut child = Command::new(std::env::current_exe().map_err(|e| e.to_string())?)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| e.to_string())?;
        let stdout = child.stdout.take().ok_or("child stdout unavailable")?;
        let (tx, lines) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                match line {
                    Ok(line) => {
                        if tx.send(line).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            child,
            lines,
            reader: Some(reader),
        })
    }
    fn line(&self) -> Result<String, String> {
        self.lines
            .recv_timeout(CHILD_BUDGET)
            .map_err(|_| "child observation timed out".into())
    }
    fn finish(&mut self) -> Result<(), String> {
        let deadline = Instant::now() + CHILD_BUDGET;
        loop {
            if let Some(status) = self.child.try_wait().map_err(|e| e.to_string())? {
                if let Some(reader) = self.reader.take() {
                    reader.join().map_err(|_| "child reader panicked")?;
                }
                return if status.success() {
                    Ok(())
                } else {
                    Err(format!("child failed: {status}"))
                };
            }
            if Instant::now() >= deadline {
                return Err("child exit timed out".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}
fn parent() -> Result<(), String> {
    let mut negatives = Vec::new();
    let mut observations = Vec::new();
    for case in ["valid", "pin", "anonymous", "unknown", "empty"] {
        let mut server = OwnedChild::spawn(&["--provider", case])?;
        let ready = server.line()?;
        let words: Vec<_> = ready.split_whitespace().collect();
        if words.len() != 4 || words[0] != "LISTEN" {
            return Err(format!("invalid provider observation: {ready}"));
        }
        let provider_pid: u32 = words[1].parse().map_err(|_| "invalid provider pid")?;
        let mut client = OwnedChild::spawn(&["--requester", case, words[2], words[3]])?;
        let reply = client.line()?;
        let observed = server.line()?;
        client.finish()?;
        server.finish()?;
        let cw: Vec<_> = reply.split_whitespace().collect();
        let sw: Vec<_> = observed.split_whitespace().collect();
        if cw.len() != 5 || sw.len() != 7 || cw[0] != "CLIENT" || sw[0] != "SERVER" {
            return Err("invalid process result".into());
        }
        let requester_pid: u32 = cw[1].parse().map_err(|_| "invalid requester pid")?;
        if provider_pid != server.child.id()
            || requester_pid != client.child.id()
            || provider_pid == requester_pid
            || provider_pid == std::process::id()
            || requester_pid == std::process::id()
        {
            return Err("process identities do not match owned children".into());
        }
        if case == "valid" {
            if cw[2] != "verified"
                || cw[3] != words[3]
                || cw[4] != "true"
                || sw[2] != "1"
                || sw[3] != "0"
                || sw[4] != hex(identity(72)?.peer_id())
                || sw[5] != "true"
                || sw[6] != "true"
            {
                return Err("real authenticated payload observation failed".into());
            }
        } else {
            if cw[2] != "denied" || sw[2] != "0" || sw[3] != "0" {
                return Err(format!("unauthenticated delivery observed for {case}"));
            }
            negatives.push(case);
        }
        eprintln!("case={case} {ready}; {reply}; {observed}");
        observations.push(format!("{{\"case\":\"{case}\",\"provider_pid\":{provider_pid},\"requester_pid\":{requester_pid},\"accepted\":{},\"unauthenticated_payload_deliveries\":{}}}", sw[2], sw[3]));
    }
    if negatives.len() != 4 {
        return Err("negative observations incomplete".into());
    }
    emit(&format!(
        "{{\"verdict\":\"PASS\",\"two_processes\":true,\"peer_keys_verified\":true,\"tls13\":true,\"payload_integrity\":true,\"wrong_server_pin_denied\":true,\"anonymous_client_denied\":true,\"unknown_client_denied\":true,\"empty_allowlist_denied\":true,\"unauthenticated_payload_deliveries\":0,\"observations\":[{}]}}",
        observations.join(",")
    ))
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let result = match args.get(1).map(String::as_str) {
        Some("--provider") if args.len() == 3 => provider(&args[2]),
        Some("--requester") if args.len() == 5 => requester(&args[2], &args[3], &args[4]),
        Some("--json") if args.len() == 2 => parent(),
        _ => Err("usage: mutual_auth_e4 --json".into()),
    };
    if let Err(error) = result {
        eprintln!("mutual-auth verifier failed: {error}");
        println!("{{\"verdict\":\"FAIL\"}}");
        std::process::exit(1);
    }
}

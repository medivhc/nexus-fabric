//! Node-side real SSH client for the web terminal.
//!
//! The gateway node speaks the SSH protocol to the target sshd on the user's
//! behalf. The browser submits credentials in the `ssh_open` message; they are
//! used here to authenticate and are never persisted. The browser DataChannel
//! carries only the terminal byte stream (pty layer), not SSH protocol bytes.
//!
//! `run_ssh_client` owns the `ssh2::Session` in a dedicated thread: it reads
//! terminal output from the SSH channel and forwards it upstream, and forwards
//! terminal input (received over the browser/mesh channel) into the SSH channel.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::time::Duration;

use crate::protocol::SshAuth;

/// Commands sent from the gateway/mesh handler to the SSH worker thread.
pub enum SshInput {
    /// Terminal bytes typed by the user (forward to the sshd channel stdin).
    Data(Vec<u8>),
    /// The browser or an upstream node asked to close the terminal.
    Close,
}

/// TCP connect + SSH handshake timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Blocking-operation timeout used by libssh2 so the bridge loop can poll the
/// input channel and the stop flag while waiting for sshd output.
const SSH_IO_TIMEOUT_MS: u32 = 100;

/// Run one SSH client session until the channel closes, the input channel is
/// dropped, or [`stop`] is set.
///
/// - `output` is called with every chunk of bytes read from the sshd.
/// - `closed` is called once when the session ends, with a human-readable reason.
/// - `opened` is called once after pty+shell are established (`Ok(())`), or
///   with an error if the SSH connection/authentication/channel setup fails.
pub fn run_ssh_client(
    target: SocketAddr,
    auth: Option<SshAuth>,
    rx: Receiver<SshInput>,
    stop: Arc<AtomicBool>,
    mut output: impl FnMut(&[u8]) + Send + 'static,
    mut closed: impl FnMut(&str) + Send + 'static,
    mut opened: impl FnMut(Result<(), String>) + Send + 'static,
) {
    let tcp = match TcpStream::connect_timeout(&target, CONNECT_TIMEOUT) {
        Ok(t) => t,
        Err(e) => {
            opened(Err(format!("connect to sshd: {e}")));
            return;
        }
    };
    let _ = tcp.set_nodelay(true);

    let mut sess = match ssh2::Session::new() {
        Ok(s) => s,
        Err(e) => {
            opened(Err(format!("ssh session: {e}")));
            return;
        }
    };
    sess.set_tcp_stream(tcp);
    sess.set_timeout(SSH_IO_TIMEOUT_MS);

    if let Err(e) = sess.handshake() {
        opened(Err(format!("ssh handshake: {e}")));
        return;
    }

    if let Err(e) = authenticate(&sess, auth) {
        opened(Err(e));
        return;
    }
    if !sess.authenticated() {
        opened(Err("authentication failed: not authenticated".into()));
        return;
    }

    let mut ch = match sess.channel_session() {
        Ok(c) => c,
        Err(e) => {
            opened(Err(format!("open ssh channel: {e}")));
            return;
        }
    };
    if let Err(e) = ch.request_pty("xterm", None, Some((80, 24, 0, 0))) {
        opened(Err(format!("request pty: {e}")));
        return;
    }
    if let Err(e) = ch.shell() {
        opened(Err(format!("start shell: {e}")));
        return;
    }

    opened(Ok(()));

    let mut buf = [0u8; 4096];
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }

        // Drain terminal input from the browser/mesh.
        loop {
            match rx.try_recv() {
                Ok(SshInput::Data(bytes)) => {
                    if ch.write_all(&bytes).is_err() {
                        closed("sshd write error");
                        return;
                    }
                    let _ = ch.flush();
                }
                Ok(SshInput::Close) => {
                    closed("client closed");
                    return;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    // The upstream session is gone; exit.
                    return;
                }
            }
        }

        // Read sshd output.
        match ch.read(&mut buf) {
            Ok(0) => {
                closed("sshd closed connection");
                return;
            }
            Ok(n) => output(&buf[..n]),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // No output pending: loop to re-check the stop flag and input.
            }
            Err(e) => {
                closed(&format!("sshd read error: {e}"));
                return;
            }
        }
    }
}

/// Authenticate the SSH session with the browser-provided credentials.
fn authenticate(sess: &ssh2::Session, auth: Option<SshAuth>) -> Result<(), String> {
    match auth {
        Some(SshAuth::Password { username, password }) => sess
            .userauth_password(&username, &password)
            .map_err(|e| format!("authentication failed: {e}")),
        Some(SshAuth::Key {
            username,
            private_key,
        }) => sess
            .userauth_pubkey_memory(&username, None, &private_key, None)
            .map_err(|e| format!("authentication failed: {e}")),
        None => Err("no credentials provided (form is empty)".into()),
    }
}

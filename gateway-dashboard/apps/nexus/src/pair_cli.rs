//! `nexus pair` 命令族：设备配对（D7）。
//!
//! 职责：
//! - `invite`：生成配对码 + 前台 TCP 监听（5 分钟超时），等待加入方完成握手
//! - `join`：输入配对码，连接邀请方完成握手
//! - `list`：列出已配对设备（`peers/` 目录）
//! - `remove`：删除已配对设备
//!
//! 身份与存储：
//! - `<config-dir>/identity.toml`：本机 ed25519 身份（600 权限）
//! - `<config-dir>/peers/<hex>.toml`：已配对设备（644 权限）
//!
//! 纯本地文件操作 + 前台 TCP，不经过 daemon（daemon 热加载 peers/ 目录）。

use nexus_discovery::paired::{
    NodeIdentity, PairedPeer, PairingCode, PairingError, PairingFrame, decode_pairing_frame,
    decode_peer_file, encode_pairing_frame, encode_peer_file, hex_decode, hex_encode,
    pairing_sign_msg,
};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// 配对握手 TCP 端口（邀请方监听）。
const PAIR_PORT: u16 = 18443;
/// 邀请方监听超时（5 分钟）。
const INVITE_TIMEOUT: Duration = Duration::from_secs(300);
/// 单次握手 I/O 超时。
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// `nexus pair` 入口。返回进程退出码。
pub fn run_pair(args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln!("usage: nexus pair invite|join|list|remove --dir <config-dir> [...]");
        return 2;
    }
    match args[0].as_str() {
        "invite" => run_invite(&args[1..]),
        "join" => run_join(&args[1..]),
        "list" => run_list(&args[1..]),
        "remove" => run_remove(&args[1..]),
        other => {
            eprintln!("error: unknown pair subcommand '{other}'");
            eprintln!("usage: nexus pair invite|join|list|remove --dir <config-dir> [...]");
            2
        }
    }
}

/// 从 args 解析 `--dir <config-dir>`。
fn parse_dir(args: &[String]) -> Result<PathBuf, String> {
    let mut iter = args.iter().peekable();
    while let Some(a) = iter.next() {
        if a == "--dir" {
            let d = iter
                .next()
                .ok_or_else(|| "missing value for --dir".to_string())?;
            return Ok(PathBuf::from(d));
        }
    }
    Err("missing --dir <config-dir>".to_string())
}

/// 从 args 解析 `--name <name>`（可选）。
fn parse_name(args: &[String]) -> Option<String> {
    let mut iter = args.iter().peekable();
    while let Some(a) = iter.next() {
        if a == "--name" {
            return iter.next().cloned();
        }
    }
    None
}

/// 从 args 解析 `--addr <ip:port>`（可选）。
fn parse_addr(args: &[String]) -> Option<String> {
    let mut iter = args.iter().peekable();
    while let Some(a) = iter.next() {
        if a == "--addr" {
            return iter.next().cloned();
        }
    }
    None
}

/// 加载或生成本机身份（`identity.toml`）。
fn load_or_create_identity(dir: &Path) -> Result<NodeIdentity, String> {
    let path = dir.join("identity.toml");
    if path.exists() {
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        // 解析 seed = "<64 hex>"
        for line in text.lines() {
            let line = line.trim();
            if let Some(hex) = line.strip_prefix("seed") {
                let hex = hex.trim().trim_start_matches('=').trim().trim_matches('"');
                let bytes = hex_decode(hex).map_err(|e| format!("bad seed hex: {e}"))?;
                if bytes.len() != 32 {
                    return Err("identity.toml: seed must be 32 bytes".to_string());
                }
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&bytes);
                return NodeIdentity::from_seed(&seed)
                    .map_err(|e| format!("identity from_seed: {e}"));
            }
        }
        return Err("identity.toml: missing seed field".to_string());
    }
    // 生成新身份并持久化（600 权限）。
    let identity = NodeIdentity::generate().map_err(|e| format!("generate identity: {e}"))?;
    let seed_hex = hex_encode(&identity.seed());
    let text = format!("# Nexus node identity (ed25519). KEEP PRIVATE.\nseed = \"{seed_hex}\"\n");
    std::fs::write(&path, text).map_err(|e| format!("write {}: {e}", path.display()))?;
    // 设置 600 权限（Unix）。
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path)
            .map_err(|e| format!("metadata {}: {e}", path.display()))?
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&path, perms)
            .map_err(|e| format!("chmod {}: {e}", path.display()))?;
    }
    Ok(identity)
}

/// 从 `peers/` 目录加载所有已配对设备。
fn load_peers(dir: &Path) -> Result<Vec<PairedPeer>, String> {
    let peers_dir = dir.join("peers");
    if !peers_dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let entries =
        std::fs::read_dir(&peers_dir).map_err(|e| format!("read {}: {e}", peers_dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read_dir entry: {e}"))?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        match decode_peer_file(&text) {
            Ok(peer) => out.push(peer),
            Err(e) => eprintln!("warning: skip {}: {e}", path.display()),
        }
    }
    out.sort_by_key(|a| a.peer_id);
    Ok(out)
}

/// 保存一个已配对设备到 `peers/<hex>.toml`。
fn save_peer(dir: &Path, peer: &PairedPeer) -> Result<(), String> {
    let peers_dir = dir.join("peers");
    std::fs::create_dir_all(&peers_dir)
        .map_err(|e| format!("create {}: {e}", peers_dir.display()))?;
    let filename = format!("{}.toml", hex_encode(&peer.peer_id));
    let path = peers_dir.join(filename);
    let text = encode_peer_file(peer);
    std::fs::write(&path, text).map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(())
}

/// 当前 Unix 时间戳（秒）。
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `nexus pair invite --dir <dir> [--name <name>]`
///
/// 生成配对码，打印到 stdout，然后在前台监听 TCP 等待加入方（5 分钟超时）。
fn run_invite(args: &[String]) -> i32 {
    let dir = match parse_dir(args) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!("usage: nexus pair invite --dir <config-dir> [--name <name>]");
            return 2;
        }
    };
    if !dir.is_dir() {
        eprintln!("error: not a directory: {}", dir.display());
        return 1;
    }
    let name = parse_name(args).unwrap_or_else(|| "nexus-node".to_string());
    let identity = match load_or_create_identity(&dir) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };

    // 生成配对码。
    let code = match PairingCode::generate(identity.peer_id()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: generate pairing code: {e}");
            return 1;
        }
    };
    println!("pairing code (valid 5 minutes, share via secure channel):");
    println!();
    println!("  {}", code.encode());
    println!();
    println!("waiting for peer to join on port {PAIR_PORT}... (Ctrl-C to cancel)");

    // 前台 TCP 监听。
    let listener = match TcpListener::bind(("0.0.0.0", PAIR_PORT)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: bind 0.0.0.0:{PAIR_PORT}: {e}");
            return 1;
        }
    };
    listener.set_nonblocking(false).unwrap_or(());
    let deadline = Instant::now() + INVITE_TIMEOUT;

    // 生成 token（从配对码中提取，用于验证签名）。
    let token = code.token;

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            eprintln!("error: invite timed out (5 minutes)");
            return 1;
        }
        // 用短超时 accept 以便检查 deadline。
        listener.set_nonblocking(true).unwrap_or(());
        match listener.accept() {
            Ok((stream, addr)) => {
                println!("connection from {addr}, performing handshake...");
                match handle_invite_handshake(stream, &identity, &name, &token, &dir) {
                    Ok(peer_name) => {
                        println!("paired with '{peer_name}' successfully");
                        return 0;
                    }
                    Err(e) => {
                        eprintln!("error: handshake failed: {e}");
                        return 1;
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(e) => {
                eprintln!("error: accept: {e}");
                return 1;
            }
        }
    }
}

/// 邀请方握手：接收 PairRequest → 验证 → 发送 PairAccept → 保存 peer。
fn handle_invite_handshake(
    stream: TcpStream,
    identity: &NodeIdentity,
    name: &str,
    expected_token: &[u8; 16],
    dir: &Path,
) -> Result<String, String> {
    stream
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|e| format!("set timeout: {e}"))?;
    stream
        .set_write_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|e| format!("set timeout: {e}"))?;

    let mut stream = stream;
    // 读取 PairRequest（长度前缀 u16 BE + payload）。
    let frame_bytes = read_frame(&mut stream)?;
    let frame = decode_pairing_frame(&frame_bytes).map_err(|e| format!("decode: {e}"))?;
    let (peer_id, token, peer_name) = match frame {
        PairingFrame::PairRequest {
            peer_id,
            token,
            name,
        } => (peer_id, token, name),
        _ => return Err("expected PairRequest".to_string()),
    };

    // 验证 token 匹配（防重放/配对码混淆）。
    if token != *expected_token {
        let reject = PairingFrame::PairReject {
            reason: "token mismatch".to_string(),
        };
        let reject_bytes =
            encode_pairing_frame(&reject).map_err(|e| format!("encode reject: {e}"))?;
        let _ = write_frame(&mut stream, &reject_bytes);
        return Err(PairingError::TokenMismatch.to_string());
    }

    // 签名：sign(sk_A, token || peer_id_B)。
    let msg = pairing_sign_msg(&token, &peer_id);
    let signature = identity.sign(&msg);

    // 发送 PairAccept。
    let accept = PairingFrame::PairAccept {
        peer_id: identity.peer_id(),
        name: name.to_string(),
        signature,
    };
    let accept_bytes = encode_pairing_frame(&accept).map_err(|e| format!("encode: {e}"))?;
    write_frame(&mut stream, &accept_bytes)?;

    // 保存 peer（地址取 TCP 对端地址）。
    let peer_addr = stream.peer_addr().map_err(|e| format!("peer_addr: {e}"))?;
    let peer = PairedPeer {
        peer_id,
        name: peer_name.clone(),
        addresses: vec![peer_addr],
        paired_at: now_secs(),
    };
    save_peer(dir, &peer)?;

    Ok(peer_name)
}

/// `nexus pair join --dir <dir> <code> [--addr <ip:port>] [--name <name>]`
fn run_join(args: &[String]) -> i32 {
    let dir = match parse_dir(args) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!(
                "usage: nexus pair join --dir <config-dir> <code> [--addr <ip:port>] [--name <name>]"
            );
            return 2;
        }
    };
    if !dir.is_dir() {
        eprintln!("error: not a directory: {}", dir.display());
        return 1;
    }
    // 找到配对码（第一个非 flag 参数，跳过 --dir/--addr/--name 及其值）。
    let code_str = {
        let mut iter = args.iter().peekable();
        let mut result = None;
        while let Some(s) = iter.next() {
            if s == "--dir" || s == "--addr" || s == "--name" {
                iter.next();
                continue;
            }
            if s.starts_with("--") {
                continue;
            }
            result = Some(s.clone());
            break;
        }
        result
    };
    let code_str = match code_str {
        Some(c) => c,
        None => {
            eprintln!("error: missing <code>");
            eprintln!(
                "usage: nexus pair join --dir <config-dir> <code> [--addr <ip:port>] [--name <name>]"
            );
            return 2;
        }
    };
    let code = match PairingCode::decode(&code_str) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: invalid pairing code: {e}");
            return 1;
        }
    };
    let name = parse_name(args).unwrap_or_else(|| "nexus-node".to_string());
    let identity = match load_or_create_identity(&dir) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };

    // 确定邀请方地址。
    let addr_str = match parse_addr(args) {
        Some(a) => a,
        None => {
            eprintln!(
                "error: --addr <ip:port> is required (mDNS discovery not yet implemented in CLI)"
            );
            eprintln!(
                "hint: run 'nexus pair invite' on the other device, it listens on port {PAIR_PORT}"
            );
            return 2;
        }
    };
    let addr: SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: invalid --addr '{addr_str}': {e}");
            return 2;
        }
    };

    // 连接并握手。
    println!("connecting to {addr}...");
    let stream = match TcpStream::connect_timeout(&addr, HANDSHAKE_TIMEOUT) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: connect {addr}: {e}");
            return 1;
        }
    };
    match handle_join_handshake(stream, &identity, &name, &code, &dir) {
        Ok(peer_name) => {
            println!("paired with '{peer_name}' successfully");
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

/// 加入方握手：发送 PairRequest → 接收 PairAccept → 验证签名 → 保存 peer。
fn handle_join_handshake(
    stream: TcpStream,
    identity: &NodeIdentity,
    name: &str,
    code: &PairingCode,
    dir: &Path,
) -> Result<String, String> {
    stream
        .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|e| format!("set timeout: {e}"))?;
    stream
        .set_write_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|e| format!("set timeout: {e}"))?;
    let mut stream = stream;

    // 发送 PairRequest。
    let request = PairingFrame::PairRequest {
        peer_id: identity.peer_id(),
        token: code.token,
        name: name.to_string(),
    };
    let request_bytes = encode_pairing_frame(&request).map_err(|e| format!("encode: {e}"))?;
    write_frame(&mut stream, &request_bytes)?;

    // 接收 PairAccept 或 PairReject。
    let frame_bytes = read_frame(&mut stream)?;
    let frame = decode_pairing_frame(&frame_bytes).map_err(|e| format!("decode: {e}"))?;
    let (peer_id, peer_name, signature) = match frame {
        PairingFrame::PairAccept {
            peer_id,
            name,
            signature,
        } => (peer_id, name, signature),
        PairingFrame::PairReject { reason } => {
            return Err(format!("rejected by peer: {reason}"));
        }
        _ => return Err("expected PairAccept".to_string()),
    };

    // 验证：code 中的 pubkey 必须与 PairAccept 中的 peer_id 一致。
    if peer_id != code.peer_id {
        return Err("peer_id mismatch: PairAccept pubkey != pairing code pubkey".to_string());
    }

    // 验证签名：verify(pk_A, sign(sk_A, token || peer_id_B), token || peer_id_B)。
    let msg = pairing_sign_msg(&code.token, &identity.peer_id());
    if !NodeIdentity::verify(&peer_id, &msg, &signature) {
        return Err("signature verification failed".to_string());
    }

    // 保存 peer（地址取连接目标地址）。
    let peer_addr = stream.peer_addr().map_err(|e| format!("peer_addr: {e}"))?;
    let peer = PairedPeer {
        peer_id,
        name: peer_name.clone(),
        addresses: vec![peer_addr],
        paired_at: now_secs(),
    };
    save_peer(dir, &peer)?;

    Ok(peer_name)
}

/// `nexus pair list --dir <dir>`
fn run_list(args: &[String]) -> i32 {
    let dir = match parse_dir(args) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!("usage: nexus pair list --dir <config-dir>");
            return 2;
        }
    };
    let peers = match load_peers(&dir) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    if peers.is_empty() {
        println!("no paired devices");
        return 0;
    }
    for peer in peers {
        let id_hex = hex_encode(&peer.peer_id);
        let addrs: Vec<String> = peer.addresses.iter().map(|a| a.to_string()).collect();
        println!("{id_hex}  {}  [{}]", peer.name, addrs.join(", "));
    }
    0
}

/// `nexus pair remove --dir <dir> <peer-id-hex>`
fn run_remove(args: &[String]) -> i32 {
    let dir = match parse_dir(args) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!("usage: nexus pair remove --dir <config-dir> <peer-id-hex>");
            return 2;
        }
    };
    // 找到 peer-id（第一个非 flag 参数）。
    let id_hex = {
        let mut iter = args.iter().peekable();
        let mut result = None;
        while let Some(s) = iter.next() {
            if s == "--dir" {
                iter.next();
                continue;
            }
            if s.starts_with("--") {
                continue;
            }
            result = Some(s.clone());
            break;
        }
        result
    };
    let id_hex = match id_hex {
        Some(h) => h,
        None => {
            eprintln!("error: missing <peer-id-hex>");
            eprintln!("usage: nexus pair remove --dir <config-dir> <peer-id-hex>");
            return 2;
        }
    };
    // 支持完整 hex 或前缀匹配。
    let peers = match load_peers(&dir) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let matches: Vec<&PairedPeer> = peers
        .iter()
        .filter(|p| hex_encode(&p.peer_id).starts_with(&id_hex))
        .collect();
    match matches.len() {
        0 => {
            eprintln!("error: no paired device matches '{id_hex}'");
            1
        }
        1 => {
            let peer = matches[0];
            let filename = format!("{}.toml", hex_encode(&peer.peer_id));
            let path = dir.join("peers").join(filename);
            match std::fs::remove_file(&path) {
                Ok(()) => {
                    println!("removed '{}' ({})", peer.name, hex_encode(&peer.peer_id));
                    0
                }
                Err(e) => {
                    eprintln!("error: remove {}: {e}", path.display());
                    1
                }
            }
        }
        _ => {
            eprintln!(
                "error: ambiguous prefix '{id_hex}' matches {} devices:",
                matches.len()
            );
            for p in matches {
                eprintln!("  {}  {}", hex_encode(&p.peer_id), p.name);
            }
            1
        }
    }
}

/// 读取长度前缀帧（u16 BE 长度 + payload）。
fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| format!("read frame len: {e}"))?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len > 64 * 1024 {
        return Err(format!("frame too large: {len}"));
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .map_err(|e| format!("read frame: {e}"))?;
    Ok(buf)
}

/// 写入长度前缀帧。
fn write_frame(stream: &mut TcpStream, payload: &[u8]) -> Result<(), String> {
    if payload.len() > u16::MAX as usize {
        return Err("frame too large".to_string());
    }
    let len = (payload.len() as u16).to_be_bytes();
    stream
        .write_all(&len)
        .map_err(|e| format!("write frame len: {e}"))?;
    stream
        .write_all(payload)
        .map_err(|e| format!("write frame: {e}"))?;
    stream.flush().map_err(|e| format!("flush: {e}"))?;
    Ok(())
}

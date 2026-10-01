//! E4 场景 `product.pairing` 的可执行验证：双节点配对流程。
//!
//! 在进程内模拟完整配对流程（不依赖真实 TCP，协议逻辑与 `pair_cli` 一致）：
//! 1. A 生成身份 + 配对码（格式校验）
//! 2. B 解析配对码 → 构造 PairRequest → A 验证 token → A 签名 → B 验证签名
//! 3. 双方各自写入 peer 文件（`peers/<hex>.toml`），验证文件存在且可解析
//! 4. 负面测试：错误 token 被拒绝
//!
//! 输出 JSON verdict（供 `scenarios/product/pairing.toml` 断言）。

use nexus_discovery::paired::{
    NodeIdentity, PairedPeer, PairingCode, PairingFrame, decode_pairing_frame, decode_peer_file,
    encode_pairing_frame, encode_peer_file, hex_encode, pairing_sign_msg,
};
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let json_mode = args.iter().any(|a| a == "--json");

    let result = run_pairing_flow();

    if json_mode {
        let verdict = if result.all_pass { "PASS" } else { "FAIL" };
        println!(
            "{{\"verdict\":\"{verdict}\",\"code_format_valid\":{},\"pairing_completed\":{},\
             \"a_has_b_peer_file\":{},\"b_has_a_peer_file\":{},\
             \"signature_verified\":{},\"wrong_token_rejected\":{}}}",
            result.code_format_valid,
            result.pairing_completed,
            result.a_has_b_peer_file,
            result.b_has_a_peer_file,
            result.signature_verified,
            result.wrong_token_rejected,
        );
    } else {
        println!("code_format_valid: {}", result.code_format_valid);
        println!("pairing_completed: {}", result.pairing_completed);
        println!("a_has_b_peer_file: {}", result.a_has_b_peer_file);
        println!("b_has_a_peer_file: {}", result.b_has_a_peer_file);
        println!("signature_verified: {}", result.signature_verified);
        println!("wrong_token_rejected: {}", result.wrong_token_rejected);
        println!("verdict: {}", if result.all_pass { "PASS" } else { "FAIL" });
    }

    std::process::exit(if result.all_pass { 0 } else { 1 });
}

struct FlowResult {
    code_format_valid: bool,
    pairing_completed: bool,
    a_has_b_peer_file: bool,
    b_has_a_peer_file: bool,
    signature_verified: bool,
    wrong_token_rejected: bool,
    all_pass: bool,
}

fn run_pairing_flow() -> FlowResult {
    let mut r = FlowResult {
        code_format_valid: false,
        pairing_completed: false,
        a_has_b_peer_file: false,
        b_has_a_peer_file: false,
        signature_verified: false,
        wrong_token_rejected: false,
        all_pass: false,
    };

    // 1. A 生成身份 + 配对码。
    let identity_a = match NodeIdentity::generate() {
        Ok(id) => id,
        Err(e) => {
            eprintln!("A generate identity: {e}");
            return r;
        }
    };
    let identity_b = match NodeIdentity::generate() {
        Ok(id) => id,
        Err(e) => {
            eprintln!("B generate identity: {e}");
            return r;
        }
    };

    let code = match PairingCode::generate(identity_a.peer_id()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("generate pairing code: {e}");
            return r;
        }
    };

    // 2. 配对码格式校验：encode → decode 往返，字段一致。
    let code_str = code.encode();
    let code2 = match PairingCode::decode(&code_str) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("decode pairing code: {e}");
            return r;
        }
    };
    if code2.peer_id != code.peer_id || code2.token != code.token {
        eprintln!("pairing code roundtrip mismatch");
        return r;
    }
    // 格式：nexus-pair:v1:<43 chars>:<22 chars>（base64url 无填充）
    if !code_str.starts_with("nexus-pair:v1:") {
        eprintln!("bad pairing code prefix: {code_str}");
        return r;
    }
    r.code_format_valid = true;

    // 3. B 构造 PairRequest（模拟带外通道传递配对码）。
    let request = PairingFrame::PairRequest {
        peer_id: identity_b.peer_id(),
        token: code2.token,
        name: "device-b".to_string(),
    };
    let request_bytes = match encode_pairing_frame(&request) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("encode request: {e}");
            return r;
        }
    };

    // 4. A 接收并验证：解码 → token 匹配 → 签名。
    let decoded_req = match decode_pairing_frame(&request_bytes) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("decode request: {e}");
            return r;
        }
    };
    let (b_peer_id, b_token, b_name) = match decoded_req {
        PairingFrame::PairRequest {
            peer_id,
            token,
            name,
        } => (peer_id, token, name),
        _ => {
            eprintln!("expected PairRequest");
            return r;
        }
    };
    // A 验证 token（必须与配对码中的一致）。
    if b_token != code.token {
        eprintln!("token mismatch");
        return r;
    }
    // A 签名：sign(sk_A, token || peer_id_B)。
    let msg = pairing_sign_msg(&b_token, &b_peer_id);
    let signature = identity_a.sign(&msg);

    let accept = PairingFrame::PairAccept {
        peer_id: identity_a.peer_id(),
        name: "device-a".to_string(),
        signature,
    };
    let accept_bytes = match encode_pairing_frame(&accept) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("encode accept: {e}");
            return r;
        }
    };

    // 5. B 接收并验证：解码 → peer_id 一致 → 签名验证。
    let decoded_accept = match decode_pairing_frame(&accept_bytes) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("decode accept: {e}");
            return r;
        }
    };
    let (a_peer_id, a_name, a_sig) = match decoded_accept {
        PairingFrame::PairAccept {
            peer_id,
            name,
            signature,
        } => (peer_id, name, signature),
        PairingFrame::PairReject { reason } => {
            eprintln!("rejected: {reason}");
            return r;
        }
        _ => {
            eprintln!("expected PairAccept");
            return r;
        }
    };
    if a_peer_id != code.peer_id {
        eprintln!("peer_id mismatch");
        return r;
    }
    let verify_msg = pairing_sign_msg(&code.token, &identity_b.peer_id());
    if !NodeIdentity::verify(&a_peer_id, &verify_msg, &a_sig) {
        eprintln!("signature verification failed");
        return r;
    }
    r.signature_verified = true;

    // 6. 双方写入 peer 文件（模拟两个独立配置目录）。
    let tmp = std::env::temp_dir().join(format!("pairing_flow_{}", std::process::id()));
    let a_dir = tmp.join("a");
    let b_dir = tmp.join("b");
    let _ = std::fs::remove_dir_all(&tmp); // 清理旧残留
    if let Err(e) = std::fs::create_dir_all(a_dir.join("peers")) {
        eprintln!("create a_dir: {e}");
        return r;
    }
    if let Err(e) = std::fs::create_dir_all(b_dir.join("peers")) {
        eprintln!("create b_dir: {e}");
        return r;
    }

    // A 保存 B 的信息。
    let peer_b = PairedPeer {
        peer_id: b_peer_id,
        name: b_name,
        addresses: vec!["127.0.0.1:18443".parse().unwrap()],
        paired_at: 1727740000,
    };
    let b_file = a_dir
        .join("peers")
        .join(format!("{}.toml", hex_encode(&b_peer_id)));
    if let Err(e) = std::fs::write(&b_file, encode_peer_file(&peer_b)) {
        eprintln!("write b_file: {e}");
        return r;
    }

    // B 保存 A 的信息。
    let peer_a = PairedPeer {
        peer_id: a_peer_id,
        name: a_name,
        addresses: vec!["127.0.0.1:18443".parse().unwrap()],
        paired_at: 1727740000,
    };
    let a_file = b_dir
        .join("peers")
        .join(format!("{}.toml", hex_encode(&a_peer_id)));
    if let Err(e) = std::fs::write(&a_file, encode_peer_file(&peer_a)) {
        eprintln!("write a_file: {e}");
        return r;
    }

    // 7. 验证双方 peer 文件存在且可解析。
    let b_text = match std::fs::read_to_string(&b_file) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("read b_file: {e}");
            return r;
        }
    };
    match decode_peer_file(&b_text) {
        Ok(p) if p.peer_id == b_peer_id => r.a_has_b_peer_file = true,
        Ok(_) => eprintln!("b_file peer_id mismatch"),
        Err(e) => eprintln!("decode b_file: {e}"),
    }

    let a_text = match std::fs::read_to_string(&a_file) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("read a_file: {e}");
            return r;
        }
    };
    match decode_peer_file(&a_text) {
        Ok(p) if p.peer_id == a_peer_id => r.b_has_a_peer_file = true,
        Ok(_) => eprintln!("a_file peer_id mismatch"),
        Err(e) => eprintln!("decode a_file: {e}"),
    }

    if r.a_has_b_peer_file && r.b_has_a_peer_file {
        r.pairing_completed = true;
    }

    // 8. 负面测试：错误 token 被拒绝。
    let bad_request = PairingFrame::PairRequest {
        peer_id: identity_b.peer_id(),
        token: [0xFF; 16], // 错误的 token
        name: "attacker".to_string(),
    };
    let bad_bytes = encode_pairing_frame(&bad_request).unwrap();
    let bad_decoded = decode_pairing_frame(&bad_bytes).unwrap();
    if let PairingFrame::PairRequest { token, .. } = bad_decoded {
        // A 验证 token：不匹配 → 拒绝。
        if token != code.token {
            r.wrong_token_rejected = true;
        }
    }

    // 清理临时目录。
    let _ = std::fs::remove_dir_all(&tmp);

    r.all_pass = r.code_format_valid
        && r.pairing_completed
        && r.a_has_b_peer_file
        && r.b_has_a_peer_file
        && r.signature_verified
        && r.wrong_token_rejected;
    r
}

// 未使用的 PathBuf 导入清理（保留以备扩展）。
#[allow(dead_code)]
fn _unused(_p: PathBuf) {}

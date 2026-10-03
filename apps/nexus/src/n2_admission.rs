//! N2 跨机准入协议（P0-5）：提供方侧 admission（D6）＋挑战-应答握手。
//!
//! 背景：P0-4 的 `nexus use` 在本地同时扮演请求方与提供方；`n2_identity.rs`
//! 预告"完整握手在 P0-5"。本模块实现跨机时的握手与准入：
//!
//! - B 机 `nexus provider serve --bind <addr:port>`：TCP 监听；每连接先发送
//!   32 字节随机 challenge，请求方以其 ed25519 身份密钥签名后发送准入请求；
//! - 提供方验证签名 → principal 由**验证过**的公钥派生（D6"不接受请求方自称"
//!   硬约束）→ 查**本地** grant 表（D6：授权判定在 provider 侧每次建 Session
//!   时执行）→ 每次判定写审计记录 → 允许则写租约（D1：提供方侧只做
//!   admission＋租约，不建第二个领域 Session）；
//! - 线路格式 `n2-admission-v1`：独立 TCP 连接上的 u32 BE 长度前缀＋JSON。
//!   不复用 0x21–0x25 控制帧——D8"传输无关（流类型前缀）"：准入是独立的流类型，
//!   冻结的 5 种帧不做任何修改（无 requirement-change）。
//!
//! P0 安全边界（诚实声明）：challenge-response 证明请求方持有其声称公钥对应
//! 的私钥（防被动冒名）；无保密性、无前向安全——完整双向认证通道为 P1 演进
//! 方向（D8"QUIC 复用为演进方向"），P0 威胁模型为单 Workspace 单管理员。

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use nexus_auth::{AuthRequest, GrantTable, Principal};
use nexus_domain::{ResourceId, ResourceOperation, ResourceRef, WorkspaceId};
use nexus_registry::ProviderAdvertisement;
use ring::signature::UnparsedPublicKey;

use crate::n2_directory::{DEFAULT_WORKSPACE, N2Directory};
use crate::n2_identity::{auth_keypair, ensure_auth_identity};
use crate::n2_store::{N2Store, local_actor, now_unix_pub};

/// 准入流协议版本。
pub const ADMISSION_PROTOCOL_V1: u32 = 1;

/// 广告 locator 中标记提供方准入端点的 scheme（`n2adm://host:port`）。
///
/// 约定：`resource publish` 的 locator 列表中，首个非 `n2adm://` locator 为
/// Service 数据面端点（`service_locator_of` 提取，写入 `ProviderRecord.locator`
/// 作 plan.path；P1-13：不再无条件取 `locators[0]`）；`n2adm://` locator 为
/// 准入控制端点（`use` 跨机时拨号，见 `control_locator_of`）。
pub const CONTROL_LOCATOR_SCHEME: &str = "n2adm://";

/// 提供方租约 TTL（秒；与 `use_cli::LEASE_TTL_SECS` 一致，P0 固定 1 小时）。
pub const ADMISSION_LEASE_TTL_SECS: u64 = 3600;

/// 准入请求（请求方 → 提供方，JSON）。
#[derive(Debug)]
pub struct AdmissionRequest {
    pub v: u32,
    /// 请求方 ed25519 公钥 hex（64 字符）。
    pub pubkey_hex: String,
    /// 对 challenge 的签名 hex（128 字符）。
    pub sig_hex: String,
    /// 请求方已 open 的会话 id（提供方租约与之关联；两侧独立提交终态，D1）。
    pub session_id: String,
    /// 不透明资源 Id（D2：名字不出传输层）。
    pub resource_id: String,
    /// 操作（P0 仅 "Use"）。
    pub operation: String,
}

/// 准入判定结果（提供方 → 请求方）。
#[derive(Debug, PartialEq, Eq)]
pub enum AdmissionVerdict {
    /// 允许：携带提供方标识与 Service 数据面端点。
    Admitted { provider: String, endpoint: String },
    /// 拒绝：结构化 Deny 码（D6 五种之一）；审计已写。
    Denied { deny: String },
    /// 资源未知（提供方已 revoke/withdraw；请求方应失效本地缓存广告）。
    NotFound,
}

/// 准入客户端错误（传输/协议层；与提供方的判定 `Denied` 区分）。
#[derive(Debug)]
pub enum AdmitError {
    /// 连接失败（对端下线/不可达 → 调用方映射为 ProviderOffline）。
    Connect(String),
    Io(String),
    Protocol(String),
    Crypto(String),
}

impl std::fmt::Display for AdmitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdmitError::Connect(e) => write!(f, "connect: {e}"),
            AdmitError::Io(e) => write!(f, "io: {e}"),
            AdmitError::Protocol(e) => write!(f, "protocol: {e}"),
            AdmitError::Crypto(e) => write!(f, "crypto: {e}"),
        }
    }
}

/// 已处理的准入连接序号（仅 B 侧 stderr 结构化日志 `conn #N` 用；
/// review-n2-p05 WARN-3：原 `pub fn connection_count()` 零调用者且注释误导
/// （跨进程的 `nexus plan` 只读断言不可能用它），已删除。plan 只读性的真实
/// 观测通道是 B 侧日志，见 P0-5 E5 报告 #4）。
static CONNECTION_COUNT: AtomicU64 = AtomicU64::new(0);

/// 从广告 locator 列表中提取准入控制端点（`n2adm://host:port` → `host:port`）。
#[must_use]
pub fn control_locator_of(ad: &ProviderAdvertisement) -> Option<String> {
    ad.locators
        .iter()
        .find(|l| l.starts_with(CONTROL_LOCATOR_SCHEME))
        .map(|l| l[CONTROL_LOCATOR_SCHEME.len()..].to_string())
}

/// 从广告 locator 列表中提取 Service 数据面端点（首个非 `n2adm://` 条目）。
#[must_use]
pub fn service_locator_of(ad: &ProviderAdvertisement) -> Option<String> {
    ad.locators
        .iter()
        .find(|l| !l.starts_with(CONTROL_LOCATOR_SCHEME))
        .cloned()
}

// ---------------------------------------------------------------------------
// 线路编解码（u32 BE 长度前缀＋JSON；单连接单请求-响应）
// ---------------------------------------------------------------------------

const MAX_FRAME_BYTES: usize = 64 * 1024;

fn write_frame(stream: &mut TcpStream, payload: &[u8]) -> Result<(), String> {
    let len = u32::try_from(payload.len()).map_err(|_| "frame too large".to_string())?;
    stream
        .write_all(&len.to_be_bytes())
        .and_then(|()| stream.write_all(payload))
        .map_err(|e| format!("write frame: {e}"))
}

fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| format!("read frame len: {e}"))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_FRAME_BYTES {
        return Err(format!("bad frame len: {len}"));
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .map_err(|e| format!("read frame body: {e}"))?;
    Ok(buf)
}

fn hex_decode(s: &str, expect_len: usize, what: &str) -> Result<Vec<u8>, String> {
    if s.len() != expect_len * 2 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("bad {what} hex"));
    }
    (0..expect_len)
        .map(|i| {
            u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| format!("{what} hex: {e}"))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// 提供方侧：admission 服务
// ---------------------------------------------------------------------------

/// 处理一条准入连接（B 机侧；阻塞式，P0 顺序处理）。
///
/// 返回人类可读的判定摘要（stderr 日志用）。
pub fn serve_one_connection(stream: &mut TcpStream, node_dir: &std::path::Path) -> String {
    let n = CONNECTION_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "?".to_string());
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let outcome = handle_admission(stream, node_dir);
    format!("n2-admission: conn #{n} from {peer} -> {outcome}")
}

/// 单连接准入处理内核（可测试；`stream` 已连入）。
fn handle_admission(stream: &mut TcpStream, node_dir: &std::path::Path) -> String {
    // 1. 发送 challenge（32 随机字节）。
    let mut challenge = [0u8; 32];
    if let Err(e) = getrandom::getrandom(&mut challenge) {
        return error_response(stream, &format!("rng: {e}"), "rng failure");
    }
    if let Err(e) = stream.write_all(&challenge) {
        return format!("challenge write failed: {e}");
    }
    // 2. 读准入请求。
    let body = match read_frame(stream) {
        Ok(b) => b,
        Err(e) => return format!("read request failed: {e}"),
    };
    let req = match parse_admission_request(&body) {
        Ok(r) => r,
        Err(e) => return error_response(stream, &format!("bad request: {e}"), "protocol error"),
    };
    // 3. 验证签名 → principal（D6：不接受自称）。
    let principal = match verify_handshake(&challenge, &req) {
        Ok(p) => p,
        Err(e) => {
            // 握手失败 = 明确拒绝（deny），非传输错误：主体无法被密钥证明。
            let body = serde_json::json!({
                "v": ADMISSION_PROTOCOL_V1,
                "verdict": "deny",
                "deny": "HandshakeFailed",
                "audit_written": false,
                "message": e,
            })
            .to_string();
            let _ = write_frame(stream, body.as_bytes());
            return "handshake failed".to_string();
        }
    };
    // 4. 资源反查（Id → 本地命名；未知 → NOT_FOUND）。
    let store = match N2Store::open(node_dir) {
        Ok(s) => s,
        Err(e) => return error_response(stream, &format!("store: {e}"), "store failure"),
    };
    let now = now_unix_pub();
    let directory = match N2Directory::open_with_store(&store, now) {
        Ok(d) => d,
        Err(e) => return error_response(stream, &format!("directory: {e}"), "store failure"),
    };
    let resource_id = ResourceId(req.resource_id.clone());
    // 必须查 live 广告而非仅 name 映射：`resource revoke` 删广告（withdraw），
    // 名字映射是本地别名，撤销后残留不代表仍在提供。
    if directory
        .registry()
        .lookup_ads(&resource_id, now)
        .is_empty()
    {
        let body = serde_json::json!({"v": ADMISSION_PROTOCOL_V1, "verdict": "error", "code": "NOT_FOUND"}).to_string();
        let _ = write_frame(stream, body.as_bytes());
        return format!("unknown or withdrawn resource {}", req.resource_id);
    }
    let Some(name) = directory.name_of_resource(&resource_id) else {
        let body = serde_json::json!({"v": ADMISSION_PROTOCOL_V1, "verdict": "error", "code": "NOT_FOUND"}).to_string();
        let _ = write_frame(stream, body.as_bytes());
        return format!("unknown resource {}", req.resource_id);
    };
    let rref = match nexus_domain::ResourceName::new(&name) {
        Ok(n) => ResourceRef::new(WorkspaceId::new(DEFAULT_WORKSPACE), n),
        // review-n2-p05 WARN-1：生产路径不得 panic；本地存储损坏走结构化错误，
        // 不崩整个 provider serve 进程。
        Err(e) => {
            return error_response(
                stream,
                &format!("bad stored resource name: {e}"),
                "store failure",
            );
        }
    };
    // 5. 提供方侧 grant 判定（D6：每次建 Session 执行；每次判定写审计）。
    let table: GrantTable = match store.load_grant_table() {
        Ok(t) => t,
        Err(e) => return error_response(stream, &format!("grants: {e}"), "store failure"),
    };
    let mut sink = store.audit_sink();
    let operation = match req.operation.as_str() {
        "Use" => ResourceOperation::Use,
        "Manage" => ResourceOperation::Manage,
        _ => {
            return error_response(
                stream,
                &format!("unknown operation: {}", req.operation),
                "protocol error",
            );
        }
    };
    let decision = table.authorize(
        &AuthRequest {
            workspace: rref.workspace.clone(),
            resource: rref.clone(),
            principal: principal.clone(),
            operation,
        },
        now,
        &mut sink,
    );
    match decision {
        nexus_domain::AuthorizationDecision::Allow => {
            // 6a. 允许：写租约（D1 提供方侧 admission＋租约）。
            let provider_id = format!("prov-{}", local_actor(node_dir));
            if let Err(e) = write_provider_lease(
                &store,
                &req.session_id,
                &provider_id,
                &resource_id,
                &principal.0,
                now,
            ) {
                return error_response(stream, &format!("lease: {e}"), "store failure");
            }
            let endpoint = directory
                .registry()
                .lookup_ads(&resource_id, now)
                .into_iter()
                .find(|ad| ad.provider.0 == provider_id)
                .and_then(|ad| service_locator_of(&ad))
                .unwrap_or_default();
            let body = serde_json::json!({
                "v": ADMISSION_PROTOCOL_V1,
                "verdict": "admit",
                "provider": provider_id,
                "endpoint": endpoint,
            })
            .to_string();
            let _ = write_frame(stream, body.as_bytes());
            format!("admit session={} principal={}", req.session_id, principal.0)
        }
        nexus_domain::AuthorizationDecision::Deny(reason) => {
            // 6b. 拒绝：结构化 Deny＋审计已写（`audit_written=true`）。
            let body = serde_json::json!({
                "v": ADMISSION_PROTOCOL_V1,
                "verdict": "deny",
                "deny": reason.code(),
                "audit_written": true,
            })
            .to_string();
            let _ = write_frame(stream, body.as_bytes());
            format!(
                "deny session={} principal={} reason={}",
                req.session_id,
                principal.0,
                reason.code()
            )
        }
    }
}

/// 发送错误响应并返回日志摘要。
fn error_response(stream: &mut TcpStream, msg: &str, summary: &str) -> String {
    let body = serde_json::json!({"v": ADMISSION_PROTOCOL_V1, "verdict": "error", "message": msg})
        .to_string();
    let _ = write_frame(stream, body.as_bytes());
    summary.to_string()
}

fn parse_admission_request(body: &[u8]) -> Result<AdmissionRequest, String> {
    let v: serde_json::Value = serde_json::from_slice(body).map_err(|e| format!("json: {e}"))?;
    let get = |k: &str| {
        v.get(k)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("missing '{k}'"))
    };
    let version = v
        .get("v")
        .and_then(serde_json::Value::as_u64)
        .ok_or("missing 'v'")?;
    if version != u64::from(ADMISSION_PROTOCOL_V1) {
        return Err(format!("unsupported version: {version}"));
    }
    Ok(AdmissionRequest {
        v: ADMISSION_PROTOCOL_V1,
        pubkey_hex: get("pubkey_hex")?,
        sig_hex: get("sig_hex")?,
        session_id: get("session_id")?,
        resource_id: get("resource_id")?,
        operation: get("operation")?,
    })
}

/// 验证 challenge-response；返回握手派生的 principal（D6 硬约束）。
fn verify_handshake(challenge: &[u8; 32], req: &AdmissionRequest) -> Result<Principal, String> {
    let pubkey = hex_decode(&req.pubkey_hex, 32, "pubkey")?;
    let sig = hex_decode(&req.sig_hex, 64, "sig")?;
    let verifier = UnparsedPublicKey::new(&ring::signature::ED25519, &pubkey);
    verifier
        .verify(challenge, &sig)
        .map_err(|_| "signature verification failed".to_string())?;
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pubkey);
    Ok(Principal::from_ed25519_public_key(&pk))
}

/// 提供方侧租约落盘（`n2/lease/<session-id>`；与 `use_cli` 本地租约同形）。
fn write_provider_lease(
    store: &N2Store,
    session_id: &str,
    provider: &str,
    resource: &ResourceId,
    principal: &str,
    now: u64,
) -> Result<(), String> {
    let data = serde_json::json!({
        "session": session_id,
        "provider": provider,
        "resource": resource.0,
        "principal": principal,
        "granted_at_unix": now,
        "expires_at_unix": now.saturating_add(ADMISSION_LEASE_TTL_SECS),
    })
    .to_string();
    store
        .kv()
        .put(&format!("n2/lease/{session_id}"), data.as_bytes())
        .map_err(|e| format!("put lease: {e}"))?;
    Ok(())
}

/// 在 `bind` 上监听并顺序处理准入连接（`nexus provider serve` 用；`--once`
/// 则只处理一条连接后返回，便于测试）。
pub fn serve_forever(bind: &str, node_dir: &std::path::Path, once: bool) -> Result<(), String> {
    let addr: SocketAddr = bind
        .parse()
        .map_err(|e| format!("bad bind address '{bind}': {e}"))?;
    let listener = TcpListener::bind(addr).map_err(|e| format!("bind {bind}: {e}"))?;
    let bound = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| bind.to_string());
    // 机器可读的绑定地址（stdout；人类日志走 stderr）。
    println!(
        "{}",
        serde_json::json!({"verdict":"PASS","command":"provider serve","provider":{"control": bound}})
    );
    eprintln!(
        "n2-admission: serving on {bound} (node_dir={})",
        node_dir.display()
    );
    loop {
        let (mut stream, _) = listener.accept().map_err(|e| format!("accept: {e}"))?;
        let summary = serve_one_connection(&mut stream, node_dir);
        eprintln!("{summary}");
        if once {
            break;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 请求方侧：准入客户端（A 机 `use` 用）
// ---------------------------------------------------------------------------

/// 请求方准入：拨号 → 读 challenge → 签名 → 发请求 → 读判定。
pub fn admit_session(
    control_addr: &str,
    node_dir: &std::path::Path,
    session_id: &str,
    resource_id: &ResourceId,
) -> Result<AdmissionVerdict, AdmitError> {
    let addr: SocketAddr = control_addr
        .parse()
        .map_err(|e| AdmitError::Connect(format!("bad control address '{control_addr}': {e}")))?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .map_err(|e| AdmitError::Connect(format!("{control_addr}: {e}")))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| AdmitError::Io(e.to_string()))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| AdmitError::Io(e.to_string()))?;
    // 1. 读 challenge。
    let mut challenge = [0u8; 32];
    stream
        .read_exact(&mut challenge)
        .map_err(|e| AdmitError::Protocol(format!("read challenge: {e}")))?;
    // 2. 以本节点 ed25519 身份签名。
    let store = N2Store::open(node_dir).map_err(|e| AdmitError::Io(format!("store: {e}")))?;
    let (pubkey, _) =
        ensure_auth_identity(&store).map_err(|e| AdmitError::Crypto(format!("identity: {e}")))?;
    let keypair = auth_keypair(&store).map_err(AdmitError::Crypto)?;
    let sig = keypair.sign(&challenge);
    let pubkey_hex: String = pubkey.iter().map(|b| format!("{b:02x}")).collect();
    let sig_hex: String = sig.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    // 3. 发准入请求。
    let body = serde_json::json!({
        "v": ADMISSION_PROTOCOL_V1,
        "pubkey_hex": pubkey_hex,
        "sig_hex": sig_hex,
        "session_id": session_id,
        "resource_id": resource_id.0,
        "operation": "Use",
    })
    .to_string();
    write_frame(&mut stream, body.as_bytes()).map_err(AdmitError::Io)?;
    // 4. 读判定。
    let resp = read_frame(&mut stream).map_err(AdmitError::Protocol)?;
    parse_admission_response(&resp).map_err(AdmitError::Protocol)
}

fn parse_admission_response(body: &[u8]) -> Result<AdmissionVerdict, String> {
    let v: serde_json::Value = serde_json::from_slice(body).map_err(|e| format!("json: {e}"))?;
    match v.get("verdict").and_then(serde_json::Value::as_str) {
        Some("admit") => {
            let provider = v
                .get("provider")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string();
            let endpoint = v
                .get("endpoint")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string();
            Ok(AdmissionVerdict::Admitted { provider, endpoint })
        }
        Some("deny") => {
            let deny = v
                .get("deny")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("Unknown")
                .to_string();
            Ok(AdmissionVerdict::Denied { deny })
        }
        Some("error") => {
            let code = v
                .get("code")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            if code == "NOT_FOUND" {
                Ok(AdmissionVerdict::NotFound)
            } else {
                Err(v
                    .get("message")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("provider error")
                    .to_string())
            }
        }
        other => Err(format!("unknown verdict: {other:?}")),
    }
}

/// 本节点提供方标识（与 `resource publish` 一致：`prov-<local_actor>`）。
#[must_use]
pub fn local_provider_id(node_dir: &std::path::Path) -> String {
    format!("prov-{}", local_actor(node_dir))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_auth::{Grant, Principal};
    use nexus_domain::{ProviderId, ResourceName, WorkspaceId};
    use std::sync::mpsc;

    fn temp_node_dir(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("n2-admission-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn publish_svc(dir: &std::path::Path, control: &str) {
        // 在 B 侧发布 Service（`resource publish` 的存储语义；不经 CLI）。
        let store = N2Store::open(dir).unwrap();
        let provider = local_provider_id(dir);
        let ad = ProviderAdvertisement {
            provider: ProviderId(provider),
            resource: ResourceId("res-svc-b".into()),
            capabilities: vec!["service".into()],
            locators: vec![
                "tcp://10.99.99.99:8080".into(),
                format!("{CONTROL_LOCATOR_SCHEME}{control}"),
            ],
            discoverable_by: nexus_registry::Discoverability::Public,
            use_grants: vec![],
            unavailable: None,
            issued_at_secs: 1000,
            ttl_secs: 0,
        };
        store.save_ad(&ad).unwrap();
        store
            .save_names(&[crate::n2_store::NameEntry {
                workspace: WorkspaceId::new(DEFAULT_WORKSPACE),
                name: ResourceName::new("svc-b").unwrap(),
                resource_id: ResourceId("res-svc-b".into()),
                kind: Some(nexus_domain::ResourceKind::Service),
            }])
            .unwrap();
    }

    fn grant_for(dir: &std::path::Path, principal: &Principal) {
        let store = N2Store::open(dir).unwrap();
        store
            .save_grant(&Grant::new(
                ResourceRef::new(
                    WorkspaceId::new(DEFAULT_WORKSPACE),
                    ResourceName::new("svc-b").unwrap(),
                ),
                principal.clone(),
                vec![ResourceOperation::Use],
                None,
            ))
            .unwrap();
    }

    fn serve_once_in_thread(dir: std::path::PathBuf) -> (SocketAddr, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let summary = serve_one_connection(&mut stream, &dir);
            let _ = tx.send(summary);
        });
        (addr, rx)
    }

    #[test]
    fn admit_roundtrip_with_grant() {
        // 有 grant → admit；B 写租约＋审计；principal 来自验证过的公钥。
        let dir_b = temp_node_dir("b");
        let dir_a = temp_node_dir("a");
        let (addr, rx) = serve_once_in_thread(dir_b.clone());
        // B 先发布（control locator 指向实际监听地址）。
        publish_svc(&dir_b, &addr.to_string());
        // A 的身份；B 为其 grant。
        let store_a = N2Store::open(&dir_a).unwrap();
        let (pubkey_a, principal_a) = ensure_auth_identity(&store_a).unwrap();
        grant_for(&dir_b, &principal_a);
        let verdict = admit_session(
            &addr.to_string(),
            &dir_a,
            "sess-test-1",
            &ResourceId("res-svc-b".into()),
        )
        .unwrap();
        match verdict {
            AdmissionVerdict::Admitted { provider, endpoint } => {
                assert!(provider.starts_with("prov-"));
                assert_eq!(endpoint, "tcp://10.99.99.99:8080");
            }
            other => panic!("expected admit, got {other:?}"),
        }
        let summary = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(summary.contains("admit"), "{summary}");
        // B 侧租约落盘（D1）。
        let store_b = N2Store::open(&dir_b).unwrap();
        let lease = store_b
            .kv()
            .get("n2/lease/sess-test-1")
            .unwrap()
            .expect("lease");
        let v: serde_json::Value = serde_json::from_slice(&lease).unwrap();
        assert_eq!(v["principal"], serde_json::json!(principal_a.0));
        // principal 确实由 A 的公钥派生（非自称）。
        assert_eq!(principal_a, Principal::from_ed25519_public_key(&pubkey_a));
        let _ = std::fs::remove_dir_all(&dir_b);
        let _ = std::fs::remove_dir_all(&dir_a);
    }

    #[test]
    fn deny_without_grant_writes_audit() {
        // 无 grant → deny NoSuchGrant；B 侧审计有记录；A 侧无租约。
        let dir_b = temp_node_dir("b2");
        let dir_a = temp_node_dir("a2");
        let (addr, rx) = serve_once_in_thread(dir_b.clone());
        publish_svc(&dir_b, &addr.to_string());
        let verdict = admit_session(
            &addr.to_string(),
            &dir_a,
            "sess-test-2",
            &ResourceId("res-svc-b".into()),
        )
        .unwrap();
        assert_eq!(
            verdict,
            AdmissionVerdict::Denied {
                deny: "NoSuchGrant".to_string()
            }
        );
        let summary = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(summary.contains("deny"), "{summary}");
        let store_b = N2Store::open(&dir_b).unwrap();
        assert!(store_b.kv().get("n2/lease/sess-test-2").unwrap().is_none());
        let entries = crate::n2_store::replay_audit_entries(store_b.kv()).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].1.contains("NoSuchGrant"), "{}", entries[0].1);
        let _ = std::fs::remove_dir_all(&dir_b);
        let _ = std::fs::remove_dir_all(&dir_a);
    }

    #[test]
    fn unknown_resource_is_not_found() {
        let dir_b = temp_node_dir("b3");
        let dir_a = temp_node_dir("a3");
        let (addr, _rx) = serve_once_in_thread(dir_b.clone());
        publish_svc(&dir_b, &addr.to_string());
        let verdict = admit_session(
            &addr.to_string(),
            &dir_a,
            "sess-test-3",
            &ResourceId("res-nope".into()),
        )
        .unwrap();
        assert_eq!(verdict, AdmissionVerdict::NotFound);
        let _ = std::fs::remove_dir_all(&dir_b);
        let _ = std::fs::remove_dir_all(&dir_a);
    }

    #[test]
    fn withdrawn_resource_is_not_found() {
        // revoke（删广告）后提供方必须拒绝建 Session：live 广告为空 → NOT_FOUND，
        // 即使 name 映射残留（revoke 只删广告不删本地别名）。
        let dir_b = temp_node_dir("b5");
        let dir_a = temp_node_dir("a5");
        let (addr, _rx) = serve_once_in_thread(dir_b.clone());
        publish_svc(&dir_b, &addr.to_string());
        // 模拟 `resource revoke`：删广告（名字映射保留）。
        {
            let store = N2Store::open(&dir_b).unwrap();
            let provider = ProviderId(local_provider_id(&dir_b));
            assert!(
                store
                    .delete_ad(&provider, &ResourceId("res-svc-b".into()))
                    .unwrap()
            );
        }
        let verdict = admit_session(
            &addr.to_string(),
            &dir_a,
            "sess-test-5",
            &ResourceId("res-svc-b".into()),
        )
        .unwrap();
        assert_eq!(verdict, AdmissionVerdict::NotFound);
        let _ = std::fs::remove_dir_all(&dir_b);
        let _ = std::fs::remove_dir_all(&dir_a);
    }

    #[test]
    fn tampered_signature_is_rejected() {
        // 冒名：用 B 的密钥签名但声称是别人 → 握手失败（D6 不接受自称）。
        let dir_b = temp_node_dir("b4");
        let dir_a = temp_node_dir("a4");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let dir_b2 = dir_b.clone();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            serve_one_connection(&mut stream, &dir_b2)
        });
        publish_svc(&dir_b, &addr.to_string());
        // 握手冒名：直接发一个 pubkey 与对不上 challenge 的签名。
        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut challenge = [0u8; 32];
        stream.read_exact(&mut challenge).unwrap();
        let body = serde_json::json!({
            "v": 1,
            "pubkey_hex": "aa".repeat(32),
            "sig_hex": "bb".repeat(64),
            "session_id": "sess-evil",
            "resource_id": "res-svc-b",
            "operation": "Use",
        })
        .to_string();
        write_frame(&mut stream, body.as_bytes()).unwrap();
        let resp = read_frame(&mut stream).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&resp).unwrap();
        assert_eq!(v["verdict"], serde_json::json!("deny"));
        assert_eq!(v["deny"], serde_json::json!("HandshakeFailed"));
        let summary = handle.join().unwrap();
        assert!(summary.contains("handshake"), "{summary}");
        let _ = std::fs::remove_dir_all(&dir_b);
        let _ = std::fs::remove_dir_all(&dir_a);
    }

    #[test]
    fn connect_refused_is_connect_error() {
        // 对端无监听 → Connect 错误（调用方映射为 ProviderOffline）。
        let dir_a = temp_node_dir("a5");
        let err = admit_session(
            "127.0.0.1:1",
            &dir_a,
            "sess-x",
            &ResourceId("res-svc-b".into()),
        )
        .unwrap_err();
        assert!(matches!(err, AdmitError::Connect(_)), "{err}");
        let _ = std::fs::remove_dir_all(&dir_a);
    }
}

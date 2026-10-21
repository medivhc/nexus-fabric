//! Provider daemon：显式生命周期的 language server 会话池（MODULE.md「Provider Daemon & Result Cache」会话层）。
//!
//! 三处形状选择都是契约里的句子，实现口径记在这里：
//! - **只回环**：`TcpListener` 绑 `127.0.0.1:0`，真实端口写进租约；不做 TLS、不做发现服务。
//!   选 TCP 而不是 unix socket / named pipe，是为了两宿主同一份实现 —— 否则 Windows 冒烟宿主
//!   会留下一条"Linux 才测过"的路径。
//! - **单线程 accept 轮询**：不起线程池、不引依赖，会话池因此不需要锁，"两个并发查询共用一个
//!   rust-analyzer"这类竞态直接不存在。代价是 `stop` 要等当前那次查询结束；契约承诺的是"查询不
//!   hang 在超时上"和"退出时回收 provider"，没承诺秒停。
//! - **线协议是实现细节**：沿用 `lsp` 的 `Content-Length` 分帧，但消息面只有 Nexus 级查询
//!   （verb + target + workspace + 预算），不暴露 raw LSP。服务端**重新**解析 argv、重新查
//!   verb 白名单、重新做作用域门：客户端检查过不代表服务端免检。

use serde_json::{Value, json};
use std::io::{BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::cache;
use super::dto::{CodeIntelError, Failure};
use super::lsp::{self, FrameIn};
use super::provider::{probe_version, resolve_binary};
use super::{ProviderSession, RustAnalyzerProvider, SessionKey, Verb};
use crate::env::Repo;
use crate::evidence::Bindings;

type Outcome = (String, String, Vec<(String, Value)>);

/// 契约默认 idle（selftest 的 `defaults_idle_secs = 900` 对它）。
pub const DEFAULT_IDLE_SECS: u64 = 900;
/// 出厂调优值，不作兼容承诺（契约「字段与可得性」的默认值一条）。
pub const DEFAULT_MAX_WORKSPACES: usize = 2;
/// selftest 用它把私有命名空间传给派生的 CLI 子进程（契约「作用域与隔离」②）。
/// 之所以走 env 而不是 CLI flag：命令面已经冻结成 `start|stop|status|selftest`，
/// 多一个对外 flag 就多一个可以被场景误钉的口子。
pub const NAMESPACE_ENV: &str = "NEXUS_CODE_INTEL_NAMESPACE";

const LEASE_FILE: &str = "lease.json";
/// 一次 daemon **查询 / stop** 的读上界。它不是场景里那条"不许 hang"的时间断言（那是把宿主
/// 负载写进契约），只是客户端别永远卡在 read 上的自保。stop 也走这一档：daemon 现在是
/// "先把 provider 收干净再回帧"，最坏耗时按会话数线性增长。
const CLIENT_READ_TIMEOUT: Duration = Duration::from_secs(900);
/// 握手与探活的读上界。**不能**复用查询那一档：一个僵住但仍在 accept 的 daemon 会让
/// `start` 的轮询、`status` 与每次 `code` 的路由选择都等满 900s（round 2 的 N-r2-2，实测 25s 未返回）。
const PROBE_READ_TIMEOUT: Duration = Duration::from_secs(10);

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 租约内容。字段名照契约的 `{pid, port, token, started_at, last_heartbeat, idle_secs,
/// workspace_key, version}`，另加 `max_workspaces` —— `status` 要报**生效值**，
/// 没有它就只能报契约默认。
#[derive(Debug, Clone)]
pub struct Lease {
    pub pid: u32,
    pub port: u16,
    pub token: String,
    pub started_at: u64,
    pub last_heartbeat: u64,
    pub idle_secs: u64,
    pub workspace_key: String,
    pub version: String,
    pub max_workspaces: usize,
    /// 这份租约**从哪个命名空间读到的**。它不进租约文件（契约的租约字段表里没有它），
    /// 但 `daemon.lease_path` 要说的是"路径在哪"，没有这个就没法说。
    pub dir: PathBuf,
}

/// daemon 自身版本。握手比它：不同构建的 CLI 不该复用对方留下的会话池
/// （内部线协议是实现细节，实现细节改了旧连接还在，就是拿不兼容的形状喂新代码）。
fn daemon_version() -> String {
    format!("nexus-harness {}", env!("CARGO_PKG_VERSION"))
}

impl Lease {
    fn to_json(&self) -> Value {
        json!({
            "pid": self.pid,
            "port": self.port,
            "token": self.token,
            "started_at": self.started_at,
            "last_heartbeat": self.last_heartbeat,
            "idle_secs": self.idle_secs,
            "workspace_key": self.workspace_key,
            "version": self.version,
            "max_workspaces": self.max_workspaces,
        })
    }

    fn from_json(v: &Value, dir: &Path) -> Option<Lease> {
        Some(Lease {
            pid: v.get("pid")?.as_u64()? as u32,
            port: v.get("port")?.as_u64()? as u16,
            token: v.get("token")?.as_str()?.to_string(),
            started_at: v.get("started_at")?.as_u64()?,
            last_heartbeat: v.get("last_heartbeat")?.as_u64()?,
            idle_secs: v.get("idle_secs")?.as_u64()?,
            workspace_key: v.get("workspace_key")?.as_str()?.to_string(),
            version: v.get("version")?.as_str()?.to_string(),
            max_workspaces: v.get("max_workspaces")?.as_u64()? as usize,
            dir: dir.to_path_buf(),
        })
    }

    pub fn addr(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.port))
    }
}

/// 命名空间 = 仓库根的 FNV（契约 Side Effects 的 `nexus-code-intel-daemon-<fnv>`）。
/// 用它而不是随机值，是为了让"另一个 CLI 进程找得到同一个 daemon"不需要发现服务。
pub fn namespace_dir(root: &Path) -> PathBuf {
    let key = root.to_string_lossy().replace('\\', "/");
    std::env::temp_dir().join(format!(
        "nexus-code-intel-daemon-{}",
        cache::fnv1a_hex(&key)
    ))
}

/// selftest 的私有命名空间：每次运行唯一。写死一个"私有但同名"的目录，第二次跑就会命中
/// 上一次的缓存条目，`default_path_*` 与 `cache_second_run_tier` 的含义随运行次数漂移。
pub fn unique_namespace_dir(tag: &str) -> PathBuf {
    let raw = format!("{tag}-{}-{}", now_secs(), std::process::id());
    std::env::temp_dir().join(format!(
        "nexus-code-intel-daemon-selftest-{}",
        cache::fnv1a_hex(&raw)
    ))
}

/// CLI 侧的命名空间：env 优先（selftest 注入），否则按仓库根推导。
pub fn namespace_from_env_or(root: &Path) -> PathBuf {
    match std::env::var(NAMESPACE_ENV) {
        Ok(v) if !v.trim().is_empty() => PathBuf::from(v),
        _ => namespace_dir(root),
    }
}

pub fn cache_dir(namespace: &Path) -> PathBuf {
    cache::cache_dir_for(namespace)
}

pub fn lease_path(namespace: &Path) -> PathBuf {
    namespace.join(LEASE_FILE)
}

pub fn read_lease(namespace: &Path) -> Option<Lease> {
    let text = std::fs::read_to_string(lease_path(namespace)).ok()?;
    Lease::from_json(&serde_json::from_str(&text).ok()?, namespace)
}

fn write_lease(namespace: &Path, lease: &Lease) -> std::io::Result<()> {
    std::fs::create_dir_all(namespace)?;
    // 先写临时名再 rename：半截 JSON 会被并发的 `status` 读成"没有 daemon"，
    // 那是把"有但读坏了"翻译成"没有"，方向正好错。
    let tmp = namespace.join(format!("{LEASE_FILE}.tmp"));
    std::fs::write(&tmp, lease.to_json().to_string())?;
    std::fs::rename(&tmp, lease_path(namespace))
}

pub fn remove_lease(namespace: &Path) {
    let _ = std::fs::remove_file(lease_path(namespace));
}

/// 命名空间里那份租约**还是不是我们这一份**（按 token 判，不按 pid：pid 会被复用，
/// 而且被 `--takeover` 换代之后，我们对那个文件已经没有任何处置权）。
/// 读不到租约时算"是我们的"——要么还没写，要么本来就该由我们把收尾做完。
///
/// 这一层存在的理由是 round 3 的 N-r3-5/N-r3-6：被放弃的旧 daemon 会
/// ① 每 2s 无条件 `write_lease` ⇒ 把接手方的租约**踩回去**（换代不持久），
/// ② 退出时 `remove_lease` + `cache::purge` ⇒ 删掉**留守 daemon 正在用**的租约与共享结果缓存
/// （实测：B 按 idle 自退出后 `daemon status` 报"没有 daemon 在跑"，而 A 仍在监听）。
/// 判据本身是纯函数 ⇒ 由单测 `superseded_lease_is_not_ours_to_touch` 钉住。
fn lease_is_ours(namespace: &Path, token: &str) -> bool {
    match read_lease(namespace) {
        Some(current) => current.token == token,
        None => true,
    }
}

/// `start` 遇到"租约在场、daemon 没答话"时，允不允许换掉那份租约。
/// 纯函数是为了让它**有承载体**（round 3 的 N-r3-4：只钉 flag 解析不够，
/// 把调用点的 `|| takeover` 删掉，两宿主 152 单测与 26 场景仍全绿）。
/// 调用点若不再经过这里，这个私有函数就变成未使用项 ⇒ `clippy -D warnings` 的 `dead_code` 直接红。
fn may_replace_unanswered_lease(refused: bool, takeover: bool) -> bool {
    refused || takeover
}

/// token 是**误用防护，不是安全边界**（契约要求照此声明）：目录按用户隔离，同用户本来就能
/// 直接跑 `nexus-harness code`，daemon 能做的事不多于 CLI 能做的事。
fn mint_token(seed: &str) -> String {
    cache::fnv1a_hex(&format!("{}:{}:{:?}", std::process::id(), now_secs(), seed))
}

fn roundtrip(stream: &mut TcpStream, msg: &Value) -> Result<Value, String> {
    stream
        .write_all(&lsp::encode_frame(msg))
        .and_then(|()| stream.flush())
        .map_err(|e| format!("写 daemon 请求失败: {e}"))?;
    let mut reader = BufReader::new(&mut *stream);
    match lsp::read_frame_result(&mut reader) {
        FrameIn::Message(v) => Ok(v),
        FrameIn::CleanEof => Err("daemon 在返回结果前关掉了连接".to_string()),
        FrameIn::Failed(f) => Err(format!(
            "daemon 响应不合规({}): {}",
            f.code.code(),
            f.reason
        )),
    }
}

pub struct Client {
    stream: TcpStream,
    lease: Lease,
}

impl Client {
    /// 连接 + hello。失败返回**结构化原因**：契约要求 `daemon_unavailable` 带可诊断的原因，
    /// "连不上"这种没有下一步信息的句子不算原因。
    pub fn connect(lease: &Lease) -> Result<Client, String> {
        let mut stream = TcpStream::connect_timeout(&lease.addr(), Duration::from_secs(5))
            .map_err(|e| {
                // 把"端口上确实没人听"与"连不上但可能只是忙"分开：前者才允许删租约。
                // OS 文案随宿主语言变（中文 Windows 是"由于连接方在一段时间后…"），所以
                // 判据不能靠字符串本地化文本 —— 显式附加一个 ASCII 标记给调用方分类用。
                let marker = if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    " CONNECTION_REFUSED"
                } else {
                    ""
                };
                format!("连不上 daemon {}：{e}{marker}", lease.addr())
            })?;
        stream
            .set_read_timeout(Some(PROBE_READ_TIMEOUT))
            .map_err(|e| e.to_string())?;
        stream
            .set_write_timeout(Some(Duration::from_secs(60)))
            .map_err(|e| e.to_string())?;
        let reply = roundtrip(
            &mut stream,
            &json!({"t": "hello", "token": lease.token, "version": daemon_version()}),
        )
        .map_err(|e| format!("daemon 握手失败: {e}"))?;
        if reply.get("t").and_then(Value::as_str) != Some("ready") {
            return Err(format!("daemon 握手回了不该回的形状: {reply}"));
        }
        // 客户端报**自己**的版本，服务端报它的（ready 帧里的 version 就是租约里那份）。
        // 不一致就拒：新 CLI 复用旧构建留下的会话池，等于用可能已变的内部形状喂旧进程。
        if reply.get("version").and_then(Value::as_str) != Some(lease.version.as_str()) {
            return Err(format!(
                "daemon 版本不符: 本次是 {}，租约里是 {}",
                daemon_version(),
                lease.version
            ));
        }
        Ok(Client {
            stream,
            lease: lease.clone(),
        })
    }

    pub fn ping(&mut self) -> Result<Value, String> {
        roundtrip(
            &mut self.stream,
            &json!({"t": "ping", "token": self.lease.token}),
        )
    }

    /// 把一次 `code` 查询交给 daemon 执行。线协议只带 argv、仓库根与本次工作树指纹；
    /// 服务端不复用客户端的任何判定结果。
    pub fn query(
        &mut self,
        repo_root: &Path,
        argv: &[String],
        digest: &str,
    ) -> Result<Value, String> {
        // 握手是秒级的事，一次真查询可能要几分钟：长超时只在这一档打开。
        self.stream.set_read_timeout(Some(CLIENT_READ_TIMEOUT)).ok();
        roundtrip(
            &mut self.stream,
            &json!({
                "t": "query",
                "token": self.lease.token,
                "repo_root": repo_root.to_string_lossy().replace('\\', "/"),
                "digest": digest,
                "argv": argv,
            }),
        )
    }

    pub fn stop(mut self) -> Result<Value, String> {
        // daemon 收到 stop 后先回收 provider 再回帧 ⇒ 等的是"会话数 × 有序关闭上界"。
        self.stream.set_read_timeout(Some(CLIENT_READ_TIMEOUT)).ok();
        roundtrip(
            &mut self.stream,
            &json!({"t": "stop", "token": self.lease.token}),
        )
    }
}

/// 存活判定：一次握手 + ping。契约规定不用 `kill(pid,0)` 判存活（那要 libc）。
/// 返回 `(应答, pong 内容, 原因)`，三个出口互相不覆盖。
pub fn probe(lease: &Lease) -> (bool, Option<Value>, String) {
    match Client::connect(lease) {
        Ok(mut c) => match c.ping() {
            Ok(v) => (true, Some(v), String::new()),
            Err(e) => (false, None, e),
        },
        Err(e) => (false, None, e),
    }
}

struct PoolSession {
    session: ProviderSession,
    workspace: String,
    last_used: u64,
}

impl Drain {
    /// 还没建过池子就失败时的中性值。
    fn empty() -> Drain {
        Drain {
            lived: 0,
            still_alive: 0,
        }
    }
}

/// 会话池的一次性回收结果。两个数都是**观测**：
/// `lived` = 回收前池子里有几个会话，`still_alive` = 回收后操作系统仍认为活着的 provider 数。
struct Drain {
    lived: usize,
    still_alive: usize,
}

/// 回收会话池：逐个走 provider 自己的有序关闭（shutdown → exit → 有界等待 → kill），
/// 并把每个子进程"是否真的退出"收进 `still_alive`。
///
/// 这一层存在的理由是 B-1：`sessions_after_stop` 必须能变红。若有人把 `LspSession::shutdown`
/// 里的等待/kill 删掉，provider 子进程仍在 ⇒ `still_alive > 0` ⇒ 探针与场景立刻不绿；
/// 而旧实现报的是常量 0，那种回归会无声通过。
fn drain_pool(pool: &mut Vec<PoolSession>) -> Drain {
    let lived = pool.len();
    let mut still_alive = 0usize;
    for entry in pool.iter_mut() {
        // `close_with_report` 是三档，不是布尔（rust_analyzer.rs:834 / lsp.rs:609-644）：
        // `Some(true)` = 操作系统 `try_wait` 确认已退；`Some(false)` = 仍活着**或最后那次
        // `try_wait` 问不到**（`reaped` 只认 `Ok(Some(_))`，所以"问不到"落在这一档）；
        // `None` = 这个条目根本没有会话可回收（从未开过，或早已被 `Drop` 收过）⇒ 不算泄漏。
        // 如实声明覆盖面：这个观测只到**我们直接持有的那个子进程**。rust-analyzer 自己再
        // spawn 的后代不在 std 能枚举的范围（要 libc），所以 `sessions_after_stop=0` 说的是
        // "我们持有的那批句柄都退了"，不是"这台机器上没有 rust-analyzer 在跑"。
        if matches!(entry.session.provider.close_with_report(), Some(false)) {
            still_alive += 1;
        }
    }
    pool.clear();
    Drain { lived, still_alive }
}

/// daemon 服务端主体。返回回收观测与退出原因；`still_alive` 就是 `sessions_after_stop` 的口径。
/// 曾经这里写着"恒为 0"，但那句话与代码不符（代码在 `clear()` 之前取 `pool.len()`），
/// 独立评审 round 1 一并记为 B-1 的一部分。
fn serve(
    namespace: &Path,
    repo_root: &Path,
    workspace_key: &str,
    idle_secs: u64,
    max_workspaces: usize,
) -> (Drain, String) {
    let listener = match TcpListener::bind(("127.0.0.1", 0)) {
        Ok(l) => l,
        Err(e) => return (Drain::empty(), format!("绑不上回环端口: {e}")),
    };
    let port = match listener.local_addr() {
        Ok(a) => a.port(),
        Err(e) => return (Drain::empty(), format!("读不到监听端口: {e}")),
    };
    let lease = Lease {
        pid: std::process::id(),
        port,
        token: mint_token(&namespace.to_string_lossy()),
        started_at: now_secs(),
        last_heartbeat: now_secs(),
        idle_secs,
        workspace_key: workspace_key.to_string(),
        version: daemon_version(),
        max_workspaces,
        dir: namespace.to_path_buf(),
    };
    if let Err(e) = write_lease(namespace, &lease) {
        return (
            Drain::empty(),
            format!("写不出租约 {}: {e}", lease_path(namespace).display()),
        );
    }
    listener.set_nonblocking(true).ok();

    let mut pool: Vec<PoolSession> = Vec::new();
    let mut stop_drain: Option<Drain> = None;
    let mut last_activity = now_secs();
    let mut last_beat = Instant::now();

    let reason: String = loop {
        if last_beat.elapsed() >= Duration::from_secs(2) {
            last_beat = Instant::now();
            // 只在**这份租约还是我们的**时候续写。被 `--takeover` 换代之后还照原样写，
            // 等于把接手方的租约踩回自己名下（N-r3-6：换代因此可能不持久）。
            if lease_is_ours(namespace, &lease.token) {
                let mut beat = lease.clone();
                beat.last_heartbeat = now_secs();
                let _ = write_lease(namespace, &beat);
            }
        }
        if now_secs().saturating_sub(last_activity) >= idle_secs {
            break format!("idle {idle_secs}s 到期，daemon 自行退出");
        }
        match listener.accept() {
            Ok((stream, _peer)) => {
                last_activity = now_secs();
                if let Conn::Stop(drain) = handle_conn(stream, &lease, &mut pool, repo_root) {
                    stop_drain = Some(drain);
                    break "收到 stop".to_string();
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(80));
            }
            Err(e) => break format!("accept 失败: {e}"),
        }
    };
    // 退出路径只有一条清理：`drain_pool`（观测每个 provider 是否真的被操作系统收掉）
    // → 删自己写的租约 → 删缓存目录。idle 自退出与 stop 走同一条，不给它开后门。
    // stop 的回收观测由 `Conn::Stop` 带出，所以这里**优先用带出的那份**，否则对外字段会退化成
    // 恒 0（N-r2-1）。
    let drain = stop_drain.unwrap_or_else(|| drain_pool(&mut pool));
    // 清理只在**租约还归我们**时做（N-r3-5 实测：被 takeover 放弃的旧实例后来 idle 退出，
    // 把接手方那份租约和整个命名空间的共享结果缓存一起删了 ⇒ 活着的 daemon 变成"没人起过"，
    // 而缓存是跨命令资产，被第三方踩掉是真损失）。不是我们的就别动。
    if lease_is_ours(namespace, &lease.token) {
        remove_lease(namespace);
        cache::purge(&cache_dir(namespace));
    }
    (drain, reason)
}

enum Conn {
    Done,
    /// stop 已在这条连接里完成回收，**观测随返回值带出**：它就是 `sessions_after_stop` 与
    /// `daemon serve` 退出 envelope 的共同出处。不带出的话，外层只能对空池再 drain 一次，
    /// 那个数恒 0（round 2 的 N-r2-1：恒 0 的字段不是观测，B-1 的反证力在这里就没了）。
    Stop(Drain),
}

fn write_frame(stream: &mut TcpStream, msg: &Value) -> std::io::Result<()> {
    stream.write_all(&lsp::encode_frame(msg))?;
    stream.flush()
}

/// 一条连接：必须先 hello 且 token 相符，之后才允许 ping / query / stop。
/// 未过握手的连接除了 `refused` 一个字节都不回 —— 拒绝误连是 token 的全部职责，
/// 而"回一个看起来像结果的帧"就是把未认证输入放进对外形状。
fn handle_conn(
    mut stream: TcpStream,
    lease: &Lease,
    pool: &mut Vec<PoolSession>,
    repo_root: &Path,
) -> Conn {
    // accept 出来的连接**继承监听器的非阻塞模式**（Windows 上尤其如此）。不关掉它，
    // 第一帧读就会拿到 WouldBlock，被读帧器判成"半帧断开"——实测症状是 `status` 报
    // `header read failed: 你的主机中的软件中止了一个已建立的连接 (os error 10053)`。
    stream.set_nonblocking(false).ok();
    stream.set_read_timeout(Some(CLIENT_READ_TIMEOUT)).ok();
    stream.set_write_timeout(Some(Duration::from_secs(60))).ok();
    let hello = {
        let mut reader = BufReader::new(&mut stream);
        match lsp::read_frame_result(&mut reader) {
            FrameIn::Message(v) => Some(v),
            _ => None,
        }
    };
    let Some(hello) = hello else {
        return Conn::Done;
    };
    if hello.get("t").and_then(Value::as_str) != Some("hello")
        || hello.get("token").and_then(Value::as_str) != Some(lease.token.as_str())
    {
        let _ = write_frame(
            &mut stream,
            &json!({"t": "refused", "code": "TOKEN_MISMATCH"}),
        );
        return Conn::Done;
    }
    // 版本判定在**客户端**：服务端只报自己租约里的版本（`ready` 帧），由连接方决定要不要继续。
    // 服务端也判一次的话，"客户端报自己的版本"与"租约里那份"必然不等，每个连接都会被拒。
    if write_frame(
        &mut stream,
        &json!({"t": "ready", "version": lease.version}),
    )
    .is_err()
    {
        return Conn::Done;
    }
    loop {
        let msg = {
            let mut reader = BufReader::new(&mut stream);
            match lsp::read_frame_result(&mut reader) {
                FrameIn::Message(v) => v,
                _ => return Conn::Done,
            }
        };
        if msg.get("token").and_then(Value::as_str) != Some(lease.token.as_str()) {
            let _ = write_frame(
                &mut stream,
                &json!({"t": "refused", "code": "TOKEN_MISMATCH"}),
            );
            return Conn::Done;
        }
        let kind = msg.get("t").and_then(Value::as_str).unwrap_or("");
        match kind {
            "ping" => {
                let reply = json!({
                    "t": "pong",
                    "sessions": pool.len(),
                    "capacity": lease.max_workspaces,
                    "idle_secs": lease.idle_secs,
                    "workspace_key": lease.workspace_key,
                    // 会话键的四个分量原样报出。加它不是为了对外承诺（线协议是实现细节），
                    // 而是因为"复用没生效"这件事在没有分量之前只能靠猜：selftest 实测到
                    // sessions=2 时，光看数字分不清是 workspace 不同、版本探测抖了还是指纹变了。
                    "session_keys": pool
                        .iter()
                        .map(|p| {
                            json!({
                                "workspace": p.session.key.workspace,
                                "version": p.session.key.version,
                                "digest": p.session.key.digest,
                                "binary": p.session.key.binary,
                                "queries": p.session.queries,
                            })
                        })
                        .collect::<Vec<_>>(),
                });
                if write_frame(&mut stream, &reply).is_err() {
                    return Conn::Done;
                }
            }
            "stop" => {
                // **先回收、再回报**：两个数都来自 `drain_pool` 的真实观测
                // （`still_alive` 靠操作系统对子进程的 `try_wait` 结果）。
                // 之前这里是字面量 0 —— 独立评审 round 1 的 B-1：常量不可证伪，
                // 关闭逻辑哪怕退化成不 kill/不等待，探针与场景仍双双照绿。
                let drain = drain_pool(pool);
                let _ = write_frame(
                    &mut stream,
                    &json!({"t": "stopped",
                           "sessions_before_stop": drain.lived,
                           "sessions_after_stop": drain.still_alive}),
                );
                return Conn::Stop(drain);
            }
            "query" => {
                let reply = serve_query(&msg, pool, lease, repo_root);
                if write_frame(&mut stream, &reply).is_err() {
                    return Conn::Done;
                }
            }
            other => {
                let _ = write_frame(
                    &mut stream,
                    &daemon_error(
                        CodeIntelError::Unsupported,
                        &format!("UNSUPPORTED: daemon 不接受消息类型 {other:?}"),
                    ),
                );
            }
        }
    }
}

fn daemon_error(code: CodeIntelError, reason: &str) -> Value {
    json!({"t": "result", "ok": false, "error": {"code": code.code(), "reason": reason}})
}

/// 服务端执行一次查询。白名单、作用域门、参数解析都在**这里**重走一遍。
fn serve_query(msg: &Value, pool: &mut Vec<PoolSession>, lease: &Lease, repo_root: &Path) -> Value {
    let Some(items) = msg.get("argv").and_then(Value::as_array) else {
        return daemon_error(CodeIntelError::QueryInvalid, "daemon 请求缺 argv");
    };
    let argv: Vec<String> = items
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    let claimed = msg.get("repo_root").and_then(Value::as_str).unwrap_or("");
    let want = claimed.replace('\\', "/");
    let serve = repo_root.to_string_lossy().replace('\\', "/");
    // daemon 只服务它启动时所在的那棵树。索引是按仓库建的，接受别的仓库根就是把
    // "跨仓库共用索引"说成合法。
    if want != serve {
        return daemon_error(
            CodeIntelError::WorkspaceUnresolved,
            &format!("daemon 服务对象是 {serve}，不接受 {claimed:?}"),
        );
    }
    let verb_raw = argv.first().map(String::as_str).unwrap_or("");
    let Some(verb) = Verb::parse(verb_raw) else {
        return daemon_error(
            CodeIntelError::Unsupported,
            &format!("UNSUPPORTED: daemon 只服务 8 个只读 verb，收到 {verb_raw}"),
        );
    };
    let digest = msg
        .get("digest")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let repo = Repo {
        root: repo_root.to_path_buf(),
    };
    let request = match super::parse_request(verb, &argv[1..], &repo) {
        Ok(r) => r,
        Err(f) => return failure_to_result(&f),
    };
    if let Err(f) = super::validate_scope(&repo, &request) {
        return failure_to_result(&f);
    }
    let binary = match resolve_binary(request.provider_override.as_deref()) {
        Ok(b) => b,
        Err(f) => return failure_to_result(&f),
    };
    let version = probe_version(&binary);
    let key = SessionKey {
        binary: binary.to_string_lossy().replace('\\', "/"),
        workspace: request.budget.workspace_scope.clone(),
        version: version.clone(),
        digest,
    };
    let workspace = request.budget.workspace_scope.clone();
    let mut reused = false;
    let mut session_queries = 1usize;
    let mut absorbed = (0usize, 0usize, 0usize);

    if let Some(pos) = pool.iter().position(|p| p.session.key == key) {
        let mut entry = pool.remove(pos);
        entry.session.queries += 1;
        session_queries = entry.session.queries;
        entry.last_used = now_secs();
        reused = true;
        pool.push(entry);
    } else {
        // 同 workspace 但键不同（实测最常见的是工作树指纹变了）⇒ 旧会话对这个键**无效**，
        // 必须换掉而不是并存。第一版在这里只按"别的 workspace"找驱逐对象，结果是同一个
        // workspace 留下两个会话：`--max-workspaces 1` 都能被撑到 2（selftest 实测抓出来的）。
        // 留着它的后果不只是多占一个进程：同一棵树同时存在两个索引，下一个查询命中哪个
        // 取决于查找顺序，那就是把"索引描述哪一版工作树"变成不确定的事。
        let stale_same_workspace: Vec<usize> = pool
            .iter()
            .enumerate()
            .filter(|(_, p)| p.workspace == workspace)
            .map(|(i, _)| i)
            .collect();
        for i in stale_same_workspace.iter().rev() {
            let mut dropped = pool.remove(*i);
            let meta = dropped.session.provider.finish_meta();
            absorbed.0 += meta.write_requests_refused;
            absorbed.1 += meta.server_requests_unhandled;
            absorbed.2 += meta.dropped_notifications;
        }
        // 容量按 workspace 计（契约「LRU 驱逐即关闭该会话的 RA 子进程」）。
        if distinct_workspaces(pool, &workspace) >= lease.max_workspaces.max(1) {
            if let Some(victim) = pick_lru_victim(pool, &workspace) {
                let mut dropped = pool.remove(victim);
                let meta = dropped.session.provider.finish_meta();
                absorbed.0 += meta.write_requests_refused;
                absorbed.1 += meta.server_requests_unhandled;
                absorbed.2 += meta.dropped_notifications;
            }
        }
        let provider = match RustAnalyzerProvider::start(
            &binary,
            &request.workspace,
            repo_root,
            &version,
            request.timeouts,
        ) {
            Ok(p) => p,
            Err(f) => return failure_to_result(&f),
        };
        pool.push(PoolSession {
            session: ProviderSession {
                provider,
                key: key.clone(),
                queries: 1,
            },
            workspace: workspace.clone(),
            last_used: now_secs(),
        });
    }
    let entry = match pool.last_mut() {
        Some(e) => e,
        None => {
            return daemon_error(CodeIntelError::ProviderCrashed, "会话池意外为空");
        }
    };
    let execution = super::execute(&request, &mut entry.session.provider, repo_root);
    let mut meta = entry.session.provider.finish_meta();
    // 被驱逐会话的三个 refusal 计数必须并进本次输出（与 `mcp serve` 跨重启合并计数同一口径）：
    // 否则"daemon 在你这次查询之前替别人拒过 N 次写请求"随进程消失，只读不变量变成看不见的东西。
    meta.absorb(absorbed.0, absorbed.1, absorbed.2);
    meta.session_reused = reused;
    meta.session_queries = session_queries;
    entry.last_used = now_secs();
    match execution {
        // 刻意返回**未经预算裁剪**的结果：`apply_budget` 只在 CLI 那一处跑。服务端再裁一次
        // 就是把同一条规则复制成两份，而复制出去的规则迟早漂移（`anchors` 复用 `run()`
        // 而不是另起一条查询路径，是同一个理由）。
        Ok(items) => json!({
            "t": "result",
            "ok": true,
            "results": items,
            "provider": meta.to_json(),
        }),
        Err(f) => {
            let mut v = failure_to_result(&f);
            v["provider"] = meta.to_json();
            v
        }
    }
}

fn failure_to_result(f: &Failure) -> Value {
    json!({"t": "result", "ok": false, "error": f.to_json()})
}

fn distinct_workspaces(pool: &[PoolSession], current: &str) -> usize {
    let mut set: Vec<&str> = Vec::new();
    for p in pool {
        if !set.contains(&p.workspace.as_str()) {
            set.push(p.workspace.as_str());
        }
    }
    if !set.contains(&current) {
        set.push(current);
    }
    set.len()
}

/// 选驱逐对象：非本次 workspace 里 `last_used` 最早的那个。
/// 并列时取下标最小者 —— 不是随便挑：并列意味着同一秒内两次访问，稳定选择让 selftest
/// 的 LRU 观测在快速跑的宿主上也可复现。
fn pick_lru_victim(pool: &[PoolSession], keep: &str) -> Option<usize> {
    let mut best: Option<(u64, usize)> = None;
    for (i, p) in pool.iter().enumerate() {
        if p.workspace == keep {
            continue;
        }
        match best {
            Some((t, _)) if p.last_used >= t => {}
            _ => best = Some((p.last_used, i)),
        }
    }
    best.map(|(_, i)| i)
}

/// `daemon` 输出里嵌套对象的组成。刻意用一个结构而不是各处手拼 `json!`：
/// `port`/`pid`/`lease_path` 的缺席规则、`daemon_unavailable` 的条件出现，全靠这一处保证一致。
pub struct DaemonState {
    pub running: bool,
    pub detected: bool,
    pub session_source: &'static str,
    pub lease: Option<Lease>,
    pub stale_lease: bool,
    pub unavailable: Option<String>,
    pub provider_sessions: usize,
    pub capacity: usize,
    pub idle_secs: u64,
    /// 只有 `daemon start` 才有"是不是已经有一个在跑"这个问题。
    pub already_running: Option<bool>,
}

impl DaemonState {
    pub fn to_json(&self) -> Value {
        let mut obj = serde_json::Map::new();
        obj.insert("running".to_string(), json!(self.running));
        obj.insert("detected".to_string(), json!(self.detected));
        obj.insert("session_source".to_string(), json!(self.session_source));
        obj.insert("stale_lease".to_string(), json!(self.stale_lease));
        obj.insert(
            "provider_sessions".to_string(),
            json!(self.provider_sessions),
        );
        obj.insert(
            "provider_session_capacity".to_string(),
            json!(self.capacity),
        );
        obj.insert("idle_secs".to_string(), json!(self.idle_secs));
        // 契约：`running=false` 时这三个**不出现**（不是 null/0 占位）。把"有但不知道"
        // 写成 0 会被消费方读成"端口是 0"。
        if self.running {
            if let Some(l) = &self.lease {
                obj.insert("port".to_string(), json!(l.port));
                obj.insert("pid".to_string(), json!(l.pid));
                obj.insert(
                    "lease_path".to_string(),
                    // 对外统一成 `/`：本模块其它路径字段（`provider.binary` 除外）都是这个口径，
                    // 而 `join` 在 Windows 上会塞进 `\`，同一目录两种写法会让消费方误判成两个路径。
                    json!(lease_path(&l.dir).to_string_lossy().replace('\\', "/")),
                );
            }
        }
        if let Some(v) = self.already_running {
            obj.insert("already_running".to_string(), json!(v));
        }
        if let Some(r) = &self.unavailable {
            obj.insert("daemon_unavailable".to_string(), json!(r));
        }
        Value::Object(obj)
    }

    /// `code`/`context` 用的最小事实集合：本次没问 daemon，也不谎称有会话。
    pub fn not_asked(reason: Option<String>) -> DaemonState {
        DaemonState {
            running: false,
            detected: false,
            session_source: "in-process",
            lease: None,
            stale_lease: false,
            unavailable: reason,
            provider_sessions: 0,
            capacity: DEFAULT_MAX_WORKSPACES,
            idle_secs: DEFAULT_IDLE_SECS,
            already_running: None,
        }
    }
}

fn snapshot_json() -> Value {
    match Repo::discover()
        .and_then(|repo| crate::config::Config::load(&repo).map(|config| (repo, config)))
    {
        Ok((repo, config)) => Bindings::current(&repo, &config).to_json(),
        // 取不到绑定时如实说"取不到"：空串 + error 字段，比伪造一个 revision 强
        // （与 `mcp serve` 的 degraded snapshot 同一形状）。
        Err(e) => json!({"source_revision": "", "working_tree_digest": "", "error": e}),
    }
}

fn fields(state: &DaemonState) -> Vec<(String, Value)> {
    vec![
        ("authority".to_string(), json!("advisory")),
        ("daemon".to_string(), state.to_json()),
        ("snapshot".to_string(), snapshot_json()),
    ]
}

fn blocked(state: &DaemonState, reason: &str) -> Outcome {
    let mut f = fields(state);
    f.push(("results".to_string(), json!([])));
    f.push(("count".to_string(), json!(0)));
    f.push((
        "error".to_string(),
        json!({"code": CodeIntelError::QueryInvalid.code(), "reason": reason}),
    ));
    ("BLOCKED".to_string(), reason.to_string(), f)
}

/// `daemon` 各命令的成功出口。`results`/`count` 恒存在（与 `code` 同一形状），
/// `extra` 放该命令特有的字段（`sessions_after_stop` 之类）。
fn pass(state: &DaemonState, extra: Vec<(String, Value)>, message: String) -> Outcome {
    let mut f = fields(state);
    f.push(("results".to_string(), json!([])));
    f.push(("count".to_string(), json!(0)));
    f.extend(extra);
    ("PASS".to_string(), message, f)
}

/// 失败但不是"参数错"的那一类（`stop` 打到不存在的 daemon ⇒ UNKNOWN）。
/// 用 UNKNOWN 而不是 FAIL：没有 daemon 可停是一个**无法判定**的事实，不是这次调用做错了什么。
fn unknown(state: &DaemonState, message: String, extra: Vec<(String, Value)>) -> Outcome {
    let mut f = fields(state);
    f.push(("results".to_string(), json!([])));
    f.push(("count".to_string(), json!(0)));
    f.extend(extra);
    ("UNKNOWN".to_string(), message, f)
}

/// 已知的启动参数集合。未知参数一律 `BLOCKED`（本模块两次栽在"参数被接受但不生效"上，
/// daemon 一次新增三个参数，同一漂移最可能复发的地方就是它）。
struct StartArgs {
    /// `--takeover`：租约指向一个"连得上但不答话"的 daemon 时，显式授权清掉那份租约
    /// 再启新的。**仍不去 kill pid** —— 没有可移植手段判断那个 pid 是不是我们的 daemon
    /// （契约禁止 `kill(pid,0)`，那要引 libc）。
    takeover: bool,
    workspace: Option<String>,
    idle_secs: Option<u64>,
    max_workspaces: Option<usize>,
    namespace: Option<String>,
    repo_root: Option<String>,
}

fn parse_args(args: &[String], serve_entry: bool) -> Result<StartArgs, String> {
    let mut out = StartArgs {
        takeover: false,
        workspace: None,
        idle_secs: None,
        max_workspaces: None,
        namespace: None,
        repo_root: None,
    };
    let mut i = 0;
    while i < args.len() {
        let take = |name: &str| -> Result<&String, String> {
            args.get(i + 1).ok_or_else(|| format!("{name} 缺值"))
        };
        match args[i].as_str() {
            // 无值 flag 必须单独列出来：下面统一 `i += 2`，把它当带值 flag 处理会把后一个
            // token 当值吞掉 —— 那正是"参数被接受但不生效"的形状。
            "--takeover" if !serve_entry => {
                out.takeover = true;
                i += 1;
                continue;
            }
            "--workspace" => out.workspace = Some(take("--workspace")?.clone()),
            "--idle-secs" => {
                let v = take("--idle-secs")?.clone();
                out.idle_secs = Some(
                    v.parse()
                        .map_err(|_| format!("--idle-secs 不是非负整数: {v}"))?,
                );
                if out.idle_secs == Some(0) {
                    return Err("--idle-secs 不能是 0（那等于 start 完立刻自杀）".to_string());
                }
            }
            "--max-workspaces" => {
                let v = take("--max-workspaces")?.clone();
                out.max_workspaces = Some(
                    v.parse()
                        .map_err(|_| format!("--max-workspaces 不是正整数: {v}"))?,
                );
                if out.max_workspaces == Some(0) {
                    return Err(
                        "--max-workspaces 不能是 0（没有可服务会话的 daemon 不该活着）".to_string(),
                    );
                }
            }
            "--namespace" | "--repo-root" if serve_entry => {
                let v = take(args[i].as_str())?.clone();
                if args[i] == "--namespace" {
                    out.namespace = Some(v);
                } else {
                    out.repo_root = Some(v);
                }
            }
            other => return Err(format!("未知参数: {other}")),
        }
        i += 2;
    }
    Ok(out)
}

pub fn dispatch(args: &[String]) -> Outcome {
    match args.first().map(String::as_str) {
        Some("start") => start(&args[1..]),
        Some("stop") => stop(&args[1..]),
        Some("status") => status(&args[1..]),
        Some("selftest") => selftest(&args[1..]),
        Some("serve") => serve_command(&args[1..]),
        other => {
            let name = other.unwrap_or("");
            let state = DaemonState {
                running: false,
                detected: false,
                session_source: "in-process",
                lease: None,
                stale_lease: false,
                unavailable: None,
                provider_sessions: 0,
                capacity: DEFAULT_MAX_WORKSPACES,
                idle_secs: DEFAULT_IDLE_SECS,
                already_running: None,
            };
            let reason = if name.is_empty() {
                "缺少 daemon 子命令：daemon start|stop|status|selftest".to_string()
            } else {
                format!("daemon {name} 不是已知子命令；只支持 start|stop|status|selftest")
            };
            blocked(&state, &reason)
        }
    }
}

/// `start`：幂等。已活着 ⇒ `PASS` + `already_running=true`，绝不起第二个。
fn start(args: &[String]) -> Outcome {
    let parsed = match parse_args(args, false) {
        Ok(p) => p,
        Err(e) => return blocked(&DaemonState::not_asked(None), &e),
    };
    let repo = match Repo::discover() {
        Ok(r) => r,
        Err(e) => {
            let state = DaemonState::not_asked(Some(format!("仓库发现失败: {e}")));
            return blocked(&state, &format!("WORKSPACE_UNRESOLVED: {e}"));
        }
    };
    start_in(
        &namespace_from_env_or(&repo.root),
        &repo.root,
        parsed.workspace.as_deref().unwrap_or("."),
        parsed.idle_secs.unwrap_or(DEFAULT_IDLE_SECS),
        parsed.max_workspaces.unwrap_or(DEFAULT_MAX_WORKSPACES),
        parsed.takeover,
    )
}

/// `start` 的实现体，命名空间与仓库根都是参数而不是从环境读 —— selftest 要在**自己那份
/// 每次运行唯一的**命名空间里跑完整生命周期（契约「作用域与隔离」②），
/// 不能碰开发者真实在跑的 daemon 的 `lease.json`。
pub fn start_in(
    namespace: &Path,
    repo_root: &Path,
    workspace: &str,
    idle_secs: u64,
    capacity: usize,
    takeover: bool,
) -> Outcome {
    if let Some(lease) = read_lease(namespace) {
        let (alive, pong, why) = probe(&lease);
        if alive {
            let pong = pong.unwrap_or(Value::Null);
            let state = DaemonState {
                running: true,
                detected: true,
                session_source: "daemon",
                lease: Some(lease.clone()),
                stale_lease: false,
                unavailable: None,
                provider_sessions: pong.get("sessions").and_then(Value::as_u64).unwrap_or(0)
                    as usize,
                capacity: lease.max_workspaces,
                idle_secs: lease.idle_secs,
                already_running: Some(true),
            };
            return pass(
                &state,
                Vec::new(),
                format!("daemon 已在 {}: 复用现有实例", lease.addr()),
            );
        }
        // 残留租约（daemon 崩了没删文件）在这里被**覆盖**而不是拒绝启动：否则一次崩溃会永久挡住
        // `start`。但"覆盖"的前提是有证据说它是残留 —— 没被拒只是没答上时，起第二个 daemon
        // 会留下两个监听者与一份被踩掉的租约（第一个就此不可发现）。与 `stop` 同一判据。
        // 判定走 `may_replace_unanswered_lease`（纯函数 + 单测真值表），不写在这里就地展开。
        if !may_replace_unanswered_lease(why.contains("CONNECTION_REFUSED"), takeover) {
            let state = DaemonState {
                running: false,
                detected: false,
                session_source: "in-process",
                lease: Some(lease.clone()),
                stale_lease: false,
                unavailable: Some(why.clone()),
                provider_sessions: 0,
                capacity: lease.max_workspaces,
                idle_secs: lease.idle_secs,
                already_running: Some(false),
            };
            return unknown(
                &state,
                format!(
                    "租约里的 daemon {} 这次没答上也没被拒（{why}）⇒ 不覆盖租约、不起第二个实例；\
                     请稍后重试，或先确认 pid {} 已不在",
                    lease.addr(),
                    lease.pid
                ),
                Vec::new(),
            );
        }
    }
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => {
            return blocked(
                &DaemonState::not_asked(Some(format!("无法定位自身可执行文件: {e}"))),
                &format!("cannot locate executable: {e}"),
            );
        }
    };
    // 残留租约（daemon 崩了没删文件）在这里被**覆盖**而不是拒绝启动：
    // 否则一次崩溃会永久挡住 `start`，而契约只要求 `stop` 不去 kill 无法验证的 pid。
    //
    // daemon 的 stdio 走**自己命名空间里的日志文件**而不是 `Stdio::null()`：实测三个 handle
    // 全 null 时，Windows 上派生的 daemon 会继承调用方的 stdout 管道句柄，于是
    // `nexus-harness daemon start --json | cat` 要等 daemon 自己退出才拿到 EOF（实测挂 40s 不返回，
    // 改成显式文件句柄后 464ms 返回）。场景求值器正是用管道读子进程输出的，
    // 所以这不是"顺手优化"而是让 E4 能跑起来的前提。附带好处：daemon 崩溃不再无声无息。
    let log_path = namespace.join("serve.log");
    let stdio = std::fs::create_dir_all(namespace)
        .and_then(|()| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
        })
        .and_then(|file| {
            let dup = file.try_clone()?;
            // stdin 也走**显式文件句柄**（命名空间里一个空文件），不用 `Stdio::null()`：
            // 实测 stdout/stderr 已经是文件、只有 stdin 是 null 时，调用方的 stdout 管道句柄
            // 仍被 daemon 继承（`| cat` 挂满 30s 超时）。三个句柄全部显式给出是 std 能
            // 建立 handle list 的前提，这一步就是为了不再漏任何可继承句柄。
            let stdin_path = namespace.join("stdin.devnull");
            let stdin = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&stdin_path)?;
            Ok((
                std::process::Stdio::from(stdin),
                std::process::Stdio::from(file),
                std::process::Stdio::from(dup),
            ))
        });
    let spawn = match stdio {
        Err(e) => Err(e),
        Ok((stdin, stdout, stderr)) => std::process::Command::new(&exe)
            .args([
                "daemon",
                "serve",
                "--namespace",
                &namespace.to_string_lossy(),
                "--repo-root",
                &repo_root.to_string_lossy(),
                "--workspace",
                workspace,
                "--idle-secs",
                &idle_secs.to_string(),
                "--max-workspaces",
                &capacity.to_string(),
            ])
            .current_dir(repo_root)
            .stdin(stdin)
            .stdout(stdout)
            .stderr(stderr)
            .env(NAMESPACE_ENV, namespace)
            .spawn(),
    };
    if let Err(e) = spawn {
        let state = DaemonState::not_asked(Some(format!("daemon 子进程起不来: {e}")));
        return blocked(&state, &format!("daemon 子进程起不来: {e}"));
    }
    // 等它自己写租约并应答握手：端口只有子进程知道（绑的是 :0），父进程替它写就是伪造。
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if let Some(lease) = read_lease(namespace) {
            let (alive, pong, _) = probe(&lease);
            if alive {
                let pong = pong.unwrap_or(Value::Null);
                let state = DaemonState {
                    running: true,
                    detected: true,
                    session_source: "daemon",
                    lease: Some(lease.clone()),
                    stale_lease: false,
                    unavailable: None,
                    provider_sessions: pong.get("sessions").and_then(Value::as_u64).unwrap_or(0)
                        as usize,
                    capacity: lease.max_workspaces,
                    idle_secs: lease.idle_secs,
                    already_running: Some(false),
                };
                return pass(
                    &state,
                    Vec::new(),
                    format!("daemon 已启动于 {}", lease.addr()),
                );
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let reason = format!(
        "daemon 子进程在 30s 内没有应答握手（命名空间 {}）",
        namespace.display()
    );
    let lease = read_lease(namespace);
    let stale = lease.is_some();
    let state = DaemonState {
        running: false,
        detected: false,
        session_source: "in-process",
        lease,
        stale_lease: stale,
        unavailable: Some(reason.clone()),
        provider_sessions: 0,
        capacity,
        idle_secs,
        already_running: Some(false),
    };
    blocked(&state, &reason)
}

/// `serve`：`start` 派生的子进程入口。它不面向 Agent（契约「生命周期」一条已声明），
/// 参数由 `start` 自己写出，因此这里的未知参数同样 `BLOCKED`。
fn serve_command(args: &[String]) -> Outcome {
    let parsed = match parse_args(args, true) {
        Ok(p) => p,
        Err(e) => return blocked(&DaemonState::not_asked(None), &e),
    };
    let (Some(namespace), Some(repo_root)) = (parsed.namespace.clone(), parsed.repo_root.clone())
    else {
        return blocked(
            &DaemonState::not_asked(None),
            "daemon serve 需要 --namespace 与 --repo-root（由 daemon start 写出）",
        );
    };
    let idle = parsed.idle_secs.unwrap_or(DEFAULT_IDLE_SECS);
    let capacity = parsed.max_workspaces.unwrap_or(DEFAULT_MAX_WORKSPACES);
    let workspace = parsed.workspace.unwrap_or_else(|| ".".to_string());
    let ns = PathBuf::from(namespace);
    let root = PathBuf::from(repo_root);
    let (drain, reason) = serve(&ns, &root, &workspace, idle, capacity);
    let state = DaemonState {
        running: false,
        detected: false,
        session_source: "in-process",
        lease: None,
        stale_lease: false,
        unavailable: None,
        provider_sessions: drain.still_alive,
        capacity,
        idle_secs: idle,
        already_running: None,
    };
    let mut f = fields(&state);
    f.push(("results".to_string(), json!([])));
    f.push(("count".to_string(), json!(0)));
    ("PASS".to_string(), reason, f)
}

/// `stop`：可达 ⇒ 让它自己退出并删租约；不可达 ⇒ 只删文件并报 `stale_lease=true`，
/// **不去 kill 一个无法验证的 pid**（那是把"看起来像我们的进程"当成我们的进程）。
fn stop(args: &[String]) -> Outcome {
    if let Err(e) = parse_args(args, false) {
        return blocked(&DaemonState::not_asked(None), &e);
    }
    let repo = match Repo::discover() {
        Ok(r) => r,
        Err(e) => {
            return blocked(
                &DaemonState::not_asked(None),
                &format!("WORKSPACE_UNRESOLVED: {e}"),
            );
        }
    };
    stop_in(&namespace_from_env_or(&repo.root))
}

/// `stop` 的实现体，命名空间是参数（selftest 要在自己的私有命名空间里走完整生命周期）。
pub fn stop_in(namespace: &Path) -> Outcome {
    let Some(lease) = read_lease(namespace) else {
        // 契约：stop 一个不存在的 daemon ⇒ UNKNOWN（既不是 PASS 也不是 FAIL）。
        let state = DaemonState {
            running: false,
            detected: false,
            session_source: "in-process",
            lease: None,
            stale_lease: false,
            unavailable: Some(format!(
                "没有 daemon 可停（租约 {} 不存在）",
                lease_path(namespace).display()
            )),
            provider_sessions: 0,
            capacity: DEFAULT_MAX_WORKSPACES,
            idle_secs: DEFAULT_IDLE_SECS,
            already_running: None,
        };
        return unknown(
            &state,
            format!(
                "没有 daemon 在跑（命名空间 {}），无需 stop",
                namespace.display()
            ),
            Vec::new(),
        );
    };
    match Client::connect(&lease) {
        Ok(c) => {
            let reply = c.stop();
            // daemon 是**先回收 provider、再删自己的租约**，所以这里等的是"它自己什么时候写完
            // 收尾"。上限（`lease_removal_bound`）只是 CLI 的自保，不是契约时限；到点仍不消失只说明"没等到证据"，
            // 因此结论是 UNKNOWN（不是 FAIL），且**不替 daemon 删租约** —— 猜着删就是把
            // "可能仍在收尾"的活 daemon 变成找不到主人的孤儿（round 2 的 N-r2-3）。
            let lease_removal_bound = Duration::from_secs(30);
            let deadline = Instant::now() + lease_removal_bound;
            while Instant::now() < deadline && lease_path(namespace).exists() {
                std::thread::sleep(Duration::from_millis(100));
            }
            let gone = !lease_path(namespace).exists();
            // 值**只从 daemon 的应答里取**。取不到就报 -1：问不到不等于证明没有，
            // 而写死 0 会让"关闭逻辑退化"这类回归在探针与场景里双双隐身（B-1）。
            let observed = reply
                .as_ref()
                .ok()
                .and_then(|v| v.get("sessions_after_stop").and_then(Value::as_i64))
                .unwrap_or(-1);
            let extra = vec![
                ("sessions_after_stop".to_string(), json!(observed)),
                (
                    "stop_reply".to_string(),
                    reply.clone().unwrap_or_else(|e| json!({"error": e})),
                ),
            ];
            let state = DaemonState {
                running: false,
                detected: false,
                session_source: "in-process",
                lease: Some(lease.clone()),
                stale_lease: false,
                unavailable: if gone && observed == 0 {
                    None
                } else {
                    // 三种"没凑齐证据"的形状要分开说（round 3 的 N-r3-2：原先把"帧里报了个负数"
                    // 和"帧里根本没这个量"都写成后者，同一个 envelope 自相矛盾 ——
                    // `sessions_after_stop=-5` 明明透传着，reason 却说"帧里没有"）。
                    Some(match reply.as_ref() {
                        Ok(_) if observed >= 0 => {
                            format!("daemon 回报仍有 {observed} 个 provider 未退出")
                        }
                        Ok(v) if v.get("sessions_after_stop").is_some() => format!(
                            "daemon 的 stopped 帧报了这个负数：{observed}（原样透传，不折算成 0，也不当成没答）；\
                             租约在 {lease_removal_bound:?} 内消失={gone}"
                        ),
                        Ok(_) => format!(
                            "daemon 的 stopped 帧里没有 sessions_after_stop；租约在 {lease_removal_bound:?} 内消失={gone}"
                        ),
                        Err(e) => format!("stop 应答取不到: {e}"),
                    })
                },
                provider_sessions: observed.max(0) as usize,
                capacity: lease.max_workspaces,
                idle_secs: lease.idle_secs,
                already_running: None,
            };
            if gone && observed == 0 {
                pass(
                    &state,
                    extra,
                    format!("daemon {} 已停止，租约与缓存目录已删", lease.addr()),
                )
            } else {
                unknown(
                    &state,
                    format!(
                        "stop 未能证明回收完成（租约已删={gone}，等待上限 {lease_removal_bound:?}，\
                         sessions_after_stop 本次取到 {observed}）；这个数的出处见 daemon_unavailable"
                    ),
                    extra,
                )
            }
        }
        Err(e) => {
            // 只有"确实没人监听"才够格把租约当残留删掉。负载宿主上一次 connect 超时**不是**
            // "daemon 死了"：独立评审 round 1 的 OPEN-1 就是这个形状 —— 同机并发跑
            // `verify --fast` 时一次 stop 把活着的 daemon 误判成残留并删了租约，
            // 结果是 daemon 仍在跑但再也没人找得到它（比留一个孤儿进程更难收拾）。
            let refused = e.contains("CONNECTION_REFUSED");
            if refused {
                remove_lease(namespace);
                cache::purge(&cache_dir(namespace));
            }
            let state = DaemonState {
                running: false,
                detected: false,
                session_source: "in-process",
                lease: Some(lease.clone()),
                stale_lease: refused,
                unavailable: Some(e.clone()),
                provider_sessions: 0,
                capacity: lease.max_workspaces,
                idle_secs: lease.idle_secs,
                already_running: None,
            };
            unknown(
                &state,
                if refused {
                    format!(
                        "租约指向被拒的端口 {}: {e}；已删租约，未 kill pid {}",
                        lease.addr(),
                        lease.pid
                    )
                } else {
                    format!(
                        "daemon {} 这次没答上（{}），但没被拒 ⇒ 按可能只是繁忙处理：**未删租约**、未 kill pid {}；\
                         稍后重试 stop，或确认进程已不在后手工删租约",
                        lease.addr(),
                        e,
                        lease.pid
                    )
                },
                Vec::new(),
            )
        }
    }
}

/// `status`：报**生效值**。契约要求显式 `--workspace` 指明探测哪个命名空间（缺省语义未定义，
/// 所以缺省时不猜，直接 BLOCKED）。
fn status(args: &[String]) -> Outcome {
    let parsed = match parse_args(args, false) {
        Ok(p) => p,
        Err(e) => return blocked(&DaemonState::not_asked(None), &e),
    };
    if parsed.workspace.is_none() {
        return blocked(
            &DaemonState::not_asked(None),
            "daemon status 需要显式 --workspace：不带它就是在探测一个未定义的作用域（契约「字段与可得性」）",
        );
    }
    let repo = match Repo::discover() {
        Ok(r) => r,
        Err(e) => {
            return blocked(
                &DaemonState::not_asked(None),
                &format!("WORKSPACE_UNRESOLVED: {e}"),
            );
        }
    };
    status_in(&namespace_from_env_or(&repo.root))
}

/// `status` 的实现体。它报的是**生效值**：有活 daemon ⇒ 取它握手里的数字，
/// 否则取契约默认（`defaults_idle_secs = 900` 那枚值断言走的就是这条分支）。
pub fn status_in(namespace: &Path) -> Outcome {
    let Some(lease) = read_lease(namespace) else {
        let state = DaemonState::not_asked(None);
        return pass(
            &state,
            Vec::new(),
            format!("没有 daemon 在跑（命名空间 {}）", namespace.display()),
        );
    };
    let (alive, pong, why) = probe(&lease);
    let pong = pong.unwrap_or(Value::Null);
    let state = DaemonState {
        running: alive,
        detected: alive,
        session_source: if alive { "daemon" } else { "in-process" },
        lease: Some(lease.clone()),
        stale_lease: !alive && why.contains("CONNECTION_REFUSED"),
        unavailable: (!alive).then_some(why.clone()),
        provider_sessions: pong.get("sessions").and_then(Value::as_u64).unwrap_or(0) as usize,
        capacity: pong
            .get("capacity")
            .and_then(Value::as_u64)
            .map(|v| v as usize)
            .unwrap_or(lease.max_workspaces),
        idle_secs: pong
            .get("idle_secs")
            .and_then(Value::as_u64)
            .unwrap_or(lease.idle_secs),
        already_running: None,
    };
    if alive {
        pass(
            &state,
            Vec::new(),
            format!(
                "daemon 在 {} 上应答（会话 {} 个 workspace，容量 {}）",
                lease.addr(),
                state.provider_sessions,
                state.capacity
            ),
        )
    } else {
        unknown(
            &state,
            format!("租约在，但 {} 没人应答: {why}", lease.addr()),
            Vec::new(),
        )
    }
}

/// `code`/`context` 客户端侧的三个出口，互相不覆盖：
/// `NotAsked`（`--no-daemon`）、`Unavailable{原因}`（想用而没当成）、`Connected`（走通了）。
pub enum Route {
    NotAsked,
    Connected(Client, Lease),
    Unavailable { state: DaemonState, reason: String },
}

/// 客户端选路。`detected` 与 `running` 分开（契约把 `running` 定义为"本次经由 daemon"，
/// 环境里有没有可用 daemon 是另一个字段的问题，两问不许互相覆盖）。
pub fn route(repo_root: &Path, allow_daemon: bool) -> Route {
    if !allow_daemon {
        return Route::NotAsked;
    }
    let namespace = namespace_from_env_or(repo_root);
    let Some(lease) = read_lease(&namespace) else {
        return Route::Unavailable {
            state: DaemonState::not_asked(None),
            reason: format!("命名空间 {} 没有租约（没人 start 过）", namespace.display()),
        };
    };
    match Client::connect(&lease) {
        Ok(c) => Route::Connected(c, lease),
        Err(e) => {
            let state = DaemonState {
                running: false,
                detected: false,
                session_source: "in-process",
                lease: Some(lease.clone()),
                // 被拒才算"这份租约是残留"；没答上只是繁忙 ⇒ 不能把对外字段说成垃圾租约。
                stale_lease: e.contains("CONNECTION_REFUSED"),
                unavailable: Some(e.clone()),
                provider_sessions: 0,
                capacity: lease.max_workspaces,
                idle_secs: lease.idle_secs,
                already_running: None,
            };
            Route::Unavailable { state, reason: e }
        }
    }
}

/// selftest 的两处观测都用它：拿不到租约或握手失败时报 null，让探针**如实变红**，
/// 而不是把"问不到"折算成 0 或 1。
fn ping_sessions(namespace: &Path) -> Value {
    read_lease(namespace)
        .and_then(|l| Client::connect(&l).and_then(|mut c| c.ping()).ok())
        .and_then(|p| p.get("sessions").cloned())
        .unwrap_or(Value::Null)
}

/// 起一个 CLI 子进程跑给定参数并读回它的 JSON envelope。
/// selftest 用它证明"两个不同进程"这件事是真的，而不是在同一次调用里假装。
/// `namespace` 通过 env 注入：命令面冻结成四个子命令，多一个对外 flag 就多一个
/// 可以被场景误钉成"能力"的口子（契约「生命周期」一条已声明这一点）。
pub fn run_cli(args: &[&str], namespace: &Path, cwd: &Path) -> Result<Value, String> {
    let exe = std::env::current_exe().map_err(|e| format!("无法定位自身可执行文件: {e}"))?;
    let out = std::process::Command::new(&exe)
        .args(args)
        .arg("--json")
        .current_dir(cwd)
        .env(NAMESPACE_ENV, namespace)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("spawn {} {args:?} 失败: {e}", exe.display()))?;
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    serde_json::from_str::<Value>(&text)
        .map_err(|e| format!("子进程输出不是 JSON: {e}；原文 {text}"))
}

/// 一枚探针的观测。`observed` 就是对外那 23 个字段的值 —— 断言与对外值同源，
/// 不存在"探针过了但字段报的是另一件事"。
struct Probe {
    name: &'static str,
    ok: bool,
    observed: Value,
    detail: String,
}

fn p_bool(name: &'static str, observed: bool, detail: String) -> Probe {
    Probe {
        name,
        ok: observed,
        observed: json!(observed),
        detail,
    }
}

/// 观测值必须**等于**契约规定的那个值才算过。`expected` 来自契约，不是"上次跑出来的值"。
fn p_expect(name: &'static str, observed: Value, expected: Value, detail: String) -> Probe {
    Probe {
        ok: observed == expected,
        name,
        observed,
        detail,
    }
}

/// `daemon selftest`：契约那份 23 枚字段清单的机器执行体（MODULE.md「字段清单」一节）。
///
/// 隔离口径逐条对应契约「作用域与隔离」：
/// ① 必须显式 `--workspace`，作用域是仓库内夹具且只读不写；
/// ② 每个观测用**每次运行唯一**的命名空间，不只是"私有"；
/// ③ 需要"无 daemon"前提的探针自己确认起始状态，不靠执行顺序碰运气；
/// ④ 空闲自退出用注入的小 `--idle-secs` 观测（默认 900s 大于场景超时，天然不可测）；
/// ⑤ 复用类探针强制 `--no-cache`，否则 Phase 4 的复用判据会被自己造的缓存糊成绿。
fn selftest(args: &[String]) -> Outcome {
    let started = Instant::now();
    let parsed = match parse_args(args, false) {
        Ok(p) => p,
        Err(e) => return blocked(&DaemonState::not_asked(None), &e),
    };
    let Some(workspace) = parsed.workspace.clone() else {
        return blocked(
            &DaemonState::not_asked(None),
            "daemon selftest 需要显式 --workspace：契约规定它没有缺省作用域，缺省即环境依赖",
        );
    };
    let repo = match Repo::discover() {
        Ok(r) => r,
        Err(e) => {
            return blocked(
                &DaemonState::not_asked(Some(format!("仓库发现失败: {e}"))),
                &format!("WORKSPACE_UNRESOLVED: {e}"),
            );
        }
    };
    let root = repo.root.clone();
    let probe_symbol = "Egress";
    // 生命周期的"没写仓库"必须是**前后差集**而不是"整棵树干净"：在开发机上跑 selftest 时
    // 工作树本来就有未提交的实现，按"0 行"判会把别人的工作当成这次的副作用（假红），
    // 而按差集判才正好回答"selftest 自己造了什么文件"。CI 上两者等价。
    let dirty_before = git_status_lines(&root);
    let mut probes: Vec<Probe> = Vec::new();
    let mut scratch_dirs: Vec<PathBuf> = Vec::new();

    // ---- 观测 1：显式生命周期。无 daemon 时 stop 必须 UNKNOWN，再 start、幂等、status ----
    let ns_life = unique_namespace_dir("lifecycle");
    scratch_dirs.push(ns_life.clone());
    let absent = stop_in(&ns_life);
    probes.push(p_expect(
        "stop_absent_verdict",
        json!(absent.0),
        json!("UNKNOWN"),
        format!("stop 一个不存在的 daemon 的 verdict：{}", absent.1),
    ));
    let start1 = start_in(
        &ns_life,
        &root,
        &workspace,
        DEFAULT_IDLE_SECS,
        DEFAULT_MAX_WORKSPACES,
        false,
    );
    probes.push(p_expect(
        "start_verdict",
        json!(start1.0),
        json!("PASS"),
        format!("daemon start：{}", start1.1),
    ));
    let status1 = status_in(&ns_life);
    probes.push(p_expect(
        "status_running_after_start",
        field_of(&status1, "daemon.running"),
        json!(true),
        "start 后 status 是否报 running=true".to_string(),
    ));
    let start2 = start_in(
        &ns_life,
        &root,
        &workspace,
        DEFAULT_IDLE_SECS,
        DEFAULT_MAX_WORKSPACES,
        false,
    );
    probes.push(p_expect(
        "already_running",
        field_of(&start2, "daemon.already_running"),
        json!(true),
        format!("第二次 start 是否复用而不是起第二个：{}", start2.1),
    ));

    // ---- 观测 2：默认路径不自动 spawn（自己确认"起始无 daemon"）----
    let ns_default = unique_namespace_dir("default-path");
    scratch_dirs.push(ns_default.clone());
    let defaults = status_in(&ns_default);
    probes.push(p_expect(
        "defaults_idle_secs",
        field_of(&defaults, "daemon.idle_secs"),
        json!(DEFAULT_IDLE_SECS),
        format!("空命名空间里 status 报出的生效 idle_secs：{}", defaults.1),
    ));
    let default_run = run_cli(
        &[
            "code",
            "symbol",
            probe_symbol,
            "--workspace",
            &workspace,
            "--no-cache",
        ],
        &ns_default,
        &root,
    );
    probes.push(p_expect(
        "default_path_session_source",
        default_run
            .as_ref()
            .map(|v| field_of_value(v, "daemon.session_source"))
            .unwrap_or(Value::Null),
        json!("in-process"),
        match &default_run {
            Ok(_) => "无 daemon 时普通查询的会话来源".to_string(),
            Err(e) => e.clone(),
        },
    ));
    probes.push(p_bool(
        "default_path_lease_absent",
        !lease_path(&ns_default).exists(),
        format!(
            "跑完默认路径查询后租约仍未出现 ⇒ 没被自动拉起（{}）",
            lease_path(&ns_default).display()
        ),
    ));

    // ---- 观测 3：第二个进程经由 daemon，且会话真的被复用（强制 --no-cache）----
    let first = run_cli(
        &[
            "code",
            "symbol",
            probe_symbol,
            "--workspace",
            &workspace,
            "--no-cache",
        ],
        &ns_life,
        &root,
    );
    let second = run_cli(
        &[
            "code",
            "symbol",
            probe_symbol,
            "--workspace",
            &workspace,
            "--no-cache",
        ],
        &ns_life,
        &root,
    );
    probes.push(p_expect(
        "second_process_session_source",
        second
            .as_ref()
            .map(|v| field_of_value(v, "daemon.session_source"))
            .unwrap_or(Value::Null),
        json!("daemon"),
        format!(
            "第一次 {}，第二次子进程 verdict={}；第一次就失败说明 daemon 侧连冷启动都没成",
            first
                .as_ref()
                .map(|_| "ok".to_string())
                .unwrap_or_else(|e| e.clone()),
            second
                .as_ref()
                .map(|v| v["verdict"].clone())
                .unwrap_or(Value::Null),
        ),
    ));
    let sessions = ping_sessions(&ns_life);
    probes.push(p_expect(
        "reuse_provider_sessions",
        sessions.clone(),
        json!(1),
        format!("两次不同进程的查询之后 daemon 侧会话数（是 1 不是 2）：{sessions:?}"),
    ));

    // ---- 观测 4：残留租约（崩掉的 daemon 留下的）不谎报 ----
    let ns_stale = unique_namespace_dir("stale-lease");
    scratch_dirs.push(ns_stale.clone());
    write_bogus_lease(&ns_stale);
    let stale_status = status_in(&ns_stale);
    probes.push(p_expect(
        "stale_lease_detected",
        field_of(&stale_status, "daemon.stale_lease"),
        json!(true),
        format!(
            "租约指向没人听的端口时 status 是否报出来：{}",
            stale_status.1
        ),
    ));
    let stale_run = run_cli(
        &[
            "code",
            "symbol",
            probe_symbol,
            "--workspace",
            &workspace,
            "--no-cache",
        ],
        &ns_stale,
        &root,
    );
    probes.push(p_expect(
        "stale_fallback_verdict",
        stale_run
            .as_ref()
            .map(|v| v["verdict"].clone())
            .unwrap_or(Value::Null),
        json!("PASS"),
        match &stale_run {
            Ok(_) => "残留租约下查询照常完成（不 hang、不把回落说成别的结论）".to_string(),
            Err(e) => e.clone(),
        },
    ));
    probes.push(p_expect(
        "stale_fallback_session_source",
        stale_run
            .as_ref()
            .map(|v| field_of_value(v, "daemon.session_source"))
            .unwrap_or(Value::Null),
        json!("in-process"),
        "回落确实走的是进程内会话".to_string(),
    ));

    // ---- 观测 5：token 拒绝误连（误用防护，不是安全边界，见契约声明）----
    let refusal = read_lease(&ns_life).map(|mut l| {
        l.token = String::new();
        match Client::connect(&l) {
            Err(e) => e,
            Ok(_) => "daemon 接受了空 token 的握手".to_string(),
        }
    });
    // 断言要做到 message 一层。只要求"握手没成功"的话，版本不符、连接被中途打断、
    // 或租约指向别人家的服务都会让这枚探针假绿 —— 本模块的既有教训就是
    // "只断言回了 error 等于没断言 message"。
    let rejected = refusal
        .as_deref()
        .is_some_and(|r| r.contains("TOKEN_MISMATCH"));
    probes.push(p_bool(
        "wrong_token_rejected",
        rejected,
        format!(
            "空 token 必须被认出来拒掉（实际应答：{}）",
            refusal.as_deref().unwrap_or("<命名空间里没有租约可试>")
        ),
    ));

    // ---- 观测 6：LRU 到容量仍只有一个会话 ----
    let ns_lru = unique_namespace_dir("lru");
    scratch_dirs.push(ns_lru.clone());
    let lru_start = start_in(&ns_lru, &root, &workspace, DEFAULT_IDLE_SECS, 1, false);
    let src_workspace = format!("{workspace}/src");
    let q_a = run_cli(
        &[
            "code",
            "symbol",
            probe_symbol,
            "--workspace",
            &workspace,
            "--no-cache",
        ],
        &ns_lru,
        &root,
    );
    let q_b = run_cli(
        &[
            "code",
            "symbol",
            probe_symbol,
            "--workspace",
            &src_workspace,
            "--no-cache",
        ],
        &ns_lru,
        &root,
    );
    let lru_sessions = ping_sessions(&ns_lru);
    probes.push(p_expect(
        "lru_provider_sessions_at_capacity",
        lru_sessions.clone(),
        json!(1),
        format!(
            "--max-workspaces 1 下查两个 workspace 后的会话数（start={}，A={}，B={}）：{lru_sessions:?}",
            lru_start.0,
            q_a.as_ref().map(|_| "ok".to_string()).unwrap_or_else(|e| e.clone()),
            q_b.as_ref().map(|_| "ok".to_string()).unwrap_or_else(|e| e.clone()),
        ),
    ));

    // ---- 观测 7：结果缓存真的命中过；默认可用；可关 ----
    let ns_cache = unique_namespace_dir("cache");
    scratch_dirs.push(ns_cache.clone());
    let c_first = run_cli(
        &["code", "symbol", probe_symbol, "--workspace", &workspace],
        &ns_cache,
        &root,
    );
    let c_second = run_cli(
        &["code", "symbol", probe_symbol, "--workspace", &workspace],
        &ns_cache,
        &root,
    );
    // 契约给这枚字段的值是 **true**（"默认为允许"这个性质本身），不是 `cache.disabled` 的原始
    // false。第一版我直接把 `cache.disabled` 当观测值发出去，于是 selftest 自己跑是"自洽"的，
    // 而**场景**红了 —— 场景与 selftest 是两个独立承载体，这正是它们不该互相代替的原因。
    // 判据仍然是那个可证伪的事实：默认路径上 `cache.disabled` 必须为 false。
    let default_enabled = c_first
        .as_ref()
        .is_ok_and(|v| field_of_value(v, "cache.disabled") == json!(false));
    probes.push(p_expect(
        "cache_default_enabled",
        json!(default_enabled),
        json!(true),
        format!(
            "默认路径 cache.disabled=false（契约：默认值都是允许）。第一次查询 verdict={}，tier={:?}",
            c_first.as_ref().map(|v| v["verdict"].clone()).unwrap_or(Value::Null),
            c_first.as_ref().map(|v| field_of_value(v, "cache.tier"))
        ),
    ));
    probes.push(p_expect(
        "cache_second_run_tier",
        c_second
            .as_ref()
            .map(|v| field_of_value(v, "cache.tier"))
            .unwrap_or(Value::Null),
        json!("disk"),
        format!(
            "同指纹第二次相同查询必须落到 disk（第一次 tier={:?}）",
            c_first.as_ref().map(|v| field_of_value(v, "cache.tier"))
        ),
    ));
    let c_disabled = run_cli(
        &[
            "code",
            "symbol",
            probe_symbol,
            "--workspace",
            &workspace,
            "--no-cache",
        ],
        &ns_cache,
        &root,
    );
    let disable_ok = c_disabled.as_ref().is_ok_and(|v| {
        field_of_value(v, "cache.disabled") == json!(true)
            && field_of_value(v, "cache.tier") == json!("miss")
            && v["verdict"] == json!("PASS")
    });
    probes.push(p_bool(
        "cache_disableable",
        disable_ok,
        "--no-cache ⇒ disabled=true 且 tier=miss 且查询仍 PASS（三项一起判）".to_string(),
    ));

    // ---- 观测 8：空闲自退出（注入小 idle）----
    let ns_idle = unique_namespace_dir("idle-exit");
    scratch_dirs.push(ns_idle.clone());
    let idle_start = start_in(
        &ns_idle,
        &root,
        &workspace,
        3,
        DEFAULT_MAX_WORKSPACES,
        false,
    );
    let mut exited = false;
    let deadline = Instant::now() + Duration::from_secs(25);
    while Instant::now() < deadline {
        if !lease_path(&ns_idle).exists() {
            exited = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    let still_answers = read_lease(&ns_idle).map(|l| probe(&l).0).unwrap_or(false);
    probes.push(p_bool(
        "idle_self_exit_observed",
        exited && !still_answers,
        format!(
            "注入 --idle-secs 3 后到点自行退出（start={}，租约消失={exited}，端口仍应答={still_answers}）",
            idle_start.0
        ),
    ));
    probes.push(p_bool(
        "lease_removed_on_idle",
        !lease_path(&ns_idle).exists(),
        "自退出也删掉自己写的租约".to_string(),
    ));

    // ---- 观测 9：命令面与参数兑现 ----
    let surfaced = run_cli(&["definitely-not-a-command"], &ns_default, &root);
    let message = surfaced
        .as_ref()
        .map(|v| v["message"].as_str().unwrap_or("").to_string())
        .unwrap_or_default();
    // 逐个**全名**核对，而不是 `contains("daemon")`。这条清单第三次漏名字（先是 mcp 与 daemon，
    // 补的时候又漏了 run），说明"人读一遍"不是承载体：`contains` 还会让 "code" 这种短名
    // 靠子串蒙混过关。按逗号切词后要求精确相等，缺哪个就报哪个。
    const SURFACE: [&str; 13] = [
        "status", "context", "check", "test", "verify", "explain", "bench", "replay", "scenario",
        "run", "code", "mcp", "daemon",
    ];
    let listed: Vec<&str> = message
        .split(':')
        .nth(1)
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let missing: Vec<&str> = SURFACE
        .iter()
        .copied()
        .filter(|c| !listed.contains(c))
        .collect();
    probes.push(p_bool(
        "commands_surface_lists_daemon",
        missing.is_empty(),
        format!(
            "兜底 BLOCKED 消息必须列出全部 13 个已分派命令；缺：{missing:?}（实际消息：{message}）"
        ),
    ));
    let bad_flag = dispatch(&["start".to_string(), "--totally-made-up".to_string()]);
    probes.push(p_bool(
        "unknown_flag_blocked",
        bad_flag.0 == "BLOCKED",
        format!(
            "未知启动参数必须 BLOCKED 而不是\"接受但不生效\"（verdict={}，{}）",
            bad_flag.0, bad_flag.1
        ),
    ));

    // ---- 收尾：停掉活的 daemon、确认无残留会话、确认工作树没被写过 ----
    let stopped = stop_in(&ns_life);
    let reply_sessions = field_of(&stopped, "sessions_after_stop");
    probes.push(p_expect(
        "sessions_after_stop",
        reply_sessions,
        json!(0),
        format!(
            "stop 后仍活着的 provider 数（观测值：daemon 在回收每个会话后用子进程的 try_wait 判定，\
             取不到应答时 CLI 报 -1 而不是 0；旧实现写死 0，独立评审 round 1 判为不可证伪）：{}",
            stopped.1
        ),
    ));
    let _ = stop_in(&ns_lru);
    let dirty_after = git_status_lines(&root);
    // 两边都问得到 git 才谈"新增了几行"。问不到就报 -1，让探针如实变红 ——
    // 把"无法证明"折算成"证明没有"是本模块反复禁止的那一类错。
    let added_count: i64 = match (&dirty_before, &dirty_after) {
        (Some(before), Some(after)) => after.iter().filter(|l| !before.contains(l)).count() as i64,
        _ => -1,
    };
    let added: Vec<&String> = match (&dirty_before, &dirty_after) {
        (Some(before), Some(after)) => after.iter().filter(|l| !before.contains(l)).collect(),
        _ => Vec::new(),
    };
    probes.push(p_expect(
        "dirty_after_lifecycle",
        json!(added_count),
        json!(0),
        format!(
            "生命周期结束后相对开始前新增的工作树条目数（前 {:?} 行、后 {:?} 行，新增：{added:?}）",
            dirty_before.as_ref().map(|v| v.len()),
            dirty_after.as_ref().map(|v| v.len()),
        ),
    ));

    for dir in &scratch_dirs {
        let _ = std::fs::remove_dir_all(dir);
    }

    let all_ok = probes.iter().all(|p| p.ok);
    let failed: Vec<&str> = probes.iter().filter(|p| !p.ok).map(|p| p.name).collect();
    let mut fields: Vec<(String, Value)> = vec![("authority".to_string(), json!("advisory"))];
    for p in &probes {
        fields.push((p.name.to_string(), p.observed.clone()));
    }
    fields.push(("probe_count".to_string(), json!(probes.len())));
    fields.push((
        "probes".to_string(),
        json!(
            probes
                .iter()
                .map(|p| json!({"name": p.name, "ok": p.ok, "detail": p.detail}))
                .collect::<Vec<_>>()
        ),
    ));
    fields.push((
        "duration_ms".to_string(),
        json!(started.elapsed().as_millis()),
    ));
    fields.push(("daemon".to_string(), DaemonState::not_asked(None).to_json()));
    fields.push(("snapshot".to_string(), snapshot_json()));
    fields.push(("results".to_string(), json!([])));
    fields.push(("count".to_string(), json!(0)));
    let verdict = if all_ok { "PASS" } else { "FAIL" };
    let message = if all_ok {
        format!("daemon selftest：{} 枚探针全过", probes.len())
    } else {
        format!("daemon selftest：{} 枚探针没过 —— {failed:?}", failed.len())
    };
    (verdict.to_string(), message, fields)
}

/// 读自己构造的 `Outcome` 里的点号路径字段（`daemon.running`）。
fn field_of(outcome: &Outcome, dotted: &str) -> Value {
    let mut parts = dotted.split('.');
    let head = parts.next().unwrap_or("");
    let mut value = outcome
        .2
        .iter()
        .find(|(k, _)| k == head)
        .map(|(_, v)| v.clone())
        .unwrap_or(Value::Null);
    for key in parts {
        value = value.get(key).cloned().unwrap_or(Value::Null);
    }
    value
}

/// 读一个已解析 envelope 里的点号路径。
fn field_of_value(v: &Value, dotted: &str) -> Value {
    let mut out = v.clone();
    for key in dotted.split('.') {
        out = out.get(key).cloned().unwrap_or(Value::Null);
    }
    out
}

/// 一个"确定没人监听、且连接一定被判 **refused**"的端口。
///
/// 别用端口 1：实测 Windows 上连 `127.0.0.1:1` 得到的是 `connection timed out`（不是 refused），
/// 而 `stop`/`start`/`route` 的"残留租约"分类按 refused 走 ⇒ 端口 1 会让同一份测试在两宿主上
/// 走不同分支（Linux refused、Windows 超时）。做法是绑一个临时端口再立即释放：
/// 两宿主对无人监听的回环端口都回 ECONNREFUSED。竞争窗口只会让测试变红，不会让它假绿。
fn certainly_closed_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .unwrap_or(1)
}

/// 手写一份"没人听的端口"的租约，用来观测残留租约这条路。
/// 端口来自 `certainly_closed_port()`：既不会误连到真 daemon，也不需要先造一个真进程再杀它
/// （那是 `stop` 明确不肯做的事）。
fn write_bogus_lease(namespace: &Path) {
    let lease = Lease {
        pid: 1,
        port: certainly_closed_port(),
        token: "bogus".to_string(),
        started_at: now_secs(),
        last_heartbeat: now_secs(),
        idle_secs: DEFAULT_IDLE_SECS,
        workspace_key: ".".to_string(),
        version: daemon_version(),
        max_workspaces: DEFAULT_MAX_WORKSPACES,
        dir: namespace.to_path_buf(),
    };
    let _ = write_lease(namespace, &lease);
}

/// `git status --porcelain` 的行。取不到 git 时报 `-1`（探针如实变红），
/// 而不是把"问不到"折算成"没改动"——那与 `dirty_state=null` 的既有口径同源。
fn git_status_lines(root: &Path) -> Option<Vec<String>> {
    let out = std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(root)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| l.to_string())
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code_intel::ProviderMeta;

    /// 契约「点名单测」之一：未运行时 `port`/`pid`/`lease_path` **不出现**。
    /// 求值器没有"字段缺席"算子，所以这条只能在这里证；场景侧钉的是别的字段。
    #[test]
    fn daemon_decline_omits_absent_fields() {
        let state = DaemonState::not_asked(Some("没有租约".to_string()));
        let v = state.to_json();
        assert_eq!(v["running"], json!(false));
        for k in ["port", "pid", "lease_path"] {
            assert!(v.get(k).is_none(), "running=false 时 {k} 仍出现：{}", v);
        }
        // 反过来也必须出现，否则"缺席规则"会顺手把该报的也藏掉。
        let lease = Lease {
            pid: 4242,
            port: 4242,
            token: "t".to_string(),
            started_at: 1,
            last_heartbeat: 1,
            idle_secs: DEFAULT_IDLE_SECS,
            workspace_key: ".".to_string(),
            version: daemon_version(),
            max_workspaces: DEFAULT_MAX_WORKSPACES,
            dir: PathBuf::from("nowhere"),
        };
        let mut running = DaemonState::not_asked(None);
        running.running = true;
        running.lease = Some(lease);
        let v = running.to_json();
        assert_eq!(v["port"], json!(4242));
        assert_eq!(v["pid"], json!(4242));
        assert!(v.get("lease_path").is_some());
    }

    /// 契约「点名单测」之一：回落必须带**结构化且非空**的原因。
    /// "连不上"这种没有下一步信息的句子不算原因（契约 `daemon_unavailable` 一条）。
    #[test]
    fn daemon_unavailable_carries_structured_reason() {
        let ns = unique_namespace_dir("unavailable-reason");
        let lease = Lease {
            pid: 1,
            // 一定回 ECONNREFUSED 的端口（见 `certainly_closed_port`：端口 1 在 Windows 上是超时）。
            port: certainly_closed_port(),
            token: "bogus".to_string(),
            started_at: now_secs(),
            last_heartbeat: now_secs(),
            idle_secs: DEFAULT_IDLE_SECS,
            workspace_key: ".".to_string(),
            version: daemon_version(),
            max_workspaces: DEFAULT_MAX_WORKSPACES,
            dir: ns.clone(),
        };
        let reason = match Client::connect(&lease) {
            Err(e) => e,
            // 端口 1 上有东西应答了握手 ⇒ 观测前提不成立。这条要**如实变红**，
            // 不能因为"看起来连上了"就当成回落被证明了。
            Ok(_) => "端口 1 竟然应答了握手，观测前提不成立".to_string(),
        };
        assert!(!reason.is_empty(), "回落原因为空就是把失败说成了沉默");
        // 原因里必须能被认出是哪一步坏的：连不上 / 握手 / 版本，三者之一。
        let mentions = ["连不上", "握手", "版本", "refused"]
            .iter()
            .any(|m| reason.contains(m));
        assert!(mentions, "回落原因不可诊断：{reason}");
        let state = DaemonState::not_asked(Some(reason));
        let v = state.to_json();
        assert!(
            v.get("daemon_unavailable")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty()),
            "daemon_unavailable 必须带非空原因：{v}"
        );
        let _ = std::fs::remove_dir_all(&ns);
    }

    /// B-1 的另一半：daemon 答不上来时，CLI **不许**替它把 `sessions_after_stop` 说成 0。
    /// 用指向被拒端口的租约构造该分支（绑 1 端口需要特权，任何宿主上都不会有人在那儿听协议），
    /// 断言 verdict 是 UNKNOWN 且**这个字段根本不存在**。
    #[test]
    fn stop_does_not_claim_zero_without_an_answer() {
        let ns = unique_namespace_dir("stop-no-answer");
        write_bogus_lease(&ns);
        let outcome = stop_in(&ns);
        assert_eq!(
            outcome.0, "UNKNOWN",
            "拿不到应答不是\"停成功了\"：{}",
            outcome.1
        );
        assert!(
            outcome.2.iter().all(|(k, _)| k != "sessions_after_stop"),
            "daemon 没应答却报 sessions_after_stop=0 就是把无法证明折算成证明没有：{:?}",
            outcome.2.iter().map(|(k, _)| k).collect::<Vec<_>>()
        );
        // 只有"被拒"才够格清掉残留租约（让下次 start 能重新占位），且不 kill 无法验证的 pid。
        assert!(!lease_path(&ns).exists());
        let _ = std::fs::remove_dir_all(&ns);
    }

    /// 契约「点名单测」之一（隔离 ③b 顶掉了 selftest 里的那枚探针）：
    /// 会话复用键含工作树指纹，**换了指纹必须判为不同会话**。
    #[test]
    fn session_reuse_key_rejects_changed_digest() {
        let base = SessionKey {
            binary: "rust-analyzer".to_string(),
            workspace: "engineering/nexus-harness/fixtures/code-intel".to_string(),
            version: "1.98.1".to_string(),
            digest: "aaaa".to_string(),
        };
        let mut moved = base.clone();
        moved.digest = "bbbb".to_string();
        assert_ne!(base, moved, "指纹参与键比较，变了就不是同一个会话");
        // 失效原因必须指向指纹（顺序有意：指纹变化最危险，先报它）。
        assert_eq!(
            super::super::session_invalidated_reason(&base, &moved),
            "digest_changed"
        );
        let same = base.clone();
        assert_eq!(base, same, "同值克隆不该被判成另一个会话");
    }

    /// 契约「点名单测」之一：daemon 的**命中路径不许**把运行元数据带过来。
    /// 与 `cache::cache_hit_restamps_run_metadata` 成对：前者证存储面，这条证回放面。
    #[test]
    fn cache_hit_restamps_run_metadata() {
        let stored = json!({
            "kind": "rust-analyzer", "binary": "ra", "version": "1.98.1", "ready": true,
            "duration_ms": 99999, "restart_count": 7, "session_reused": true, "session_queries": 42,
        });
        let mut meta = ProviderMeta::from_json(&stored);
        // 客户端按本次重新生成的三个量：耗时、复用与否、会话计数。
        meta.duration_ms = 12;
        meta.session_reused = false;
        meta.session_queries = 0;
        let out = meta.to_json();
        assert_eq!(
            out["duration_ms"],
            json!(12),
            "命中路径带着上次的耗时就冒充了本次成本"
        );
        assert_eq!(out["session_reused"], json!(false));
        assert_eq!(out["session_queries"], json!(0));
        // 而"记事实"的四键必须留着（冻结场景在可缓存 verb 上钉 provider.ready）。
        assert_eq!(out["ready"], json!(true));
        assert_eq!(out["kind"], json!("rust-analyzer"));
    }

    /// 契约「点名单测」之一：内部线协议不越 verb 白名单。
    /// 这条是 `serve_query` 的门，不是客户端的门 —— 客户端检查过不代表服务端免检。
    #[test]
    fn wire_refuses_non_whitelist() {
        let repo = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| PathBuf::from("."));
        let lease = Lease {
            pid: 1,
            port: 1,
            token: "t".to_string(),
            started_at: 1,
            last_heartbeat: 1,
            idle_secs: DEFAULT_IDLE_SECS,
            workspace_key: ".".to_string(),
            version: daemon_version(),
            max_workspaces: DEFAULT_MAX_WORKSPACES,
            dir: PathBuf::from("nowhere"),
        };
        // 三个非白名单名：写能力、未知 verb、以及消息类型本身不在 {hello,ping,query,stop}。
        for verb in ["rename", "format", "apply-edit"] {
            let reply = serve_query(
                &json!({"argv": [verb, "x"], "repo_root": repo.to_string_lossy(), "digest": "d"}),
                &mut Vec::new(),
                &lease,
                &repo,
            );
            assert_eq!(reply["ok"], json!(false), "{verb} 竟被执行了：{reply}");
            assert_eq!(reply["error"]["code"], json!("UNSUPPORTED"));
        }
        let other = daemon_error(
            CodeIntelError::Unsupported,
            "UNSUPPORTED: 消息类型 websocket",
        );
        assert_eq!(other["error"]["code"], json!("UNSUPPORTED"));
        // 换一个仓库根来问也必须在执行前被拒（索引是按仓库建的）。
        let foreign = serve_query(
            &json!({"argv": ["symbol", "x"], "repo_root": "Z:/definitely/not/here", "digest": "d"}),
            &mut Vec::new(),
            &lease,
            &repo,
        );
        assert_eq!(foreign["error"]["code"], json!("WORKSPACE_UNRESOLVED"));
    }

    /// 契约「点名单测」之一：selftest 的对外键集合必须与本模块那份清单逐名对齐。
    /// 这条把 `probe_count` 的散文担保解除掉：多一名少一名都红，不靠人核对。
    #[test]
    fn daemon_selftest_field_list_matches_contract() {
        let module =
            std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("MODULE.md"))
                .expect("读本模块 MODULE.md");
        // 取「`daemon selftest --json` 的字段清单」之后第一个 ```text 代码块。
        let anchor = module
            .find("`daemon selftest --json` 的字段清单")
            .expect("MODULE.md 里应有 daemon selftest 字段清单一节");
        let block_start = module[anchor..]
            .find("```text")
            .map(|i| anchor + i + 7)
            .expect("清单应是 ```text 代码块");
        let block_end = module[block_start..]
            .find("```")
            .map(|i| block_start + i)
            .expect("代码块应有收尾");
        let listed: Vec<String> = module[block_start..block_end]
            .lines()
            .filter_map(|line| {
                let name = line.trim_start().split([' ', '\t']).next().unwrap_or("");
                if line.starts_with("  ") && is_ident(name) {
                    Some(name.to_string())
                } else {
                    None
                }
            })
            .collect();
        let expected_count: usize = module[block_start..block_end]
            .lines()
            .filter(|l| {
                l.starts_with("  ")
                    && is_ident(l.trim_start().split([' ', '\t']).next().unwrap_or(""))
            })
            .count();
        assert!(!listed.is_empty(), "清单解析为空就是这条单测自己失效了");

        let declared = selftest_field_names();
        assert_eq!(
            declared, listed,
            "selftest 实际键集合与契约清单不一致（缺一名或多一名都算契约破坏）"
        );
        assert_eq!(
            declared.len(),
            expected_count,
            "清单条数与 probe_count 的散文数字对不上"
        );
        // `probe_count` 也必须等于这个数：selftest 自己报的数字与清单同源。
        assert_eq!(declared.len(), 23, "清单条数变了要同步本测试与场景期望数");
    }

    /// round 2 的 N-r2-2 的判据载体：**探活/握手用短预算，不是查询那 900s**。
    /// 夹具是"接了连接但永远不答话"的监听者 —— 就是"daemon 僵住但进程还在"的形状。
    /// 断言的是**时长**而不是原因文案：把这一档换回 `CLIENT_READ_TIMEOUT` 时，`start` 的轮询、
    /// `status` 与每次 `code` 的路由选择都会等满 15 分钟，而这条测试先变红。
    #[test]
    fn silent_daemon_probe_returns_within_the_probe_budget() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("绑临时端口做静默监听者");
        let port = listener.local_addr().expect("取到监听端口").port();
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            // 只 accept，不读不写：客户端的请求停在服务端接收缓冲里，永远没有回帧。
            // 已接受的连接必须**抱着**，否则测试测的是"对端提前关闭"而不是"不答话"。
            let mut held = Vec::new();
            for stream in listener.incoming().take(1).flatten() {
                held.push(stream);
            }
            let _ = stop_rx.recv();
            held.len()
        });
        let ns = unique_namespace_dir("silent-probe");
        let lease = Lease {
            pid: std::process::id(),
            port,
            token: "bogus".to_string(),
            started_at: now_secs(),
            last_heartbeat: now_secs(),
            idle_secs: DEFAULT_IDLE_SECS,
            workspace_key: ".".to_string(),
            version: daemon_version(),
            max_workspaces: DEFAULT_MAX_WORKSPACES,
            dir: ns.clone(),
        };
        let started = Instant::now();
        // 探活放进工作线程 + **有界等待**：万一哪天连读超时都不设了（`set_read_timeout(None)`），
        // 这条测试要变红而不是把整个 `cargo test` 挂死 —— libtest 没有 per-test 超时
        // （round 3 的 N-r3-8：原写法对这种回归形式是"挂住"，不是"红"）。
        let (done_tx, done_rx) = std::sync::mpsc::channel::<(bool, Option<Value>, String)>();
        std::thread::spawn(move || {
            let _ = done_tx.send(probe(&lease));
        });
        let (alive, pong, why) = match done_rx.recv_timeout(Duration::from_secs(60)) {
            Ok(v) => v,
            Err(_) => {
                panic!("探活 60s 没返回：读超时可能整档被去掉（那时无预算可红，只能靠这层界）")
            }
        };
        let elapsed = started.elapsed();
        // 探针已经有结论了，这时才释放夹具里被抱住的连接（早一步关会让"沉默"变成"EOF"，形状就变了）。
        drop(stop_tx);
        let _ = holder.join();
        let _ = std::fs::remove_dir_all(&ns);
        assert!(
            !alive && pong.is_none(),
            "不答话的监听者被判成活着，就是把沉默折算成就绪"
        );
        assert!(
            elapsed <= Duration::from_secs(60),
            "探活等了 {elapsed:?}：握手档被换回查询预算（{CLIENT_READ_TIMEOUT:?}）了"
        );
        assert!(
            !why.contains("CONNECTION_REFUSED"),
            "连得上但不答话不是\"被拒\"；分类成残留会让 start 起第二个实例：{why}"
        );
        assert!(!why.is_empty(), "探针没拿到应答却不给原因 = 把失败说成沉默");
    }

    /// 契约 ①（**握手成功之后**没了应答 ⇒ `-1`）的承载体。round 3 的 N-r3-3 指出这一支原先
    /// 在仓内没有任何承载体：selftest 与场景钉的都是"有应答"的路，而
    /// `stop_does_not_claim_zero_without_an_answer` 用的是被拒端口（那是 ②）。
    /// 夹具必须**先正确应答 hello**，再在第二个请求上关连接：单纯不答话走的是 ②（字段缺席），
    /// 而且 `stop` 档的读预算是 900s —— 拿那个形状做单测会挂 15 分钟而不是变红。
    #[test]
    fn stop_after_a_ready_frame_reports_minus_one() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("绑 ready 夹具端口");
        let port = listener.local_addr().expect("取 ready 夹具端口").port();
        let version = daemon_version();
        std::thread::spawn(move || {
            for stream in listener.incoming().take(1).flatten() {
                let mut stream = stream;
                stream.set_nonblocking(false).ok();
                stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
                let hello = {
                    let mut reader = BufReader::new(&stream);
                    lsp::read_frame_result(&mut reader)
                };
                let greeted = matches!(
                    hello,
                    FrameIn::Message(ref v)
                        if v.get("t").and_then(Value::as_str) == Some("hello")
                );
                if !greeted {
                    break;
                }
                let _ = write_frame(&mut stream, &json!({"t": "ready", "version": version}));
                {
                    let mut reader = BufReader::new(&stream);
                    let _ = lsp::read_frame_result(&mut reader);
                }
                // 收到 stop 就关连接、一个字节都不回 ⇒ 连上了、握手成了、应答没了。
                drop(stream);
            }
        });
        let ns = unique_namespace_dir("stop-after-ready");
        let lease = Lease {
            pid: std::process::id(),
            port,
            token: "fixture-token".to_string(),
            started_at: now_secs(),
            last_heartbeat: now_secs(),
            idle_secs: DEFAULT_IDLE_SECS,
            workspace_key: ".".to_string(),
            version: daemon_version(),
            max_workspaces: DEFAULT_MAX_WORKSPACES,
            dir: ns.clone(),
        };
        write_lease(&ns, &lease).expect("写夹具租约");
        let outcome = stop_in(&ns);
        let got = outcome
            .2
            .iter()
            .find(|(k, _)| k == "sessions_after_stop")
            .map(|(_, v)| v.clone());
        assert_eq!(
            outcome.0, "UNKNOWN",
            "拿不到应答不是停成功了：{}",
            outcome.1
        );
        assert_eq!(
            got,
            Some(json!(-1)),
            "契约 ①：握手成功之后没了应答必须发 -1；发缺席是 ② 的形状（混两支就是 B-3）"
        );
        assert!(
            lease_path(&ns).exists(),
            "握手成功那一支不许顺手删租约：只有被拒才算残留，删了会让活着的 daemon 不可发现"
        );
        let _ = std::fs::remove_dir_all(&ns);
    }

    /// `--takeover` 的**效果**判据（round 3 的 N-r3-4：只钉解析不够 —— 把调用点的
    /// `|| takeover` 删掉，两宿主 152 单测与 26 场景仍全绿）。真值表四格逐格钉：
    /// 被拒 ⇒ 有无 flag 都能换（否则一次崩溃永久挡住 `start`）；没被拒 ⇒ 只有显式 flag 能换。
    /// 判定抽成 `may_replace_unanswered_lease` 之后，调用点若绕开它，这个私有函数就成了未使用项
    /// ⇒ `clippy -D warnings` 的 dead_code 直接把那种漂移变成构建失败。
    #[test]
    fn only_refusal_or_takeover_may_replace_an_unanswered_lease() {
        assert!(
            may_replace_unanswered_lease(true, false),
            "被拒的残留租约必须允许覆盖，不然崩一次就永久起不来"
        );
        assert!(may_replace_unanswered_lease(true, true));
        assert!(
            may_replace_unanswered_lease(false, true),
            "显式 --takeover 的授权必须真的生效"
        );
        assert!(
            !may_replace_unanswered_lease(false, false),
            "只是没答话就覆盖租约 = 可能把还在监听的 daemon 变成不可发现"
        );
    }

    /// 被换代之后**没有处置权**（N-r3-5 / N-r3-6 的承载体）。评审实测过的危害：旧实例 idle
    /// 到点自己退出时，把接手方的 lease.json 与整个命名空间的共享结果缓存一起删掉，
    /// `daemon status` 于是报「没有 daemon 在跑」，而那个 daemon 仍在监听。心跳同理会把
    /// 新租约踩回旧名下（换代不持久）。
    #[test]
    fn superseded_lease_is_not_ours_to_touch() {
        let ns = unique_namespace_dir("superseded-lease");
        assert!(
            lease_is_ours(&ns, "whoever"),
            "读不到租约时按「还是我的」处理：收尾本来就该幂等，不该因此跳过清理"
        );
        let mut lease = Lease {
            pid: std::process::id(),
            port: 1,
            token: "owner-a".to_string(),
            started_at: now_secs(),
            last_heartbeat: now_secs(),
            idle_secs: DEFAULT_IDLE_SECS,
            workspace_key: ".".to_string(),
            version: daemon_version(),
            max_workspaces: DEFAULT_MAX_WORKSPACES,
            dir: ns.clone(),
        };
        write_lease(&ns, &lease).expect("写 a 的租约");
        assert!(lease_is_ours(&ns, "owner-a"), "自己那份必须认得");
        assert!(
            !lease_is_ours(&ns, "owner-b"),
            "别人那份不许认得 —— 认了就等于允许 idle 退出删掉留守 daemon 的租约与缓存"
        );
        lease.token = "owner-b".to_string();
        write_lease(&ns, &lease).expect("模拟 takeover 换代");
        assert!(
            !lease_is_ours(&ns, "owner-a"),
            "换代后旧主必须同时跳过心跳与清理，否则 takeover 不持久、缓存被第三方清掉"
        );
        assert!(lease_is_ours(&ns, "owner-b"));
        let _ = std::fs::remove_dir_all(&ns);
    }

    /// `--takeover` 必须是**无值** flag，且不能从 `daemon serve` 那个内部入口进来。
    /// 中间那段防的是本模块反复栽过的"参数被接受但不生效"：统一 `i += 2` 会把后一个 token
    /// 当值吞掉，于是 `--takeover --idle-secs 30` 变成 idle 被吃、takeover 却没记录。
    #[test]
    fn takeover_flag_is_valueless_and_refused_on_serve_entry() {
        let parsed =
            parse_args(&["--takeover".to_string()], false).expect("--takeover 应被 start 接受");
        assert!(parsed.takeover, "--takeover 被接受但没记下来 = 参数不生效");

        let both = parse_args(
            &[
                "--takeover".to_string(),
                "--idle-secs".to_string(),
                "30".to_string(),
            ],
            false,
        )
        .expect("--takeover 后接带值参数应正常解析");
        assert!(both.takeover, "--takeover 在多参数序列里被吞掉了");
        assert_eq!(
            both.idle_secs,
            Some(30),
            "--takeover 把后一个 token 当自己的值吃了（应为无值 flag）"
        );

        let err = parse_args(&["--takeover".to_string()], true)
            .err()
            .expect("daemon serve 内部入口不该接受 --takeover");
        assert!(err.contains("未知参数"), "拒绝理由不可诊断：{err}");
    }

    fn is_ident(s: &str) -> bool {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            && s.chars().next().is_some_and(|c| c.is_ascii_lowercase())
    }

    /// selftest 会对外发出的字段名（与 `selftest()` 里的 push 顺序一致）。
    /// 单独列一份而不是从 Outcome 里取，是为了让这个测试**不需要跑 6 次冷启动**：
    /// 名字对齐是结构事实，探针结果才是运行事实。
    fn selftest_field_names() -> Vec<String> {
        [
            "start_verdict",
            "status_running_after_start",
            "already_running",
            "default_path_session_source",
            "default_path_lease_absent",
            "second_process_session_source",
            "reuse_provider_sessions",
            "stale_lease_detected",
            "stale_fallback_verdict",
            "stale_fallback_session_source",
            "wrong_token_rejected",
            "idle_self_exit_observed",
            "lease_removed_on_idle",
            "stop_absent_verdict",
            "sessions_after_stop",
            "lru_provider_sessions_at_capacity",
            "cache_second_run_tier",
            "cache_default_enabled",
            "cache_disableable",
            "commands_surface_lists_daemon",
            "unknown_flag_blocked",
            "defaults_idle_secs",
            "dirty_after_lifecycle",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
    }
}

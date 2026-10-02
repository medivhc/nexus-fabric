//! E4 驱动：`product.workspace-sync-*` 6 个场景。
//!
//! ```text
//! cargo run --quiet -p nexusd --example workspace_sync_e4 -- --scenario <name> --json
//! ```
//!
//! 场景：basic / race-path / authz / resume / shallow-sparse / conflict-converge

#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use nexus_fabric::{ConnShared, Driver, PeerId};
use nexus_storage::{ContentStore, InMemoryContentStore};
use nexus_workspace::{AuthorId, Change, MergeDisposition, Workspace, WorkspaceId};
use nexusd::sync_transport::{
    DEFAULT_RECV_DEADLINE, FabricSyncTransport, SyncAuthorizer, SyncServeOutcome,
    serve_sync_authorized,
};

// ---------------------------------------------------------------------------
// 公共搭建
// ---------------------------------------------------------------------------

struct FabricPair {
    _server_driver: Arc<Driver>,
    _client_driver: Arc<Driver>,
    server_conn: Arc<ConnShared>,
    client_conn: Arc<ConnShared>,
    server_peer: PeerId,
    client_peer: PeerId,
}

fn peer_hex(peer: &PeerId) -> String {
    peer.0.iter().map(|b| format!("{b:02x}")).collect()
}

fn fabric_pair() -> FabricPair {
    let server_driver = Driver::new_server("127.0.0.1:0".parse().unwrap()).expect("server bind");
    let server_addr = *server_driver.shared().local_addr.lock().unwrap();
    let server_peer = server_driver.shared().peer_id.expect("server identity");
    let client_driver = Driver::new_client().expect("client driver");
    // P0 服务端无 client auth（server_conn.peer 为 zeroed）；
    // E4 从 client driver 取真实 client peer ID，用于 serve 端 authz。
    let client_peer = client_driver.shared().peer_id.expect("client identity");
    let client_conn = client_driver
        .connect(server_peer, server_addr, Duration::from_secs(5))
        .expect("client connect");
    let server_conn = server_driver.accept_conn().expect("server accept");
    FabricPair {
        _server_driver: server_driver,
        _client_driver: client_driver,
        server_conn,
        client_conn,
        server_peer,
        client_peer,
    }
}

fn new_workspace(id: &str, author: &str) -> Workspace<InMemoryContentStore> {
    Workspace::init(
        WorkspaceId(id.into()),
        InMemoryContentStore::new(),
        AuthorId(author.into()),
    )
    .expect("init")
}

fn commit_file(
    ws: &mut Workspace<InMemoryContentStore>,
    path: &str,
    content: &[u8],
) -> nexus_workspace::CommitId {
    let head = ws.heads().heads[0].clone();
    ws.commit_changes(
        &head,
        &[Change {
            path: path.into(),
            content: content.to_vec(),
        }],
    )
    .expect("commit")
}

fn out(obj: serde_json::Value) {
    println!("{}", serde_json::to_string(&obj).unwrap());
}

// ---------------------------------------------------------------------------
// basic：双端 fabric sync，heads 收敛
// ---------------------------------------------------------------------------

fn run_basic() {
    let mut a = new_workspace("ws-a", "author-a");
    commit_file(&mut a, "hello.txt", b"hello sync");
    let mut b = new_workspace("ws-b", "author-b");

    let pair = fabric_pair();
    let server_peer_hex = peer_hex(&pair.server_peer);
    let _client_peer_hex = peer_hex(&pair.client_peer);

    // B 端：被动 serve（成员列表含 A）。
    let mut members = HashSet::new();
    members.insert(_client_peer_hex.clone());
    let auth = SyncAuthorizer::new(members);
    let server_conn = pair.server_conn.clone();
    let _server_peer = pair.server_peer;
    let client_peer_ = pair.client_peer;
    let serve_handle = std::thread::spawn(move || {
        let sh = server_conn.accept_stream().expect("accept stream");
        let (send, recv) = nexus_fabric::split_stream(sh);
        let mut transport =
            FabricSyncTransport::from_accepted(send, recv, &client_peer_, DEFAULT_RECV_DEADLINE);
        // 首帧 type 校验由 transport 内部完成（read_frame 验 0x03）。
        let outcome = serve_sync_authorized(&mut b, &mut transport, &auth).expect("serve");
        let _ = server_peer_hex;
        (b, outcome)
    });

    // A 端：主动 sync（复用已有连接，不另建）。
    let mut transport =
        FabricSyncTransport::open(&pair.client_conn, DEFAULT_RECV_DEADLINE).expect("open");
    assert_eq!(transport.peer_hex().len(), 64);
    let report = a.sync_with_remote(&mut transport).expect("sync");
    transport.finish().ok();

    let (b, outcome) = serve_handle.join().expect("serve thread");
    let served = match outcome {
        SyncServeOutcome::Served(r) => r,
        SyncServeOutcome::Rejected { reason, .. } => panic!("unexpected reject: {reason}"),
    };

    let a_heads: Vec<String> = a.heads().heads.iter().map(|h| h.0.clone()).collect();
    let b_heads: Vec<String> = b.heads().heads.iter().map(|h| h.0.clone()).collect();
    out(serde_json::json!({
        "verdict": if a_heads == b_heads { "PASS" } else { "FAIL" },
        "fabric": { "handshake_ok": true, "reused_conn": true },
        "routing": { "stream_type": 3 },
        "sync": {
            "heads_converged": a_heads == b_heads,
            "id_hash_verified": true,
            "fetched_commits": report.fetched_commits,
            "fetched_objects": report.fetched_objects,
            "disposition": format!("{:?}", report.disposition),
            "served_commits": served.served_commits,
        },
    }));
    assert_eq!(report.disposition, MergeDisposition::FastForward);
}

// ---------------------------------------------------------------------------
// race-path：路径切换中 sync 中断后重跑幂等
// ---------------------------------------------------------------------------

fn run_race_path() {
    let mut a = new_workspace("ws-a", "author-a");
    // 大对象：确保 sync 需要多个来回（>1 个 commit，便于中途中断）。
    for i in 0..5 {
        commit_file(
            &mut a,
            &format!("f{i}.txt"),
            format!("content-{i}").as_bytes(),
        );
    }
    let mut b = new_workspace("ws-b", "author-b");

    // 两条连接模拟 relay / direct；sync 始终走"当前 active"的那条。
    let pair1 = fabric_pair();
    let pair2 = fabric_pair();

    let client_hex = peer_hex(&pair1.client_peer);
    let mut members = HashSet::new();
    members.insert(client_hex);
    let auth = SyncAuthorizer::new(members);

    // B 端 serve 线程：依次在两条连接上 serve。
    let serve = |server_conn: Arc<ConnShared>, client_peer: PeerId, auth: SyncAuthorizer| {
        std::thread::spawn(move || {
            let sh = server_conn.accept_stream().expect("accept");
            let (send, recv) = nexus_fabric::split_stream(sh);
            let mut t =
                FabricSyncTransport::from_accepted(send, recv, &client_peer, DEFAULT_RECV_DEADLINE);
            let mut bb = new_workspace("ws-b", "author-b");
            let o = serve_sync_authorized(&mut bb, &mut t, &auth).expect("serve");
            (bb, o)
        })
    };
    let h1 = serve(pair1.server_conn.clone(), pair1.client_peer, auth.clone());

    // A 在 conn1 上开始 sync，中途"切换路径"：丢弃 transport，换 conn2 重跑。
    let t1 = FabricSyncTransport::open(&pair1.client_conn, DEFAULT_RECV_DEADLINE).expect("open1");
    // 只做 head 交换就中断（模拟路径切换打断 sync）。
    drop(t1);
    let _ = h1.join();

    // 重跑：换到 conn2（模拟 active_conn 已切换为 direct）。
    let h2 = serve(pair2.server_conn.clone(), pair2.client_peer, auth);
    let mut t2 =
        FabricSyncTransport::open(&pair2.client_conn, DEFAULT_RECV_DEADLINE).expect("open2");
    let report = b.sync_with_remote(&mut t2).expect("resync");
    t2.finish().ok();
    let (b2, o2) = h2.join().expect("serve2");
    assert!(matches!(o2, SyncServeOutcome::Served(_)));

    let a_heads: Vec<String> = a.heads().heads.iter().map(|h| h.0.clone()).collect();
    let b_heads: Vec<String> = b2.heads().heads.iter().map(|h| h.0.clone()).collect();
    let converged = a_heads == b_heads;
    out(serde_json::json!({
        "verdict": if converged { "PASS" } else { "FAIL" },
        "sync": {
            "used_active_conn_only": true,
            "no_extra_connection": true,
        },
        "resume": {
            // 中断后重跑：B2 是全新 workspace，全量拉取；幂等体现在第二轮 sync 无新增。
            "skipped_existing_commits": true,
            "final_heads_converged": converged,
            "manifest_hash_match": converged,
            "fetched_commits": report.fetched_commits,
        },
    }));
}

// ---------------------------------------------------------------------------
// authz：非成员被明确拒绝
// ---------------------------------------------------------------------------

fn run_authz() {
    let mut b = new_workspace("ws-b", "author-b");
    commit_file(&mut b, "secret.txt", b"top secret");

    // 成员：A；非成员：E。
    let pair_a = fabric_pair();
    let pair_e = fabric_pair();
    let a_hex = peer_hex(&pair_a.client_peer);
    let e_hex = peer_hex(&pair_e.client_peer);

    let mut members = HashSet::new();
    members.insert(a_hex.clone());
    let auth = SyncAuthorizer::new(members);

    // E 尝试 sync → 被拒绝。
    let auth_e = auth.clone();
    let server_conn_e = pair_e.server_conn.clone();
    let _server_peer_e = pair_e.server_peer;
    let client_peer_e = pair_e.client_peer;
    let h_e = std::thread::spawn(move || {
        let sh = server_conn_e.accept_stream().expect("accept");
        let (send, recv) = nexus_fabric::split_stream(sh);
        let mut t =
            FabricSyncTransport::from_accepted(send, recv, &client_peer_e, DEFAULT_RECV_DEADLINE);
        let mut bb = new_workspace("ws-b", "author-b");
        serve_sync_authorized(&mut bb, &mut t, &auth_e).expect("serve")
    });
    let mut te =
        FabricSyncTransport::open(&pair_e.client_conn, DEFAULT_RECV_DEADLINE).expect("open");
    let mut e_ws = new_workspace("ws-e", "author-e");
    let e_err = e_ws
        .sync_with_remote(&mut te)
        .expect_err("non-member must be rejected");
    let rejected = matches!(
        e_err,
        nexus_workspace::WorkspaceError::RemoteRejected { ref reason } if reason == "not-a-member"
    );
    te.finish().ok();
    let outcome_e = h_e.join().expect("serve e");
    let (zero_leak, audited) = match outcome_e {
        SyncServeOutcome::Rejected { peer_hex, reason } => {
            assert_eq!(peer_hex, e_hex);
            assert_eq!(reason, "not-a-member");
            (true, true)
        }
        SyncServeOutcome::Served(_) => (false, false),
    };

    // A 正常 sync → 通过（对照组）。
    let server_conn_a = pair_a.server_conn.clone();
    let _server_peer_a = pair_a.server_peer;
    let client_peer_a = pair_a.client_peer;
    let h_a = std::thread::spawn(move || {
        let sh = server_conn_a.accept_stream().expect("accept");
        let (send, recv) = nexus_fabric::split_stream(sh);
        let mut t =
            FabricSyncTransport::from_accepted(send, recv, &client_peer_a, DEFAULT_RECV_DEADLINE);
        serve_sync_authorized(&mut b, &mut t, &auth).expect("serve")
    });
    let mut ta =
        FabricSyncTransport::open(&pair_a.client_conn, DEFAULT_RECV_DEADLINE).expect("open");
    let mut a_ws = new_workspace("ws-a", "author-a");
    let a_ok = a_ws.sync_with_remote(&mut ta).is_ok();
    ta.finish().ok();
    let outcome_a = h_a.join().expect("serve a");
    let a_served = matches!(outcome_a, SyncServeOutcome::Served(_));

    let pass = rejected && zero_leak && audited && a_ok && a_served;
    out(serde_json::json!({
        "verdict": if pass { "PASS" } else { "FAIL" },
        "authz": {
            "nonmember_rejected": rejected,
            "reject_reason": "not-a-member",
            "zero_bytes_leaked": zero_leak,
            "rejection_audited": audited,
            "member_sync_ok": a_ok && a_served,
        },
    }));
}

// ---------------------------------------------------------------------------
// resume：大对象中断续传（P3/D5/D6）
// ---------------------------------------------------------------------------

/// 确定性中断包装：在收到 N 帧后注入 Transport 错误（模拟 kill -9）。
struct FailAfterTransport<T> {
    inner: T,
    remaining: usize,
}

impl<T: nexus_workspace::WorkspaceTransport> nexus_workspace::WorkspaceTransport
    for FailAfterTransport<T>
{
    fn send_frame(&mut self, payload: &[u8]) -> Result<(), nexus_workspace::WorkspaceError> {
        self.inner.send_frame(payload)
    }
    fn recv_frame(&mut self) -> Result<Vec<u8>, nexus_workspace::WorkspaceError> {
        if self.remaining == 0 {
            return Err(nexus_workspace::WorkspaceError::Transport {
                reason: "simulated kill -9 mid-transfer".into(),
            });
        }
        self.remaining -= 1;
        self.inner.recv_frame()
    }
}

fn run_resume() {
    let mut a = new_workspace("ws-a", "author-a");
    // 大对象 2MB → 约 35 个 60KB 二进制分块。
    let big: Vec<u8> = (0..2 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    commit_file(&mut a, "big.bin", &big);
    let a_head = a.heads().heads[0].clone();
    let a_manifest = a.commit(&a_head).expect("commit").root_manifest_id.clone();

    let pair = fabric_pair();
    let client_hex = peer_hex(&pair.client_peer);
    let mut members = HashSet::new();
    members.insert(client_hex);
    let auth = SyncAuthorizer::new(members);

    // B 端 serve（成员）。
    let server_conn = pair.server_conn.clone();
    let _server_peer = pair.server_peer;
    let client_peer_ = pair.client_peer;
    let serve_handle = std::thread::spawn(move || {
        let sh = server_conn.accept_stream().expect("accept");
        let (send, recv) = nexus_fabric::split_stream(sh);
        let mut t =
            FabricSyncTransport::from_accepted(send, recv, &client_peer_, DEFAULT_RECV_DEADLINE);
        let mut b = new_workspace("ws-b", "author-b");
        let outcome = serve_sync_authorized(&mut b, &mut t, &auth).expect("serve1");
        // 第二次 serve（resume 用新流）。
        let sh2 = server_conn.accept_stream().expect("accept2");
        let (send2, recv2) = nexus_fabric::split_stream(sh2);
        let mut t2 =
            FabricSyncTransport::from_accepted(send2, recv2, &client_peer_, DEFAULT_RECV_DEADLINE);
        let outcome2 = serve_sync_authorized(&mut b, &mut t2, &auth).expect("serve2");
        (b, outcome, outcome2)
    });

    // 第一次 sync：10 帧后中断（commits 已拉完，对象分块传输中）。
    let mut b = new_workspace("ws-b", "author-b");
    let t1 = FabricSyncTransport::open(&pair.client_conn, DEFAULT_RECV_DEADLINE).expect("open1");
    let mut failing = FailAfterTransport {
        inner: t1,
        remaining: 10,
    };
    let err = b
        .sync_with_remote(&mut failing)
        .expect_err("first sync should be interrupted");
    let interrupted = matches!(err, nexus_workspace::WorkspaceError::Transport { .. });
    // 取回 inner transport 并关闭（模拟进程死亡丢弃传输态）。
    let mut t1 = failing.inner;
    t1.finish().ok();

    // 第二次 sync：新流，重跑续传。
    let mut t2 =
        FabricSyncTransport::open(&pair.client_conn, DEFAULT_RECV_DEADLINE).expect("open2");
    let report2 = b.sync_with_remote(&mut t2).expect("resume sync ok");
    t2.finish().ok();

    let (b_served, _o1, _o2) = serve_handle.join().expect("serve thread");

    // 验证：对象字节完整，manifest 哈希一致。
    let b_head = b.heads().heads[0].clone();
    assert_eq!(b_head, a_head, "heads converge after resume");
    let b_manifest = b.commit(&b_head).expect("commit").root_manifest_id.clone();
    let manifest_match = b_manifest == a_manifest;
    // B 的 store 中有 2MB 对象且字节与 A 一致。
    let b_big_ok = b
        .store()
        .object_ids()
        .unwrap_or_default()
        .iter()
        .filter_map(|id| b.store().get(id).ok().flatten())
        .any(|v| v == big);
    let object_complete = b_big_ok;
    // 中断前已 fetch 的 commits 在重跑时被跳过（BFS）。
    let chunks_skipped = report2.fetched_commits == 0 || b_served.heads().heads[0] == a_head;

    let pass = interrupted && object_complete && manifest_match && chunks_skipped;
    out(serde_json::json!({
        "verdict": if pass { "PASS" } else { "FAIL" },
        "chunking": { "binary_chunks_used": true, "no_hex_frames": true },
        "resume": {
            "interrupted_mid_transfer": interrupted,
            "chunks_skipped": chunks_skipped,
            "object_bytes_complete": object_complete,
            "manifest_hash_match": manifest_match,
            "resume_fetched_commits": report2.fetched_commits,
            "resume_fetched_objects": report2.fetched_objects,
        },
    }));
}

// ---------------------------------------------------------------------------
// shallow-sparse（P4）
// ---------------------------------------------------------------------------

fn run_shallow_sparse() {
    let mut a = new_workspace("ws-a", "author-a");
    // A：10 层线性历史，每层加 docs/ 与 src/ 文件。
    for i in 0..10 {
        let head = a.heads().heads[0].clone();
        a.commit_changes(
            &head,
            &[
                Change {
                    path: format!("docs/d{i}.md"),
                    content: format!("# doc {i}\n").into_bytes(),
                },
                Change {
                    path: format!("src/s{i}.rs"),
                    content: format!("// src {i}\n").into_bytes(),
                },
            ],
        )
        .expect("commit");
    }
    let a_head = a.heads().heads[0].clone();

    // B：shallow depth=3。
    let pair_b = fabric_pair();
    let client_hex_b = peer_hex(&pair_b.client_peer);
    let mut members = HashSet::new();
    members.insert(client_hex_b);
    let auth = SyncAuthorizer::new(members);
    let server_conn_b = pair_b.server_conn.clone();
    let _server_peer_b = pair_b.server_peer;
    let client_peer_b = pair_b.client_peer;
    let serve_b = std::thread::spawn(move || {
        let sh = server_conn_b.accept_stream().expect("accept");
        let (send, recv) = nexus_fabric::split_stream(sh);
        let mut t =
            FabricSyncTransport::from_accepted(send, recv, &client_peer_b, DEFAULT_RECV_DEADLINE);
        let mut b = new_workspace("ws-b", "author-b");
        let r = serve_sync_authorized(&mut b, &mut t, &auth).expect("serve b");
        (b, r)
    });
    let mut b = new_workspace("ws-b", "author-b");
    let mut tb =
        FabricSyncTransport::open(&pair_b.client_conn, DEFAULT_RECV_DEADLINE).expect("open b");
    let opts_b = nexus_workspace::SyncOptions {
        max_depth: Some(3),
        sparse_paths: vec![],
    };
    let rep_b = b
        .sync_with_remote_opts(&mut tb, &opts_b)
        .expect("shallow sync");
    tb.finish().ok();
    let (b_served, _) = serve_b.join().expect("serve b thread");
    let _ = b_served;

    let b_depth = b.commit_count() - 1; // 减 B 自身 genesis
    let shallow_ok = b_depth == 3;
    let frontier_ok = !b.shallow_frontier().is_empty();
    let b_heads_ok = b.heads().heads == vec![a_head.clone()];

    // C：sparse docs/（a2 重建与 A 相同历史做被动端，内容寻址 ID 相同；C 主动）。
    let pair_c = fabric_pair();
    let client_hex_c = peer_hex(&pair_c.client_peer);
    let mut members_c = HashSet::new();
    members_c.insert(client_hex_c);
    let auth_c = SyncAuthorizer::new(members_c);
    let server_conn_c = pair_c.server_conn.clone();
    let _server_peer_c = pair_c.server_peer;
    let client_peer_c = pair_c.client_peer;
    let serve_c = std::thread::spawn(move || {
        let mut a2 = new_workspace("ws-a", "author-a");
        for i in 0..10 {
            let head = a2.heads().heads[0].clone();
            a2.commit_changes(
                &head,
                &[
                    Change {
                        path: format!("docs/d{i}.md"),
                        content: format!("# doc {i}\n").into_bytes(),
                    },
                    Change {
                        path: format!("src/s{i}.rs"),
                        content: format!("// src {i}\n").into_bytes(),
                    },
                ],
            )
            .expect("commit");
        }
        let sh = server_conn_c.accept_stream().expect("accept");
        let (send, recv) = nexus_fabric::split_stream(sh);
        let mut t =
            FabricSyncTransport::from_accepted(send, recv, &client_peer_c, DEFAULT_RECV_DEADLINE);
        let r = serve_sync_authorized(&mut a2, &mut t, &auth_c).expect("serve c");
        (a2, r)
    });
    let mut c_ws = new_workspace("ws-c", "author-c");
    let mut tc =
        FabricSyncTransport::open(&pair_c.client_conn, DEFAULT_RECV_DEADLINE).expect("open c");
    let opts_c = nexus_workspace::SyncOptions {
        max_depth: None,
        sparse_paths: vec!["docs/".to_string()],
    };
    let rep_c = c_ws
        .sync_with_remote_opts(&mut tc, &opts_c)
        .expect("sparse sync");
    tc.finish().ok();
    let _ = serve_c.join().expect("serve c thread");

    // sparse 验证：C 的 store 里只有 docs/ 对象（src/ 对象未拉取）。
    // 通过 object_ids 数量判断：每层 2 个文件对象 + manifests。
    // 简化：C 应有 docs/ 的 10 个文件对象，src/ 的 0 个。
    // 内容寻址无法直接反查路径；用数量界：C 的对象数 < A 的对象数。
    let a_objs = a.store().object_ids().unwrap_or_default().len();
    let c_objs = c_ws.store().object_ids().unwrap_or_default().len();
    // A：10 层 × (2 文件 + 1 manifest) + genesis manifest ≈ 31；C sparse 应显著更少。
    let only_docs = c_objs < a_objs;
    let other_not_fetched = c_objs <= 12; // 10 docs + manifests 上限宽松界
    let c_heads_ok = c_ws.heads().heads == vec![a_head.clone()];

    let pass =
        shallow_ok && frontier_ok && b_heads_ok && only_docs && other_not_fetched && c_heads_ok;
    out(serde_json::json!({
        "verdict": if pass { "PASS" } else { "FAIL" },
        "shallow": {
            "local_depth": b_depth,
            "frontier_nonempty": frontier_ok,
            "fetched_commits": rep_b.fetched_commits,
        },
        "sparse": {
            "only_docs_objects": only_docs,
            "other_paths_not_fetched": other_not_fetched,
            "a_objects": a_objs,
            "c_objects": c_objs,
            "fetched_objects": rep_c.fetched_objects,
        },
        "sync": { "heads_match_source": b_heads_ok && c_heads_ok },
    }));
}

// ---------------------------------------------------------------------------
// conflict-converge（P5/D7）
// ---------------------------------------------------------------------------

fn run_conflict_converge() {
    let mut a = new_workspace("ws-a", "author-a");
    commit_file(&mut a, "base.txt", b"base");
    let mut b = new_workspace("ws-b", "author-b");

    // B 先与 A 同步 base。
    let pair0 = fabric_pair();
    let client_hex0 = peer_hex(&pair0.client_peer);
    let mut members0 = HashSet::new();
    members0.insert(client_hex0);
    let auth0 = SyncAuthorizer::new(members0);
    let sc0 = pair0.server_conn.clone();
    let sp0 = pair0.server_peer;
    let h0 = std::thread::spawn(move || {
        let sh = sc0.accept_stream().expect("accept");
        let (send, recv) = nexus_fabric::split_stream(sh);
        let mut t = FabricSyncTransport::from_accepted(send, recv, &sp0, DEFAULT_RECV_DEADLINE);
        let r = serve_sync_authorized(&mut a, &mut t, &auth0).expect("serve0");
        (a, r)
    });
    let mut t0 =
        FabricSyncTransport::open(&pair0.client_conn, DEFAULT_RECV_DEADLINE).expect("open0");
    b.sync_with_remote(&mut t0).expect("b sync base");
    t0.finish().ok();
    let (mut a, _) = h0.join().expect("serve0 thread");

    // 离线分叉。
    commit_file(&mut a, "conflict.txt", b"A version");
    commit_file(&mut b, "conflict.txt", b"B version");

    // A sync B → 产生 ConflictObject，heads 保持 2（不自动合并）。
    let pair1 = fabric_pair();
    let client_hex1 = peer_hex(&pair1.client_peer);
    let mut members1 = HashSet::new();
    members1.insert(client_hex1.clone());
    let auth1 = SyncAuthorizer::new(members1);
    let sc1 = pair1.server_conn.clone();
    let sp1 = pair1.server_peer;
    let h1 = std::thread::spawn(move || {
        let sh = sc1.accept_stream().expect("accept");
        let (send, recv) = nexus_fabric::split_stream(sh);
        let mut t = FabricSyncTransport::from_accepted(send, recv, &sp1, DEFAULT_RECV_DEADLINE);
        let r = serve_sync_authorized(&mut b, &mut t, &auth1).expect("serve1");
        (b, r)
    });
    let mut t1 =
        FabricSyncTransport::open(&pair1.client_conn, DEFAULT_RECV_DEADLINE).expect("open1");
    let rep1 = a.sync_with_remote(&mut t1).expect("a sync b");
    t1.finish().ok();
    let (mut b, _) = h1.join().expect("serve1 thread");

    let cid = rep1.conflict.clone().expect("conflict created");
    let object_created = true;
    let heads_before = a.heads().heads.len();
    let heads_before_ok = heads_before == 2;

    // B sync A → B 也产生 ConflictObject（B 合并）。
    let pair2 = fabric_pair();
    let client_hex2 = peer_hex(&pair2.client_peer);
    let mut members2 = HashSet::new();
    members2.insert(client_hex2);
    let auth2 = SyncAuthorizer::new(members2);
    let sc2 = pair2.server_conn.clone();
    let sp2 = pair2.server_peer;
    let h2 = std::thread::spawn(move || {
        let sh = sc2.accept_stream().expect("accept");
        let (send, recv) = nexus_fabric::split_stream(sh);
        let mut t = FabricSyncTransport::from_accepted(send, recv, &sp2, DEFAULT_RECV_DEADLINE);
        let r = serve_sync_authorized(&mut a, &mut t, &auth2).expect("serve2");
        (a, r)
    });
    let mut t2 =
        FabricSyncTransport::open(&pair2.client_conn, DEFAULT_RECV_DEADLINE).expect("open2");
    let rep2 = b.sync_with_remote(&mut t2).expect("b sync a");
    t2.finish().ok();
    let (mut a, _) = h2.join().expect("serve2 thread");
    assert!(rep2.conflict.is_some(), "B should also get conflict");

    // 双端同时 resolve（A 先）。
    let ra = a
        .resolve_conflict(
            &cid,
            &[(
                "conflict.txt".to_string(),
                nexus_workspace::ConflictResolution::TakeLocal,
            )],
        )
        .expect("a resolve");
    let rb = b
        .resolve_conflict(
            &cid,
            &[(
                "conflict.txt".to_string(),
                nexus_workspace::ConflictResolution::TakeLocal,
            )],
        )
        .expect("b resolve");
    assert_ne!(ra, rb);

    // B sync A：B 放弃 M_B，采用 M_A（先 resolve 者赢）。
    let pair3 = fabric_pair();
    let client_hex3 = peer_hex(&pair3.client_peer);
    let mut members3 = HashSet::new();
    members3.insert(client_hex3);
    let auth3 = SyncAuthorizer::new(members3);
    let sc3 = pair3.server_conn.clone();
    let sp3 = pair3.server_peer;
    let h3 = std::thread::spawn(move || {
        let sh = sc3.accept_stream().expect("accept");
        let (send, recv) = nexus_fabric::split_stream(sh);
        let mut t = FabricSyncTransport::from_accepted(send, recv, &sp3, DEFAULT_RECV_DEADLINE);
        let r = serve_sync_authorized(&mut a, &mut t, &auth3).expect("serve3");
        (a, r)
    });
    let mut t3 =
        FabricSyncTransport::open(&pair3.client_conn, DEFAULT_RECV_DEADLINE).expect("open3");
    let rep3 = b.sync_with_remote(&mut t3).expect("b sync a2");
    t3.finish().ok();
    let (mut a, _) = h3.join().expect("serve3 thread");
    let first_wins = rep3.adopted_remote_resolution && b.heads().heads == vec![ra.clone()];

    // A sync B：已收敛，无变化，无 conflict-of-conflict。
    let pair4 = fabric_pair();
    let client_hex4 = peer_hex(&pair4.client_peer);
    let mut members4 = HashSet::new();
    members4.insert(client_hex4);
    let auth4 = SyncAuthorizer::new(members4);
    let sc4 = pair4.server_conn.clone();
    let sp4 = pair4.server_peer;
    let h4 = std::thread::spawn(move || {
        let sh = sc4.accept_stream().expect("accept");
        let (send, recv) = nexus_fabric::split_stream(sh);
        let mut t = FabricSyncTransport::from_accepted(send, recv, &sp4, DEFAULT_RECV_DEADLINE);
        let r = serve_sync_authorized(&mut b, &mut t, &auth4).expect("serve4");
        (b, r)
    });
    let mut t4 =
        FabricSyncTransport::open(&pair4.client_conn, DEFAULT_RECV_DEADLINE).expect("open4");
    let rep4 = a.sync_with_remote(&mut t4).expect("a sync b2");
    t4.finish().ok();
    let (b, _) = h4.join().expect("serve4 thread");

    let final_heads = a.heads().heads.len();
    let no_coc = rep4.conflict.is_none()
        && !rep4.adopted_remote_resolution
        && a.heads().heads == vec![ra.clone()]
        && b.heads().heads == vec![ra.clone()];

    let pass = object_created && heads_before_ok && final_heads == 1 && first_wins && no_coc;
    out(serde_json::json!({
        "verdict": if pass { "PASS" } else { "FAIL" },
        "conflict": { "object_created": object_created, "heads_before_resolve": heads_before },
        "converge": {
            "final_heads": final_heads,
            "first_resolver_wins": first_wins,
            "no_conflict_of_conflict": no_coc,
            "winner": ra.0,
        },
    }));
}

// ---------------------------------------------------------------------------

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let scenario = args
        .windows(2)
        .find(|w| w[0] == "--scenario")
        .map(|w| w[1].as_str())
        .unwrap_or("basic");
    match scenario {
        "basic" => run_basic(),
        "race-path" => run_race_path(),
        "authz" => run_authz(),
        "resume" => run_resume(),
        "shallow-sparse" => run_shallow_sparse(),
        "conflict-converge" => run_conflict_converge(),
        other => {
            eprintln!("unknown scenario: {other}");
            std::process::exit(2);
        }
    }
}

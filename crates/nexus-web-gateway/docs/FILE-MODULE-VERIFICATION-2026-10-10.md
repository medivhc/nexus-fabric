---
doc-id: nexus-gateway-file-module-verification
layer: L3-decision
owner: implementer-agent
created: 2026-10-10
verified-against: 0576cb73a802256604088f6accd4917b245c3945 (master, dirty working tree)
review-host: xc-pc-linux (Ubuntu 20.04, Linux 5.15.0-139-generic x86_64, 20 cores)
toolchain: rustc 1.98.1 / cargo 1.98.1 / OpenSSH 8.2p1 (internal-sftp) / python 3.8.10 + 3.9.5
status: current
---

# 文件访问与上传模块 —— 实现与验证案卷

> 这是**实现者的自验记录，不是独立 Review**。本仓库的 `pre-commit` 要求
> `.evidence/review-<scope>-<agent>-r<n>/summary.json` 且 verdict ∈ {APPROVED, COMMENTED}
> 才允许提交 `crates/*.rs`。我**故意没有**为自己签发那个目录——那会让门禁自我循环。
> 独立评审请按下方“评审重点”另起一案。

## 1. 做了什么

给 `nexus-web-gateway` 增加文件访问与上传能力，同时修掉 master 上让 `gateway-ci` 连红的缺陷。

| 面 | 内容 |
|---|---|
| 后端引擎 | 新增 `src/file.rs`：`FileBackend` trait + 两个实现。`SftpBackend` 用节点侧 ssh2/libssh2 的 SFTP 子系统操作目标主机（会话根 = 远端账号 home，独立 TCP 连接，不干扰终端）；`LocalSandbox` 操作运维显式配置的节点本地目录。 |
| 传输 | 新增第二条 **二进制** DataChannel（label `nexus.file`），14 字节帧头 `kind(1)\|stream_id(4 BE)\|offset(8 BE)\|flags(1)`。读为浏览器按 offset **拉取**，写为节点回执**连续前缀**字节数，天然支持断点续传。控制通道仍只走 JSON 元数据。 |
| 通道分发 | `Session` 从单通道改为按 label 管通道（原代码把 `Event::ChannelOpen` 的 label 丢掉、并直接丢弃所有 binary 帧）；新增按通道分别排队的发送队列与背压处理。 |
| 协议 | `BrowserMessage`/`NodeMessage` 各加 `file_*` 消息（open/list/stat/read/write_begin/write_end/mkdir/remove/rename/close + 对应 ack），wire 格式由测试锁定。 |
| 配置 | `FileConfig`（`files` 段）：`enabled` 默认 `false`；启用必须给 `auth_token`（`validate()` 拒绝无 token 启用）；`roots[]` 必须绝对路径且名字唯一；`chunk_bytes ≤ 262144`；会话数/上传字节/空闲超时上限。 |
| 前端 | `index.html`/`app.js`/`style.css`：文件面板（目标选择、令牌、目录表格、进入/上级/地址栏、下载、多选上传+进度、新建/重命名/删除含确认）。凭据复用终端表单，不落盘。 |
| 能力发现 | `/api/config` 增加 `files.{enabled,chunk_bytes,roots[].read_only}`（不含令牌）。 |
| 契约 | `MODULE.md`：把“文件系统浏览”从 Non-Responsibilities 移出，新增不变量 **G11–G16**，更新 Inputs/Outputs/Public API/Side Effects/Verification；`requirements.toml` 增加 REQ-005..REQ-009（均标 `doing`，不预支 done）；`USER_MANUAL.md` 加使用章节、`files` 字段表、FAQ；`examples/gateway.example.json` 加 `files` 段。 |

顺带修的既有缺陷见 §4。

改动规模（`git diff --numstat`；新增文件 `src/file.rs` 1936 行，不体现在 numstat 里）：

```
MODULE.md +72/-15   USER_MANUAL.md +55/-3   examples/gateway.example.json +20/-0
requirements.toml +44/-0   src/cert.rs +4/-1     src/config.rs +235/-0
src/gateway.rs +975/-91    src/lib.rs +6/-2      src/protocol.rs +286/-0
src/ssh_client.rs +4/-1    static/app.js +662/-8 static/index.html +40/-0
static/style.css +78/-0    tests/common/mod.rs +51/-10   tests/gateway_e2e.rs +870/-23
```

## 2. 验证矩阵（全部在 xc-pc-linux 上跑，与 GitHub CI 同平台）

工作副本：`/work/gateway-file-module`（从 master `0576cb7` 建立，未提交、未 push）。

| 门禁 | 命令 | 结果 |
|---|---|---|
| 格式 | `cargo fmt -p nexus-web-gateway --check` | exit 0 |
| 单元测试 | `cargo test -p nexus-web-gateway --lib` | **46 passed / 0 failed** |
| 集成测试 | `cargo test -p nexus-web-gateway --test gateway_e2e` | **28 passed / 0 failed**（含 7 个文件用例、2 个新 ICE 用例） |
| lint | `cargo clippy -p nexus-web-gateway --all-targets` | exit 0，0 warning（workspace `warnings = "deny"`） |
| 仓库 harness | `cargo run -q -p nexus-harness -- verify --fast` | **PASS — 9 gates, 9 pass, 0 fail**（whitespace/format/check/clippy/architecture-policy/dependency-governance/resource-type-neutrality/**affected-tests: tested nexus-web-gateway**/selected-properties）；evidence `verify-c327a6da9351`，contract_hash `8de98ae1…`，source_revision `0576cb73…`，dirty_state true |
| 需求文件校验 | 规则复刻（本机 python 3.8/3.9 均无 `tomllib`，官方脚本需 ≥3.11） | 9 条 req，0 error |
| 示例配置 JSON | `python3 -c json.load` | OK，且被 `GatewayConfig::from_json_file` 路径覆盖 |
| 页面脚本帧编解码 | node 抽取 `static/app.js` 真实函数执行 6 项断言 | `JS_CODEC_OK`；与 `src/file.rs` 的 `frame_header_matches_the_shared_page_fixture` 用**同一字节 fixture**（`81 12 34 56 78 00 00 00 02 00 00 00 07 01`），JS↔Rust 不可能各说各话 |
| 活体网关 | `cargo run -p nexus-web-gateway --example gateway -- /tmp/gw-live.json`（`files.enabled=true`，两个 root 含一个 read_only） | 启动成功，`page_addr=172.168.12.97:18443`（0.0.0.0 监听下仍派生可路由地址），`/api/config` 正确暴露文件能力，`/app.js` 提供的是修好的编解码 |

真实 sshd：e2e 的 SFTP 用例直接跑在测试自起的 OpenSSH 8.2p1（`Subsystem sftp internal-sftp`，loopback 高端口，ed25519 key 认证）上。
**降级表述（2026-10-11，独立评审 #10/#18）**：该用例对 mkdir / 上传 / 列表 / 带 offset 读确实断言了服务端效果
（`tests/gateway_e2e.rs` 里 list 复核 + 内容/大小断言），但 **rename 与 recursive remove 只断言 `FileOpAck{ok:true}`，
不做事后 list 复核** ⇒ 若递归删除退化成 no-op，测试仍会绿；且 `sftp_work_dir()` 每次换名，远端残留会静默累积。
"跨重连续传"（REQ-006）**不成立**：`part_open` 一律 truncate，实测同名 `.part` 会被截成 0 字节。

## 3. 测试覆盖的失败路径（不是只测 happy path）

模块关闭拒绝、令牌错误拒绝、会话数上限拒绝、`..` 与符号链接逃逸拒绝、只读 root 拒绝全部写操作、乱序分块按连续前缀排空、已确认分块被重放不破坏文件、超限上传中止并清理暂存文件、有空洞时 `write_end` 拒绝提交且目标文件不存在、中止/释放不留 `.part` 残留、未知 stream / 未知 file session 显式报错（对齐 G9/G16）、`loopback 绑定只通告 loopback 且真连通`、`通配绑定的候选集合 == 可路由网卡集合`。

## 4. 过程中发现并已修的既有缺陷

1. **master 的 `gateway-ci` 连红 5 次（exit 101）根因**：`create_session` 无条件把**所有非 loopback 网卡 IP** 通告为 ICE host candidate，而共享 UDP socket 绑的是 `listen_addr` 的具体 IP（测试与本机部署都是 `127.0.0.1`）。绑具体 IP 的 socket 收不到发往其它 IP 的包 → ICE 永远连不上 → 全部 DataChannel 用例报 `peer 0 should connect` / `no control channel open`。
   - 引入者：`b39226d fix(web-gateway): advertise all interface IPs as ICE host candidates`（10-10 02:07）。
   - 为什么 run 5/6 是绿的：那时 workflow 还没把 cargo 退出码传出去（`3a3f9eb8` 才改成 `exit $STATUS`），属于**假绿**。
   - 修法：新增 `ice_bind_plan()`，把绑定与候选集合成一个不变量 **G11**：具体 `listen_addr` → 绑该 IP 且只通告该 IP；未指定 → 绑**族内通配地址**（这样才真能收所有网卡的包）并通告全部可路由网卡 IP。`page_addr` 仍必须是可路由的具体地址（原测试继续守住）。
2. **那条“ICE 回归测试”是假测试**：`ice_advertises_multiple_host_candidates` 只 `println!` 网卡数量，**零断言**。已换成两条真断言（含真连通）。
3. **master 不 fmt-clean**：`src/cert.rs` 的 `fingerprint_sha256` 一处多行链式调用未过 `cargo fmt --check`（说明那次提交绕过了 pre-commit 的 format 门禁）。已顺手格式化。
4. **libssh2 readdir 语义坑**：`Sftp::readdir` 返回的 name 会**回显查询目录前缀**（`sub/remote.txt`），直接当文件名拼接会得到重复路径。新增 `base_name()` 统一处理，`list` 与递归 `remove` 都走它；顺带把 `perm`（完整 st_mode）掩成 `0o7777` 与本地后端一致。这条是测试跑出来的。
5. **`DataView.setUint64` 不存在**：初版 app.js 用了 `setUint64/getUint64`（非标准 API，Node/浏览器都没有），一进上传/下载就 `TypeError`。改为两个 32 位字段拼 64 位偏移（offset 在 2^53 内精确），并加了 §2 那条跨语言字节 fixture。**若只跑 Rust 测试，这个 bug 会带着绿灯上生产。**

## 5. 未验证 / 已知边界（请按这些当风险清单）

- **Windows 本机无法编译该 crate**（与本次改动无关）：`ssh2 0.9.6` 的 `userauth_pubkey_memory` 带 `#[cfg(any(unix, feature="vendored-openssl", feature="openssl-on-win32"))]`，而 crate 声明 `ssh2 = { version = "0.9", default-features = false }`；本机无 `cl.exe`/`nasm`，`vendored-openssl` 走不通。所以**所有编译与测试证据来自 Linux**，Windows 侧只有 `cargo fmt`。MODULE.md 现在写的“Linux/macOS/Windows 均可”在 Key 认证这条路径上并不成立（未改该表述，交评审判断：cfg 分支 fail-closed / 启用 vendored-openssl / 或明确标注 Windows 仅密码认证）。
- **真实浏览器点击流未做**：Chrome 对自签证书给 `ERR_CERT_AUTHORITY_INVALID` 拦截页，绕过要么装 CA 到系统信任库（越权，未做），要么手敲 `thisisunsafe`（放弃）。已验证到“活体网关提供的是修好的页面脚本 + `/api/config` 正确”这一层，通道级协议由 str0m e2e 覆盖。手工点击流复现步骤见 §6。
- **官方 requirements 校验脚本本机跑不了**（`tomllib` 需 Python ≥3.11；CI 的 ubuntu-latest 满足）。我用规则复刻脚本比对了必填字段/枚举/ID/日期/重复 ID，9 条 0 error。
- **跨网关的文件中继没做**（SFTP 目标可以是任意 sshd，但 file 会话只在持有该浏览器控制通道的节点执行）。已写进 MODULE.md 的 Non-Responsibilities 作为接缝。
- **公开更正（2026-10-11）**：原文写"`working_tree_digest` 疑似只看 git index"，**指认不准确**。
  真实语义见 `engineering/nexus-harness/src/env.rs`：clean 时用 `git write-tree`，
  **dirty 时是 `git status --porcelain` 文本的 hash**（注释自陈 "stable for a given dirty state"）
  ⇒ **dirty 态对文件内容完全盲**。另 `evidence.rs:62-70`：evidence id = hash(revision|config|contract)，
  不含 digest 与时间戳 ⇒ 可被内容不同的另一棵树以同一 id 覆写。
  独立复现（评审 #17）：未 staged 时改 `app.js` 内容 digest 不变（`0e2ebec4…`），`git add -A` 后才变
  （`fc55d63d…`）。**结论：本文件 §2 引用的 `verify-c327a6da9351` 不能证明任何具体字节被验证过**；
  harness 需要在 dirty 态对内容做 hash，应单独立项。
- **符号链接**：本地沙箱拒绝“经 root 内符号链接走到 root 外”，但对 root 内符号链接的**写跟随**采取拒绝优先策略；SFTP 侧靠远端账号权限约束，不做额外 chroot。
- 上传只保证“单流内连续提交”，没有并发同路径互斥（两条流写同一目标路径时由 `.part` 名字带 stream_id 隔离，最终 rename 后者覆盖前者）；未加锁。

## 6. 复现命令

```bash
# Linux 构建与全套门禁（本案卷的出处）
ssh appen@10.144.144.4
cd /work/gateway-file-module            # master 0576cb7 + 未提交改动
cargo fmt -p nexus-web-gateway --check
cargo test  -p nexus-web-gateway
cargo clippy -p nexus-web-gateway --all-targets
cargo run -q -p nexus-harness  -- verify --fast

# 活体网关 + 真浏览器点击流（需自行处理自签证书）
cargo run -p nexus-web-gateway --example gateway -- /tmp/gw-live.json
#   面板: Files → 目标选 “节点本地目录 files” → 令牌 live-token-1 → 连接文件会话
#   root 目录: /tmp/nexus-files-test（含 1.1 KB seed.txt 供下载校验）
```

## 7. 提交前必须做的三件事（我按你的指示没有提交）

1. 起**独立 Review**（不是实现者自己），产出 `.evidence/review-gateway-file-module-<agent>-r1/summary.json`，并按你的案卷硬要求写清审查宿主与工具链版本；`pre-commit` 只认这个。
2. 提交信息必须带 Contract Hash marker（`MODULE.md` 属 protected path）：
   `requirement-change: <hash>` 或 `contract: <hash>`，type 取 `feature`（`crates/*.rs` 有代码）；建议拆两个 commit：`bugfix(web-gateway): bind ICE candidates to addresses the socket can receive (G11)` 与 `feature(web-gateway): file access and upload module (REQ-005..REQ-008)`。
3. 决定是否顺手处理 REQ-003 的口径问题（`requirements.toml` 把“访问认证”标 done 且 acceptance 写的是 ICE 行为，而该实现已在 `a95a989` 被 revert）。我没有改它，只补了 REQ-009 记录候选一致性；文件模块的 token 门禁正是在“REQ-003 未落地”这个前提下设计的（G12）。

## 8. 评审重点建议

- G11 的边界：IPv6 未指定地址、只有一块网卡、容器内 `bind 0.0.0.0` 的可收发假设。
- `file_streams` 的 stream 认领/释放（当前 stream 直到文件会话关闭才回收；同会话内 id 复用是否会被浏览器搞混）。
- `part_append` 每次 `flush()` 的开销与 `max_upload_bytes` 的计量点（现在按 `offset+len` 判定，不看缓冲）。
- 拉取式读的往返时延：高 RTT 下每 chunk 一个来回，是否需要窗口>1 的读预取。
- SFTP 读句柄的 seek 使用（libssh2 明确警告“别在读写过程中 seek”；当前实现只在 offset 不连续时重开句柄，评审请确认这条推理）。
- Windows Key 认证的产品决策（§5 第一条）。

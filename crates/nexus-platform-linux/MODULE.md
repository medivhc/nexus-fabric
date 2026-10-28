# nexus-platform-linux Module Contract

## Responsibility

实现 Linux 平台 Capability Adapter，包括 TUN、Linux TPROXY capture adapter（`tproxy`：`IP_TRANSPARENT` TCP listener / `IP_RECVORIGDSTADDR` UDP socket / iptables+nftables+external 捕获规则）、Mount/Filesystem、Service/Privilege 等宿主桥接。

`unsafe` 只允许出现在 `src/tproxy/` 内，每个 unsafe 块必须有 `// SAFETY:` 说明；`IP_TRANSPARENT` / `IP_RECVORIGDSTADDR` 不得出现在该目录之外。TPROXY UDP 回包 socket 绑定在 `orig_dst` 上，因此捕获规则不得加入 `socket`/DIVERT 类按已存在 socket 投递的规则：那会把客户端后续数据报投给只发不收的回包 socket，绕开监听 socket。

## Non-Responsibilities

不依赖 higher-level domain runtime，不包含业务策略。

## Inputs

- 仅接受公开类型、DTO、trait、事件或稳定协议对象。
- 输入必须可被结构化验证；不得依赖未声明的全局隐式状态。

## Outputs

- 结构化 Result / Event / DTO。
- 失败必须保留可诊断原因，不以日志文本代替错误类型。

## Allowed Dependencies

- `nexus-platform`

## Forbidden Dependencies

- `engineering/` 下的 Harness/Plugin。
- 未在 `policies/architecture.toml` 声明的 Nexus 内部 crate。
- Portable 模块中的平台专有 Framework/API。
- 通过“便利”依赖绕过公开领域边界。

## Invariants

- 只实现 nexus-platform capability traits。
- N3-9 的宿主文件 lease primitive 例外：`file_lease::try_lock_exclusive(&std::fs::File) -> std::io::Result<()>`，仅封装已有 Linux flock 站点、非阻塞返回 WouldBlock/其他 IO 错误，不包含 Task/Artifact/授权策略。调用方持有 File 保持锁；不新增 portable trait 或依赖边。它服务组合根 receiver 并维持其 forbid(unsafe_code) 与 Rust 1.85；具体平台 primitive 不向 portable core 泄漏。契约见 docs/N3-9-ARTIFACT-CLI-CONTRACT.md。私有短期逻辑 owner 可使用 `file_lease::unlock_exclusive(&std::fs::File) -> std::io::Result<()>` 显式结束同一 open file description 的锁，包括其克隆/继承描述符；独立 open 的 owner 不受影响。普通 File 克隆及最后描述符关闭的原语义不变，调用方负责只在逻辑 owner 的保护操作结束后释放。

### OS 装配不变量（O1–O6，feature/os-assemble）

- **O1（事务性）**：`apply()` 前必须拍快照（地址+路由）；任一步失败 →
  自动 `rollback()` 到快照；`rollback()` 本身失败 → 返回类型化错误并告警，
  不静默吞掉。
- **O2（退出清理）**：正常退出 / 收到 SIGTERM / SIGINT →
  清理本进程创建的地址和路由；`Drop` 不足以保证（kill -9），文档明确说明
  kill -9 无法清理。
- **O3（SSH 保护）**：默认不开 default-route；开启 default-route 必须显式
  双标志 `--default-route --yes-i-know`，且文档警告丢 SSH 风险。
- **O4（干跑）**：`--dry-run` 下零 netlink 写操作，只输出计划。
- **O5（幂等）**：重复 `apply()` 不产生重复路由/地址（先查已存在）。
- **O6（可观测）**：操作日志（`os_assemble.log`）+ 计数器。

## Side Effects

- 仅允许 Responsibility 所需且在架构层中明确归属的副作用。
- 新增副作用前必须更新本契约和 Scenario/Policy（如影响外部行为）。

## Public API

- 默认最小 surface：`private -> pub(crate) -> pub`。
- Public API 变更必须保持结构化、可版本化并有调用方验证。
- 本骨架只提供最小编译锚点；业务 API 在实现阶段增量添加。

已实现（W4，v9 §22）：

- `pub mod fuse_ws`：Linux FUSE 适配器，消费 portable
  `nexus_platform::ProjectedWorkspace`（fuser 0.18，无 libfuse 链接）。
  `FuseWorkspaceFs`（`Clone` 共享，`commit()`/`head()`）、
  `mount_projected_workspace()`（后台线程挂载，drop 即卸载）。
  语义：写操作 stage 进 WorkingSet，`commit()` 才落盘；inode 号会话内有效；
  `mkdir` 是内存 overlay（不提交）；正确性优先 v1，无 readdir 缓存。
  不拥有 replica selection / path planning / cache policy / commit 语义。
- 场景映射：`scenarios/platform/workspace_fuse_projection.toml` 由
  `crates/nexus-platform-linux/examples/workspace_fuse_e4.rs` 驱动
  （`platform = "linux"`，无 /dev/fuse 时 verdict=SKIP）。

## Verification

最低：

```text
cargo check -p nexus-platform-linux
cargo clippy -p nexus-platform-linux --all-targets -- -D warnings
```

TPROXY UDP 回包（PRODUCT §11.18）的单测需要 `CAP_NET_ADMIN`：无权限时打印
`SKIP <test>` 并返回（非特权 CI 不因此变红，但也不构成覆盖）。作为 Evidence 引用的
运行必须带 `NEXUS_REQUIRE_PRIVILEGED_TESTS=1` 以特权执行，此时无权限即 FAIL：

```text
sudo -E env NEXUS_REQUIRE_PRIVILEGED_TESTS=1 cargo test -p nexus-platform-linux --lib tproxy_udp
```

产品级观察为 E5 `scripts/acceptance/tproxy/run.sh s2`：回包源为 `orig_dst`（IP 与端口）；
router netns 独占持有某个 `orig_dst` 时该回包被丢弃（客户端收不到任何源的回包）并计
`udp_reply_failed`。

如果该模块影响产品行为，还必须映射 Integration/Scenario Evidence。

## Performance Budget

未定义性能预算的路径不得宣称“性能完成”。进入 hot path 后必须在 Contract 中增加 baseline、noise tolerance、warning threshold 与 blocking threshold。

## Observability

稳定结构化字段优先于自由文本；如涉及 Session/Provider/Path/Workspace，应携带对应 correlation id。

## Recovery Semantics

任何持久状态或长期任务都必须定义 crash 后的 reconcile 行为。无持久状态的纯模块应保持可重建。

## Platform Constraints

平台专有代码只允许存在于 `nexus-platform-*` 或 Composition Root。Portable crate 必须通过相应 portability gate。

### N3-12 原子目录无覆盖发布

Linux adapter 提供安全 publish_directory_no_replace(source,destination) -> std::io::Result<()>，封装 renameat2(RENAME_NOREPLACE)。调用方负责源/目标父目录的权限、inode绑定及文件/目录fsync；primitive保证存在目标原子拒绝，EINVAL/ENOSYS不退回覆盖rename。最小unsafe仅OS FFI指针有效期、不保留指针，portable app保持forbid(unsafe_code)，无新增依赖。

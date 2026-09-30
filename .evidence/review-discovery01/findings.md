# 独立 Review 报告 — 发现机制（第 1 轮）

- **Review ID**: `ecd906541620`
- **审查对象**: `origin/feature/discovery` @ `122a888`（`122a8882ac1f77cb09d1b34969282ac810a401ce`）
- **Contract hash**: `f92cb1267cde61077ac494097be6d11d58d69645`（已独立复现一致）
- **Reviewer**: 独立子代理 `28396096`（未参与实现）
- **Verdict**: **APPROVED**（0 FAIL，0 WARN；6 条非阻塞建议）

## 独立验证（全部自己跑，非复述实现者结论）

| 项目 | 结果 |
|---|---|
| `cargo test -p nexus-discovery`（独立 worktree + 独立 target dir） | 80/80 PASS |
| `cargo fmt --check -p nexus-discovery` | clean |
| `cargo clippy -p nexus-discovery --all-targets -- -D warnings` | clean |
| E4 `product.discovery-static`（xc-pc-linux 独立 worktree `/tmp/nexus-discovery-review-e4` @122a888） | PASS（全部字段正确） |
| E4 `product.discovery-mdns`（同上，真机组播互发现） | PASS（a↔b 双向发现，自回环干净） |
| `nexus-harness verify --fast`（独立重跑） | **8/8 PASS**（Evidence `9140141aa079`，source_revision 122a888） |

## 维度结论

### 1. contract-consistency — PASS
- D1–D6 与 MODULE.md 冻结契约逐条核对一致；`Discovery::resolve` trait 方法 vs 冻结 inherent 方法的二义性已在契约中明确调和（inherent 优先、trait 经 UFCS），未"修复式改名"破坏冻结 API。
- 冻结后 Protected 路径零改动：`git diff 3451deb..122a888 -- MODULE.md scenarios/...` 为空。
- Contract hash 独立复现一致；Red Evidence 真实（双场景在旧实现上 FAIL）。
- 既有冻结契约（remote P0 / Presence / LSA P5 / 选路系列）零改动：`lib.rs` +128/−0，`lsa.rs` +41/−0，纯增量。

### 2. edge-coverage — PASS
- `decode_name`：压缩指针有界跳转（8 次）、截断/越界/自指循环均返回 None（有单测）。
- `decode_packet`：`rdlen` 用 `checked_add`，长度前缀解码用 capacity hint（遵循知识条目 lsa-codec-alloc-001）。
- 畸形数据报静默忽略（空包/11 字节/`0xff` 垃圾，有单测）；非法 locator（`bogus://`、无 locator、主机名）诚实跳过（有单测）。
- TTL 过期经 `prune_expired` 清理（有单测）；自回环学习跳过（有单测）。
- 未单测但防御完备的路径：响应包缺 SRV/TXT/A 任一部分 → 不入缓存（`if let (Some, Some)`）。

### 3. api-surface-minimization — PASS
- 新增 pub 项（`Discovery` trait、`DiscoverySource`、`ResolvedAddr`、`DiscoveryMetrics(+Snapshot)`、`MdnsDiscovery`、`LsaDiscovery`、`AggregateDiscovery`、`parse_locator`、三个常量）均为组合根/E4 所需；`lib.rs` 保持 `#![forbid(unsafe_code)]`；纯访问器带 `#[must_use]`。
- `instance_name()` 标明测试/诊断用，合理。

### 4. dependency-boundary — PASS
- `nexus-discovery` 零新增依赖（仅原有 nexus-domain/registry/platform）；零 I/O。
- `socket2` 严格 confined 于 `apps/nexus`（Cargo.toml + mdns example），符合 D-D-1。
- 独立重跑 fast verify 中 `architecture-policy`（40 crates）与 `dependency-governance`（cargo-deny 四项）均为 PASS。
- `Cargo.lock` 纯增量（42 行，无版本变动）。

### 5. error-handling-quality — PASS
- 新库代码（非测试）零 `unwrap`/`expect`/`panic!`（`encode_name` 仅 `debug_assert` 标签长度，且输入为内部构造的有界实例名）。
- `parse_locator` 非法输入返回 None，不 panic。
- 建议（非阻塞）：构造函数用 `DiscoveryError::Transport` 表达"IPv6 不支持/实例名全空"属语义借用——冻结枚举无更合适变体，属务实选择，错误消息本身清晰。

### 6. test-quality — PASS
- 13 个新单测（mdns 8 + aggregate 5）全部验证真实行为：查询/宣告往返、自回环忽略、畸形包、TTL 过期、构造器拒绝、实例名清洗、压缩指针、异服务查询、优先级、去重、miss 计数、分源命中计数、mDNS 源参与聚合。非 happy-path-only。
- E4 example 走生产路径（真实 `StaticDiscovery`/`LsaDiscovery`/`AggregateDiscovery`/`MdnsDiscovery`），无测试替身。
- mdns E4 的 SKIP/FAIL 边界诚实：仅 socket 装配失败与 pump 期 `PermissionDenied`（EPERM）→ SKIP；其余错误与超时 → FAIL；`main` 仅在 FAIL 时 exit(1)。

### 7. complexity-control — PASS
- 手写 DNS 子集（~580 行含测试）经 D-D-1 评审：`mdns-sd` 的 daemon 线程与 AGENTS.md §13 结构化并发冲突，且 Avahi/Bonjour 互操作非需求。仓库已有手写 LSA/窄 netlink/TURN 先例。
- Deletion Test 已在 MODULE.md 中为 trait 与各源分别论证。

### 8. observability — PASS
- `DiscoveryMetrics`（AtomicU64，`&self` 可更新）+ `snapshot()`；分源 hits/miss；Prometheus 命名约定文档化（导出为组合根职责）。
- 计数语义（去重前按源计数）与实现一致；`cached_peer_count` 供诊断。

## 非阻塞建议（6 条，不阻塞进 full verify）

1. MODULE.md D3 写 sanitize 保留 `[a-zA-Z0-9-]`，实现保留 `[a-z0-9_-]`（另多转小写）：行为安全（DNS 大小写不敏感；`_` 在 DNS-SD 实践中合法），属契约文本精度问题，建议下次触碰 MODULE.md 时对齐（Protected 期内不动）。
2. `encode_announce` 中 `tb.len() as u8`：PeerId 超 250 字符时长度前缀截断（畸形但无内存安全问题，解码侧安全忽略；真实 ed25519 PeerId 不可达）。建议改 u16 长度或加 `debug_assert!`。
3. `aggregate.rs` 注释称"变体声明顺序即优先级（…数值序）"：枚举未派生 `Ord`，优先级实际由 `resolve_with_sources` 的数组顺序保证。建议澄清注释，避免后人误以为判别值有序。
4. 构造函数错误复用 `DiscoveryError::Transport`（见维度 5）：可接受，建议在 MODULE.md 错误语义处一句话说明复用理由。
5. mdns example 用 `unsafe { UdpSocket::from_raw_fd(...) }`：sound 且有所有权注释，但 `socket2::Socket` 原生支持 `send_to`/`recv_from`，转换 dance 可删（example-only）。
6. mdns example 中 query 响应发送用 `let _ =` 吞错：verdict 仍要求真实双向发现故无法掩盖为 PASS，但建议 propagate 以便诊断。

## 风险与诚实边界（实现者已声明，复核成立）

- `MdnsDiscovery::resolve` 返回缓存快照，过期清理是组合根义务（`prune_expired`），MODULE.md D3 已明说。
- mDNS 无认证（DESIGN §8.1 会话层负责）；跨子网不工作；实例名冲突解决超出范围。
- `LsaDiscovery` 只读 `Lsa.locator`（P5 冻结字段），无线协议扩展，无第二期。

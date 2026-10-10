---
id: 2026-10-03-n2-p02-registry-discovery
date: 2026-10-03
module: nexus-registry
category: implementation-pattern
task_type: feature
---

# N2 P0-2：Provider 广告类型与控制面帧协议的三个选址/格式决定

## 决定 1：5 种控制帧的编解码归 nexus-registry（不是 transport/auth/新 crate）

`RESOURCE_ANNOUNCE / RESOURCE_QUERY / AUTH_GRANT / AUTH_REVOKE / LEASE_RENEW`
同时引用 `ProviderAdvertisement`（registry）和 grant 字段（auth 形状）。
`policies/architecture.toml` 是 deny-by-default（`unlisted_internal_dependencies = "deny"`）：
- `nexus-transport` 只允许 `[nexus-delivery, nexus-platform]`——放过去要改 policy；
- `nexus-auth` 只允许 `[nexus-domain]`——看不到 `ProviderAdvertisement`；
- 唯一无需改 policy 的归属是 `nexus-registry`（已有 `nexus-domain`，广告类型也在此）。

`AUTH_GRANT` 的主体/操作字段用 wire DTO（`UsageGrant{principal: String, ...}`）
镜像 `nexus-auth::Grant`，不直接引用 auth 类型——wire 格式独立版本化，
且避免 registry→auth 依赖边。Deletion Test 通过：帧协议没有独立于
"Registry 的 wire 面孔"的变化维度。

## 决定 2：同一认证路径 = 类型层面"不存在未认证的控制通道"

`ControlChannel::established(transport, AuthenticatedPeer)` 构造即要求
`AuthenticatedPeer`；认证本身发生在构造之前、调用方的既有门控里
（remote P0：`nexus_auth::verify_token`；N2：D6 ed25519 身份）。
`AuthenticatedPeer::new` 只是 newtype 包装——真正的约束是
"本模块不提供任何匿名构造路径"，而不是在 registry 里重做一次认证
（那才是第二套认证路径）。P0-4 组合根负责把门控结果传进来。

## 决定 3：帧格式照抄两处既有约定，不发明第三种

- 首字节显式 `u8` 类型标签（0x21–0x25，避开 discovery 的 0x01–0x0E 段）
  ——NAT wireup T3 教训：不靠首字节内容猜类型；
- 字段编码照抄 `nexus-discovery` 的 `put_str/get_str` 风格：
  字符串 = u16 BE + UTF-8，u64 = BE 8 字节，集合 = u16 BE 计数，
  Option = u8 标志；解码统一拒绝空帧/未知标签/截断/非法 UTF-8/
  非法名字/未知判别值/尾部多余字节。

## 可复用要点

- `UnavailabilityReason::as_str()` 拼写（`ProviderOffline`/`HealthDegraded`/
  `NotAcceptingWork`）与 `scenarios/product/n2-provider-offline.toml`
  冻结期望逐字一致——P0-5 直接复用，不要另起字符串。
- Portable Core 时间：`now_secs: u64` 由调用方传入，模块内不取系统时钟；
  `ttl_secs = 0` 约定为永不过期（静态配置用），`saturating_add` 防溢出。
- worktree 的 `.githooks` 会掉可执行位（bare repo 建 worktree 的已知坑）：
  提交前 `chmod +x .githooks/{pre-commit,commit-msg,pre-push,hook-common.sh}`，
  否则门禁静默不跑。
- 真机同步：`rsync --exclude ".git"`（无斜杠——worktree 的 `.git` 是指针文件，
  带斜杠的 `--exclude ".git/"` 拦不住它）+ `--exclude "target/"`；
  真机 `git init` + sync commit 后 `nexus-harness verify --fast`；
  `CARGO_TARGET_DIR=<worktree>/target` 隔离多轨道。

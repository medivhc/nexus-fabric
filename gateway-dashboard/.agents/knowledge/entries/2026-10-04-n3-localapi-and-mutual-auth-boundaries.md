---
id: n3-localapi-mutual-auth-boundaries
date: 2026-10-04
module: apps/nexus / apps/nexusd / nexus-fabric
category: implementation-pitfall
task_type: feature
---

# LocalAPI 凭据与双向 TLS 的真实边界

N3 LocalAPI 先验证有限 header 和 bearer，再读取 DTO；每次操作使用持久接受合同的
principal、workspace、provider、resource，重新读取真实当前 Use grant。Workspace 选择
不授予权限；audit 写入失败必须拒绝。冷启动只打开原 authority，不能初始化空存储掩盖丢失。

已有 v0 凭据 loader 的普通 read 会在 FIFO 上阻塞，token 换行也能污染 HTTP header。
N3 客户端连接本地 daemon 后，只读取已存在的 private regular token，使用 nonblocking /
nofollow 和 fd 类型复查、4096 字节上限、无空白控制的 ASCII。真实 FIFO 红灯以子进程
截止时间及 kill/reap 保留；拒绝用 wire 零字节证明没有发送凭据。服务端要逐请求复核
固定 token inode、权限及内容，不能只相信创建时的 0600。

TLS 身份必须取自实际 RFC5280 SubjectPublicKeyInfo，不能搜索任意 DER OID / 32 字节，
否则扩展区嵌入 allowlisted key 会脱离 CertificateVerify 的实际签名身份。Secure server
要求 client CertificateVerify 和 allowlist，客户端固定 server key 并等待 HANDSHAKE_DONE；
客户端 Connected 事件可能早于服务器完成客户端证书验证。双方完成前禁止 accepted、
stream 与 datagram 发布。Legacy 身份占位或 server pin 不能代表 mutual authentication。

新 E4 证明真实本地 HTTP 边界和两个独立进程的 mTLS；并不证明远程 Task RPC、容量预留、
Snapshot 上传、Submit 执行或 CLI 完整下载。局部通过不能替代原 22 个 N3 完整场景。
证据目录 `.evidence/n3-6/`，冻结契约 `docs/N3-6-LOCALAPI-SECURITY-CONTRACT.md`。

## 提前拒绝与 TCP reset

首次 Fast 暴露 daemon 拒绝后直接 drop TCP 的间歇失败：未读取的请求体可能使
TCP close 发送 RST，客户端拿不到完整错误 envelope。不能为修复而读取未认证 Body
或等待剩余 Body。响应合并为有总写入预算的 frame，写完后 shutdown(Write) 发 FIN。
真实进程回归发送有未完成 body 的错 token 请求，20 次完整 401 + EOF 且不等待
advertised 1MiB；旧断言完整保留，原 Fast FAIL 与独立 socket 探测均保留。

## 查询服务不能使用可初始化的存储 open

独立 R1 真实冷启动负例保留 task-api.toml / N2 identity，将整个 tasks root
移走后发现通用 FileTaskAcceptanceStore::open 创建空 authority。此前仅删除账本文件
而保留 receipt 的回归覆盖不够。查询/取消装配使用 crate-private open_existing：
不创建 root/lock/receipt/接受或 runtime image，不迁移未知 authority；完整缺失和
空目录替换均返回 StateCorrupt。原用于显式接受/初始化的 public open 行为保留。
测试夹具先通过原 Snapshot/TaskOwner 持久适配明确 provision 和接受，再启动服务；
不能让 service.open 充当隐含 test seed。真实冷启动负例同时核实缺失保持缺失、
空替换仍空以及归还原目录后完整 Task view 和接受字节恢复。

## 测试辅助文件与 Harness 目标发现

首轮 Full 的 workspace-tests 通过，但 integration 把 tests 下辅助目录的 mod.rs
识别为独立 Cargo 测试目标，运行 --test mod 后失败。辅助文件移到 test_support，
两个真实进程测试及 E4 用显式 path 共享；原断言保持完整。保留首轮 Full 原证据，
位置修正后重新 Fast、独立 Review 和 Full，不能把局部测试通过改写成 Full 通过。

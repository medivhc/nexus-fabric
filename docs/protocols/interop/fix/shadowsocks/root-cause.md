# Shadowsocks 线格式不兼容 — 根因报告（S27）

- 协议/格：Shadowsocks Default；Handshake/TcpSmall/TcpThroughput/LongLived/Reconnect 失败，F1/F2 PASS
- 证据：`evidence/shadowsocks/default/handshake/PIV-shadowsocks-default-handshake-20261024T173553Z-001/`
- 参照：sing-box 1.13.16（method chacha20-ietf-poly1305）

## 现象
产品 SOCKS5 → SS 出站连到 sing-box，发送自研 record 帧后目标端无回显；H 等到 60s 超时，
T1/T2/L/R 快速失败（连接被关闭）。产品 JSON 显示 `routing.outbound_kind=shadowsocks`（路由正确）。

## 根因
`crates/nexus-outbound-shadowsocks/src/lib.rs` 的 `SsStream` 不是 SIP004 AEAD：
- 密钥派生：HKDF-SHA256，info 固定 `"ss-c2s"/"ss-s2c"`，无 per-session salt；
- 帧格式：`nonce(12B) || ciphertext+tag`，外层 `u32 BE length`（`:279-380`）。
标准 shadowsocks AEAD（chacha20-ietf-poly1305）要求：32B salt + HKDF-SHA1 派生 subkey、
LE 计数器 nonce、`u16 BE 长度 + tag` 分块。两者线格式完全不同，参照端无法解密。
自洽单测（同 crate encrypt/decrypt 往返）掩盖了互操作缺口。

标准 AEAD 的密钥派生是两步（SIP004）：
1. 口令 → master key：`EVP_BytesToKey`（摘要 MD5，无 salt、1 次迭代），得到 32B key；
2. master key + 每个会话随机 32B salt：以 salt 为 IKM、master key 为 PRK 走 **HKDF-SHA1**，
   info 固定为 `"ss-subkey"`，派生会话 subkey，再用于 AEAD 加密。
因此实现同时依赖 **SHA-1**（HKDF）与 **MD5**（EVP_BytesToKey）；两者已在 workspace
依赖图中（`nexus-turn`、`nexus-outbound-anytls`、`nexus-web-gateway` 使用），SS crate
只需新增直接依赖声明，无需引入新的第三方版本。

## 影响面
- 所有 SS 产品路径（TCP）。负向格 F1/F2 仍能 PASS（认证/配置拒绝在服务端关闭连接）。
- crate 其它使用方（loopback 测试）依赖自洽格式，改动会波及。

## 修复方案（路径 B：新增标准 AEAD 能力）
实现 SIP004：salt 生成/读取、`EVP_BytesToKey`（MD5）口令 → master key、HKDF-SHA1
（info=`"ss-subkey"`）→ 会话 subkey、LE nonce、标准分块 framing；保留旧格式仅用于
既有 loopback 测试或迁移测试。依赖 SHA-1 与 MD5（复用 workspace 已有版本，SS crate
新增直接依赖声明）+ 会话状态机。

## 量化估算
- 代码：~250–350 行（含 SHA-1/HKDF 适配与测试），1.5–2 人日；若引入新依赖需 dependency review。
- 与“不得改产品配置面”不冲突，但属于协议实现新增，**超出本 run 局部修复范围**。
- 结论：升级 coordinator；本 run 按证据判 Shadowsocks BROKEN（H FAIL，Nexus 族）。

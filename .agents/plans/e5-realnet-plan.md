# E5 真实网络验收测试计划

> 任务类型：test（产品级验收；不写新产品代码，只写测试/场景）
> 状态：计划（待执行）
> 日期：2026-10-01
> 基线：master `f89b697`；N1 M1-M7（E4 在 netns 模拟环境 5/5 PASS）

---

## 1. 目标

验证用户关键验收场景（2026-09-29）：**手机与电脑组网后，即使手机关闭 WiFi（底层地址切换），文件传输也不中断**。

本次 **Android 暂时不做**，用真实网络环境模拟地址切换，达到 E5（独立外部观察）的前置条件。

与 E4 的区别：

| 维度 | E4（已完成） | E5（本次） |
|------|-------------|-----------|
| 网络环境 | netns + veth（虚拟） | 真实网卡 + 真实 IP + 真实内核路由 |
| 地址切换 | netns 内 `ip addr del/add` | 真实接口上次 IP `del/add` |
| 节点 | 同一机器双 netns | 同一机器双真实接口 |
| 传输 | 2MB | 10MB |

---

## 2. 拓扑

```
xc-pc-linux（真机）
┌─────────────────────────────────────────────────┐
│ Node A（"电脑"，静态）                           │
│   underlay: 172.168.12.97 (enp5s0, 有线)        │
│   VPI: 10.144.0.1/24                            │
│   TUN: tun_n1a                                  │
│                                                 │
│ Node B（"手机模拟"，漫游端）                      │
│   underlay 起始: 172.168.9.99 (wlp6s0 次 IP, WiFi)│
│   underlay 漫游后: 172.168.12.98 (enp5s0 次 IP)  │
│   VPI: 10.144.0.2/24                            │
│   TUN: tun_n1b                                  │
│                                                 │
│ 真实路径：B(172.168.9.99) → A(172.168.12.97)     │
│   经内核真实路由，源 IP 保留（已验证）            │
└─────────────────────────────────────────────────┘
```

**为什么双接口单机器算"真实网络"**：
- 使用真实物理网卡（enp5s0 有线网卡、wlp6s0 WiFi 网卡），非 veth/loopback
- 使用真实 IP 地址（非 netns 隔离）
- 数据包走真实内核路由、真实 ARP，非内存拷贝
- 地址切换是真实的 `ip addr del/add`，旧地址真实不可达

**源 IP 选择说明**（2026-10-01 实测）：
- B 起始绑定 `172.168.9.99`（wlp6s0 次 IP），A 看到的源为 `172.168.9.99:port1`
- B 删 IP 后 `rebind()` 用 wildcard（`0.0.0.0:0`，产品代码行为，不可改）
- 内核对本地目标（172.168.12.97）选源时可能选 `172.168.12.97`（目标自身）
- 但端口必变（随机），4-tuple（源 IP:port）一定变化，QUIC 被动迁移仍被触发
- 迁移机制与 E4 相同（E4 是 IP+port 变，本次是 port 必变、IP 可能变）

**为什么不用 VPS**：引入公网延迟变量，且 EasyTier TUN 会叠加一层封装，不如双接口干净。

---

## 3. 漫游模拟（"手机关 WiFi"）

| 步骤 | 操作 | 说明 |
|------|------|------|
| 1 | B 绑定 `172.168.9.99`（wlp6s0 次 IP，需预先 `sudo ip addr add`） | 模拟"手机连 WiFi" |
| 2 | A→B 经 VPI TCP 传 10MB 确定性文件 | 传输中 |
| 3 | 传 ~50% 时：`sudo ip addr del 172.168.9.99/23 dev wlp6s0` | **模拟"手机关闭 WiFi"**：旧 IP 真实消失 |
| 4 | B 主动 `conn.rebind()` 到 `172.168.12.98`（enp5s0 次 IP） | 模拟"切到蜂窝" + OS 网络变更通知 |
| 5 | B 从新地址发迁移触发包（keepalive burst） | 驱动 A 的 QUIC 被动迁移 |
| 6 | A 检测到新源地址，被动迁移 | 连接不中断 |
| 7 | 传输完成 | 校验 |

**安全**：只操作次 IP（`172.168.9.99`、`172.168.12.98`），不碰主 IP（`172.168.9.32`、`172.168.12.97`），不 down 网卡，不影响 SSH（走 EasyTier tun0）。

---

## 4. 断言（冻结期望）

与 E4 同标准（`product.n1-connectivity-roam` 的放宽版）：

| 字段 | 期望 | 说明 |
|------|------|------|
| `verdict` | `PASS` | 总 verdict |
| `transfer.hash_match` | `true` | 10MB 文件哈希一致（FNV-1a，不重不漏） |
| `connection.id_unchanged` | `true` | CID 不变（连接与地址解耦，M4） |
| `link.rebind_occurred` | `true` | 确实发生过 rebind（反空转） |
| `transfer.stalled_within_budget` | `true` | stall < 30s（E4 同门限） |

**成功标准**：
- 哈希必须匹配（数据完整性底线）
- CID 必须不变（M4 核心不变量）
- 必须真实发生 rebind（否则测试无意义）
- stall 上限 30s（与 E4 一致；真实网络 RTT 更小，预期远低于此）

---

## 5. 关键决策

### D1：用哪两个真实节点？
**决策**：xc-pc-linux 双真实接口（enp5s0 + wlp6s0），Node A 在有线、Node B 在 WiFi。
**理由**：真实网卡 + 真实 IP + 真实路由；无需第二台物理机；VPS 会引入公网变量。

### D2：如何触发真实的地址切换？
**决策**：次 IP 的 `ip addr del`（删 WiFi 次 IP）+ 应用层主动 `rebind()` 到有线次 IP。
**理由**：
- `ip addr del` 是真实的地址失效（旧地址不可达），不是模拟
- 主动 rebind 模拟 OS 网络变更通知（Android 的 `onAvailable()` 回调等价物）
- 不 down 网卡、不碰主 IP，安全

### D3：传输方向和大小？
**决策**：A→B 传 10MB（E4 的 5 倍）。
**理由**：更大文件 → 更长传输窗口 → 更高的漫游中途命中率；10MB 在百兆内网 < 10s，不拖慢测试。

### D4：实现方式？
**决策**：新建 example `n1_roam_realnet.rs`，复用 `n1_roam.rs` 的 N1 装配逻辑，去掉 netns 部分，改用真实接口 + 次 IP。
**理由**：
- test 类型：只写测试代码，不改产品代码
- 复用已验证的 N1 装配路径（production path）
- 场景文件：`scenarios/product/n1_connectivity_roam_realnet.toml`

---

## 6. 风险与缓解

| 风险 | 缓解 |
|------|------|
| 次 IP 残留（测试异常退出） | 前置清理：`ip addr del` 幂等；example 启动时先清残留 |
| TUN 设备残留 | 同上；`ip link del` 幂等清理 |
| WiFi 实际断开影响测试 | 只删次 IP，不 down 网卡；主 IP 保持 |
| 防火墙拦截 | 同一机器，INPUT 链默认 ACCEPT（已验证 UDP 可达） |
| 沙盒 UDP EPERM | 测试在 xc-pc-linux 真机跑，不在沙盒跑 |

---

## 7. 执行步骤

1. 新建 `crates/nexus-network/examples/n1_roam_realnet.rs`（基于 `n1_roam.rs`，去 netns）
2. 新建 `scenarios/product/n1_connectivity_roam_realnet.toml`
3. 真机编译：`cargo build -p nexus-network --example n1_roam_realnet`
4. 预检：次 IP 加/删、TUN 创建（`~/tun-cap.sh`）
5. 执行：`cargo run -p nexus-network --example n1_roam_realnet -- --json`
6. 记录：verdict、hash_match、id_unchanged、rebind_occurred、stalled_ms
7. 失败时按 AGENTS.md §24 诊断（先定位，不随机改）
8. 提交（不 push）

---

## 8. 诚实边界

- **不宣称 Final PASS**：Candidate Completion 需 Harness 判定
- **环境限制如实记录**：如遇真机特有问题（权限、路由），记录为环境限制
- **不修改产品代码**：test 类型红线
- **不碰 N1 冻结合同**：沿用 M1-M7 语义

# netns 特权诊断方法（匿名 netns）

**场景**：E4 example 用 `unshare(CLONE_NEWNET)` 创建匿名 netns（无名），`ip netns exec <name>` 直接用不了，
`nsenter` 无密码不可用。

**方法**：`ip netns attach` 把已存在进程的 netns 绑定为命名 netns。

```bash
# 1. 找到子进程 PID（E4 子进程带 --child= 参数）
pgrep -af 'n1_roam --child='

# 2. attach（appen 有 NOPASSWD sudo for /usr/bin/ip）
sudo -n ip netns attach n1a <PID_A>
sudo -n ip netns attach n1b <PID_B>

# 3. 在 netns 内执行诊断
sudo -n ip netns exec n1a ss -tin          # TCP 状态：cwnd/rto/rtt/retrans
sudo -n ip netns exec n1a cat /proc/net/tcp
sudo -n ip netns exec n1a ip route
sudo -n ip netns exec n1a ip neigh
sudo -n ip netns exec n1a ip -s link show <if>  # 接口计数器
sudo -n ip netns exec n1b tcpdump -i <tun> -c 20 tcp  # 抓包（需等流量）

# 4. 看进程线程（确认 pump 线程存活）
for t in /proc/<PID>/task/*; do cat $t/comm; done
# 关键线程名：n1-pump-up（上行）, n1-pump-dn-<peer>（下行）, n1-pump-sup,
#            n1-link-*, n1-kaping-*, n1-karesp-*, nexus-fabric-dr

# 5. 用完清理
sudo -n ip netns del n1a
sudo -n ip netns del n1b
```

**注意**：
- E4 父进程超时退出后子进程会成为孤儿，但只要还在跑就能 attach。
- `ip netns attach` 要求目标进程的 netns 与当前不同（匿名即可）。
- TUN 接口计数器方向：TUN 的 RX = userspace→kernel（下行），TX = kernel→userspace（上行）。
  验证：B（接收端）TUN RX=1.76MB 数据，TX=64KB ACK。
- veth 计数器可验证 underlay UDP 是否流通（QUIC 存活）。

**实战发现（2026-10-01 N1 E4）**：用此方法发现 A 端 `n1-pump-up` 线程消失、B 端
`n1-pump-dn-*` 线程消失——这是用户态 instrumentation 15 轮都看不到的（线程死亡无日志）。

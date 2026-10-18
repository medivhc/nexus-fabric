# sandbox-env-guard — 沙箱环境守卫方案（mise 驱动）

让 **agent 每次进入沙箱/项目时自动探测环境能力**，输出**结构化 JSON 能力矩阵**；
**harness 依据该矩阵筛选本次应运行 / 应跳过的测试**，使「环境不支持的测试」不再空跑、不污染证据。

设计对齐 `nexus-fabric/AGENTS.md`：仓库即 API、机器约束、独立验证、持久化证据——
环境能力是 Evidence 的绑定维度之一（对应 `harness.toml` 的 `bind_platform_capabilities = true`）。

---

## 1. 架构

```text
agent 进入沙箱
      │  (mise shell hook 启用 + mise trust)
      ▼
┌──────────────────┐   写入 .env-report/env-report.json
│ mise task         │ ──────────────────────────────────────┐
│  check-env        │                                        │
│  (env-check.py)   │                                        ▼
└──────────────────┘                         能力矩阵 (结构化 JSON)
      │                                                  │
      │  mise task test-plan                            │ 读取
      ▼                                                  ▼
┌──────────────────┐   写入 .env-report/test-plan.json  harness
│ harness-select    │ ───────────────────────────────►  (nexus-harness /
│  .py              │   {selected:[...], skipped:[...]}   CI / 自定义)
└──────────────────┘                                      │
                                                          ▼
                                              只运行 selected；
                                              skipped 记 SKIPPED/UNSUPPORTED
                                              （不计入 FAIL，不污染 Evidence）
```

---

## 2. 文件清单

| 文件 | 作用 |
|------|------|
| `mise.toml` | 工具版本声明 + `check-env`/`test-plan`/`guard` 任务 + `enter` hook |
| `scripts/env-check` | 能力探测（host/toolchain/libs/capabilities）→ 结构化 JSON |
| `scripts/env-report.schema.json` | env-report 的 JSON Schema（harness 可校验） |
| `scripts/harness-select` | 读能力矩阵 + 映射表，输出应运行/应跳过测试清单 |
| `scripts/guard-plan` | `harness-select` 的退出码显式包装（供 mise/CI 调用，退出码严格透传） |
| `scripts/run_tests.py` | 守卫自回归套件（门控矩阵 + 错误路径 + env-check 组件 + 接口契约） |
| `scripts/git-push-via-ssh443` | 沙箱内推送（一次性 SSH key 经 api 注册 → 走 443 → 自动清理） |
| `test-capability-map.toml` | **测试 → 所需 capability** 映射（维护入口，无需改代码） |
| `samples/scenarios/*.toml` | 演示用 scenario（id 命中不同映射分支） |
| `.env-report/env-report.json` | 探测产物（运行后生成） |
| `.env-report/test-plan.json` | 筛选产物（运行后生成，harness 读取） |

### 2.1 CLI 与退出码契约（接口契约，供 harness / CI 判定）

| 命令 | 退出码 | 含义 |
|------|--------|------|
| `env-check` | `0` | 正常：已探测并写出 `env-report.json` |
| `env-check` | `1` | 无法写出报告（目录不可写 / IO 错误）→ 环境状态未知，**不得继续** |
| `env-check` | `2` | 未使用（保留 BLOCKED 语义，与 harness-select 对齐） |
| `harness-select` | `0` | 正常：已产出 test-plan（`mode=scenarios` 或 `demo`） |
| `harness-select` | `1` | 参数 / IO 错误：map 或 env-report 缺失、不可解析 |
| `harness-select` | `2` | **BLOCKED**：`--scenarios-dir` 下无 scenario toml → 拒绝产出 test-plan（绝不降级为「用 map pattern 冒充测试 id」） |
| `run_tests.py` | `0` / `1` | 全绿 / 有用例失败 |

两个脚本均支持 `--version` 与 `--help`：

```bash
python scripts/env-check --version        # env-check 1.0 (schema 1)
python scripts/harness-select --version   # harness-select 1.0 (schema 1)
python scripts/env-check --help           # 含退出码说明
python scripts/env-check --out-dir DIR    # 显式输出目录（优先于环境变量 ENV_REPORT_DIR）
```

> `--version` 输出**工具版本**与**产物 schema 版本**两个值。二者分离：工具迭代不一定改
> schema，下游应校验 `schema_version` 而非工具版本。

---

## 3. 安装与启用 mise（国内源 + GitHub 代理预编译二进制）

**原则：尽量不源码安装。** 本沙箱直连 GitHub 超时（crates.io 同理），故 mise 一律从
**GitHub 加速代理**拉**预编译二进制**安装，而不是 `cargo install mise`（源码编译动辄 15+
分钟，且新版传递依赖 `aws-smithy-*` 要求 rustc ≥ 1.94，坑多）。

### 3.1 GitHub 代理基准（v2026-10-14 实测）

对 mise `v2026.10.10` 的 `linux-x64` 资产做范围下载（8MiB）测速，结果：

| 代理 | HTTP | 耗时 | 吞吐 | 结论 |
|------|------|------|------|------|
| **https://v6.gh-proxy.org** | 206 | 3.2s | **~2.6 MB/s** | ✅ **最快，默认采用** |
| https://ghfast.top | 206 | 10.3s | ~0.8 MB/s | 可用，备选 |
| https://edgeone.gh-proxy.org | 206 | 11.0s | ~0.8 MB/s | 可用，备选 |
| https://hk.gh-proxy.org | 206 | 50s+ | ~16 KB/s | ❌ 几乎不可用 |
| https://cdn.gh-proxy.org | 206 | 50s+ | ~13 KB/s | ❌ 几乎不可用 |

> 基准脚本（可复跑）：对 `https://<proxy>/https://github.com/jdx/mise/releases/download/v2026.10.10/mise-v2026.10.10-linux-x64.tar.gz`
> 发 `-r 0-8388607` 范围请求，取 `%{time_total}`/`%{speed_download}`。
> 切换代理只需改 `GITHUB_PROXY` 环境变量或 `scripts/env-check` 里的 `DEFAULT_GITHUB_PROXY`。

### 3.2 预编译安装 mise（一条命令，无源码编译）

```bash
VER="v2026.10.10"
PROXY="https://v6.gh-proxy.org"          # 基准最快节点
ASSET="mise-${VER}-linux-x64.tar.gz"
curl -sSL --connect-timeout 8 --max-time 120 \
  -o /tmp/mise.tgz \
  "${PROXY}/https://github.com/jdx/mise/releases/download/${VER}/${ASSET}"
mkdir -p /tmp/mise-extract && tar -xzf /tmp/mise.tgz -C /tmp/mise-extract
install -m 0755 "$(find /tmp/mise-extract -type f -name mise | head -1)" /root/.local/bin/mise
hash -r; mise --version                   # 应显示 2026.10.10 linux-x64
```

若 `v6` 节点抖动，把 `PROXY` 换成 `ghfast.top` 或 `edgeone.gh-proxy.org` 即可（见 3.1）。

- cargo/crates.io → `rsproxy.cn`（已写入 `~/.cargo/config.toml`）
- rustup → `rsproxy.cn`（已写入 `~/.zshrc`/`~/.bashrc` 的 `RUSTUP_DIST_SERVER`）
- apt → 腾讯云镜像（系统已默认）
- git clone GitHub 仓库 → 同样可加代理前缀：`git clone ${PROXY}/https://github.com/<owner>/<repo>.git`

启用自动 hook（**「每次进入沙箱自动检查」的关键**）：

```bash
# 1) 在 shell rc 启用 mise shell hook（zsh / bash）
echo 'eval "$(mise activate zsh)"' >> ~/.zshrc
echo 'eval "$(mise activate bash)"' >> ~/.bashrc

# 2) 信任本项目（mise 安全模型：未信任项目不执行 hook/task）
cd engineering/sandbox-env-guard
mise trust

# 3) 验证：进入目录即自动触发 check-env（或直接手动运行）
mise run check-env
mise run guard        # check-env + test-plan 一步到位
```

> 若不想依赖 mise 自动 hook，agent 也可在每次会话开始显式执行
> `mise run guard`（或 `python3 scripts/env-check && python3 scripts/harness-select ...`），
> 效果等价。

---

## 4. 结构化输出格式

**env-report.json（能力矩阵，节选）：**

```json
{
  "schema_version": "1",
  "generator": "sandbox-env-guard",
  "checked_at": "2026-10-14T11:31:06+00:00",
  "host": { "os": "linux", "arch": "x86_64", "distro": "Ubuntu 24.04.3 LTS" },
  "toolchain": { "rust": "1.93.0", "cargo": "1.93.0", "rustup": "1.28.2", "cargo_mirror": "rsproxy.cn" },
  "libraries": { "libssl_dev": "3.0.13", "clang": "18.1.3", "cmake": "3.28.3", "pkg_config": "1.8.1" },
  "capabilities": {
    "linux_executor":     { "status": "ok" },
    "windows_executor":   { "status": "unsupported", "reason": "host OS is not windows" },
    "openssh_e2e":        { "status": "missing", "need": "openssh-server" },
    "tun_net_admin":      { "status": "degraded", "reason": "no /dev/net/tun in sandbox" },
    "github_proxy":       { "status": "ok", "endpoint": "https://v6.gh-proxy.org",
                            "http": "200", "latency_ms": 1566,
                            "note": "GitHub 经代理可达（快）" },
    "internet_egress":    { "status": "ok", "loopback_udp": true, "external_udp": true,
                            "udp_responders": ["8.8.8.8", "223.5.5.5"],
                            "external_tcp": true,
                            "udp_probe": "8.8.8.8,223.5.5.5:53",
                            "note": "出网 UDP/TCP 均可达，真远端类场景可运行" }
  },
  "unsupported_capabilities": ["windows_executor", "macos_executor", "ios_executor", "android_cross", "confidential_transport"],
  "missing_capabilities": ["openssh_e2e"],
  "degraded_capabilities": ["tun_net_admin"]
}
```

`github_proxy` 能力：探测能否经 `GITHUB_PROXY`（默认 `v6.gh-proxy.org`）访问 GitHub。
`ok` 才能跑依赖拉取外部制品/仓库的测试；`missing`（代理与直连均不可达）→ 该类测试 skip；
`degraded`（可达但 > 15s）仍可用但建议对拉取操作限时。状态由 `scripts/env-check` 的
`probe_github_proxy()` 产出，可被 `test-capability-map.toml` 的
`[tests."product.fetch-external-*"] requires = ["github_proxy"]` 引用。

### 4.1 两个关键能力的设计差异（决定是否该门控）

| 能力 | 场景契约 | 环境不具备时 | **是否用能力门控 skip** |
|------|---------|------------|----------------------|
| `tun_net_admin` | `one_of = ["PASS","SKIP"]` / 断言 `TUN_ERROR` | 代码**自带结构化降级** → 场景仍 **PASS**（验证"不静默降级 mock"的契约） | ❌ **不门控**（跳过反而丢掉应跑的真实覆盖） |
| `internet_egress` | `equals = "PASS"`（严格） | 代码**硬 FAIL**（SKIP 不被契约接受） | ✅ **门控**（否则把"环境限制"误记成"代码失败"） |

判断准则：**先读场景契约的期望值**——接受 `SKIP`/降级值的不要门控；写死 `PASS` 的才门控。

`internet_egress` 探测细节（见 `probe_internet_egress()`）：
- 回环 UDP（bind + 互发）+ 出网 UDP（**向多个公共 DNS 发合法 DNS 查询**）+ 出网 TCP（参考主机）。
- ⚠️ **必须发合法 DNS 查询**：裸发一字节到 53 端口无人回应，会**误判为"出网 UDP 被封"**
  （2026-10-14 实测踩坑）。真实网络常"选择性可达"（本沙箱 8.8.8.8/223.5.5.5 通、1.1.1.1 不通），
  故探测多个端点并记录 `udp_responders`。
- 状态：`ok`（出网 UDP+TCP 均可达）/ `degraded`（仅回环或 TCP 可达 → 真远端类应 skip）/
  `missing`（连回环都不可用）。
- 端点可用环境变量覆盖：`EGRESS_UDP_HOSTS`（逗号分隔）、`EGRESS_UDP_PORT`、
  `EGRESS_TCP_HOST`、`EGRESS_TCP_PORT`。

**test-plan.json（harness 消费）：**

```json
{
  "selected": ["product.n3-10-operator-grant"],
  "skipped": [
    { "id": "product.windows_linux_e5", "required": ["windows_executor"],
      "blocked_by": { "capability": "windows_executor", "status": "unsupported" } },
    { "id": "product.web-gateway-ssh", "required": ["openssh_e2e"],
      "blocked_by": { "capability": "openssh_e2e", "status": "missing" } }
  ],
  "summary": { "total": 3, "runnable": 1, "skipped": 2 }
}
```

`capability.status` 语义：`ok` 可运行；`unsupported`/`missing`/`degraded`/`unknown` → 该测试 skip。

---

## 5. 接入 nexus-fabric 的 harness（两条路径）

`nexus-fabric` 的 `harness.toml` 已声明 `bind_platform_capabilities = true`、
`[commands].verify_* = "nexus-harness verify ..."`，且 scenario 为 TOML。
本方案低侵入接入，**不改动受保护的 `scenarios/` 契约**：

### 路径 A（推荐，零改仓库）：外部筛选器
把本方案放到仓库根或侧旁目录，harness 跑验证前先生成 test-plan，只验证 `selected`：

```bash
# 在 nexus-fabric 仓库内
python3 engineering/sandbox-env-guard/scripts/env-check \
        --ENV_REPORT_DIR=.env-report            # 写 .env-report/env-report.json
python3 engineering/sandbox-env-guard/scripts/harness-select \
        --env-report .env-report/env-report.json \
        --map engineering/sandbox-env-guard/test-capability-map.toml \
        --scenarios-dir scenarios/product \
        --out .env-report/test-plan.json
# 依据 test-plan.json 的 selected 逐条：
for id in $(jq -r '.selected[]' .env-report/test-plan.json); do
  nexus-harness verify --scenario "$id" --json
done
# skipped 项不计入失败；可汇总为 SKIPPED verdict 写入 .evidence
```

### 路径 B（语义更紧，需小改 harness）：scenario 声明 requires
在 scenario TOML 增加可选字段（受保护路径需带 `contract:` 哈希，按 AGENTS.md 流程）：

```toml
[environment]
requires_capabilities = ["linux_executor", "tun_net_admin"]
```

`nexus-harness` 在 `verify` 时读取 `.env-report/env-report.json`，对 `requires`
中任一 capability `status != ok` 的场景，直接产出 `SKIPPED`（新增 verdict 或
复用 `UNKNOWN`/`BLOCKED` 但语义标注 skip），并在 Evidence 中持久化该绑定维度。

---

## 6. 维护约定
- **新增能力**：在 `scripts/env-check` 的 `caps` 字典加一项（键名即契约）。
- **新增测试类别**：在 `test-capability-map.toml` 加一条 fnmatch 模式 + `requires`。
- **新增被跳过的理由**：harness 自动据 `capabilities[].status` 归类，无需额外代码。
- capability 名称是 env-check 与 map 之间的唯一契约，改名需同步两处。

## 7. 故障与扩展
- 探测失败的项保守记 `unknown` → 对应测试 skip（fail-safe）。
- 想让某能力「缺失也可跑但降级」，harness-select 可把 `degraded` 视为 ok（改判定分支）。
- 多 agent 并行时，各自写入 `.env-report/env-report.json` 并用 `NEXUS_AGENT` 命名空间
  隔离（对齐 AGENTS.md §29.2 证据命名空间）。

---

## 8. 跨平台：Windows 没有 bash 怎么办

**结论：不需要 bash。** 本方案的核心逻辑是**纯 Python**（`env-check` / `harness-select`
均为 Python，`harness-select` 零 Unix 依赖），命令里不含 `&&`、管道、重定向等 bash 语法，
因此 Windows 原生 `cmd` / PowerShell 均可运行。

### 8.1 Windows 上的两种入口

| 方式 | 命令 | 说明 |
|------|------|------|
| **PowerShell 脚本（推荐）** | `.\scripts\guard.ps1` | 无需 mise、无需 bash；自动探测 `py -3` / `py` / `python3`（Windows 只有 `py` 启动器也能跑） |
| mise 任务 | `mise run guard` | 需先在 PowerShell 启用 `mise activate powershell` |

`guard.ps1` 可选参数：`-ScenariosDir <目录>`、`-ReportDir <目录>`。

### 8.2 已做的跨平台处理

| 位置 | 原问题 | 处理 |
|------|--------|------|
| `mise.toml` | `python3` / `python` 在 Windows 不存在 | mise 任务命令用 **`python`**（仅 Unix shell）；Windows 走 **`scripts/guard.ps1`**，由它探测 `py -3` / `py` / `python3`（不依赖 bash / mise） |
| `mise.toml` | `guard` 用 `cmd1 && cmd2`（PowerShell 5.x 不支持） | 改用 mise 的 **`depends`**，与 shell 无关 |
| `env-check` `dpkg_ver()` | `dpkg-query` 仅 Debian 系 | 非 posix 或无 dpkg 时直接返回 `None`，不报错 |
| `env-check` `openssh_e2e` | 只查 dpkg 包 | 改为 `shutil.which("sshd")` **或** dpkg（Windows 的 OpenSSH Server 提供 `sshd.exe`） |
| `env-check` `tun_net_admin` | 硬查 `/dev/net/tun` | posix 才查；Windows 走 wintun，标记 `degraded` 并注明由场景结构化降级自行判定 |
| `/etc/os-release` | Windows 无此文件 | 本就包在 `try/except` 中，安全降级 |

### 8.3 Windows 上的已知差异

- `libraries.libssl_dev` / `pkg_config` 依赖 dpkg/pkg-config，Windows 上为 `null`（仅信息性，不门控任何测试）。
- TUN 类场景在 Windows 走 **wintun**：同样按 §4.1 准则**不做能力门控**（场景自带 `TUN_ERROR`/`SKIP` 降级契约）。
- 若要在 Windows 上启用 mise 的进入钩子：`mise activate powershell | Out-String | Invoke-Expression`
  写入 `$PROFILE`，并执行 `mise trust`。但**对 agent 而言 hook 不可靠**（非交互 shell），
  应靠 `CLAUDE.md` 入口规则 + `guard.ps1` 显式执行（见 §9）。

> ⚠️ 上述 Windows 处理为**静态兼容性改造**（消除 bash/Debian 假设），
> `guard.ps1` 尚未在真实 Windows 上实跑验证；如在 Windows 使用请回报结果以便修正。

---

## 9. 让 agent 执行这些逻辑（分层，不靠单一文档）

单靠"让 agent 读文档"不够（会遗忘、上下文可能被压缩）。按可靠度分层：

| 层 | 机制 | 触发 | 可靠度 | 现状 |
|---|---|---|---|---|
| 1 | **入口文档** `CLAUDE.md` / `AGENTS.md` | agent 进入项目自动读取 | 中（依赖遵守） | ✅ `/workspace/CLAUDE.md` |
| 2 | **机器钩子** settings.json `hooks` | 每次会话自动执行 | 高（不依赖自觉） | ❌ 待确认宿主是否支持 |
| 3 | mise `[hooks] enter` | 交互式 shell 进目录 | 低（agent 非交互，通常不触发） | 已配 |
| 4 | 显式命令 / Skill | agent 主动调用 | 中 | ✅ `mise run guard` / `guard.ps1` |

**设计要点**：文档只做**指针**（"跑这条命令、读这个 JSON"），
逻辑放脚本、契约放 `test-plan.json`。给 agent 消费的是**结构化 JSON**，不是散文——
即 nexus-fabric AGENTS.md 的"仓库即 API"。

`CLAUDE.md` 中已写明：Step 0 跑守卫 → 只读 `test-plan.json` 的 `selected`/`skipped` →
skipped 记为 `SKIPPED` 不得记 PASS → 禁止为变绿削弱 gate（应返回 `BLOCKED`）。

## 10. 沙箱出网与推送通道（2026-10-15 实测）

沙箱对 GitHub 各端点的通达性**差异极大**，且**读与写走的不是同一条路**。
踩过坑后把实测结论固化在此，避免重复排查。

### 10.1 通达性实测

| 端点 | 用途 | 直连结果 | 备注 |
|------|------|----------|------|
| `github.com:443` | git 读/写（HTTPS） | ❌ **SYN 被丢，curl 挂死 >7min** | 最坑：解析到的 IP 被拦，间歇性连上也要 36s |
| `api.github.com` | REST API | ✅ **秒通（~0.74s）** | 与 github.com 不是同一 IP 段，完全不受影响 |
| `codeload.github.com` | 源码包下载 | ✅ 通（~15s，慢） | |
| `ssh.github.com:443` | **SSH-over-443** | ✅ **TCP 可达，握手正常** | 沙箱唯一可靠的 git 写通道 |
| `v6.gh-proxy.org` 等 | 反向代理（下载加速） | ✅ 通（~0.8s） | 见 10.2 的重要限制 |

### 10.2 关键区分：代理能加速下载，但**不能用于推送**

gh-proxy 类（`v6.gh-proxy.org` / `ghfast.top` / `gh-proxy.com`）是**URL 前缀反向代理**，
工作方式是转发路径 `https://<proxy>/https://github.com/<path>`。实测限制：

| 操作 | 经 gh-proxy | 原因 |
|------|-------------|------|
| 下载制品/页面（GET） | ✅ 可用 | 纯转发，§3.1 的代理基准结论仍成立 |
| `git push`（写） | ❌ **不可用** | ① 剥离 `Authorization` 头（返回 `No anonymous write access`）；② 把 URL 内嵌的 `user:token@` 当作路径一部分，导致 `repository not found` |

**结论**：`github_proxy` 这个 capability 只描述**下载出网能力**，
**不能**被解读为"可以推送"。二者必须分开看待。

### 10.3 可复现的推送步骤（SSH-over-443）

```bash
# 1) 生成临时 key，经 api.github.com 注册（该端点直连通，无需代理）
ssh-keygen -t ed25519 -f ~/.ssh/gh_push_tmp -N "" -C "sandbox-temp-push"
curl -X POST -H "Authorization: token $TOKEN" -H "Content-Type: application/json" \
     -d "{\"title\":\"sandbox-temp-push\",\"key\":\"$(cat ~/.ssh/gh_push_tmp.pub)\"}" \
     https://api.github.com/user/keys

# 2) SSH 走 443 端口绕过 github.com 的拦截
cat > ~/.ssh/config <<'EOF'
Host github.com
    HostName ssh.github.com
    Port 443
    User git
    IdentityFile ~/.ssh/gh_push_tmp
EOF

# 3) 推送（用 insteadOf 临时覆盖，不污染 origin 配置）
git -c url."git@github.com:".insteadOf="https://github.com/" push -u origin <branch>

# 4) 清理：删除账户上的临时 key + 本地 key + config
curl -X DELETE -H "Authorization: token $TOKEN" https://api.github.com/user/keys/<key_id>
rm -f ~/.ssh/gh_push_tmp* ~/.ssh/config
```

> 该方法依赖 token 具备 `admin:public_key` scope。注册用临时 key、用完即删，
> 比长期保留 PAT 在 git 配置里更安全。

## 11. CI 集成（guard.yml）

守卫自身也接入 CI（`.github/workflows/guard.yml`），在 PR / push(master) 触及
`engineering/sandbox-env-guard/**` 时自动运行，防止门控契约被回归破坏：

| job | 内容 |
|-----|------|
| `guard-tests` | 跑 `python scripts/run_tests.py`（14 用例门控契约 + 错误路径 + env-check 组件测试），非零退出即 CI 失败 |
| `guard-flow` | 跑 `env-check`（`SKIP_NETWORK_PROBES=1` 保确定性）→ `harness-select` 扫真实 `scenarios/` → 断言 `mode=scenarios` → 上传 `env-report.json` + `test-plan.json` 作 artifact，并写入 `$GITHUB_STEP_SUMMARY` |

要点：
- **确定性优先**：CI 里 env-check 用 `SKIP_NETWORK_PROBES=1` 跳过出网探测——否则网络类能力在 ok/degraded/missing 间随 CI 网络抖动跳变，test-plan 不稳定。回归套件本身不依赖真实网络。
- **mode 断言**：`guard-flow` 显式校验 test-plan 的 `mode == scenarios`，防止「扫到空 → demo 幻觉」或「扫空 → BLOCKED」悄悄发生。
- Python 用 `actions/setup-python@v5` 锁 3.11（`tomllib` 依赖），不依赖 runner 预装版本。

本地等价（无需 mise / GitHub Actions）：

```bash
cd engineering/sandbox-env-guard
python scripts/run_tests.py                                   # guard-tests
SKIP_NETWORK_PROBES=1 python scripts/env-check                # guard-flow step 1
python scripts/harness-select --env-report .env-report/env-report.json \
  --map test-capability-map.toml --scenarios-dir ../../scenarios \
  --out .env-report/test-plan.json                            # guard-flow step 2
```

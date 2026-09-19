# 本机环境速查（Agent 参考）

> 用途：让 Agent 在不重新探测的情况下快速了解本机环境与已知坑。
> 信息采集时间：2026-09-17（实测核验）。涉及可变量（磁盘余量、进程状态）以采集时为准，操作前如涉及请重新确认。

## 1. 系统概况



| 项  | 值                                                                         |
| -- | ------------------------------------------------------------------------- |
| OS | Windows 10 专业版 22H2（Build 19045）x64                                       |
| 主机 | ASUS，Intel i7-12700（12 核 / 20 线程）                                         |
| 内存 | 31.7 GB                                                                   |
| 显卡 | NVIDIA 驱动 560.94；当前挂载虚拟显示适配器（远程 / 云机环境特征）                                 |
| 磁盘 | C: 238 GB（仅剩～11 GB，**告警**）；D: 932 GB（剩～354 GB）；E: 476 GB（仅剩～21 GB，**告警**） |



* 远程控制 / 云机类软件常驻：向日葵、ToDesk、UU 远程、海马云云电脑、顺网云电脑。

* 大文件 / 构建产物优先放 D:，避免 C:、E: 写满。

## 2. 命令约定（必须遵守）



* 所有命令行操作一律使用 **PowerShell 7**（`C:\Program Files\PowerShell\7\pwsh.exe`）；禁止 Bash / Unix shell 语法。

* 复杂命令建议：`pwsh -NoProfile -EncodedCommand <Base64(UTF-16LE)>`；外层 5.1 只做转发，业务命令由 pwsh 7 解析。

* 文件读写必须显式指定编码（默认 UTF-8）。

* 仅当 pwsh 不存在时才降级 powershell.exe 5.1，并规避其已知缺陷（Out-File/Export-Csv 默认编码、ConvertFrom-Json 宽松解析、-Path 通配符陷阱）。

## 3. 开发工具链（PATH 可用，已核验）



| 工具                 | 版本                                                 | 备注                              |
| ------------------ | -------------------------------------------------- | ------------------------------- |
| Git                | 2.46.0                                             |                                 |
| Node.js            | v22.23.2（PATH 命中）                                  | 见「已知坑」多版本说明                     |
| npm                | 10.9.8                                             |                                 |
| Python             | 3.14.7（`python` 命令）                                | 另有 3.12.10（`py`）与 uv 托管 3.12.13 |
| pip                | 26.2（关联 D:\Python312）                              |                                 |
| uv                 | 0.10.9                                             | Python 环境管理推荐                   |
| Rust (rustc/cargo) | 1.95.0                                             | rustup 1.29.1                   |
| Go                 | 1.26.1                                             |                                 |
| Docker CLI         | 29.5.2                                             | 引擎默认停止，需先启动 Docker Desktop      |
| kubectl            | v1.34.1                                            |                                 |
| .NET SDK           | 10.0.302                                           | 另有 9.0.304 SDK、8.0 Runtime      |
| CMake              | 3.26.3                                             |                                 |
| LLVM / clang       | 23.1.1                                             | `C:\Program Files\LLVM\bin`     |
| FFmpeg             | 8.1.1                                              |                                 |
| GitHub CLI (gh)    | 2.88.1                                             |                                 |
| ripgrep            | 15.2.0                                             |                                 |
| Zig                | 0.16.0                                             |                                 |
| protobuf           | 35.1                                               |                                 |
| PowerShell         | 7.5.4                                              |                                 |
| WSL2               | Ubuntu + docker-desktop 两个发行版（默认 Ubuntu，均 Stopped） |                                 |

**未安装**（如需可补装）：Java/Maven/Gradle、pnpm/yarn/bun、conda、helm、terraform、MySQL/PostgreSQL/Redis 客户端、jq/make/fd。

## 4. 已知环境坑（操作前注意）



1. **Node 多版本混乱**：PATH 中 `node` 优先命中豆包沙箱运行时（v22.23.2），系统另有 Node 24.14.1（Program Files）与 scoop 的 nodejs。安装全局 npm 包时确认 `npm prefix` 指向预期位置。

2. **Python 多套并存**：`python` → 3.14.7；`py`/`py -3.12` → 3.12.10（D:\Python312，py 启动器注册表已于 2026-09-17 修复）；`uv` 另托管 3.12.13。固定用一套（推荐 `uv` 或 `py -3.12`），勿混用。

3. **gcc 不可用作正式编译器**：PATH 中 gcc 是 Strawberry Perl 附带的 32 位 4.9.2。C/C++ 编译用 clang（LLVM）或 VS 自带 MSVC。

4. **Docker 引擎默认停止**：`docker` 命令可用，但 `com.docker.service` Stopped；需要时启动 Docker Desktop。

5. **磁盘紧张**：C:、E: 使用率 >95%；构建、下载、日志优先放 D:。

## 5. 网络与代理



* Clash Verge（内核 verge-mihomo）监听 **127.0.0.1:7897**（混合端口，当前对局域网开放）。

* **系统代理开关当前关闭**（WinINET ProxyEnable=0，但保留配置 127.0.0.1:7897）；环境变量 HTTP/HTTPS/ALL\_PROXY 均未设置；WinHTTP 直连。

* 需要走代理的应用需显式配置 `127.0.0.1:7897`。

* easytier-gui 运行中（组网用途）。

## 6. 浏览器 CDP（远程调试）



* 调试实例：**msedge**，经 netsh portproxy 暴露：


  * `0.0.0.0:9224 → 127.0.0.1:9223` / `::1:9223`

  * 另有 `0.0.0.0:9222 → 127.0.0.1:9222`、`0.0.0.0:9223 → 127.0.0.1:9223` 等规则

* 常用端点（[http://localhost:9224](http://localhost:9224)）：


  * `GET /json`：列出页面 target（含 title/url/id/webSocketDebuggerUrl）

  * `PUT /json/new?<url编码>`：新建并打开标签页

  * 每个 target 的 `ws://localhost:9224/devtools/page/<id>` 可连 WebSocket 执行 CDP 命令

* **安全提示**：9224 绑定 0.0.0.0 且 CDP 无认证，局域网可达；此为远程调试 / 云机场景的既有配置，若不再需要可收紧。

## 7. SSH



* `~/.ssh` 两对密钥：`id_ed25519`、`id_rsa`（均无口令，公钥与私钥配对已验证）。

* `config` 常用主机别名（用户名 / 跳板见文件，勿外泄私钥）：


  * `mylinux` → 172.168.9.202（xiangcui）

  * `j6m` → 172.168.12.107（root，经 mylinux ProxyJump）

  * `j6mb` → 172.168.12.107（root，直连）

  * `vps` → 192.3.53.155（root，指定 id\_ed25519）

  * `cloud` → 10.144.144.14（Administrator，StrictHostKeyChecking no）

  * `gpal_docker` → xc-pc-linux.local:2222（ubuntu）

* 内网主机（172.168.x.x 等）用户名多为 gpal /appen/xiangcui。

## 8. 常用软件速览



* **IDE / 开发**：VS Code、Visual Studio 2022/2026、Android Studio 2025.3、Cursor、TraeCode CN、Qoder CN、Zed、Unity 6000 + Hub、团结引擎（Tuanjie 2022.3）

* **AI 工具**：豆包、Cherry Studio、Coze、CodeBuddy CN、Antigravity、OpenCode

* **远程 / 网络**：Clash Verge、easytier、向日葵、ToDesk、UU 远程、MobaXterm、WinSCP、TigerVNC/TurboVNC、X2Go、Moonlight/Sunshine

* **效率工具**：7-Zip、Everything、Ditto、CopyQ、PowerToys、Sandboxie-Plus、Windhawk、ImDisk、KopiaUI、Obsidian、Anki、滴答清单

* **网络分析 / 硬件**：Wireshark 4.4 + Npcap、DB Browser for SQLite、PEAK CAN 卡驱动、创芯 USBCANFD、方向盘桥接、GameSir 手柄

* **通讯 / 影音**：微信、钉钉、Telegram、PotPlayer、VLC、百度网盘

## 9. 已完成的环境修复（历史记录）



* 2026-09-17：修复 `py` 启动器 —— 注册表 `HKCU\SOFTWARE\Python\PythonCore\3.12\InstallPath` 从失效的 `C:\Users\xiangcui\AppData\Local\Programs\Python\Python312\` 更正为 `D:\Python312\`。
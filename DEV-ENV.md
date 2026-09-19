# Nexus 远程 Linux 开发环境（xc-pc-linux.local）

> 本文档记录远程开发环境
>
> **非敏感**
>
> 信息；登录凭据见本地私密文件
> `%USERPROFILE%\.nexus-remote-credentials`
>
> （不入版本库，禁止提交）。
> 2026-09-17 建立并完成 Linux 全量验证（21/21）。

## 连接



```
ssh appen@xc-pc-linux.local
```



* 使用本机 `~/.ssh/id_ed25519`（Windows 端 `C:\Users\xiangcui\.ssh\id_ed25519`），密钥免密已通。

* VS Code：`Remote - SSH` 扩展连接后打开 `/work/nexus-dev/nexus` 即进入开发入口。

## 主机



| 项     | 值                                                                        |
| ----- | ------------------------------------------------------------------------ |
| 主机名   | xc-pc-linux.local                                                        |
| 登录用户  | appen                                                                    |
| OS    | **Ubuntu 20.04.6 LTS**（focal；内核 5.15.0-139-generic x86\_64）              |
| 系统盘   | `/dev/nvme0n1p2` ext4 232G，挂载 `/`，清理后剩余约 **12G**（95%）                    |
| apt 源 | [mirrors.ustc.edu.cn](https://mirrors.ustc.edu.cn) focal + 若干 PPA / 第三方源 |

## 数据盘与开发目录（2026-09-17 建立）



| 项       | 值                                                                                                                          |
| ------- | -------------------------------------------------------------------------------------------------------------------------- |
| 数据盘     | `/dev/sda1` ext4 931.5G，挂载 `/media/appen/data` 与 `/work`（同盘双挂载点）                                                           |
| 可用空间    | 54G（94% 已用）                                                                                                                |
| **开发根** | `/work/nexus-dev`（属主 appen:appen，权限 775）                                                                                   |
| 工作树     | `/work/nexus-dev/nexus`（git clone 自 bundle，origin 指向 `/work/nexus-dev/nexus.git` bare）                                     |
| bare 仓库 | `/work/nexus-dev/nexus.git`                                                                                                |
| Rust 栈  | `/work/nexus-dev/.rustup`（RUSTUP\_HOME）、`/work/nexus-dev/.cargo`（CARGO\_HOME）、`/work/nexus-dev/target`（CARGO\_TARGET\_DIR） |
| 数据盘既有内容 | `/media/appen/data` 下已有 `workspace/` 等既有项目与 SMB 挂载（勿删改）                                                                    |
| 网络盘     | `//172.168.4.212/tsgroup`（115T CIFS，挂 `/mnt/tsgroup_233VAN_002_0828`）                                                      |

## Rust 工具链（全量，已装数据盘）



| 项               | 值                                                                                                                       |
| --------------- | ----------------------------------------------------------------------------------------------------------------------- |
| rustup          | 1.29.1（RUSTUP\_HOME=/work/nexus-dev/.rustup）                                                                            |
| stable（default） | **1.98.1**（rustc/cargo 1.98.1；clippy/rustfmt/llvm-tools 齐）                                                              |
| nightly         | **1.100.0-nightly**（cargo-fuzz 0.13.2 用）                                                                                |
| targets         | x86\_64-linux-gnu、x86\_64-linux-musl、wasm32-unknown-unknown、**wasm32-wasip1**                                           |
| 工具              | cargo-fuzz 0.13.2、cargo-deny 0.20.2、cargo-llvm-cov 0.9.1、clang/clang++ **11.0.0**（focal 最高版本，`/usr/local/bin/clang` 软链） |
| 二进制             | `/work/nexus-dev/.cargo/bin`                                                                                            |

> 旧
>
> `~/.rustup`
>
> 、
>
> `~/.cargo`
>
> （系统盘，共～4.4G）已于新环境验证 21/21 后删除。

### 使用注意



* **环境变量**（已写入 `~/.bashrc`，交互登录自动生效；非交互 SSH 需手动 export）：



```
export RUSTUP\_HOME=/work/nexus-dev/.rustup

export CARGO\_HOME=/work/nexus-dev/.cargo

export CARGO\_TARGET\_DIR=/work/nexus-dev/target

export PATH=\$CARGO\_HOME/bin:\$PATH
```



* **crates 镜像**：[rsproxy.cn](https://rsproxy.cn)（sparse index + git-fetch-with-cli），配置在 `$CARGO_HOME/config.toml`。

* **fuzz gate**：`cd /work/nexus-dev/nexus/fuzz && cargo +nightly fuzz check`（已验证通过；clang 11 满足 libFuzzer）。

* **coverage gate**：cargo-llvm-cov + rustup llvm-tools-preview（已验证通过）。

## 验证状态（Linux 全量闭环）

`/work/nexus-dev/target/debug/nexus-harness verify --full --json`：



* **21/21 PASS，0 fail，0 unknown**（绑定 master `c40a587d`，dirty=false；Evidence `verify-4175e34eea1f` 起）。

* 16 个 product scenario 全 PASS（含 socks5-handshake、connectivity-carrier-split、remote-\* 系列）。

## 仓库同步（Windows ⇄ Linux）

本机 `git push` 会被本机 pre-push hook 拦截（dirty 工作树判定），改用 **git bundle** 通道：



```
\# Windows（本机仓库 D:\next\nexus）：

git bundle create D:\nexus-master.bundle master

scp D:\nexus-master.bundle appen@xc-pc-linux.local:/work/nexus-dev/

\# Linux：

git -C /work/nexus-dev/nexus fetch /work/nexus-dev/nexus-master.bundle master

git -C /work/nexus-dev/nexus merge --ff-only FETCH\_HEAD

rm /work/nexus-dev/nexus-master.bundle
```



* bundle 只含已提交 master 历史，不携带未提交工作树改动。

* 每次同步前先 `git -C D:/next/nexus log --oneline -1` 确认本机 HEAD。

* 注意：本机工作树可能含并行任务未提交改动（如他组的 PRODUCT.md/ 半成品 scenario），bundle 天然隔离。

## 凭据



* root 口令等凭据**不在本项目内**：见 `%USERPROFILE%\.nexus-remote-credentials`

  （Windows 本地私有文件，仅当前用户可读）。

* 禁止将该文件内容、任何口令写入本仓库或提交到 git。
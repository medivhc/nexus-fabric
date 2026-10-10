# Nexus 实际开发流程

> 本文档记录**实际执行中**的开发流程（tribal knowledge）。
> 正式工程契约见仓库根目录 `AGENTS.md` / `DEVELOPMENT.md` —— 那是制度，
> 这里是制度在真实环境里的落地方式。

## 1. 工作模式：Coordinator + 独立 Worktree

- 每个并行轨道**必须**从 origin/master 建独立 git worktree 再开工；
  主工作树 `~/workspace/nexus-xc` 只给总协调用，轨道不许碰。
  （教训：2026-09-30 四个 side chat 共用一棵树，一条轨道的 checkout
  删掉了另一条未提交的改动。）
- 大任务用 coordinator subagent fan-out，coordinator 只做合并与裁决，
  不直接写业务代码。
- 用户指令"开工/继续做" = 跑完
  计划 → 实现 → 真机验证 → 独立评审 → full verify 完整闭环；
  只有**契约必须变更**时才停下找用户。

## 2. Contract-First（实践版）

1. 先写 PRODUCT.md 章节 + `scenarios/` 新场景（contract-first）
2. 在旧实现上跑出 Red（FAIL）Evidence，冻结契约
3. 实现 → 场景变绿
4. `requirement-change` 是唯一允许改已冻结期望的任务类型；
   此时旧 Evidence 全部标 STALE

## 3. 验证分层

| 环境 | 跑什么 | 说明 |
|---|---|---|
| 沙盒 | `verify --fast` | 沙盒 UDP 被禁，`verify --full` 永无绿基线，**不跑** |
| xc-pc-linux 真机 | `verify --full`、E4 场景 | 经 SSH（mesh），`CARGO_TARGET_DIR=<worktree>/target` 隔离 |
| NU-SH-1217 | N2 跨机 E4 | 10.x.x.x，需 sudo 密码的操作提前列出 |

- `cargo check` 必须 `--workspace --all-targets`（examples 里的旧签名会漏网）。
- 时序 flake 判读：用干净基线 worktree（同 commit、未改代码）对照跑，
  基线也 FAIL 的是环境噪音，不是回归。
- pre-push 门禁：STALE evidence 先归档到 `~/workspace/evidence-archive/<date>/`
  （不删除，ID 保持可引用），再 push；并确认 `nexus-harness` 在 PATH 上、
  `.githooks` 有可执行位（worktree 会丢 +x）。

## 4. 独立评审

- 实现者与评审者必须是独立执行者；同一会话刚写完代码不许自己评审。
- 八个维度：契约一致性、边界覆盖、API 面控制、依赖边界、
  错误处理质量、测试质量、复杂度控制、可观测性。
- Verdict：APPROVED / COMMENTED / CHANGES_REQUESTED / BLOCKED；
  CHANGES_REQUESTED 必须修完再走一轮（默认上限 3 轮，超了转人工）。

## 5. 免费模型横评（opencode）

- 用途：独立代码评审、独立 bug 修复（与主实现者隔离，用于交叉验证）。
- 模型：`opencode/mimo-v2.6-flash-free`、`opencode/space-bunny-free`
  （原生 `opencode/` provider，需 `opencode auth login` 后的 Zen credential；
  service key 的 provider 只留 space-bunny）。
- **铁律**：
  - `opencode run "任务" < /dev/null`（否则等 stdin 表现为 hang）
  - **两个模型实例绝不并行**（opencode DB 锁冲突，并行必失败）——串行，
    一个完全结束、输出落盘确认后，再起下一个
  - 评审/修复前把模型输出文件移出输入目录，保证后跑的看不到先跑的
- 模型输出是 raw leads：**每条必须亲自读代码验真**，误报剔除并注明原因，
  分级分歧按"代码零分支属实但证明弱"等原则统一口径。

## 6. 构建加速

- 真机多轨道：各轨道独立 `CARGO_TARGET_DIR`（防并发污染），
  去重靠共享 sccache（`/work/nexus-dev/sccache`，20G，按内容寻址）。
  `~/.bashrc` 顶部已导出 `RUSTC_WRAPPER=sccache` 等。
- `/tmp` 是 512M tmpfs —— 大构建不上 `/tmp`，放 `~/workspace/`。

## 7. 网络生命线

- `tun0` / `10.x.x.x/24` 是 SSH 生命线，**不得修改**。
- `ssh xc-pc-linux` 经 EasyTier 端口转发（127.0.0.1:12222 → 10.x.x.x:22）；
  `/root/.ssh/config` 的别名在 VM 更换后可能丢失，
  若出现 "Connection reset by 198.19.0.1:3128" 先重建别名再排查 mesh。
- `easytier-watchdog` 是 runtime cron（每 10 分钟），不是系统 crontab ——
  `crontab -l` 为空是正常的，不要"修复"它。

## 8. 报告规范（给用户的中文报告）

```text
任务类型 / 修改模块 / 修改契约 / 修改实现 /
新增-修改 Tests-Scenarios /
Fast Verification / Full Verification /
Evidence ID-Path / Evidence Freshness /
剩余风险-Blocker /
Candidate Completion: yes-no /
Final Verdict: 仅 Harness 可决定
```

- 不写 done/complete/finished；没产生 fresh Evidence 就不宣称完成。
- 给状态时一次给全：代码状态、真机证据、评审 verdict、还缺什么、
  哪些还不能宣称 —— 用户要的是状态，不是过程唠叨。

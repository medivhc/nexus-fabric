# nexus-proxy-config Module Contract

## Responsibility

代理内核产品线的配置模型层：把用户提供的 YAML 配置文件解析为 typed structs
（入站监听、规则表、策略组、出站定义），并做结构化校验。这是 Nexus 首个配置
文件入口。

## Non-Responsibilities

- 不执行规则匹配、不选择出站、不发起网络 I/O；
- 不解析 Clash 订阅 YAML（P1+）；
- 不持有运行时状态（选中项、measurement 缓存），只负责一次性配置装载与校验。

## Inputs

- YAML 文本（字节流或字符串）。
- 配置 schema 版本号（P0 冻结为 `schema_version = 1`）。

## Outputs

- 结构化 `ProxyConfig`（typed structs）或 `ConfigError`（保留字段路径与原因）。
- 校验错误必须结构化：`CONFIG_INVALID { field, reason }`，不以日志文本代替。

## Allowed Dependencies

- `nexus-domain`

## Forbidden Dependencies

- `engineering/` 下的 Harness/Plugin。
- `nexus-planner` / `nexus-connectivity` / `nexus-ingress`（配置层不依赖运行时层，
  避免循环依赖；运行时层依赖本配置层）。
- 未在 `policies/architecture.toml` 声明的 Nexus 内部 crate。
- Portable 模块中的平台专有 Framework/API。

## Invariants

- 配置解析为纯函数（零 I/O、零副作用）；同一份 YAML 永远产出同一个 `ProxyConfig`。
- 规则表必须以 `MATCH` 规则结尾；否则返回 `CONFIG_INVALID`。
- 每条规则的 `outbound` 字段引用的 tag 必须能在出站/策略组定义表中解析；
  悬空引用返回 `CONFIG_INVALID`。
- selector 策略组候选列表不得为空；urltest 组同理。
- 该 crate 必须保持 WASI/portable 可检查（不直接读写文件系统；文件 I/O 由
  Composition Root 完成，本层只消费已读入的文本）。

## Side Effects

- 无（纯解析与校验）。

## Public API

- 默认最小 surface：`private -> pub(crate) -> pub`。
- P0 冻结接口骨架（实现阶段填充）：
  - `ProxyConfig`：typed root struct（`inbounds` / `rules` / `groups` / `outbounds`）；
  - `InboundConfig`：`{ tag, kind: "socks5", listen }`；
  - `RuleConfig`：`{ kind: "domain_suffix"|"domain"|"ip_cidr"|"match", match: String,
    action: ActionChainConfig }`；
  - `ActionChainConfig`：有序动作列表；P0 首动作为 `{ kind: "select_outbound",
    tag: String }`；
  - `GroupConfig`：`{ tag, kind: "selector"|"urltest", candidates: Vec<String>,
    (urltest 可选 tolerance/latency_budget) }`；
  - `OutboundConfig`：`{ tag, kind: "direct"|"relay", locator: Option<String> }`；
  - `parse(yaml: &str) -> Result<ProxyConfig, ConfigError>`。

## Verification

最低：

```text
cargo check -p nexus-proxy-config
cargo clippy -p nexus-proxy-config --all-targets -- -D warnings
```

如果该模块影响产品行为，还必须映射 Integration/Scenario Evidence。

## Performance Budget

未定义性能预算的路径不得宣称"性能完成"。配置解析不在数据面热路径，不设
硬预算；进入 hot path 后必须在 Contract 中增加 baseline、noise tolerance、
warning threshold 与 blocking threshold。

## Observability

配置校验失败必须携带结构化字段路径与原因，不输出自由文本日志。

## Recovery Semantics

无持久运行时状态；配置为不可变装载结果。进程重启后重新解析 YAML 即可。

## Platform Constraints

平台专有代码只允许存在于 `nexus-platform-*` 或 Composition Root。Portable crate
必须通过相应 portability gate。

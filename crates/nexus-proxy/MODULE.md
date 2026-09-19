# nexus-proxy Module Contract

## Responsibility

代理内核产品线的规则引擎 + 策略组 + 编排 service：消费 `ProxyConfig`，对
`nexus-ingress` 产出的 `FlowContext` 执行顺序规则匹配，产出 `rule_action` 动作链，
经策略组解析为选定出站 tag，再委派 `nexus-connectivity` 激活 Direct/Relay 链路。

## Non-Responsibilities

- 不实现 SOCKS5 协议状态机（复用 `nexus-ingress`）；
- 不解析 YAML（复用 `nexus-proxy-config`）；
- 不实现真实加密代理协议栈（Shadowsocks/Vmess/Trojan，P1+）；
- 不实现 TUN 透明代理（P1+）；
- 不实现 Clash 订阅解析（P1+）；
- 不创建第二套系统级 Core Planner（规则引擎是领域局部组件，不是 Planner）。

## Inputs

- `ProxyConfig`（来自 `nexus-proxy-config`）。
- `FlowContext`（来自 `nexus-ingress`，origin=socks5）。
- 注入的 `LinkProbe` trait 对象（来自 `nexus-connectivity`，urltest 组使用）。
- 注入的离线确定性 measurement 数据源（mock，禁止真实网络探测）。

## Outputs

- `RoutingDecision`：`{ matched_rule, rule_kind, selected_outbound_tag,
  group_type, first_action }`。
- 结构化错误：`NoMatchRule` / `OutboundTagUnresolved` / `SelectorEmpty` /
  `UrltestNoValidCandidate`。

## Allowed Dependencies

- `nexus-domain`
- `nexus-proxy-config`
- `nexus-ingress`
- `nexus-policy`
- `nexus-planner`
- `nexus-connectivity`
- `nexus-measurement`

## Forbidden Dependencies

- `engineering/` 下的 Harness/Plugin。
- `nexus-network` / `nexus-service` / `nexus-workspace` / `nexus-compute`（不反向
  依赖领域运行时；代理内核是独立产品线，不污染远程资源访问闭环）。
- `nexus-platform-*`（Portable Core 不直接调用平台 API）。
- 未在 `policies/architecture.toml` 声明的 Nexus 内部 crate。

## Invariants

- 规则匹配为纯函数（零 I/O）：相同 `FlowContext` + 相同 `ProxyConfig` 永远产出
  同一个 `RoutingDecision`。
- 首匹配即终止（first-match）；`MATCH` 规则必须在表尾。
- `rule_action` 动作链的第一动作必须是 `SELECT_OUTBOUND <tag>`；后续动作为
  P1+ 扩展口，P0 不实现也不触发。
- 策略组解析：
  - `selector`：直接返回当前选中 tag，切换为确定性操作（不探测）；
  - `urltest`：从注入的离线 measurement 数据中选 RTT 最低候选；无有效候选
    返回 `UrltestNoValidCandidate`；
  - `load_balance`：round-robin 均匀分发——组内确定性游标，每次决策选
    `candidate[cursor % n]` 并推进游标；连续 N 次在 n 个候选上各命中次数差 ≤1。
    游标为进程内状态（`Cell<usize>`，不产生副作用、不探测）；
  - `relay`：链式级联，候选列表即跳序 `[A, B, ...]`；决策把完整跳序写入
    `RoutingDecision.relay_hops`，`selected_outbound_tag` 为列表最后一跳（出口）。
    离线确定性（mock 两跳均经过），不建真实第二跳。
- 出站激活委派 `nexus-connectivity::LinkActivator`：Direct 成功即直连；Direct
  不可达回退 Relay；全部不可达报告事实，不替换配置中的出站 tag。
- 规则引擎不调用系统级 Core Planner；它是代理内核产品线的领域局部组件，
  不产生第二套系统级 Plan。
- 该 crate 的规则匹配核心（纯函数部分）保持 Portable；LinkProbe/LinkActivator
  的注入点由 Composition Root 装配。

## Allowed Equivalence: urltest selection

经审核的允许等价决策（P0 冻结记录）：`urltest` 组复用 `nexus-measurement` 的
选优语义（RTT 最低者胜出；缺失 measurement 排后；同分按候选 tag 字典序决胜），
但不直接调用 `nexus-planner::score_candidates`。

理由：`nexus-planner::score_candidates` 作用于 `nexus-registry::ProviderRecord`，
而 `nexus-registry` 不在本 crate 的 Allowed Dependencies 内（代理内核是独立产品线，
不得把 Provider/Registry 图谱拉进分流内核）。因此 urltest 经由 Composition Root
注入的 `MeasurementSource` trait（离线确定性 `BTreeMap<String, u32>`）承载同一套
选优语义，而非在本 crate 内重新引入 Registry 依赖。

这是经审核的等价决策，不是第二套系统级 Plan：它不复制 Planner 的规划/建连时序，
不产生系统级 `Plan`，仅在领域局部按 measurement 选出一个出站 tag；规则引擎仍是
代理内核产品线的领域局部组件，满足上文 Invariants 中“不产生第二套系统级 Plan”的约束。

## Side Effects

- 出站链路激活（经注入的 `LinkActivator`）产生网络副作用；规则匹配本身无副作用。
- 新增副作用前必须更新本契约和 Scenario/Policy（如影响外部行为）。

## Public API

- 默认最小 surface：`private -> pub(crate) -> pub`。
- P0 冻结接口骨架（实现阶段填充）：
  - `RuleEngine::new(config: &ProxyConfig) -> Self`：从配置构建规则表（纯函数）；
  - `ProviderFetcher` trait（§11.12，纯接口零 I/O）：`load(&mut self, cfg: &RuleProviderConfig)`
    -> `Result<FetchedProvider, String>`；`FetchedProvider { lines, source }`，
    `ProviderSource::{Local, Cached, Online}` 命中来源可观察；组合根负责实现
    （`FileProviderFetcher` / `CachedHttpProviderFetcher`）；
  - `geoip_nex::parse(&[u8]) -> Result<HashMap<String, Vec<String>>, ParseError>`
    （§11.12 格式 v1，纯函数零 I/O，输出与 `RuleData.geoip` 兼容）；
  - `RuleData`：组合根注入的规则数据（geoip 国家码→CIDR、geosite 分类→域名、
    rule-providers 解析结果；`Default` 为空）；`RuleEngine::new` 委托空数据，
    `RuleEngine::with_data(config, &RuleData)` / `ProxyService::with_rule_data`
    启用完整能力（§11.11，编译期展开，决策零 I/O）；
  - `RuleEngine::route(&self, flow: &FlowContext) -> RoutingDecision`：
    对单个 FlowContext 执行顺序匹配，返回动作链首动作 + 出站 tag；
  - `SelectorGroup::new(candidates, initial)` / `select(&self) -> &str` /
    `switch_to(&mut self, tag)`：手动选择组；
  - `UrltestGroup::new(candidates)` / `select(&self, measurements: &MeasurementSource)
    -> Result<&str, ProxyError>`：按离线 measurement 自动选优；
  - `LoadBalanceGroup`：round-robin 组，`pick(&self) -> &str` 选当前游标候选并推进；
  - relay 组由 `GroupKind::Relay` 配置承载，跳序列表经 `RoutingDecision.relay_hops` 暴露。
  - `ProxyService`：编排 service，持有 RuleEngine + Group 注册表 + Outbound 注册表，
    对每个入站 FlowContext 执行 route -> group resolve -> outbound activate。

## Verification

最低：

```text
cargo check -p nexus-proxy
cargo clippy -p nexus-proxy --all-targets -- -D warnings
```

产品行为映射到 E4 Scenario（scenarios/product/proxy_*.toml）。

## Performance Budget

规则匹配为线性首匹配扫描，不在数据面热路径（每连接一次）；不设硬预算。
进入 per-packet 热路径后必须在 Contract 中增加 baseline、noise tolerance、
warning threshold 与 blocking threshold。

## Observability

每次分流决策必须输出结构化字段：`matched_rule` / `rule_kind` /
`selected_outbound_tag` / `group_type` / `flow_origin`。Hot path（per-packet）
禁止无节制日志。

## Recovery Semantics

无持久状态（配置不可变装载；selector 选中项为进程内状态，重启后回配置默认值）。
进程重启后重新装载配置即可，无需 journal/reconcile。

## Platform Constraints

平台专有代码只允许存在于 `nexus-platform-*` 或 Composition Root。Portable crate
必须通过相应 portability gate。LinkProbe/LinkActivator 的真实 I/O 实现由
Composition Root 注入，本 crate 只做策略编排。

# E4 场景证据索引

> 生成：`nexus-harness scenario index --write`（按 subdir + id 字典序，确定性）
> 校验：`scenario index --check`（architecture_gate 调用）+ 单测 `index_matches_scenarios`
> external 含 3 个 scripts/e4 真流量场景（被测 target = nexusd，按执行载体记 external）
> first recorded revision 绑定本地 .evidence；无本地证据写 unrecorded（不伪造）
> `--write` 保留既有行的 first_revision（id 已存在且 carrier 未变时不刷新）

<!-- index-rows-begin -->
| scenario id | carrier | command carrier | requirement | first recorded revision |
|---|---|---|---|---|
| engineering.bench-gate-verdicts | engineering | nexus-harness bench | PRODUCT.md#12-bench-gate | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| engineering.code-intelligence-budget-count | engineering | nexus-harness code | docs/SEMANTIC-CODE-INTELLIGENCE-PROPOSAL.md#5-context-budget | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| engineering.code-intelligence-budget-truncation | engineering | nexus-harness code | docs/SEMANTIC-CODE-INTELLIGENCE-PROPOSAL.md#5-context-budget | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| engineering.code-intelligence-cache-disabled | engineering | nexus-harness code | engineering/nexus-harness/MODULE.md#provider-daemon--result-cache | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| engineering.code-intelligence-callees | engineering | nexus-harness code | docs/SEMANTIC-CODE-INTELLIGENCE-PROPOSAL.md#16-acceptance-criteria | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| engineering.code-intelligence-callers | engineering | nexus-harness code | docs/SEMANTIC-CODE-INTELLIGENCE-PROPOSAL.md#16-acceptance-criteria | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| engineering.code-intelligence-context-anchors | engineering | nexus-harness context | docs/SEMANTIC-CODE-INTELLIGENCE-PROPOSAL.md#15-suggested-implementation-phases | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| engineering.code-intelligence-context-no-fake-semantics | engineering | nexus-harness context | docs/SEMANTIC-CODE-INTELLIGENCE-PROPOSAL.md#12-failure-semantics | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| engineering.code-intelligence-context-scope-guard | engineering | nexus-harness context | docs/SEMANTIC-CODE-INTELLIGENCE-PROPOSAL.md#14-security-and-resource-control | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| engineering.code-intelligence-daemon-command-surface | engineering | nexus-harness daemon | engineering/nexus-harness/MODULE.md#public-api | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| engineering.code-intelligence-daemon-explicit-only | engineering | nexus-harness code | engineering/nexus-harness/MODULE.md#provider-daemon--result-cache | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| engineering.code-intelligence-daemon-lifecycle | engineering | nexus-harness daemon | engineering/nexus-harness/MODULE.md#provider-daemon--result-cache | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| engineering.code-intelligence-daemon-unknown-flag | engineering | nexus-harness daemon | engineering/nexus-harness/MODULE.md#public-api | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| engineering.code-intelligence-definition | engineering | nexus-harness code | docs/SEMANTIC-CODE-INTELLIGENCE-PROPOSAL.md#16-acceptance-criteria | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| engineering.code-intelligence-diagnostics-advisory | engineering | nexus-harness code | docs/SEMANTIC-CODE-INTELLIGENCE-PROPOSAL.md#7-compiler-truth-remains-separate | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| engineering.code-intelligence-diagnostics-item-shape | engineering | nexus-harness code | docs/SEMANTIC-CODE-INTELLIGENCE-PROPOSAL.md#16-acceptance-criteria | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| engineering.code-intelligence-hover | engineering | nexus-harness code | docs/SEMANTIC-CODE-INTELLIGENCE-PROPOSAL.md#16-acceptance-criteria | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| engineering.code-intelligence-implementations | engineering | nexus-harness code | docs/SEMANTIC-CODE-INTELLIGENCE-PROPOSAL.md#16-acceptance-criteria | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| engineering.code-intelligence-mcp-handshake | engineering | nexus-harness mcp | docs/SEMANTIC-CODE-INTELLIGENCE-PROPOSAL.md#10-mcp-integration | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| engineering.code-intelligence-mcp-real-query | engineering | nexus-harness mcp | docs/SEMANTIC-CODE-INTELLIGENCE-PROPOSAL.md#4-agent-facing-api | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| engineering.code-intelligence-provider-unavailable | engineering | nexus-harness code | docs/SEMANTIC-CODE-INTELLIGENCE-PROPOSAL.md#12-failure-semantics | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| engineering.code-intelligence-read-only-counters | engineering | nexus-harness code | docs/SEMANTIC-CODE-INTELLIGENCE-PROPOSAL.md#14-security-and-resource-control | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| engineering.code-intelligence-scope-escape | engineering | nexus-harness code | docs/SEMANTIC-CODE-INTELLIGENCE-PROPOSAL.md#14-security-and-resource-control | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| engineering.code-intelligence-scope-violation | engineering | nexus-harness code | docs/SEMANTIC-CODE-INTELLIGENCE-PROPOSAL.md#14-security-and-resource-control | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| engineering.code-intelligence-symbol | engineering | nexus-harness code | docs/SEMANTIC-CODE-INTELLIGENCE-PROPOSAL.md#4-agent-facing-api | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| engineering.code-intelligence-workspace-escape | engineering | nexus-harness code | docs/SEMANTIC-CODE-INTELLIGENCE-PROPOSAL.md#14-security-and-resource-control | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| engineering.code-intelligence-write-method-denied | engineering | nexus-harness code | docs/SEMANTIC-CODE-INTELLIGENCE-PROPOSAL.md#14-security-and-resource-control | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| engineering.harness-status-verdicts | engineering | nexus-harness status | harness.toml#evidence | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| engineering.harness-verify-fast-evidence | engineering | nexus-harness verify | DEVELOPMENT.md#6 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| platform.os-assemble | n1-fabric | cargo -p nexus-platform-linux | PRODUCT.md#12-os-assemble | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| platform.virtual-packet-interface | n1-fabric | cargo -p nexus-platform-host | PRODUCT.md#cross-platform | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| platform.win-ip-route | n1-fabric | cargo -p nexus-platform-windows | docs/WINDOWS_TUN_DESIGN.md#5 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| platform.win-procattr | n1-fabric | cargo -p nexus-projection | crates/nexus-projection/MODULE.md#S26 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| platform.windows-system-proxy | n1-fabric | cargo -p nexusd | PRODUCT.md#13-system-proxy | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| platform.workspace-fuse-projection | n1-fabric | cargo -p nexus-platform-linux | v9#22 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| platform.workspace-projection-channels | n1-fabric | cargo -p nexus-workspace | PRODUCT.md#workspace | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| platform.workspace-projection-fallback | n1-fabric | cargo -p nexus-workspace | PRODUCT.md#workspace | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.auto-discovery | v9-connectivity | cargo -p nexus | PRODUCT.md#remote | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.auto-reconnect | v9-connectivity | nexus-harness run | PRODUCT.md#12-auto-reconnect | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.bandwidth-policy | v9-connectivity | cargo -p nexus | PRODUCT.md#12-bandwidth-policy | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.bandwidth-qos | v9-connectivity | nexus-harness run | PRODUCT.md#12-bandwidth-qos | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.boost-v1 | n1-fabric | cargo -p nexus-projection | docs/DAEMON_ARCHITECTURE.md#12 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.bootstrap-join | v9-connectivity | cargo -p nexus-harness | PRODUCT.md#bootstrap-join | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.cac1-proxy-v6-echo | n1-fabric | cargo -p nexusd | DAEMON_ARCHITECTURE.md#10 | unrecorded |
| product.certificate-manager | v9-connectivity | cargo -p nexus | PRODUCT.md#12-certificate-manager | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.cli-compute-jobs | v9-connectivity | cargo -p nexus | PRODUCT.md#9-observability | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.cli-connectivity-candidates | v9-connectivity | cargo -p nexus | PRODUCT.md#9-observability | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.cli-connectivity-links | v9-connectivity | cargo -p nexus | PRODUCT.md#9-observability | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.cli-connectivity-probe | v9-connectivity | cargo -p nexus | PRODUCT.md#9-observability | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.cli-diagnose | v9-connectivity | cargo -p nexus | PRODUCT.md#9-observability | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.cli-dns-providers | v9-connectivity | cargo -p nexus | PRODUCT.md#9-observability | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.cli-dns-resolve | v9-connectivity | cargo -p nexus | PRODUCT.md#9-observability | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.cli-run-command | v9-connectivity | cargo -p nexus | PRODUCT.md#cli | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.cli-subnet | v9-connectivity | cargo -p nexus | PRODUCT.md#12-subnet-cli | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.cli-workspace-cache | v9-connectivity | cargo -p nexus | PRODUCT.md#9-observability | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.cli-workspace-conflicts | v9-connectivity | cargo -p nexus | PRODUCT.md#9-observability | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.composition-root | n1-fabric | cargo -p nexusd | DAEMON_ARCHITECTURE.md#13 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.compression | v9-connectivity | cargo -p nexus | PRODUCT.md#12-compression | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.config-hot-reload | v9-connectivity | cargo -p nexus | PRODUCT.md#12-config-hot-reload | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.config-hot-reload-watch | v9-connectivity | cargo -p nexus | PRODUCT.md#12-config-hot-reload-real | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.connection-pool | v9-connectivity | cargo -p nexus | PRODUCT.md#12-connection-pool | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.connection-pool-real | v9-connectivity | cargo -p nexus | PRODUCT.md#12-connection-pool-real | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.connectivity-carrier-split | v9-connectivity | cargo -p nexus | PRODUCT.md#network | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.connectivity-evaluation | v9-connectivity | cargo -p nexus | v9 §8.1 Connectivity Evaluation | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.connectivity-failure-rollback | v9-connectivity | cargo -p nexus | PRODUCT.md#session | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.coord-core | v9-connectivity | cargo -p nexus | PRODUCT.md#12-coord | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.coord-join-loopback | v9-connectivity | cargo -p nexus | PRODUCT.md#12-coord | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.crash-recovery-boot-reconcile | n1-fabric | cargo -p nexusd | v9 §15.2/§15.3 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.cross-subnet | v9-connectivity | cargo -p nexus | PRODUCT.md#12-cross-subnet | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.daemon-real-host-auth-denied | v9-connectivity | cargo -p nexus | PRODUCT.md#remote | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.daemon-real-host-flow | v9-connectivity | cargo -p nexus | PRODUCT.md#remote | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.daemon-real-relay-flow | v9-connectivity | cargo -p nexus | PRODUCT.md#remote | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.daemon-real-socks-proxy-flow | v9-connectivity | cargo -p nexus | PRODUCT.md#11-proxy-kernel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.daemon-rejects-unknown-resource | v9-connectivity | cargo -p nexus | PRODUCT.md#remote | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.daemon-run-remote-service-flow | v9-connectivity | cargo -p nexus | PRODUCT.md#remote | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.daemon-run-with-command | v9-connectivity | cargo -p nexus | PRODUCT.md#16-n2-resource-access | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.daemon-run-workspace-flow | v9-connectivity | cargo -p nexus | PRODUCT.md#remote | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.daemon-tun-dataplane | v9-connectivity | cargo -p nexus | PRODUCT.md#12-daemon-tun-dataplane | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.daemon-workspace-mount | n1-fabric | cargo -p nexusd | v9#22 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.dataplane-unified | n1-fabric | cargo -p nexusd | DAEMON_ARCHITECTURE.md#6 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.decentralized-join-config | v9-connectivity | cargo -p nexus | PRODUCT.md#12-decentralized-join-config | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.dijkstra-fib | v9-connectivity | cargo -p nexus | PRODUCT.md#12-dijkstra-fib | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.discovery-enhanced | v9-connectivity | cargo -p nexus | PRODUCT.md#12-discovery-enhanced | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.discovery-mdns | v9-connectivity | cargo -p nexus | DESIGN.md#8.2 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.discovery-static | v9-connectivity | cargo -p nexus | DESIGN.md#8.2 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.disjoint | v9-connectivity | cargo -p nexus | PRODUCT.md#12-disjoint | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.dns-degradation | n1-fabric | cargo -p nexusd | DAEMON_ARCHITECTURE.md#10 | unrecorded |
| product.dns-exit-binding | v9-connectivity | cargo -p nexus | PRODUCT.md#network | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.dns-fake-ip-aaaa-nodata | n1-fabric | cargo -p nexusd | DAEMON_ARCHITECTURE.md#10 | unrecorded |
| product.dns-fake-ip-roundtrip | n1-fabric | cargo -p nexusd | DAEMON_ARCHITECTURE.md#10 | unrecorded |
| product.dns-ipcidr-rule | v9-connectivity | cargo -p nexus | PRODUCT.md#11-proxy-kernel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.dns-mesh-names | n1-fabric | cargo -p nexusd | DAEMON_ARCHITECTURE.md#10 | unrecorded |
| product.dns-rule-server-selection | v9-connectivity | cargo -p nexus | PRODUCT.md#11-dns | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.dns-unified | n1-fabric | nexus-harness run | DAEMON_ARCHITECTURE.md#10 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.dns-upstream-real | n1-fabric | cargo -p nexusd | DAEMON_ARCHITECTURE.md#10 | unrecorded |
| product.ecmp | v9-connectivity | cargo -p nexus | PRODUCT.md#12-ecmp | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.fabric-conn-basic | n1-fabric | cargo -p nexus-fabric | docs/foundation/DESIGN.md#3 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.fabric-conn-roam | n1-fabric | cargo -p nexus-fabric | docs/foundation/DESIGN.md#3 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.fabric-egress-basic | n1-fabric | cargo -p nexus-projection | docs/foundation/DESIGN.md#6.4 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.fabric-egress-domain | n1-fabric | cargo -p nexus-projection | docs/foundation/DESIGN.md#6.4 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.fabric-egress-real-udp | n1-fabric | cargo -p nexus-projection | docs/foundation/DESIGN.md#6.4 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.fabric-egress-remote | n1-fabric | cargo -p nexus-projection | docs/foundation/DESIGN.md#6.4 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.fabric-egress-tcp | n1-fabric | cargo -p nexus-projection | docs/foundation/DESIGN.md#6.4 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.fabric-mutual-auth | n1-fabric | cargo -p nexus-fabric | PRODUCT.md#17-n3-task | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.fabric-over-proxy | n1-fabric | cargo -p nexusd | docs/foundation/DESIGN.md#3.5 fabric-over-proxy | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.fabric-path-basic | n1-fabric | cargo -p nexus-path | docs/foundation/DESIGN.md#4 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.fabric-path-rebind | n1-fabric | cargo -p nexus-projection | docs/foundation/DESIGN.md#4 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.fabric-path-roam | n1-fabric | cargo -p nexus-path | docs/foundation/DESIGN.md#4 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.fabric-process-qos | n1-fabric | cargo -p nexus-projection | docs/foundation/DESIGN.md#6.3 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.fabric-projection-basic | n1-fabric | cargo -p nexus-projection | docs/foundation/DESIGN.md#6 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.fabric-projection-roam | n1-fabric | cargo -p nexus-projection | docs/foundation/DESIGN.md#6 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.fabric-semantic-ingress | n1-fabric | cargo -p nexus-projection | docs/foundation/DESIGN.md#6.2 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.fabric-tun-device | n1-fabric | cargo -p nexus-projection | docs/foundation/DESIGN.md#6.4 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.fabric-turn-relay | n1-fabric | cargo -p nexus-turn | docs/foundation/DESIGN.md#4 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.failover | v9-connectivity | cargo -p nexus | PRODUCT.md#12-failover | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.failover-health | v9-connectivity | cargo -p nexus | PRODUCT.md#12-failover-health | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.fib-forwarding | v9-connectivity | cargo -p nexus | PRODUCT.md#12.56-fib-forwarding | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.fib-manager | v9-connectivity | cargo -p nexus | PRODUCT.md#12-fib-manager | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.fib-manager-shared | v9-connectivity | cargo -p nexus | PRODUCT.md#12.54-fib-manager-shared | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.firewall-rules | v9-connectivity | nexus-harness run | PRODUCT.md#12-firewall-rules | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.flow-hash | v9-connectivity | cargo -p nexus | PRODUCT.md#12-flow-hash | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.flow-session-mapping | n1-fabric | cargo -p nexusd | PRODUCT.md#tun-ingress-session-chain | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.fragmentation | v9-connectivity | cargo -p nexus | PRODUCT.md#12-fragmentation | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.geoip-nex-roundtrip | v9-connectivity | cargo -p nexus | PRODUCT.md#11-proxy-kernel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.geoip-source-ip2region | v9-connectivity | cargo -p nexus | PRODUCT.md#11-proxy-kernel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.geosite-nex-roundtrip | v9-connectivity | cargo -p nexus | PRODUCT.md#11-proxy-kernel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.graceful-exit | v9-connectivity | cargo -p nexus | PRODUCT.md#12-graceful-exit | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.graceful-exit-real | v9-connectivity | cargo -p nexus | PRODUCT.md#12-graceful-exit-real | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.group-isolation | v9-connectivity | cargo -p nexus | PRODUCT.md#12-group-isolation | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.health-check | v9-connectivity | cargo -p nexus | PRODUCT.md#12-health-check | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.health-check-real | v9-connectivity | cargo -p nexus | PRODUCT.md#12-health-check-real | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.hole-punch-multi | v9-connectivity | cargo -p nexus | PRODUCT.md#12-holepunch-multi | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.identity-auto-exchange | v9-connectivity | cargo -p nexus | PRODUCT.md#12-identity-auto-exchange | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.internet-access-flow | v9-connectivity | cargo -p nexus | PRODUCT.md#network | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.ipv6-dataplane | n1-fabric | cargo -p nexusd | DAEMON_ARCHITECTURE.md#6 | unrecorded |
| product.ipv6-tcp-termination | n1-fabric | cargo -p nexusd | DAEMON_ARCHITECTURE.md#10 | unrecorded |
| product.k-shortest | v9-connectivity | cargo -p nexus | PRODUCT.md#12-k-shortest | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.link-encryption | v9-connectivity | cargo -p nexus | PRODUCT.md#remote | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.log-level | v9-connectivity | cargo -p nexus | PRODUCT.md#12-log-level | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.lsa-discovery | v9-connectivity | cargo -p nexus | PRODUCT.md#12-lsa-discovery | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.mesh-dns | v9-connectivity | nexus-harness run | PRODUCT.md#12-mesh-dns | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.multihop-routing | v9-connectivity | nexus-harness run | PRODUCT.md#12-multihop-routing | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.multipath | n1-fabric | nexus-harness run | docs/DAEMON_ARCHITECTURE.md#12.6 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.multipath-quic-seq | n1-fabric | cargo -p nexus-projection | GAP-2 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n1-connectivity-roam | n1-fabric | cargo -p nexus-network | v9 §1/§8/§10/§12 N1 Universal Connectivity；白皮书 §6；M1–M7 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n1-connectivity-roam-realnet | n1-fabric | cargo -p nexus-network | v9 §1/§8/§10/§12 N1 Universal Connectivity；白皮书 §6；M1–M7；用户关键验收场景（2026-09-29） | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n1-wireup | n1-fabric | cargo -p nexusd | apps/nexusd/MODULE.md#W1-W4 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n2-grant-deny-audit | v9-connectivity | cargo -p nexus | PRODUCT.md#16-n2-resource-access | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n2-grant-expired-deny | v9-connectivity | cargo -p nexus | PRODUCT.md#16-n2-resource-access | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n2-plan-explain-estimate | v9-connectivity | cargo -p nexus | PRODUCT.md#16-n2-resource-access | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n2-plan-explain-history | v9-connectivity | cargo -p nexus | PRODUCT.md#16-n2-resource-access | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n2-plan-preview | v9-connectivity | cargo -p nexus | PRODUCT.md#16-n2-resource-access | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n2-plan-unknown-not-found | v9-connectivity | cargo -p nexus | PRODUCT.md#16-n2-resource-access | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n2-provider-offline | v9-connectivity | cargo -p nexus | PRODUCT.md#16-n2-resource-access | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n2-resource-list | v9-connectivity | cargo -p nexus | PRODUCT.md#16-n2-resource-access | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n2-resource-publish | v9-connectivity | cargo -p nexus | PRODUCT.md#16-n2-resource-access | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n2-resource-revoke | v9-connectivity | cargo -p nexus | PRODUCT.md#16-n2-resource-access | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n2-resource-show | v9-connectivity | cargo -p nexus | PRODUCT.md#16-n2-resource-access | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n2-revoked-resource-unusable | v9-connectivity | cargo -p nexus | PRODUCT.md#16-n2-resource-access | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n2-session-close | v9-connectivity | cargo -p nexus | PRODUCT.md#16-n2-resource-access | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n2-session-list | v9-connectivity | cargo -p nexus | PRODUCT.md#16-n2-resource-access | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n2-session-watch | v9-connectivity | cargo -p nexus | PRODUCT.md#16-n2-resource-access | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n2-session-watch-not-found | v9-connectivity | cargo -p nexus | PRODUCT.md#16-n2-resource-access | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n2-use-loop | v9-connectivity | cargo -p nexus | PRODUCT.md#16-n2-resource-access | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n2-use-probe-honesty | v9-connectivity | cargo -p nexus | PRODUCT.md#16-n2-resource-access | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n2-use-rejects-command | v9-connectivity | cargo -p nexus | PRODUCT.md#16-n2-resource-access | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n2-use-unknown-not-found | v9-connectivity | cargo -p nexus | PRODUCT.md#16-n2-resource-access | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n3-10-operator-grant | external | python3 | PRODUCT.md#177-n3-10 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n3-11-provider-init | external | python3 | PRODUCT.md#178-n3-11 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n3-12-snapshot-staging | external | python3 | PRODUCT.md#179-n3-12 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n3-8-foundation-boundary | external | python3 | PRODUCT.md#175-n3-8 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n3-9-artifact-cli | external | python3 | PRODUCT.md#176-n3-9 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n3-acceptance-crash | n1-fabric | cargo -p nexusd | PRODUCT.md#17-n3-task | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n3-artifact-integrity | n1-fabric | cargo -p nexusd | PRODUCT.md#17-n3-task | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n3-artifact-missing | n1-fabric | cargo -p nexusd | PRODUCT.md#17-n3-task | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n3-artifact-resume | n1-fabric | cargo -p nexusd | PRODUCT.md#17-n3-task | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n3-authorization | n1-fabric | cargo -p nexusd | PRODUCT.md#17-n3-task | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n3-cancel-pending | n1-fabric | cargo -p nexusd | PRODUCT.md#17-n3-task | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n3-cancel-race | n1-fabric | cargo -p nexusd | PRODUCT.md#17-n3-task | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n3-client-reattach | n1-fabric | cargo -p nexusd | PRODUCT.md#17-n3-task | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n3-crash-reconcile | n1-fabric | cargo -p nexusd | PRODUCT.md#17-n3-task | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n3-environment-mismatch | n1-fabric | cargo -p nexusd | PRODUCT.md#17-n3-task | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n3-gc-roots | n1-fabric | cargo -p nexusd | PRODUCT.md#17-n3-task | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n3-idempotency | n1-fabric | cargo -p nexusd | PRODUCT.md#17-n3-task | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n3-idempotency-conflict | n1-fabric | cargo -p nexusd | PRODUCT.md#17-n3-task | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n3-idempotency-expiry | n1-fabric | cargo -p nexusd | PRODUCT.md#17-n3-task | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n3-input-integrity | n1-fabric | cargo -p nexusd | PRODUCT.md#17-n3-task | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n3-localapi-v1-boundary | n1-fabric | cargo -p nexusd | PRODUCT.md#17-n3-task | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n3-log-limit | n1-fabric | cargo -p nexusd | PRODUCT.md#17-n3-task | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n3-nonzero-exit | n1-fabric | cargo -p nexusd | PRODUCT.md#17-n3-task | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n3-path-safety | n1-fabric | cargo -p nexusd | PRODUCT.md#17-n3-task | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n3-snapshot-immutable | n1-fabric | cargo -p nexusd | PRODUCT.md#17-n3-task | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n3-submit | n1-fabric | cargo -p nexusd | PRODUCT.md#17-n3-task | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n3-timeout | n1-fabric | cargo -p nexusd | PRODUCT.md#17-n3-task | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.n3-unsupported-isolation | n1-fabric | cargo -p nexusd | PRODUCT.md#17-n3-task | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.node-disjoint | v9-connectivity | cargo -p nexus | PRODUCT.md#12.55-node-disjoint | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.node-priority | v9-connectivity | cargo -p nexus | PRODUCT.md#12-node-priority | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.node-tags | v9-connectivity | cargo -p nexus | PRODUCT.md#12-node-tags | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.observability-compute-jobs | v9-connectivity | cargo -p nexus | PRODUCT.md#9-observability | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.observability-connectivity-candidates | v9-connectivity | cargo -p nexus | PRODUCT.md#9-observability | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.observability-connectivity-links | v9-connectivity | cargo -p nexus | PRODUCT.md#9-observability | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.observability-connectivity-probe | v9-connectivity | cargo -p nexus | PRODUCT.md#9-observability | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.observability-diagnose | v9-connectivity | cargo -p nexus | PRODUCT.md#9-observability | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.observability-dns-cache | n1-fabric | cargo -p nexusd | PRODUCT.md#9-observability | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.observability-dns-providers | v9-connectivity | cargo -p nexus | PRODUCT.md#9-observability | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.observability-dns-resolve | v9-connectivity | cargo -p nexus | PRODUCT.md#9-observability | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.observability-plan-explain | n1-fabric | cargo -p nexusd | PRODUCT.md#9-observability | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.observability-session-watch | n1-fabric | cargo -p nexusd | PRODUCT.md#9-observability | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.observability-status | n1-fabric | cargo -p nexusd | PRODUCT.md#9-observability | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.observability-unsupported | v9-connectivity | cargo -p nexus | PRODUCT.md#9-observability | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.observability-workspace-cache | v9-connectivity | cargo -p nexus | PRODUCT.md#9-observability | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.observability-workspace-conflicts | v9-connectivity | cargo -p nexus | PRODUCT.md#9-observability | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.observability-workspace-heads | v9-connectivity | cargo -p nexus | PRODUCT.md#9-observability | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.outbound-reload-restore | n1-fabric | cargo -p nexusd | apps/nexusd/MODULE.md#统一数据面装配 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.outbound-warning-config-check | n1-fabric | cargo -p nexusd | apps/nexus/MODULE.md#出站-interop-标注步骤-3 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.outbound-warning-status | n1-fabric | cargo -p nexusd | apps/nexusd/MODULE.md#出站-interop-标注五载体步骤-3spec-v14-5253542026-10-26 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.pairing | v9-connectivity | cargo -p nexus | .agents/plans/pairing-plan.md | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.path-fallback | n1-fabric | cargo -p nexus-path | docs/foundation/DESIGN.md#3.5 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.path-fallback-skip | n1-fabric | cargo -p nexus-path | docs/foundation/DESIGN.md#3.5 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.path-predict-ewma | n1-fabric | cargo -p nexus-path | docs/foundation/DESIGN.md#4.6 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.path-race | n1-fabric | cargo -p nexus-path | docs/foundation/DESIGN.md#4.4 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.peer-source-wiring | n1-fabric | cargo -p nexusd | spec §7 AC16 / §4.2 / §4.4.2 / §4.5.1 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.performance-benchmark | v9-connectivity | cargo -p nexus | PRODUCT.md#12-perf-benchmark | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.pipeline-compression | v9-connectivity | cargo -p nexus | PRODUCT.md#12-dataplane-pipeline | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.pipeline-firewall | v9-connectivity | cargo -p nexus | PRODUCT.md#12-dataplane-pipeline | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.pipeline-fragmentation | v9-connectivity | cargo -p nexus | PRODUCT.md#12-dataplane-pipeline | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.pipeline-qos | v9-connectivity | cargo -p nexus | PRODUCT.md#12-dataplane-pipeline | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.plugin-dial-ss | v9-connectivity | cargo -p nexus | docs/foundation/DESIGN.md#7.3 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.plugin-dial-unknown | v9-connectivity | cargo -p nexus | docs/foundation/DESIGN.md#7.3 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.plugin-obfs-echo | n1-fabric | cargo -p nexus-plugin | docs/foundation/DESIGN.md#7 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.provider-derivation | n1-fabric | cargo -p nexusd | PRODUCT.md#11-tun-transparent-inbound | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-clash-subscription-parse | v9-connectivity | cargo -p nexus | PRODUCT.md#11-proxy-kernel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-default-match | v9-connectivity | cargo -p nexus | PRODUCT.md#11-proxy-kernel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-engine-stage-json | n1-fabric | cargo -p nexusd | apps/nexusd/MODULE.md#统一数据面装配 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-engine-unsupported-outbound | n1-fabric | cargo -p nexusd | apps/nexusd/MODULE.md#统一数据面装配 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-extended-rules | v9-connectivity | cargo -p nexus | PRODUCT.md#11-proxy-kernel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-fwd | n1-fabric | cargo -p nexusd | apps/nexusd/MODULE.md#proxy-fwd | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-fwd-fail-closed | n1-fabric | cargo -p nexusd | apps/nexusd/MODULE.md#proxy-fwd | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-fwd-trojan-plaintext-rejected | n1-fabric | cargo -p nexusd | apps/nexusd/MODULE.md#proxy-fwd | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-fwd-trojan-tls-engine | n1-fabric | cargo -p nexusd | apps/nexusd/MODULE.md#proxy-fwd | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-fwd-tun-production | n1-fabric | cargo -p nexusd | apps/nexusd/MODULE.md#proxy-fwd | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-fwd-udp-unsupported | n1-fabric | cargo -p nexusd | apps/nexusd/MODULE.md#proxy-fwd | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-fwd-udp-vless-anytls | n1-fabric | cargo -p nexusd | PRODUCT.md#11-tun-proxy-udp | unrecorded |
| product.proxy-geoip-rule | v9-connectivity | cargo -p nexus | PRODUCT.md#11-proxy-kernel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-geosite-rule | v9-connectivity | cargo -p nexus | PRODUCT.md#11-proxy-kernel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-http-mixed-inbound | v9-connectivity | cargo -p nexus | PRODUCT.md#11-proxy-kernel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-ipcidr-rule-match | v9-connectivity | cargo -p nexus | PRODUCT.md#11-proxy-kernel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-loadbalance-group | v9-connectivity | cargo -p nexus | PRODUCT.md#11-proxy-kernel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-outbound-shadowsocks-flow | v9-connectivity | cargo -p nexus | PRODUCT.md#11-proxy-kernel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-outbound-trojan-flow | v9-connectivity | cargo -p nexus | PRODUCT.md#11-proxy-kernel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-outbound-vless-flow | v9-connectivity | cargo -p nexus | PRODUCT.md#11-vless-dataplane | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-redaction-parity | n1-fabric | cargo -p nexusd | PRODUCT.md#11-proxy-kernel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-relay-group | v9-connectivity | cargo -p nexus | PRODUCT.md#11-proxy-kernel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-rule-invalid | v9-connectivity | cargo -p nexus | PRODUCT.md#11-proxy-kernel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-rule-provider-fetch | v9-connectivity | cargo -p nexus | PRODUCT.md#11-proxy-kernel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-rule-provider-fetch-https | v9-connectivity | cargo -p nexus | PRODUCT.md#11-proxy-kernel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-rule-set | v9-connectivity | cargo -p nexus | PRODUCT.md#11-proxy-kernel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-selector-group | v9-connectivity | cargo -p nexus | PRODUCT.md#11-proxy-kernel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-shadowsocks-adapter | v9-connectivity | cargo -p nexus | PRODUCT.md#11-proxy-kernel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-shadowsocks-real-tcp | v9-connectivity | cargo -p nexus | PRODUCT.md#11-proxy-kernel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-socks5-domain-rule-forward | v9-connectivity | cargo -p nexus | PRODUCT.md#11-proxy-kernel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-speedtest | v9-connectivity | cargo -p nexus | PRODUCT.md#11-proxy-kernel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-speedtest-http204 | v9-connectivity | cargo -p nexus | PRODUCT.md#11-proxy-kernel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-speedtest-http204-bad-status | v9-connectivity | cargo -p nexus | PRODUCT.md#11-proxy-kernel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-speedtest-http204-loopback | v9-connectivity | cargo -p nexus | PRODUCT.md#11-proxy-kernel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-speedtest-loopback | v9-connectivity | cargo -p nexus | PRODUCT.md#11-proxy-kernel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-subscription-online-update | v9-connectivity | cargo -p nexus | PRODUCT.md#11-proxy-kernel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-transport | n1-fabric | cargo -p nexus-proxy-transport | docs/foundation/DESIGN.md#3.5 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-transport-ss | n1-fabric | cargo -p nexus-proxy-transport | docs/foundation/DESIGN.md#3.5 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-transport-trojan | n1-fabric | cargo -p nexus-proxy-transport | docs/foundation/DESIGN.md#3.5 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-transport-trojan-tls | n1-fabric | cargo -p nexus-proxy-transport | docs/foundation/DESIGN.md#3.5 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-trojan-adapter | v9-connectivity | cargo -p nexus | PRODUCT.md#11-trojan | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-trojan-auth-rejected | v9-connectivity | cargo -p nexus | PRODUCT.md#11-trojan | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-trojan-fallback-rejected | v9-connectivity | cargo -p nexus | PRODUCT.md#11-proxy-kernel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-trojan-header-format | v9-connectivity | cargo -p nexus | PRODUCT.md#11-trojan-header-format | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-trojan-node-config | v9-connectivity | cargo -p nexus | PRODUCT.md#11-trojan-node-config | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-trojan-real-tls-params | v9-connectivity | cargo -p nexus | PRODUCT.md#11-trojan-real-tls | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-tun-inbound | v9-connectivity | cargo -p nexus | PRODUCT.md#11-tun-transparent-inbound | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-urltest-group | v9-connectivity | cargo -p nexus | PRODUCT.md#11-proxy-kernel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.proxy-vmess-adapter | v9-connectivity | cargo -p nexus | PRODUCT.md#11-proxy-kernel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.psk-handshake-admission | v9-connectivity | cargo -p nexus | PRODUCT.md#12-psk-admission | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.qos-cake | shared-leaf | nexus-harness run | docs/DAEMON_ARCHITECTURE.md#11 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.qos-cake-enabled-path | n1-fabric | cargo -p nexusd | docs/DAEMON_ARCHITECTURE.md#11.5 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.relay-fallback | v9-connectivity | cargo -p nexus | PRODUCT.md#remote | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.remote-compute-job-flow | v9-connectivity | cargo -p nexus | PRODUCT.md#remote | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.remote-compute-rejected-rollback | v9-connectivity | cargo -p nexus | PRODUCT.md#remote | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.remote-connectivity-failure-rollback | v9-connectivity | cargo -p nexus | PRODUCT.md#remote | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.remote-internet-access-flow | v9-connectivity | cargo -p nexus | PRODUCT.md#remote | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.remote-nat-relay-fallback-flow | v9-connectivity | cargo -p nexus | PRODUCT.md#remote | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.remote-network-auth-rejected-rollback | v9-connectivity | cargo -p nexus | PRODUCT.md#remote | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.remote-presence-dynamic-flow | v9-connectivity | cargo -p nexus | PRODUCT.md#remote | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.remote-presence-expired-rollback | v9-connectivity | cargo -p nexus | PRODUCT.md#remote | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.remote-presence-network-discovery-flow | v9-connectivity | cargo -p nexus | PRODUCT.md#remote | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.remote-presence-network-unknown-rollback | v9-connectivity | cargo -p nexus | PRODUCT.md#remote | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.remote-relay-unavailable-rollback | v9-connectivity | cargo -p nexus | PRODUCT.md#remote | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.remote-service-access-flow | v9-connectivity | cargo -p nexus | PRODUCT.md#remote | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.remote-workspace-commit-flow | v9-connectivity | cargo -p nexus | PRODUCT.md#remote | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.remote-workspace-rejected-rollback | v9-connectivity | cargo -p nexus | PRODUCT.md#remote | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.resource-session-lifecycle | v9-connectivity | cargo -p nexus | PRODUCT.md#session | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.routing-strategy | v9-connectivity | cargo -p nexus | PRODUCT.md#12-routing-strategy | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.schedule-cli | v9-connectivity | cargo -p nexus | PRODUCT.md#14-schedule | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.schedule-cli-reachable | v9-connectivity | cargo -p nexus | PRODUCT.md#14-schedule | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.schedule-flow | v9-connectivity | cargo -p nexus | PRODUCT.md#14-schedule | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.secure-state | v9-connectivity | cargo -p nexus | PRODUCT.md#12-secure-state | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.secure-store | v9-connectivity | cargo -p nexus | PRODUCT.md#12-secure-store | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.smart-retry | v9-connectivity | cargo -p nexus | PRODUCT.md#12-smart-retry | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.smart-retry-real | v9-connectivity | cargo -p nexus | PRODUCT.md#12-smart-retry-real | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.socks5-handshake | v9-connectivity | cargo -p nexus | PRODUCT.md#network | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.strategy-extended | v9-connectivity | cargo -p nexus | PRODUCT.md#12.53-strategy-extended | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.strategy-hot-reload | v9-connectivity | cargo -p nexus | PRODUCT.md#12.58-strategy-hot-reload | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.strategy-watcher | v9-connectivity | cargo -p nexus | PRODUCT.md#12.58-strategy-hot-reload | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.subnet-daemon | v9-connectivity | cargo -p nexus | PRODUCT.md#12-subnet-daemon | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.subnet-punch-cli | v9-connectivity | cargo -p nexus | PRODUCT.md#12-punch-cli | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.subnet-punch-status | v9-connectivity | cargo -p nexus | PRODUCT.md#12-punch-cli | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.tproxy-capture-failure | n1-fabric | cargo -p nexusd | PRODUCT.md#11-tun-transparent-inbound | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.tproxy-inbound-linux | n1-fabric | cargo -p nexusd | PRODUCT.md#11-tun-transparent-inbound | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.traffic-stats | v9-connectivity | cargo -p nexus | PRODUCT.md#12-traffic-stats | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.transparent-rule-consistency | n1-fabric | cargo -p nexusd | PRODUCT.md#11-tun-transparent-inbound | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.tun-dataplane | v9-connectivity | cargo -p nexus | PRODUCT.md#12-tun-dataplane | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.tun-flow-sessions-auto | n1-fabric | cargo -p nexusd | PRODUCT.md#11-tun-transparent-inbound | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.tun-os-assemble | n1-fabric | cargo -p nexusd | PRODUCT.md#11-tun-transparent-inbound | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.tun-outbound-anytls-flow | external | scripts/e4/tun_outbound_ref_flow.sh | apps/nexusd/MODULE.md#proxy-fwd | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.tun-outbound-shadowsocks-flow | external | scripts/e4/tun_outbound_ref_flow.sh | apps/nexusd/MODULE.md#proxy-fwd | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.tun-outbound-vless-flow | external | scripts/e4/tun_outbound_ref_flow.sh | apps/nexusd/MODULE.md#proxy-fwd | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.tun-production-chain | n1-fabric | cargo -p nexusd | PRODUCT.md#11-tun-transparent-inbound | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.turn-relay-allocate | v9-connectivity | cargo -p nexus | PRODUCT.md#12-turn | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.unified-classifier | n1-fabric | cargo -p nexus-projection | docs/DAEMON_ARCHITECTURE.md#12.5 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.virtual-subnet-encrypted-3node | v9-connectivity | cargo -p nexus | PRODUCT.md#12-virtual-subnet-networking | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.virtual-subnet-holepunch | v9-connectivity | cargo -p nexus | PRODUCT.md#12-holepunch-tunnel | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.virtual-subnet-mesh-3node | v9-connectivity | nexus-harness run | PRODUCT.md#12-static-routing | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.virtual-subnet-nat-probe | v9-connectivity | cargo -p nexus | PRODUCT.md#12-nat-probe | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.virtual-subnet-tunnel | v9-connectivity | nexus-harness run | PRODUCT.md#12-virtual-subnet-networking | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.weighted-selection | v9-connectivity | cargo -p nexus | PRODUCT.md#12.52-weighted-selection | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.workspace-authority-v2 | n1-fabric | cargo -p nexus-workspace | v9 §17/§18 + requirement-change workspace-authority-v2 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.workspace-cache-eviction | n1-fabric | cargo -p nexus-workspace | v9#22 | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.workspace-gc | n1-fabric | cargo -p nexus-workspace | v9 §20 Workspace DAG Compaction、Shallow Sync 与 CAS GC | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.workspace-intel | v9-connectivity | cargo -p nexus | v9 §21 Workspace Intelligence | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.workspace-offline-merge | n1-fabric | cargo -p nexus-workspace | PRODUCT.md#workspace | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.workspace-shallow-sparse | n1-fabric | cargo -p nexus-workspace | v9 §20 Shallow Metadata Sync / Sparse Replica / On-demand Deepening | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.workspace-sync-authz | n1-fabric | cargo -p nexusd | 白皮书 §成员与策略权威 + C2-D4（serve_sync 前置成员授权；第一版静态成员列表；未授权返回明确拒绝帧） | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.workspace-sync-basic | n1-fabric | cargo -p nexusd | v9 §17/§18 + C2-D1/D2/D3（fabric QUIC bi-stream 承载，复用 active_conn，STREAM_TYPE_WORKSPACE_SYNC=0x03） | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.workspace-sync-conflict-converge | n1-fabric | cargo -p nexusd | v9 §18 + C2-D7（先 resolve 者赢；协议传播 resolution；conflict-state 交换帧；禁止双端各解各的） | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.workspace-sync-over-race-path | n1-fabric | cargo -p nexusd | v9 §17/§18 + C2-D1（复用 NatSwitching::active_conn 当前优选连接；路径竞速对 sync 透明，Identity≠Locator） | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.workspace-sync-resume | n1-fabric | cargo -p nexusd | v9 §17/§18 + C2-D5（OBJECT-DATA 去 hex 改二进制分块 OBJECT-CHUNK/OBJECT-END）+ C2-D6（非原子、幂等、可续；fetch 每批 persist） | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| product.workspace-sync-shallow-sparse | n1-fabric | cargo -p nexusd | v9 §20 + C2-P4（HEADS 携带 replica policy/depth/sparse filter；WANT-COMMITS 按 depth 截断 BFS；sparse 只拉指定路径对象） | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| regression.crash-recovery | n1-fabric | cargo -p nexus-workspace | (none) | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
| regression.session-outcome-exactly-once | n1-fabric | cargo -p nexus-session | (none) | cd60989394be2c939cabfc74ecbbc25c81b8b8e4 |
<!-- index-rows-end -->

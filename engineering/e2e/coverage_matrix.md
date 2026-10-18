# E2E 覆盖矩阵（PRODUCT 锚点 × 场景）

生成时间：2026-10-18T16:14:58  run_id=20261018-161449
场景总数：277（product-scenarios 门禁子目录 product+engineering+platform：275）  PRODUCT 锚点总数：97

| PRODUCT 锚点 | 覆盖场景数 | 场景 IDs |
|---|---:|---|
| `11-clash-subscription-parse` | 0 | — 无覆盖 — |
| `11-dns` | 1 | product.dns-rule-server-selection |
| `11-dns-ipcidr` | 0 | — 无覆盖 — |
| `11-geoip-geosite-providers` | 0 | — 无覆盖 — |
| `11-geosite-nex` | 0 | — 无覆盖 — |
| `11-http-mixed-inbound` | 0 | — 无覆盖 — |
| `11-outbound-adapter` | 0 | — 无覆盖 — |
| `11-outbound-tunnel-dataplane` | 0 | — 无覆盖 — |
| `11-proxy-kernel` | 32 | product.daemon-real-socks-proxy-flow, product.dns-ipcidr-rule, product.geoip-nex-roundtrip, product.geoip-source-ip2region, product.geosite-nex-roundtrip, product.proxy-clash-subscription-parse, product.proxy-default-match, product.proxy-extended-rules, product.proxy-geoip-rule, product.proxy-geosite-rule, product.proxy-http-mixed-inbound, product.proxy-ipcidr-rule-match, product.proxy-loadbalance-group, product.proxy-outbound-shadowsocks-flow, product.proxy-outbound-trojan-flow, product.proxy-relay-group, product.proxy-rule-invalid, product.proxy-rule-provider-fetch, product.proxy-rule-provider-fetch-https, product.proxy-rule-set, product.proxy-selector-group, product.proxy-shadowsocks-adapter, product.proxy-shadowsocks-real-tcp, product.proxy-socks5-domain-rule-forward, product.proxy-speedtest, product.proxy-speedtest-http204, product.proxy-speedtest-http204-bad-status, product.proxy-speedtest-http204-loopback, product.proxy-speedtest-loopback, product.proxy-subscription-online-update, product.proxy-urltest-group, product.proxy-vmess-adapter |
| `11-public-datasource-plugin` | 0 | — 无覆盖 — |
| `11-rule-provider-https` | 0 | — 无覆盖 — |
| `11-rule-providers-online` | 0 | — 无覆盖 — |
| `11-shadowsocks-real-tcp` | 0 | — 无覆盖 — |
| `11-speedtest` | 0 | — 无覆盖 — |
| `11-subscription-update` | 0 | — 无覆盖 — |
| `11-trojan` | 2 | product.proxy-trojan-adapter, product.proxy-trojan-auth-rejected |
| `11-trojan-header-format` | 1 | product.proxy-trojan-header-format |
| `11-trojan-node-config` | 1 | product.proxy-trojan-node-config |
| `11-trojan-real-tls` | 1 | product.proxy-trojan-real-tls-params |
| `11-tun-transparent-inbound` | 1 | product.proxy-tun-inbound |
| `11-vmess` | 0 | — 无覆盖 — |
| `12-auto-reconnect` | 1 | product.auto-reconnect |
| `12-bandwidth-policy` | 1 | product.bandwidth-policy |
| `12-bandwidth-qos` | 1 | product.bandwidth-qos |
| `12-bench-gate` | 1 | engineering.bench-gate-verdicts |
| `12-certificate-manager` | 1 | product.certificate-manager |
| `12-compression` | 1 | product.compression |
| `12-config-hot-reload` | 1 | product.config-hot-reload |
| `12-config-hot-reload-real` | 1 | product.config-hot-reload-watch |
| `12-connection-pool` | 1 | product.connection-pool |
| `12-connection-pool-real` | 1 | product.connection-pool-real |
| `12-coord` | 2 | product.coord-core, product.coord-join-loopback |
| `12-cross-subnet` | 1 | product.cross-subnet |
| `12-daemon-tun-dataplane` | 1 | product.daemon-tun-dataplane |
| `12-dataplane-pipeline` | 4 | product.pipeline-compression, product.pipeline-firewall, product.pipeline-fragmentation, product.pipeline-qos |
| `12-decentralized-join-config` | 1 | product.decentralized-join-config |
| `12-dijkstra-fib` | 1 | product.dijkstra-fib |
| `12-discovery-enhanced` | 1 | product.discovery-enhanced |
| `12-disjoint` | 1 | product.disjoint |
| `12-ecmp` | 1 | product.ecmp |
| `12-encryption` | 0 | — 无覆盖 — |
| `12-failover` | 1 | product.failover |
| `12-failover-health` | 1 | product.failover-health |
| `12-fib-manager` | 1 | product.fib-manager |
| `12-firewall-rules` | 1 | product.firewall-rules |
| `12-flow-hash` | 1 | product.flow-hash |
| `12-fragmentation` | 1 | product.fragmentation |
| `12-graceful-exit` | 1 | product.graceful-exit |
| `12-graceful-exit-real` | 1 | product.graceful-exit-real |
| `12-group-isolation` | 1 | product.group-isolation |
| `12-health-check` | 1 | product.health-check |
| `12-health-check-real` | 1 | product.health-check-real |
| `12-holepunch-multi` | 1 | product.hole-punch-multi |
| `12-holepunch-tunnel` | 1 | product.virtual-subnet-holepunch |
| `12-identity-auto-exchange` | 1 | product.identity-auto-exchange |
| `12-k-shortest` | 1 | product.k-shortest |
| `12-log-level` | 1 | product.log-level |
| `12-lsa-discovery` | 1 | product.lsa-discovery |
| `12-mesh-dns` | 1 | product.mesh-dns |
| `12-multihop-routing` | 1 | product.multihop-routing |
| `12-nat-path` | 1 | product.path-decision |
| `12-nat-probe` | 1 | product.virtual-subnet-nat-probe |
| `12-node-priority` | 1 | product.node-priority |
| `12-node-tags` | 1 | product.node-tags |
| `12-os-assemble` | 1 | platform.os-assemble |
| `12-perf-benchmark` | 1 | product.performance-benchmark |
| `12-psk-admission` | 1 | product.psk-handshake-admission |
| `12-punch-cli` | 2 | product.subnet-punch-cli, product.subnet-punch-status |
| `12-realize-reliability` | 0 | — 无覆盖 — |
| `12-routing-strategy` | 1 | product.routing-strategy |
| `12-secure-state` | 1 | product.secure-state |
| `12-secure-store` | 1 | product.secure-store |
| `12-smart-retry` | 1 | product.smart-retry |
| `12-smart-retry-real` | 1 | product.smart-retry-real |
| `12-static-routing` | 1 | product.virtual-subnet-mesh-3node |
| `12-subnet-cli` | 1 | product.cli-subnet |
| `12-subnet-daemon` | 1 | product.subnet-daemon |
| `12-traffic-stats` | 1 | product.traffic-stats |
| `12-tun-dataplane` | 1 | product.tun-dataplane |
| `12-turn` | 1 | product.turn-relay-allocate |
| `12-virtual-subnet-networking` | 2 | product.virtual-subnet-encrypted-3node, product.virtual-subnet-tunnel |
| `13-system-proxy` | 1 | platform.windows-system-proxy |
| `14-schedule` | 3 | product.schedule-cli, product.schedule-cli-reachable, product.schedule-flow |
| `15-persist-recover` | 0 | — 无覆盖 — |
| `16-n2-resource-access` | 12 | product.daemon-run-with-command, product.n2-grant-deny-audit, product.n2-plan-preview, product.n2-provider-offline, product.n2-resource-list, product.n2-resource-publish, product.n2-resource-revoke, product.n2-resource-show, product.n2-session-close, product.n2-session-list, product.n2-session-watch, product.n2-use-loop |
| `17-n3-task` | 24 | product.fabric-mutual-auth, product.n3-acceptance-crash, product.n3-artifact-integrity, product.n3-artifact-missing, product.n3-artifact-resume, product.n3-authorization, product.n3-cancel-pending, product.n3-cancel-race, product.n3-client-reattach, product.n3-crash-reconcile, product.n3-environment-mismatch, product.n3-gc-roots, product.n3-idempotency-conflict, product.n3-idempotency-expiry, product.n3-idempotency, product.n3-input-integrity, product.n3-localapi-v1-boundary, product.n3-log-limit, product.n3-nonzero-exit, product.n3-path-safety, product.n3-snapshot-immutable, product.n3-submit, product.n3-timeout, product.n3-unsupported-isolation |
| `9-observability` | 24 | product.cli-compute-jobs, product.cli-connectivity-candidates, product.cli-connectivity-links, product.cli-connectivity-probe, product.cli-diagnose, product.cli-dns-providers, product.cli-dns-resolve, product.cli-workspace-cache, product.cli-workspace-conflicts, product.observability-compute-jobs, product.observability-connectivity-candidates, product.observability-connectivity-links, product.observability-connectivity-probe, product.observability-diagnose, product.observability-dns-cache, product.observability-dns-providers, product.observability-dns-resolve, product.observability-plan-explain, product.observability-session-watch, product.observability-status, product.observability-unsupported, product.observability-workspace-cache, product.observability-workspace-conflicts, product.observability-workspace-heads |
| `cli` | 1 | product.cli-run-command |
| `cross-platform` | 1 | platform.virtual-packet-interface |
| `devices` | 0 | — 无覆盖 — |
| `idempotency` | 0 | — 无覆盖 — |
| `network` | 4 | product.connectivity-carrier-split, product.dns-exit-binding, product.internet-access-flow, product.socks5-handshake |
| `observe-adapt` | 0 | — 无覆盖 — |
| `remote` | 24 | product.auto-discovery, product.daemon-real-host-auth-denied, product.daemon-real-host-flow, product.daemon-real-relay-flow, product.daemon-rejects-unknown-resource, product.daemon-run-remote-service-flow, product.daemon-run-workspace-flow, product.link-encryption, product.nat-hole-punching, product.relay-fallback, product.remote-compute-job-flow, product.remote-compute-rejected-rollback, product.remote-connectivity-failure-rollback, product.remote-internet-access-flow, product.remote-nat-relay-fallback-flow, product.remote-network-auth-rejected-rollback, product.remote-presence-dynamic-flow, product.remote-presence-expired-rollback, product.remote-presence-network-discovery-flow, product.remote-presence-network-unknown-rollback, product.remote-relay-unavailable-rollback, product.remote-service-access-flow, product.remote-workspace-commit-flow, product.remote-workspace-rejected-rollback |
| `session` | 2 | product.connectivity-failure-rollback, product.resource-session-lifecycle |
| `tun-ingress-session-chain` | 1 | product.flow-session-mapping |
| `workspace` | 3 | product.workspace-offline-merge, platform.workspace-projection-channels, platform.workspace-projection-fallback |

未映射到任何锚点的门禁场景数：72

未映射场景：product.boost-v1, product.bootstrap-join, product.composition-root, product.connectivity-evaluation, product.crash-recovery-boot-reconcile, product.daemon-workspace-mount, product.dataplane-unified, product.discovery-mdns, product.discovery-static, product.dns-unified, product.fabric-conn-basic, product.fabric-conn-roam, product.fabric-egress-basic, product.fabric-egress-domain, product.fabric-egress-real-udp, product.fabric-egress-remote, product.fabric-egress-tcp, product.fabric-path-basic, product.fabric-path-rebind, product.fabric-path-roam, product.fabric-process-qos, product.fabric-projection-basic, product.fabric-projection-roam, product.fabric-semantic-ingress, product.fabric-tun-device, product.fabric-turn-relay, product.fib-forwarding, product.fib-manager-shared, product.multipath, product.multipath-quic-seq, product.n1-connectivity-roam, product.n1-connectivity-roam-realnet, product.n1-wireup, product.n3-10-operator-grant, product.n3-8-foundation-boundary, product.n3-9-artifact-cli, product.node-disjoint, product.pairing, product.path-fallback, product.path-fallback-skip …

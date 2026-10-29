"""冻结命名（计划 §3.3）：枚举值 -> kebab 标签。禁止用通用大写拆词（AnyTls 会拆错）。"""
PROTOCOL = {
    "Vless": "vless",
    "Anytls": "anytls",
    "Hysteria2": "hysteria2",
    "Trojan": "trojan",
    "Shadowsocks": "shadowsocks",
}
VARIANT = {
    "Default": "default",
    "VlessVision": "vless-vision",
    "Hy2Salamander": "hy2-salamander",
    "TrojanFallback": "trojan-fallback",
    "AnyTlsCustomPadding": "anytls-custom-padding",
}
CELL = {
    "Handshake": "handshake",
    "TcpSmall": "tcp-small",
    "TcpThroughput": "tcp-throughput",
    "UdpEcho": "udp-echo",
    "UdpEchoCrate": "udp-echo-crate",
    "BadCredential": "bad-credential",
    "BadConfig": "bad-config",
    "LongLived": "long-lived",
    "Reconnect": "reconnect",
    "QpackDiag": "qpack-diag",
    "PaddingDiag": "padding-diag",
}


def label(kind, value):
    table = {"protocol": PROTOCOL, "variant": VARIANT, "cell": CELL}[kind]
    if value not in table:
        raise KeyError(f"unknown {kind} label: {value}")
    return table[value]

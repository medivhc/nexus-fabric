//! Trojan 第一响应守卫（fail-closed 判据的纯函数层）。
//!
//! Trojan 协议没有响应头、没有握手确认、没有密码校验回执，所以「节点是否接受了本次
//! 连接」只能从**首个下行字节**与**目标端口**推断。本模块把该判据收敛为纯函数：
//! 输入是 SOCKS5/HTTP 目标端口、首包（≤16 字节）、是否 EOF、客户端是否已先说话以及
//! 策略；输出是 `WaitMore` / `Success` / `Reject(cause)`。
//!
//! 判据顺序即 spec §5.3 的 1→6，不允许在判据外新增启发式（AC-7：不做内容相似度、
//! 延迟统计、重试次数等「看起来像」的判断）。
//!
//! 两种策略：
//! - `Strict`（默认）：端口绑定的 greeting 白名单（§5.2）之外的首包一律拒绝；
//! - `Signature`（显式安全降级，官方逃生口）：只拒绝 `HTTP/` 状态行，其余放行，
//!   因此非 HTTP fallback 全部漏报（R-3），这是该模式已登记的代价。

use std::time::Duration;

/// 首包缓冲上限（分类只看前 16 字节）。
pub(crate) const FIRST_BYTES_MAX: usize = 16;
/// 自适应窗口下限。
pub(crate) const WINDOW_MIN_MS: u64 = 50;
/// 自适应窗口上限（UX 与「服务端可探测的本地挂起」的折中）。
pub(crate) const WINDOW_MAX_MS: u64 = 600;
/// 自适应窗口在 `t_connect` 之上留的抖动/处理余量。
pub(crate) const WINDOW_SLACK_MS: u64 = 50;
/// `GreetingMatch::Prefix` 允许的一次性延长（§4）。
pub(crate) const PREFIX_EXTRA_WAIT_MS: u64 = 50;
/// 拒绝路径对节点的有界 drain 字节上限（AC-6）。
pub(crate) const NODE_DRAIN_MAX_BYTES: usize = 65_536;
/// 拒绝路径对节点的有界 drain 时间上限（AC-6）。
pub(crate) const NODE_DRAIN_MAX_MS: u64 = 50;

/// 第一响应守卫策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GuardPolicy {
    /// 端口绑定 greeting 白名单（默认）。
    Strict,
    /// 只认 `HTTP/` 签名（显式安全降级）。
    Signature,
}

/// 首包与「端口 + 白名单前缀」的匹配结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GreetingMatch {
    /// 完整匹配某条白名单前缀。
    Match,
    /// 是某条白名单前缀的严格前缀（需要更多字节才能判定）。
    Prefix,
    /// 不匹配任何白名单前缀。
    NoMatch,
}

/// 就绪判定结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadinessVerdict {
    /// 首包可能还需更多字节（调用方最多再等 `PREFIX_EXTRA_WAIT_MS`）。
    WaitMore,
    /// 放行：写 success 进入中继。
    Success,
    /// 拒绝：写失败应答、有界 drain、关闭节点。
    Reject(RejectCause),
}

/// 拒绝原因（对应 spec §6 的失败变体）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RejectCause {
    /// 首包是 HTTP 状态行（fallback 页面）。
    FallbackHttp,
    /// 严格模式下首包不符合端口绑定 greeting 白名单。
    UnsolicitedServerData,
    /// 首包为空且节点已关闭（含「半个 greeting 就 EOF」）。
    ClosedBeforeReady,
}

impl RejectCause {
    /// spec §6 / §9 固定的 reason 前缀。
    pub(crate) fn reason_prefix(self) -> &'static str {
        match self {
            Self::FallbackHttp => "trojan fallback signature detected",
            Self::UnsolicitedServerData => "unsolicited server data rejected",
            Self::ClosedBeforeReady => "tunnel closed before ready",
        }
    }
}

/// 端口绑定的 server-first greeting 白名单（§5.2，编译期内置，不做成用户可编辑规则）。
const GREETINGS: &[(u16, &[u8])] = &[
    (22, b"SSH-"),
    (21, b"220"),
    (25, b"220"),
    (587, b"220"),
    (110, b"+OK"),
    (143, b"* OK"),
    (5900, b"RFB "),
];

/// 自适应窗口或显式覆盖：覆盖 > 0 时直接返回 `min(override, 5000)`，否则
/// `clamp(connect_elapsed + WINDOW_SLACK_MS, WINDOW_MIN_MS, WINDOW_MAX_MS)`。
pub(crate) fn ready_window_ms(connect_elapsed: Duration, override_ms: Option<u64>) -> u64 {
    if let Some(n) = override_ms {
        if n > 0 {
            return n.min(5000);
        }
    }
    let connect_ms = u64::try_from(connect_elapsed.as_millis()).unwrap_or(u64::MAX);
    connect_ms
        .saturating_add(WINDOW_SLACK_MS)
        .clamp(WINDOW_MIN_MS, WINDOW_MAX_MS)
}

/// 配置字符串 → 策略。配置层已保证只有两种取值；其他输入按 fail-safe 归入 `Strict`
/// （不得 panic，也不得静默放宽判据）。
pub(crate) fn guard_policy(raw: Option<&str>) -> GuardPolicy {
    match raw {
        Some("signature") => GuardPolicy::Signature,
        _ => GuardPolicy::Strict,
    }
}

/// 首包与「目标端口 + 白名单前缀」的匹配（§5.2）。
pub(crate) fn greeting_match(dest_port: u16, first: &[u8]) -> GreetingMatch {
    if first.is_empty() {
        return GreetingMatch::NoMatch;
    }
    let mut prefix_seen = false;
    for (port, prefix) in GREETINGS {
        if *port != dest_port {
            continue;
        }
        if first.starts_with(prefix) {
            return GreetingMatch::Match;
        }
        if prefix.starts_with(first) {
            prefix_seen = true;
        }
    }
    if prefix_seen {
        GreetingMatch::Prefix
    } else {
        GreetingMatch::NoMatch
    }
}

/// 首包是否是 HTTP 状态行（`HTTP/` 覆盖 HTTP/1.0、1.1、2）。
pub(crate) fn is_http_status_prefix(first: &[u8]) -> bool {
    first.len() >= 5 && &first[..5] == b"HTTP/"
}

/// 首包分类（§5.3 规则 1→6 的唯一实现）。
pub(crate) fn classify_first_downstream(
    dest_port: u16,
    first: &[u8],
    client_payload_seen: bool,
    eof: bool,
    policy: GuardPolicy,
) -> ReadinessVerdict {
    // 1) 客户端已先说话：守卫不适用。
    if client_payload_seen {
        return ReadinessVerdict::Success;
    }
    // 2) HTTP 状态行一律拒绝（两种策略都认）。
    if is_http_status_prefix(first) {
        return ReadinessVerdict::Reject(RejectCause::FallbackHttp);
    }
    let matched = greeting_match(dest_port, first);
    // 3) 完整白名单 greeting 放行。
    if matched == GreetingMatch::Match {
        return ReadinessVerdict::Success;
    }
    // 4) EOF：完整 greeting 之后才判 => 半个 greeting + EOF 归 ClosedBeforeReady。
    if eof {
        return ReadinessVerdict::Reject(RejectCause::ClosedBeforeReady);
    }
    // 签名模式：只拒绝 HTTP，其余一律放行（已登记漏报面 R-3）。
    if policy == GuardPolicy::Signature {
        return ReadinessVerdict::Success;
    }
    // 5) 非空且是某条白名单前缀的严格前缀 => 再等一次。
    if matched == GreetingMatch::Prefix && !first.is_empty() && first.len() < FIRST_BYTES_MAX {
        return ReadinessVerdict::WaitMore;
    }
    // 6) 其他一律拒绝。
    ReadinessVerdict::Reject(RejectCause::UnsolicitedServerData)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strict(port: u16, first: &[u8], eof: bool) -> ReadinessVerdict {
        classify_first_downstream(port, first, false, eof, GuardPolicy::Strict)
    }

    fn signature(port: u16, first: &[u8], eof: bool) -> ReadinessVerdict {
        classify_first_downstream(port, first, false, eof, GuardPolicy::Signature)
    }

    use ReadinessVerdict::Reject;
    use ReadinessVerdict::Success;
    use ReadinessVerdict::WaitMore;

    #[test]
    fn v01_http_404_is_fallback_signature() {
        assert_eq!(
            strict(26200, b"HTTP/1.1 404 Not Found\r\n", false),
            Reject(RejectCause::FallbackHttp)
        );
    }

    #[test]
    fn v02_http_200_in_signature_mode_is_still_rejected() {
        assert_eq!(
            signature(26200, b"HTTP/1.0 200 OK\r\n", false),
            Reject(RejectCause::FallbackHttp)
        );
    }

    #[test]
    fn v03_ssh_banner_on_22_passes() {
        assert_eq!(strict(22, b"SSH-2.0-OpenSSH_9.6\r\n", false), Success);
    }

    #[test]
    fn v04_ssh_banner_on_443_is_rejected() {
        assert_eq!(
            strict(443, b"SSH-2.0-OpenSSH_9.6\r\n", false),
            Reject(RejectCause::UnsolicitedServerData)
        );
    }

    #[test]
    fn v05_smtp_banner_on_25_passes() {
        assert_eq!(strict(25, b"220 mail.example ESMTP\r\n", false), Success);
    }

    #[test]
    fn v06_smtp_banner_on_80_is_rejected() {
        assert_eq!(
            strict(80, b"220 mail.example ESMTP\r\n", false),
            Reject(RejectCause::UnsolicitedServerData)
        );
    }

    #[test]
    fn v07_pop3_banner_on_110_passes() {
        assert_eq!(strict(110, b"+OK POP3 ready\r\n", false), Success);
    }

    #[test]
    fn v08_vnc_banner_on_5900_passes() {
        assert_eq!(strict(5900, b"RFB 003.008\n", false), Success);
    }

    #[test]
    fn v09_mysql_handshake_is_rejected() {
        assert_eq!(
            strict(3306, &[0x5f, 0, 0, 0, 0x0a, 0x38, 0x2e, 0x30], false),
            Reject(RejectCause::UnsolicitedServerData)
        );
    }

    #[test]
    fn v10_partial_ssh_prefix_waits_for_more() {
        assert_eq!(strict(22, b"SS", false), WaitMore);
    }

    #[test]
    fn v11_partial_greeting_then_eof_is_closed_before_ready() {
        assert_eq!(
            strict(22, b"SS", true),
            Reject(RejectCause::ClosedBeforeReady)
        );
    }

    #[test]
    fn v12_empty_first_with_eof_is_closed_before_ready_in_both_modes() {
        assert_eq!(
            strict(26200, b"", true),
            Reject(RejectCause::ClosedBeforeReady)
        );
        assert_eq!(
            signature(26200, b"", true),
            Reject(RejectCause::ClosedBeforeReady)
        );
    }

    #[test]
    fn v13_tls_server_hello_bytes_are_rejected() {
        assert_eq!(
            strict(26200, &[0x16, 0x03, 0x03, 0x00, 0x7a, 0x02], false),
            Reject(RejectCause::UnsolicitedServerData)
        );
    }

    #[test]
    fn v14_signature_mode_allows_arbitrary_binary() {
        assert_eq!(signature(26200, &[0x16, 0x03, 0x03, 0x01], false), Success);
    }

    #[test]
    fn v15_http_prefix_with_client_payload_is_success_in_both_modes() {
        for policy in [GuardPolicy::Strict, GuardPolicy::Signature] {
            assert_eq!(
                classify_first_downstream(26200, b"HTTP/", true, false, policy),
                Success,
                "client_payload_seen 时守卫不适用（{policy:?}）"
            );
        }
    }

    #[test]
    fn v16_smtp_banner_on_non_standard_port_is_rejected_in_strict() {
        assert_eq!(
            strict(2500, b"220 mail.example ESMTP\r\n", false),
            Reject(RejectCause::UnsolicitedServerData)
        );
    }

    #[test]
    fn v17_signature_mode_is_the_escape_hatch_for_v16() {
        assert_eq!(
            signature(2500, b"220 mail.example ESMTP\r\n", false),
            Success
        );
    }

    #[test]
    fn v18_fragmented_http_prefix_is_rejected_with_coarser_reason() {
        // 已接受的 reason 精度缺口（§5.3）：仍 fail-closed，只是归为「非白名单首包」。
        assert_eq!(
            strict(26200, b"HT", false),
            Reject(RejectCause::UnsolicitedServerData)
        );
    }

    #[test]
    fn greeting_match_empty_input_is_no_match() {
        assert_eq!(greeting_match(22, b""), GreetingMatch::NoMatch);
        assert_eq!(greeting_match(26200, b""), GreetingMatch::NoMatch);
    }

    #[test]
    fn greeting_match_requires_port_binding() {
        assert_eq!(greeting_match(22, b"SSH-"), GreetingMatch::Match);
        assert_eq!(greeting_match(2222, b"SSH-"), GreetingMatch::NoMatch);
        // 非白名单端口上，前缀的严格前缀也不进入 WaitMore（规则 5 的端口绑定）。
        assert_eq!(greeting_match(2222, b"SS"), GreetingMatch::NoMatch);
    }

    #[test]
    fn greeting_match_prefix_is_strict_prefix_only() {
        assert_eq!(greeting_match(143, b"*"), GreetingMatch::Prefix);
        assert_eq!(greeting_match(143, b"* OK"), GreetingMatch::Match);
        assert_eq!(greeting_match(143, b"* X"), GreetingMatch::NoMatch);
    }

    #[test]
    fn http_prefix_helper_needs_five_bytes() {
        assert!(!is_http_status_prefix(b"HTTP"));
        assert!(is_http_status_prefix(b"HTTP/"));
        assert!(is_http_status_prefix(b"HTTP/1.1 404 Not Found\r\n"));
        assert!(!is_http_status_prefix(b"htTp/"));
    }

    #[test]
    fn ready_window_adaptive_clamps() {
        assert_eq!(ready_window_ms(Duration::from_millis(0), None), 50);
        // 公式是 clamp(t_connect + 50, 50, 600)：下限只在 t_connect=0 时命中。
        assert_eq!(ready_window_ms(Duration::from_millis(5), None), 55);
        assert_eq!(ready_window_ms(Duration::from_millis(80), None), 130);
        assert_eq!(ready_window_ms(Duration::from_millis(2000), None), 600);
        assert_eq!(ready_window_ms(Duration::from_secs(1), None), 600);
    }

    #[test]
    fn ready_window_override_and_zero_means_adaptive() {
        assert_eq!(ready_window_ms(Duration::from_millis(80), Some(0)), 130);
        assert_eq!(ready_window_ms(Duration::from_millis(80), Some(1)), 1);
        assert_eq!(ready_window_ms(Duration::from_millis(80), Some(5000)), 5000);
        // 配置层已限制 0..=5000；运行时仍按 min(n, 5000) 收敛（不信任上游）。
        assert_eq!(ready_window_ms(Duration::from_millis(80), Some(9000)), 5000);
    }

    #[test]
    fn guard_policy_defaults_to_strict() {
        assert_eq!(guard_policy(None), GuardPolicy::Strict);
        assert_eq!(guard_policy(Some("strict")), GuardPolicy::Strict);
        assert_eq!(guard_policy(Some("signature")), GuardPolicy::Signature);
        // fail-safe：非法输入不得放宽为 signature。
        assert_eq!(guard_policy(Some("off")), GuardPolicy::Strict);
        assert_eq!(guard_policy(Some("")), GuardPolicy::Strict);
    }

    #[test]
    fn reject_causes_have_frozen_reason_prefixes() {
        assert_eq!(
            RejectCause::FallbackHttp.reason_prefix(),
            "trojan fallback signature detected"
        );
        assert_eq!(
            RejectCause::UnsolicitedServerData.reason_prefix(),
            "unsolicited server data rejected"
        );
        assert_eq!(
            RejectCause::ClosedBeforeReady.reason_prefix(),
            "tunnel closed before ready"
        );
    }
}

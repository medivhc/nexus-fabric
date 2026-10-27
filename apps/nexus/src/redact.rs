//! 密钥脱敏（daemon + CLI **共享一份实现**；spec §9）。
//!
//! 语义：按空白分词，命中 password 类键后把其值（可能带引号/多词，值边界未知）
//! 掩码为 `***`，并丢弃该行剩余 token。键集合与掩码规则 daemon/CLI 逐字一致，
//! 消除 R2 的「两份同语义代码」漂移风险（R2-F11）。
//!
//! - [`redact_secrets`]：只删密钥面，**不做** 128B 截断/控制字符过滤，且未命中时
//!   原样返回（保留多行诊断与文件名/行号）；对已脱敏文本幂等（双写点安全）。
//! - [`sanitize`]：`redact_secrets` + 去控制字符 + 128 B 截断（用于 `detail`/`field`
//!   字段级契约）。

/// 需要掩码的键（与 `apps/nexus/src/outbound_check.rs` 的 `SECRET_KEYS` 一致）。
const SECRET_KEYS: [&str; 4] = ["password", "uuid", "obfs_key", "obfs_password"];

/// 键名规范化：去掉两侧所有非字母数字、非下划线字符，再转小写。
///
/// 解析器用单引号包裹回显行（`expected 'key: value', got '{text}'`），紧凑键值
/// 形态（`password=…` / `password:…`）分词后键与 `'` 粘连；标点必须在这里统一
/// 剥掉。bare 分支与 inline 分支共用本函数——两分支曾各自去标点，导致引号邻接
/// 形态只有一边命中（fix-r1 review F1）。
fn normalize_key(raw: &str) -> String {
    raw.trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .to_ascii_lowercase()
}

/// 密钥 token 是否已经带掩码值（`password:***` / `'password=***'` / `password: ***`）。
///
/// 双写点（watcher 构造点 + 打印点）会二次进入本函数；已经掩码的值不能再追加
/// 一个 `***`（fix-r2 实测的 `password:*** ***` 破损形态，PR2R1-08）。
fn value_is_mask(token: &str) -> bool {
    token
        .split_once(':')
        .or_else(|| token.split_once('='))
        .map(|(_, value)| value.trim_matches(|ch| ch == '\'' || ch == '"') == "***")
        .unwrap_or(false)
}

/// 值尾部的引号（解析器回显 `'…'` 与 Debug `"` 叠加时保留闭合引号）。
///
/// 只保留引号，不保留值本身：掩码后文本仍可读，且引号不被吞掉
/// （fix-r2 实测的 `got 'password:***` 单引号不闭合，PR2R1-08）。
fn trailing_quotes(value: &str) -> String {
    value
        .chars()
        .rev()
        .take_while(|ch| matches!(ch, '\'' | '"'))
        .collect::<String>()
        .chars()
        .rev()
        .collect()
}

/// `password` / `uuid` / `obfs_key` / `obfs_password` 后面的值替换为 `***`。
///
/// 兼容 `key: value` 与 `key=value` 两种写法；键大小写不敏感，比较前两侧标点
/// （含解析器回显用的引号）经 `normalize_key` 统一剥除。命中后其余 token
/// 全部丢弃，因为值的边界未知（可能带引号、可能多词）。
///
/// 对已脱敏文本幂等：掩码值（`***`，带不带空格/引号）原样保留，不再追加第二个
/// `***`；新掩码保留值的尾部引号，避免不闭合引号。
///
/// 未命中任何密钥键时原样返回（保留换行/缩进），避免把不含密钥的多行 TOML
/// 诊断压成一行——本函数只负责删掉密钥面，不重排其他日志文本。
pub fn redact_secrets(text: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut redacted = false;
    for token in text.split_whitespace() {
        let bare = normalize_key(token);
        if SECRET_KEYS.contains(&bare.as_str()) {
            out.push(token.to_string());
            if !value_is_mask(token) {
                out.push("***".to_string());
            }
            redacted = true;
            break;
        }
        let inline = token
            .split_once(':')
            .or_else(|| token.split_once('='))
            .filter(|(key, _)| SECRET_KEYS.contains(&normalize_key(key).as_str()));
        match inline {
            Some((key, _)) => {
                if value_is_mask(token) {
                    out.push(token.to_string());
                } else {
                    let value = token
                        .split_once(':')
                        .or_else(|| token.split_once('='))
                        .map(|(_, value)| value)
                        .unwrap_or("");
                    out.push(format!("{key}:***{}", trailing_quotes(value)));
                }
                redacted = true;
                break;
            }
            None => out.push(token.to_string()),
        }
    }
    if !redacted {
        return text.to_string();
    }
    out.join(" ")
}

/// `redact_secrets` + 去控制字符 + 128 B 截断（`detail` / `field` 字段契约）。
///
/// 128 B 上限与 `adapter::DETAIL_MAX_BYTES` 同值；日志行**不**截断（保留诊断）。
#[must_use]
pub fn sanitize(text: &str) -> String {
    const DETAIL_MAX_BYTES: usize = 128;
    let redacted = redact_secrets(text);
    let mut out = String::new();
    for ch in redacted.chars() {
        if ch.is_control() {
            continue;
        }
        if out.len() + ch.len_utf8() > DETAIL_MAX_BYTES {
            break;
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::redact_secrets;

    #[test]
    fn colon_form_password_is_masked() {
        let text = "parse proxy.yaml: password: r2-marker-colon";
        let got = redact_secrets(text);
        assert!(!got.contains("r2-marker-colon"), "leaked: {got}");
        assert!(got.contains("password:"), "key kept: {got}");
        assert!(got.contains("***"), "mask present: {got}");
    }

    #[test]
    fn colonless_multi_word_password_is_masked() {
        let text = "expected 'key: value', got 'password \"r2-marker-quoted alpha beta\"'";
        let got = redact_secrets(text);
        for secret in ["r2-marker-quoted", "alpha", "beta"] {
            assert!(!got.contains(secret), "leaked {secret}: {got}");
        }
        assert!(got.contains("expected 'key: value'"), "diag kept: {got}");
    }

    #[test]
    fn inline_and_other_secret_keys_are_masked() {
        let got = redact_secrets("a=1 uuid=r2-marker-uuid obfs_key=r2-marker-obfs");
        assert!(!got.contains("r2-marker-uuid"), "leaked: {got}");
        // `obfs_key=...` 位于 uuid 之后：命中 uuid 即截断整行，同样不泄漏。
        assert!(!got.contains("r2-marker-obfs"), "leaked: {got}");
    }

    /// F1（fix-r1 review）：解析器用单引号包裹回显行（`got '{text}'`），紧凑键值
    /// 形态在空白分词后键与前导 `'` 粘连成单 token；两个分支必须同一去标点口径。
    #[test]
    fn quoted_adjacent_inline_password_forms_are_masked() {
        let eq = redact_secrets("got 'password=r2-f1-marker-eq'");
        assert!(!eq.contains("r2-f1-marker-eq"), "leaked: {eq}");
        assert!(eq.contains("***"), "mask present: {eq}");

        let colon = redact_secrets("at 'password:r2-f1-marker-colon'");
        assert!(!colon.contains("r2-f1-marker-colon"), "leaked: {colon}");
        assert!(colon.contains("***"), "mask present: {colon}");
    }

    /// F1：其它密钥键在引号邻接紧凑形态下同样必须命中（大小写不敏感）。
    #[test]
    fn quoted_adjacent_inline_other_secret_keys_are_masked() {
        let uuid = redact_secrets("got 'uuid=r2-f1-marker-uuid'");
        assert!(!uuid.contains("r2-f1-marker-uuid"), "leaked: {uuid}");
        assert!(uuid.contains("***"), "mask present: {uuid}");

        let obfs = redact_secrets("at 'OBFS_PASSWORD:r2-f1-marker-obfs'");
        assert!(!obfs.contains("r2-f1-marker-obfs"), "leaked: {obfs}");
        assert!(obfs.contains("***"), "mask present: {obfs}");
    }

    #[test]
    fn non_secret_text_is_untouched() {
        // 多行 TOML 诊断不含密钥键时必须逐字保留（只删密钥面，不重排日志）。
        let text =
            "parse network.toml: TOML parse error at line 2, column 9\n  |\n2 | bogus\n  |\n";
        assert_eq!(redact_secrets(text), text);
    }

    #[test]
    fn already_masked_text_is_idempotent() {
        let once = redact_secrets("password: *** trailing");
        assert_eq!(redact_secrets(&once), once);
    }

    /// PR2R1-08（前半）：已脱敏文本再入 redact 必须逐字不变（fix-r1 测试族的
    /// 全部既有形态 + 无空格紧凑形态）。
    #[test]
    fn already_masked_forms_are_idempotent() {
        for case in [
            "password: ***",
            "password:***",
            "password=***",
            "got 'password:***'",
            "at 'uuid=***'",
            "reason: \"expected 'key: value', got 'password:***'\"",
            "password *** trailing",
        ] {
            let once = redact_secrets(case);
            assert_eq!(
                redact_secrets(&once),
                once,
                "redact is not idempotent for {case:?}"
            );
        }
    }

    /// PR2R1-08（前半）：评审 §3.3 实测的破损原文（`password:*** ***`）必须收敛为
    /// 单掩码，且再入 redact 逐字不变。
    #[test]
    fn review_broken_double_mask_is_repaired() {
        let broken = "files [\"proxy.yaml\"]: parse proxy.yaml: ConfigError { field: \"<seq-item>\", \
                      reason: \"expected 'key: value', got 'password:*** ***";
        let got = redact_secrets(broken);
        assert_eq!(
            got.matches("***").count(),
            1,
            "double mask not repaired: {got}"
        );
        assert!(!got.contains("*** ***"), "double mask not repaired: {got}");
        assert_eq!(redact_secrets(&got), got, "not idempotent: {got}");
    }

    /// PR2R1-08（前半）：双写点组合（watcher 构造点先脱敏、打印点再脱敏）不得
    /// 产生 `password:*** ***`，也不得留下不闭合引号。
    #[test]
    fn two_redaction_points_keep_single_mask_and_balanced_quotes() {
        const MARKER: &str = "r2f3redactmarker9a1b";
        let raw = format!(
            "files [\"proxy.yaml\"]: parse proxy.yaml: ConfigError {{ field: \"<seq-item>\", \
             reason: \"expected 'key: value', got 'password={MARKER}'\" }}"
        );

        let once = redact_secrets(&raw);
        assert!(!once.contains(MARKER), "first pass leaked: {once}");
        assert_eq!(
            once.matches("***").count(),
            1,
            "first pass produced a double mask: {once}"
        );
        assert!(
            once.contains("'password:***'\""),
            "closing quotes must be preserved: {once}"
        );

        let twice = redact_secrets(&once);
        assert_eq!(twice, once, "second pass changed the text: {twice}");
        assert_eq!(twice.matches('\'').count() % 2, 0, "unbalanced ': {twice}");
        assert_eq!(twice.matches('"').count() % 2, 0, "unbalanced \": {twice}");
    }

    #[test]
    fn sanitize_truncates_and_strips_control_chars() {
        let long = format!("password=secret {}", "x".repeat(400));
        let got = super::sanitize(&long);
        assert!(!got.contains("secret"), "leaked: {got}");
        assert!(got.len() <= 128, "not truncated: {}", got.len());
        assert!(
            !got.chars().any(|c| c.is_control()),
            "control chars: {got:?}"
        );
    }
}

//! 组合根：公开数据源适配（§11.15 源插件，首期 = ip2region TXT）。
//!
//! - [`parse_ip2region_txt`]：ip2region 公开 TXT → 分类（ISO 码）→ CIDR 文本
//!   列表，供 [`nexus_proxy::geoip_nex::build`] 生成 `geoip.nex`。
//! - 国家字段映射：内置常用中文国家名 → ISO 3166-1 alpha-2（纯数据）。
//!   无法识别的国家文本（含 `0` / `内网IP` / `未分配`）→ 跳过并计入
//!   [`Ip2RegionParse::skipped`]，不静默丢弃、不臆测归属。
//!
//! 纯函数零 I/O（文本 → 结构化结果）；文件读取由调用方（example / CLI）负责。

use nexus_proxy::geoip_nex::{cidrs_from_range, format_ipv4, parse_ipv4};

/// ip2region TXT 解析结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ip2RegionParse {
    /// ISO 国家码 → CIDR 文本列表（按输入行顺序聚合）。
    pub entries: Vec<(String, Vec<String>)>,
    /// 跳过行数（国家字段无法识别）。
    pub skipped: usize,
}

/// 常用中文国家名 → ISO 3166-1 alpha-2（覆盖常见流量归属）。
const COUNTRY_ISO: &[(&str, &str)] = &[
    ("中国", "CN"),
    ("中国香港", "HK"),
    ("中国澳门", "MO"),
    ("中国台湾", "TW"),
    ("香港", "HK"),
    ("澳门", "MO"),
    ("台湾", "TW"),
    ("美国", "US"),
    ("日本", "JP"),
    ("韩国", "KR"),
    ("朝鲜", "KP"),
    ("新加坡", "SG"),
    ("马来西亚", "MY"),
    ("泰国", "TH"),
    ("越南", "VN"),
    ("印度尼西亚", "ID"),
    ("菲律宾", "PH"),
    ("印度", "IN"),
    ("巴基斯坦", "PK"),
    ("孟加拉国", "BD"),
    ("斯里兰卡", "LK"),
    ("尼泊尔", "NP"),
    ("缅甸", "MM"),
    ("柬埔寨", "KH"),
    ("老挝", "LA"),
    ("蒙古", "MN"),
    ("哈萨克斯坦", "KZ"),
    ("乌兹别克斯坦", "UZ"),
    ("俄罗斯", "RU"),
    ("英国", "GB"),
    ("德国", "DE"),
    ("法国", "FR"),
    ("意大利", "IT"),
    ("西班牙", "ES"),
    ("葡萄牙", "PT"),
    ("荷兰", "NL"),
    ("比利时", "BE"),
    ("瑞士", "CH"),
    ("奥地利", "AT"),
    ("瑞典", "SE"),
    ("挪威", "NO"),
    ("丹麦", "DK"),
    ("芬兰", "FI"),
    ("波兰", "PL"),
    ("乌克兰", "UA"),
    ("土耳其", "TR"),
    ("希腊", "GR"),
    ("爱尔兰", "IE"),
    ("捷克", "CZ"),
    ("罗马尼亚", "RO"),
    ("匈牙利", "HU"),
    ("澳大利亚", "AU"),
    ("新西兰", "NZ"),
    ("加拿大", "CA"),
    ("墨西哥", "MX"),
    ("巴西", "BR"),
    ("阿根廷", "AR"),
    ("智利", "CL"),
    ("哥伦比亚", "CO"),
    ("秘鲁", "PE"),
    ("委内瑞拉", "VE"),
    ("南非", "ZA"),
    ("埃及", "EG"),
    ("沙特阿拉伯", "SA"),
    ("阿联酋", "AE"),
    ("以色列", "IL"),
    ("伊朗", "IR"),
    ("伊拉克", "IQ"),
    ("阿富汗", "AF"),
    ("尼日利亚", "NG"),
    ("肯尼亚", "KE"),
    ("埃塞俄比亚", "ET"),
    ("法国海外", "FR"),
];

/// 中文国家名 → ISO 码。
fn iso_for_country(name: &str) -> Option<&'static str> {
    COUNTRY_ISO
        .iter()
        .find(|(cn, _)| *cn == name)
        .map(|(_, iso)| *iso)
}

/// 解析 ip2region TXT（UTF-8 文本）。
///
/// 行格式：`start_ip|end_ip|country|province|city|isp`（竖线分隔，取前 2 列 IP
/// 与第 3 列国家；多出的列忽略）。空行 / `#` 注释忽略。国家字段无法识别 →
/// 跳过并计数。IP 段解析失败 → 该行计入 `skipped` 且不影响其余行。
#[must_use]
pub fn parse_ip2region_txt(text: &str) -> Ip2RegionParse {
    let mut buckets: Vec<(String, Vec<String>)> = Vec::new();
    let mut skipped = 0usize;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut cols = line.split('|');
        let (Some(start), Some(end), Some(country)) = (cols.next(), cols.next(), cols.next())
        else {
            skipped += 1;
            continue;
        };
        let Some(iso) = iso_for_country(country.trim()) else {
            skipped += 1;
            continue;
        };
        let (Ok(start), Ok(end)) = (parse_ipv4(start.trim()), parse_ipv4(end.trim())) else {
            skipped += 1;
            continue;
        };
        if start > end {
            skipped += 1;
            continue;
        }
        for (base, prefix) in cidrs_from_range(start, end) {
            let cidr = format!("{}/{}", format_ipv4(base), prefix);
            match buckets.iter_mut().find(|(code, _)| code == iso) {
                Some((_, list)) => list.push(cidr),
                None => buckets.push((iso.to_string(), vec![cidr])),
            }
        }
    }

    Ip2RegionParse {
        entries: buckets,
        skipped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sample() {
        let text = "\
# ip2region sample
0.0.0.0|0.255.255.255|0|0|0|0|0
1.0.1.0|1.0.3.255|中国|福建|福州|电信
8.8.8.8|8.8.8.8|美国|0|0|0
";
        let parsed = parse_ip2region_txt(text);
        assert_eq!(parsed.skipped, 1);
        assert_eq!(parsed.entries.len(), 2);
        let cn = &parsed.entries[0];
        assert_eq!(cn.0, "CN");
        assert_eq!(
            cn.1,
            vec!["1.0.1.0/24".to_string(), "1.0.2.0/23".to_string()]
        );
        let us = &parsed.entries[1];
        assert_eq!(us.0, "US");
        assert_eq!(us.1, vec!["8.8.8.8/32".to_string()]);
    }

    #[test]
    fn parse_unknown_country_skipped() {
        let text = "1.2.3.4|1.2.3.4|火星|0|0|0\n";
        assert_eq!(parse_ip2region_txt(text).skipped, 1);
    }

    #[test]
    fn parse_bad_line_skipped() {
        let text = "not-an-ip|1.2.3.4|中国|0|0|0\n";
        assert_eq!(parse_ip2region_txt(text).skipped, 1);
    }
}

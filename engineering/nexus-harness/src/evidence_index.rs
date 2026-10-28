//! `docs/evidence-index.md`：仓库内场景 → carrier 索引（P4）。
//!
//! 索引是**仓库元数据**，不是验收断言来源：它记录每个场景声明的执行载体
//! 与命令载体，供人/评审定位；`scenario index --check` 与
//! `architecture_gate` 共用本模块的单一实现校验「索引 == 场景集」。
//!
//! 三个入口：
//! - `collect`：从场景加载结果 + `carrier_for_command` 重新派生（totality：
//!   仓库内每个场景都必须可派生）；
//! - `render` / `parse`：确定性 markdown 表格的写出与读回；
//! - `check`：id 集合 + carrier + command carrier 相等 + v9 单调性。
//!
//! `first_revision` 列绑定本地 `.evidence`：`latest.json → dir →
//! metadata.json → bindings.source_revision`，读不到写 `unrecorded`（不伪造）。
//! `--write` 对已存在且 carrier 未变的 id **保留原值**（列名是「首次记录」，
//! 每次刷新会让列名说谎并产生 338 行噪声）。

use crate::config::Config;
use crate::env::Repo;
use crate::scenario::{self, Carrier};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

/// 索引文件相对仓库根的路径。
pub const INDEX_PATH: &str = "docs/evidence-index.md";

/// 与 `scenario list` / verify 的场景集一致（4 个场景子目录）。
const SCAN_SUBDIRS: &[&str] = &["product", "regression", "platform", "engineering"];

const ROWS_BEGIN: &str = "<!-- index-rows-begin -->";
const ROWS_END: &str = "<!-- index-rows-end -->";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub id: String,
    pub carrier: Carrier,
    /// 命令载体的机械渲染（C6）：`cargo -p <pkg>` / `nexus-harness <sub>` / 首 token。
    pub command_carrier: String,
    pub requirement: Option<String>,
    /// `Some("unrecorded")` = 本地确无证据；`Some(<40hex>)` = 首次记录的 revision。
    pub first_revision: Option<String>,
}

/// 从场景集构建索引行。加载错误或派生不可判定一律拒绝（fail-closed）。
pub fn collect(config: &Config) -> Result<Vec<Row>, Vec<String>> {
    let (scenarios, load_errors) =
        scenario::load_all_reporting(&config.scenarios_dir, SCAN_SUBDIRS);
    if !load_errors.is_empty() {
        return Err(load_errors);
    }
    let requirements = read_requirements(&config.scenarios_dir);
    let mut rows = Vec::new();
    let mut problems = Vec::new();
    for s in &scenarios {
        let Some(command) = s.command.as_deref() else {
            problems.push(format!("{}: 无 [when].command，carrier 不可派生", s.id));
            continue;
        };
        match scenario::carrier_for_command(command) {
            Some(derived) if derived == s.carrier => {}
            Some(derived) => problems.push(format!(
                "{}: 声明 {} 与派生 {} 不一致",
                s.id,
                s.carrier.as_str(),
                derived.as_str()
            )),
            None => problems.push(format!(
                "{}: command 不命中任何 carrier 规则: {command}",
                s.id
            )),
        }
        rows.push(Row {
            id: s.id.clone(),
            carrier: s.carrier,
            command_carrier: command_carrier(command),
            requirement: requirements.get(&s.id).cloned().flatten(),
            first_revision: None,
        });
    }
    if !problems.is_empty() {
        return Err(problems);
    }
    // 排序口径：subdir + id 字典序。场景 id 恒以 `<subdir>.` 开头，
    // 故按 id 排序即等价（不依赖调用方 SCAN_SUBDIRS 顺序）。
    rows.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(rows)
}

/// 渲染确定性索引文本。`latest_rev` 只填充**尚未**有 first_revision 的行。
pub fn render(rows: &[Row], latest_rev: Option<&str>) -> String {
    let mut out = String::new();
    out.push_str("# E4 场景证据索引\n\n");
    out.push_str(
        "> 生成：`nexus-harness scenario index --write`（按 subdir + id 字典序，确定性）\n",
    );
    out.push_str(
        "> 校验：`scenario index --check`（architecture_gate 调用）+ 单测 `index_matches_scenarios`\n",
    );
    out.push_str(
        "> external 含 3 个 scripts/e4 真流量场景（被测 target = nexusd，按执行载体记 external）\n",
    );
    out.push_str(
        "> first recorded revision 绑定本地 .evidence；无本地证据写 unrecorded（不伪造）\n",
    );
    out.push_str("> `--write` 保留既有行的 first_revision（id 已存在且 carrier 未变时不刷新）\n\n");
    out.push_str(ROWS_BEGIN);
    out.push('\n');
    out.push_str(
        "| scenario id | carrier | command carrier | requirement | first recorded revision |\n",
    );
    out.push_str("|---|---|---|---|---|\n");
    for r in rows {
        let requirement = r.requirement.as_deref().unwrap_or("(none)");
        let revision = r
            .first_revision
            .as_deref()
            .or(latest_rev)
            .unwrap_or("unrecorded");
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            r.id,
            r.carrier.as_str(),
            r.command_carrier,
            requirement,
            revision
        ));
    }
    out.push_str(ROWS_END);
    out.push('\n');
    out
}

/// 读回索引文本。表格行畸形 / carrier 非闭集 → 错误（fail-closed）。
pub fn parse(text: &str) -> Result<Vec<Row>, Vec<String>> {
    let mut in_rows = false;
    let mut seen_begin = false;
    let mut errors = Vec::new();
    let mut rows = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line == ROWS_BEGIN {
            in_rows = true;
            seen_begin = true;
            continue;
        }
        if line == ROWS_END {
            break;
        }
        if !in_rows || !line.starts_with('|') {
            continue;
        }
        if line.contains("scenario id") || line.chars().all(|c| matches!(c, '|' | '-' | ':' | ' '))
        {
            continue;
        }
        let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
        if cells.len() != 5 {
            errors.push(format!("索引行字段数不是 5: {line}"));
            continue;
        }
        let Some(carrier) = Carrier::parse(cells[1]) else {
            errors.push(format!("索引行 carrier 非闭集: {line}"));
            continue;
        };
        rows.push(Row {
            id: cells[0].to_string(),
            carrier,
            command_carrier: cells[2].to_string(),
            requirement: (cells[3] != "(none)").then(|| cells[3].to_string()),
            first_revision: Some(cells[4].to_string()),
        });
    }
    if !seen_begin {
        errors.push(format!("索引缺少 {ROWS_BEGIN} 标记"));
    }
    if errors.is_empty() {
        Ok(rows)
    } else {
        Err(errors)
    }
}

/// 索引 vs 场景集逐行比对（id 集合 + carrier + command carrier）。
pub fn diff_rows(index: &[Row], current: &[Row]) -> Vec<String> {
    let mut errors = Vec::new();
    let mut index_map: HashMap<&str, &Row> = HashMap::new();
    for r in index {
        if index_map.insert(r.id.as_str(), r).is_some() {
            errors.push(format!("索引存在重复 id: {}", r.id));
        }
    }
    let current_map: HashMap<&str, &Row> = current.iter().map(|r| (r.id.as_str(), r)).collect();

    let mut only_index: Vec<&str> = index_map
        .keys()
        .copied()
        .filter(|id| !current_map.contains_key(id))
        .collect();
    only_index.sort();
    let mut only_scenarios: Vec<&str> = current_map
        .keys()
        .copied()
        .filter(|id| !index_map.contains_key(id))
        .collect();
    only_scenarios.sort();
    if !only_index.is_empty() {
        errors.push(format!(
            "仅索引有（{}）: {}",
            only_index.len(),
            limit_list(&only_index)
        ));
    }
    if !only_scenarios.is_empty() {
        errors.push(format!(
            "仅场景有（{}）: {}",
            only_scenarios.len(),
            limit_list(&only_scenarios)
        ));
    }
    for (id, row) in &current_map {
        let Some(idx) = index_map.get(id) else {
            continue;
        };
        if idx.carrier != row.carrier {
            errors.push(format!(
                "carrier 漂移 {}: 索引={} 场景={}",
                id,
                idx.carrier.as_str(),
                row.carrier.as_str()
            ));
        }
        if idx.command_carrier != row.command_carrier {
            errors.push(format!(
                "command carrier 漂移 {}: 索引={} 重算={}",
                id, idx.command_carrier, row.command_carrier
            ));
        }
    }
    errors
}

/// v9 场景只减不增（C7）：当前 v9 id 集合必须是基线的子集。
///
/// 新增 v9 = 违规；删除 v9 = 允许；carrier 改判按「当前 v9 是否在基线 v9 里」
/// 判新增/删除。
pub fn monotonic_violations(baseline: &[Row], current: &[Row]) -> Vec<String> {
    let baseline_v9: std::collections::HashSet<&str> = baseline
        .iter()
        .filter(|r| r.carrier == Carrier::V9Connectivity)
        .map(|r| r.id.as_str())
        .collect();
    let mut violations: Vec<String> = current
        .iter()
        .filter(|r| r.carrier == Carrier::V9Connectivity && !baseline_v9.contains(r.id.as_str()))
        .map(|r| {
            format!(
                "新增 v9-connectivity 场景（policy: only-decrease）: {}",
                r.id
            )
        })
        .collect();
    violations.sort();
    violations
}

/// 单一校验实现：`scenario index --check` 与 `architecture_gate` 共用。
///
/// `Ok(detail)`（附行数/载体数）或 `Err(错误清单)`。单调性基线取
/// **git HEAD 已提交索引**；HEAD 无该文件时跳过并在 detail 写明。
pub fn check(repo: &Repo, config: &Config) -> Result<String, Vec<String>> {
    let current = collect(config)?;
    let path = repo.root.join(INDEX_PATH);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| vec![format!("索引读取失败 {}: {e}", path.display())])?;
    let index = parse(&text)?;
    let mut errors = diff_rows(&index, &current);
    let mut note = String::new();
    match repo.git(&["show", &format!("HEAD:{INDEX_PATH}")]) {
        Ok(baseline_text) => match parse(&baseline_text) {
            Ok(baseline) => errors.extend(monotonic_violations(&baseline, &current)),
            Err(e) => errors.push(format!("HEAD 索引不可解析: {}", e.join("; "))),
        },
        // 首次落地索引的那次提交（HEAD 还没有该文件）→ 跳过单调性子检查。
        Err(_) => note = " (no committed baseline yet)".to_string(),
    }
    if errors.is_empty() {
        let carriers: BTreeMap<&str, usize> = current.iter().fold(BTreeMap::new(), |mut acc, r| {
            *acc.entry(r.carrier.as_str()).or_insert(0) += 1;
            acc
        });
        Ok(format!(
            "{} rows, {} carriers{}",
            current.len(),
            carriers.len(),
            note
        ))
    } else {
        Err(errors)
    }
}

/// 本地最新证据的 revision 种子（`latest.json → dir → metadata.json`）。
pub fn latest_revision(config: &Config) -> Option<String> {
    let latest = std::fs::read_to_string(config.evidence_dir.join("latest.json")).ok()?;
    let latest: serde_json::Value = serde_json::from_str(&latest).ok()?;
    let dir = latest.get("dir")?.as_str()?;
    let meta = std::fs::read_to_string(config.evidence_dir.join(dir).join("metadata.json")).ok()?;
    let meta: serde_json::Value = serde_json::from_str(&meta).ok()?;
    meta.get("bindings")?
        .get("source_revision")?
        .as_str()
        .map(str::to_string)
}

/// 命令载体列的机械渲染（C6）：不做语义推断，只提取包名/子命令。
fn command_carrier(command: &str) -> String {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    let Some(first) = tokens.first() else {
        return String::new();
    };
    if *first == "cargo" {
        if let Some(pkg) = tokens
            .windows(2)
            .find(|w| matches!(w[0], "-p" | "--package"))
            .map(|w| w[1])
        {
            return format!("cargo -p {pkg}");
        }
        return "cargo".to_string();
    }
    if Path::new(first).file_name().and_then(|n| n.to_str()) == Some("nexus-harness") {
        return match tokens.get(1) {
            Some(sub) => format!("nexus-harness {sub}"),
            None => "nexus-harness".to_string(),
        };
    }
    first.to_string()
}

/// 顶层 `requirement`（索引列）；缺失 → `(none)`。
fn read_requirements(scenarios_dir: &Path) -> HashMap<String, Option<String>> {
    let mut out = HashMap::new();
    for sub in SCAN_SUBDIRS {
        let dir = scenarios_dir.join(sub);
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut files: Vec<PathBuf> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "toml"))
            .collect();
        files.sort();
        for f in files {
            let Ok(text) = std::fs::read_to_string(&f) else {
                continue;
            };
            let Ok(v) = toml::from_str::<toml::Value>(&text) else {
                continue;
            };
            let Some(id) = v.get("id").and_then(toml::Value::as_str) else {
                continue;
            };
            let requirement = v
                .get("requirement")
                .and_then(toml::Value::as_str)
                .map(str::to_string);
            out.insert(id.to_string(), requirement);
        }
    }
    out
}

fn limit_list(items: &[&str]) -> String {
    let shown: Vec<&str> = items.iter().take(10).copied().collect();
    if items.len() > shown.len() {
        format!("{}, … (+{})", shown.join(", "), items.len() - shown.len())
    } else {
        shown.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: &str, carrier: Carrier) -> Row {
        Row {
            id: id.to_string(),
            carrier,
            command_carrier: "cargo -p nexus".to_string(),
            requirement: Some("R".to_string()),
            first_revision: None,
        }
    }

    #[test]
    fn render_is_deterministic() {
        let rows = vec![
            row("product.a", Carrier::V9Connectivity),
            row("engineering.b", Carrier::Engineering),
        ];
        let a = render(&rows, Some("rev1"));
        let b = render(&rows, Some("rev1"));
        assert_eq!(a, b);
        let parsed = parse(&a).expect("render output must parse");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[1].first_revision.as_deref(), Some("rev1"));
    }

    #[test]
    fn render_keeps_preserved_first_revision() {
        let mut rows = vec![row("product.a", Carrier::V9Connectivity)];
        rows[0].first_revision = Some("oldrev".to_string());
        let text = render(&rows, Some("newrev"));
        assert!(text.contains("| product.a | v9-connectivity | cargo -p nexus | R | oldrev |"));
        let text = render(&[row("product.a", Carrier::V9Connectivity)], None);
        assert!(text.contains("| unrecorded |"));
    }

    #[test]
    fn index_write_is_deterministic() {
        let repo = Repo::discover().expect("must run inside the nexus repository");
        let config = Config::load(&repo).expect("config must load");
        let rows = collect(&config).expect("collect must succeed");
        assert_eq!(render(&rows, None), render(&rows, None));
    }

    #[test]
    fn index_matches_scenarios() {
        let repo = Repo::discover().expect("must run inside the nexus repository");
        let config = Config::load(&repo).expect("config must load");
        let detail = check(&repo, &config).expect("index must match scenarios");
        assert!(detail.contains("339 rows"), "{detail}");
        assert!(detail.contains("5 carriers"), "{detail}");
    }

    #[test]
    fn index_check_detects_missing_row() {
        let index = vec![row("product.a", Carrier::V9Connectivity)];
        let current = vec![
            row("product.a", Carrier::V9Connectivity),
            row("product.b", Carrier::N1Fabric),
        ];
        let errors = diff_rows(&index, &current);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("仅场景有（1）"), "{errors:?}");
        assert!(errors[0].contains("product.b"), "{errors:?}");
    }

    #[test]
    fn index_check_detects_carrier_drift() {
        let index = vec![row("product.a", Carrier::V9Connectivity)];
        let current = vec![row("product.a", Carrier::N1Fabric)];
        let errors = diff_rows(&index, &current);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("carrier 漂移"), "{errors:?}");
    }

    #[test]
    fn index_check_detects_unknown_id() {
        let index = vec![
            row("product.a", Carrier::V9Connectivity),
            row("product.zombie", Carrier::V9Connectivity),
        ];
        let current = vec![row("product.a", Carrier::V9Connectivity)];
        let errors = diff_rows(&index, &current);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("仅索引有（1）"), "{errors:?}");
        assert!(errors[0].contains("product.zombie"), "{errors:?}");
    }

    #[test]
    fn monotonic_allows_removal() {
        let baseline = vec![
            row("product.a", Carrier::V9Connectivity),
            row("product.b", Carrier::V9Connectivity),
        ];
        let current = vec![row("product.a", Carrier::V9Connectivity)];
        assert!(monotonic_violations(&baseline, &current).is_empty());
    }

    #[test]
    fn monotonic_rejects_addition() {
        let baseline = vec![row("product.a", Carrier::V9Connectivity)];
        let current = vec![
            row("product.a", Carrier::V9Connectivity),
            row("product.new", Carrier::V9Connectivity),
        ];
        let errors = monotonic_violations(&baseline, &current);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("product.new"), "{errors:?}");
    }

    #[test]
    fn monotonic_treats_carrier_change_as_add_or_remove() {
        let baseline = vec![
            row("product.a", Carrier::N1Fabric),
            row("product.b", Carrier::V9Connectivity),
        ];
        // a: n1 → v9 = 新增 v9（违规）；b: v9 → n1 = 删除 v9（允许）。
        let current = vec![
            row("product.a", Carrier::V9Connectivity),
            row("product.b", Carrier::N1Fabric),
        ];
        let errors = monotonic_violations(&baseline, &current);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("product.a"), "{errors:?}");
    }

    #[test]
    fn command_carrier_renders_three_shapes() {
        assert_eq!(
            command_carrier("cargo run --quiet -p nexusd --example x -- --json"),
            "cargo -p nexusd"
        );
        assert_eq!(
            command_carrier("nexus-harness run qos-cake --json"),
            "nexus-harness run"
        );
        assert_eq!(
            command_carrier("scripts/e4/tun_outbound_ref_flow.sh vless"),
            "scripts/e4/tun_outbound_ref_flow.sh"
        );
    }
}

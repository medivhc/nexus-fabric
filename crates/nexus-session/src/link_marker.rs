//! 链路 durable marker（v9 §15.2/§15.3：Session + Connectivity crash recovery）。
//!
//! 2026-10-26 由 `nexus-connectivity` 迁入（接缝④，划界见
//! `docs/adr/0001-dual-stack-boundary.md`）：持久记录的归属与 `SessionRecord` 同址，
//! `nexus-connectivity` 不再持久化链路状态。`links.json` 的字节格式（字段名、
//! 字典序、紧凑 JSON、`"direct"`/`"relay"` 字符串值）保持不变。

/// 链路类型（durable record 专用）。
///
/// 与 `nexus_connectivity::LinkKind` 不同层：`LinkKind` 是运行时链路激活的候选类型
/// （CLI/proxy 使用）；本类型是持久记录里的分类，只保证 `links.json` 的
/// `"direct"` / `"relay"` 字符串不变。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkMarkerKind {
    Direct,
    Relay,
}

impl LinkMarkerKind {
    /// `links.json` 的稳定字符串值（逐字锁定旧格式）。
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Relay => "relay",
        }
    }

    /// 从 `links.json` 的字符串值解析；未知值返回与旧实现同文案的错误。
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "direct" => Ok(Self::Direct),
            "relay" => Ok(Self::Relay),
            other => Err(format!("unknown link kind: {other}")),
        }
    }
}

/// 已建立链路的 durable marker：进程死亡后可恢复的最小链路状态。
///
/// 语义（诚实）：marker 只记录"crash 前存在一条已建立链路"这一事实。
/// 进程死亡 = socket 死亡，冷启动 reconcile 必须把未 stale 的 marker 标为 stale
/// （触发重建），不许假装链路还活着。stale marker 的清理/覆盖由 Composition Root 决定。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkMarker {
    /// 稳定链路标识（如 `"direct/<peer>"`；同一标识只保留最新一条）。
    pub link_id: String,
    /// 链路类型。
    pub kind: LinkMarkerKind,
    /// 建连目标 locator。
    pub locator: String,
    /// 建立时间的 unix 秒（诊断用，不参与 reconcile 决策）。
    pub established_at_unix: u64,
    /// 是否已在冷启动 reconcile 中被标为 stale。
    pub stale: bool,
}

impl LinkMarker {
    /// 新建一条"已建立、未 stale"的 marker。
    #[must_use]
    pub fn established(
        link_id: impl Into<String>,
        kind: LinkMarkerKind,
        locator: impl Into<String>,
        established_at_unix: u64,
    ) -> Self {
        Self {
            link_id: link_id.into(),
            kind,
            locator: locator.into(),
            established_at_unix,
            stale: false,
        }
    }
}

/// 链路 marker 存储契约（Portable；文件实现由 Composition Root 注入，
/// 与 `nexus_session::SessionRecordStore` 同模式）。
pub trait LinkMarkerStore {
    /// 加载全部 marker；文件不存在视为 Ok(vec![])，损坏必须返回 Err（不静默丢弃）。
    fn load(&self) -> Result<Vec<LinkMarker>, String>;
    /// 按 `link_id` upsert 一条 marker（原子写）。
    fn save(&mut self, marker: &LinkMarker) -> Result<(), String>;
}

/// 冷启动链路 marker reconcile 的结构化结果。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LinkReconcileReport {
    /// 检查的 marker 数。
    pub markers_checked: usize,
    /// 本轮被标为 stale 的数量。
    pub marked_stale: usize,
}

/// 冷启动 reconcile 链路 marker（幂等；v9 §15.3）。
///
/// 规则：
/// - 未 stale 的 marker → 标为 stale 并回写（进程已死，其 socket 不可能存活）；
/// - 已 stale → 跳过。
///
///   本函数只标记，不建连；重建是调用方（重建链路的一方）的职责
///   （由调用方根据报告触发）。
pub fn reconcile_link_markers<S: LinkMarkerStore>(
    store: &mut S,
) -> Result<LinkReconcileReport, String> {
    let markers = store.load()?;
    let mut report = LinkReconcileReport {
        markers_checked: markers.len(),
        marked_stale: 0,
    };
    for marker in markers {
        if marker.stale {
            continue;
        }
        let mut stale = marker.clone();
        stale.stale = true;
        store.save(&stale)?;
        report.marked_stale += 1;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Default)]
    struct MemStore {
        markers: RefCell<Vec<LinkMarker>>,
    }

    impl LinkMarkerStore for MemStore {
        fn load(&self) -> Result<Vec<LinkMarker>, String> {
            Ok(self.markers.borrow().clone())
        }

        fn save(&mut self, marker: &LinkMarker) -> Result<(), String> {
            let mut markers = self.markers.borrow_mut();
            if let Some(slot) = markers.iter_mut().find(|m| m.link_id == marker.link_id) {
                *slot = marker.clone();
            } else {
                markers.push(marker.clone());
            }
            Ok(())
        }
    }

    #[test]
    fn kind_strings_are_stable() {
        assert_eq!(LinkMarkerKind::Direct.as_str(), "direct");
        assert_eq!(LinkMarkerKind::Relay.as_str(), "relay");
        assert_eq!(LinkMarkerKind::parse("direct"), Ok(LinkMarkerKind::Direct));
        assert_eq!(LinkMarkerKind::parse("relay"), Ok(LinkMarkerKind::Relay));
        assert_eq!(
            LinkMarkerKind::parse("quic"),
            Err("unknown link kind: quic".to_string())
        );
    }

    #[test]
    fn reconcile_marks_unstale_once_and_is_idempotent() {
        let mut store = MemStore::default();
        store
            .save(&LinkMarker::established(
                "direct/p1",
                LinkMarkerKind::Direct,
                "10.0.0.1:1",
                100,
            ))
            .unwrap();
        store
            .save(&LinkMarker::established(
                "relay/p2",
                LinkMarkerKind::Relay,
                "relay.example:443",
                200,
            ))
            .unwrap();

        let report = reconcile_link_markers(&mut store).unwrap();
        assert_eq!(report.markers_checked, 2);
        assert_eq!(report.marked_stale, 2);
        assert!(store.load().unwrap().iter().all(|m| m.stale));
        // locator/kind 保留，供重建路径使用。
        let kept = store.load().unwrap();
        assert_eq!(kept[0].kind, LinkMarkerKind::Direct);
        assert_eq!(kept[0].locator, "10.0.0.1:1");

        let again = reconcile_link_markers(&mut store).unwrap();
        assert_eq!(again.markers_checked, 2);
        assert_eq!(again.marked_stale, 0, "must not re-mark stale markers");
    }

    #[test]
    fn empty_store_reconciles_cleanly() {
        let mut store = MemStore::default();
        let report = reconcile_link_markers(&mut store).unwrap();
        assert_eq!(report.markers_checked, 0);
        assert_eq!(report.marked_stale, 0);
    }
}

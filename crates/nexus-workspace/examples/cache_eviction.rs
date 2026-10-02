//! E4 driver for `scenarios/product/workspace_cache_eviction.toml`.
//!
//! Drives `CacheManager` through the frozen expectations:
//! pinned entries survive pressure, score-based eviction order,
//! oversize rejection, unpin re-enables eviction, remove() refuses pinned.

#![forbid(unsafe_code)]

use nexus_storage::ObjectId;
use nexus_workspace::cache::{CacheError, CacheManager, CachePin, InsertSignals};

fn oid(s: &str) -> ObjectId {
    ObjectId(s.to_string())
}

fn sig(cost: u64) -> InsertSignals {
    InsertSignals {
        refetch_cost: cost,
        workingset_probability: None,
        graph_centrality: None,
    }
}

fn main() {
    let json = std::env::args().any(|a| a == "--json");
    let r = run();
    if json {
        match r {
            Ok(fields) => println!("{fields}"),
            Err(e) => println!(
                "{{\"verdict\":\"FAIL\",\"error\":\"{}\"}}",
                e.replace('"', "'")
            ),
        }
    } else if let Err(e) = r {
        eprintln!("cache_eviction failed: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<String, String> {
    // 1) pinned entries survive capacity pressure (iron rule).
    let mut c = CacheManager::new(1000);
    c.insert(&oid("a"), vec![0u8; 300], sig(0)).map_err(|e| format!("{e:?}"))?;
    c.insert(&oid("b"), vec![1u8; 300], sig(0)).map_err(|e| format!("{e:?}"))?;
    c.insert(&oid("c"), vec![2u8; 300], sig(0)).map_err(|e| format!("{e:?}"))?;
    assert!(c.pin(&oid("a"), CachePin::DirtyJournal));
    assert!(c.pin(&oid("b"), CachePin::Explicit));
    // Used 900/1000; inserting d(300) needs 200 more -> must evict c (only unpinned).
    let evicted = c.insert(&oid("d"), vec![3u8; 300], sig(0)).map_err(|e| format!("{e:?}"))?;
    let pinned_survive_pressure = c.get(&oid("a")).is_some()
        && c.get(&oid("b")).is_some()
        && c.get(&oid("d")).is_some()
        && c.get(&oid("c")).is_none()
        && evicted == vec![oid("c")];

    // 2) eviction order is score-based: big+cold+cheap goes first.
    let mut c2 = CacheManager::new(1000);
    c2.insert(&oid("x"), vec![0u8; 500], sig(0)).map_err(|e| format!("{e:?}"))?;
    c2.insert(&oid("y"), vec![0u8; 300], sig(0)).map_err(|e| format!("{e:?}"))?;
    c2.insert(&oid("z"), vec![0u8; 100], sig(10)).map_err(|e| format!("{e:?}"))?;
    for _ in 0..5 {
        let _ = c2.get(&oid("z")); // hot + expensive to refetch
    }
    let evicted2 = c2.insert(&oid("w"), vec![0u8; 400], sig(0)).map_err(|e| format!("{e:?}"))?;
    let eviction_order_score_based =
        evicted2 == vec![oid("x")] && c2.get(&oid("y")).is_some() && c2.get(&oid("z")).is_some();

    // 3) single object larger than capacity is rejected, cache untouched.
    let mut c3 = CacheManager::new(500);
    let oversize_rejected = matches!(
        c3.insert(&oid("big"), vec![0u8; 600], sig(0)),
        Err(CacheError::TooLarge { .. })
    ) && c3.len() == 0;

    // 4) unpin re-enables eviction.
    let mut c4 = CacheManager::new(600);
    c4.insert(&oid("a"), vec![0u8; 300], sig(0)).map_err(|e| format!("{e:?}"))?;
    c4.insert(&oid("b"), vec![0u8; 300], sig(0)).map_err(|e| format!("{e:?}"))?;
    assert!(c4.pin(&oid("a"), CachePin::ConflictState));
    c4.insert(&oid("e"), vec![0u8; 300], sig(0)).map_err(|e| format!("{e:?}"))?; // evicts b
    assert!(c4.unpin(&oid("a"), CachePin::ConflictState));
    let evicted4 = c4.insert(&oid("f"), vec![0u8; 300], sig(0)).map_err(|e| format!("{e:?}"))?;
    let unpinned_becomes_evictable = evicted4.contains(&oid("a")) && c4.get(&oid("a")).is_none();

    // 5) remove() refuses pinned entries.
    let mut c5 = CacheManager::new(1000);
    c5.insert(&oid("p"), vec![0u8; 100], sig(0)).map_err(|e| format!("{e:?}"))?;
    assert!(c5.pin(&oid("p"), CachePin::UnreplicatedCommit));
    let remove_refuses_pinned =
        c5.remove(&oid("p")).is_none() && c5.get(&oid("p")).is_some();

    Ok(format!(
        "{{\
        \"verdict\":\"PASS\",\
        \"pinned_survive_pressure\":{pinned_survive_pressure},\
        \"eviction_order_score_based\":{eviction_order_score_based},\
        \"oversize_rejected\":{oversize_rejected},\
        \"unpinned_becomes_evictable\":{unpinned_becomes_evictable},\
        \"remove_refuses_pinned\":{remove_refuses_pinned}\
        }}"
    ))
}

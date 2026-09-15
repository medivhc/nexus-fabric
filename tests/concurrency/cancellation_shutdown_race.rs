//! 并发竞态：协作取消与所有权失效保护（ARCHITECTURE §7 / tests/README.md）。
//!
//! 验证：`CancelToken` 只表达"请求停止"，并发 cancel 首次置位唯一；
//! `AbortOnDropHandle` 在 Owner 消失（drop）时自动请求取消，防止任务泄漏。

use std::sync::Arc;
use std::thread;

use nexus_session::{AbortOnDropHandle, CancelToken};

/// 8 个线程同时 `cancel()`，必须恰好 1 个观察到"首次置位"（first-win）。
#[test]
fn concurrent_cancel_is_first_win() {
    let token = Arc::new(CancelToken::new());

    let handles: Vec<_> = (0..8)
        .map(|_| {
            let token = Arc::clone(&token);
            thread::spawn(move || token.cancel())
        })
        .collect();

    let first_wins = handles
        .into_iter()
        .map(|h| h.join().expect("thread joined"))
        .filter(|ok| *ok)
        .count();

    assert_eq!(
        first_wins, 1,
        "exactly one cancel() call may observe first-set"
    );
    assert!(
        token.is_cancelled(),
        "token must be cancelled after any cancel"
    );
}

/// 已取消的令牌再次 cancel 一律返回 false，且状态保持不变。
#[test]
fn cancel_after_cancel_never_returns_first() {
    let token = CancelToken::new();
    assert!(token.cancel());
    for _ in 0..8 {
        assert!(!token.cancel());
    }
    assert!(token.is_cancelled());
}

/// `AbortOnDropHandle` 被 drop（Owner 消失）时自动请求取消；
/// 多个 guard 共享同一令牌时，最后一个 guard drop 后令牌仍处于已取消状态。
#[test]
fn abort_on_drop_cancels_token_when_owner_dies() {
    let token = CancelToken::new();
    {
        let _guard = AbortOnDropHandle::new(token.clone());
        assert!(!token.is_cancelled(), "alive owner: not cancelled");
    }
    assert!(token.is_cancelled(), "owner died: must cancel");
}

/// 取消后 `is_cancelled` 对所有观察者一致（Acquire/Release 可见性）。
#[test]
fn cancellation_is_visible_across_threads() {
    let token = Arc::new(CancelToken::new());
    let observer = Arc::clone(&token);
    let handle = thread::spawn(move || {
        while !observer.is_cancelled() {
            thread::yield_now();
        }
        true
    });

    // 主线程稍后请求取消。
    thread::sleep(std::time::Duration::from_millis(10));
    token.cancel();

    assert!(
        handle.join().expect("observer joined"),
        "observer must see cancel"
    );
}

//! Repunch scheduler: pure state machine, virtual-time testable.
//!
//! Triggers: periodic (`repunch_interval`), reflexive change, relay
//! degradation. Events coalesce within 5s; any symmetric side disables all
//! automatic repunch (C-22).

use std::collections::VecDeque;

use nexus_nat_traversal::PunchConfig;

pub use crate::status::RepunchTrigger;

/// Event coalescing window (frozen 5000ms).
const EVENT_COALESCE_MS: u64 = 5_000;

#[derive(Debug)]
pub struct Scheduler {
    interval_ms: u64,
    last_periodic_ms: u64,
    pending: VecDeque<(u64, RepunchTrigger)>,
    last_event_emit_ms: Option<u64>,
}

impl Scheduler {
    pub fn new(config: &PunchConfig) -> Self {
        Self {
            interval_ms: config.repunch_interval.as_millis() as u64,
            last_periodic_ms: 0,
            pending: VecDeque::new(),
            last_event_emit_ms: None,
        }
    }

    /// Record a successful/attempted session start so periodic cadence restarts.
    pub fn note_attempt(&mut self, now_ms: u64) {
        self.last_periodic_ms = now_ms;
    }

    pub fn note_event(&mut self, now_ms: u64, trigger: RepunchTrigger) {
        // Coalesce duplicate queued trigger kinds.
        if self.pending.iter().any(|(_, t)| *t == trigger) {
            return;
        }
        self.pending.push_back((now_ms, trigger));
    }

    /// One scheduler tick. `symmetric` means either side is Symmetric: all
    /// automatic repunch is disabled and queued events are dropped.
    pub fn on_tick(&mut self, now_ms: u64, symmetric: bool) -> Option<RepunchTrigger> {
        if symmetric {
            self.pending.clear();
            return None;
        }
        if let Some((at, trigger)) = self.pending.front().copied() {
            if now_ms >= at {
                if self
                    .last_event_emit_ms
                    .is_none_or(|last| now_ms >= last.saturating_add(EVENT_COALESCE_MS))
                {
                    self.pending.pop_front();
                    self.last_event_emit_ms = Some(now_ms);
                    self.last_periodic_ms = now_ms;
                    return Some(trigger);
                }
                // Inside the coalescing window: fold queued events into the
                // window instead of emitting a storm.
                self.pending.clear();
            }
        }
        if now_ms >= self.last_periodic_ms.saturating_add(self.interval_ms) {
            self.last_periodic_ms = now_ms;
            return Some(RepunchTrigger::Periodic);
        }
        None
    }
}

//! Requester cache and cancellation delivery intent, never a provider state writer.
use crate::task::record_codec;
use nexus_domain::task::{
    codec::{CanonicalDto, DigestFn, Value},
    *,
};
use std::collections::BTreeMap;

/// Service-authenticated scope; callers cannot supply this through a Task DTO.
#[derive(Debug, Clone, Copy)]
pub struct RequesterScope<'a> {
    pub principal: &'a str,
    pub provider: &'a str,
    pub workspace: &'a str,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelReason {
    User,
    Revoked,
}
impl CancelReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::User => "User",
            Self::Revoked => "Revoked",
        }
    }
}
/// The original provider image remains intact. Only view() applies local overlays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequesterMirror {
    provider_view: TaskView,
    observation_lost: bool,
    intent: CancelRequestIntent,
}
record_codec!(RequesterMirror {
    provider_view: TaskView,
    observation_lost: bool,
    intent: CancelRequestIntent
});
impl RequesterMirror {
    /// The composition root must authenticate both the user and provider channel.
    pub fn new(
        view: TaskView,
        scope: RequesterScope<'_>,
        hash: DigestFn,
    ) -> Result<Self, TaskError> {
        native(&view, hash)?;
        scoped(&view, scope)?;
        Ok(Self {
            intent: view.cancel_request.clone(),
            provider_view: view,
            observation_lost: false,
        })
    }
    pub fn validate(&self, hash: DigestFn) -> Result<(), TaskError> {
        native(&self.provider_view, hash)?;
        self.intent.validate()?;
        if self.intent.origin != IntentOrigin::RequesterIntent
            || self
                .intent
                .reason
                .as_deref()
                .is_some_and(|r| r != "User" && r != "Revoked")
        {
            return Err(TaskError::invalid(
                "invalid requester cancellation origin/reason",
            ));
        }
        if self
            .intent
            .requested_at_unix
            .is_some_and(|t| t < self.provider_view.accepted_contract.accepted_at_unix)
        {
            return Err(TaskError::invalid("cancel intent precedes task acceptance"));
        }
        self.view().validate()
    }
    pub fn view(&self) -> TaskView {
        let mut v = self.provider_view.clone();
        v.cancel_request = self.intent.clone();
        if self.observation_lost {
            v.observation = Observation::PendingVerification;
        }
        v
    }
    pub fn provider_view(&self) -> &TaskView {
        &self.provider_view
    }
    pub fn authorize_scope(&self, scope: RequesterScope<'_>) -> Result<(), TaskError> {
        scoped(&self.provider_view, scope)
    }
    /// Reconnection never submits or starts work. Replayed identical images also
    /// restore observation freshness, while preserving a pending local cancel.
    pub fn receive(
        &mut self,
        view: TaskView,
        scope: RequesterScope<'_>,
        hash: DigestFn,
    ) -> Result<(), TaskError> {
        self.authorize_scope(scope)?;
        native(&view, hash)?;
        scoped(&view, scope)?;
        validate_provider_transition(&self.provider_view, &view)?;
        self.provider_view = view;
        self.observation_lost = false;
        Ok(())
    }
    pub fn disconnected(&mut self) {
        self.observation_lost = true;
    }
    /// Pure reduction only: the daemon must durably publish before returning Queued.
    pub fn queue_cancel(
        &mut self,
        scope: RequesterScope<'_>,
        reason: CancelReason,
        at_unix: u64,
    ) -> Result<(), TaskError> {
        self.authorize_scope(scope)?;
        if self.intent.state != CancelRequestState::None {
            if self.intent.reason.as_deref() != Some(reason.as_str()) {
                return Err(TaskError::invalid("cancel intent reason is immutable"));
            }
            return Ok(());
        }
        if at_unix < self.provider_view.accepted_contract.accepted_at_unix || at_unix > MAX_INTEGER
        {
            return Err(TaskError::invalid("invalid cancel intent clock"));
        }
        self.intent = CancelRequestIntent {
            origin: IntentOrigin::RequesterIntent,
            state: CancelRequestState::Queued,
            requested_at_unix: Some(at_unix),
            reason: Some(reason.as_str().into()),
            error: None,
        };
        self.observation_lost = true;
        Ok(())
    }
    /// Only call after a scoped durable provider acknowledgement, or rejection.
    /// The response TaskId is taken from the authenticated response envelope.
    /// Neither proves that a process stopped. Terminal images retain pending intent.
    pub fn settle_cancel(
        &mut self,
        scope: RequesterScope<'_>,
        response_task_id: &TaskId,
        rejection: Option<TaskError>,
    ) -> Result<(), TaskError> {
        self.authorize_scope(scope)?;
        if response_task_id != &self.provider_view.task_id {
            return Err(TaskError::invalid(
                "cancel response belongs to another Task",
            ));
        }
        if let Some(e) = &rejection {
            e.validate()?;
        }
        let state = if rejection.is_some() {
            CancelRequestState::Rejected
        } else {
            CancelRequestState::Acknowledged
        };
        if self.intent.state == state && self.intent.error == rejection {
            return Ok(());
        }
        if self.intent.state != CancelRequestState::Queued {
            return Err(TaskError::invalid(
                "cancel acknowledgement lacks pending intent or conflicts",
            ));
        }
        self.intent.state = state;
        self.intent.error = rejection;
        Ok(())
    }
    pub fn cancel_pending(&self) -> bool {
        self.intent.state == CancelRequestState::Queued
    }
}
fn native(v: &TaskView, hash: DigestFn) -> Result<(), TaskError> {
    v.verify_digests(hash)?;
    if v.cancel_request.state != CancelRequestState::None {
        return Err(TaskError::invalid(
            "provider native view contains requester intent",
        ));
    }
    Ok(())
}
fn scoped(v: &TaskView, s: RequesterScope<'_>) -> Result<(), TaskError> {
    let c = &v.accepted_contract;
    if c.authenticated_principal != s.principal
        || c.request.provider != s.provider
        || c.request.workspace != s.workspace
    {
        return Err(TaskError::new(
            TaskErrorCode::AuthDenied,
            "requester authenticated scope differs",
            false,
        ));
    }
    Ok(())
}
#[cfg(test)]
#[path = "task_requester_tests.rs"]
mod tests;

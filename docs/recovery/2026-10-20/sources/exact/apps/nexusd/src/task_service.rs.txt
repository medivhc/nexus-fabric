//! Optional local provider service. Submit remains gated on real remote prerequisites.
use nexus_control_api::task::{TaskEnvelope, TaskRequest};
// `TaskCallContext` / `TaskResponse` 由 Linux-only 的 `task_service_provider`
// （经 `use super::*` 继承本模块导入）与各 `#[cfg(target_os = "linux")]` 分支消费。
#[cfg(target_os = "linux")]
use nexus_control_api::task::{TaskCallContext, TaskResponse};
use nexus_domain::task::{TaskError, TaskErrorCode, TaskId};
use std::path::{Path, PathBuf};
/// Borrowed by every daemon consumer; only the composition root constructs it.
pub type SharedSessionManager =
    std::sync::Arc<std::sync::Mutex<Option<nexus_session::SessionManager>>>;
#[cfg(target_os = "linux")]
#[path = "task_service_provider.rs"]
mod provider;

pub struct LocalTaskService {
    config_root: PathBuf,
    #[cfg(target_os = "linux")]
    provider: Result<Option<provider::ProviderService>, TaskError>,
}
impl LocalTaskService {
    /// Boot runs once before READY; later queries never initialize authority.
    pub fn open(config_root: &Path) -> Self {
        Self {
            config_root: config_root.to_owned(),
            #[cfg(target_os = "linux")]
            provider: load(config_root, None),
        }
    }
    /// Production composition injects the existing sole resource Session owner.
    pub fn open_with_sessions(config_root: &Path, sessions: SharedSessionManager) -> Self {
        #[cfg(not(target_os = "linux"))]
        let _ = sessions;
        Self {
            config_root: config_root.to_owned(),
            #[cfg(target_os = "linux")]
            provider: load(config_root, Some(sessions)),
        }
    }
    /// Trusted Rust composition entry. No LocalAPI operation calls this method.
    pub fn prepare_with_existing_session(
        &self,
        task_id: &TaskId,
        session_id: &nexus_domain::SessionId,
    ) -> Result<nexus_compute::task_runtime::RuntimeState, TaskError> {
        #[cfg(target_os = "linux")]
        {
            let service = self
                .provider
                .as_ref()
                .map_err(Clone::clone)?
                .as_ref()
                .ok_or_else(|| unsupported("local Task service disabled"))?;
            let principal = nexus::task_authorization::authenticated_principal(&self.config_root)?;
            let context =
                TaskCallContext::from_authenticated(principal, service.workspace().to_owned())?;
            service.prepare_with_existing_session(&context, task_id, session_id)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (task_id, session_id);
            Err(unsupported("local provider Task service requires Linux"))
        }
    }
    pub fn execute(&self, request: TaskRequest) -> TaskEnvelope {
        let task_id = request.task_id().cloned();
        let result = (|| {
            request.validate()?;
            #[cfg(target_os = "linux")]
            {
                let service = self.provider.as_ref().map_err(Clone::clone)?.as_ref().ok_or_else(|| unsupported("TaskApplicationService is not assembled: task-api.toml is absent; local Task service disabled"))?;
                let principal =
                    nexus::task_authorization::authenticated_principal(&self.config_root)?;
                let context =
                    TaskCallContext::from_authenticated(principal, service.workspace().to_owned())?;
                use nexus_control_api::task::TaskApplicationService;
                let response = service.execute(&context, request)?;
                response.validate()?;
                Ok(response)
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (&self.config_root, request);
                Err(unsupported("local provider Task service requires Linux"))
            }
        })();
        match result {
            Ok(response) => TaskEnvelope::Success(response),
            Err(error) => TaskEnvelope::Error { error, task_id },
        }
    }
}
fn unsupported(reason: &str) -> TaskError {
    TaskError::new(TaskErrorCode::UnsupportedCapability, reason, false)
}
#[cfg(target_os = "linux")]
fn load(
    config_root: &Path,
    sessions: Option<SharedSessionManager>,
) -> Result<Option<provider::ProviderService>, TaskError> {
    use std::{fs, io::Read, os::unix::fs::OpenOptionsExt};
    // A remaining managed anchor must never fall back to disabled/legacy mode,
    // or open a store that can create a replacement identity or authority.
    crate::task_provider_init::validate_managed_root(config_root)?;
    let path = config_root.join("task-api.toml");
    let mut file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(0x20000 | 0x800)
        .open(&path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(TaskError::invalid(format!("task-api config: {e}"))),
    };
    if !file
        .metadata()
        .map_err(|e| TaskError::invalid(e.to_string()))?
        .is_file()
    {
        return Err(TaskError::invalid("task-api config must be regular"));
    }
    let mut text = String::new();
    file.by_ref()
        .take(16_385)
        .read_to_string(&mut text)
        .map_err(|e| TaskError::invalid(e.to_string()))?;
    if text.len() > 16_384 {
        return Err(TaskError::invalid("task-api config too large"));
    }
    let value: toml::Table = text
        .parse()
        .map_err(|e: toml::de::Error| TaskError::invalid(e.to_string()))?;
    if value.len() != 2 {
        return Err(TaskError::invalid(
            "task-api config requires only provider and workspace",
        ));
    }
    let provider = value
        .get("provider")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| TaskError::invalid("missing provider"))?;
    let workspace = value
        .get("workspace")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| TaskError::invalid("missing workspace"))?;
    TaskId::new(provider.to_owned())?;
    TaskId::new(workspace.to_owned())?;
    provider::ProviderService::open(config_root, provider, workspace, sessions).map(Some)
}

#[cfg(all(test, target_os = "linux"))]
#[path = "task_service_tests.rs"]
mod tests;

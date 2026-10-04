//! Provider-private append files and checksummed progress. Never reset on reopen.
use super::*;
use std::io::{Seek, SeekFrom};
use std::os::unix::{fs::OpenOptionsExt, io::AsRawFd};

pub(super) struct Logs {
    pub(super) directory: PathBuf,
    task: String,
    contract: String,
    limit: u64,
}
impl Logs {
    pub(super) fn create(
        root: &Path,
        task: &TaskId,
        contract: &Sha256Digest,
        limit: u64,
    ) -> Result<Self, TaskError> {
        private_dir(&root.join("executions-v1"))?;
        let result = Self::location(root, task, contract, limit);
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&result.directory)
            .map_err(|_| {
                corrupt(
                    "execution authority already exists or cannot be created; reconcile required",
                )
            })?;
        sync_dir(
            result
                .directory
                .parent()
                .ok_or_else(|| corrupt("missing execution parent"))?,
        )?;
        for name in ["stdout", "stderr", "logs.lock", "owner.lock", "start.lock"] {
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(result.directory.join(name))
                .map_err(io_error)?
                .sync_all()
                .map_err(io_error)?;
        }
        result.save(&json!({"schema_version":1,"task_id":result.task,"contract_digest":result.contract,"limit":limit,"sizes":[0,0],"truncated":[false,false],"sealed":false}))?;
        Ok(result)
    }
    fn location(root: &Path, task: &TaskId, contract: &Sha256Digest, limit: u64) -> Self {
        Self {
            directory: root
                .join("executions-v1")
                .join(&sha256(task.as_str().as_bytes()).as_str()[7..]),
            task: task.as_str().to_owned(),
            contract: contract.as_str().to_owned(),
            limit,
        }
    }
    pub(super) fn open(
        root: &Path,
        task: &TaskId,
        contract: &Sha256Digest,
        limit: u64,
    ) -> Result<Self, TaskError> {
        let result = Self::location(root, task, contract, limit);
        check_dir(&root.join("executions-v1"))?;
        check_dir(&result.directory)?;
        let _lock = result.lock("logs.lock", false)?;
        result.load()?;
        Ok(result)
    }
    pub(super) fn lock(&self, name: &str, nonblocking: bool) -> Result<File, TaskError> {
        let file = checked_file(&self.directory.join(name), true)?;
        unsafe extern "C" {
            fn flock(fd: std::ffi::c_int, op: std::ffi::c_int) -> std::ffi::c_int;
        }
        loop {
            // SAFETY: live owned fd, LOCK_EX (+ LOCK_NB) have no pointer argument.
            if unsafe { flock(file.as_raw_fd(), if nonblocking { 6 } else { 2 }) } == 0 {
                return Ok(file);
            }
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if nonblocking && e.kind() == std::io::ErrorKind::WouldBlock {
                return Err(TaskError::new(
                    TaskErrorCode::CapacityUnavailable,
                    "execution owner is active",
                    true,
                ));
            }
            return Err(TaskError::new(
                TaskErrorCode::PersistenceFailed,
                "execution authority is locked or unavailable",
                true,
            ));
        }
    }
    fn load(&self) -> Result<Json, TaskError> {
        let mut file = checked_file(&self.directory.join("logs-v1.json"), false)?;
        let mut raw = Vec::new();
        Read::by_ref(&mut file)
            .take(16385)
            .read_to_end(&mut raw)
            .map_err(io_error)?;
        if raw.len() > 16384 {
            return Err(corrupt("oversized log authority"));
        }
        let envelope: Json = serde_json::from_slice(&parse_canonical_json(&raw)?.canonical_bytes())
            .map_err(json_error)?;
        let payload = &envelope["payload"];
        if envelope.as_object().map(|x| x.len()) != Some(2)
            || envelope["checksum"] != sha256(&canonical(payload)?).as_str()
            || payload.as_object().map(|x| x.len()) != Some(7)
            || payload["schema_version"] != 1
            || payload["task_id"] != self.task
            || payload["contract_digest"] != self.contract
            || payload["limit"] != self.limit
            || !payload["sealed"].is_boolean()
            || payload["sizes"].as_array().map(Vec::len) != Some(2)
            || payload["truncated"].as_array().map(Vec::len) != Some(2)
        {
            return Err(corrupt("invalid or mismatched log authority"));
        }
        let mut total = 0u64;
        for (i, name) in ["stdout", "stderr"].iter().enumerate() {
            let n = payload["sizes"][i]
                .as_u64()
                .ok_or_else(|| corrupt("invalid log length"))?;
            total = total
                .checked_add(n)
                .ok_or_else(|| corrupt("log length overflow"))?;
            if !payload["truncated"][i].is_boolean()
                || checked_file(&self.directory.join(name), false)?
                    .metadata()
                    .map_err(io_error)?
                    .len()
                    != n
            {
                return Err(corrupt("log bytes differ from durable authority"));
            }
        }
        if total > self.limit {
            return Err(corrupt("log quota exceeded"));
        }
        Ok(payload.clone())
    }
    fn save(&self, payload: &Json) -> Result<(), TaskError> {
        let envelope = json!({"payload":payload,"checksum":sha256(&canonical(payload)?).as_str()});
        publish(&self.directory, "logs-v1.json", &canonical(&envelope)?)
    }
    pub(super) fn append(&self, stream: usize, bytes: &[u8]) -> Result<(), TaskError> {
        if stream > 1 {
            return Err(TaskError::invalid("invalid log stream"));
        }
        let _lock = self.lock("logs.lock", false)?;
        let mut payload = self.load()?;
        if payload["sealed"] == true {
            return Err(corrupt("cannot append sealed logs"));
        }
        let before = payload.clone();
        let a = payload["sizes"][0]
            .as_u64()
            .ok_or_else(|| corrupt("invalid stdout length"))?;
        let b = payload["sizes"][1]
            .as_u64()
            .ok_or_else(|| corrupt("invalid stderr length"))?;
        let count = bytes
            .len()
            .min((self.limit - a - b).min(usize::MAX as u64) as usize);
        if count > 0 {
            let name = ["stdout", "stderr"][stream];
            let mut file = checked_file(&self.directory.join(name), true)?;
            file.seek(SeekFrom::End(0)).map_err(io_error)?;
            file.write_all(&bytes[..count]).map_err(io_error)?;
            file.sync_all().map_err(io_error)?;
            let old = payload["sizes"][stream]
                .as_u64()
                .ok_or_else(|| corrupt("invalid log length"))?;
            payload["sizes"][stream] = json!(old + count as u64);
        }
        if count < bytes.len() {
            payload["truncated"][stream] = json!(true);
        }
        if payload != before {
            self.save(&payload)?;
        }
        Ok(())
    }
    pub(super) fn seal(&self) -> Result<(), TaskError> {
        let _lock = self.lock("logs.lock", false)?;
        let mut payload = self.load()?;
        payload["sealed"] = json!(true);
        self.save(&payload)
    }
    pub(super) fn sealed(&self) -> Result<bool, TaskError> {
        let _lock = self.lock("logs.lock", false)?;
        Ok(self.load()?["sealed"] == true)
    }
    pub(super) fn page(
        &self,
        stream: LogStream,
        offset: u64,
        max_bytes: usize,
    ) -> Result<LogPage, TaskError> {
        if max_bytes == 0 || max_bytes > 65536 {
            return Err(TaskError::invalid("log page must be 1..65536 bytes"));
        }
        let _lock = self.lock("logs.lock", false)?;
        let payload = self.load()?;
        let i = match stream {
            LogStream::Stdout => 0,
            LogStream::Stderr => 1,
        };
        let n = payload["sizes"][i]
            .as_u64()
            .ok_or_else(|| corrupt("invalid log length"))?;
        if offset > n {
            return Err(TaskError::invalid("log offset beyond retained bytes"));
        }
        let mut file = checked_file(&self.directory.join(["stdout", "stderr"][i]), false)?;
        file.seek(SeekFrom::Start(offset)).map_err(io_error)?;
        let mut bytes = vec![0; (n - offset).min(max_bytes as u64) as usize];
        file.read_exact(&mut bytes).map_err(io_error)?;
        let next_offset = offset + bytes.len() as u64;
        Ok(LogPage {
            bytes,
            next_offset,
            eof: payload["sealed"] == true && next_offset == n,
            truncated: payload["truncated"][i] == true,
        })
    }
}
fn canonical(value: &Json) -> Result<Vec<u8>, TaskError> {
    Ok(parse_canonical_json(&serde_json::to_vec(value).map_err(json_error)?)?.canonical_bytes())
}
pub(super) fn publish(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), TaskError> {
    let temp = dir.join(format!(".publish-{}.tmp", new_task_id()?.as_str()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temp)
        .map_err(io_error)?;
    file.write_all(bytes).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    fs::rename(temp, dir.join(name)).map_err(io_error)?;
    sync_dir(dir)
}
pub(super) fn checked_file(path: &Path, write: bool) -> Result<File, TaskError> {
    let file = OpenOptions::new()
        .read(true)
        .write(write)
        .custom_flags(0x20000 | 0x800)
        .open(path)
        .map_err(|_| corrupt("missing or inaccessible log authority"))?;
    let meta = file.metadata().map_err(io_error)?;
    if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 {
        return Err(corrupt("log authority must be private regular file"));
    }
    Ok(file)
}

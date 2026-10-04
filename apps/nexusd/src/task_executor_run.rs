//! Execution call owns its drain thread and namespace cleanup.
use super::*;
impl LinuxTaskExecutor {
    pub(super) fn execute(
        &self,
        id: &TaskId,
        contract: &AcceptedContract,
        input: &Path,
        frozen: &nexus_workspace::snapshot::FrozenSnapshot,
        logs: &Logs,
        verify_start: &mut dyn FnMut(&AcceptedContract) -> Result<(), TaskError>,
    ) -> Result<RuntimeState, TaskError> {
        let digest = self.owner.runtime(id)?.view.contract_digest;
        let limits = &contract.request.limits;
        let name = format!(
            "nexus-task-{}",
            &sha256(id.as_str().as_bytes()).as_str()[7..]
        );
        let tmpfs = format!(
            "rw,exec,nosuid,nodev,size={},mode=0700,uid=65534,gid=65534",
            limits.storage_bytes
        );
        let transfer = transfer_input(logs, input, frozen)?;
        let value = self.docker.request("POST",&format!("/containers/create?name={name}"),json!({
            "Image":contract.environment_evidence.image_digest.as_str(),"Entrypoint":["/bin/sleep"],"Cmd":["2147483647"],"User":"65534:65534","WorkingDir":"/","Labels":{"nexus.task_id":id.as_str(),"nexus.contract_digest":digest.as_str()},
            "HostConfig":{"NetworkMode":"none","ReadonlyRootfs":true,"Privileged":false,"IpcMode":"none","CgroupnsMode":"private","Memory":limits.memory_bytes,"MemorySwap":limits.memory_bytes,"CpuPeriod":100000,"CpuQuota":limits.cpu_millis*100,"PidsLimit":256,"CapDrop":["ALL"],"CapAdd":[],"SecurityOpt":["no-new-privileges"],"LogConfig":{"Type":"none"},"Tmpfs":{"/work":tmpfs},"Mounts":[{"Type":"bind","Source":transfer.to_str().ok_or_else(||unsupported("transfer root is not UTF-8"))?,"Target":"/input","ReadOnly":true,"BindOptions":{"Propagation":"rprivate"}}]}
        }))?;
        let container = docker::string(&value, "Id")?.to_owned();
        docker::engine_id(&container)?;
        let mut guard = ContainerGuard {
            docker: self.docker.clone(),
            id: container.clone(),
            stopped: false,
        };
        self.docker.operation(&container, "start")?;
        verify_container(
            &self.docker.inspect(&container)?,
            id,
            &digest,
            contract,
            &tmpfs,
            &transfer,
        )?;
        self.docker
            .helper(&container, &["/bin/cp", "-R", "/input/.", "/work/"])?;
        let prepared_archive = self.docker.archive(&container)?;
        let files = archive::parse(&prepared_archive)?;
        for file in &frozen.files {
            let entry = archive::regular(&files, &file.path)?;
            if entry.bytes.len() as u64 != file.size_bytes
                || sha256(entry.bytes) != file.sha256
                || (entry.mode & 0o111 != 0) != file.executable
            {
                return Err(TaskError::new(
                    TaskErrorCode::InputIntegrityFailed,
                    "materialized input length/digest/mode mismatch",
                    false,
                ));
            }
        }
        drop(files);
        drop(prepared_archive);
        verify_start(contract)?;
        let start_gate = logs.lock("start.lock", false)?;
        if now()? >= contract.prepare_deadline_unix {
            guard.stop()?;
            return self.record(id, RuntimeAction::PrepareDeadline { now_unix: now()? });
        }
        let latest = self.owner.runtime(id)?;
        if latest.view.cancellation.state != CancellationState::None {
            guard.stop()?;
            proof(
                logs,
                "reaped-v1.json",
                json!({"schema_version":1,"task_id":id.as_str(),"contract_digest":digest.as_str(),"container":container,"exec":null,"subtree_stopped":true}),
            )?;
            logs.seal()?;
            return Ok(latest);
        }
        let cwd = if contract.request.cwd == "." {
            "/work".to_owned()
        } else {
            format!("/work/{}", contract.request.cwd)
        };
        let exec =
            self.docker
                .exec_create(&container, &contract.request.command, "65534:65534", &cwd)?;
        let sequence = self.owner.runtime(id)?.view.last_event_seq + 1;
        let start = self.owner.record_event(
            id,
            RuntimeEvent {
                sequence,
                action: RuntimeAction::StartIntent {
                    handle: format!("docker:{container}:{exec}"),
                },
            },
        )?;
        if !start.applied {
            return Err(corrupt("replayed start intent cannot spawn"));
        }
        // From here all failures are ambiguous; neither a retry nor a new
        // execution ID is permitted. Persist the adapter identity before start.
        proof(
            logs,
            "engine-v1.json",
            json!({"schema_version":1,"task_id":id.as_str(),"contract_digest":digest.as_str(),"container":container,"exec":exec,"argv":contract.request.command,"cwd":cwd}),
        )?;
        let mut stream = self.docker.start_exec(&exec)?;
        drop(start_gate);
        let abort = std::sync::atomic::AtomicBool::new(false);
        let shutdown = stream.try_clone().map_err(io_error)?;
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        std::thread::scope(|scope| {
            let drain = scope.spawn(|| {
                let mut frames = Frames::default();
                let mut buffer = [0; 16384];
                let result = (|| loop {
                    if abort.load(std::sync::atomic::Ordering::Acquire) {
                        return Err(corrupt("drain interrupted before EOF"));
                    }
                    match stream.read(&mut buffer) {
                        Ok(0) => return frames.complete(),
                        Ok(n) => frames.push(&buffer[..n], |i, bytes| logs.append(i, bytes))?,
                        Err(e) if docker::timeout(&e) => {}
                        Err(e) => return Err(io_error(e)),
                    }
                })();
                // The receiver is owned by this same scope; an early error may
                // stop monitoring, in which case retaining unsealed logs is safe.
                let _ = send.send(result);
            });
            let result = (|| {
                let mut eof = false;
                let mut started: Option<Instant> = None;
                let mut stopped_reason: Option<String> = None;
                let mut ended: Option<Instant> = None;
                loop {
                    match receive.try_recv() {
                        Ok(result) => {
                            result?;
                            eof = true;
                        }
                        Err(std::sync::mpsc::TryRecvError::Empty) => {}
                        Err(std::sync::mpsc::TryRecvError::Disconnected) if eof => {}
                        Err(_) => return Err(corrupt("drain worker disappeared")),
                    }
                    let observed = self.docker.exec_inspect(&exec)?;
                    if observed["ContainerID"] != container || observed["ID"] != exec {
                        return Err(corrupt("execution identity changed"));
                    }
                    if started.is_none() && observed["Pid"].as_u64().is_some_and(|p| p > 0) {
                        let instant = Instant::now();
                        let at_unix = now()?;
                        proof(
                            logs,
                            "started-v1.json",
                            json!({"schema_version":1,"task_id":id.as_str(),"contract_digest":digest.as_str(),"container":container,"exec":exec,"boot_id":fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(io_error)?.trim(),"confirmed_monotonic_ns":monotonic_ns()?,"at_unix":at_unix,"timeout_seconds":limits.timeout_seconds}),
                        )?;
                        self.record(id, RuntimeAction::Started { at_unix })?;
                        started = Some(instant);
                    }
                    if observed["Running"] == false
                        && observed["ExitCode"].is_i64()
                        && started.is_some()
                    {
                        if ended.is_none() {
                            if stopped_reason.is_none() {
                                // Quiesce remaining descendants while copying explicit
                                // outputs to private durable staging, before tmpfs dies.
                                proof(
                                    logs,
                                    "exit-proof-v1.json",
                                    json!({"schema_version":1,"task_id":id.as_str(),"contract_digest":digest.as_str(),"container":container,"exec":exec,"exit_code":observed["ExitCode"]}),
                                )?;
                                self.docker.quiesce(&container)?;
                                let archive = self.docker.archive(&container)?;
                                publish(
                                    &logs.directory,
                                    "working-tree-unregistered-v1.tar",
                                    &archive,
                                )?;
                                stage_outputs(logs, &archive, contract, id, &digest)?;
                            }
                            guard.stop()?;
                            proof(
                                logs,
                                "reaped-v1.json",
                                json!({"schema_version":1,"task_id":id.as_str(),"contract_digest":digest.as_str(),"container":container,"exec":exec,"subtree_stopped":true}),
                            )?;
                            ended = Some(Instant::now());
                        }
                        if eof {
                            logs.seal()?;
                            let state = if let Some(reason) = stopped_reason {
                                self.record(
                                    id,
                                    RuntimeAction::Stopped {
                                        reason,
                                        signal: Some("SIGKILL".into()),
                                    },
                                )?
                            } else {
                                let code = observed["ExitCode"]
                                    .as_u64()
                                    .and_then(|n| u8::try_from(n).ok())
                                    .ok_or_else(|| corrupt("unrepresentable actual exit code"))?;
                                self.record(id, RuntimeAction::Exited { exit_code: code })?
                            };
                            return Ok(state);
                        }
                        if ended.is_some_and(|t| t.elapsed() > Duration::from_secs(15)) {
                            return Err(corrupt("execution exited but log EOF was not confirmed"));
                        }
                    } else if started.is_some() && stopped_reason.is_none() {
                        let state = self.owner.runtime(id)?;
                        let reason =
                            if state.view.cancellation.state == CancellationState::Requested {
                                state.view.cancellation.reason.clone()
                            } else if started.is_some_and(|t| {
                                t.elapsed() >= Duration::from_secs(limits.timeout_seconds)
                            }) {
                                Some("Timeout".into())
                            } else {
                                None
                            };
                        if let Some(reason) = reason {
                            proof(
                                logs,
                                "stop-intent-v1.json",
                                json!({"schema_version":1,"task_id":id.as_str(),"contract_digest":digest.as_str(),"container":container,"exec":exec,"reason":reason}),
                            )?;
                            guard.stop()?;
                            stopped_reason = Some(reason);
                        }
                    }
                    if started.is_none() && eof {
                        return Err(corrupt(
                            "exec attempt ended without confirmed process start; reconcile required",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            })();
            abort.store(true, std::sync::atomic::Ordering::Release);
            let _ = shutdown.shutdown(std::net::Shutdown::Both);
            drain.join().map_err(|_| corrupt("log drain panicked"))?;
            result
        })
    }
}
struct ContainerGuard {
    docker: Docker,
    id: String,
    stopped: bool,
}
impl ContainerGuard {
    fn stop(&mut self) -> Result<(), TaskError> {
        self.docker.stop(&self.id)?;
        self.stopped = true;
        Ok(())
    }
}
impl Drop for ContainerGuard {
    fn drop(&mut self) {
        if !self.stopped {
            // Drop cannot report errors; run returns failure, retaining identities for reconciliation.
            let _ = self.docker.stop(&self.id);
        }
    }
}

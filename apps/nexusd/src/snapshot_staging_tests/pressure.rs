use super::*;

#[test]
fn cancelled_payload_deletion_error_retains_charge_and_can_be_retried() {
    let i = Input::small();
    let f = Fixture::new(GLOBAL + i.charge(), 8);
    let s = f.service();
    let c = f.context();
    let v = s.execute(&c, i.begin("x")).unwrap();
    i.upload_all(&s, &c, &v.upload_id);
    s.set_fault("cancel_payload_delete_failed");
    assert_code(
        s.execute(
            &c,
            SnapshotRequest::Cancel {
                upload_id: v.upload_id.clone(),
            },
        ),
        TaskErrorCode::PersistenceFailed,
    );
    let pending = get(&s, &c, &v.upload_id);
    assert_eq!(pending.state, UploadState::Cancelling);
    assert_eq!(pending.reserved_bytes, i.charge());
    assert!(f.payload(&v.upload_id, &i.files[0].sha256).exists());
    s.set_fault("cancel_payload_delete_failed");
    assert!(s.execute(&c, i.begin("next")).is_err());
    assert_eq!(
        s.test_observe(&v.upload_id).unwrap().view.reserved_bytes,
        i.charge()
    );
    assert!(s.execute(&c, i.chunk(&v.upload_id, 0, b"abc")).is_err());
    assert!(
        s.execute(
            &c,
            SnapshotRequest::Seal {
                upload_id: v.upload_id.clone()
            }
        )
        .is_err()
    );
    s.set_fault("");
    let done = s
        .execute(
            &c,
            SnapshotRequest::Cancel {
                upload_id: v.upload_id.clone(),
            },
        )
        .unwrap();
    assert_eq!(done.reserved_bytes, 0);
    assert!(
        !f.namespace()
            .join("uploads")
            .join(v.upload_id.as_str())
            .exists()
    );
    assert_eq!(
        s.execute(&c, i.begin("next")).unwrap().state,
        UploadState::Receiving
    );
}
#[test]
fn ledger_table_future_metadata_is_bounded_and_expired_tombstones_free_capacity() {
    // Reserve a large future state first, then fill its remaining metadata
    // envelope with tombstones. Current tiny offsets cannot be used as spare
    // metadata: this active upload must still reach full offsets/intents/states.
    let names = (0..128).map(|n| format!("f{n:03}")).collect::<Vec<_>>();
    let payloads = (0..128)
        .map(|n| {
            if n == 0 {
                vec![b'x'; 67_108_864 - 127 * 8]
            } else {
                (n as u64).to_be_bytes().to_vec()
            }
        })
        .collect::<Vec<_>>();
    let entries = names
        .iter()
        .zip(&payloads)
        .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
        .collect::<Vec<_>>();
    let i = Input::new(&entries);
    assert_eq!(
        i.payloads.len(),
        128,
        "metadata pressure requires unique blob records, not deduped paths"
    );
    assert_eq!(i.snapshot.total_bytes, 67_108_864);
    let f = Fixture::new(MAX_INTEGER, 8);
    let mut s = f.service();
    let c = f.context();
    s.set_time(1_000_000);
    let key = |n: usize| format!("{}{:04x}", "𠜎".repeat(252), n);
    let active = s.execute(&c, i.begin(&key(0))).unwrap();
    let observed_active = s.test_observe(&active.upload_id).unwrap();
    let active_ceiling = observed_active.future_ceiling_bytes;
    assert!(observed_active.actual_record_bytes <= active_ceiling);
    assert!(active_ceiling <= 524_288);
    let mut count = 1;
    for n in 1..=1024 {
        let before = inventory(&f.namespace());
        match s.execute(&c, i.begin(&key(n))) {
            Ok(view) => {
                count += 1;
                assert!(count <= 1024);
                let allowance_before_cancel = s.test_metadata_allowance().unwrap();
                s.execute(
                    &c,
                    SnapshotRequest::Cancel {
                        upload_id: view.upload_id,
                    },
                )
                .unwrap();
                assert_eq!(
                    s.test_metadata_allowance().unwrap(),
                    allowance_before_cancel,
                    "unexpired tombstones retain their original future allowance"
                );
            }
            Err(error) => {
                assert_eq!(error.code, TaskErrorCode::CapacityUnavailable);
                assert_eq!(inventory(&f.namespace()), before);
                break;
            }
        }
    }
    let (filled, retained) = s.test_metadata_allowance().unwrap();
    assert_eq!(retained, count);
    assert!(count > 1);
    assert!(filled <= 4 * 1024 * 1024);
    assert!(
        4 * 1024 * 1024 - filled < active_ceiling,
        "long-binding multi-blob table must actually approach its future byte cap"
    );
    let before = inventory(&f.namespace());
    assert_code(
        s.execute(&c, i.begin(&key(1025))),
        TaskErrorCode::CapacityUnavailable,
    );
    assert_eq!(inventory(&f.namespace()), before);
    // Filling with cancelled records cannot steal allowance already reserved
    // for the active upload's largest offsets and durable chunk intent.
    let largest = i.files.iter().max_by_key(|file| file.size_bytes).unwrap();
    let last_offset = largest.size_bytes - 65_536;
    let bytes = i.payloads.get(&largest.sha256).unwrap();
    let mut offset = 0u64;
    while offset < last_offset {
        let next = (offset + 65_536).min(last_offset);
        s.execute(
            &c,
            SnapshotRequest::PutChunk {
                upload_id: active.upload_id.clone(),
                blob_sha256: largest.sha256.clone(),
                offset,
                bytes: bytes[offset as usize..next as usize].to_vec(),
                chunk_sha256: sha256(&bytes[offset as usize..next as usize]),
            },
        )
        .unwrap();
        offset = next;
    }
    s.set_fault("chunk_intent_durable");
    assert_code(
        s.execute(
            &c,
            SnapshotRequest::PutChunk {
                upload_id: active.upload_id.clone(),
                blob_sha256: largest.sha256.clone(),
                offset: last_offset,
                bytes: bytes[last_offset as usize..].to_vec(),
                chunk_sha256: sha256(&bytes[last_offset as usize..]),
            },
        ),
        TaskErrorCode::PersistenceFailed,
    );
    let intent = s.test_observe(&active.upload_id).unwrap();
    assert_eq!(intent.future_ceiling_bytes, active_ceiling);
    assert!(intent.actual_record_bytes <= active_ceiling);
    assert!(
        fs::metadata(f.namespace().join("ledger-v1.json"))
            .unwrap()
            .len()
            <= 4 * 1024 * 1024
    );
    if let Ok(tmp) = fs::metadata(f.namespace().join(".ledger-v1.tmp")) {
        assert!(tmp.len() <= 4 * 1024 * 1024);
    }
    assert_eq!(
        (
            intent.chunk.as_ref().unwrap().old_offset,
            intent.chunk.as_ref().unwrap().next_offset
        ),
        (last_offset, largest.size_bytes)
    );
    assert_eq!(s.test_metadata_allowance().unwrap(), (filled, retained));
    drop(s);
    s = FileSnapshotStaging::open_with_test_time(&f.root, 1_000_000)
        .unwrap()
        .unwrap();
    s.set_time(1_000_000);
    for (digest, bytes) in &i.payloads {
        let view = get(&s, &c, &active.upload_id);
        let offset = view
            .blobs
            .iter()
            .find(|blob| &blob.sha256 == digest)
            .unwrap()
            .durable_offset;
        if offset < bytes.len() as u64 {
            s.execute(
                &c,
                SnapshotRequest::PutChunk {
                    upload_id: active.upload_id.clone(),
                    blob_sha256: digest.clone(),
                    offset,
                    bytes: bytes[offset as usize..].to_vec(),
                    chunk_sha256: sha256(&bytes[offset as usize..]),
                },
            )
            .unwrap();
        }
    }
    assert_eq!(
        s.execute(
            &c,
            SnapshotRequest::Seal {
                upload_id: active.upload_id.clone()
            }
        )
        .unwrap()
        .state,
        UploadState::Staged
    );
    assert_eq!(s.test_metadata_allowance().unwrap(), (filled, retained));
    let sealed = s.test_observe(&active.upload_id).unwrap();
    assert!(sealed.actual_record_bytes <= active_ceiling);
    assert!(
        fs::metadata(f.namespace().join("ledger-v1.json"))
            .unwrap()
            .len()
            <= 4 * 1024 * 1024
    );
    s.execute(
        &c,
        SnapshotRequest::Cancel {
            upload_id: active.upload_id,
        },
    )
    .unwrap();
    assert_eq!(s.test_metadata_allowance().unwrap(), (filled, retained));
    assert_code(
        s.execute(&c, i.begin(&key(1025))),
        TaskErrorCode::CapacityUnavailable,
    );
    s.set_time(1_000_000 + 86_399);
    assert_code(
        s.execute(&c, i.begin(&key(1025))),
        TaskErrorCode::CapacityUnavailable,
    );
    s.set_time(1_000_000 + 86_400);
    let new = s.execute(&c, i.begin(&key(1025))).unwrap();
    assert_eq!(new.state, UploadState::Receiving);
    assert!(s.test_metadata_allowance().unwrap().0 < filled);
}
#[test]
fn declared_total_64m_boundary_charges_without_preallocating_blob_and_overflow_rejects() {
    let f = Fixture::standard();
    let s = f.service();
    let c = f.context();
    let mut i = Input::small();
    i.files[0].size_bytes = 67_108_864;
    i.redeclare();
    let v = s.execute(&c, i.begin("limit")).unwrap();
    assert_eq!(v.blobs[0].size_bytes, 67_108_864);
    assert_eq!(v.blobs[0].durable_offset, 0);
    assert_eq!(v.reserved_bytes, i.charge());
    assert_eq!(
        fs::metadata(f.payload(&v.upload_id, &i.files[0].sha256))
            .unwrap()
            .len(),
        0
    );
    s.execute(
        &c,
        SnapshotRequest::Cancel {
            upload_id: v.upload_id,
        },
    )
    .unwrap();
    let before = inventory(&f.namespace());
    for size in [67_108_865, MAX_INTEGER, MAX_INTEGER + 1] {
        i.files[0].size_bytes = size;
        i.redeclare();
        assert!(s.execute(&c, i.begin("over")).is_err());
        assert_eq!(inventory(&f.namespace()), before);
    }
}
#[test]
fn manifest_digest_size_collision_and_path_collision_are_rejected_with_valid_snapshot_identity() {
    let f = Fixture::standard();
    let s = f.service();
    let c = f.context();
    let before = inventory(&f.namespace());
    let mut duplicate_digest = Input::new(&[("a", b"same"), ("b", b"same")]);
    duplicate_digest.files[1].size_bytes += 1;
    duplicate_digest.redeclare();
    assert!(s.execute(&c, duplicate_digest.begin("dup-size")).is_err());
    assert_eq!(inventory(&f.namespace()), before);
    let mut collision = Input::new(&[("a", b"same"), ("b", b"same")]);
    collision.files[1].path = "a/child".into();
    collision.redeclare();
    assert!(s.execute(&c, collision.begin("collision")).is_err());
    assert_eq!(inventory(&f.namespace()), before);
    let mut zero = Input::new(&[("empty", b"")]);
    zero.files[0].sha256 = sha256(b"nonempty");
    zero.redeclare();
    assert_code(
        s.execute(&c, zero.begin("zero-hash")),
        TaskErrorCode::InputIntegrityFailed,
    );
    assert_eq!(inventory(&f.namespace()), before);
}

#[test]
fn current_authorization_audit_runs_before_attempting_busy_staging_lease() {
    let result = std::process::Command::new("timeout")
        .arg("45s")
        .arg(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "snapshot_staging::tests::pressure::audit_lease_probe_child",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "bounded audit/lease probe failed: {}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}
#[test]
#[ignore = "owned bounded subprocess invoked by current_authorization_audit_runs_before_attempting_busy_staging_lease"]
fn audit_lease_probe_child() {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    struct LeaseHolder(std::process::Child);
    impl LeaseHolder {
        fn release(&mut self) {
            // Closing stdin terminates the shell's bounded read and lets
            // flock close its original lease FD before the worker joins.
            drop(self.0.stdin.take());
            let _ = self.0.wait();
        }
    }
    impl Drop for LeaseHolder {
        fn drop(&mut self) {
            self.release();
        }
    }
    for operation in ["begin", "chunk", "get", "seal", "cancel"] {
        let f = Fixture::standard();
        let s = f.service();
        let c = f.context();
        let i = Input::small();
        let v = s.execute(&c, i.begin("original")).unwrap();
        if operation == "seal" {
            i.upload_all(&s, &c, &v.upload_id);
        }
        let request = match operation {
            "begin" => i.begin("next"),
            "chunk" => i.chunk(&v.upload_id, 0, b"abc"),
            "get" => SnapshotRequest::Get {
                upload_id: v.upload_id.clone(),
            },
            "seal" => SnapshotRequest::Seal {
                upload_id: v.upload_id.clone(),
            },
            _ => SnapshotRequest::Cancel {
                upload_id: v.upload_id.clone(),
            },
        };
        let store = nexus::n2_store::N2Store::open(&f.root).unwrap();
        // Linux E3 dependencies: flock, timeout and sh. timeout bounds the
        // helper even if the readiness read or an incorrect adapter blocks.
        let mut child = Command::new("timeout")
            .arg("15s")
            .arg("flock")
            .arg("--exclusive")
            .arg(f.namespace().join("staging.lock"))
            .arg("sh")
            .arg("-c")
            .arg("printf 'locked\\n'; read hold")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line, "locked\n");
        let mut lease = LeaseHolder(child);
        let staging = inventory(&f.namespace());
        let before = nexus::n2_store::replay_audit_entries(store.kv())
            .unwrap()
            .len();
        let observed = std::thread::scope(|scope| {
            let worker = scope.spawn(|| s.execute(&c, request));
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut seen = false;
            while Instant::now() < deadline {
                let entries = nexus::n2_store::replay_audit_entries(store.kv());
                if entries.as_ref().is_ok_and(|entries| entries.len() > before) {
                    seen = true;
                    break;
                }
                std::thread::yield_now();
            }
            // Release before joining even on a failed observation. The frozen
            // contract allows waiting for the lease; no invented busy errno.
            let unchanged_while_locked = inventory(&f.namespace()) == staging;
            lease.release();
            let outcome = worker.join().unwrap();
            (seen, unchanged_while_locked, outcome)
        });
        assert!(
            observed.0,
            "{operation} must audit outside the original fixed staging lease"
        );
        assert!(
            observed.1,
            "{operation} wrote staging while another process held its lease"
        );
        // Both bounded contention refusal and completion after release are
        // legal; the independent audit ordering is the required observation.
        if operation == "get" {
            assert_eq!(inventory(&f.namespace()), staging);
        }
    }
}

#[test]
fn fifo_authority_is_rejected_promptly_without_reading_it() {
    // The subprocess owns its fixture and is always reaped. A broken blocking
    // reader is an actual timeout failure instead of hanging the whole suite.
    let result = std::process::Command::new("timeout")
        .arg("10s")
        .arg(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "snapshot_staging::tests::pressure::fifo_probe_child",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "bounded FIFO probe failed: {}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}
#[test]
#[ignore = "owned bounded subprocess invoked by fifo_authority_is_rejected_promptly_without_reading_it"]
fn fifo_probe_child() {
    let f = Fixture::standard();
    f.initialize();
    let p = f.namespace().join("ledger-v1.json");
    fs::remove_file(&p).unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .arg("-m")
            .arg("600")
            .arg(&p)
            .status()
            .unwrap()
            .success()
    );
    // The public adapter must use nonblocking nofollow descriptors and type
    // checking, so a FIFO with no producer cannot wait for external input.
    assert_code(
        FileSnapshotStaging::open(&f.root),
        TaskErrorCode::StateCorrupt,
    );
    assert!(fs::symlink_metadata(&p).unwrap().file_type().is_fifo());
}

#[test]
fn exact_manifest_65536_bytes_is_admitted_and_next_byte_rejected() {
    let names = (0..128).map(|n| format!("f{n:03}")).collect::<Vec<_>>();
    let entries = names
        .iter()
        .map(|s| (s.as_str(), b"abc".as_slice()))
        .collect::<Vec<_>>();
    let mut input = Input::new(&entries);
    let mut remaining = 65_536 - input.manifest.len();
    for file in &mut input.files {
        let extend = remaining.min(3000);
        file.path.push_str(&"x".repeat(extend));
        remaining -= extend;
        if remaining == 0 {
            break;
        }
    }
    assert_eq!(remaining, 0);
    input.redeclare();
    assert_eq!(input.manifest.len(), 65_536);
    FrozenSnapshot {
        reference: input.snapshot.clone(),
        files: input.files.clone(),
    }
    .validate(sha256)
    .unwrap();
    let f = Fixture::standard();
    let s = f.service();
    let c = f.context();
    assert_eq!(
        s.execute(&c, input.begin("exact-manifest"))
            .unwrap()
            .reserved_bytes,
        input.charge()
    );
    input.files[127].path.push('x');
    input.redeclare();
    assert_eq!(input.manifest.len(), 65_537);
    let before = inventory(&f.namespace());
    assert!(s.execute(&c, input.begin("large-manifest")).is_err());
    assert_eq!(inventory(&f.namespace()), before);
}

#[test]
fn identical_payload_inode_replacement_is_not_accepted_as_original_owned_file() {
    let f = Fixture::standard();
    let s = f.service();
    let c = f.context();
    let i = Input::small();
    let v = s.execute(&c, i.begin("x")).unwrap();
    s.execute(&c, i.chunk(&v.upload_id, 0, b"abc")).unwrap();
    let path = f.payload(&v.upload_id, &i.files[0].sha256);
    let bytes = fs::read(&path).unwrap();
    fs::rename(&path, f.base.join("old-payload")).unwrap();
    private_file(&path, &bytes);
    let before = inventory(&f.namespace());
    assert_code(
        s.execute(
            &c,
            SnapshotRequest::Get {
                upload_id: v.upload_id,
            },
        ),
        TaskErrorCode::StateCorrupt,
    );
    assert_code(
        FileSnapshotStaging::open(&f.root),
        TaskErrorCode::StateCorrupt,
    );
    assert_eq!(inventory(&f.namespace()), before);
}

#[test]
fn path_like_owner_supplied_upload_id_is_only_index_lookup_and_preserves_decoy() {
    let f = Fixture::standard();
    let s = f.service();
    let decoy = f.base.join("decoy");
    private_file(&decoy, b"untouched");
    let before = inventory(&decoy);
    let staging = inventory(&f.namespace());
    for name in ["../../decoy", "a/b", "秘密/根"] {
        let id = UploadId::new(name.into()).unwrap();
        for request in [
            SnapshotRequest::Get {
                upload_id: id.clone(),
            },
            SnapshotRequest::Cancel {
                upload_id: id.clone(),
            },
            SnapshotRequest::Seal { upload_id: id },
        ] {
            assert!(s.execute(&f.context(), request).is_err());
            assert_eq!(inventory(&f.namespace()), staging);
            assert_eq!(inventory(&decoy), before);
        }
    }
}

#[test]
fn every_mutation_and_pending_boot_require_exclusive_original_staging_lease() {
    let result = std::process::Command::new("timeout")
        .arg("75s")
        .arg(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "snapshot_staging::tests::pressure::shared_holder_exclusive_writer_probe_child",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "bounded shared-holder probe failed: {}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
#[ignore = "owned bounded subprocess invoked by every_mutation_and_pending_boot_require_exclusive_original_staging_lease"]
fn shared_holder_exclusive_writer_probe_child() {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    struct SharedHolder(std::process::Child);
    impl SharedHolder {
        fn release(&mut self) {
            drop(self.0.stdin.take());
            let _ = self.0.wait();
        }
    }
    impl Drop for SharedHolder {
        fn drop(&mut self) {
            self.release();
        }
    }
    // /proc/locks is the Linux kernel's actual flock table, not an application
    // hook or elapsed-time guess. Identify the original inode and its device.
    fn lock_key(metadata: &fs::Metadata) -> String {
        let device = metadata.dev();
        let major = ((device >> 8) & 0xfff) | ((device >> 32) & 0xfffff000);
        let minor = (device & 0xff) | ((device >> 12) & 0xffffff00);
        format!("{major:02x}:{minor:02x}:{}", metadata.ino())
    }
    fn kernel_lock(table: &str, key: &str, waiter: bool, access: &str) -> bool {
        table.lines().any(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            fields.contains(&key)
                && fields.contains(&"FLOCK")
                && fields.contains(&"ADVISORY")
                && fields.contains(&access)
                && fields.contains(&"->") == waiter
        })
    }
    for operation in ["begin", "chunk", "seal", "cancel", "boot"] {
        let f = Fixture::standard();
        let s = f.service();
        let c = f.context();
        let i = Input::small();
        let original = s.execute(&c, i.begin("original")).unwrap();
        if matches!(operation, "seal" | "boot") {
            i.upload_all(&s, &c, &original.upload_id);
        }
        if operation == "boot" {
            s.set_fault("seal_intent_durable");
            assert_code(
                s.execute(
                    &c,
                    SnapshotRequest::Seal {
                        upload_id: original.upload_id.clone(),
                    },
                ),
                TaskErrorCode::PersistenceFailed,
            );
            s.set_fault("");
            assert_eq!(
                s.test_observe(&original.upload_id).unwrap().view.state,
                UploadState::Receiving
            );
        }
        let request = match operation {
            "begin" => i.begin("next"),
            "chunk" => i.chunk(&original.upload_id, 0, b"abc"),
            "seal" => SnapshotRequest::Seal {
                upload_id: original.upload_id.clone(),
            },
            "cancel" => SnapshotRequest::Cancel {
                upload_id: original.upload_id.clone(),
            },
            _ => SnapshotRequest::Get {
                upload_id: original.upload_id.clone(),
            },
        };
        // No stale grant or malformed state can explain refusal under the lock.
        nexus::task_authorization::authorize_use(&f.root, &f.principal, WORKSPACE, RESOURCE)
            .unwrap();
        let lock = f.namespace().join("staging.lock");
        let key = lock_key(&fs::metadata(&lock).unwrap());
        let child = Command::new("timeout")
            .arg("12s")
            .arg("flock")
            .arg("--shared")
            .arg(&lock)
            .arg("sh")
            .arg("-c")
            .arg("printf 'shared-locked\\n'; read hold")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut holder = SharedHolder(child);
        let mut line = String::new();
        BufReader::new(holder.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line, "shared-locked\n");
        assert!(
            kernel_lock(
                &fs::read_to_string("/proc/locks").unwrap(),
                &key,
                false,
                "READ"
            ),
            "holder must really hold SH on the original inode before the writer starts"
        );
        let before = inventory(&f.namespace());
        let store = nexus::n2_store::N2Store::open(&f.root).unwrap();
        let audit_before = nexus::n2_store::replay_audit_entries(store.kv())
            .unwrap()
            .len();
        // Dropping the old instance matters for the boot path: a fresh public
        // open must finish the actual durable SealIntent under its own lease.
        let service = if operation == "boot" {
            drop(s);
            None
        } else {
            Some(s)
        };
        let observed = std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                if let Some(service) = &service {
                    service.execute(&c, request.clone())
                } else {
                    let opened = FileSnapshotStaging::open(&f.root)?.ok_or_else(|| {
                        TaskError::new(TaskErrorCode::StateCorrupt, "provision lost", false)
                    })?;
                    Ok(opened.test_observe(&original.upload_id)?.view)
                }
            });
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut write_waiter = false;
            while Instant::now() < deadline {
                if kernel_lock(
                    &fs::read_to_string("/proc/locks").unwrap(),
                    &key,
                    true,
                    "WRITE",
                ) {
                    write_waiter = true;
                    break;
                }
                if worker.is_finished() {
                    break;
                }
                std::thread::yield_now();
            }
            // At this synchronized point either the kernel blocked an EX
            // attempt on this inode, or the call has actually completed. An
            // SH writer will complete/write, and cannot pass this observation.
            let unchanged = inventory(&f.namespace()) == before;
            let audit_seen = nexus::n2_store::replay_audit_entries(store.kv())
                .unwrap()
                .len()
                > audit_before;
            let finished_under_holder = worker.is_finished();
            holder.release();
            let outcome = worker.join().unwrap();
            (
                write_waiter,
                unchanged,
                audit_seen,
                finished_under_holder,
                outcome,
            )
        });
        assert!(
            observed.1,
            "{operation}: no staging mutation while the SH owner holds the original inode"
        );
        assert!(
            observed.0 || observed.3,
            "{operation}: no synchronized lock attempt/completion before deadline"
        );
        if operation != "boot" {
            assert!(
                observed.2,
                "{operation}: current Use audit must precede its lease attempt"
            );
        }
        if observed.3 {
            assert!(
                observed.4.is_err(),
                "{operation}: success under an independent SH holder proves missing exclusive serialization"
            );
        } else {
            assert!(
                observed.0,
                "{operation}: a waiting writer must be an actual kernel EX waiter"
            );
            observed.4.as_ref().expect(
                "a genuinely blocked legal operation completes after shared holder release",
            );
        }
        // Both bounded contention refusal and waiting are allowed; retry the
        // same operation after release and require its real successful effect.
        let released = if let Some(service) = &service {
            service.execute(&c, request).unwrap()
        } else {
            let opened = f.open();
            opened.test_observe(&original.upload_id).unwrap().view
        };
        assert_eq!(released.snapshot, i.snapshot);
        match operation {
            "begin" => {
                assert_ne!(released.upload_id, original.upload_id);
                assert_eq!(released.reserved_bytes, i.charge());
            }
            "chunk" => {
                assert_eq!(released.upload_id, original.upload_id);
                assert_eq!(released.blobs[0].durable_offset, 3);
                assert_eq!(released.reserved_bytes, i.charge());
            }
            "seal" | "boot" => {
                assert_eq!(released.upload_id, original.upload_id);
                assert_eq!(released.state, UploadState::Staged);
                assert_eq!(released.reserved_bytes, i.charge());
            }
            _ => {
                assert_eq!(released.upload_id, original.upload_id);
                assert_eq!(released.state, UploadState::Cancelled);
                assert_eq!(released.reserved_bytes, 0);
                assert!(
                    !f.namespace()
                        .join("uploads")
                        .join(original.upload_id.as_str())
                        .exists()
                );
            }
        }
    }
}

// Both real calls must reach the exact pre-lease seam before either may take
// the lease. Then A finishes before B is released. This deterministic overlap
// exposes mutable decisions made outside the lease even with nonblocking flock:
// the delayed caller must reread the committed key/budget/prefix under its lock.
// A Barrier alone would not force B's acquisition after A's durable commit.
fn ordered_real_competitors(
    f: &Fixture,
    first: &FileSnapshotStaging,
    second: &FileSnapshotStaging,
    first_request: SnapshotRequest,
    second_request: SnapshotRequest,
) -> (
    Result<UploadView, TaskError>,
    Result<UploadView, TaskError>,
    Vec<Entry>,
) {
    use std::sync::{Mutex, mpsc};
    use std::time::Duration;
    fn arm(service: &FileSnapshotStaging) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (arrived, observed) = mpsc::channel();
        let (resume, release) = mpsc::channel();
        service.set_test_before_lease(TestBeforeLease {
            arrived,
            release: Mutex::new(release),
        });
        (observed, resume)
    }
    fn after_contention(
        service: &FileSnapshotStaging,
        context: &TaskCallContext,
        request: SnapshotRequest,
    ) -> Result<UploadView, TaskError> {
        // Bounded contention is legal. This one-shot gate has already been
        // consumed, so explicit retries reread current authoritative state.
        // That contention includes the pre-gate check itself: every execute
        // starts by validating the provider authority, which takes an
        // exclusive lease on acceptance.lock for the whole record-reading,
        // decoding and binding-verification pass. Two concurrent executes
        // therefore race on that lease, and the loser gets retryable
        // CapacityUnavailable ("initialization authority lease is busy").
        // The holder critical section spans real I/O, so immediate retries
        // routinely burn out before it releases under load; back off so a
        // transient hold resolves instead of failing the rendezvous.
        // Still bounded: 100 attempts x 20ms = 2s max, well inside the 5s
        // rendezvous waits and the 35s child bound.
        for attempt in 0..100 {
            let result = service.execute(context, request.clone());
            if !result.as_ref().is_err_and(|error| {
                error.code == TaskErrorCode::CapacityUnavailable && error.retryable
            }) || attempt == 99
            {
                return result;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        unreachable!()
    }
    let c = f.context();
    let before = inventory(&f.namespace());
    std::thread::scope(|scope| {
        // Controllers are owned in this scope. Panic/drop closes each sender;
        // actual hooks also use recv_timeout, and the whole child is bounded.
        let (arrived_a, resume_a) = arm(first);
        let (arrived_b, resume_b) = arm(second);
        let a = scope.spawn(|| after_contention(first, &c, first_request));
        let b = scope.spawn(|| after_contention(second, &c, second_request));
        arrived_a
            .recv_timeout(Duration::from_secs(5))
            .expect("first real execute reached immediately before its staging lease");
        arrived_b
            .recv_timeout(Duration::from_secs(5))
            .expect("second real execute reached immediately before its staging lease");
        assert!(!a.is_finished() && !b.is_finished());
        assert_eq!(inventory(&f.namespace()), before);
        resume_a.send(()).unwrap();
        let first_result = a.join().unwrap();
        assert!(
            first_result.is_ok(),
            "legal uncontended first writer must commit before B is released: {first_result:?}"
        );
        let after_first = inventory(&f.namespace());
        assert!(!b.is_finished(), "B is still inside its real invocation");
        resume_b.send(()).unwrap();
        let second_result = b.join().unwrap();
        (first_result, second_result, after_first)
    })
}

fn run_competing_writers_child(name: &str) {
    let result = std::process::Command::new("timeout")
        .arg("--kill-after=2s")
        .arg("35s")
        .arg(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", name, "--nocapture"])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "owned bounded actual-writer competition failed: {}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn competing_same_key_begin_has_one_original_upload_and_one_charge() {
    run_competing_writers_child(
        "snapshot_staging::tests::pressure::same_key_begin_competitors_child",
    );
}
#[test]
#[ignore = "owned bounded subprocess invoked by competing_same_key_begin_has_one_original_upload_and_one_charge"]
fn same_key_begin_competitors_child() {
    let i = Input::small();
    let f = Fixture::new(GLOBAL + i.charge(), 8);
    f.initialize();
    // Both instances are genuinely open before either real call is paused.
    let first = f.open();
    let second = f.open();
    let (a, b, after_first) = ordered_real_competitors(
        &f,
        &first,
        &second,
        i.begin("contended-same-key"),
        i.begin("contended-same-key"),
    );
    let a = a.unwrap();
    assert_eq!(
        b.unwrap(),
        a,
        "both real calls return the same original view"
    );
    assert_eq!(a.reserved_bytes, i.charge());
    assert_eq!(a.snapshot, i.snapshot);
    assert_eq!(inventory(&f.namespace()), after_first);
    assert_eq!(first.test_metadata_allowance().unwrap().1, 1);
    let upload_tree = inventory(&f.namespace().join("uploads"));
    drop(first);
    drop(second);
    let cold = f.open();
    assert_eq!(get(&cold, &f.context(), &a.upload_id), a);
    assert_eq!(
        cold.execute(&f.context(), i.begin("contended-same-key"))
            .unwrap(),
        a
    );
    assert_eq!(cold.test_metadata_allowance().unwrap().1, 1);
    assert_eq!(inventory(&f.namespace().join("uploads")), upload_tree);
    assert_code(
        cold.execute(&f.context(), i.begin("competitor-budget-control")),
        TaskErrorCode::CapacityUnavailable,
    );
    // One cancel releases exactly the single charge, not an orphan duplicate.
    cold.execute(
        &f.context(),
        SnapshotRequest::Cancel {
            upload_id: a.upload_id,
        },
    )
    .unwrap();
    assert_eq!(
        cold.execute(&f.context(), i.begin("competitor-budget-control"))
            .unwrap()
            .reserved_bytes,
        i.charge()
    );
}

#[test]
fn competing_different_keys_cannot_both_spend_the_last_upload_charge() {
    run_competing_writers_child(
        "snapshot_staging::tests::pressure::different_key_budget_competitors_child",
    );
}
#[test]
#[ignore = "owned bounded subprocess invoked by competing_different_keys_cannot_both_spend_the_last_upload_charge"]
fn different_key_budget_competitors_child() {
    let i = Input::small();
    let f = Fixture::new(GLOBAL + i.charge(), 8);
    f.initialize();
    let first = f.open();
    let second = f.open();
    let (a, b, after_first) = ordered_real_competitors(
        &f,
        &first,
        &second,
        i.begin("winner-a"),
        i.begin("delayed-b"),
    );
    let a = a.unwrap();
    assert_code(b, TaskErrorCode::CapacityUnavailable);
    assert_eq!(a.reserved_bytes, i.charge());
    assert_eq!(inventory(&f.namespace()), after_first);
    assert_eq!(first.test_metadata_allowance().unwrap().1, 1);
    let upload_tree = inventory(&f.namespace().join("uploads"));
    drop(first);
    drop(second);
    let cold = f.open();
    assert_eq!(get(&cold, &f.context(), &a.upload_id), a);
    assert_eq!(cold.execute(&f.context(), i.begin("winner-a")).unwrap(), a);
    assert_code(
        cold.execute(&f.context(), i.begin("delayed-b")),
        TaskErrorCode::CapacityUnavailable,
    );
    assert_eq!(cold.test_metadata_allowance().unwrap().1, 1);
    assert_eq!(inventory(&f.namespace().join("uploads")), upload_tree);
    cold.execute(
        &f.context(),
        SnapshotRequest::Cancel {
            upload_id: a.upload_id.clone(),
        },
    )
    .unwrap();
    let admitted = cold.execute(&f.context(), i.begin("delayed-b")).unwrap();
    assert_ne!(admitted.upload_id, a.upload_id);
    assert_eq!(admitted.reserved_bytes, i.charge());
}

#[test]
fn competing_same_offset_different_chunks_never_replace_confirmed_bytes() {
    run_competing_writers_child(
        "snapshot_staging::tests::pressure::different_chunk_same_offset_competitors_child",
    );
}
#[test]
#[ignore = "owned bounded subprocess invoked by competing_same_offset_different_chunks_never_replace_confirmed_bytes"]
fn different_chunk_same_offset_competitors_child() {
    let i = Input::small();
    let f = Fixture::new(GLOBAL + i.charge(), 8);
    let original_service = f.service();
    let original = original_service
        .execute(&f.context(), i.begin("chunk-owner"))
        .unwrap();
    original_service
        .execute(&f.context(), i.chunk(&original.upload_id, 0, b"abc"))
        .unwrap();
    let payload = f.payload(&original.upload_id, &i.files[0].sha256);
    let before = fs::symlink_metadata(&payload).unwrap();
    assert_eq!(fs::read(&payload).unwrap(), b"abc");
    drop(original_service);
    let first = f.open();
    let second = f.open();
    // At their shared pre-lease rendezvous both chunks are in range, contiguous,
    // have correct independent hashes and the same owner/grant. Only the first
    // committed prefix makes B an illegal different-bytes retry.
    let (a, b, after_first) = ordered_real_competitors(
        &f,
        &first,
        &second,
        i.chunk(&original.upload_id, 3, b"def"),
        i.chunk(&original.upload_id, 3, b"XYZ"),
    );
    let a = a.unwrap();
    assert!(
        b.is_err(),
        "different bytes cannot succeed after the first real writer commits"
    );
    assert_eq!(a.blobs[0].durable_offset, 6);
    assert_eq!(a.reserved_bytes, i.charge());
    assert_eq!(a.snapshot, i.snapshot);
    assert_eq!(inventory(&f.namespace()), after_first);
    assert_eq!(fs::read(&payload).unwrap(), b"abcdef");
    let after = fs::symlink_metadata(&payload).unwrap();
    assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
    let durable = first.test_observe(&original.upload_id).unwrap();
    drop(first);
    drop(second);
    let cold = f.open();
    assert_eq!(cold.test_observe(&original.upload_id).unwrap(), durable);
    assert_eq!(get(&cold, &f.context(), &original.upload_id), a);
    assert_eq!(inventory(&f.namespace()), after_first);
    assert_eq!(cold.test_metadata_allowance().unwrap().1, 1);
    assert_code(
        cold.execute(&f.context(), i.begin("second-budget-control")),
        TaskErrorCode::CapacityUnavailable,
    );
    let sealed = cold
        .execute(
            &f.context(),
            SnapshotRequest::Seal {
                upload_id: original.upload_id,
            },
        )
        .unwrap();
    assert_eq!(sealed.state, UploadState::Staged);
    assert_eq!(sealed.snapshot, i.snapshot);
    assert_eq!(sealed.reserved_bytes, i.charge());
    assert_eq!(fs::read(&payload).unwrap(), b"abcdef");
    let sealed_inode = fs::symlink_metadata(&payload).unwrap();
    assert_eq!(
        (sealed_inode.dev(), sealed_inode.ino()),
        (before.dev(), before.ino())
    );
}

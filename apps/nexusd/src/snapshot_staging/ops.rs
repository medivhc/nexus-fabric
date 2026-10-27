//! The lease owner is the sole ledger writer and budget release authority.
use super::*;
use init::Nodes;
fn record(l: &Ledger, id: &UploadId) -> Result<Record, TaskError> {
    l.records
        .iter()
        .find(|r| &r.id == id)
        .cloned()
        .ok_or_else(|| corrupt("transaction record missing"))
}
fn dirs(n: &Nodes, r: &Record) -> Result<(io::Directory, io::Directory), TaskError> {
    let d = required(recovery::upload(n, r)?)?;
    let b = child(&d, "blobs", r.blob_directory)?;
    Ok((d, b))
}
pub(super) fn expire(s: &FileSnapshotStaging, n: &Nodes, l: &mut Ledger) -> Result<(), TaskError> {
    let mut next = l.clone();
    next.records.retain(|r| !ledger::expired(r, s.now()));
    if next.records != l.records {
        ledger::save(s, n, l, next, "expire", None)?
    }
    Ok(())
}
pub(super) fn execute(
    s: &FileSnapshotStaging,
    n: &Nodes,
    l: &mut Ledger,
    c: &TaskCallContext,
    request: &SnapshotRequest,
    verified: &recovery::Verified,
) -> Result<UploadView, TaskError> {
    if let SnapshotRequest::Get { upload_id } = request {
        return Ok(record(l, upload_id)?.view(&l.binding));
    }
    // Validate input before any pruning or transaction recovery.
    let declared = if let SnapshotRequest::Begin {
        snapshot,
        manifest_json,
        ..
    } = request
    {
        Some(manifest(snapshot, manifest_json)?)
    } else {
        None
    };
    if let SnapshotRequest::PutChunk {
        bytes,
        chunk_sha256,
        ..
    } = request
    {
        if sha256(bytes) != *chunk_sha256 {
            return Err(integrity("chunk digest mismatch"));
        }
    }
    expire(s, n, l)?;
    if let Some(id) = request_id(request) {
        // Legal TTL pruning can remove the already authorized target.
        if !l.records.iter().any(|r| &r.id == id) {
            return Err(TaskError::new(
                TaskErrorCode::AuthDenied,
                "unknown snapshot upload",
                false,
            ));
        }
        recovery::recover(s, n, l, id)?;
    }
    match request {
        SnapshotRequest::Begin {
            resource,
            upload_key,
            snapshot,
            manifest_json,
            ..
        } => {
            if let Some(r) = l
                .records
                .iter()
                .find(|r| {
                    r.owner == c.principal() && r.resource == *resource && r.key == *upload_key
                })
                .cloned()
            {
                if r.snapshot != **snapshot
                    || (r.state != UploadState::Cancelled && r.manifest != *manifest_json)
                {
                    return Err(TaskError::new(
                        TaskErrorCode::IdempotencyConflict,
                        "upload key is bound to original snapshot",
                        false,
                    ));
                }
                recovery::recover(s, n, l, &r.id)?;
                return Ok(record(l, &r.id)?.view(&l.binding));
            }
            let blobs = declared.ok_or_else(|| corrupt("missing admission declarations"))?;
            let charge = charge(manifest_json, &blobs)?;
            let active = l
                .records
                .iter()
                .filter(|r| r.state != UploadState::Cancelled)
                .count() as u64;
            let reserved = l
                .records
                .iter()
                .filter(|r| r.state != UploadState::Cancelled)
                .try_fold(GLOBAL, |n, r| n.checked_add(r.charge))
                .and_then(|n| n.checked_add(charge));
            if active >= s.policy.max_active_uploads
                || reserved.is_none_or(|n| n > s.policy.max_reserved_bytes)
                || l.records.len() >= 1024
            {
                return Err(capacity("staging budget or index is full"));
            }
            let id = UploadId::new(new_task_id()?.as_str().into())?;
            let mut r = Record {
                id: id.clone(),
                owner: c.principal().into(),
                resource: resource.clone(),
                key: upload_key.clone(),
                snapshot: (**snapshot).clone(),
                manifest: manifest_json.clone(),
                charge,
                ceiling: 0,
                state: UploadState::Receiving,
                blobs,
                directory: None,
                blob_directory: None,
                manifest_inode: None,
                intent: Some(Intent::Begin),
                cancelled_at: None,
            };
            r.ceiling = future_ceiling(&r);
            let mut next = l.clone();
            next.records.push(r);
            if next
                .records
                .last()
                .is_some_and(|r| r.ceiling > RECORD_LIMIT)
                || ledger::allowance(&next)? > LEDGER_LIMIT
            {
                return Err(capacity("staging future metadata envelope is full"));
            }
            #[cfg(test)]
            {
                *lock(&s.last)? = Some(id.clone());
            }
            ledger::save(s, n, l, next, "begin", Some(&id))?;
            s.hit("begin_reservation_durable")?;
            finish_begin(s, n, l, &id)?;
            Ok(record(l, &id)?.view(&l.binding))
        }
        SnapshotRequest::PutChunk {
            upload_id,
            blob_sha256,
            offset,
            bytes,
            chunk_sha256,
        } => {
            let r = record(l, upload_id)?;
            if !matches!(r.state, UploadState::Receiving | UploadState::Staged) {
                return Err(TaskError::invalid("upload is terminal or cancelling"));
            }
            let blob = r
                .blobs
                .iter()
                .find(|b| b.digest == *blob_sha256)
                .ok_or_else(|| TaskError::invalid("chunk digest is not declared by upload"))?;
            let end = offset
                .checked_add(bytes.len() as u64)
                .filter(|x| *x <= blob.size)
                .ok_or_else(|| TaskError::invalid("chunk exceeds declared blob"))?;
            let (_, bd) = dirs(n, &r)?;
            let target = file(&bd, basename(blob_sha256), blob.size, blob.inode)?;
            if end <= blob.offset {
                if target.read_range(*offset, bytes.len())? != *bytes {
                    return Err(integrity("retry changes confirmed prefix"));
                }
                return Ok(r.view(&l.binding));
            }
            if *offset != blob.offset || r.state != UploadState::Receiving {
                return Err(TaskError::invalid(
                    "chunk is not contiguous confirmed progress",
                ));
            }
            let chunk = Chunk {
                blob: blob_sha256.clone(),
                old: *offset,
                next: end,
                old_prefix: blob.prefix.clone(),
                hash: chunk_sha256.clone(),
                phase: "writing".into(),
                scratch: None,
            };
            ledger::edit(s, n, l, upload_id, "chunk_intent", |r| {
                r.intent = Some(Intent::Chunk(chunk))
            })?;
            s.hit("chunk_intent_durable")?;
            let d = required(recovery::upload(n, &record(l, upload_id)?)?)?;
            let scratch = io::create_file(&d, name(SCRATCH), 65536)?;
            let inode = scratch.id();
            io::sync_directory(&d)?;
            ledger::edit(s, n, l, upload_id, "chunk_bind", |r| {
                if let Some(Intent::Chunk(c)) = &mut r.intent {
                    c.scratch = Some(inode)
                }
            })?;
            io::write_new(&scratch, bytes)?;
            s.hit("chunk_scratch_written")?;
            if scratch.hash_prefix(bytes.len() as u64)? != *chunk_sha256 {
                return Err(corrupt("written scratch hash mismatch"));
            }
            io::sync_file(&scratch)?;
            ledger::edit(s, n, l, upload_id, "chunk_ready", |r| {
                if let Some(Intent::Chunk(c)) = &mut r.intent {
                    c.phase = "ready".into()
                }
            })?;
            s.hit("chunk_scratch_ready_durable")?;
            finish_chunk(s, n, l, upload_id, Some(verified))?;
            Ok(record(l, upload_id)?.view(&l.binding))
        }
        SnapshotRequest::Seal { upload_id } => {
            let r = record(l, upload_id)?;
            if r.state == UploadState::Staged {
                return Ok(r.view(&l.binding));
            }
            if r.state != UploadState::Receiving {
                return Err(TaskError::invalid("only Receiving uploads can Seal"));
            }
            verify_complete(n, &r)?;
            ledger::edit(s, n, l, upload_id, "seal_intent", |r| {
                r.intent = Some(Intent::Seal)
            })?;
            s.hit("seal_intent_durable")?;
            finish_seal(s, n, l, upload_id)?;
            Ok(record(l, upload_id)?.view(&l.binding))
        }
        SnapshotRequest::Cancel { upload_id } => {
            let r = record(l, upload_id)?;
            if r.state == UploadState::Cancelled {
                return Ok(r.view(&l.binding));
            }
            if r.state != UploadState::Cancelling {
                ledger::edit(s, n, l, upload_id, "cancel_intent", |r| {
                    r.state = UploadState::Cancelling;
                    r.intent = Some(Intent::Cleanup(Cleanup {
                        directories_durable: false,
                    }))
                })?;
                s.hit("cancel_intent_durable")?
            }
            finish_cancel(s, n, l, upload_id)?;
            Ok(record(l, upload_id)?.view(&l.binding))
        }
        SnapshotRequest::Get { .. } => Err(corrupt("unreachable dispatch")),
    }
}
pub(super) fn finish_begin(
    s: &FileSnapshotStaging,
    n: &Nodes,
    l: &mut Ledger,
    id: &UploadId,
) -> Result<(), TaskError> {
    let mut r = record(l, id)?;
    if r.directory.is_none() {
        let d = io::create_directory(&n.uploads, name(id.as_str()))?;
        io::sync_directory(&n.uploads)?;
        ledger::edit(s, n, l, id, "begin_bind", |r| r.directory = Some(d.id()))?;
        r = record(l, id)?;
    }
    let d = required(recovery::upload(n, &r)?)?;
    if r.blob_directory.is_none() {
        let bd = io::create_directory(&d, name("blobs"))?;
        io::sync_directory(&d)?;
        ledger::edit(s, n, l, id, "begin_bind", |r| {
            r.blob_directory = Some(bd.id())
        })?;
        r = record(l, id)?;
    }
    if r.manifest_inode.is_none() {
        let f = io::create_file(&d, name(MANIFEST), 65536)?;
        io::sync_directory(&d)?;
        ledger::edit(s, n, l, id, "begin_bind", |r| {
            r.manifest_inode = Some(f.id())
        })?;
        io::write_new(&f, r.manifest.as_bytes())?;
        io::sync_file(&f)?;
        io::sync_directory(&d)?;
        r = record(l, id)?;
    }
    let mf = file(&d, MANIFEST, 65536, r.manifest_inode)?;
    if mf.len()? == 0 {
        io::append(&mf, 0, r.manifest.as_bytes())?;
        io::sync_file(&mf)?;
        io::sync_directory(&d)?;
    }
    if mf.read_all()? != r.manifest.as_bytes() {
        return Err(corrupt("incomplete or changed owned manifest"));
    }
    s.hit("begin_manifest_durable")?;
    let bd = child(&d, "blobs", r.blob_directory)?;
    let mut bindings = r.blobs.iter().map(|b| b.inode).collect::<Vec<_>>();
    let mut changed = false;
    for (i, b) in r.blobs.iter().enumerate() {
        if b.inode.is_none() {
            let f = io::create_file(&bd, name(basename(&b.digest)), b.size)?;
            io::sync_file(&f)?;
            bindings[i] = Some(f.id());
            changed = true;
        }
    }
    if changed {
        io::sync_directory(&bd)?;
        ledger::edit(s, n, l, id, "begin_bind", |r| {
            for (b, i) in r.blobs.iter_mut().zip(bindings) {
                b.inode = i
            }
        })?
    }
    recovery::validate_record(n, &record(l, id)?)?;
    ledger::edit(s, n, l, id, "begin_done", |r| r.intent = None)
}
/// `verified` is the entry verification of the current request; recovery
/// passes `None` and keeps full re-hashing (N3-12 §5 exemptions).
pub(super) fn finish_chunk(
    s: &FileSnapshotStaging,
    n: &Nodes,
    l: &mut Ledger,
    id: &UploadId,
    verified: Option<&recovery::Verified>,
) -> Result<(), TaskError> {
    let r = record(l, id)?;
    match verified {
        Some(v) => recovery::validate_record_trusting(n, &r, v)?,
        None => recovery::validate_record(n, &r)?,
    }
    let Some(Intent::Chunk(c)) = &r.intent else {
        return Err(corrupt("missing ChunkIntent"));
    };
    let (d, bd) = dirs(n, &r)?;
    let scratch = optional_file(&d, SCRATCH, 65536, c.scratch)?;
    if c.phase == "writing" {
        if let Some(f) = scratch {
            if c.scratch.is_none() {
                return Err(corrupt("unowned scratch"));
            }
            io::remove_file(&f)?;
            io::sync_directory(&d)?
        }
        return ledger::edit(s, n, l, id, "chunk_clear", |r| r.intent = None);
    }
    let b = r
        .blobs
        .iter()
        .find(|b| b.digest == c.blob)
        .ok_or_else(|| corrupt("missing chunk blob"))?;
    let target = file(&bd, basename(&c.blob), b.size, b.inode)?;
    if c.phase == "ready" {
        let sf = scratch
            .as_ref()
            .ok_or_else(|| corrupt("ScratchReady scratch missing"))?;
        let len = target.len()?;
        let mut appended = None;
        if len < c.next {
            let remaining = sf.read_range(len - c.old, (c.next - len) as usize)?;
            io::append(&target, len, &remaining)?;
            if len == c.old {
                appended = Some(remaining);
            }
        }
        s.hit("chunk_blob_appended")?;
        io::sync_file(&target)?;
        s.hit("chunk_blob_durable")?;
        // Continue the entry digest with the appended, read-back-verified
        // chunk; otherwise (recovery, partial tail) re-hash the whole prefix.
        let base = verified
            .and_then(|v| v.get(id, &c.blob))
            .filter(|p| p.offset == c.old && p.inode == target.id());
        let prefix = match (base, appended) {
            (Some(p), Some(bytes)) => {
                let mut stream = p.stream.clone();
                stream.update(&bytes);
                stream.finish()
            }
            _ => target.hash_prefix(c.next)?,
        };
        ledger::edit(s, n, l, id, "chunk_commit", |r| {
            if let Some(b) = r.blobs.iter_mut().find(|b| b.digest == c.blob) {
                b.offset = c.next;
                b.prefix = prefix
            }
            if let Some(Intent::Chunk(c)) = &mut r.intent {
                c.phase = "cleanup".into()
            }
        })?;
        s.hit("chunk_committed_cleanup_durable")?;
    }
    if let Some(f) = scratch {
        io::remove_file(&f)?;
    }
    s.hit("chunk_scratch_deleted")?;
    io::sync_directory(&d)?;
    ledger::edit(s, n, l, id, "chunk_clear", |r| r.intent = None)?;
    s.hit("chunk_cleared_durable")
}
fn verify_complete(n: &Nodes, r: &Record) -> Result<(), TaskError> {
    manifest(&r.snapshot, &r.manifest).map_err(|_| corrupt("retained manifest changed"))?;
    let (_, bd) = dirs(n, r)?;
    for b in &r.blobs {
        if b.offset != b.size {
            return Err(TaskError::invalid("snapshot input is incomplete"));
        }
        let f = file(&bd, basename(&b.digest), b.size, b.inode)?;
        if f.len()? != b.size || f.hash_prefix(b.size)? != b.digest {
            return Err(integrity("complete blob digest mismatch"));
        }
    }
    Ok(())
}
pub(super) fn finish_seal(
    s: &FileSnapshotStaging,
    n: &Nodes,
    l: &mut Ledger,
    id: &UploadId,
) -> Result<(), TaskError> {
    let r = record(l, id)?;
    verify_complete(n, &r)?;
    ledger::edit(s, n, l, id, "seal_commit", |r| {
        r.intent = None;
        r.state = UploadState::Staged
    })?;
    s.hit("seal_staged_durable")
}
pub(super) fn finish_cancel(
    s: &FileSnapshotStaging,
    n: &Nodes,
    l: &mut Ledger,
    id: &UploadId,
) -> Result<(), TaskError> {
    let r = record(l, id)?;
    recovery::validate_record(n, &r)?;
    let Some(Intent::Cleanup(c)) = &r.intent else {
        return Err(corrupt("missing CleanupIntent"));
    };
    if !c.directories_durable {
        // One original CleanupIntent covers every bound node. It survives all
        // partial deletion windows; absence is a pending owned unlink, while
        // any present node must still match the original inode and inventory.
        if let Some(d) = recovery::upload(n, &r)? {
            if let Some(bd) = optional_child(&d, "blobs", r.blob_directory)? {
                for b in &r.blobs {
                    if let Some(f) = optional_file(&bd, basename(&b.digest), b.size, b.inode)? {
                        s.hit("cancel_before_payload_delete")?;
                        s.hit("cancel_payload_delete_failed")?;
                        io::remove_file(&f)?;
                        s.hit("cancel_payload_deleted")?;
                    }
                }
                s.hit("cancel_directory_sync_failed")?;
                io::sync_directory(&bd)?;
            }
            if let Some(f) = optional_file(&d, MANIFEST, 65536, r.manifest_inode)? {
                io::remove_file(&f)?;
            }
            s.hit("cancel_directory_sync_failed")?;
            io::sync_directory(&d)?;
            if let Some(bd) = optional_child(&d, "blobs", r.blob_directory)? {
                if !bd.children()?.is_empty() {
                    return Err(corrupt("owned blobs directory is not empty"));
                }
                io::sync_directory(&bd)?;
                io::remove_empty_directory(&bd)?;
            }
            s.hit("cancel_directory_sync_failed")?;
            io::sync_directory(&d)?;
            if !d.children()?.is_empty() {
                return Err(corrupt("owned upload directory is not empty"));
            }
            io::sync_directory(&d)?;
            io::remove_empty_directory(&d)?;
        }
        s.hit("cancel_directory_sync_failed")?;
        io::sync_directory(&n.uploads)?;
        ledger::edit(s, n, l, id, "cleanup_durable", |r| {
            if let Some(Intent::Cleanup(c)) = &mut r.intent {
                c.directories_durable = true;
            }
        })?;
    }
    s.hit("cancel_directory_durable_before_release")?;
    let at = s.now();
    ledger::edit(s, n, l, id, "cancel_commit", |r| {
        r.state = UploadState::Cancelled;
        r.intent = None;
        r.cancelled_at = Some(at);
        r.manifest.clear();
        r.blobs.clear();
    })?;
    s.hit("cancel_release_durable")
}

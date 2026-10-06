use super::*;
use crate::n3_acceptance::new_task_id;
use std::{
    os::unix::fs::symlink,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
struct Dir(PathBuf);
impl Dir {
    fn new() -> Self {
        let p =
            std::env::temp_dir().join(format!("n3-download-{}", new_task_id().unwrap().as_str()));
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        Self(p)
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn record(bytes: &[u8]) -> ArtifactRecord {
    ArtifactRecord {
        schema_version: 1,
        artifact_id: ArtifactId::new("artifact-test".into()).unwrap(),
        task_id: TaskId::new("task-test".into()).unwrap(),
        snapshot_id: sha256(b"snapshot"),
        environment_digest: sha256(b"env"),
        producer_node: "provider".into(),
        workspace: "workspace".into(),
        owner_principal: "principal".into(),
        path: "result".into(),
        size_bytes: bytes.len() as u64,
        content_sha256: sha256(bytes),
        storage_ref: "private-locator".into(),
        created_at_unix: 100,
        retain_until_unix: 200,
        publication_state: PublicationState::Published,
    }
}
#[test]
fn download_resumes_verified_prefix_and_publishes_without_overwrite() {
    let dir = Dir::new();
    let dest = dir.0.join("result");
    let r = record(b"abcdef");
    let mut d = ArtifactDownload::open(&r, &dest).unwrap();
    assert_eq!(d.append(0, b"abc").unwrap(), 3);
    assert_eq!(d.append(0, b"abc").unwrap(), 3);
    assert!(!dest.exists());
    drop(d);
    let mut d = ArtifactDownload::open(&r, &dest).unwrap();
    assert_eq!(d.offset(), 3);
    assert!(d.append(1, b"bcd").is_err());
    assert_eq!(d.append(3, b"def").unwrap(), 6);
    assert_eq!(d.finish().unwrap(), dest);
    assert_eq!(fs::read(&dest).unwrap(), b"abcdef");
    drop(d);
    let mut d = ArtifactDownload::open(&r, &dest).unwrap();
    assert_eq!(d.offset(), 6);
    assert_eq!(d.finish().unwrap(), dest);
    assert_eq!(fs::read(&dest).unwrap(), b"abcdef");
}
#[test]
fn corrupt_download_never_publishes_and_existing_output_stays_unchanged() {
    let dir = Dir::new();
    let dest = dir.0.join("bad");
    let r = record(b"correct");
    let mut d = ArtifactDownload::open(&r, &dest).unwrap();
    d.append(0, b"corrupt").unwrap();
    assert_eq!(
        d.finish().unwrap_err().code,
        TaskErrorCode::ArtifactIntegrityFailed
    );
    assert!(!dest.exists());
    drop(d);
    let existing = dir.0.join("existing");
    fs::write(&existing, b"keep me").unwrap();
    assert_eq!(
        ArtifactDownload::open(&r, &existing).err().unwrap().code,
        TaskErrorCode::OutputExists
    );
    assert_eq!(fs::read(existing).unwrap(), b"keep me");
}
#[test]
fn destination_race_and_symlink_cannot_replace_user_files() {
    let dir = Dir::new();
    let dest = dir.0.join("result");
    let r = record(b"good");
    let mut d = ArtifactDownload::open(&r, &dest).unwrap();
    d.append(0, b"good").unwrap();
    fs::write(&dest, b"winner").unwrap();
    assert_eq!(d.finish().unwrap_err().code, TaskErrorCode::OutputExists);
    assert_eq!(fs::read(&dest).unwrap(), b"winner");
    let target = dir.0.join("other");
    fs::write(&target, b"private").unwrap();
    let link = dir.0.join("link");
    symlink(&target, &link).unwrap();
    assert_eq!(
        ArtifactDownload::open(&r, &link).err().unwrap().code,
        TaskErrorCode::OutputExists
    );
    assert_eq!(fs::read(&target).unwrap(), b"private");
    let real = dir.0.join("real");
    fs::create_dir(&real).unwrap();
    let parent = dir.0.join("parent-link");
    symlink(&real, &parent).unwrap();
    assert_eq!(
        ArtifactDownload::open(&r, &parent.join("output"))
            .err()
            .unwrap()
            .code,
        TaskErrorCode::InvalidPath
    );
}
#[test]
fn lost_torn_or_mutated_progress_never_resets_partial_bytes() {
    for variant in 0..4 {
        let dir = Dir::new();
        let dest = dir.0.join("result");
        let r = record(b"abcdef");
        let mut d = ArtifactDownload::open(&r, &dest).unwrap();
        d.append(0, b"abc").unwrap();
        let private = d.directory.clone();
        drop(d);
        match variant {
            0 => fs::remove_file(private.join("progress-v1.json")).unwrap(),
            1 => {
                fs::write(private.join("progress-v1.json"), b"torn").unwrap();
            }
            2 => {
                fs::write(private.join("partial"), b"XYZ").unwrap();
            }
            _ => {
                let mut f = OpenOptions::new()
                    .append(true)
                    .open(private.join("partial"))
                    .unwrap();
                f.write_all(b"torn-extra").unwrap();
            }
        }
        assert!(ArtifactDownload::open(&r, &dest).is_err());
        assert!(!dest.exists());
        assert!(fs::read(private.join("partial")).unwrap().len() >= 3);
    }
}
#[test]
fn wrong_artifact_identity_pending_record_and_hardlinks_are_rejected() {
    let dir = Dir::new();
    let dest = dir.0.join("result");
    let r = record(b"abcd");
    let mut d = ArtifactDownload::open(&r, &dest).unwrap();
    d.append(0, b"ab").unwrap();
    let private = d.directory.clone();
    drop(d);
    let mut other = r.clone();
    other.artifact_id = ArtifactId::new("another-artifact".into()).unwrap();
    assert!(ArtifactDownload::open(&other, &dest).is_err());
    other = r.clone();
    other.publication_state = PublicationState::Pending;
    assert_eq!(
        ArtifactDownload::open(&other, &dest).err().unwrap().code,
        TaskErrorCode::ArtifactUnavailable
    );
    fs::hard_link(private.join("partial"), dir.0.join("stolen-link")).unwrap();
    assert!(ArtifactDownload::open(&r, &dest).is_err());
    assert_eq!(fs::read(private.join("partial")).unwrap(), b"ab");
}
#[test]
fn empty_artifact_and_page_bounds_are_verified() {
    let dir = Dir::new();
    let dest = dir.0.join("empty");
    let mut d = ArtifactDownload::open(&record(b""), &dest).unwrap();
    d.finish().unwrap();
    assert_eq!(fs::read(dest).unwrap(), b"");
    let dest = dir.0.join("small");
    let mut d = ArtifactDownload::open(&record(b"abcd"), &dest).unwrap();
    assert!(d.append(1, b"a").is_err());
    assert!(d.append(0, b"").is_err());
    assert!(d.append(0, b"abcde").is_err());
    assert!(d.finish().is_err());
    assert!(!dest.exists());
}
#[test]
fn real_sigkill_during_atomic_publication_recovers_same_inode() {
    use std::os::unix::process::ExitStatusExt;
    for point in [
        "after_publish_intent",
        "after_link",
        "after_destination_sync",
    ] {
        let dir = Dir::new();
        let dest = dir.0.join("result");
        let r = record(b"abcdef");
        let mut d = ArtifactDownload::open(&r, &dest).unwrap();
        d.append(0, b"abcdef").unwrap();
        drop(d);
        let recordfile = dir.0.join("record.json");
        fs::write(&recordfile, r.to_value().canonical_bytes()).unwrap();
        let marker = dir.0.join("ready");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "artifact_download::tests::download_process_fixture",
                "--ignored",
                "--nocapture",
            ])
            .env("NEXUS_DOWNLOAD_FIXTURE_RECORD", &recordfile)
            .env("NEXUS_DOWNLOAD_FIXTURE_DESTINATION", &dest)
            .env("NEXUS_DOWNLOAD_FIXTURE_POINT", point)
            .env("NEXUS_DOWNLOAD_FIXTURE_MARKER", &marker)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !marker.exists() {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("fixture exited early: {status}");
            }
            if Instant::now() > deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("fixture never reached {point}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        child.kill().unwrap();
        assert_eq!(child.wait().unwrap().signal(), Some(9));
        let mut recovered = ArtifactDownload::open(&r, &dest).unwrap();
        recovered.finish().unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"abcdef");
        assert_eq!(
            recovered.partial(false).unwrap().metadata().unwrap().ino(),
            fs::metadata(dest).unwrap().ino()
        );
    }
}
#[test]
#[ignore = "child fixture invoked by real SIGKILL parent"]
fn download_process_fixture() {
    let r: ArtifactRecord = crate::n3_acceptance::decode_dto(
        &fs::read(std::env::var("NEXUS_DOWNLOAD_FIXTURE_RECORD").unwrap()).unwrap(),
    )
    .unwrap();
    let dest = PathBuf::from(std::env::var("NEXUS_DOWNLOAD_FIXTURE_DESTINATION").unwrap());
    let point = std::env::var("NEXUS_DOWNLOAD_FIXTURE_POINT").unwrap();
    let marker = PathBuf::from(std::env::var("NEXUS_DOWNLOAD_FIXTURE_MARKER").unwrap());
    ArtifactDownload::open(&r, &dest)
        .unwrap()
        .finish_with(&mut |p| {
            if p == point {
                fs::write(&marker, b"ready").unwrap();
                File::open(&marker).unwrap().sync_all().unwrap();
                loop {
                    std::thread::park();
                }
            }
            Ok(())
        })
        .unwrap();
}

#[test]
fn losing_both_partial_and_progress_cannot_restart_an_existing_download() {
    let dir = Dir::new();
    let dest = dir.0.join("result");
    let r = record(b"abcdef");
    let mut d = ArtifactDownload::open(&r, &dest).unwrap();
    d.append(0, b"abc").unwrap();
    let private = d.directory.clone();
    drop(d);
    fs::remove_file(private.join("partial")).unwrap();
    fs::remove_file(private.join("progress-v1.json")).unwrap();
    assert!(
        ArtifactDownload::open(&r, &dest).is_err(),
        "known destination authority must not restart as fresh"
    );
    assert!(!private.join("partial").exists());
}

#[test]
fn missing_receiver_lock_cannot_create_a_second_owner() {
    let dir = Dir::new();
    let dest = dir.0.join("result");
    let r = record(b"abcdef");
    let mut d = ArtifactDownload::open(&r, &dest).unwrap();
    d.append(0, b"abc").unwrap();
    fs::remove_file(d.directory.join("receiver.lock")).unwrap();
    assert!(
        ArtifactDownload::open(&r, &dest).is_err(),
        "new lock inode must not bypass existing owner"
    );
    assert!(
        d.append(3, b"def").is_err(),
        "live owner must detect lock authority loss"
    );
}

#[test]
fn independent_same_process_receiver_is_busy_without_mutating_prefix() {
    let dir = Dir::new();
    let dest = dir.0.join("result");
    let r = record(b"abcdef");
    let mut owner = ArtifactDownload::open(&r, &dest).unwrap();
    owner.append(0, b"abc").unwrap();
    let private = owner.directory.clone();
    let metadata = fs::read(private.join("progress-v1.json")).unwrap();
    let competing_record = r.clone();
    let competing_destination = dest.clone();
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        tx.send(ArtifactDownload::open(
            &competing_record,
            &competing_destination,
        ))
        .ok();
    });
    let error = match rx.recv_timeout(Duration::from_secs(2)) {
        Ok(result) => result.err().expect("distinct File must compete for lease"),
        Err(error) => {
            // Release the original owner before joining, so a blocking-lock
            // regression reports failure without leaving a detached worker.
            drop(owner);
            worker.join().unwrap();
            panic!("competing receiver waited instead of reporting busy: {error}");
        }
    };
    worker.join().unwrap();
    assert_eq!(error.code, TaskErrorCode::CapacityUnavailable);
    assert!(error.retryable);
    assert_eq!(fs::read(private.join("partial")).unwrap(), b"abc");
    assert_eq!(
        fs::read(private.join("progress-v1.json")).unwrap(),
        metadata
    );
    assert!(!dest.exists());
    drop(owner);
    let mut resumed = ArtifactDownload::open(&r, &dest).unwrap();
    assert_eq!(resumed.offset(), 3);
    resumed.append(3, b"def").unwrap();
    resumed.finish().unwrap();
    assert_eq!(fs::read(dest).unwrap(), b"abcdef");
}

#[test]
fn replaced_lease_inode_stops_live_owner_without_changing_prefix() {
    let dir = Dir::new();
    let dest = dir.0.join("result");
    let r = record(b"abcdef");
    let mut owner = ArtifactDownload::open(&r, &dest).unwrap();
    owner.append(0, b"abc").unwrap();
    let private = owner.directory.clone();
    let metadata = fs::read(private.join("progress-v1.json")).unwrap();
    fs::rename(private.join("receiver.lock"), private.join("old-lock")).unwrap();
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(private.join("receiver.lock"))
        .unwrap()
        .sync_all()
        .unwrap();
    assert_eq!(
        owner.append(3, b"def").unwrap_err().code,
        TaskErrorCode::StateCorrupt
    );
    assert_eq!(
        owner.finish().unwrap_err().code,
        TaskErrorCode::StateCorrupt
    );
    assert_eq!(fs::read(private.join("partial")).unwrap(), b"abc");
    assert_eq!(
        fs::read(private.join("progress-v1.json")).unwrap(),
        metadata
    );
    assert!(!dest.exists());
}

//! N3-12 §1: real Linux filesystem observations of atomic no-replace
//! publication. Fsync/private parent validation belong to the composition root.
use super::{publish_directory_no_replace, publish_with_test_error};
use std::{
    fs, io,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::{
        Arc, Barrier,
        atomic::{AtomicU64, Ordering},
    },
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "nexus-n312-noreplace-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn inode(path: &Path) -> (u64, u64) {
    let meta = fs::symlink_metadata(path).unwrap();
    (meta.dev(), meta.ino())
}
fn tree(path: &Path, bytes: &[u8]) {
    fs::create_dir(path).unwrap();
    fs::write(path.join("payload"), bytes).unwrap();
}

#[test]
fn no_replace_moves_directory_preserving_original_directory_and_payload_inodes() {
    let temp = Temp::new();
    let source = temp.path("source");
    let target = temp.path("target");
    tree(&source, b"source bytes");
    let source_inode = inode(&source);
    let payload_inode = inode(&source.join("payload"));
    publish_directory_no_replace(&source, &target)
        .expect("absent target must accept atomic publication");
    assert!(!source.exists());
    assert_eq!(inode(&target), source_inode);
    assert_eq!(inode(&target.join("payload")), payload_inode);
    assert_eq!(fs::read(target.join("payload")).unwrap(), b"source bytes");
}

#[test]
fn no_replace_existing_nonempty_directory_preserves_both_trees() {
    let temp = Temp::new();
    let source = temp.path("source");
    let target = temp.path("target");
    tree(&source, b"source");
    tree(&target, b"original target");
    let before = (
        inode(&source),
        inode(&source.join("payload")),
        inode(&target),
        inode(&target.join("payload")),
    );
    let error = publish_directory_no_replace(&source, &target).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(
        (
            inode(&source),
            inode(&source.join("payload")),
            inode(&target),
            inode(&target.join("payload"))
        ),
        before
    );
    assert_eq!(fs::read(source.join("payload")).unwrap(), b"source");
    assert_eq!(
        fs::read(target.join("payload")).unwrap(),
        b"original target"
    );
}

#[test]
fn no_replace_existing_empty_directory_is_not_overwritten() {
    let temp = Temp::new();
    let source = temp.path("source");
    let target = temp.path("target");
    tree(&source, b"source");
    fs::create_dir(&target).unwrap();
    let before = (
        inode(&source),
        inode(&source.join("payload")),
        inode(&target),
    );
    assert_eq!(
        publish_directory_no_replace(&source, &target)
            .unwrap_err()
            .kind(),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(
        (
            inode(&source),
            inode(&source.join("payload")),
            inode(&target)
        ),
        before
    );
    assert_eq!(fs::read(source.join("payload")).unwrap(), b"source");
    assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
}

#[test]
fn no_replace_files_use_same_atomic_no_overwrite_primitive() {
    let temp = Temp::new();
    let source = temp.path("source");
    let target = temp.path("target");
    fs::write(&source, b"first").unwrap();
    let source_inode = inode(&source);
    publish_directory_no_replace(&source, &target).unwrap();
    assert_eq!(inode(&target), source_inode);
    assert!(!source.exists());
    fs::write(&source, b"second").unwrap();
    let next_source_inode = inode(&source);
    assert_eq!(
        publish_directory_no_replace(&source, &target)
            .unwrap_err()
            .kind(),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(inode(&target), source_inode);
    assert_eq!(inode(&source), next_source_inode);
    assert_eq!(fs::read(&target).unwrap(), b"first");
    assert_eq!(fs::read(&source).unwrap(), b"second");
}

#[test]
fn no_replace_existing_symlink_is_a_target_and_is_not_followed() {
    let temp = Temp::new();
    let source = temp.path("source");
    let target = temp.path("target");
    let decoy = temp.path("decoy");
    tree(&source, b"source");
    tree(&decoy, b"decoy");
    std::os::unix::fs::symlink(&decoy, &target).unwrap();
    let before = (
        inode(&source),
        inode(&target),
        inode(&decoy),
        inode(&decoy.join("payload")),
    );
    assert_eq!(
        publish_directory_no_replace(&source, &target)
            .unwrap_err()
            .kind(),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(
        (
            inode(&source),
            inode(&target),
            inode(&decoy),
            inode(&decoy.join("payload"))
        ),
        before
    );
    assert_eq!(fs::read_link(&target).unwrap(), decoy);
    assert_eq!(fs::read(source.join("payload")).unwrap(), b"source");
    assert_eq!(fs::read(target.join("payload")).unwrap(), b"decoy");
}

#[test]
fn no_replace_dangling_destination_symlink_preserves_link_and_source() {
    let temp = Temp::new();
    let source = temp.path("source");
    let target = temp.path("target");
    let missing_referent = temp.path("absent-referent");
    tree(&source, b"source");
    std::os::unix::fs::symlink(&missing_referent, &target).unwrap();
    let before = (
        inode(&source),
        inode(&source.join("payload")),
        inode(&target),
    );
    let link_before = fs::read_link(&target).unwrap();
    assert_eq!(
        fs::symlink_metadata(&missing_referent).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    assert_eq!(
        publish_directory_no_replace(&source, &target)
            .unwrap_err()
            .kind(),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(
        (
            inode(&source),
            inode(&source.join("payload")),
            inode(&target)
        ),
        before
    );
    assert!(
        fs::symlink_metadata(&target)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read_link(&target).unwrap(), link_before);
    assert_eq!(fs::read(source.join("payload")).unwrap(), b"source");
    assert_eq!(
        fs::symlink_metadata(&missing_referent).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
}

#[test]
fn no_replace_enosys_and_einval_preserve_empty_directory_without_fallback() {
    // Linux ENOSYS=38 and EINVAL=22: inject only this call's syscall result.
    // Ordinary rename would successfully overwrite the empty directory.
    for errno in [38, 22] {
        let temp = Temp::new();
        let source = temp.path("source");
        let target = temp.path("target");
        tree(&source, b"source");
        fs::create_dir(&target).unwrap();
        let before = (
            inode(&source),
            inode(&source.join("payload")),
            inode(&target),
        );
        let error = publish_with_test_error(&source, &target, errno).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported, "errno {errno}");
        assert_eq!(
            (
                inode(&source),
                inode(&source.join("payload")),
                inode(&target)
            ),
            before
        );
        assert_eq!(fs::read(source.join("payload")).unwrap(), b"source");
        assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
    }
}

#[test]
fn no_replace_enosys_and_einval_preserve_regular_files_without_fallback() {
    for errno in [38, 22] {
        let temp = Temp::new();
        let source = temp.path("source");
        let target = temp.path("target");
        fs::write(&source, b"source").unwrap();
        fs::write(&target, b"original target").unwrap();
        let before = (inode(&source), inode(&target));
        let error = publish_with_test_error(&source, &target, errno).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported, "errno {errno}");
        assert_eq!((inode(&source), inode(&target)), before);
        assert_eq!(fs::read(&source).unwrap(), b"source");
        assert_eq!(fs::read(&target).unwrap(), b"original target");
    }
}

#[test]
fn no_replace_two_concurrent_directory_publishers_have_exactly_one_winner() {
    let temp = Temp::new();
    let sources = [temp.path("source-a"), temp.path("source-b")];
    let target = temp.path("target");
    for (i, source) in sources.iter().enumerate() {
        tree(source, &[i as u8]);
    }
    let original_inodes = [
        (inode(&sources[0]), inode(&sources[0].join("payload"))),
        (inode(&sources[1]), inode(&sources[1].join("payload"))),
    ];
    let barrier = Arc::new(Barrier::new(3));
    let handles: Vec<_> = sources
        .iter()
        .cloned()
        .map(|source| {
            let target = target.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                publish_directory_no_replace(&source, &target)
            })
        })
        .collect();
    barrier.wait();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(
        results.iter().filter(|r| r.is_ok()).count(),
        1,
        "one atomic publication must win"
    );
    let winner = results.iter().position(Result::is_ok).unwrap();
    let loser = 1 - winner;
    assert_eq!(
        results[loser].as_ref().unwrap_err().kind(),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(
        (inode(&target), inode(&target.join("payload"))),
        original_inodes[winner]
    );
    assert_eq!(
        fs::read(target.join("payload")).unwrap(),
        vec![winner as u8]
    );
    assert!(!sources[winner].exists());
    assert_eq!(
        (
            inode(&sources[loser]),
            inode(&sources[loser].join("payload"))
        ),
        original_inodes[loser]
    );
    assert_eq!(
        fs::read(sources[loser].join("payload")).unwrap(),
        vec![loser as u8]
    );
}

#[test]
fn no_replace_missing_source_preserves_existing_target_and_returns_typed_io() {
    let temp = Temp::new();
    let source = temp.path("missing");
    let target = temp.path("target");
    tree(&target, b"original");
    let before = (inode(&target), inode(&target.join("payload")));
    assert_eq!(
        publish_directory_no_replace(&source, &target)
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotFound
    );
    assert!(!source.exists());
    assert_eq!((inode(&target), inode(&target.join("payload"))), before);
    assert_eq!(fs::read(target.join("payload")).unwrap(), b"original");
}

#[test]
fn no_replace_missing_destination_parent_leaves_source_unchanged() {
    let temp = Temp::new();
    let source = temp.path("source");
    let target = temp.path("missing-parent/target");
    tree(&source, b"original");
    let before = (inode(&source), inode(&source.join("payload")));
    assert_eq!(
        publish_directory_no_replace(&source, &target)
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotFound
    );
    assert!(!temp.path("missing-parent").exists());
    assert_eq!((inode(&source), inode(&source.join("payload"))), before);
    assert_eq!(fs::read(source.join("payload")).unwrap(), b"original");
}

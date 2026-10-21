//! Private bounded Linux IO. Callers own the initialization state machine.
use super::{InitFailure, Result, corrupt, persistence};
use nexus_domain::task::TaskErrorCode;
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

const FLAGS: i32 = 0x20000 | 0x800; // Linux O_NOFOLLOW | O_NONBLOCK.
pub(super) const SMALL: u64 = 16 * 1024;
pub(super) const AUTHORITY: u64 = 64 * 1024 * 1024;

pub(super) fn identity(meta: &Metadata) -> (u64, u64) {
    (meta.dev(), meta.ino())
}
pub(super) fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(persistence(e)),
    }
}
pub(super) fn directory(path: &Path, private: bool) -> Result<(u64, u64)> {
    let meta = fs::symlink_metadata(path).map_err(persistence)?;
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || (private && meta.permissions().mode() & 0o777 != 0o700)
    {
        return Err(corrupt("initialization directory must be real and private"));
    }
    Ok(identity(&meta))
}
pub(super) struct Root {
    pub(super) path: PathBuf,
    pub(super) binding: (u64, u64),
    ancestors: Vec<(PathBuf, File, (u64, u64))>,
}
impl Root {
    pub(super) fn open(path: &Path) -> Result<Self> {
        if !path.is_absolute()
            || path
                .components()
                .any(|c| c == std::path::Component::ParentDir)
        {
            return Err(corrupt(
                "initialization root requires an absolute path without ..",
            ));
        }
        let binding = directory(path, true)?;
        let mut ancestors = Vec::new();
        for ancestor in path.ancestors() {
            let before = directory(ancestor, ancestor == path)?;
            if ancestor == path && before != binding {
                return Err(corrupt("initialization root changed before opening"));
            }
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(FLAGS)
                .open(ancestor)
                .map_err(persistence)?;
            if identity(&file.metadata().map_err(persistence)?) != before {
                return Err(corrupt("initialization ancestor changed while opening"));
            }
            ancestors.push((ancestor.to_owned(), file, before));
        }
        let root = Self {
            path: path.to_owned(),
            binding,
            ancestors,
        };
        root.check()?;
        Ok(root)
    }
    pub(super) fn check(&self) -> Result<()> {
        if directory(&self.path, true)? != self.binding {
            return Err(corrupt("original initialization root changed"));
        }
        for (path, file, binding) in &self.ancestors {
            if directory(path, path == &self.path)? != *binding
                || identity(&file.metadata().map_err(persistence)?) != *binding
            {
                return Err(corrupt("initialization root or ancestor inode changed"));
            }
        }
        Ok(())
    }
}
pub(super) struct Record {
    pub(super) file: File,
    pub(super) path: PathBuf,
    pub(super) bytes: Vec<u8>,
    limit: u64,
    strict: bool,
}
impl Record {
    pub(super) fn binding(&self) -> Result<(u64, u64)> {
        Ok(identity(&self.file.metadata().map_err(persistence)?))
    }
    pub(super) fn check(&self) -> Result<()> {
        check_file(&self.file, &self.path, self.strict)?;
        let current = read(&self.path, self.limit, self.strict)?;
        if current.binding()? != self.binding()? || current.bytes != self.bytes {
            return Err(corrupt("original initialization record changed"));
        }
        Ok(())
    }
}
pub(super) fn check_file(file: &File, path: &Path, strict: bool) -> Result<()> {
    let fd = file.metadata().map_err(persistence)?;
    let named = fs::symlink_metadata(path).map_err(persistence)?;
    let mode = fd.permissions().mode() & 0o777;
    if !fd.is_file()
        || fd.nlink() != 1
        || named.file_type().is_symlink()
        || identity(&fd) != identity(&named)
        || if strict {
            mode != 0o600
        } else {
            mode & 0o022 != 0
        }
    {
        return Err(corrupt(
            "initialization record must be bound, singly linked regular and private",
        ));
    }
    Ok(())
}
pub(super) fn read_optional(path: &Path, limit: u64, strict: bool) -> Result<Option<Record>> {
    let mut file = match OpenOptions::new().read(true).custom_flags(FLAGS).open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return if exists(path)? {
                Err(corrupt("unreadable initialization authority"))
            } else {
                Ok(None)
            };
        }
        Err(e) if e.raw_os_error() == Some(40) => {
            return Err(corrupt("linked initialization authority"));
        }
        Err(e) => return Err(persistence(e)),
    };
    check_file(&file, path, strict)?;
    if file.metadata().map_err(persistence)?.len() > limit {
        return Err(corrupt("initialization record exceeds its byte bound"));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(persistence)?;
    if bytes.len() as u64 > limit {
        return Err(corrupt("initialization record grew beyond its byte bound"));
    }
    check_file(&file, path, strict)?;
    Ok(Some(Record {
        file,
        path: path.to_owned(),
        bytes,
        limit,
        strict,
    }))
}
pub(super) fn read(path: &Path, limit: u64, strict: bool) -> Result<Record> {
    read_optional(path, limit, strict)?
        .ok_or_else(|| corrupt("required initialization authority is missing"))
}
pub(super) fn sync(path: &Path) -> Result<()> {
    let before = directory(path, false)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(FLAGS)
        .open(path)
        .map_err(persistence)?;
    if identity(&file.metadata().map_err(persistence)?) != before {
        return Err(corrupt("directory changed before synchronization"));
    }
    file.sync_all().map_err(persistence)?;
    if directory(path, false)? != before {
        return Err(corrupt("directory changed during synchronization"));
    }
    Ok(())
}
pub(super) struct Lease {
    pub(super) file: File,
    path: PathBuf,
}
impl Lease {
    pub(super) fn acquire(root: &Root, path: &Path, create: bool) -> Result<Self> {
        root.check()?;
        let (file, created) = if create {
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(FLAGS)
                .open(path)
            {
                Ok(file) => (file, true),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let file = OpenOptions::new()
                        .read(true)
                        .custom_flags(FLAGS)
                        .open(path)
                        .map_err(persistence)?;
                    check_file(&file, path, true)?;
                    nexus_platform_linux::file_lease::try_lock_exclusive(&file).map_err(|e| {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            InitFailure::new(
                                TaskErrorCode::CapacityUnavailable,
                                "initialization lease is busy",
                                true,
                            )
                        } else {
                            persistence(e)
                        }
                    })?;
                    // The retry return still ends a successfully acquired scope.
                    let _lease = Self {
                        file,
                        path: path.to_owned(),
                    };
                    return Err(InitFailure::new(
                        TaskErrorCode::CapacityUnavailable,
                        "provider initialization appeared concurrently; retry from its durable state",
                        true,
                    ));
                }
                Err(e) => return Err(persistence(e)),
            }
        } else {
            (
                OpenOptions::new()
                    .read(true)
                    .custom_flags(FLAGS)
                    .open(path)
                    .map_err(persistence)?,
                false,
            )
        };
        let result = (|| {
            check_file(&file, path, true)?;
            nexus_platform_linux::file_lease::try_lock_exclusive(&file).map_err(|e| {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    InitFailure::new(
                        TaskErrorCode::CapacityUnavailable,
                        "initialization authority lease is busy",
                        true,
                    )
                } else {
                    persistence(e)
                }
            })?;
            let lease = Self {
                file,
                path: path.to_owned(),
            };
            lease.check(root)?;
            if created {
                lease.file.sync_all().map_err(persistence)?;
                sync(&root.path)?;
            }
            Ok(lease)
        })();
        result.map_err(|failure: InitFailure| {
            if created {
                failure.at("intent", true)
            } else {
                failure
            }
        })
    }
    pub(super) fn binding(&self) -> Result<(u64, u64)> {
        Ok(identity(&self.file.metadata().map_err(persistence)?))
    }
    pub(super) fn check(&self, root: &Root) -> Result<()> {
        root.check()?;
        check_file(&self.file, &self.path, true)
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        // An unrelated child can inherit this OFD until exec even with CLOEXEC.
        // End the private operation's lease now, rather than waiting for that
        // child's descriptor to close. Drop cannot return an IO error or panic
        // during unwind; on failure, closing our File remains the fallback.
        let _ = nexus_platform_linux::file_lease::unlock_exclusive(&self.file);
    }
}
pub(super) fn create_directory(root: &Root, path: &Path) -> Result<(u64, u64)> {
    root.check()?;
    for parent in path
        .parent()
        .ok_or_else(|| corrupt("directory lacks parent"))?
        .ancestors()
    {
        directory(parent, parent.starts_with(&root.path))?;
    }
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(persistence)?;
    sync(
        path.parent()
            .ok_or_else(|| corrupt("initialization directory lacks parent"))?,
    )?;
    root.check()?;
    directory(path, true)
}
pub(super) fn create_file(root: &Root, path: &Path, bytes: &[u8]) -> Result<Record> {
    root.check()?;
    let mut file = OpenOptions::new()
        .write(true)
        .read(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(FLAGS)
        .open(path)
        .map_err(persistence)?;
    check_file(&file, path, true)?;
    file.write_all(bytes).map_err(persistence)?;
    file.sync_all().map_err(persistence)?;
    sync(
        path.parent()
            .ok_or_else(|| corrupt("initialization file lacks parent"))?,
    )?;
    root.check()?;
    check_file(&file, path, true)?;
    let published = read(path, SMALL, true)?;
    if published.binding()? != identity(&file.metadata().map_err(persistence)?)
        || published.bytes != bytes
    {
        return Err(corrupt("created initialization record was replaced"));
    }
    Ok(published)
}
pub(super) fn replace(
    root: &Root,
    path: &Path,
    before: Option<&Record>,
    bytes: &[u8],
    prepublish: impl Fn() -> Result<()>,
) -> Result<Record> {
    let check = || {
        root.check()?;
        prepublish()?;
        if let Some(before) = before {
            before.check()?;
        } else if exists(path)? {
            return Err(corrupt("initialization publication target appeared"));
        }
        Ok(())
    };
    check()?;
    let tmp = root.path.join(format!(
        ".task-provider-init-write-{}",
        nexus::n3_acceptance::new_task_id()
            .map_err(InitFailure::from)?
            .as_str()
    ));
    let temporary = create_file(root, &tmp, bytes)?;
    check()?;
    temporary.check()?;
    fs::rename(&tmp, path).map_err(persistence)?;
    sync(
        path.parent()
            .ok_or_else(|| corrupt("initialization target lacks parent"))?,
    )?;
    root.check()?;
    let published = read(path, SMALL, true)?;
    if published.binding()? != temporary.binding()? || published.bytes != bytes {
        return Err(corrupt(
            "initialization publication changed prepared record",
        ));
    }
    Ok(published)
}
pub(super) fn publish_identity(
    root: &Root,
    source: &Record,
    target: &Path,
    prepublish: impl Fn() -> Result<()>,
) -> Result<Record> {
    root.check()?;
    prepublish()?;
    source.check()?;
    if exists(target)? {
        return Err(corrupt("identity target appeared before publication"));
    }
    // rename preserves the staged original inode; init owns this fresh N2 root.
    fs::rename(&source.path, target).map_err(persistence)?;
    sync(
        target
            .parent()
            .ok_or_else(|| corrupt("identity target lacks parent"))?,
    )?;
    sync(&root.path)?;
    root.check()?;
    prepublish()?;
    let published = read(target, SMALL, true)?;
    if published.binding()? != source.binding()? || published.bytes != source.bytes {
        return Err(corrupt("identity publication changed original material"));
    }
    Ok(published)
}
pub(super) fn sentinel(root: &Root, path: &Path, expected: &[u8]) -> Result<Record> {
    let before = read(path, SMALL, true)?;
    if before.bytes == expected {
        return Ok(before);
    }
    if !before.bytes.is_empty() {
        return Err(corrupt("unexpected capacity owner content"));
    }
    root.check()?;
    before.check()?;
    let mut writer = OpenOptions::new()
        .write(true)
        .custom_flags(FLAGS)
        .open(path)
        .map_err(persistence)?;
    check_file(&writer, path, true)?;
    if identity(&writer.metadata().map_err(persistence)?) != before.binding()? {
        return Err(corrupt("capacity owner inode changed"));
    }
    writer.write_all(expected).map_err(persistence)?;
    writer.sync_all().map_err(persistence)?;
    sync(
        path.parent()
            .ok_or_else(|| corrupt("capacity owner lacks parent"))?,
    )?;
    let after = read(path, SMALL, true)?;
    if after.binding()? != before.binding()? || after.bytes != expected {
        return Err(corrupt("capacity owner sentinel changed"));
    }
    root.check()?;
    Ok(after)
}

#[cfg(test)]
mod scoped_owner_lease_release_tests {
    use super::*;
    use std::process::{Child, Command, Stdio};

    // These E2 tests exercise only the real private IO owner. The fixture is
    // deliberately not a fabricated initialized provider/staging authority.
    struct Fixture {
        root: Root,
        path: PathBuf,
        expected_bytes: &'static [u8],
    }
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "n311-scoped-owner-{}",
                nexus::n3_acceptance::new_task_id().unwrap().as_str()
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            let root = Root::open(&path).unwrap();
            Self {
                path: path.join("task-provider-init.lock"),
                root,
                expected_bytes: b"",
            }
        }
        fn acquire(&self, create: bool) -> Result<Lease> {
            Lease::acquire(&self.root, &self.path, create)
        }
        fn unchanged(&self, binding: (u64, u64)) {
            self.root.check().unwrap();
            let meta = fs::symlink_metadata(&self.path).unwrap();
            assert_eq!(identity(&meta), binding, "fixed lock inode changed");
            assert!(meta.is_file());
            assert_eq!(meta.nlink(), 1);
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
            assert_eq!(fs::read(&self.path).unwrap(), self.expected_bytes);
            assert_eq!(fs::read_dir(&self.root.path).unwrap().count(), 1);
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root.path);
        }
    }

    // A single owned process (no shell/grandchild) retains only a cloned OFD on
    // stdin. spawn's completed exec, /proc/fd identity, and try_wait are the
    // barriers; no elapsed sleep or scheduler race is used for test ordering.
    struct OwnedChild {
        child: Child,
    }
    impl OwnedChild {
        fn inheriting(file: &File) -> Self {
            let child = Command::new("/bin/sleep")
                .arg("600")
                .stdin(Stdio::from(file.try_clone().unwrap()))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut owned = Self { child };
            owned.assert_holds(identity(&file.metadata().unwrap()));
            eprintln!("owned-child spawned pid={}", owned.child.id());
            owned
        }
        fn assert_holds(&mut self, binding: (u64, u64)) {
            assert!(self.child.try_wait().unwrap().is_none(), "child exited");
            let fd = PathBuf::from(format!("/proc/{}/fd/0", self.child.id()));
            assert_eq!(identity(&fs::metadata(fd).unwrap()), binding);
            assert!(self.child.try_wait().unwrap().is_none(), "child exited");
        }
        fn stop(&mut self) {
            let pid = self.child.id();
            let _ = self.child.kill();
            self.child
                .wait()
                .expect("reap owned descriptor-holder child");
            assert!(!PathBuf::from(format!("/proc/{pid}")).exists());
            eprintln!("owned-child reaped pid={pid}");
        }
    }
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            // Drop must also reap when a regression assertion unwinds. Avoid
            // double-panic, but record both operations for cleanup evidence.
            let pid = self.child.id();
            let killed = self.child.kill();
            let waited = self.child.wait();
            eprintln!(
                "owned-child drop pid={pid} kill={killed:?} wait={waited:?} proc_exists={}",
                PathBuf::from(format!("/proc/{pid}")).exists()
            );
        }
    }

    fn assert_busy(result: Result<Lease>) {
        let failure = match result {
            Ok(_) => panic!("independent contender acquired an owned lease"),
            Err(failure) => failure,
        };
        assert_eq!(failure.error.code, TaskErrorCode::CapacityUnavailable);
        assert!(failure.error.retryable);
    }
    fn assert_raw_busy(path: &Path) {
        let contender = File::open(path).unwrap();
        let error = nexus_platform_linux::file_lease::try_lock_exclusive(&contender)
            .expect_err("independent raw contender acquired an owned lease");
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
    }

    enum Exit {
        Normal,
        Error,
        Unwind,
    }
    fn release_on_exit(exit: Exit, existing: bool) {
        let mut fixture = Fixture::new();
        let owner = if existing {
            // Establish the fixed inode through real private IO, then end the
            // initial owner without an inherited child. These prescribed bytes
            // are test input, never inferred from production output.
            let initial = fixture.acquire(true).unwrap();
            let original_binding = initial.binding().unwrap();
            drop(initial);
            fixture.expected_bytes = b"n311-scoped-owner-regression-sentinel-v1\n";
            fs::write(&fixture.path, fixture.expected_bytes).unwrap();
            fixture.unchanged(original_binding);
            let owner = fixture.acquire(false).unwrap();
            assert_eq!(owner.binding().unwrap(), original_binding);
            fixture.unchanged(original_binding);
            owner
        } else {
            fixture.acquire(true).unwrap()
        };
        let binding = owner.binding().unwrap();
        let mut old_child = OwnedChild::inheriting(&owner.file);
        assert_busy(fixture.acquire(false));
        // Failed acquisition must not release this legitimate owner.
        assert_raw_busy(&fixture.path);
        owner.check(&fixture.root).unwrap();
        fixture.unchanged(binding);
        match exit {
            Exit::Normal => drop(owner),
            Exit::Error => {
                fn fail_after_acquire(_owner: Lease) -> Result<()> {
                    Err(corrupt("test operation fails while owning its lease"))
                }
                let error = fail_after_acquire(owner).unwrap_err();
                assert_eq!(error.error.code, TaskErrorCode::StateCorrupt);
            }
            Exit::Unwind => {
                let unwound = std::panic::catch_unwind(move || {
                    let _owner = owner;
                    panic!("test operation unwinds while owning its lease");
                });
                assert!(unwound.is_err());
            }
        }
        old_child.assert_holds(binding);
        fixture.unchanged(binding);
        // R1: logical operation ended. An unrelated inherited descriptor must
        // not retain the short-lived private owner's exclusive authority.
        let new_owner = fixture.acquire(false).unwrap_or_else(|failure| {
            panic!("R1: owner ended but live inherited child retains lease: {failure:?}")
        });
        assert_eq!(new_owner.binding().unwrap(), binding);
        fixture.unchanged(binding);
        old_child.assert_holds(binding);
        assert_busy(fixture.acquire(false));
        fixture.unchanged(binding);
        // R2: closing the old child's OFD cannot unlock the new independent
        // owner. Its original fixed inode and exclusivity remain intact.
        old_child.stop();
        assert_busy(fixture.acquire(false));
        fixture.unchanged(binding);
        new_owner.check(&fixture.root).unwrap();
        drop(new_owner);
        let final_owner = fixture.acquire(false).unwrap();
        assert_eq!(final_owner.binding().unwrap(), binding);
        fixture.unchanged(binding);
    }

    #[test]
    fn r1_normal_drop_releases_private_owner_while_inherited_child_lives() {
        release_on_exit(Exit::Normal, false);
    }
    #[test]
    fn r1_error_return_releases_private_owner_while_inherited_child_lives() {
        release_on_exit(Exit::Error, false);
    }
    #[test]
    fn r1_unwind_releases_private_owner_while_inherited_child_lives() {
        release_on_exit(Exit::Unwind, false);
    }

    #[test]
    fn r1_existing_nonempty_normal_drop_releases_owner_while_inherited_child_lives() {
        release_on_exit(Exit::Normal, true);
    }
    #[test]
    fn r1_existing_nonempty_error_return_releases_owner_while_inherited_child_lives() {
        release_on_exit(Exit::Error, true);
    }
    #[test]
    fn r1_existing_nonempty_unwind_releases_owner_while_inherited_child_lives() {
        release_on_exit(Exit::Unwind, true);
    }

    #[test]
    fn r2_failed_acquire_preserves_independently_owned_external_lock() {
        let fixture = Fixture::new();
        drop(fixture.acquire(true).unwrap());
        let raw_owner = File::open(&fixture.path).unwrap();
        nexus_platform_linux::file_lease::try_lock_exclusive(&raw_owner).unwrap();
        let binding = identity(&raw_owner.metadata().unwrap());
        let mut child = OwnedChild::inheriting(&raw_owner);
        // Only the external child owns the generic lock now, independently
        // of every failed private guard construction below.
        drop(raw_owner);
        for create in [false, true] {
            assert_busy(fixture.acquire(create));
            child.assert_holds(binding);
            assert_raw_busy(&fixture.path);
        }
        fixture.unchanged(binding);
        child.stop();
        let owner = fixture.acquire(false).unwrap();
        assert_eq!(owner.binding().unwrap(), binding);
    }

    #[test]
    fn r2_generic_file_clone_retains_lock_until_last_descriptor_closes() {
        let fixture = Fixture::new();
        drop(fixture.acquire(true).unwrap());
        let raw_owner = File::open(&fixture.path).unwrap();
        nexus_platform_linux::file_lease::try_lock_exclusive(&raw_owner).unwrap();
        let binding = identity(&raw_owner.metadata().unwrap());
        let clone = raw_owner.try_clone().unwrap();
        let mut child = OwnedChild::inheriting(&clone);
        drop(raw_owner);
        assert_raw_busy(&fixture.path);
        drop(clone);
        child.assert_holds(binding);
        assert_raw_busy(&fixture.path);
        child.stop();
        let fresh = File::open(&fixture.path).unwrap();
        nexus_platform_linux::file_lease::try_lock_exclusive(&fresh).unwrap();
        assert_raw_busy(&fixture.path);
        fixture.unchanged(binding);
    }

    #[test]
    fn r2_existing_file_create_failure_allows_immediate_reacquire() {
        let fixture = Fixture::new();
        let owner = fixture.acquire(true).unwrap();
        let binding = owner.binding().unwrap();
        drop(owner);
        // The AlreadyExists branch can acquire the raw flock, then return
        // retryable Err before constructing Lease. This checks its ordinary
        // return path, not the uninstrumented transient inheritance window.
        assert_busy(fixture.acquire(true));
        let next = fixture.acquire(false).unwrap();
        assert_eq!(next.binding().unwrap(), binding);
        fixture.unchanged(binding);
    }

    #[test]
    fn r2_owned_child_drop_kills_and_reaps_during_panic() {
        let fixture = Fixture::new();
        let owner = fixture.acquire(true).unwrap();
        let child = OwnedChild::inheriting(&owner.file);
        let pid = child.child.id();
        let unwound = std::panic::catch_unwind(move || {
            let _child = child;
            panic!("verify child cleanup on assertion unwind");
        });
        assert!(unwound.is_err());
        assert!(!PathBuf::from(format!("/proc/{pid}")).exists());
        assert_busy(fixture.acquire(false));
        drop(owner);
        assert!(fixture.acquire(false).is_ok());
    }
}

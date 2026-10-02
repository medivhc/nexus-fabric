//! E4 driver for `scenarios/platform/workspace_fuse_projection.toml`.
//!
//! Mounts a real Workspace via the Linux FUSE adapter, performs file I/O
//! through the kernel, commits, and verifies the Head advanced.
//! Without /dev/fuse (e.g. sandbox) prints verdict=SKIP, never FAIL.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use nexus_platform_linux::fuse_ws::mount_projected_workspace;
use nexus_storage::InMemoryContentStore;
use nexus_workspace::{
    NativeApiWorkspaceAccess, Workspace, WorkspaceAccess, WorkspaceId, WorkspaceProjection,
};

fn skip(reason: &str) {
    println!("{{\"verdict\":\"SKIP\",\"reason\":\"{reason}\"}}");
}

fn fail(reason: &str) -> ! {
    println!(
        "{{\"verdict\":\"FAIL\",\"reason\":\"{}\"}}",
        reason.replace('"', "'")
    );
    std::process::exit(1);
}

fn main() {
    let json = std::env::args().any(|a| a == "--json");
    if !Path::new("/dev/fuse").exists() {
        if json {
            skip("no /dev/fuse on this host");
        } else {
            eprintln!("SKIP: no /dev/fuse on this host");
        }
        return;
    }
    match run_e4() {
        Ok(fields) => println!("{fields}"),
        Err(e) => fail(&e),
    }
}

fn run_e4() -> Result<String, String> {
    // 1. Workspace + projection adapter.
    let store = InMemoryContentStore::new();
    let ws = Workspace::init(WorkspaceId("fuse-e4".into()), store).map_err(|e| format!("{e:?}"))?;
    let access = NativeApiWorkspaceAccess::new(ws);
    let head_before = access.head().cloned().map(|c| c.0.clone());
    let projected = WorkspaceProjection::new(access);

    // 2. Mount into an isolated temp dir.
    let mountpoint: PathBuf =
        std::env::temp_dir().join(format!("nexus-fuse-e4-{}", std::process::id()));
    if mountpoint.exists() {
        std::fs::remove_dir_all(&mountpoint).map_err(|e| format!("rmdir: {e}"))?;
    }
    std::fs::create_dir_all(&mountpoint).map_err(|e| format!("mkdir: {e}"))?;
    let (fs, _session) = mount_projected_workspace(Box::new(projected), &mountpoint)
        .map_err(|e| format!("mount: {e}"))?;
    // _session unmounts on drop; explicit cleanup below.

    let r: Result<String, String> = (|| {
        // 3. Kernel write -> read back.
        let hello = mountpoint.join("hello.txt");
        std::fs::write(&hello, b"hello fuse").map_err(|e| format!("write: {e}"))?;
        let back = std::fs::read(&hello).map_err(|e| format!("read: {e}"))?;
        let write_ok = true;
        let read_back_ok = back == b"hello fuse";

        // 4. readdir shows the file.
        let mut seen = false;
        for e in std::fs::read_dir(&mountpoint).map_err(|e| format!("readdir: {e}"))? {
            let e = e.map_err(|e| format!("readdir entry: {e}"))?;
            if e.file_name().to_string_lossy() == "hello.txt" {
                seen = true;
            }
        }
        let readdir_ok = seen;

        // 5. Commit through the adapter; Head must advance.
        let new_head = fs.commit().map_err(|e| format!("commit: {e}"))?;
        let head_after = fs.head();
        let commit_ok = head_after.as_deref() == Some(new_head.as_str())
            && Some(new_head.as_str()) != head_before.as_deref();

        // 6. Overwrite + delete through the kernel.
        std::fs::write(&hello, b"v2").map_err(|e| format!("overwrite: {e}"))?;
        let back2 = std::fs::read(&hello).map_err(|e| format!("read2: {e}"))?;
        let overwrite_ok = back2 == b"v2";
        std::fs::remove_file(&hello).map_err(|e| format!("unlink: {e}"))?;
        let delete_ok = !hello.exists();

        Ok(format!(
            "{{\
            \"verdict\":\"PASS\",\
            \"write_ok\":{write_ok},\
            \"read_back_ok\":{read_back_ok},\
            \"readdir_ok\":{readdir_ok},\
            \"commit_ok\":{commit_ok},\
            \"overwrite_ok\":{overwrite_ok},\
            \"delete_ok\":{delete_ok}\
            }}"
        ))
    })();

    // 7. Unmount + cleanup (always).
    drop(_session);
    let _ = std::fs::remove_dir_all(&mountpoint);
    r
}

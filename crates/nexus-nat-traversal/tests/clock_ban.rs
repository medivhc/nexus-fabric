use std::fs;
use std::path::{Path, PathBuf};

// Scanned in-process rather than via an external `rg`, so the gate does not
// depend on tools installed on the host (CI runners ship without ripgrep).
const BANNED: &[&str] = &["SystemTime", "Instant::now", "thread::sleep", "std::thread"];

// Every regular file under `src`, not only `.rs`, so the scan stays a superset
// of the old `rg` run; like rg, symlinks are not followed.
fn source_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        let meta =
            fs::symlink_metadata(&path).unwrap_or_else(|e| panic!("stat {}: {e}", path.display()));
        if meta.is_dir() {
            source_files(&path, out);
        } else if meta.is_file() {
            out.push(path);
        }
    }
}

#[test]
fn g5_no_system_time_in_core() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    source_files(&src, &mut files);
    assert!(
        !files.is_empty(),
        "no source files found under {}",
        src.display()
    );

    let mut hits = String::new();
    for file in &files {
        let bytes = fs::read(file).unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
        for (idx, line) in String::from_utf8_lossy(&bytes).lines().enumerate() {
            if BANNED.iter().any(|pat| line.contains(pat)) {
                hits.push_str(&format!("{}:{}:{line}\n", file.display(), idx + 1));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "protocol core must not read system time or sleep:\n{hits}"
    );
}

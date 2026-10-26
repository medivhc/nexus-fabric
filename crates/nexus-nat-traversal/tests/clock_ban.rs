use std::fs;
use std::path::{Path, PathBuf};

// Scanned in-process rather than via an external `rg`, so the gate does not
// depend on tools installed on the host (CI runners ship without ripgrep).
const BANNED: &[&str] = &["SystemTime", "Instant::now", "thread::sleep", "std::thread"];

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn g5_no_system_time_in_core() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_sources(&src, &mut files);
    assert!(
        !files.is_empty(),
        "no Rust sources found under {}",
        src.display()
    );

    let mut hits = String::new();
    for file in &files {
        let text =
            fs::read_to_string(file).unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
        for (idx, line) in text.lines().enumerate() {
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

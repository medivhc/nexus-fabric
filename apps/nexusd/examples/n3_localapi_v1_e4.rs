//! Independent real-daemon protocol boundary observer; no Task state machine.
#[path = "../test_support/n3_localapi.rs"]
mod support;
fn main() {
    let result = (|| {
        let executable = std::env::current_exe().map_err(|e| e.to_string())?;
        let directory = executable
            .parent()
            .and_then(std::path::Path::parent)
            .ok_or("missing target directory")?;
        let binary = directory.join(if cfg!(windows) {
            "nexusd.exe"
        } else {
            "nexusd"
        });
        if !binary.is_file() {
            let status = std::process::Command::new("cargo")
                .args([
                    "build", "--locked", "--quiet", "-p", "nexusd", "--bin", "nexusd",
                ])
                .status()
                .map_err(|e| e.to_string())?;
            if !status.success() {
                return Err("daemon build failed".into());
            }
        }
        Ok::<_, String>(support::boundary(&binary))
    })()
    .unwrap_or_else(|reason| serde_json::json!({"verdict":"FAIL","reason":reason}));
    println!("{result}");
    if result["verdict"] != "PASS" {
        std::process::exit(1);
    }
}

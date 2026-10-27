//! Gate-level regression tests for scenario discovery failures.
//! Expectations: docs/e2e-test-system-contract.md §§2, 4, 4b;
//! AGENTS.md requires failed verification inputs to remain observable.

use crate::config::{Config, VerifyTimeouts};
use crate::gates::Gate;
use crate::scenario::{ScenarioResult, run_gate};
use serde_json::json;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        loop {
            let path = std::env::temp_dir().join(format!(
                "nexus-harness-load-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("create private fixture: {e}"),
            }
        }
    }

    fn write(&self, relative: &str, bytes: impl AsRef<[u8]>) {
        let path = self.0.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    fn run(&self, subdirs: &[&str]) -> (Vec<ScenarioResult>, Gate) {
        let config = Config {
            policies_dir: self.0.join("policies"),
            scenarios_dir: self.0.clone(),
            evidence_dir: self.0.join("evidence"),
            crates_dir: self.0.join("crates"),
            engineering_dir: self.0.join("engineering"),
            quality: json!({}),
            portable_core: Vec::new(),
            bind_working_tree_digest: true,
            verify_timeouts: VerifyTimeouts::defaults(),
        };
        run_gate(
            &config,
            "product-scenarios",
            subdirs,
            None,
            &config.verify_timeouts.scenarios,
        )
    }

    fn assert_failed_file(&self, filename: &str) {
        let (_, gate) = self.run(&["product"]);
        assert_eq!(gate.verdict, "FAIL", "{}", gate.detail);
        assert!(gate.detail.contains(filename), "{}", gate.detail);
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const VALID_STATIC: &str = "schema_version = 1\nid = 'product.valid'\n";

#[test]
fn malformed_only_pack_is_failed_instead_of_empty_pass() {
    let f = Fixture::new();
    f.write("product/broken.toml", "schema_version = [\n");
    f.assert_failed_file("broken.toml");
}

#[test]
fn malformed_file_cannot_hide_behind_a_valid_scenario() {
    let f = Fixture::new();
    f.write("product/valid.toml", VALID_STATIC);
    f.write("product/broken.toml", "schema_version = [\n");
    f.assert_failed_file("broken.toml");
}

#[test]
fn invalid_schema_versions_make_the_gate_fail() {
    for header in [
        "",
        "schema_version = 0\n",
        "schema_version = 2\n",
        "schema_version = '1'\n",
    ] {
        let f = Fixture::new();
        f.write(
            "product/schema.toml",
            format!("{header}id = 'product.invalid'\n"),
        );
        f.assert_failed_file("schema.toml");
    }
}

#[test]
fn invalid_required_ids_make_the_gate_fail() {
    for id in ["", "id = 1\n"] {
        let f = Fixture::new();
        f.write("product/id.toml", format!("schema_version = 1\n{id}"));
        f.assert_failed_file("id.toml");
    }
}

#[test]
fn unreadable_utf8_scenario_is_a_gate_failure() {
    let f = Fixture::new();
    f.write("product/encoding.toml", [0xff, 0xfe]);
    f.assert_failed_file("encoding.toml");
}

#[test]
fn existing_selected_directory_read_failure_is_not_an_empty_pack() {
    let f = Fixture::new();
    f.write("product", "this selected directory is actually a file");
    let (_, gate) = f.run(&["product"]);
    assert_eq!(gate.verdict, "FAIL", "{}", gate.detail);
    assert!(gate.detail.contains("product"), "{}", gate.detail);
}

#[test]
fn valid_static_scenario_keeps_its_declared_unknown_result() {
    let f = Fixture::new();
    f.write("product/valid.toml", VALID_STATIC);
    let (results, gate) = f.run(&["product"]);
    assert_eq!(gate.verdict, "PASS", "{}", gate.detail);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, "product.valid");
    assert_eq!(results[0].verdict, "UNKNOWN");
}

#[test]
fn empty_and_absent_optional_directories_are_explicitly_unknown() {
    let f = Fixture::new();
    std::fs::create_dir(f.0.join("product")).unwrap();
    for subdirs in [&["product"][..], &["regression"][..]] {
        let (results, gate) = f.run(subdirs);
        assert_eq!(gate.verdict, "UNKNOWN", "{}", gate.detail);
        assert!(results.is_empty());
        assert!(!gate.detail.is_empty());
    }
}

#[test]
fn unrelated_files_and_unselected_subdirectories_do_not_fail_the_pack() {
    let f = Fixture::new();
    f.write("product/valid.toml", VALID_STATIC);
    f.write("product/README.md", "invalid TOML [");
    f.write("engineering/broken.toml", "invalid TOML [");
    let (results, gate) = f.run(&["product"]);
    assert_eq!(gate.verdict, "PASS", "{}", gate.detail);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, "product.valid");
}

#[test]
fn every_rejected_file_is_named_in_the_gate_diagnostic() {
    let f = Fixture::new();
    f.write("product/z-last.toml", "schema_version = [\n");
    f.write(
        "product/a-first.toml",
        "schema_version = 2\nid = 'product.invalid'\n",
    );
    let (_, gate) = f.run(&["product"]);
    assert_eq!(gate.verdict, "FAIL", "{}", gate.detail);
    for filename in ["a-first.toml", "z-last.toml"] {
        assert!(gate.detail.contains(filename), "{}", gate.detail);
    }
}

#[test]
fn rejected_inputs_in_any_selected_subdirectory_fail_the_whole_pack() {
    for (invalid, valid) in [("product", "regression"), ("regression", "product")] {
        let f = Fixture::new();
        f.write(
            &format!("{valid}/valid.toml"),
            format!("schema_version = 1\nid = '{valid}.valid'\n"),
        );
        f.write(&format!("{invalid}/broken.toml"), "schema_version = [\n");
        let (_, gate) = f.run(&["product", "regression"]);
        assert_eq!(gate.verdict, "FAIL", "{}", gate.detail);
        assert!(gate.detail.contains("broken.toml"), "{}", gate.detail);
        assert!(gate.detail.contains(invalid), "{}", gate.detail);
    }
}

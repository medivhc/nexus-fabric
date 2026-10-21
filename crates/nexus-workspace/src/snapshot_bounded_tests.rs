//! N3-12 contract §§1–2: tests use real Workspace commits and a separately
//! checked hash oracle. The production API is an intentionally failing stub.
use super::{SnapshotFile, SnapshotLimits, SnapshotSelection};
use crate::{
    AuthorId, Change, CommitId, NativeApiWorkspaceAccess, Workspace, WorkspaceAccess, WorkspaceId,
};
use nexus_domain::task::{Sha256Digest, TaskError, TaskErrorCode};
use nexus_storage::{
    ContentStore, InMemoryContentStore, ObjectId, object_id_of,
    strong::{StrongContentStore, verify_content},
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

#[derive(Clone, Default, Debug)]
struct Source {
    inner: Arc<Mutex<InMemoryContentStore>>,
    puts: Arc<Mutex<usize>>,
    overrides: Arc<Mutex<BTreeMap<ObjectId, Option<Vec<u8>>>>>,
}
impl ContentStore for Source {
    fn contains(&self, id: &ObjectId) -> Result<bool, String> {
        self.inner.lock().unwrap().contains(id)
    }
    fn get(&self, id: &ObjectId) -> Result<Option<Vec<u8>>, String> {
        if let Some(bytes) = self.overrides.lock().unwrap().get(id) {
            return Ok(bytes.clone());
        }
        self.inner.lock().unwrap().get(id)
    }
    fn put(&mut self, bytes: &[u8]) -> Result<ObjectId, String> {
        *self.puts.lock().unwrap() += 1;
        self.inner.lock().unwrap().put(bytes)
    }
    fn object_ids(&self) -> Result<Vec<ObjectId>, String> {
        self.inner.lock().unwrap().object_ids()
    }
}
#[derive(Default)]
struct Target {
    put_calls: usize,
    objects: BTreeMap<Sha256Digest, Vec<u8>>,
}
impl StrongContentStore for Target {
    fn get_verified(&self, digest: &Sha256Digest, size: u64) -> Result<Vec<u8>, TaskError> {
        let bytes = self.objects.get(digest).ok_or_else(|| {
            TaskError::new(
                TaskErrorCode::InputUnavailable,
                "absent test target object",
                false,
            )
        })?;
        verify_content(digest, size, bytes, sha256)?;
        Ok(bytes.clone())
    }
    fn put_verified(&mut self, digest: &Sha256Digest, bytes: &[u8]) -> Result<(), TaskError> {
        self.put_calls += 1;
        verify_content(digest, bytes.len() as u64, bytes, sha256)?;
        self.objects.insert(digest.clone(), bytes.to_vec());
        Ok(())
    }
}
fn selection() -> SnapshotSelection {
    SnapshotSelection {
        include: vec![".".into()],
        exclude: vec![],
        executable: vec![],
    }
}
fn limits() -> SnapshotLimits {
    SnapshotLimits {
        max_files: 1024,
        max_total_bytes: 67_108_864,
        max_manifest_bytes: 65_536,
    }
}
fn fixture(files: &[(&str, &[u8])]) -> (Workspace<Source>, CommitId, Source) {
    let source = Source::default();
    let mut ws = Workspace::init(
        WorkspaceId("bounded-workspace".into()),
        source.clone(),
        AuthorId("test-author".into()),
    )
    .unwrap();
    let parent = ws.heads().heads[0].clone();
    let commit = ws
        .commit_changes(
            &parent,
            &files
                .iter()
                .map(|(path, bytes)| Change {
                    path: (*path).into(),
                    content: bytes.to_vec(),
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();
    (ws, commit, source)
}
fn assert_source_unchanged(source: &Source, before_puts: usize, before_ids: Vec<ObjectId>) {
    assert_eq!(
        *source.puts.lock().unwrap(),
        before_puts,
        "freeze must not write requester CAS"
    );
    let mut current = source.object_ids().unwrap();
    current.sort();
    let mut before = before_ids;
    before.sort();
    assert_eq!(
        current, before,
        "freeze must not create or remove source objects"
    );
}
fn assert_target_untouched(target: &Target) {
    assert_eq!(
        target.put_calls, 0,
        "full admission must precede every target put"
    );
    assert!(
        target.objects.is_empty(),
        "rejected freeze leaves target empty"
    );
}
fn expect_code(result: Result<super::FrozenSnapshot, TaskError>, code: TaskErrorCode) {
    assert_eq!(result.expect_err("contract requires rejection").code, code);
}

#[test]
fn bounded_freeze_exact_byte_file_and_utf8_manifest_limits_succeed() {
    let (ws, commit, source) = fixture(&[("é.txt", b"abc")]);
    let expected_manifest = format!(
        "[{{\"executable\":false,\"path\":\"é.txt\",\"sha256\":\"{}\",\"size_bytes\":3}}]",
        sha256(b"abc").as_str()
    )
    .into_bytes();
    let before_puts = *source.puts.lock().unwrap();
    let before_ids = source.object_ids().unwrap();
    let mut target = Target::default();
    let frozen = ws
        .freeze_snapshot_bounded(
            &commit,
            &selection(),
            &mut target,
            sha256,
            SnapshotLimits {
                max_files: 1,
                max_total_bytes: 3,
                max_manifest_bytes: expected_manifest.len(),
            },
        )
        .expect("exact limits must be inclusive");
    assert_eq!(
        frozen.files,
        vec![SnapshotFile {
            path: "é.txt".into(),
            sha256: sha256(b"abc"),
            size_bytes: 3,
            executable: false
        }]
    );
    assert_eq!(frozen.reference.commit_id, commit.0);
    assert_eq!(frozen.reference.file_count, 1);
    assert_eq!(frozen.reference.total_bytes, 3);
    assert_eq!(frozen.reference.manifest_sha256, sha256(&expected_manifest));
    assert_eq!(target.get_verified(&sha256(b"abc"), 3).unwrap(), b"abc");
    assert_eq!(
        target
            .get_verified(&sha256(&expected_manifest), expected_manifest.len() as u64)
            .unwrap(),
        expected_manifest
    );
    frozen.validate(sha256).unwrap();
    assert_source_unchanged(&source, before_puts, before_ids);
}

#[test]
fn bounded_freeze_aggregate_one_byte_over_budget_rejects_before_target_write() {
    let (ws, commit, _) = fixture(&[("a", b"ab"), ("b", b"cd")]);
    let mut target = Target::default();
    expect_code(
        ws.freeze_snapshot_bounded(
            &commit,
            &selection(),
            &mut target,
            sha256,
            SnapshotLimits {
                max_total_bytes: 3,
                ..limits()
            },
        ),
        TaskErrorCode::CapacityUnavailable,
    );
    assert_target_untouched(&target);
}

#[test]
fn bounded_freeze_single_blob_one_byte_over_budget_rejects() {
    let (ws, commit, _) = fixture(&[("a", b"abcd")]);
    let mut target = Target::default();
    expect_code(
        ws.freeze_snapshot_bounded(
            &commit,
            &selection(),
            &mut target,
            sha256,
            SnapshotLimits {
                max_total_bytes: 3,
                ..limits()
            },
        ),
        TaskErrorCode::CapacityUnavailable,
    );
    assert_target_untouched(&target);
}

#[test]
fn bounded_freeze_manifest_cap_counts_utf8_bytes_instead_of_characters() {
    let (ws, commit, _) = fixture(&[("é.txt", b"abc")]);
    let manifest = format!(
        "[{{\"executable\":false,\"path\":\"é.txt\",\"sha256\":\"{}\",\"size_bytes\":3}}]",
        sha256(b"abc").as_str()
    );
    assert!(manifest.len() > manifest.chars().count());
    let mut target = Target::default();
    expect_code(
        ws.freeze_snapshot_bounded(
            &commit,
            &selection(),
            &mut target,
            sha256,
            SnapshotLimits {
                max_manifest_bytes: manifest.len() - 1,
                ..limits()
            },
        ),
        TaskErrorCode::CapacityUnavailable,
    );
    assert_target_untouched(&target);
}

#[test]
fn bounded_freeze_1024_file_limit_is_inclusive_and_1025_fails() {
    let names: Vec<_> = (0..1025).map(|i| format!("f{i:04}")).collect();
    let files: Vec<_> = names
        .iter()
        .map(|name| (name.as_str(), b"".as_slice()))
        .collect();
    let (ws, commit, _) = fixture(&files);
    // The portable API accepts caller limits; this isolates the independent
    // file-count cap from the CLI adapter's smaller canonical manifest cap.
    let roomy = SnapshotLimits {
        max_total_bytes: 0,
        max_manifest_bytes: 1_048_576,
        ..limits()
    };
    let selected = SnapshotSelection {
        exclude: vec!["f1024".into()],
        ..selection()
    };
    let frozen = ws
        .freeze_snapshot_bounded(&commit, &selected, &mut Target::default(), sha256, roomy)
        .expect("1024 files allowed with adequate manifest budget");
    assert_eq!(frozen.reference.file_count, 1024);
    assert_eq!(frozen.reference.total_bytes, 0);
    let mut larger_target = Target::default();
    let larger = ws
        .freeze_snapshot_bounded(
            &commit,
            &selection(),
            &mut larger_target,
            sha256,
            SnapshotLimits {
                max_files: 1025,
                ..roomy
            },
        )
        .expect("portable caller-provided limit may exceed CLI's 1024 cap");
    assert_eq!(larger.reference.file_count, 1025);
    assert_eq!(larger.files.len(), 1025);
    assert_eq!(larger.reference.total_bytes, 0);
    larger.validate(sha256).unwrap();
    let mut target = Target::default();
    expect_code(
        ws.freeze_snapshot_bounded(&commit, &selection(), &mut target, sha256, roomy),
        TaskErrorCode::CapacityUnavailable,
    );
    assert_target_untouched(&target);
}

#[test]
fn bounded_freeze_empty_selected_manifest_obeys_metadata_limit() {
    let (ws, commit, _) = fixture(&[("a", b"abc")]);
    let selected = SnapshotSelection {
        exclude: vec![".".into()],
        ..selection()
    };
    let empty_limits = SnapshotLimits {
        max_files: 0,
        max_total_bytes: 0,
        max_manifest_bytes: 2,
    };
    let mut target = Target::default();
    let frozen = ws
        .freeze_snapshot_bounded(&commit, &selected, &mut target, sha256, empty_limits)
        .expect("empty selected set is a valid explicit freeze");
    assert!(frozen.files.is_empty());
    assert_eq!(frozen.reference.total_bytes, 0);
    assert_eq!(frozen.reference.manifest_sha256, sha256(b"[]"));
    assert_eq!(target.get_verified(&sha256(b"[]"), 2).unwrap(), b"[]");
    let mut rejected_target = Target::default();
    expect_code(
        ws.freeze_snapshot_bounded(
            &commit,
            &selected,
            &mut rejected_target,
            sha256,
            SnapshotLimits {
                max_manifest_bytes: 1,
                ..empty_limits
            },
        ),
        TaskErrorCode::CapacityUnavailable,
    );
    assert_target_untouched(&rejected_target);
}

#[test]
fn bounded_freeze_explicit_old_commit_ignores_new_head_and_uncommitted_working_set() {
    let (mut ws, old, source) = fixture(&[("input", b"original")]);
    let new = ws
        .commit_changes(
            &old,
            &[Change {
                path: "input".into(),
                content: b"new-head".to_vec(),
            }],
        )
        .unwrap();
    assert_ne!(old, new);
    let mut access = NativeApiWorkspaceAccess::new(ws);
    access.write_file("input", b"uncommitted-decoy").unwrap();
    let ws = access.into_workspace();
    let before_puts = *source.puts.lock().unwrap();
    let before_ids = source.object_ids().unwrap();
    let head_before = ws.heads().clone();
    let state_before = ws.state_root().clone();
    let mut target = Target::default();
    let frozen = ws
        .freeze_snapshot_bounded(&old, &selection(), &mut target, sha256, limits())
        .unwrap();
    assert_eq!(frozen.reference.commit_id, old.0);
    assert_eq!(
        target.get_verified(&frozen.files[0].sha256, 8).unwrap(),
        b"original"
    );
    assert_eq!(*ws.heads(), head_before);
    assert_eq!(*ws.state_root(), state_before);
    assert_source_unchanged(&source, before_puts, before_ids);
}

#[test]
fn bounded_freeze_unknown_explicit_commit_never_falls_back_to_head() {
    let (ws, _, source) = fixture(&[("a", b"abc")]);
    let before_puts = *source.puts.lock().unwrap();
    let before_ids = source.object_ids().unwrap();
    let mut target = Target::default();
    expect_code(
        ws.freeze_snapshot_bounded(
            &CommitId("0123456789abcdef".into()),
            &selection(),
            &mut target,
            sha256,
            limits(),
        ),
        TaskErrorCode::InputUnavailable,
    );
    assert_target_untouched(&target);
    assert_source_unchanged(&source, before_puts, before_ids);
}

#[test]
fn bounded_freeze_invalid_selection_and_unmatched_include_are_not_silent_omissions() {
    let (ws, commit, _) = fixture(&[("a", b"abc")]);
    for selected in [
        SnapshotSelection {
            include: vec![],
            ..selection()
        },
        SnapshotSelection {
            include: vec!["../a".into()],
            ..selection()
        },
        SnapshotSelection {
            include: vec!["a".into(), "a".into()],
            ..selection()
        },
        SnapshotSelection {
            executable: vec!["missing".into()],
            ..selection()
        },
    ] {
        let mut target = Target::default();
        let error = ws
            .freeze_snapshot_bounded(&commit, &selected, &mut target, sha256, limits())
            .expect_err("invalid selection rejected");
        assert!(matches!(
            error.code,
            TaskErrorCode::InvalidRequest | TaskErrorCode::InvalidPath
        ));
        assert_target_untouched(&target);
    }
    for include in [vec!["missing".into()], vec!["a".into(), "missing".into()]] {
        let mut target = Target::default();
        expect_code(
            ws.freeze_snapshot_bounded(
                &commit,
                &SnapshotSelection {
                    include,
                    ..selection()
                },
                &mut target,
                sha256,
                limits(),
            ),
            TaskErrorCode::InputUnavailable,
        );
        assert_target_untouched(&target);
    }
}

#[test]
fn bounded_freeze_file_directory_collision_is_rejected() {
    let (ws, commit, _) = fixture(&[("node", b"a"), ("node/child", b"b")]);
    let mut target = Target::default();
    expect_code(
        ws.freeze_snapshot_bounded(&commit, &selection(), &mut target, sha256, limits()),
        TaskErrorCode::InvalidPath,
    );
    assert_target_untouched(&target);
}

#[test]
fn bounded_freeze_rechecks_legacy_content_locator() {
    let (ws, commit, source) = fixture(&[("a", b"original")]);
    source
        .overrides
        .lock()
        .unwrap()
        .insert(object_id_of(b"original"), Some(b"tampered".to_vec()));
    let mut target = Target::default();
    expect_code(
        ws.freeze_snapshot_bounded(&commit, &selection(), &mut target, sha256, limits()),
        TaskErrorCode::InputIntegrityFailed,
    );
    assert_target_untouched(&target);
}

#[test]
fn bounded_freeze_rechecks_legacy_manifest_locator() {
    let (ws, commit, source) = fixture(&[("a", b"abc")]);
    let root = ws.commit(&commit).unwrap().root_manifest_id.clone();
    source
        .overrides
        .lock()
        .unwrap()
        .insert(root, Some(b"a\t0000000000000000\n".to_vec()));
    let mut target = Target::default();
    expect_code(
        ws.freeze_snapshot_bounded(&commit, &selection(), &mut target, sha256, limits()),
        TaskErrorCode::InputIntegrityFailed,
    );
    assert_target_untouched(&target);
}

#[test]
fn bounded_freeze_missing_source_manifest_or_blob_is_input_unavailable() {
    for manifest_missing in [true, false] {
        let (ws, commit, source) = fixture(&[("a", b"abc")]);
        let missing = if manifest_missing {
            ws.commit(&commit).unwrap().root_manifest_id.clone()
        } else {
            object_id_of(b"abc")
        };
        source.overrides.lock().unwrap().insert(missing, None);
        let mut target = Target::default();
        expect_code(
            ws.freeze_snapshot_bounded(&commit, &selection(), &mut target, sha256, limits()),
            TaskErrorCode::InputUnavailable,
        );
        assert_target_untouched(&target);
    }
}

#[test]
fn bounded_freeze_duplicate_blob_counts_per_file_and_keeps_executable_selection() {
    let (ws, commit, _) = fixture(&[("a", b"abc"), ("sub/b", b"abc")]);
    let selected = SnapshotSelection {
        executable: vec!["sub/b".into()],
        ..selection()
    };
    let mut target = Target::default();
    let frozen = ws
        .freeze_snapshot_bounded(
            &commit,
            &selected,
            &mut target,
            sha256,
            SnapshotLimits {
                max_total_bytes: 6,
                ..limits()
            },
        )
        .unwrap();
    assert_eq!(
        frozen.reference.total_bytes, 6,
        "logical bytes count both files despite dedup"
    );
    assert_eq!(frozen.reference.file_count, 2);
    assert_eq!(frozen.files[0].path, "a");
    assert!(!frozen.files[0].executable);
    assert_eq!(frozen.files[1].path, "sub/b");
    assert!(frozen.files[1].executable);
    assert_eq!(
        target.objects.len(),
        2,
        "one shared blob and one canonical manifest"
    );
    let mut rejected_target = Target::default();
    expect_code(
        ws.freeze_snapshot_bounded(
            &commit,
            &selected,
            &mut rejected_target,
            sha256,
            SnapshotLimits {
                max_total_bytes: 5,
                ..limits()
            },
        ),
        TaskErrorCode::CapacityUnavailable,
    );
    assert_target_untouched(&rejected_target);
}

#[test]
fn bounded_freeze_does_not_change_existing_unbounded_freeze_abi_or_snapshot_identity() {
    let (ws, commit, _) = fixture(&[("a", b"abc")]);
    let selected = selection();
    let old = ws
        .freeze_snapshot(&commit, &selected, &mut Target::default(), sha256)
        .unwrap();
    let bounded = ws
        .freeze_snapshot_bounded(&commit, &selected, &mut Target::default(), sha256, limits())
        .unwrap();
    assert_eq!(bounded, old, "limits must not enter SnapshotRef identity");
}

// Independent, test-only SHA-256; standard known-answer vectors below guard the
// oracle. No new dependency or production hashing implementation is introduced.
fn sha256(input: &[u8]) -> Sha256Digest {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut bytes = input.to_vec();
    bytes.push(0x80);
    while bytes.len() % 64 != 56 {
        bytes.push(0);
    }
    bytes.extend_from_slice(&((input.len() as u64) * 8).to_be_bytes());
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    for chunk in bytes.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes(word.try_into().unwrap());
        }
        for i in 16..64 {
            let a = w[i - 15];
            let b = w[i - 2];
            w[i] = w[i - 16]
                .wrapping_add(a.rotate_right(7) ^ a.rotate_right(18) ^ (a >> 3))
                .wrapping_add(w[i - 7])
                .wrapping_add(b.rotate_right(17) ^ b.rotate_right(19) ^ (b >> 10));
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for i in 0..64 {
            let t1 = h
                .wrapping_add(e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25))
                .wrapping_add((e & f) ^ (!e & g))
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let t2 = (a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22))
                .wrapping_add((a & b) ^ (a & c) ^ (b & c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }
    let mut result = [0u8; 32];
    for (word, output) in state.iter().zip(result.chunks_exact_mut(4)) {
        output.copy_from_slice(&word.to_be_bytes());
    }
    Sha256Digest::from_bytes(result)
}

#[test]
fn bounded_freeze_test_hash_oracle_matches_standard_sha256_vectors() {
    assert_eq!(
        sha256(b"").as_str(),
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256(b"abc").as_str(),
        "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").as_str(),
        "sha256:248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

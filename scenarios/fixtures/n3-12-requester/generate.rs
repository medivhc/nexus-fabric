use std::{fs, path::PathBuf};
use nexus_storage::{ContentStore, FsContentStore, ObjectId, object_id_of};
use nexus_workspace::{AuthorId, NativeApiWorkspaceAccess, Workspace, WorkspaceAccess, WorkspaceId};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = PathBuf::from(std::env::args().nth(1).ok_or("output required")?);
    if output.exists() { return Err("output exists".into()); }
    fs::create_dir_all(output.join("config/data/workspaces/n312-source"))?;
    let config = output.join("config");
    fs::write(config.join("workspace.toml"), "[[workspace]]\nid = \"n312-source\"\nauthor = \"fixture-author\"\nauto_commit_secs = 0\n")?;
    let store = FsContentStore::open(&config.join("data/cas"))?;
    let ws = Workspace::init(WorkspaceId("n312-source".into()), store, AuthorId("fixture-author".into()))?;
    let genesis = ws.heads().heads[0].clone();
    let mut access = NativeApiWorkspaceAccess::new(ws);
    let payload = (0..98317).map(|i| ((i * 17 + 29) % 251) as u8).collect::<Vec<_>>();
    access.write_file("inputs/data.bin", &payload)?;
    access.write_file("inputs/empty.txt", b"")?;
    access.write_file("scripts/run.sh", b"#!/bin/sh\nprintf 'frozen source\\n'\n")?;
    access.write_file("private/excluded.txt", b"not selected in old commit\n")?;
    let old = access.commit()?;
    let old_anchor = access.state_root().ok_or("old state root missing")?;
    access.write_file("inputs/data.bin", b"changed Head bytes must not become old Commit input\n")?;
    access.write_file("inputs/head-only.txt", b"new Head-only file\n")?;
    let new = access.commit()?;
    let new_anchor = access.state_root().ok_or("new state root missing")?;
    access.write_file("inputs/data.bin", b"uncommitted WorkingSet decoy\n")?;
    assert_eq!(access.read_file("inputs/data.bin")?, b"uncommitted WorkingSet decoy\n");
    let ws = access.into_workspace();
    let old_manifest = ws.commit(&old).ok_or("old missing")?.root_manifest_id.clone();
    let new_manifest = ws.commit(&new).ok_or("new missing")?.root_manifest_id.clone();
    fs::write(config.join("data/workspaces/n312-source/state_root"), &new_anchor)?;
    let mut facts = format!("workspace=n312-source\ngenesis={}\nold_commit={}\nnew_commit={}\nold_state_root={}\nstate_root={}\nold_manifest={}\nnew_manifest={}\n", genesis.0, old.0, new.0, old_anchor, new_anchor, old_manifest.0, new_manifest.0);
    for id in ws.store().object_ids()? {
        let bytes = ws.store().get(&id)?.ok_or("exported object absent")?;
        assert_eq!(object_id_of(&bytes), id);
    }
    // The persistent source is reopened solely through existing Workspace APIs.
    let reopened = Workspace::open(WorkspaceId("n312-source".into()), FsContentStore::open(&config.join("data/cas"))?, &ObjectId(new_anchor.clone()), AuthorId("fixture-author".into()))?;
    assert!(reopened.commit(&old).is_some());
    assert_eq!(reopened.heads().heads, vec![new]);
    facts.push_str("reopen_verified=true\n");
    fs::write(output.join("facts.txt"), facts)?;
    // A physical projection decoy is deliberately outside authoritative CAS.
    fs::create_dir_all(config.join("data/mounts/n312-source/inputs"))?;
    fs::write(config.join("data/mounts/n312-source/inputs/data.bin"), b"physical projection decoy must never be scanned\n")?;
    println!("requester fixture exported: {}", output.display());
    Ok(())
}

#!/usr/bin/env python3
"""Real Cargo fixture for Harness bootstrap. Does not certify product behavior."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

SOURCE = Path(__file__).resolve().parents[2]
HARNESS = Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix='n37 real cargo fixture ') as temp:
    root = Path(temp)
    env = {k:v for k,v in os.environ.items() if not k.startswith('GIT_')}
    env['CARGO_TARGET_DIR'] = str(root / 'custom target')
    env['NEXUS_N3_TEST_CLI_BIN'] = '/nonexistent/stale-cli'
    env['NEXUS_N3_TEST_DAEMON_BIN'] = '/nonexistent/stale-daemon'
    def run(args, check=True):
        return subprocess.run(args, cwd=root, env=env, text=True, capture_output=True, check=check)
    run(['git','init','-q'])
    run(['git','config','user.name','N37 Fixture'])
    run(['git','config','user.email','fixture@example.invalid'])
    shutil.copy(SOURCE/'harness.toml',root/'harness.toml')
    shutil.copytree(SOURCE/'policies',root/'policies')
    (root/'Cargo.toml').write_text('[workspace]\nresolver="2"\nmembers=["apps/nexus","apps/nexusd"]\n')
    for name in ['nexus','nexusd']:
        d=root/'apps'/name
        (d/'src').mkdir(parents=True)
        (d/'Cargo.toml').write_text(f'[package]\nname="{name}"\nversion="0.1.0"\nedition="2024"\n')
        (d/'src/main.rs').write_text('fn main() { println!("v1"); }\n')
    test=root/'apps/nexus/tests/bootstrap.rs'
    test.parent.mkdir()
    test.write_text('''#[test] fn uses_both_current_artifacts() {
        for key in ["NEXUS_N3_TEST_CLI_BIN", "NEXUS_N3_TEST_DAEMON_BIN"] {
            let path = std::env::var_os(key).expect("explicit current artifact");
            let out = std::process::Command::new(path).output().unwrap();
            assert!(out.status.success());
            assert_eq!(String::from_utf8(out.stdout).unwrap().trim(), include_str!("expected.txt").trim());
        }
    }\n''')
    expectation=test.parent/'expected.txt'; expectation.write_text('v1\n')
    run(['git','add','.'])
    run(['git','-c','core.hooksPath=/dev/null','commit','-qm','test: fixture'])
    # Mark nexus affected while keeping its real fixture tests.
    test.write_text(test.read_text()+'// affected\n')
    def gate(label, expected):
        result=run([str(HARNESS),'test','affected','--json'],check=False)
        data=json.loads(result.stdout)
        assert data['verdict']==expected,(label,result.stdout,result.stderr)
        assert (result.returncode==0)==(expected=='PASS')
        print(json.dumps({'case':label,'exit':result.returncode,'result':data}),flush=True)
    assert not (root/'custom target/debug/nexusd').exists()
    gate('clean target, explicit stale caller overrides', 'PASS')
    for name in ['nexus','nexusd']:
        (root/'apps'/name/'src/main.rs').write_text('fn main() { println!("v2"); }\n')
    expectation.write_text('v2\n')
    gate('existing binaries after source change', 'PASS')
    (root/'custom target/debug/nexusd').unlink()
    gate('missing daemon artifact', 'PASS')
    (root/'apps/nexusd/src/main.rs').write_text('compile_error!("forced bootstrap failure");\n')
    gate('prebuild failure blocks tests', 'FAIL')

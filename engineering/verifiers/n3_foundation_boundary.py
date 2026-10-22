"""Observe the real daemon's config-root and limited Task capability boundary."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import queue
import signal
import subprocess
import sys
import tempfile
import threading


def terminate(child):
    """Send a graceful shutdown signal; Windows uses Ctrl+Break so the daemon's
    console handler can run the clean shutdown sequence (exit 0), matching Unix
    SIGTERM semantics. `CREATE_NEW_PROCESS_GROUP` isolates the event."""
    if child.poll() is not None:
        return
    if sys.platform == 'win32':
        child.send_signal(signal.CTRL_BREAK_EVENT)
    else:
        child.send_signal(signal.SIGTERM)


def popen_kwargs():
    """Windows needs a new process group so Ctrl+Break reaches only the daemon."""
    if sys.platform == 'win32':
        return {'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP}
    return {}


def observe():
    target = Path(os.environ.get('CARGO_TARGET_DIR', 'target')).resolve() / 'debug'
    daemon = Path(os.environ.get('N3_BASELINE_DAEMON', target / 'nexusd'))
    cli = Path(os.environ.get('N3_BASELINE_CLI', target / 'nexus'))
    repository = Path(__file__).resolve().parents[2]
    token = 'a' * 64
    with tempfile.TemporaryDirectory(prefix='n38-foundation-') as temporary:
        base = Path(temporary)
        root, decoy = base / 'config', base / 'decoy'
        for path in (root, decoy):
            path.mkdir(mode=0o700)
        (root / 'daemon.toml').write_text('localapi_addr = "127.0.0.1:0"\n[tun]\nenabled = false\n')
        (root / 'proxy.yaml').write_text('schema_version: 1\nrules:\n  - tag: match\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: direct\noutbounds:\n  - tag: direct\n    kind: direct\n')
        token_path = root / 'localapi.token'
        token_path.write_text(token)
        token_path.chmod(0o600)
        env = dict(os.environ, NEXUS_CONFIG_DIR=str(decoy), NEXUS_LOCALAPI_TOKEN_FILE=str(token_path))
        stderr_path = base / 'daemon.stderr'
        lines = queue.Queue()
        with stderr_path.open('w') as stderr:
            child = subprocess.Popen([str(daemon), str(root)], env=env, stdout=subprocess.PIPE, stderr=stderr, text=True, **popen_kwargs())
            def read_stdout():
                for line in child.stdout:
                    lines.put(line)
            reader = threading.Thread(target=read_stdout)
            reader.start()
            try:
                while True:
                    value = json.loads(lines.get(timeout=15))
                    if value.get('verdict') == 'READY':
                        addr = value['daemon']['localapi']
                        break
                connection = http.client.HTTPConnection(addr, timeout=7)
                try:
                    connection.request('GET', '/localapi/v0/n2/session/list', headers={'Authorization': 'Bearer ' + token})
                    response = connection.getresponse()
                    session_list = json.loads(response.read())
                    status = response.status
                finally:
                    connection.close()
                def command(args):
                    result = subprocess.run([str(cli), '--json', '--addr', addr, *args], env=env, capture_output=True, text=True, timeout=10)
                    return {'exit_code': result.returncode, 'json': json.loads(result.stdout)}
                submit = command(['task', 'submit', '--request', str(repository / 'docs/contracts/n3-submit.example.json')])
                output = base / 'output'
                output.write_bytes(b'preexisting-output')
                before = hashlib.sha256(output.read_bytes()).hexdigest()
                download = command(['artifact', 'get', 'artifact-fixture', '--output', str(output)])
                def unsupported(value):
                    return value['exit_code'] == 0 and value['json'].get('error', {}).get('code') == 'UNSUPPORTED_CAPABILITY'
                facts = {
                    'explicit_root_owns_n2': (root / 'n2').is_dir(),
                    'decoy_untouched': not list(decoy.iterdir()),
                    'n2_route_available': status == 200 and session_list.get('verdict') == 'PASS' and session_list.get('owner') == 'daemon',
                    'submit_unsupported': unsupported(submit),
                    'acceptance_unchanged': not (root / 'data/n3/tasks').exists() and not (decoy / 'data/n3/tasks').exists(),
                    'artifact_unsupported': unsupported(download),
                    'output_unchanged': before == hashlib.sha256(output.read_bytes()).hexdigest(),
                }
                observations = {'http_status': status, 'sessions': session_list, 'submit': submit, 'download': download}
            finally:
                if child.poll() is None:
                    terminate(child)
                try:
                    child.wait(timeout=12)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
                reader.join(timeout=3)
                child.stdout.close()
                if reader.is_alive():
                    raise RuntimeError('daemon stdout reader did not join')
        facts['one_manager'] = stderr_path.read_text().count('N2 SessionManager assembled (') == 1
        facts['shutdown_reaped'] = child.returncode == 0
        return {'verdict': 'PASS' if all(facts.values()) else 'FAIL', **facts, 'observations': observations,
                'scope': 'actual config-folder daemon ownership and capability rejection only; no full Task Submit/execution or download claim'}


if __name__ == '__main__':
    try:
        result = observe()
    except (OSError, ValueError, KeyError, queue.Empty, subprocess.SubprocessError, RuntimeError) as error:
        result = {'verdict': 'FAIL', 'reason': str(error)}
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result['verdict'] == 'PASS' else 1)

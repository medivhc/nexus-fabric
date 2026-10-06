"""Real Engine seed -> ordinary daemon cold boot -> actual Artifact CLI.

Uses only an existing immutable image. No public Submit or cross-node claim.
N3_BASELINE_CLI/N3_BASELINE_DAEMON select old real binaries for the RED probe.
"""
import hashlib
import http.client
import json
import os
from pathlib import Path
import queue
import signal
import socket
import subprocess
import tempfile
import threading
import time


IMAGE = 'sha256:30ecbe1509090b38ef3260f3609d64d8261230464eaa4d235901db496e9647fb'
EXPECTED = bytes(25 * 4096) + b'n39-end\n'


class EngineConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect('/var/run/docker.sock')


def engine(method, path):
    connection = EngineConnection('localhost', timeout=10)
    try:
        connection.request(method, '/v1.45' + path)
        response = connection.getresponse()
        body = response.read(2 * 1024 * 1024 + 1)
        if len(body) > 2 * 1024 * 1024:
            raise RuntimeError('Engine response exceeds bound')
        return response.status, json.loads(body) if body else None
    finally:
        connection.close()


def command(binary, args, env, timeout=12):
    process = subprocess.run([str(binary), *args], env=env, capture_output=True,
                             text=True, timeout=timeout)
    try:
        value = json.loads(process.stdout)
    except ValueError as error:
        raise RuntimeError(f'{binary.name} returned invalid JSON: exit={process.returncode}') from error
    return {'exit_code': process.returncode, 'json': value}


def passed(result):
    return result['exit_code'] == 0 and result['json'].get('verdict') == 'PASS'


def denied(result, code):
    return (result['exit_code'] == 0
            and result['json'].get('error', {}).get('code') == code)


def eof(result, record):
    page = result['json'].get('artifact', {})
    return (passed(result) and page.get('record') == record
            and page.get('offset') == record['size_bytes']
            and page.get('next_offset') == record['size_bytes']
            and page.get('bytes') == [] and page.get('eof') is True)


def identity(path):
    if not path.exists():
        return None
    metadata = path.stat()
    return metadata.st_dev, metadata.st_ino, hashlib.sha256(path.read_bytes()).hexdigest()


def observe():
    target = Path(os.environ.get('CARGO_TARGET_DIR', 'target')).resolve() / 'debug'
    seed = Path(os.environ.get('N3_ARTIFACT_SEED', target / 'examples/n3_artifact_cli_seed'))
    daemon = Path(os.environ.get('N3_BASELINE_DAEMON', target / 'nexusd'))
    cli = Path(os.environ.get('N3_BASELINE_CLI', target / 'nexus'))
    if os.environ.get('NEXUS_N3_TEST_IMAGE_ID') != IMAGE:
        return {'verdict': 'UNKNOWN', 'reason': 'qualified existing NEXUS_N3_TEST_IMAGE_ID required'}
    if not all(path.is_file() for path in (seed, daemon, cli)):
        return {'verdict': 'UNKNOWN', 'reason': 'prebuilt seed, daemon and CLI binaries required'}
    try:
        status, image = engine('GET', '/images/' + IMAGE + '/json')
    except (OSError, http.client.HTTPException, ValueError) as error:
        return {'verdict': 'UNKNOWN', 'reason': 'existing local Engine unavailable: ' + str(error)}
    if status != 200 or image.get('Id') != IMAGE:
        return {'verdict': 'UNKNOWN', 'reason': 'qualified immutable image is not already installed'}
    with tempfile.TemporaryDirectory(prefix='n39-artifact-cli-') as temporary:
        base = Path(temporary)
        root = base / 'config'
        env = dict(os.environ)
        seeded = command(seed, ['--config', str(root)], env, timeout=60)
        if not passed(seeded):
            reason = seeded['json'].get('reason', 'real execution seed failed')
            unavailable = reason.startswith(('UNSUPPORTED_CAPABILITY:', 'ENVIRONMENT_MISMATCH:'))
            return {'verdict': 'UNKNOWN' if unavailable else 'FAIL', 'reason': reason,
                    'observations': {'seed': seeded}}
        seed_value = seeded['json']
        record = seed_value['artifact']
        handle = seed_value['execution_handle'].split(':')
        if len(handle) != 3 or handle[0] != 'docker':
            raise RuntimeError('real seed did not retain its original Docker handle')
        container = handle[1]
        status, actual = engine('GET', '/containers/' + container + '/json')
        real = (status == 200 and actual['Id'] == container
                and actual['Config']['Image'] == IMAGE
                and actual['Config']['Labels']['nexus.task_id'] == seed_value['task_id']
                and actual['Config']['Labels']['nexus.contract_digest'] == seed_value['contract_digest']
                and actual['State']['Running'] is False and actual['State']['Pid'] == 0
                and seed_value['command_start_count'] == 1)
        (root / 'daemon.toml').write_text('localapi_addr = "127.0.0.1:0"\n[tun]\nenabled = false\n')
        (root / 'proxy.yaml').write_text('schema_version: 1\nrules:\n  - tag: match\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: direct\noutbounds:\n  - tag: direct\n    kind: direct\n')
        token_path = root / 'localapi.token'
        token_path.write_text('a' * 64)
        token_path.chmod(0o600)
        env['NEXUS_LOCALAPI_TOKEN_FILE'] = str(token_path)
        env['NEXUS_CONFIG_DIR'] = str(base / 'decoy')
        lines = queue.Queue()
        observations = {'seed': seeded}
        facts = {field: False for field in (
            'real_execution', 'multi_page', 'download_verified', 'final_empty_eof',
            'no_replace', 'current_use_denied', 'authorized_replay', 'shutdown_reaped')}
        facts.update(real_execution=real, multi_page=record['size_bytes'] == len(EXPECTED) > 65536)
        child = None
        reader = None
        stderr_path = base / 'daemon.stderr'
        failure = None
        try:
            with stderr_path.open('w') as stderr:
                child = subprocess.Popen([str(daemon), str(root)], env=env,
                                         stdout=subprocess.PIPE, stderr=stderr, text=True)

                def read_stdout():
                    for line in child.stdout:
                        lines.put(line)
                    lines.put(None)

                reader = threading.Thread(target=read_stdout)
                reader.start()
                observations['daemon_stdout'] = []
                deadline = time.monotonic() + 15
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise RuntimeError('ordinary daemon READY deadline expired')
                    try:
                        line = lines.get(timeout=remaining)
                    except queue.Empty as error:
                        raise RuntimeError('ordinary daemon READY deadline expired') from error
                    if line is None:
                        raise RuntimeError('ordinary daemon closed stdout before READY')
                    observations['daemon_stdout'].append(line[:16384])
                    if len(observations['daemon_stdout']) > 64:
                        raise RuntimeError('ordinary daemon startup stdout exceeded diagnostic bound')
                    ready = json.loads(line)
                    if ready.get('verdict') == 'READY':
                        break
                addr = ready['daemon']['localapi']
                shown = command(cli, ['--json', '--addr', addr, 'task', 'show',
                                      seed_value['task_id']], env)
                observations['task_show'] = shown
                view = shown['json'].get('task', {})
                facts['real_execution'] = (real and passed(shown)
                                           and view.get('task_id') == seed_value['task_id']
                                           and view.get('outcome') == 'Completed'
                                           and view.get('observation') == 'Confirmed'
                                           and view.get('execution', {}).get('exit_code') == 0)

                def download(output):
                    return command(cli, ['--json', '--addr', addr, 'artifact', 'get',
                                         record['artifact_id'], '--output', str(output)], env)

                output = base / 'download'
                result = download(output)
                observations['download'] = result
                original = identity(output)
                facts['download_verified'] = (passed(result) and output.exists()
                                              and output.read_bytes() == EXPECTED
                                              and record['content_sha256'] == 'sha256:' + hashlib.sha256(EXPECTED).hexdigest())
                facts['final_empty_eof'] = eof(result, record)
                existing = base / 'preexisting'
                existing.write_bytes(b'preserve unrelated user output')
                existing_identity = identity(existing)
                result = download(existing)
                observations['no_replace'] = result
                facts['no_replace'] = denied(result, 'OUTPUT_EXISTS') and identity(existing) == existing_identity
                revoke = command(seed, ['revoke', '--config', str(root)], env)
                result = download(output)
                observations['revoked_replay'] = result
                facts['current_use_denied'] = (passed(revoke) and original is not None
                                               and denied(result, 'AUTH_DENIED') and identity(output) == original)
                grant = command(seed, ['grant', '--config', str(root)], env)
                result = download(output)
                observations['authorized_replay'] = result
                facts['authorized_replay'] = (passed(grant) and original is not None
                                              and eof(result, record) and identity(output) == original)
        except (OSError, ValueError, KeyError, TypeError, queue.Empty,
                subprocess.SubprocessError, RuntimeError, http.client.HTTPException) as error:
            failure = str(error)
        finally:
            if child is not None:
                if child.poll() is None:
                    child.send_signal(signal.SIGTERM)
                try:
                    child.wait(timeout=12)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
                if reader is not None:
                    reader.join(timeout=3)
                child.stdout.close()
                facts['shutdown_reaped'] = child.returncode == 0 and not reader.is_alive()
            # Remove only this verifier's already stopped, label-bound container.
            # Never force/remove a running or unrelated object, image or volume.
            facts['owned_container_cleanup'] = False
            try:
                status, stopped = engine('GET', '/containers/' + container + '/json')
                labels = stopped.get('Config', {}).get('Labels', {}) if stopped else {}
                if (status != 200 or stopped['State']['Running'] is not False
                        or stopped['State']['Pid'] != 0
                        or labels.get('nexus.task_id') != seed_value['task_id']
                        or labels.get('nexus.contract_digest') != seed_value['contract_digest']):
                    raise RuntimeError('owned verification container lacks safe stopped cleanup proof')
                status, _ = engine('DELETE', '/containers/' + container)
                if status != 204:
                    raise RuntimeError('owned stopped verification container cleanup failed')
                facts['owned_container_cleanup'] = True
            except (OSError, ValueError, KeyError, RuntimeError, http.client.HTTPException) as error:
                failure = '; '.join(value for value in (failure, str(error)) if value)
            observations['daemon_stderr'] = stderr_path.read_text()[-8192:]
        return {'verdict': 'PASS' if failure is None and all(facts.values()) else 'FAIL', **facts,
                **({'reason': failure} if failure is not None else {}),
                'observations': observations,
                'scope': 'real internal execution and existing Artifact delivery; no public Submit/cross-node/Windows claim'}


if __name__ == '__main__':
    try:
        result = observe()
    except (OSError, ValueError, KeyError, TypeError, queue.Empty, subprocess.SubprocessError,
            RuntimeError, http.client.HTTPException) as error:
        result = {'verdict': 'FAIL', 'reason': str(error)}
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result['verdict'] == 'PASS' else 1)

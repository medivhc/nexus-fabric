"""Real execution and ordinary Artifact delivery under local operator Use grants.

Only initial seed provisioning uses the existing internal SDK. Every subsequent
grant read/change invokes the production CLI; this is not public Submit or
Snapshot import evidence. Baseline binary overrides produce an actual RED when
the old CLI rejects the operator command with usage exit 2.
"""
import hashlib
import http.client
import json
import os
from pathlib import Path
import queue
import signal
import subprocess
import threading
import tempfile
import time
import tomllib

from n3_artifact_cli import IMAGE, EXPECTED, denied, engine, eof, identity, passed


FIELDS = (
    'real_execution', 'scoped_list', 'revoked_download_denied',
    'restored_download', 'expired_download_denied',
    'published_inode_preserved', 'operator_audit', 'shutdown_reaped',
    'owned_container_cleanup',
)


def command(binary, args, env, timeout=12):
    """Retain real usage rejection rather than misclassifying it as bad JSON."""
    result = subprocess.run([str(binary), *args], env=env, capture_output=True,
                            text=True, timeout=timeout)
    if len(result.stdout) > 1024 * 1024 or len(result.stderr) > 1024 * 1024:
        raise RuntimeError('CLI diagnostic exceeds verification bound')
    try:
        value = json.loads(result.stdout)
        if not isinstance(value, dict):
            raise ValueError('response is not an object')
        parsed = True
    except ValueError:
        value, parsed = {}, False
    return {'exit_code': result.returncode, 'json': value,
            'json_response': parsed, 'stdout': result.stdout[-16384:],
            'stderr': result.stderr[-16384:]}


def require_pass(result, operation):
    if not passed(result):
        if result['exit_code'] == 2:
            raise RuntimeError(f'{operation}: actual CLI rejected operator command (usage exit 2)')
        raise RuntimeError(f'{operation}: actual CLI did not return PASS '
                           f'(exit={result["exit_code"]}, JSON={result["json_response"]})')


def selected_grant(result, scope, resource, principal, revoked, not_after):
    value = result['json']
    expected = {'resource': resource, 'principal': principal,
                'operations': ['use'], 'not_after': not_after,
                'revoked': revoked}
    return (passed(result) and value.get('schema_version') == 1
            and value.get('command') == 'task-provider grant list'
            and value.get('scope') == scope
            and value.get('grants') == [expected])


def mutation(result, scope, operation, resource, principal, revoked, not_after):
    value = result['json']
    return (passed(result) and value.get('schema_version') == 1
            and value.get('command') == f'task-provider grant {operation}'
            and value.get('scope') == scope and value.get('operation') == operation
            and value.get('changed') is True
            and value.get('grant') == {
                'resource': resource, 'principal': principal,
                'operations': ['use'], 'not_after': not_after, 'revoked': revoked,
            })


def operator_audit(path, scope, resource, principal, operations):
    if path.is_symlink() or not path.is_file():
        return False, []
    metadata = path.stat()
    if metadata.st_mode & 0o777 != 0o600 or metadata.st_nlink != 1:
        return False, []
    data = path.read_bytes()
    if len(data) > 1024 * 1024 or not data.endswith(b'\n'):
        return False, []
    records = [json.loads(line) for line in data.splitlines()]
    if len(records) != len(operations) * 2:
        return False, records
    fields = {'schema_version', 'mutation_id', 'phase', 'operation', 'scope',
              'resource', 'principal', 'actor', 'changed', 'before_sha256',
              'after_sha256', 'at_unix', 'previous_sha256', 'record_sha256'}
    previous = None
    for record in records:
        if not isinstance(record, dict) or set(record) != fields:
            return False, records
        claimed = record['record_sha256']
        content = {key: value for key, value in record.items() if key != 'record_sha256'}
        actual = 'sha256:' + hashlib.sha256(json.dumps(
            content, ensure_ascii=False, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest()
        if claimed != actual or record['previous_sha256'] != previous:
            return False, records
        previous = claimed
    seen = set()
    prior_grant = None
    for index, operation in enumerate(operations):
        intent, applied = records[index * 2:index * 2 + 2]
        mutation_id = intent.get('mutation_id')
        if not isinstance(mutation_id, str) or not mutation_id or mutation_id in seen:
            return False, records
        seen.add(mutation_id)
        if (intent.get('before_sha256') is None
                or intent.get('before_sha256') == intent.get('after_sha256')
                or (index > 0 and intent['before_sha256'] != prior_grant)):
            return False, records
        prior_grant = intent['after_sha256']
        for record, phase in ((intent, 'intent'), (applied, 'applied')):
            if (record.get('schema_version') != 1 or record.get('phase') != phase
                    or record.get('mutation_id') != mutation_id
                    or record.get('operation') != operation
                    or record.get('scope') != scope
                    or record.get('resource') != resource
                    or record.get('principal') != principal
                    or record.get('actor') != principal
                    or record.get('changed') is not True
                    or record.get('before_sha256') != intent['before_sha256']
                    or record.get('after_sha256') != intent['after_sha256']
                    or type(record.get('at_unix')) is not int
                    or not 0 <= record['at_unix'] <= 9007199254740991):
                return False, records
    return True, records


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

    with tempfile.TemporaryDirectory(prefix='n310-operator-grant-') as temporary:
        base, facts = Path(temporary), dict.fromkeys(FIELDS, False)
        root = base / 'config'
        env = dict(os.environ)
        child = reader = seed_value = container = None
        observations = {}
        failure, unavailable = None, False
        stderr_path = base / 'daemon.stderr'
        # All post-seed inspection/configuration lives inside this cleanup scope.
        try:
            seeded = command(seed, ['--config', str(root)], env, timeout=60)
            observations['seed'] = seeded
            seed_value = seeded['json']
            handle = seed_value.get('execution_handle')
            if isinstance(handle, str):
                parts = handle.split(':')
                if len(parts) == 3 and parts[0] == 'docker':
                    container = parts[1]
            if not passed(seeded):
                reason = seed_value.get('reason', 'real execution seed failed')
                unavailable = reason.startswith(('UNSUPPORTED_CAPABILITY:', 'ENVIRONMENT_MISMATCH:'))
                raise RuntimeError(reason)
            if container is None:
                raise RuntimeError('real seed did not retain its original Docker handle')
            record = seed_value['artifact']
            status, actual = engine('GET', '/containers/' + container + '/json')
            real = (status == 200 and actual['Id'] == container
                    and actual['Config']['Image'] == IMAGE
                    and actual['Config']['Labels']['nexus.task_id'] == seed_value['task_id']
                    and actual['Config']['Labels']['nexus.contract_digest'] == seed_value['contract_digest']
                    and actual['State']['Running'] is False and actual['State']['Pid'] == 0
                    and seed_value['command_start_count'] == 1)
            scope = tomllib.loads((root / 'task-api.toml').read_text())
            if set(scope) != {'provider', 'workspace'}:
                raise RuntimeError('seed task-api scope contains unexpected fields')
            (root / 'daemon.toml').write_text('localapi_addr = "127.0.0.1:0"\n[tun]\nenabled = false\n')
            (root / 'proxy.yaml').write_text('schema_version: 1\nrules:\n  - tag: match\n    kind: match\n    action:\n      - kind: select_outbound\n        tag: direct\noutbounds:\n  - tag: direct\n    kind: direct\n')
            token_path = root / 'localapi.token'
            token_path.write_text('a' * 64)
            token_path.chmod(0o600)
            env['NEXUS_LOCALAPI_TOKEN_FILE'] = str(token_path)
            env['NEXUS_CONFIG_DIR'] = str(base / 'decoy')
            lines = queue.Queue()
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
                    line = lines.get(timeout=remaining)
                    if line is None:
                        raise RuntimeError('ordinary daemon closed stdout before READY')
                    observations['daemon_stdout'].append(line[:16384])
                    if len(observations['daemon_stdout']) > 64:
                        raise RuntimeError('ordinary daemon startup stdout exceeded bound')
                    ready = json.loads(line)
                    if ready.get('verdict') == 'READY':
                        break
                addr = ready['daemon']['localapi']
                shown = command(cli, ['--json', '--addr', addr, 'task', 'show',
                                      seed_value['task_id']], env)
                observations['task_show'] = shown
                view = shown['json'].get('task', {})
                contract = view['accepted_contract']
                principal, request = contract['authenticated_principal'], contract['request']
                resource = request['resource']
                facts['real_execution'] = (real and passed(shown)
                    and view.get('task_id') == seed_value['task_id']
                    and view.get('outcome') == 'Completed'
                    and view.get('observation') == 'Confirmed'
                    and view.get('execution', {}).get('exit_code') == 0
                    and request['provider'] == scope['provider']
                    and request['workspace'] == scope['workspace'])

                def download(output):
                    return command(cli, ['--json', '--addr', addr, 'artifact', 'get',
                        record['artifact_id'], '--output', str(output)], env)

                def grant(operation, expiry=None):
                    args = ['--json', 'task-provider', 'grant', operation,
                            '--config', str(root), '--resource', resource]
                    if operation != 'list':
                        args += ['--self']
                    if expiry is not None:
                        args += ['--not-after', str(expiry)]
                    result = command(cli, args, env)
                    observations.setdefault('operator_commands', []).append(result)
                    require_pass(result, 'task-provider grant ' + operation)
                    return result

                output = base / 'download'
                first = download(output)
                observations['initial_download'] = first
                original = identity(output)
                content_verified = (eof(first, record) and original is not None
                    and output.read_bytes() == EXPECTED
                    and record['content_sha256'] == 'sha256:' + hashlib.sha256(EXPECTED).hexdigest())
                facts['scoped_list'] = selected_grant(
                    grant('list'), scope, resource, principal, False, None)
                revoked = grant('revoke')
                revoked_list = grant('list')
                result = download(output)
                observations['revoked_download'] = result
                facts['revoked_download_denied'] = (
                    mutation(revoked, scope, 'revoke', resource, principal, True, None)
                    and selected_grant(revoked_list, scope, resource, principal, True, None)
                    and denied(result, 'AUTH_DENIED') and identity(output) == original)
                restored = grant('add')
                restored_list = grant('list')
                result = download(output)
                observations['restored_download'] = result
                facts['restored_download'] = (
                    content_verified and mutation(restored, scope, 'add', resource, principal, False, None)
                    and selected_grant(restored_list, scope, resource, principal, False, None)
                    and eof(result, record) and identity(output) == original)
                expired_at = max(1, int(time.time()) - 60)
                expired = grant('add', expired_at)
                expired_list = grant('list')
                result = download(output)
                observations['expired_download'] = result
                facts['expired_download_denied'] = (
                    mutation(expired, scope, 'add', resource, principal, False, expired_at)
                    and selected_grant(expired_list, scope, resource, principal, False, expired_at)
                    and denied(result, 'AUTH_DENIED') and identity(output) == original)
                final_restored = grant('add')
                final_list = grant('list')
                result = download(output)
                observations['final_restored_download'] = result
                facts['restored_download'] = (facts['restored_download']
                    and mutation(final_restored, scope, 'add', resource, principal, False, None)
                    and selected_grant(final_list, scope, resource, principal, False, None)
                    and eof(result, record) and identity(output) == original)
                facts['published_inode_preserved'] = (content_verified
                    and facts['revoked_download_denied'] and facts['restored_download']
                    and facts['expired_download_denied'] and identity(output) == original)
                facts['operator_audit'], observations['operator_audit'] = operator_audit(
                    root / 'n2/task-provider-grant-audit-v1.jsonl', scope,
                    resource, principal, ['revoke', 'add', 'add', 'add'])
        except (OSError, ValueError, KeyError, TypeError, queue.Empty,
                subprocess.SubprocessError, RuntimeError, http.client.HTTPException) as error:
            failure = str(error)
        finally:
            if child is not None:
                try:
                    if child.poll() is None:
                        child.send_signal(signal.SIGTERM)
                    try:
                        child.wait(timeout=12)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=5)
                    if reader is not None:
                        reader.join(timeout=3)
                    child.stdout.close()
                    facts['shutdown_reaped'] = (child.returncode == 0
                        and reader is not None and not reader.is_alive())
                except (OSError, subprocess.SubprocessError) as error:
                    failure = '; '.join(value for value in (failure, str(error)) if value)
            # Match every retained identity before deleting this owned stopped
            # fixture. Never force-remove a running container or unrelated object.
            if container is not None and seed_value is not None:
                try:
                    status, stopped = engine('GET', '/containers/' + container + '/json')
                    labels = stopped.get('Config', {}).get('Labels', {}) if stopped else {}
                    if (status != 200 or stopped['Id'] != container
                            or stopped['Config']['Image'] != IMAGE
                            or stopped['State']['Running'] is not False
                            or stopped['State']['Pid'] != 0
                            or labels.get('nexus.task_id') != seed_value['task_id']
                            or labels.get('nexus.contract_digest') != seed_value['contract_digest']):
                        raise RuntimeError('owned fixture lacks safe stopped cleanup proof')
                    status, _ = engine('DELETE', '/containers/' + container)
                    if status != 204:
                        raise RuntimeError('owned stopped fixture cleanup failed')
                    facts['owned_container_cleanup'] = True
                except (OSError, ValueError, KeyError, TypeError, RuntimeError,
                        http.client.HTTPException) as error:
                    failure = '; '.join(value for value in (failure, str(error)) if value)
            if stderr_path.is_file():
                observations['daemon_stderr'] = stderr_path.read_text()[-8192:]
        verdict = 'UNKNOWN' if unavailable else (
            'PASS' if failure is None and all(facts.values()) else 'FAIL')
        return {'verdict': verdict, **facts,
                **({'reason': failure} if failure is not None else {}),
                'observations': observations,
                'scope': 'local scoped operator Use grants and actual existing Artifact delivery; '
                         'no public Submit/Snapshot import/cross-node/Windows claim'}


if __name__ == '__main__':
    try:
        result = observe()
    except (OSError, ValueError, KeyError, TypeError, queue.Empty,
            subprocess.SubprocessError, RuntimeError, http.client.HTTPException) as error:
        result = {'verdict': 'FAIL', 'reason': str(error)}
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result['verdict'] == 'PASS' else 1)

"""Formal provider provisioning -> ordinary no-TUN daemon; no SDK seed/Engine.

N3_BASELINE_DAEMON/CLI select real old binaries for contract RED. Observations
never retain raw identity, bearer token, CLI stdout or daemon diagnostics.
"""
import hashlib
import http.client
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import tempfile
import time
import tomllib


SCOPE = {'provider': 'n311-provider', 'workspace': 'n311-workspace'}
MARKER = 'task-provider-init-v1.json'
RECEIPT = 'task-provider-initialized-v1.json'
INIT_LOCK = 'task-provider-init.lock'
POLICY = {
    'total': {'cpu_millis': 10000, 'memory_bytes': 2 * 1024**3, 'pids': 2000,
              'runtime_storage_bytes': 256 * 1024**2,
              'backend_disk_bytes': 2 * 1024**3, 'slots': 10},
    'fixed': {'cpu_millis': 100, 'memory_bytes': 16 * 1024**2, 'pids': 4,
              'runtime_storage_bytes': 4096,
              'backend_disk_bytes': 16 * 1024**2, 'slots': 1},
    'overhead': {'cpu_millis': 10, 'memory_bytes': 8 * 1024**2, 'pids': 2,
                 'backend_disk_bytes': 1024**2},
}
FIELDS = ('formal_init', 'check_readonly', 'duplicate_init_preserved',
          'daemon_task_service_available', 'postboot_init_preserved',
          'scope_policy_change_denied', 'authority_loss_denied',
          'damaged_boot_denied', 'decoy_untouched', 'one_manager',
          'shutdown_reaped')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def tree(root):
    """Compare names, inode bindings, permissions and bytes; omit mutable atime."""
    result = {}
    for path in [root, *sorted(root.rglob('*'))]:
        meta = path.lstat()
        if not (stat.S_ISDIR(meta.st_mode) or stat.S_ISREG(meta.st_mode)):
            raise RuntimeError('fixture contains unexpected nonregular entry')
        if stat.S_ISREG(meta.st_mode) and meta.st_size > 4 * 1024**2:
            raise RuntimeError('fixture file exceeds observation bound')
        digest = sha(path.read_bytes()) if stat.S_ISREG(meta.st_mode) else None
        result[str(path.relative_to(root))] = (
            meta.st_dev, meta.st_ino, meta.st_mode, meta.st_nlink, digest)
    if len(result) > 1024:
        raise RuntimeError('fixture tree exceeds observation bound')
    return result


def command(binary, args, env, observations, label, timeout=15):
    run = subprocess.run([str(binary), *args], env=env, capture_output=True,
                         text=True, timeout=timeout)
    if max(len(run.stdout), len(run.stderr)) > 1024**2:
        raise RuntimeError(label + ': output exceeds bound')
    try:
        value = json.loads(run.stdout)
        if not isinstance(value, dict):
            raise ValueError('non-object response')
    except ValueError:
        value = {}
    observations[label] = {'exit_code': run.returncode,
                           'verdict': value.get('verdict'),
                           'error_code': value.get('error', {}).get('code')}
    return run.returncode, value


def passed(result, operation):
    code, value = result
    return (code == 0 and value.get('schema_version') == 1
            and value.get('verdict') == 'PASS'
            and value.get('command') == 'task-provider ' + operation
            and value.get('scope') == SCOPE)


def denied(result):
    code, value = result
    return (code == 0 and value.get('verdict') == 'FAIL'
            and value.get('error', {}).get('code') == 'STATE_CORRUPT'
            and value['error'].get('retryable') is False)


def boot(binary, root, env, base, label, probe=None):
    """Use owned files rather than pipe readers; child is always reaped."""
    stdout, stderr = base / (label + '.stdout'), base / (label + '.stderr')
    ready, shutdown, early_exit = None, False, False
    with stdout.open('w') as out, stderr.open('w') as err:
        child = subprocess.Popen([str(binary), str(root)], env=env,
                                 stdout=out, stderr=err)
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if stdout.stat().st_size > 1024**2 or stderr.stat().st_size > 1024**2:
                    raise RuntimeError('daemon startup output exceeds bound')
                for line in stdout.read_text().splitlines():
                    try:
                        value = json.loads(line)
                    except ValueError:
                        continue
                    if value.get('verdict') == 'READY':
                        ready = value
                if ready is not None:
                    break
                if child.poll() is not None:
                    early_exit = True
                    break
                time.sleep(0.05)
            if probe is not None:
                if ready is None:
                    raise RuntimeError('ordinary configured provider never reached READY')
                while not (root / 'localapi.token').is_file():
                    if time.monotonic() >= deadline or child.poll() is not None:
                        raise RuntimeError('ordinary daemon token unavailable')
                    time.sleep(0.05)
                probe(ready['daemon']['localapi'])
        finally:
            if child.poll() is None:
                child.send_signal(signal.SIGTERM)
            try:
                child.wait(timeout=12)
                shutdown = child.returncode == 0
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
    return {'ready': ready is not None, 'early_exit': early_exit,
            'exit_code': child.returncode, 'shutdown': shutdown,
            'manager_count': stderr.read_text().count('N2 SessionManager assembled (')}


def observe():
    target = Path(os.environ.get('CARGO_TARGET_DIR', 'target')).resolve() / 'debug'
    daemon = Path(os.environ.get('N3_BASELINE_DAEMON', target / 'nexusd'))
    cli = Path(os.environ.get('N3_BASELINE_CLI', target / 'nexus'))
    facts, observations = dict.fromkeys(FIELDS, False), {}
    if not all(path.is_file() for path in (daemon, cli)):
        return {'verdict': 'UNKNOWN', 'reason': 'prebuilt real daemon and CLI required'}
    with tempfile.TemporaryDirectory(prefix='n311-provider-') as temporary:
        base = Path(temporary)
        policy = base / 'policy.json'
        policy.write_text(json.dumps(POLICY))
        digest = 'sha256:' + sha(json.dumps(POLICY, sort_keys=True,
                                            separators=(',', ':')).encode())
        decoy = base / 'decoy'
        decoy.mkdir(mode=0o700)
        env = dict(os.environ, NEXUS_CONFIG_DIR=str(decoy))

        def create(name):
            root = base / name
            root.mkdir(mode=0o700)
            (root / 'daemon.toml').write_text(
                'localapi_addr = "127.0.0.1:0"\n[tun]\nenabled = false\n')
            return root

        def invoke(root, operation, label, provider=SCOPE['provider'],
                   workspace=SCOPE['workspace'], capacity=policy):
            args = ['task-provider', operation, '--config', str(root), '--json']
            if operation == 'init':
                args += ['--provider', provider, '--workspace', workspace,
                         '--capacity', str(capacity)]
            return command(daemon, args, env, observations, label)

        root = create('config')
        env['NEXUS_LOCALAPI_TOKEN_FILE'] = str(root / 'localapi.token')
        initialized = invoke(root, 'init', 'init')
        if not passed(initialized, 'init') or initialized[1].get('changed') is not True:
            return {'verdict': 'FAIL', **facts, 'reason':
                    'formal init rejected or failed (old CLI usage exit 2 is RED)',
                    'observations': observations}
        identity = json.loads((root / 'n2/auth-identity').read_text())
        principal = 'ed25519:' + sha(bytes.fromhex(identity['public_key_hex']))[:32]
        authority = root / 'data/n3/tasks'
        image = json.loads((authority / 'acceptance-v1.json').read_text())
        facts['formal_init'] = (
            initialized[1].get('principal') == principal
            and (root / MARKER).is_file() and (root / RECEIPT).is_file()
            and (authority / 'capacity-owner.lock').read_bytes() == b'n3-provider-init-v1-required\n'
            and tomllib.loads((root / 'task-api.toml').read_text()) == SCOPE
            and image['schema_version'] == 2 and image['ledger']['tasks'] == []
            and image['ledger']['idempotency'] == []
            and image['capacity']['policy'] == POLICY
            and image['capacity']['ready'] is False and image['capacity']['epoch'] == 0
            and image['capacity']['reservations'] == []
            and not (root / 'localapi.token').exists()
            and not (authority / 'snapshot-roots-v1.json').exists())
        before = tree(root)
        checked = invoke(root, 'check', 'check')
        facts['check_readonly'] = (passed(checked, 'check')
            and checked[1].get('initialized') is True
            and checked[1].get('principal') == principal
            and checked[1].get('policy_digest') == digest and tree(root) == before)
        repeated = invoke(root, 'init', 'duplicate')
        facts['duplicate_init_preserved'] = (passed(repeated, 'init')
            and repeated[1].get('changed') is False and tree(root) == before)

        def probe(addr):
            token = (root / 'localapi.token').read_text().strip()
            conn = http.client.HTTPConnection(addr, timeout=7)
            try:
                conn.request('GET', '/localapi/v0/n2/session/list',
                             headers={'Authorization': 'Bearer ' + token})
                response = conn.getresponse()
                sessions = json.loads(response.read(1024**2))
                n2_ok = (response.status == 200 and sessions.get('owner') == 'daemon'
                         and sessions.get('verdict') == 'PASS')
            finally:
                conn.close()
            shown = command(cli, ['--json', '--addr', addr, 'task', 'show',
                            'n311-missing-task'], env, observations, 'task_show')
            error = shown[1].get('error', {})
            facts['daemon_task_service_available'] = (n2_ok and shown[0] == 0
                and error.get('code') == 'INVALID_REQUEST'
                and error.get('reason') == 'unknown accepted TaskId'
                and error.get('retryable') is False)
            live = tree(root)
            capacity = json.loads((authority / 'acceptance-v1.json').read_text())['capacity']
            facts['daemon_task_service_available'] &= (
                live['n2/auth-identity'] == before['n2/auth-identity']
                and capacity['ready'] is True and capacity['epoch'] > 0)
            repeated = invoke(root, 'init', 'live_duplicate')
            facts['postboot_init_preserved'] = (passed(repeated, 'init')
                and repeated[1].get('changed') is False and tree(root) == live)

        startup = boot(daemon, root, env, base, 'normal', probe)
        observations['daemon'] = startup
        facts['one_manager'], facts['shutdown_reaped'] = (
            startup['manager_count'] == 1, startup['shutdown'])
        after_boot = tree(root)
        checked = invoke(root, 'check', 'postboot_check')
        facts['check_readonly'] &= (passed(checked, 'check')
            and checked[1].get('initialized') is True
            and checked[1].get('principal') == principal
            and checked[1].get('policy_digest') == digest and tree(root) == after_boot)
        repeated = invoke(root, 'init', 'postboot_duplicate')
        facts['postboot_init_preserved'] &= (passed(repeated, 'init')
            and repeated[1].get('changed') is False and tree(root) == after_boot)
        changed_policy = base / 'changed-policy.json'
        changed = json.loads(json.dumps(POLICY))
        changed['total']['slots'] += 1
        changed_policy.write_text(json.dumps(changed))
        scope_denied = invoke(root, 'init', 'scope_mismatch', provider='different-provider')
        workspace_denied = invoke(root, 'init', 'workspace_mismatch', workspace='different-workspace')
        policy_denied = invoke(root, 'init', 'policy_mismatch', capacity=changed_policy)
        facts['scope_policy_change_denied'] = (
            denied(scope_denied) and denied(workspace_denied)
            and denied(policy_denied) and tree(root) == after_boot)
        loss_ok, boot_ok = True, True
        faults = [('n2/auth-identity',), (MARKER,), (RECEIPT,),
                  ('data/n3/tasks/acceptance-v1.json',),
                  ('data/n3/tasks/capacity-initialized-v1',),
                  (MARKER, RECEIPT, INIT_LOCK), ('corrupt-completion',)]
        for index, names in enumerate(faults):
            damaged = create('damaged-' + str(index))
            if not passed(invoke(damaged, 'init', 'fixture_' + str(index)), 'init'):
                raise RuntimeError('formal damaged fixture init failed')
            # Explicit observer fault, never production reset or fabricated authority.
            if names == ('corrupt-completion',):
                (damaged / RECEIPT).write_bytes(b'corrupt-completion\n')
            else:
                for name in names:
                    (damaged / name).unlink()
            before = tree(damaged)
            loss_ok &= denied(invoke(damaged, 'check', 'lost_check_' + str(index)))
            loss_ok &= denied(invoke(damaged, 'init', 'lost_init_' + str(index)))
            loss_ok &= tree(damaged) == before
            damaged_env = dict(env, NEXUS_LOCALAPI_TOKEN_FILE=str(damaged / 'localapi.token'))
            result = boot(daemon, damaged, damaged_env, base, 'damaged_' + str(index))
            observations['damaged_boot_' + str(index)] = result
            boot_ok &= (not result['ready'] and result['early_exit']
                        and result['exit_code'] != 0 and tree(damaged) == before)
        facts['authority_loss_denied'], facts['damaged_boot_denied'] = loss_ok, boot_ok
        facts['decoy_untouched'] = not list(decoy.iterdir())
        return {'verdict': 'PASS' if all(facts.values()) else 'FAIL', **facts,
                'observations': observations,
                'scope': 'formal fresh provider and cold boot only; no Task submission/execution'}


if __name__ == '__main__':
    try:
        result = observe()
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError, subprocess.SubprocessError,
            http.client.HTTPException) as error:
        # Exceptions can contain untrusted file contents; retain only safe classification.
        result = {'verdict': 'FAIL', 'reason': 'provider observation failed',
                  'failure_class': type(error).__name__}
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result['verdict'] == 'PASS' else 1)

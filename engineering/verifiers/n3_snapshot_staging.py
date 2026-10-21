"""N3-12 real-binary observer. No provider SDK seed or fabricated authority.

Run directly for E4. E3 unittest imports Fixture below. N3_BASELINE_CLI and
N3_BASELINE_DAEMON select an actual previous revision for the contract RED.
Diagnostics intentionally retain classifications, never bearer/identity bytes.
"""
from contextlib import contextmanager
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import stat
import subprocess
import tempfile
import time

from n3_provider_init import POLICY

GLOBAL_CHARGE = 16_777_216
CHUNK = 65_536
FIELDS = ('fixed_commit_source_readonly', 'immutable_bundle_verified',
          'formal_staging_init', 'authenticated_upload', 'restart_prefix_preserved',
          'same_key_preserved', 'key_conflict_denied', 'current_grant_enforced',
          'budget_bound', 'cancel_physical_cleanup', 'damaged_boot_denied',
          'decoy_untouched', 'no_task_session_engine', 'shutdown_reaped')


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':')).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def digest(data):
    return 'sha256:' + sha(data)


def blob_name(reference):
    require(isinstance(reference, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', reference) is not None,
            'domain SHA-256 wire reference must retain sha256: prefix')
    return reference[7:]


def tree(root):
    """Observe writes through mtime/ctime as well as identity/content; exclude atime."""
    image = {}
    if not root.exists() and not root.is_symlink():
        return image
    paths = [root, *sorted(root.rglob('*'))] if root.is_dir() and not root.is_symlink() else [root]
    for path in paths:
        meta = path.lstat()
        if stat.S_ISREG(meta.st_mode):
            if meta.st_size > 72 * 1024**2:
                raise AssertionError('observation exceeds file bound')
            digest = sha(path.read_bytes())
        elif stat.S_ISLNK(meta.st_mode):
            digest = sha(os.readlink(path).encode())
        else:
            digest = None
        image[str(path.relative_to(root))] = (meta.st_dev, meta.st_ino,
            meta.st_mode, meta.st_nlink, meta.st_size if not stat.S_ISDIR(meta.st_mode) else 0,
            digest, meta.st_mtime_ns, meta.st_ctime_ns)
        if len(image) > 5000:
            raise AssertionError('observation exceeds entry bound')
    return image


def charge(manifest):
    def aligned(size):
        return ((size + 4095) // 4096) * 4096
    unique = {}
    for file in manifest:
        old = unique.setdefault(file['sha256'], file['size_bytes'])
        if old != file['size_bytes']:
            raise AssertionError('same digest with different sizes')
    return (2 * sum(aligned(size) for size in unique.values())
            + 2 * aligned(len(canonical(manifest))) + 2 * aligned(524_288)
            + aligned(CHUNK) + 4096 * (len(unique) + 6))


def require(condition, contract_point):
    if not condition:
        raise AssertionError(contract_point)


def response_pass(result, command=None):
    code, value = result
    return (code == 0 and type(value.get('schema_version')) is int and value['schema_version'] == 1
            and value.get('verdict') == 'PASS'
            and (command is None or value.get('command') == command))


_UNSPECIFIED = object()
ERROR_CODES = frozenset(('INVALID_REQUEST', 'UNSUPPORTED_VERSION', 'UNSUPPORTED_CAPABILITY',
    'AUTH_DENIED', 'PROVIDER_UNREACHABLE', 'ENVIRONMENT_MISMATCH', 'CAPACITY_UNAVAILABLE',
    'IDEMPOTENCY_CONFLICT', 'PERSISTENCE_FAILED', 'STATE_CORRUPT', 'INPUT_UNAVAILABLE',
    'INPUT_INTEGRITY_FAILED', 'INVALID_PATH', 'OUTPUT_EXISTS', 'ARTIFACT_MISSING',
    'ARTIFACT_INTEGRITY_FAILED', 'ARTIFACT_UNAVAILABLE', 'WorkloadExit', 'Timeout',
    'PrepareDeadlineExceeded', 'DeliveryDeadlineExceeded', 'ExecutionLost'))

def response_fail(result, error=None, upload_id=_UNSPECIFIED, *, command=None):
    """Validate the caller's expected envelope kind, never the response's claim.

    command=None means SnapshotEnvelope (HTTP or snapshot client operation).
    Local freeze/staging-init callers must supply the exact formal command.
    """
    code, value = result
    if not (code == 0 and type(value.get('schema_version')) is int
            and value['schema_version'] == 1 and value.get('verdict') == 'FAIL'):
        return False
    detail = value.get('error')
    if not (isinstance(detail, dict) and set(detail) == {'code', 'reason', 'retryable'}
            and isinstance(detail['code'], str) and detail['code'] in ERROR_CODES
            and isinstance(detail['reason'], str)
            and detail['reason'] and type(detail['retryable']) is bool
            and (error is None or detail['code'] == error)):
        return False
    if command is not None:
        if (command not in ('snapshot freeze', 'task-provider staging-init')
                or value.get('command') != command):
            return False
        if upload_id is not _UNSPECIFIED:
            return False
        allowed = {'schema_version', 'verdict', 'command', 'error'}
        if command == 'task-provider staging-init':
            allowed |= {'phase', 'mutation_may_have_applied'}
            if not (isinstance(value.get('phase'), str) and value['phase']
                    and type(value.get('mutation_may_have_applied')) is bool):
                return False
        return set(value) == allowed
    return (set(value) == {'schema_version', 'verdict', 'error', 'upload_id'}
            and (value['upload_id'] is None or isinstance(value['upload_id'], str))
            and (upload_id is _UNSPECIFIED or value['upload_id'] == upload_id
                 or (upload_id is not None and value['upload_id'] is None)))



class Daemon:
    """Synchronous process owner; all exit paths terminate and reap the child."""
    def __init__(self, fixture, label, unix=False):
        self.fixture = fixture
        self.label = label
        self.ready = None
        self.addr = None
        self.reaped = False
        self.out = fixture.base / (label + '.stdout')
        self.err = fixture.base / (label + '.stderr')
        self.streams = (self.out.open('wb'), self.err.open('wb'))
        self.unix = unix
        self.socket_path = fixture.base / (label + '.sock') if unix else None
        args = ([str(fixture.daemon), 'serve', '--socket', str(self.socket_path)] if unix
                else [str(fixture.daemon), str(fixture.root)])
        environment = dict(fixture.env, NEXUS_CONFIG_DIR=str(fixture.root)) if unix else fixture.env
        # -ff gives each actual tracee PID its own file, including threads.
        # Trace only execve/connect: no payload/token reads/writes or env dump.
        self.trace_prefix = fixture.base / (label + '.process-trace')
        self.daemon_pid = None
        self.trace_offsets = None
        self.child = subprocess.Popen([fixture.strace, '--seccomp-bpf', '-ff', '-o', str(self.trace_prefix),
            '-e', 'trace=execve,connect', '--', *args], env=environment,
            stdout=self.streams[0], stderr=self.streams[1])

    def await_ready(self, expected=True):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            for path in (self.out, self.err):
                require(path.stat().st_size <= 2 * 1024**2, 'bounded daemon output')
            for line in self.out.read_text(errors='replace').splitlines():
                try:
                    value = json.loads(line)
                except ValueError:
                    continue
                if value.get('verdict') == 'READY':
                    self.ready = value
                    self.addr = value['daemon'].get('localapi')
                    if self.unix:
                        require(value['daemon'].get('socket') == str(self.socket_path),
                                'real Unix serve READY path')
            if self.ready is not None or self.child.poll() is not None:
                break
            time.sleep(0.025)
        self.bind_tracee()
        if expected:
            require(self.ready is not None and self.child.poll() is None,
                    '§5 ordinary daemon must reach READY after reconciliation')
            require((self.fixture.root / 'localapi.token').is_file(),
                    '§3 genuine token authority is available')
            self.trace_offsets = {path.name: path.stat().st_size for path in self.trace_files()}
            self.fixture.observations[self.label + '_process_control'] = {
                'actual_daemon_pid': self.daemon_pid, 'daemon_sha256': sha(self.fixture.daemon.read_bytes()),
                'tracer_sha256': self.fixture.strace_sha, 'initial_exec_observed': True,
                'trace': ['execve', 'connect'], 'scope': 'no Engine qualification/execution claim'}
        else:
            require(self.ready is None and self.child.poll() is not None
                    and self.child.returncode != 0,
                    '§5 damaged staging must exit before READY')
        return self

    def trace_files(self):
        paths = sorted(self.fixture.base.glob(self.trace_prefix.name + '.*'))
        require(len(paths) <= 1024 and all(path.stat().st_size <= 2 * 1024**2 for path in paths),
                'bounded owned process trace files')
        return paths

    def bind_tracee(self):
        # Positive control is the real binary exec; never signal only strace.
        initial = 'execve(' + json.dumps(str(self.fixture.daemon)) + ','
        matches = [path for path in self.trace_files()
                   if initial in path.read_text(errors='replace')]
        require(len(matches) == 1, 'strace actual daemon exec positive control required')
        self.daemon_pid = int(matches[0].name.rsplit('.', 1)[1])
        require(self.daemon_pid != self.child.pid, 'wrapper and actual daemon are distinct owners')

    def assert_no_engine(self):
        require(self.trace_offsets is not None, 'trace begins at actual READY')
        all_lines = [line for path in self.trace_files()
                     for line in path.read_text(errors='replace').splitlines()]
        require(sum('execve(' in line for line in all_lines) == 1 and
                not any('connect(' in line for line in all_lines),
                '§1 full daemon trace contains only initial binary exec and zero outbound connects')
        lines = []
        for path in self.trace_files():
            with path.open('rb') as stream:
                stream.seek(self.trace_offsets.get(path.name, 0))
                lines.extend(stream.read(2 * 1024**2 + 1).decode(errors='replace').splitlines())
        # Isolated fixture has no peer/connect job. Reject every daemon outbound
        # connect, including arbitrary DOCKER_HOST TCP or Unix socket endpoints,
        # plus every later exec (Docker CLI/container-runtime helpers included).
        require(not any('execve(' in line or 'connect(' in line for line in lines),
                '§1 actual daemon trace has zero later exec/connect, including Engine endpoints')
        self.fixture.observations[self.label + '_engine_observation'] = {
            'post_ready_execve_count': 0, 'post_ready_connect_count': 0,
            'whole_run_initial_execve_count': 1, 'whole_run_connect_count': 0,
            'trace_initial_exec_positive_control': True, 'engine_qualified': False}

    def stop(self, kill=False):
        if self.reaped:
            return
        try:
            if self.child.poll() is None:
                if self.daemon_pid is None:
                    self.bind_tracee()
                try:
                    os.kill(self.daemon_pid, signal.SIGKILL if kill else signal.SIGTERM)
                except ProcessLookupError:
                    pass
            try:
                self.child.wait(timeout=12)
            except subprocess.TimeoutExpired:
                if self.daemon_pid is not None:
                    try:
                        os.kill(self.daemon_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                self.child.wait(timeout=5)
                raise AssertionError('actual daemon/tracer owned shutdown exceeded deadline')
        finally:
            self.reaped = self.child.poll() is not None
            for stream in self.streams:
                stream.close()
        require(self.reaped and self.daemon_pid is not None
                and not Path('/proc', str(self.daemon_pid)).exists(),
                'actual daemon process and tracer both reaped')
        if not kill and not self.unix and self.ready is not None:
            require(self.child.returncode == 0, 'daemon graceful shutdown')


class Fixture:
    def __init__(self, base):
        self.base = Path(base)
        self.base.mkdir(mode=0o700, exist_ok=True)
        target = Path(os.environ.get('CARGO_TARGET_DIR', 'target')).resolve() / 'debug'
        self.cli = Path(os.environ.get('N3_BASELINE_CLI', target / 'nexus'))
        self.daemon = Path(os.environ.get('N3_BASELINE_DAEMON', target / 'nexusd'))
        require(self.cli.is_file() and self.daemon.is_file(), 'actual prebuilt binaries required')
        self.fixture = Path(os.environ.get('N3_REQUESTER_FIXTURE',
            Path(__file__).resolve().parents[2] / 'scenarios/fixtures/n3-12-requester'))
        self.metadata = json.loads((self.fixture / 'metadata.json').read_bytes())
        # Validate fixture bytes independently before allowing any product command.
        for name, digest in self.metadata['fixture_files_sha256'].items():
            require(sha((self.fixture / name).read_bytes()) == digest,
                    '§7 requester export SHA binding ' + name)
        self.manifest = self.metadata['expected_manifest']
        self.snapshot = self.metadata['expected_snapshot']
        self.workspace = self.snapshot['workspace']
        self.provider = 'n312-provider'
        self.resource = 'compute-local'
        self.source = self.base / 'source'
        shutil.copytree(self.fixture / 'config', self.source)
        self.source.chmod(0o700)
        self.bundle = self.base / 'bundle'
        self.root = self.base / 'provider'
        self.root.mkdir(mode=0o700)
        (self.root / 'daemon.toml').write_text(
            'localapi_addr = "127.0.0.1:0"\n[tun]\nenabled = false\n')
        (self.root / 'daemon.toml').chmod(0o600)
        self.decoy = self.base / 'decoy'
        self.decoy.mkdir(mode=0o700)
        self.env = dict(os.environ, NEXUS_CONFIG_DIR=str(self.decoy),
                        NEXUS_LOCALAPI_TOKEN_FILE=str(self.root / 'localapi.token'))
        self.observations = {}
        self.strace = shutil.which('strace')
        require(self.strace is not None, 'E4 Engine observation capability unavailable: strace missing')
        self.strace_sha = sha(Path(self.strace).read_bytes())
        probe_path = self.base / 'trace-capability.log'
        probe = subprocess.run([self.strace, '-o', str(probe_path), '-e', 'trace=execve,connect',
                                '--', '/bin/true'], capture_output=True, timeout=3)
        require(probe.returncode == 0 and 'execve(' in probe_path.read_text(),
                'E4 Engine observation capability unavailable: ptrace/exec positive probe failed')
        version = subprocess.run([self.strace, '--version'], capture_output=True, timeout=3)
        require(version.returncode == 0 and len(version.stdout) < 8192, 'bounded tracer version probe')
        self.observations['process_trace_capability'] = {'tool_sha256': self.strace_sha,
            'version': version.stdout.decode(errors='replace').splitlines()[0],
            'exec_positive_control': True, 'trace_syscalls': ['execve', 'connect']}
        self.children = []
        self.policy = self.base / 'capacity.json'
        self.policy.write_bytes(canonical(POLICY))
        self.policy.chmod(0o600)
        self.budget = self.base / 'budget.json'
        self.charge = charge(self.manifest)
        self.budget.write_bytes(canonical({'schema_version': 1,
            'max_reserved_bytes': GLOBAL_CHARGE + self.charge,
            'max_active_uploads': 1}))
        self.budget.chmod(0o600)

    @property
    def staging(self):
        return self.root / 'data/n3/snapshot-staging-v1'

    def invoke(self, binary, args, label, timeout=20):
        run = subprocess.run([str(binary), *map(str, args)], env=self.env,
                             capture_output=True, timeout=timeout)
        require(max(len(run.stdout), len(run.stderr)) <= 2 * 1024**2,
                'bounded command response')
        try:
            value = json.loads(run.stdout)
            require(isinstance(value, dict), 'response is an object')
        except (ValueError, AssertionError):
            value = {}
        self.observations[label] = {'exit_code': run.returncode,
            'verdict': value.get('verdict'), 'error_code': value.get('error', {}).get('code')}
        expected_command = {('snapshot', 'freeze'): 'snapshot freeze',
                            ('task-provider', 'staging-init'): 'task-provider staging-init'}.get(
                                tuple(map(str, list(args)[:2])))
        if value.get('verdict') == 'FAIL' and expected_command is not None:
            require(response_fail((run.returncode, value), command=expected_command),
                    '§8 strict FAIL envelope for actual command ' + expected_command)
        if value.get('verdict') == 'FAIL' and list(args)[:2] in (['snapshot', 'status'], ['snapshot', 'cancel']):
            require(response_fail((run.returncode, value), upload_id=str(args[2])),
                    '§8 CLI strict FAIL and query UploadId correlation')
        return run.returncode, value

    def freeze_args(self, output=None):
        return ['snapshot', 'freeze', self.workspace, '--config', self.source,
            '--commit', self.snapshot['commit_id'], '--include', '.', '--exclude',
            'private', '--executable', 'scripts/run.sh', '--output', output or self.bundle,
            '--json']

    def freeze(self):
        before = tree(self.source)
        result = self.invoke(self.cli, self.freeze_args(), 'freeze')
        require(response_pass(result, 'snapshot freeze'),
                '§1 formal freeze must succeed (old CLI exit2 is real RED)')
        require(result[1].get('snapshot') == self.snapshot and
                result[1].get('bundle_path') == str(self.bundle), '§8 freeze correlated envelope')
        require(tree(self.source) == before, '§1 source zero writes including inode/permissions')
        self.verify_bundle()
        return result

    def verify_bundle(self, bundle=None, manifest=None, snapshot=None):
        bundle = self.bundle if bundle is None else bundle
        manifest = self.manifest if manifest is None else manifest
        snapshot = self.snapshot if snapshot is None else snapshot
        require({p.name for p in bundle.iterdir()} ==
                {'bundle-v1.json', 'manifest-v1.json', 'blobs'}, '§2 fixed bundle file set')
        require((bundle / 'bundle-v1.json').read_bytes() ==
                canonical({'schema_version': 1, 'snapshot': snapshot}), '§2 canonical metadata')
        require((bundle / 'manifest-v1.json').read_bytes() == canonical(manifest),
                '§2 original canonical SnapshotFile manifest')
        require({p.name for p in (bundle / 'blobs').iterdir()} ==
                {blob_name(file['sha256']) for file in manifest}, '§2 unique exact blob set')
        for path in [bundle, *bundle.rglob('*')]:
            info = path.lstat()
            require(not stat.S_ISLNK(info.st_mode) and (stat.S_ISREG(info.st_mode)
                or stat.S_ISDIR(info.st_mode)) and info.st_mode & 0o077 == 0,
                '§2 private non-symlink bundle')
            if stat.S_ISREG(info.st_mode):
                require(info.st_nlink == 1, '§2 bundle regular single link')
        for file in manifest:
            data = (bundle / 'blobs' / blob_name(file['sha256'])).read_bytes()
            require(len(data) == file['size_bytes'] and digest(data) == file['sha256'],
                    '§2 actual SHA-256 and exact size')

    def provision_provider(self, grant=True):
        """Only formal N3-11 provisioning; deliberately no staging initialization."""
        result = self.invoke(self.daemon, ['task-provider', 'init', '--config', self.root,
            '--provider', self.provider, '--workspace', self.workspace,
            '--capacity', self.policy, '--json'], 'provider_init')
        require(response_pass(result, 'task-provider init'), 'formal N3-11 init')
        self.provider_status = result[1]
        if grant:
            self.grant('add')
        return result

    def provision(self, grant=True):
        self.provision_provider(grant=False)
        result = self.staging_init()
        self.staging_status = self.check_staging_status(result, changed=True)
        if grant:
            self.grant('add')

    def check_staging_status(self, result, *, changed):
        require(response_pass(result, 'task-provider staging-init'), '§8 formal staging-init PASS command')
        value = result[1]
        require(set(value) == {'schema_version', 'verdict', 'command', 'scope', 'principal',
                              'policy_digest', 'changed'}
                and value['scope'] == {'provider': self.provider, 'workspace': self.workspace}
                and isinstance(value['principal'], str) and value['principal']
                and value['principal'] == self.provider_status.get('principal')
                and value['policy_digest'] == digest(self.budget.read_bytes())
                and value['changed'] is changed,
                '§8 exact staging-init shape/original scope/principal/budget and changed flag')
        return value

    @property
    def staging_marker(self):
        return self.root / 'snapshot-staging-required-v1.json'

    def staging_init(self, budget=None):
        return self.invoke(self.daemon, ['task-provider', 'staging-init', '--config',
            self.root, '--budget', budget or self.budget, '--json'], 'staging_init')

    def grant(self, operation, extra=()):
        result = self.invoke(self.cli, ['task-provider', 'grant', operation,
            '--config', self.root, '--resource', self.resource, '--self', *extra, '--json'],
            'grant_' + operation)
        require(response_pass(result, 'task-provider grant ' + operation),
                '§3 genuine scoped operator grant ' + operation)
        return result

    @contextmanager
    def boot(self, label='boot', expected=True, unix=False):
        owner = Daemon(self, label, unix=unix)
        self.children.append(owner)
        try:
            owner.await_ready(expected)
            yield owner
        finally:
            owner.stop()

    def request(self, daemon, operation, label='request', raw=None, headers=None):
        token = (self.root / 'localapi.token').read_text().strip()
        connection = self.connection(daemon)
        try:
            request_headers = {'Authorization': 'Bearer ' + token,
                               'Content-Type': 'application/json', **(headers or {})}
            request_headers = {key: value for key, value in request_headers.items() if value is not None}
            connection.request('POST', '/localapi/v1/snapshot',
                body=canonical(operation) if raw is None else raw, headers=request_headers)
            reply = connection.getresponse()
            data = reply.read(2 * 1024**2 + 1)
            require(len(data) <= 2 * 1024**2, '§3 bounded response')
            value = json.loads(data)
        finally:
            connection.close()
        self.observations[label] = {'status': reply.status, 'verdict': value.get('verdict'),
                                   'error_code': value.get('error', {}).get('code')}
        if value.get('verdict') == 'FAIL':
            expected_id = (operation.get('upload_id') if isinstance(operation, dict)
                           else _UNSPECIFIED)
            require(response_fail((0, value), upload_id=expected_id),
                    '§3 strict typed FAIL envelope and original request correlation')
        return 0, value

    def target_args(self, daemon):
        return (['--socket', daemon.socket_path] if daemon.unix else ['--addr', daemon.addr])

    def connection(self, daemon):
        if not daemon.unix:
            return http.client.HTTPConnection(daemon.addr, timeout=8)
        class UnixConnection(http.client.HTTPConnection):
            def connect(inner):
                inner.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                inner.sock.settimeout(8)
                inner.sock.connect(str(daemon.socket_path))
        return UnixConnection('localhost', timeout=8)

    def complete_bytes(self, daemon, upload_id):
        """Real authorized PutChunk of every blob; deliberately does not Seal."""
        for digest in sorted({file['sha256'] for file in self.manifest}):
            data = (self.bundle / 'blobs' / blob_name(digest)).read_bytes()
            current = self.view(self.operation(daemon, 'Get', upload_id), upload_id)
            offset = next(blob['durable_offset'] for blob in current['blobs']
                          if blob['sha256'] == digest)
            for start in range(offset, len(data), CHUNK):
                self.view(self.chunk(daemon, upload_id, digest, start, data[start:start + CHUNK]),
                          upload_id, 'Receiving')
        current = self.view(self.operation(daemon, 'Get', upload_id), upload_id, 'Receiving')
        require(all(blob['durable_offset'] == blob['size_bytes'] for blob in current['blobs']),
                'all original bytes complete before authorization Seal test')
        return current

    def check_receiving_chunk_current_use(self, daemon, upload_id, key='resume-key'):
        """Check actual grants on retry and next-write paths with legal requests.

        The original upload remains Receiving with a nonzero, incomplete prefix
        afterwards, so the formal CLI can still prove nonzero-offset resume.
        """
        initial = self.view(self.status(daemon, upload_id), upload_id, 'Receiving')
        big = next(file for file in self.manifest if file['size_bytes'] > CHUNK)
        data = (self.bundle / 'blobs' / blob_name(big['sha256'])).read_bytes()
        path = self.staging / 'uploads' / upload_id / 'blobs' / blob_name(big['sha256'])
        original_inode = (path.stat().st_dev, path.stat().st_ino)
        initial_offset = next(blob['durable_offset'] for blob in initial['blobs']
                              if blob['sha256'] == big['sha256'])
        require(0 < initial_offset < len(data) - 34,
                '§3 grant control starts with nonzero prefix and enough remaining bytes')
        original_prefix = path.read_bytes()
        require(original_prefix == data[:initial_offset], '§5 actual confirmed original prefix')
        current = initial
        for denial in ('revoke', 'expired'):
            offset = next(blob['durable_offset'] for blob in current['blobs']
                          if blob['sha256'] == big['sha256'])
            next_bytes = data[offset:offset + 17]
            next_request = {'schema_version': 1, 'operation': 'PutChunk',
                'upload_id': upload_id, 'blob_sha256': big['sha256'], 'offset': offset,
                'bytes': list(next_bytes), 'chunk_sha256': digest(next_bytes)}
            retry_bytes = data[:min(31, initial_offset)]
            retry_request = dict(next_request, offset=0, bytes=list(retry_bytes),
                                 chunk_sha256=digest(retry_bytes))
            # Both requests are legitimate before grant removal. The next-write
            # positive is deliberately delayed until after restoration to prove
            # exactly the refused bytes/offset can advance the original record.
            require(self.view(self.request(daemon, retry_request), upload_id, 'Receiving') == current,
                    '§3 authorized Receiving confirmed retry returns original progress')
            if denial == 'revoke':
                self.grant('revoke')
            else:
                require(time.time() > 1, 'real host clock is beyond explicit persisted not-after')
                self.grant('add', ['--not-after', '1'])
            denied_requests = [next_request, retry_request, self.begin_request(key),
                {'schema_version': 1, 'operation': 'Get', 'upload_id': upload_id},
                {'schema_version': 1, 'operation': 'Cancel', 'upload_id': upload_id}]
            before = tree(self.staging)
            for request in denied_requests:
                require(response_fail(self.request(daemon, request,
                            'receiving_' + denial + '_' + request['operation']),
                            'AUTH_DENIED', upload_id=request.get('upload_id')),
                        '§3 current ' + denial + ' Use denies legal Receiving ' + request['operation'])
                require(tree(self.staging) == before,
                        '§3 each denied Receiving request leaves staging unchanged')
            self.grant('add')
            require(self.view(self.status(daemon, upload_id), upload_id, 'Receiving') == current,
                    '§3 restored Get exposes unchanged denied progress')
            require(self.view(self.request(daemon, self.begin_request(key)), upload_id, 'Receiving') == current,
                    '§3 restored same-key Begin preserves original record')
            require(self.view(self.request(daemon, retry_request), upload_id, 'Receiving') == current,
                    '§3 restored confirmed retry is legitimate without progress change')
            advanced = self.view(self.request(daemon, next_request,
                                 'receiving_' + denial + '_restored_next'), upload_id, 'Receiving')
            expected = {blob['sha256']: blob['durable_offset'] for blob in current['blobs']}
            expected[big['sha256']] = offset + len(next_bytes)
            require({blob['sha256']: blob['durable_offset'] for blob in advanced['blobs']} == expected
                    and advanced['snapshot'] == initial['snapshot']
                    and advanced['reserved_bytes'] == initial['reserved_bytes']
                    and (path.stat().st_dev, path.stat().st_ino) == original_inode
                    and path.read_bytes() == data[:offset + len(next_bytes)]
                    and path.read_bytes()[:initial_offset] == original_prefix,
                    '§3 same refused next chunk advances only original offset/inode/id/ref/charge')
            current = advanced
        self.observations['receiving_chunk_current_use'] = {
            'denials': ['revoke', 'persisted-not-after-1'], 'error_code': 'AUTH_DENIED',
            'confirmed_retry_and_next_write_checked': True, 'denied_staging_unchanged': True,
            'same_request_after_restore_advances_original_record': True,
            'initial_offset': initial_offset,
            'remaining_offset': next(blob['durable_offset'] for blob in current['blobs']
                                     if blob['sha256'] == big['sha256'])}
        return current

    def check_cancelled_current_use(self, daemon, cancelled, request, denial):
        """Exercise one legal terminal request, on this independently owned fixture."""
        upload_id = cancelled['upload_id']
        namespace = self.staging / 'uploads' / upload_id
        require(cancelled['state'] == 'Cancelled' and cancelled['reserved_bytes'] == 0
                and cancelled['blobs'] == [] and not namespace.exists(),
                '§5 terminal auth control starts with physically cleaned zero-charge tombstone')
        before = tree(self.staging)
        require(self.view(self.request(daemon, request), upload_id, 'Cancelled') == cancelled,
                '§3 terminal request is legal with current Use before denial')
        if request['operation'] == 'Get':
            require(tree(self.staging) == before, '§4 authorized terminal Get is read-only')
        if denial == 'revoke':
            self.grant('revoke')
        else:
            require(denial == 'expired' and time.time() > 1,
                    'real host clock is beyond explicit persisted not-after')
            self.grant('add', ['--not-after', '1'])
        denied_before = tree(self.staging)
        require(response_fail(self.request(daemon, request), 'AUTH_DENIED',
                              upload_id=request.get('upload_id')),
                '§3 current ' + denial + ' Use gates legal Cancelled ' + request['operation'])
        require(tree(self.staging) == denied_before and not namespace.exists(),
                '§3 terminal auth denial preserves complete namespace/inode/mtime/ctime image')
        self.grant('add')
        restored_before = tree(self.staging)
        require(self.view(self.request(daemon, request), upload_id, 'Cancelled') == cancelled,
                '§3 exact terminal request after grant restoration returns original binding/zero charge')
        require(not namespace.exists(), '§5 authorized terminal retry does not recreate payload')
        if request['operation'] == 'Get':
            require(tree(self.staging) == restored_before, '§4 restored terminal Get is read-only')
        return {'operation': request['operation'], 'denial': denial, 'error_code': 'AUTH_DENIED',
                'original_terminal_view_preserved': True, 'same_request_positive_before_after': True,
                'staging_mtime_ctime_unchanged_on_denial': True, 'payload_namespace_absent': True}

    def snapshot_for_manifest(self, manifest, *, raw=None, **changes):
        """Independent reference hashing; malformed semantics can pass hash preconditions."""
        snapshot = dict(self.snapshot, manifest_sha256=digest(canonical(manifest) if raw is None else raw),
                        file_count=len(manifest), total_bytes=sum(file['size_bytes'] for file in manifest))
        snapshot.update(changes)
        snapshot.pop('snapshot_id')
        snapshot['snapshot_id'] = digest(canonical(snapshot))
        return snapshot

    def begin_request(self, key='resume-key', **changes):
        return {'schema_version': 1, 'operation': 'Begin', 'provider': self.provider,
            'workspace': self.workspace, 'resource': self.resource, 'upload_key': key,
            'snapshot': self.snapshot, 'manifest_json': canonical(self.manifest).decode(),
            **changes}

    def different_snapshot(self):
        """Valid self-consistent binding, so conflict cannot mask parse failure."""
        snapshot = dict(self.snapshot)
        snapshot['commit_id'] = self.metadata['facts']['new_commit']
        snapshot['root_manifest_id'] = self.metadata['facts']['new_manifest']
        snapshot.pop('snapshot_id')
        snapshot['snapshot_id'] = digest(canonical(snapshot))
        return snapshot

    def begin(self, daemon, key='resume-key'):
        result = self.request(daemon, self.begin_request(key), 'begin_' + key)
        self.view(result, state='Receiving')
        return result[1]['upload']

    def view(self, result, upload_id=None, state=None):
        require(response_pass(result), '§3 typed SnapshotEnvelope PASS')
        require(set(result[1]) == {'schema_version', 'verdict', 'upload'}, '§3 envelope fixed fields')
        view = result[1]['upload']
        require(set(view) == {'schema_version', 'upload_id', 'provider', 'workspace', 'resource',
                'snapshot', 'state', 'reserved_bytes', 'blobs'}, '§3 view fixed fields')
        require(view['schema_version'] == 1 and view['provider'] == self.provider
                and view['workspace'] == self.workspace and view['resource'] == self.resource
                and view['snapshot'] == self.snapshot, '§8 response original binding')
        if upload_id is not None:
            require(view['upload_id'] == upload_id, '§8 upload response correlation')
        require(re.fullmatch(r'[A-Za-z0-9_-]+', view['upload_id']) is not None,
                '§3 provider-generated safe UploadId namespace')
        if state is not None:
            require(view['state'] == state, '§5 upload state ' + state)
        if view['state'] == 'Cancelled':
            require(view['reserved_bytes'] == 0 and view['blobs'] == [], '§5 Cancelled zero charge')
        else:
            require(view['reserved_bytes'] == self.charge, '§4 exact conservative reservation')
            unique = {f['sha256']: f['size_bytes'] for f in self.manifest}
            require([b['sha256'] for b in view['blobs']] == sorted(unique), '§3 sorted unique blobs')
            for blob in view['blobs']:
                require(set(blob) == {'sha256', 'size_bytes', 'durable_offset'} and
                    blob['size_bytes'] == unique[blob['sha256']] and
                    type(blob['durable_offset']) is int and
                    0 <= blob['durable_offset'] <= blob['size_bytes'], '§8 bounded blob progress')
                if view['state'] == 'Staged':
                    require(blob['durable_offset'] == blob['size_bytes'], '§5 complete Staged blob')
        return view

    def operation(self, daemon, operation, upload_id):
        return self.request(daemon, {'schema_version': 1, 'operation': operation,
                                    'upload_id': upload_id}, operation)

    def chunk(self, daemon, upload_id, blob_digest, offset, data, **changes):
        return self.request(daemon, {'schema_version': 1, 'operation': 'PutChunk',
            'upload_id': upload_id, 'blob_sha256': blob_digest, 'offset': offset,
            'bytes': list(data), 'chunk_sha256': digest(data), **changes}, 'chunk')

    def upload(self, daemon, key='resume-key', bundle=None):
        return self.invoke(self.cli, ['snapshot', 'upload', '--bundle', bundle or self.bundle,
            '--provider', self.provider, '--resource', self.resource, '--key', key,
            *self.target_args(daemon), '--json'],
            'upload_' + key, timeout=40)

    def status(self, daemon, upload_id):
        return self.invoke(self.cli, ['snapshot', 'status', upload_id,
            *self.target_args(daemon), '--json'], 'status')

    def cancel(self, daemon, upload_id):
        return self.invoke(self.cli, ['snapshot', 'cancel', upload_id,
            *self.target_args(daemon), '--json'], 'cancel')

    def assert_no_execution(self, daemon, baseline=None):
        daemon.assert_no_engine()
        authority = self.root / 'data/n3/tasks'
        if baseline is not None:
            require(tree(authority) == baseline, '§1 original execution/runtime/Artifact authority zero changes')
        runtime = json.loads((authority / 'task-runtime-v1.json').read_bytes())
        require(runtime['runtime']['journals'] == [], '§1 zero actual execution runtime journals')
        artifacts = json.loads((authority / 'artifacts-v1.json').read_bytes())
        require(artifacts['payload']['publications'] == [], '§1 zero actual Artifact publications')
        require(not (authority / 'executions-v1').exists() or
                not list((authority / 'executions-v1').iterdir()), '§1 zero executor handles/log/output roots')
        require(not (authority / 'artifact-content-sha256-v1').exists() or
                not list((authority / 'artifact-content-sha256-v1').iterdir()), '§1 zero Artifact payload')
        ledger = json.loads((authority / 'acceptance-v1.json').read_bytes())
        require(ledger['ledger']['tasks'] == [] and ledger['ledger']['idempotency'] == []
            and ledger['capacity']['reservations'] == [], '§1 staging never accepts a Task')
        roots_path = authority / 'snapshot-roots-v1.json'
        if roots_path.exists():
            roots = json.loads(roots_path.read_bytes())['roots']
            require(roots['staged'] == [] and roots['retained'] == [] and roots['tombstones'] == [],
                    '§5 original snapshot catalog has zero accepted/preview/retained roots')
        token = (self.root / 'localapi.token').read_text().strip()
        connection = self.connection(daemon)
        try:
            connection.request('GET', '/localapi/v0/n2/session/list',
                               headers={'Authorization': 'Bearer ' + token})
            reply = connection.getresponse()
            value = json.loads(reply.read(1024**2))
            require(reply.status == 200 and value.get('verdict') == 'PASS'
                and value.get('sessions') == [], '§1 zero actual SessionManager sessions')
        finally:
            connection.close()


SELECTION_CASES = {
    'include-many': (['scripts', 'inputs/empty.txt', 'inputs/data.bin'], ['private'], ['scripts/run.sh']),
    'exclude-many': (['.'], ['private/excluded.txt', 'inputs/data.bin'], ['scripts/run.sh']),
    'executable-many': (['.'], ['private'], ['scripts/run.sh', 'inputs/empty.txt']),
    'all-many': (['scripts', 'private', 'inputs/empty.txt', 'inputs/data.bin'],
                 ['private/excluded.txt', 'inputs/data.bin'], ['scripts/run.sh', 'inputs/empty.txt']),
    'all-reversed': (['inputs/data.bin', 'inputs/empty.txt', 'private', 'scripts'],
                     ['inputs/data.bin', 'private/excluded.txt'], ['inputs/empty.txt', 'scripts/run.sh']),
    'optional-omitted': (['scripts'], [], []),
}


def legacy_fnv(data):
    value = 0xcbf29ce484222325
    for byte in data:
        value = ((value ^ byte) * 0x100000001b3) & 0xffffffffffffffff
    return format(value, '016x')


def requester_selection(fixture, include, exclude, executable):
    """Independent expectation from original requester old Commit and CAS bytes."""
    config = fixture.fixture / 'config'
    cas = config / 'data/cas'
    state_id = (config / 'data/workspaces' / fixture.workspace / 'state_root').read_text()
    state = (cas / state_id).read_bytes()
    require(legacy_fnv(state) == state_id, 'independent requester state FNV')
    old_commit = fixture.metadata['facts']['old_commit']
    entry = next(line.split() for line in state.decode().splitlines()
                 if line.startswith('commit ' + old_commit + ' '))
    _, commit_id, manifest_id, parents, author, timestamp = entry
    commit_bytes = ('nexus-commit-v1\nparents:' + ','.join(sorted(filter(None,
        parents.removeprefix('parents:').split(',')))) + '\nroot:' + manifest_id +
        '\nauthor:' + author.removeprefix('author:') + '\ntimestamp:' +
        timestamp.removeprefix('ts:') + '\n').encode()
    require(legacy_fnv(commit_bytes) == commit_id, 'independent old Commit content identity')
    raw = (cas / manifest_id).read_bytes()
    require(legacy_fnv(raw) == manifest_id, 'independent selected old root FNV')
    source = {}
    for line in raw.splitlines():
        name, object_id = line.split(b'\0')
        data = (cas / object_id.decode()).read_bytes()
        require(legacy_fnv(data) == object_id.decode(), 'independent requester content FNV')
        source[name.decode()] = data
    def matches(path, rule):
        return rule == '.' or path == rule or path.startswith(rule + '/')
    require(all(any(matches(path, rule) for path in source) for rule in include),
            'each successful include actually names an old committed file/directory')
    selected = {name: data for name, data in source.items()
                if any(matches(name, rule) for rule in include)
                and not any(matches(name, rule) for rule in exclude)}
    require(all(name in selected for name in executable), 'all executable controls are selected real files')
    manifest = [{'path': name, 'sha256': digest(data), 'size_bytes': len(data),
                 'executable': name in executable} for name, data in sorted(selected.items())]
    selection = {'schema_version': 1, 'matching': 'exact-or-directory-prefix',
                 'include': sorted(include), 'exclude': sorted(exclude), 'executable': sorted(executable)}
    snapshot = {'schema_version': 1, 'workspace': fixture.workspace, 'commit_id': commit_id,
        'root_manifest_id': manifest_id, 'manifest_sha256': digest(canonical(manifest)),
        'selection_digest': digest(canonical(selection)), 'file_count': len(manifest),
        'total_bytes': sum(len(data) for data in selected.values())}
    snapshot['snapshot_id'] = digest(canonical(snapshot))
    return manifest, snapshot, selected


def selection_freeze_case(base, case, json_output=True):
    fixture = Fixture(base)
    include, exclude, executable = SELECTION_CASES[case]
    manifest, snapshot, selected = requester_selection(fixture, include, exclude, executable)
    args = ['snapshot', 'freeze', fixture.workspace, '--config', fixture.source,
            '--commit', snapshot['commit_id'], '--output', fixture.bundle]
    for option, paths in (('--include', include), ('--exclude', exclude), ('--executable', executable)):
        for path in paths:
            args.extend((option, path))
    if json_output:
        args.append('--json')
    before = tree(fixture.source)
    result = fixture.invoke(fixture.cli, args, 'selection-' + case)
    require(result[0] == 0, 'successful distinct/optional selection CLI exit')
    if json_output:
        require(response_pass(result, 'snapshot freeze') and set(result[1]) ==
                {'schema_version', 'verdict', 'command', 'snapshot', 'bundle_path'}
                and result[1]['snapshot'] == snapshot and result[1]['bundle_path'] == str(fixture.bundle),
                '§1 repeated distinct selection values preserve exact independently derived SnapshotRef')
    fixture.verify_bundle(manifest=manifest, snapshot=snapshot)
    require(tree(fixture.source) == before, '§1 multi-selection freeze leaves source completely read-only')
    for name, data in selected.items():
        file = next(file for file in manifest if file['path'] == name)
        require((fixture.bundle / 'blobs' / blob_name(file['sha256'])).read_bytes() == data,
                'independent original selected bytes including legitimate zero-length executable')
    return {'case': case, 'manifest': manifest, 'snapshot': snapshot,
            'source_unchanged': True, 'private_complete_bundle': True}


OUTPUT_CASES = ('empty-directory', 'nonempty-directory', 'regular-file',
                'directory-symlink', 'file-symlink', 'dangling-symlink')


def existing_output_case(base, kind):
    fixture = Fixture(base)
    decoy = fixture.base / 'destination-decoy'
    decoy.mkdir(mode=0o700)
    data = decoy / 'original-bytes'
    data.write_bytes(b'preserve external destination data\n'); data.chmod(0o600)
    if kind in ('empty-directory', 'nonempty-directory'):
        fixture.bundle.mkdir(mode=0o700)
        if kind == 'nonempty-directory':
            (fixture.bundle / 'user-data').write_bytes(b'preserve user output\n')
    elif kind == 'regular-file':
        fixture.bundle.write_bytes(b'preserve existing regular destination\n'); fixture.bundle.chmod(0o600)
    elif kind == 'directory-symlink':
        fixture.bundle.symlink_to(decoy, target_is_directory=True)
    elif kind == 'file-symlink':
        fixture.bundle.symlink_to(data)
    elif kind == 'dangling-symlink':
        fixture.bundle.symlink_to(decoy / 'absent-target')
    else:
        raise AssertionError('unknown output control')
    source_before, output_before, decoy_before = tree(fixture.source), tree(fixture.bundle), tree(decoy)
    require('.' in output_before, 'existing destination including dangling symlink must be observed')
    result = fixture.invoke(fixture.cli, fixture.freeze_args(), 'existing-' + kind)
    require(response_fail(result, 'OUTPUT_EXISTS', command='snapshot freeze'),
            '§1 every existing target kind requires exact OUTPUT_EXISTS at real CLI')
    require(tree(fixture.bundle) == output_before and tree(decoy) == decoy_before
            and tree(fixture.source) == source_before,
            '§1 preserve target/link identity/bytes/mode/mtime/ctime, decoy and read-only source')
    return {'kind': kind, 'output_exists': True, 'destination_and_decoy_preserved': True,
            'source_unchanged': True}


def provider_binding_image(fixture):
    """Original N3-11 files; runtime Ready/epoch and auth audit have other owners."""
    image = tree(fixture.root)
    names = ('task-provider-init.lock', 'task-provider-init-v1.json',
             'task-provider-initialized-v1.json', 'task-api.toml')
    require(all(name in image for name in names), 'formal N3-11 complete binding exists')
    return {name: image[name] for name in names}


def check_task_service_control(fixture, daemon):
    result = fixture.invoke(fixture.cli, ['--json', *fixture.target_args(daemon),
        'task', 'show', 'n312-missing-task'], 'original_task_control')
    require(result[0] == 0 and result[1].get('error', {}).get('code') == 'INVALID_REQUEST'
            and result[1]['error'].get('reason') == 'unknown accepted TaskId'
            and result[1]['error'].get('retryable') is False,
            'original authenticated Task service remains available without staging')


def disabled_staging_case(base, operation):
    fixture = Fixture(base)
    fixture.freeze()
    fixture.provision_provider()
    binding = provider_binding_image(fixture)
    key = 'disabled-feature-key'
    begin = fixture.begin_request(key)
    unknown_id = 'valid-id-with-no-provisioned-record'
    big = next(file for file in fixture.manifest if file['size_bytes'] > CHUNK)
    data = (fixture.bundle / 'blobs' / blob_name(big['sha256'])).read_bytes()
    request = (begin if operation in ('Begin', 'upload') else
               {'schema_version': 1, 'operation': operation, 'upload_id': unknown_id})
    if operation == 'PutChunk':
        request.update(blob_sha256=big['sha256'], offset=0, bytes=list(data[:17]),
                       chunk_sha256=digest(data[:17]))
    require(not fixture.staging.exists() and not fixture.staging_marker.exists(),
            '§9 marker and namespace both absent before first ordinary boot')
    with fixture.boot('disabled-' + operation) as daemon:
        check_task_service_control(fixture, daemon)
        execution_before = tree(fixture.root / 'data/n3/tasks')
        n3_before = tree(fixture.root / 'data/n3')
        if operation == 'upload':
            result = fixture.upload(daemon, key)
        elif operation in ('status', 'cancel'):
            result = (fixture.status(daemon, unknown_id) if operation == 'status'
                      else fixture.cancel(daemon, unknown_id))
        else:
            result = fixture.request(daemon, request)
        require(response_fail(result, upload_id=None if operation in ('Begin', 'upload') else unknown_id),
                '§1 valid authenticated disabled snapshot entry returns typed FAIL: ' + operation)
        require(not fixture.staging.exists() and not fixture.staging_marker.exists()
                and tree(fixture.root / 'data/n3') == n3_before
                and provider_binding_image(fixture) == binding,
                '§1 disabled snapshot access cannot create staging/marker/policy/ledger or alter Task authority')
        fixture.assert_no_execution(daemon, execution_before)
        check_task_service_control(fixture, daemon)
    # None is a boot-time adapter state; explicit init is followed by a genuine
    # restart. The contract does not promise live provisioning/hot reload.
    enabled = fixture.staging_init()
    fixture.check_staging_status(enabled, changed=True)
    with fixture.boot('enabled-' + operation) as daemon:
        execution_before = tree(fixture.root / 'data/n3/tasks')
        if operation == 'upload':
            current = fixture.view(fixture.upload(daemon, key), state='Staged')
        else:
            current = fixture.view(fixture.request(daemon, begin), state='Receiving')
        upload_id = current['upload_id']
        if operation == 'PutChunk':
            enabled_request = dict(request, upload_id=upload_id)
            current = fixture.view(fixture.request(daemon, enabled_request), upload_id, 'Receiving')
            require(next(blob['durable_offset'] for blob in current['blobs']
                         if blob['sha256'] == big['sha256']) == 17,
                    'enabled PutChunk same original bytes/offset/hash progresses a genuine record')
        elif operation == 'Seal':
            fixture.complete_bytes(daemon, upload_id)
            current = fixture.view(fixture.operation(daemon, 'Seal', upload_id), upload_id, 'Staged')
        elif operation in ('Cancel', 'cancel'):
            current = fixture.view(fixture.cancel(daemon, upload_id) if operation == 'cancel' else
                                   fixture.operation(daemon, 'Cancel', upload_id), upload_id, 'Cancelled')
        elif operation == 'Get':
            require(fixture.view(fixture.operation(daemon, 'Get', upload_id), upload_id) == current,
                    'enabled genuine HTTP Get has a positive control')
        require(fixture.view(fixture.status(daemon, upload_id), upload_id) == current,
                'enabled formal status observes original binding/state')
        require(provider_binding_image(fixture) == binding, 'explicit staging init preserves N3-11 binding')
        fixture.assert_no_execution(daemon, execution_before)
        if current['state'] != 'Cancelled':
            fixture.view(fixture.cancel(daemon, upload_id), upload_id, 'Cancelled')
    require(all(child.reaped for child in fixture.children), 'disabled/enabled ordinary daemons reaped')
    return {'operation': operation, 'no_implicit_provision': True, 'explicit_init_then_restart': True,
            'same_bundle_key_begin_enabled': True, 'queries_use_real_generated_id_after_enable': True}


def prepared_prefix_fixture(base, state='Receiving'):
    fixture = Fixture(base)
    fixture.freeze()
    fixture.provision()
    big = next(file for file in fixture.manifest if file['size_bytes'] > CHUNK)
    data = (fixture.bundle / 'blobs' / blob_name(big['sha256'])).read_bytes()
    with fixture.boot('prefix-before-init-retry') as daemon:
        execution_before = tree(fixture.root / 'data/n3/tasks')
        first = fixture.begin(daemon)
        current = fixture.view(fixture.chunk(daemon, first['upload_id'], big['sha256'],
            0, data[:CHUNK]), first['upload_id'], 'Receiving')
        require(next(blob['durable_offset'] for blob in current['blobs']
                     if blob['sha256'] == big['sha256']) == CHUNK,
                'initializer test starts from a genuinely confirmed nonzero durable offset')
        if state in ('Staged', 'Cancelled'):
            fixture.complete_bytes(daemon, first['upload_id'])
            current = fixture.view(fixture.operation(daemon, 'Seal', first['upload_id']),
                                   first['upload_id'], 'Staged')
            if state == 'Cancelled':
                current = fixture.view(fixture.cancel(daemon, first['upload_id']), first['upload_id'], 'Cancelled')
        fixture.assert_no_execution(daemon, execution_before)
    path = fixture.staging / 'uploads' / current['upload_id'] / 'blobs' / blob_name(big['sha256'])
    if state == 'Cancelled':
        require(not path.parent.parent.exists(), 'real physical cleanup precedes terminal zero charge')
        prefix = None
    else:
        require(path.read_bytes() == (data[:CHUNK] if state == 'Receiving' else data),
                'real original durable payload before initializer retry')
        prefix = tree(path.parent)[path.name]
    return fixture, current, path, prefix


def repeated_staging_init_policy_case(base, changed_field, state='Receiving'):
    fixture, current, path, prefix = prepared_prefix_fixture(base, state)
    payload = tree(path.parent)
    before = tree(fixture.root)
    expected = dict(fixture.staging_status, changed=False)
    repeated = fixture.staging_init()
    fixture.check_staging_status(repeated, changed=False)
    require(response_pass(repeated, 'task-provider staging-init') and repeated[1] == expected
            and tree(fixture.root) == before, '§1 original completed init is precisely idempotent with live reservation')
    policy = json.loads(fixture.budget.read_bytes())
    policy[changed_field] += 4096 if changed_field == 'max_reserved_bytes' else 1
    conflict = fixture.base / 'different-valid-budget.json'
    conflict.write_bytes(canonical(policy)); conflict.chmod(0o600)
    denied = fixture.staging_init(conflict)
    require(response_fail(denied, command='task-provider staging-init') and tree(fixture.root) == before,
            '§1 different valid immutable budget fails without changing full authority or original payload')
    repeated = fixture.staging_init()
    fixture.check_staging_status(repeated, changed=False)
    require(response_pass(repeated, 'task-provider staging-init') and repeated[1] == expected
            and tree(fixture.root) == before and tree(path.parent) == payload,
            '§1 conflict preserves original budget changed:false and original payload/terminal absence')
    with fixture.boot('after-budget-conflict') as daemon:
        execution_before = tree(fixture.root / 'data/n3/tasks')
        require(fixture.view(fixture.status(daemon, current['upload_id']), current['upload_id'], state) == current
                and tree(path.parent) == payload,
                'original UploadId/SnapshotRef/state/offset/reservation/payload survive init conflict')
        fixture.assert_no_execution(daemon, execution_before)
    return {'changed_field': changed_field, 'state': state, 'conflict_typed_fail': True,
            'original_budget_repeated_changed_false': True, 'original_record_and_payload_preserved': True}


INIT_DAMAGE_CASES = ('ledger-missing', 'ledger-corrupt', 'policy-missing', 'policy-corrupt',
    'lock-missing', 'lock-replaced', 'marker-missing', 'marker-corrupt',
    'namespace-missing', 'namespace-mode', 'unknown-file')


def repeated_staging_init_damage_case(base, damage):
    fixture, current, path, prefix = prepared_prefix_fixture(base)
    token = fixture.root / 'localapi.token'
    token.unlink(missing_ok=True)
    target = (fixture.staging / 'ledger-v1.json' if damage.startswith('ledger-') else
              fixture.staging / 'policy-v1.json' if damage.startswith('policy-') else
              fixture.staging / 'staging.lock' if damage.startswith('lock-') else fixture.staging_marker)
    if damage.endswith('-missing') and damage != 'namespace-missing':
        target.unlink()
    elif damage.endswith('-corrupt'):
        target.write_bytes(b'{"corrupt":true}')
    elif damage == 'lock-replaced':
        target.rename(fixture.base / 'displaced-original-staging.lock')
        target.write_bytes(b''); target.chmod(0o600)
    elif damage == 'namespace-missing':
        require(fixture.staging_marker.is_file(), 'outer retained Complete marker survives namespace loss')
        shutil.rmtree(fixture.staging)
    elif damage == 'namespace-mode':
        fixture.staging.chmod(0o755)
    elif damage == 'unknown-file':
        extra = fixture.staging / 'unknown-evidence'
        extra.write_bytes(b'preserve unknown evidence'); extra.chmod(0o600)
    else:
        raise AssertionError('unknown controlled init damage case')
    before = tree(fixture.root)
    denied = fixture.staging_init()
    require(response_fail(denied, command='task-provider staging-init') and tree(fixture.root) == before
            and not token.exists(), '§1 repeated initializer must fail closed without repair/reset/token: ' + damage)
    if damage == 'namespace-missing':
        require(not fixture.staging.exists() and fixture.staging_marker.is_file(),
                'retained Complete marker prevents recreating a lost namespace')
    else:
        require(path.exists() and tree(path.parent)[path.name] == prefix,
                'failed initializer preserves original nonzero prefix and inode')
    return {'damage': damage, 'initializer_typed_fail': True, 'remaining_evidence_unchanged': True,
            'no_reprovision_or_token': True}


def cancelled_current_use_case(base, operation, denial):
    """One real provision/record/process per operation and grant denial."""
    fixture = Fixture(base)
    fixture.freeze()
    fixture.provision()
    with fixture.boot('terminal-' + operation + '-' + denial) as daemon:
        execution_before = tree(fixture.root / 'data/n3/tasks')
        original = fixture.begin(daemon, 'terminal-auth-key')
        upload_id = original['upload_id']
        fixture.complete_bytes(daemon, upload_id)
        fixture.view(fixture.operation(daemon, 'Seal', upload_id), upload_id, 'Staged')
        cancelled = fixture.view(fixture.cancel(daemon, upload_id), upload_id, 'Cancelled')
        request = (fixture.begin_request('terminal-auth-key') if operation == 'Begin' else
                   {'schema_version': 1, 'operation': operation, 'upload_id': upload_id})
        result = fixture.check_cancelled_current_use(daemon, cancelled, request, denial)
        fixture.assert_no_execution(daemon, execution_before)
    require(all(child.reaped for child in fixture.children), 'terminal auth process owners reaped')
    return result


def fresh_begin_current_use_case(base, denial):
    """A new index key with available budget, distinct from idempotent Begin."""
    fixture = Fixture(base)
    fixture.freeze()
    fixture.provision()
    with fixture.boot('fresh-Begin-' + denial) as daemon:
        execution_before = tree(fixture.root / 'data/n3/tasks')
        # Actual positive admission and cleanup establish enough capacity. The
        # request under test uses a different, never-before-admitted index key.
        control = fixture.begin(daemon, 'positive-control-key')
        fixture.view(fixture.cancel(daemon, control['upload_id']), control['upload_id'], 'Cancelled')
        request = fixture.begin_request('fresh-current-use-key')
        if denial == 'revoke':
            fixture.grant('revoke')
        else:
            require(denial == 'expired' and time.time() > 1, 'real persisted grant expiry')
            fixture.grant('add', ['--not-after', '1'])
        before = tree(fixture.staging)
        require(response_fail(fixture.request(daemon, request), 'AUTH_DENIED', upload_id=None),
                '§3 new-key Begin rechecks ' + denial + ' current Use with free capacity')
        require(tree(fixture.staging) == before, '§3 denied fresh Begin changes no staging authority')
        fixture.grant('add')
        admitted = fixture.view(fixture.request(daemon, request), state='Receiving')
        require(admitted['upload_id'] != control['upload_id']
                and admitted['snapshot'] == fixture.snapshot and admitted['reserved_bytes'] == fixture.charge,
                '§3 exact formerly-denied new-key request is otherwise admissible after restoration')
        fixture.view(fixture.cancel(daemon, admitted['upload_id']), admitted['upload_id'], 'Cancelled')
        fixture.assert_no_execution(daemon, execution_before)
    require(all(child.reaped for child in fixture.children), 'fresh Begin auth process owners reaped')
    return {'operation': 'fresh-Begin', 'denial': denial, 'error_code': 'AUTH_DENIED',
            'new_key_and_available_capacity': True, 'same_request_restored_success': True,
            'denied_staging_unchanged': True}


def observe():
    facts = dict.fromkeys(FIELDS, False)
    with tempfile.TemporaryDirectory(prefix='n312-staging-') as temporary:
        fixture = Fixture(Path(temporary) / 'main')
        try:
            fixture.freeze()
            facts['fixed_commit_source_readonly'] = True
            facts['immutable_bundle_verified'] = True
            original_bundle = tree(fixture.bundle)
            fixture.observations['existing_output_controls'] = [existing_output_case(
                Path(temporary) / ('existing-' + kind), kind) for kind in OUTPUT_CASES]
            fixture.observations['repeatable_selection_controls'] = [selection_freeze_case(
                Path(temporary) / ('selection-' + case), case) for case in SELECTION_CASES]
            fixture.provision()
            before = tree(fixture.staging)
            repeated = fixture.staging_init()
            require(response_pass(repeated) and repeated[1].get('changed') is False
                and tree(fixture.staging) == before, '§1 repeated staging-init zero writes')
            first_owner = Daemon(fixture, 'first')
            fixture.children.append(first_owner)
            try:
                first_owner.await_ready()
                execution_before = tree(fixture.root / 'data/n3/tasks')
                fixture.assert_no_execution(first_owner, execution_before)
                first = fixture.begin(first_owner)
                upload_id = first['upload_id']
                big = next(file for file in fixture.manifest if file['size_bytes'] > CHUNK)
                data = (fixture.bundle / 'blobs' / blob_name(big['sha256'])).read_bytes()
                view = fixture.view(fixture.chunk(first_owner, upload_id, big['sha256'],
                                    0, data[:CHUNK]), upload_id, 'Receiving')
                require(next(b for b in view['blobs'] if b['sha256'] == big['sha256'])[
                    'durable_offset'] == CHUNK, '§5 confirmed continuous prefix')
                path = fixture.staging / 'uploads' / upload_id / 'blobs' / blob_name(big['sha256'])
                prefix = tree(path.parent)[blob_name(big['sha256'])]
                require(path.read_bytes() == data[:CHUNK], '§5 durable bytes before SIGKILL')
                staged_before_get = tree(fixture.staging)
                fixture.view(fixture.status(first_owner, upload_id), upload_id, 'Receiving')
                require(tree(fixture.staging) == staged_before_get, '§4 Get zero staging writes')
                fixture.assert_no_execution(first_owner, execution_before)
            finally:
                first_owner.stop(kill=True)
            with fixture.boot('restart') as daemon:
                execution_before = tree(fixture.root / 'data/n3/tasks')
                fixture.assert_no_execution(daemon, execution_before)
                restored = fixture.view(fixture.status(daemon, upload_id), upload_id, 'Receiving')
                require(restored == view and tree(path.parent)[blob_name(big['sha256'])] == prefix,
                        '§5 SIGKILL original UploadId/offset/charge/prefix inode')
                facts['restart_prefix_preserved'] = True
                retry = fixture.view(fixture.chunk(daemon, upload_id, big['sha256'], 0,
                    data[:CHUNK]), upload_id, 'Receiving')
                require(retry == restored and tree(path.parent)[blob_name(big['sha256'])] == prefix,
                        '§5 confirmed same-range retry preserves bytes and inode')
                repeated = fixture.begin(daemon)
                require(repeated == restored, '§3 same key original progress')
                facts['same_key_preserved'] = True
                conflict = fixture.request(daemon, fixture.begin_request(
                    snapshot=fixture.different_snapshot()), 'key_conflict')
                require(response_fail(conflict, 'IDEMPOTENCY_CONFLICT'), '§3 same key changed content')
                facts['key_conflict_denied'] = True
                bounded = fixture.request(daemon, fixture.begin_request('second-key'), 'budget_bound')
                require(response_fail(bounded, 'CAPACITY_UNAVAILABLE'), '§4 exact limit rejects new upload')
                facts['budget_bound'] = True
                resume_before = fixture.check_receiving_chunk_current_use(daemon, upload_id)
                resume_offset = next(blob['durable_offset'] for blob in resume_before['blobs']
                                     if blob['sha256'] == big['sha256'])
                require(0 < resume_offset < big['size_bytes'],
                        '§6 CLI still has a nonzero prefix and remaining bytes after grant controls')
                # The formal CLI must resume the original Receiving record at
                # its nonzero durable offset. Do not pre-complete it via HTTP.
                completed = fixture.view(fixture.upload(daemon), upload_id, 'Staged')
                final_blob = tree(path.parent)[blob_name(big['sha256'])]
                require(completed['snapshot'] == restored['snapshot']
                        and completed['reserved_bytes'] == restored['reserved_bytes']
                        and final_blob[:2] == prefix[:2]
                        and path.read_bytes()[:CHUNK] == data[:CHUNK]
                        and path.read_bytes() == data,
                        '§6 actual CLI resumes nonzero prefix on original inode/id/snapshot/charge')
                fixture.observations['cli_nonzero_prefix_resume'] = {
                    'begin_state': resume_before['state'], 'begin_durable_offset': resume_offset,
                    'original_upload_id_preserved': True, 'original_blob_inode_preserved': True,
                    'original_prefix_bytes_preserved': True, 'final_state': completed['state']}
                # Staged confirmed-range retry remains a legal authorized path.
                for denial in ('revoke', 'expired'):
                    require(fixture.view(fixture.chunk(daemon, upload_id, big['sha256'], CHUNK,
                        data[CHUNK:]), upload_id, 'Staged') == completed,
                        '§3 authorized Staged confirmed retry returns original view')
                    if denial == 'revoke':
                        fixture.grant('revoke')
                    else:
                        require(time.time() > 1, 'real host clock exceeds persisted not-after')
                        fixture.grant('add', ['--not-after', '1'])
                    before_denial = tree(fixture.staging)
                    for operation in ('Get', 'Seal', 'Cancel'):
                        require(response_fail(fixture.operation(daemon, operation, upload_id),
                                    'AUTH_DENIED', upload_id=upload_id),
                                '§3 current ' + denial + ' Use denies Staged ' + operation)
                        require(tree(fixture.staging) == before_denial,
                                '§3 each denied Staged operation leaves staging unchanged')
                    require(response_fail(fixture.chunk(daemon, upload_id, big['sha256'], CHUNK,
                        data[CHUNK:]), 'AUTH_DENIED', upload_id=upload_id),
                        '§3 current Use gates legal Staged confirmed retry')
                    require(tree(fixture.staging) == before_denial,
                            '§3 denied Staged confirmed retry zero staging writes')
                    require(response_fail(fixture.request(daemon, fixture.begin_request()),
                                          'AUTH_DENIED', upload_id=None),
                            '§3 current Use gates Staged same-key Begin')
                    require(tree(fixture.staging) == before_denial,
                            '§3 denied Staged Begin zero staging writes')
                    fixture.grant('add')
                    require(fixture.view(fixture.chunk(daemon, upload_id, big['sha256'], CHUNK,
                        data[CHUNK:]), upload_id, 'Staged') == completed,
                        '§3 restored Staged confirmed retry is a valid success control')
                    require(fixture.view(fixture.status(daemon, upload_id), upload_id, 'Staged') == completed
                        and fixture.view(fixture.operation(daemon, 'Seal', upload_id), upload_id, 'Staged') == completed,
                        '§3 restored Staged Get/Seal return original record')
                repeated_complete = fixture.view(fixture.upload(daemon), upload_id, 'Staged')
                require(repeated_complete == completed, '§6 already Staged CLI retry preserves original record')
                require(tree(fixture.bundle) == original_bundle, '§6 upload leaves immutable bundle untouched')
                fixture.view(fixture.status(daemon, upload_id), upload_id, 'Staged')
                fixture.view(fixture.operation(daemon, 'Seal', upload_id), upload_id, 'Staged')
                facts['authenticated_upload'] = completed['snapshot'] == fixture.snapshot
                fixture.assert_no_execution(daemon, execution_before)
                cancelled = fixture.view(fixture.cancel(daemon, upload_id), upload_id, 'Cancelled')
                require(not path.parent.parent.exists(), '§5 physically deleted upload before charge zero')
                require(fixture.view(fixture.cancel(daemon, upload_id), upload_id, 'Cancelled') == cancelled,
                        '§5 cancel idempotent')
                require(fixture.view(fixture.request(daemon, fixture.begin_request()), upload_id,
                    'Cancelled') == cancelled, '§4 unexpired tombstone prevents resurrection')
                fresh = fixture.begin(daemon, 'after-cancel')
                require(fresh['upload_id'] != upload_id, '§4 released reservation admits new upload')
                fixture.view(fixture.cancel(daemon, fresh['upload_id']), fresh['upload_id'], 'Cancelled')
                facts['cancel_physical_cleanup'] = True
                fixture.assert_no_execution(daemon, execution_before)
            # Each terminal operation/denial has its own genuine provider state;
            # a quick tombstone return must not bypass current Use authorization.
            terminal_controls = []
            for operation in ('Get', 'Cancel', 'Begin'):
                for denial in ('revoke', 'expired'):
                    terminal_controls.append(cancelled_current_use_case(
                        Path(temporary) / ('terminal-' + operation + '-' + denial), operation, denial))
            fresh_controls = [fresh_begin_current_use_case(
                Path(temporary) / ('fresh-Begin-' + denial), denial) for denial in ('revoke', 'expired')]
            fixture.observations['cancelled_current_use_controls'] = terminal_controls
            fixture.observations['fresh_begin_current_use_controls'] = fresh_controls
            facts['current_grant_enforced'] = True
            facts['no_task_session_engine'] = True
            fixture.observations['disabled_staging_controls'] = [disabled_staging_case(
                Path(temporary) / ('disabled-' + operation), operation)
                for operation in ('upload', 'status', 'cancel')]
            fixture.observations['immutable_init_budget_control'] = repeated_staging_init_policy_case(
                Path(temporary) / 'budget-conflict-init', 'max_reserved_bytes')
            fixture.observations['lost_ledger_initializer_control'] = repeated_staging_init_damage_case(
                Path(temporary) / 'lost-ledger-init', 'ledger-missing')
            facts['formal_staging_init'] = True
            # Both damage cases begin with genuine completed provisioning and upload.
            for kind in ('missing-ledger', 'damaged-prefix'):
                damaged = Fixture(Path(temporary) / kind)
                damaged.freeze()
                damaged.provision()
                with damaged.boot(kind + '-prepare') as daemon:
                    upload = damaged.begin(daemon)
                    big = next(file for file in damaged.manifest if file['size_bytes'] > CHUNK)
                    data = (damaged.bundle / 'blobs' / blob_name(big['sha256'])).read_bytes()
                    damaged.view(damaged.chunk(daemon, upload['upload_id'], big['sha256'], 0,
                                              data[:CHUNK]), upload['upload_id'], 'Receiving')
                token = damaged.root / 'localapi.token'
                token.unlink(missing_ok=True)
                if kind == 'missing-ledger':
                    (damaged.staging / 'ledger-v1.json').unlink()
                else:
                    path = damaged.staging / 'uploads' / upload['upload_id'] / 'blobs' / blob_name(big['sha256'])
                    with path.open('r+b') as stream:
                        stream.write(bytes([data[0] ^ 1]))
                before_damage_boot = tree(damaged.root)
                with damaged.boot(kind + '-denied', expected=False):
                    pass
                require(not token.exists() and tree(damaged.root) == before_damage_boot,
                        '§5 damaged preflight zero writes/no token/no reset')
                require(all(child.reaped for child in damaged.children), 'damaged children reaped')
            facts['damaged_boot_denied'] = True
            facts['decoy_untouched'] = not list(fixture.decoy.iterdir())
            facts['shutdown_reaped'] = all(child.reaped for child in fixture.children)
            return {'verdict': 'PASS' if all(facts.values()) else 'FAIL', **facts,
                'observations': fixture.observations, 'evidence_scope': 'local Linux authenticated '
                'snapshot staging; no Task execution or remote peer claim'}
        except (AssertionError, OSError, ValueError, KeyError, TypeError,
                subprocess.SubprocessError, http.client.HTTPException) as error:
            return {'verdict': 'FAIL', **facts, 'failure_class': type(error).__name__,
                'reason': str(error) if isinstance(error, AssertionError) else 'observation failed',
                'observations': fixture.observations}


if __name__ == '__main__':
    try:
        result = observe()
    except (AssertionError, OSError, ValueError, KeyError, TypeError) as error:
        result = {'verdict': 'FAIL', **dict.fromkeys(FIELDS, False),
                  'failure_class': type(error).__name__,
                  'reason': str(error) if isinstance(error, AssertionError) else 'observer setup failed'}
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result['verdict'] == 'PASS' else 1)

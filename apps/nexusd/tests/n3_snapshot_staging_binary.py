"""Run: python3 apps/nexusd/tests/n3_snapshot_staging_binary.py -v

Real binaries only. A previous binary runs these tests as compiling/runnable RED;
no skips, stubs that fake PASS, or provider state seed. Expected values are from
N3-12 contract §§1-8 and the independent requester export SHA manifest.
"""
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

VERIFIERS = Path(__file__).resolve().parents[3] / 'engineering/verifiers'
sys.path.insert(0, str(VERIFIERS))
import n3_snapshot_staging as observer


class SnapshotBinaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='n312-binary-')
        self.addCleanup(self.temporary.cleanup)
        self.fixture = observer.Fixture(Path(self.temporary.name) / 'fixture')

    def configured(self, grant=True):
        self.fixture.freeze()
        self.fixture.provision(grant=grant)
        return self.fixture

    def boot(self, fixture=None, label='test', expected=True):
        owner = self.enterContext((fixture or self.fixture).boot(label, expected))
        return owner

    def assert_denied_unchanged(self, daemon, request, error=None, raw=None):
        before = observer.tree(self.fixture.staging)
        result = self.fixture.request(daemon, request, raw=raw)
        self.assertTrue(observer.response_fail(result, error), result)
        self.assertEqual(observer.tree(self.fixture.staging), before, 'denial mutated staging')
        return result

    def active(self):
        fixture = self.configured()
        daemon = self.boot()
        view = fixture.begin(daemon)
        return fixture, daemon, view

    def big(self):
        file = next(file for file in self.fixture.manifest if file['size_bytes'] > observer.CHUNK)
        return file, (self.fixture.bundle / 'blobs' / observer.blob_name(file['sha256'])).read_bytes()

    def test_readonly_observer_detects_same_bytes_rewrite_and_excludes_read_atime(self):
        root = self.fixture.base / 'readonly-control'
        root.mkdir(mode=0o700)
        path = root / 'source-object'
        original = b'independent same-byte rewrite control\n'
        path.write_bytes(original)
        os.utime(path, ns=(1_000_000_000, 1_000_000_000))
        before = observer.tree(root)
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(observer.tree(root), before, 'read-only control must ignore atime')
        path.write_bytes(original)
        rewritten = observer.tree(root)
        self.assertEqual(rewritten['source-object'][:6], before['source-object'][:6],
                         'control preserves inode, mode, links, length and digest')
        self.assertNotEqual(rewritten['source-object'][6:], before['source-object'][6:],
                            'mtime/ctime must expose a same-byte write')
        self.assertNotEqual(rewritten, before, 'same-byte source writes must fail zero-write oracle')
        # Restoring mtime still cannot conceal the changed ctime.
        os.utime(path, ns=(path.stat().st_atime_ns, before['source-object'][6]))
        restored_mtime = observer.tree(root)
        self.assertEqual(restored_mtime['source-object'][:7], before['source-object'][:7])
        self.assertNotEqual(restored_mtime['source-object'][7], before['source-object'][7])
        self.assertNotEqual(restored_mtime, before, 'ctime independently detects mtime restoration')

    def test_fail_observer_requires_actual_command_kind_and_staging_phase_fields(self):
        import copy
        error = {'code': 'INVALID_REQUEST', 'reason': 'independent envelope control', 'retryable': False}
        freeze = {'schema_version': 1, 'verdict': 'FAIL', 'command': 'snapshot freeze', 'error': error}
        staging = dict(freeze, command='task-provider staging-init', phase='validate',
                       mutation_may_have_applied=False)
        snapshot = {'schema_version': 1, 'verdict': 'FAIL', 'error': error, 'upload_id': 'original-id'}
        cases = ((freeze, 'snapshot freeze'), (staging, 'task-provider staging-init'), (snapshot, None))
        for payload, command in cases:
            with self.subTest(command=command):
                self.assertTrue(observer.response_fail((0, payload), command=command))
                for other, other_command in cases:
                    if other_command != command:
                        self.assertFalse(observer.response_fail((0, other), command=command),
                                         'a different command/envelope cannot substitute for a refusal')
        for field in ('phase', 'mutation_may_have_applied'):
            damaged = copy.deepcopy(staging); del damaged[field]
            self.assertFalse(observer.response_fail((0, damaged), command='task-provider staging-init'))
        for field, value in (('phase', ''), ('phase', 1), ('mutation_may_have_applied', 0)):
            damaged = copy.deepcopy(staging); damaged[field] = value
            self.assertFalse(observer.response_fail((0, damaged), command='task-provider staging-init'))
        self.assertTrue(observer.response_fail((0, snapshot), upload_id='original-id'))
        self.assertFalse(observer.response_fail((0, snapshot), upload_id='different-id'))
        self.assertTrue(observer.response_fail((0, dict(snapshot, upload_id=None)), upload_id='original-id'))
        for payload, command in cases:
            damaged = dict(payload, unexpected='field')
            self.assertFalse(observer.response_fail((0, damaged), command=command))

    def test_independent_requester_selection_controls_old_commit_and_normalizes_sets(self):
        baseline, reference, _ = observer.requester_selection(self.fixture, ['.'], ['private'], ['scripts/run.sh'])
        self.assertEqual(baseline, self.fixture.metadata['expected_manifest'])
        self.assertEqual(reference, self.fixture.metadata['expected_snapshot'])
        expected = {
            'include-many': (['inputs/data.bin', 'inputs/empty.txt', 'scripts/run.sh'], ['scripts/run.sh']),
            'exclude-many': (['inputs/empty.txt', 'scripts/run.sh'], ['scripts/run.sh']),
            'executable-many': (['inputs/data.bin', 'inputs/empty.txt', 'scripts/run.sh'], ['inputs/empty.txt', 'scripts/run.sh']),
            'all-many': (['inputs/empty.txt', 'scripts/run.sh'], ['inputs/empty.txt', 'scripts/run.sh']),
            'all-reversed': (['inputs/empty.txt', 'scripts/run.sh'], ['inputs/empty.txt', 'scripts/run.sh']),
            'optional-omitted': (['scripts/run.sh'], []),
        }
        references = {}
        for case, rules in observer.SELECTION_CASES.items():
            manifest, reference, _ = observer.requester_selection(self.fixture, *rules)
            self.assertEqual([file['path'] for file in manifest], expected[case][0])
            self.assertEqual([file['path'] for file in manifest if file['executable']], expected[case][1])
            references[case] = reference
        self.assertEqual(references['all-many'], references['all-reversed'])
        dangling = self.fixture.base / 'dangling-control'
        dangling.symlink_to(self.fixture.base / 'absent-control')
        image = observer.tree(dangling)
        self.assertEqual(set(image), {'.'})
        self.assertTrue(observer.stat.S_ISLNK(image['.'][2]))
        self.assertEqual(image['.'][5], observer.sha(os.readlink(dangling).encode()))

    def test_freeze_repeated_distinct_selection_rules_each_and_combined_succeed(self):
        for case in observer.SELECTION_CASES:
            with self.subTest(case=case):
                result = observer.selection_freeze_case(self.fixture.base / case, case)
                self.assertTrue(result['source_unchanged'])
                self.assertTrue(result['private_complete_bundle'])
        # Host paths with spaces and absent --json retain the same formal bundle
        # semantics; no particular human-readable stdout grammar is invented.
        observer.selection_freeze_case(self.fixture.base / 'source and output with spaces',
                                       'optional-omitted', json_output=False)

    def test_freeze_every_existing_destination_type_is_output_exists_and_unchanged(self):
        for kind in observer.OUTPUT_CASES:
            with self.subTest(kind=kind):
                result = observer.existing_output_case(self.fixture.base / kind, kind)
                self.assertTrue(result['output_exists'])
                self.assertTrue(result['destination_and_decoy_preserved'])
                self.assertTrue(result['source_unchanged'])

    def test_freeze_selects_old_commit_and_leaves_all_source_inodes_bytes_modes(self):
        self.fixture.freeze()
        self.assertNotEqual(self.fixture.snapshot['commit_id'],
                            self.fixture.metadata['facts']['new_commit'])
        self.fixture.verify_bundle()

    def test_freeze_missing_anchor_does_not_create_workspace_or_fallback_to_head(self):
        anchor = self.fixture.source / 'data/workspaces' / self.fixture.workspace / 'state_root'
        anchor.unlink()
        before = observer.tree(self.fixture.source)
        result = self.fixture.invoke(self.fixture.cli, self.fixture.freeze_args(), 'missing_anchor')
        self.assertTrue(observer.response_fail(result, command='snapshot freeze'), result)
        self.assertEqual(observer.tree(self.fixture.source), before)
        self.assertFalse(self.fixture.bundle.exists())

    def test_freeze_unknown_commit_does_not_fallback_to_current_head(self):
        args = self.fixture.freeze_args()
        args[args.index('--commit') + 1] = '0123456789abcdef'
        before = observer.tree(self.fixture.source)
        result = self.fixture.invoke(self.fixture.cli, args, 'unknown_commit')
        self.assertTrue(observer.response_fail(result, 'INPUT_UNAVAILABLE', command='snapshot freeze'), result)
        self.assertEqual(observer.tree(self.fixture.source), before)
        self.assertFalse(self.fixture.bundle.exists())

    def test_freeze_existing_output_no_replace_preserves_decoy(self):
        self.fixture.bundle.mkdir(mode=0o700)
        (self.fixture.bundle / 'user-data').write_bytes(b'preserve user output\n')
        before = observer.tree(self.fixture.bundle)
        result = self.fixture.invoke(self.fixture.cli, self.fixture.freeze_args(), 'existing_output')
        self.assertTrue(observer.response_fail(result, 'OUTPUT_EXISTS', command='snapshot freeze'), result)
        self.assertEqual(observer.tree(self.fixture.bundle), before)

    def test_pure_arguments_before_source_credentials_connect_xdg_or_output_io(self):
        import socket
        fifo = self.fixture.base / 'token-fifo'
        os.mkfifo(fifo, 0o600)
        source = self.fixture.base / 'source-fifo'
        os.mkfifo(source, 0o600)
        xdg = self.fixture.base / 'xdg-private'
        xdg.mkdir(mode=0o700)
        self.fixture.env.update(NEXUS_LOCALAPI_TOKEN_FILE=str(fifo), XDG_RUNTIME_DIR=str(xdg))
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(32)
        listener.settimeout(0.05)
        self.addCleanup(listener.close)
        addr = '127.0.0.1:' + str(listener.getsockname()[1])
        cases = []
        valid = self.fixture.freeze_args()
        # Any eager source read blocks: make the config directory a FIFO, and
        # also its necessary workspace.toml a FIFO in a real directory.
        source_config = self.fixture.source / 'workspace.toml'
        source_config.unlink()
        os.mkfifo(source_config, 0o600)
        for option, value in (('--include', '.'), ('--exclude', 'private'),
                              ('--executable', 'scripts/run.sh'), ('--bogus', 'x'), ('--json', None)):
            cases.append((self.fixture.cli, valid + [option] + ([] if value is None else [value])))
        for option in ('--config', '--commit', '--output'):
            cases.append((self.fixture.cli, valid + [option, valid[valid.index(option) + 1]]))
        for option in ('--include', '--exclude', '--executable', '--commit', '--output'):
            cases.append((self.fixture.cli, valid + [option]))
        for option in ('--config', '--output'):
            for path in ('relative', '/tmp/../invalid'):
                args = list(valid)
                args[args.index(option) + 1] = path
                cases.append((self.fixture.cli, args))
        trap_args = list(valid)
        trap_args[trap_args.index('--config') + 1] = source
        cases.append((self.fixture.cli, trap_args + ['--bogus', 'x']))
        upload = ['snapshot', 'upload', '--bundle', source, '--provider', self.fixture.provider,
                  '--resource', self.fixture.resource, '--key', 'a', '--addr', addr, '--json']
        for target in ('192.0.2.1:9', 'example.invalid:9'):
            args = list(upload)
            args[args.index('--addr') + 1] = target
            cases.append((self.fixture.cli, args))
        for extra in (['--provider', 'duplicate'], ['--resource', 'duplicate'], ['--key', 'again'],
                      ['--addr', addr], ['--socket', str(self.fixture.base / 'peer.sock')],
                      ['--bogus', 'x'], ['--bundle', str(source)], ['--json']):
            cases.append((self.fixture.cli, upload + extra))
        no_provider = list(upload)
        pos = no_provider.index('--provider')
        del no_provider[pos:pos + 2]
        cases.append((self.fixture.cli, no_provider))
        for verb in ('status', 'cancel'):
            valid_query = ['snapshot', verb, 'valid-upload', '--addr', addr, '--json']
            for extra in (['--addr', addr], ['--socket', str(self.fixture.base / 'peer.sock')],
                          ['--bogus', 'x'], ['--json'], ['--addr']):
                cases.append((self.fixture.cli, valid_query + extra))
            cases.append((self.fixture.cli, ['snapshot', verb, '--addr', addr]))
        cases += [(self.fixture.cli, ['snapshot', 'upload', '--key', 'x']),
                  (self.fixture.daemon, ['task-provider', 'staging-init', '--config', source,
                    '--budget', source, '--bogus', 'x'])]
        staging_init = ['task-provider', 'staging-init', '--config', source, '--budget', source, '--json']
        for extra in (['--config', source], ['--budget', source], ['--json'], ['--budget']):
            cases.append((self.fixture.daemon, staging_init + extra))
        cases.append((self.fixture.cli, ['snapshot', 'status', 'valid-upload', '--json', '--json']))
        def omit_pair(args, option):
            args = list(args); index = args.index(option); del args[index:index + 2]
            return args
        for option in ('--config', '--commit', '--include', '--output'):
            cases.append((self.fixture.cli, omit_pair(valid, option)))
        cases.append((self.fixture.cli, valid[:2] + valid[3:]))
        for option in ('--bundle', '--provider', '--resource', '--key'):
            cases.append((self.fixture.cli, omit_pair(upload, option)))
        for option in ('--config', '--budget'):
            cases.append((self.fixture.daemon, omit_pair(staging_init, option)))
        for binary, template, options in ((self.fixture.cli, upload, ('--bundle',)),
                (self.fixture.daemon, staging_init, ('--config', '--budget'))):
            for option in options:
                for bad_path in ('relative', '/tmp/../invalid'):
                    args = list(template); args[args.index(option) + 1] = bad_path
                    cases.append((binary, args))
        for template in (upload, ['snapshot', 'status', 'valid-upload', '--addr', addr, '--json'],
                         ['snapshot', 'cancel', 'valid-upload', '--addr', addr, '--json']):
            for target in ('192.0.2.1:9', 'example.invalid:9'):
                args = list(template); args[args.index('--addr') + 1] = target
                cases.append((self.fixture.cli, args))
            for bad_socket in ('relative.sock', '/tmp/../bad.sock'):
                args = list(template); index = args.index('--addr')
                args[index:index + 2] = ['--socket', bad_socket]
                cases.append((self.fixture.cli, args))
        before = observer.tree(self.fixture.base)
        for index, (binary, args) in enumerate(cases):
            with self.subTest(args=[str(arg) for arg in args]):
                result = self.fixture.invoke(binary, args, 'bad_syntax_' + str(index), timeout=3)
                self.assertEqual(result[0], 2)
                self.assertEqual(observer.tree(self.fixture.base), before)
                with self.assertRaises(socket.timeout, msg='bad syntax connected to peer before validation'):
                    client, _ = listener.accept()
                    client.close()
        self.assertEqual(observer.tree(xdg), {'.': before['xdg-private']})

    def test_nonexistent_include_rejected_without_source_or_output_mutation(self):
        args = self.fixture.freeze_args()
        args[args.index('--include') + 1] = 'no-selected-path'
        before = observer.tree(self.fixture.source)
        result = self.fixture.invoke(self.fixture.cli, args, 'missing-selection')
        self.assertTrue(observer.response_fail(result, command='snapshot freeze'), result)
        self.assertEqual(observer.tree(self.fixture.source), before)
        self.assertFalse(self.fixture.bundle.exists())

    def test_source_anchor_and_cas_reject_symlink_hardlink_fifo_before_read(self):
        for kind, target in ((kind, target) for kind in ('symlink', 'hardlink', 'fifo')
                             for target in ('anchor', 'cas')):
            with self.subTest(kind=kind, target=target):
                base = self.fixture.base / (kind + '-' + target)
                fixture = observer.Fixture(base)
                anchor = (fixture.source / 'data/workspaces' / fixture.workspace / 'state_root'
                          if target == 'anchor' else fixture.source / 'data/cas' /
                          fixture.metadata['facts']['state_root'])
                original = anchor.read_bytes()
                anchor.unlink()
                external = base / 'external'
                external.write_bytes(original)
                if kind == 'symlink':
                    anchor.symlink_to(external)
                elif kind == 'hardlink':
                    os.link(external, anchor)
                else:
                    os.mkfifo(anchor, 0o600)
                before = observer.tree(fixture.source)
                result = fixture.invoke(fixture.cli, fixture.freeze_args(), kind, timeout=3)
                self.assertTrue(observer.response_fail(result, command='snapshot freeze'), result)
                self.assertEqual(observer.tree(fixture.source), before)
                self.assertFalse(fixture.bundle.exists())

    def test_changed_legacy_locator_bytes_fail_integrity_without_source_repair(self):
        cas = self.fixture.source / 'data/cas'
        file = cas / self.fixture.metadata['facts']['state_root']
        file.write_bytes(file.read_bytes() + b'\n')
        before = observer.tree(self.fixture.source)
        result = self.fixture.invoke(self.fixture.cli, self.fixture.freeze_args(), 'locator_hash')
        self.assertTrue(observer.response_fail(result, 'INPUT_INTEGRITY_FAILED', command='snapshot freeze'), result)
        self.assertEqual(observer.tree(self.fixture.source), before)
        self.assertFalse(self.fixture.bundle.exists())

    def test_source_limits_checked_before_parsing_or_unbounded_allocation(self):
        # Observable size refusal and zero mutation; this binary test does not
        # instrument allocations or certify an internal parsing order.
        targets = [('config', 65_537), ('anchor', 257), ('state', 8 * 1024**2 + 1),
                   ('manifest', 8 * 1024**2 + 1), ('content', 64 * 1024**2 + 1)]
        for kind, length in targets:
            with self.subTest(kind=kind, length=length):
                fixture = observer.Fixture(self.fixture.base / ('limit-' + kind))
                if kind == 'config':
                    path = fixture.source / 'workspace.toml'
                elif kind == 'anchor':
                    path = fixture.source / 'data/workspaces' / fixture.workspace / 'state_root'
                elif kind == 'state':
                    path = fixture.source / 'data/cas' / fixture.metadata['facts']['state_root']
                elif kind == 'manifest':
                    path = fixture.source / 'data/cas' / fixture.metadata['facts']['old_manifest']
                else:
                    digest = next(file['sha256'] for file in fixture.manifest if file['size_bytes'] > observer.CHUNK)
                    cas = fixture.source / 'data/cas'
                    path = next(path for path in cas.iterdir() if observer.digest(path.read_bytes()) == digest)
                # Deliberately oversized actual source object, never provider state seed.
                with path.open('r+b') as stream:
                    stream.truncate(length)
                before = observer.tree(fixture.source)
                result = fixture.invoke(fixture.cli, fixture.freeze_args(), kind, timeout=10)
                self.assertTrue(observer.response_fail(result, 'CAPACITY_UNAVAILABLE', command='snapshot freeze'), result)
                self.assertEqual(observer.tree(fixture.source), before)
                self.assertFalse(fixture.bundle.exists())

    def test_source_group_writable_config_anchor_cas_is_rejected_without_chmod_repair(self):
        for target in ('config', 'anchor', 'cas'):
            with self.subTest(target=target):
                fixture = observer.Fixture(self.fixture.base / ('writable-' + target))
                path = (fixture.source / 'workspace.toml' if target == 'config' else
                        fixture.source / 'data/workspaces' / fixture.workspace / 'state_root'
                        if target == 'anchor' else fixture.source / 'data/cas' /
                        fixture.metadata['facts']['state_root'])
                path.chmod(0o664)
                before = observer.tree(fixture.source)
                result = fixture.invoke(fixture.cli, fixture.freeze_args(), target)
                self.assertTrue(observer.response_fail(result, command='snapshot freeze'), result)
                self.assertEqual(observer.tree(fixture.source), before)
                self.assertFalse(fixture.bundle.exists())

    def test_staging_init_requires_original_completed_provider_and_is_idempotent(self):
        before = observer.tree(self.fixture.root)
        self.assertTrue(observer.response_fail(self.fixture.staging_init(),
            command='task-provider staging-init'))
        self.assertEqual(observer.tree(self.fixture.root), before)
        self.fixture.provision()
        before = observer.tree(self.fixture.staging)
        result = self.fixture.staging_init()
        self.assertTrue(observer.response_pass(result))
        self.assertIs(result[1].get('changed'), False)
        self.assertEqual(observer.tree(self.fixture.staging), before)

    def test_disabled_snapshot_entries_never_provision_and_explicit_init_restart_enables_them(self):
        for operation in ('upload', 'status', 'cancel', 'Begin', 'PutChunk', 'Get', 'Seal', 'Cancel'):
            with self.subTest(operation=operation):
                result = observer.disabled_staging_case(self.fixture.base / ('disabled-' + operation), operation)
                self.assertTrue(result['no_implicit_provision'])
                self.assertTrue(result['explicit_init_then_restart'])
                self.assertTrue(result['same_bundle_key_begin_enabled'])
                self.assertTrue(result['queries_use_real_generated_id_after_enable'])

    def test_completed_staging_init_rejects_different_valid_budgets_preserving_original_record(self):
        for state in ('Receiving', 'Staged', 'Cancelled'):
            for field in ('max_reserved_bytes', 'max_active_uploads'):
                with self.subTest(state=state, changed_field=field):
                    result = observer.repeated_staging_init_policy_case(
                        self.fixture.base / (state + '-' + field), field, state)
                    self.assertTrue(result['conflict_typed_fail'])
                    self.assertTrue(result['original_budget_repeated_changed_false'])
                    self.assertTrue(result['original_record_and_payload_preserved'])

    def test_completed_staging_init_fails_closed_on_each_lost_or_damaged_authority(self):
        for damage in observer.INIT_DAMAGE_CASES:
            with self.subTest(damage=damage):
                result = observer.repeated_staging_init_damage_case(self.fixture.base / damage, damage)
                self.assertTrue(result['initializer_typed_fail'])
                self.assertTrue(result['remaining_evidence_unchanged'])
                self.assertTrue(result['no_reprovision_or_token'])

    def test_policy_rejects_nonexact_unknown_duplicate_limits_without_staging_writes(self):
        self.fixture.invoke(self.fixture.daemon, ['task-provider', 'init', '--config', self.fixture.root,
            '--provider', self.fixture.provider, '--workspace', self.fixture.workspace,
            '--capacity', self.fixture.policy, '--json'], 'init')
        invalid = [b'{"schema_version":1,"max_reserved_bytes":16777216.0,"max_active_uploads":1}',
            b'{"schema_version":1,"max_reserved_bytes":16777216,"max_reserved_bytes":99999999,"max_active_uploads":1}',
            observer.canonical({'schema_version': 1, 'max_reserved_bytes': observer.GLOBAL_CHARGE - 1,
                                'max_active_uploads': 1}),
            observer.canonical({'schema_version': 1, 'max_reserved_bytes': 2**53,
                                'max_active_uploads': 1}),
            observer.canonical({'schema_version': 1, 'max_reserved_bytes': observer.GLOBAL_CHARGE,
                                'max_active_uploads': 9}),
            observer.canonical({'schema_version': 1, 'max_reserved_bytes': observer.GLOBAL_CHARGE,
                                'max_active_uploads': 0}),
            observer.canonical({'schema_version': 1, 'max_reserved_bytes': observer.GLOBAL_CHARGE,
                                'max_active_uploads': 1, 'principal': 'caller'})]
        before = observer.tree(self.fixture.root)
        for policy in invalid:
            with self.subTest(policy=policy):
                self.fixture.budget.write_bytes(policy)
                self.assertTrue(observer.response_fail(self.fixture.staging_init(),
            command='task-provider staging-init'))
                self.assertEqual(observer.tree(self.fixture.root), before)

    def test_budget_exact_formula_one_byte_below_then_exact_limit(self):
        fixture = self.fixture
        fixture.freeze()
        budget = json.loads(fixture.budget.read_bytes())
        budget['max_reserved_bytes'] -= 1
        fixture.budget.write_bytes(observer.canonical(budget))
        fixture.provision()
        daemon = self.boot()
        self.assert_denied_unchanged(daemon, fixture.begin_request(), 'CAPACITY_UNAVAILABLE')
        exact = observer.Fixture(fixture.base / 'exact')
        exact.freeze()
        exact.provision()
        exact_daemon = self.boot(exact, 'exact')
        view = exact.begin(exact_daemon)
        self.assertEqual(view['reserved_bytes'], fixture.charge)

    def test_eight_live_reservations_ninth_denied_and_cancel_admits_replacement(self):
        fixture = self.fixture
        fixture.freeze()
        fixture.budget.write_bytes(observer.canonical({'schema_version': 1,
            'max_reserved_bytes': observer.GLOBAL_CHARGE + 10 * fixture.charge,
            'max_active_uploads': 8}))
        fixture.provision()
        daemon = self.boot()
        views = [fixture.begin(daemon, 'slot-' + str(number)) for number in range(8)]
        self.assertEqual(len({view['upload_id'] for view in views}), 8)
        self.assertEqual(sum(view['reserved_bytes'] for view in views), 8 * fixture.charge)
        self.assert_denied_unchanged(daemon, fixture.begin_request('slot-9'), 'CAPACITY_UNAVAILABLE')
        before = {view['upload_id']: observer.tree(fixture.staging / 'uploads' / view['upload_id'])
                  for view in views[1:]}
        fixture.view(fixture.cancel(daemon, views[0]['upload_id']), views[0]['upload_id'], 'Cancelled')
        replacement = fixture.begin(daemon, 'replacement')
        self.assertNotIn(replacement['upload_id'], {view['upload_id'] for view in views})
        for upload_id, image in before.items():
            self.assertEqual(observer.tree(fixture.staging / 'uploads' / upload_id), image)

    def test_single_active_slot_with_sufficient_bytes_independently_limits_count(self):
        fixture = self.fixture
        fixture.freeze()
        fixture.budget.write_bytes(observer.canonical({'schema_version': 1,
            'max_reserved_bytes': observer.GLOBAL_CHARGE + 3 * fixture.charge,
            'max_active_uploads': 1}))
        fixture.provision()
        daemon = self.boot()
        first = fixture.begin(daemon, 'one')
        self.assert_denied_unchanged(daemon, fixture.begin_request('two'), 'CAPACITY_UNAVAILABLE')
        fixture.view(fixture.cancel(daemon, first['upload_id']), first['upload_id'], 'Cancelled')
        second = fixture.begin(daemon, 'two')
        self.assertEqual(second['reserved_bytes'], fixture.charge)
        self.assertNotEqual(second['upload_id'], first['upload_id'])

    def test_empty_snapshot_still_reserves_metadata_and_seals_without_empty_chunks(self):
        fixture = self.fixture
        output = fixture.base / 'empty-bundle'
        args = ['snapshot', 'freeze', fixture.workspace, '--config', fixture.source,
            '--commit', fixture.snapshot['commit_id'], '--include', '.', '--exclude', '.',
            '--output', output, '--json']
        result = fixture.invoke(fixture.cli, args, 'freeze-empty')
        self.assertTrue(observer.response_pass(result, 'snapshot freeze'), result)
        selection = {'schema_version': 1, 'matching': 'exact-or-directory-prefix',
                     'include': ['.'], 'exclude': ['.'], 'executable': []}
        snapshot = fixture.snapshot_for_manifest([], selection_digest=observer.digest(observer.canonical(selection)))
        self.assertEqual(result[1]['snapshot'], snapshot)
        self.assertEqual(snapshot['file_count'], 0)
        self.assertEqual(snapshot['total_bytes'], 0)
        self.assertEqual((output / 'manifest-v1.json').read_bytes(), b'[]')
        self.assertEqual(list((output / 'blobs').iterdir()), [])
        fixture.provision()
        daemon = self.boot()
        result = fixture.request(daemon, fixture.begin_request('empty', snapshot=snapshot, manifest_json='[]'))
        self.assertTrue(observer.response_pass(result), result)
        view = result[1]['upload']
        self.assertEqual(view['snapshot'], snapshot)
        self.assertEqual(view['state'], 'Receiving')
        self.assertEqual(view['blobs'], [])
        self.assertEqual(view['reserved_bytes'], observer.charge([]))
        sealed = fixture.operation(daemon, 'Seal', view['upload_id'])
        self.assertTrue(observer.response_pass(sealed), sealed)
        self.assertEqual(sealed[1]['upload']['state'], 'Staged')
        self.assertEqual(sealed[1]['upload']['snapshot'], snapshot)

    def test_declared_total_above_64mib_rejected_before_any_reservation(self):
        fixture = self.configured()
        daemon = self.boot()
        manifest = [dict(fixture.manifest[0], size_bytes=67_108_865)]
        snapshot = dict(fixture.snapshot, file_count=1, total_bytes=67_108_865,
                        manifest_sha256=observer.digest(observer.canonical(manifest)))
        snapshot.pop('snapshot_id')
        snapshot['snapshot_id'] = observer.digest(observer.canonical(snapshot))
        self.assert_denied_unchanged(daemon, fixture.begin_request('oversize', snapshot=snapshot,
            manifest_json=observer.canonical(manifest).decode()), 'CAPACITY_UNAVAILABLE')

    def test_new_key_begin_rechecks_revoked_or_expired_use_with_available_capacity(self):
        for denial in ('revoke', 'expired'):
            with self.subTest(denial=denial):
                result = observer.fresh_begin_current_use_case(self.fixture.base / ('fresh-' + denial), denial)
                self.assertEqual(result['error_code'], 'AUTH_DENIED')
                self.assertTrue(result['new_key_and_available_capacity'])
                self.assertTrue(result['same_request_restored_success'])
                self.assertTrue(result['denied_staging_unchanged'])

    def test_cancelled_get_repeat_cancel_and_same_key_begin_recheck_current_use(self):
        # Every operation/denial owns a separate formally initialized provider,
        # record and daemon. No earlier operation can grant/cache authorization.
        for operation in ('Get', 'Cancel', 'Begin'):
            for denial in ('revoke', 'expired'):
                with self.subTest(operation=operation, denial=denial):
                    result = observer.cancelled_current_use_case(
                        self.fixture.base / ('terminal-' + operation + '-' + denial), operation, denial)
                    self.assertEqual(result['error_code'], 'AUTH_DENIED')
                    self.assertTrue(result['same_request_positive_before_after'])
                    self.assertTrue(result['original_terminal_view_preserved'])
                    self.assertTrue(result['staging_mtime_ctime_unchanged_on_denial'])
                    self.assertTrue(result['payload_namespace_absent'])

    def test_receiving_next_chunk_and_confirmed_retry_recheck_revoked_or_expired_use(self):
        fixture, daemon, initial = self.active()
        big, data = self.big()
        prefixed = fixture.view(fixture.chunk(daemon, initial['upload_id'], big['sha256'],
            0, data[:observer.CHUNK]), initial['upload_id'], 'Receiving')
        self.assertEqual(next(blob['durable_offset'] for blob in prefixed['blobs']
                              if blob['sha256'] == big['sha256']), observer.CHUNK)
        advanced = fixture.check_receiving_chunk_current_use(daemon, initial['upload_id'])
        self.assertEqual(next(blob['durable_offset'] for blob in advanced['blobs']
                              if blob['sha256'] == big['sha256']), observer.CHUNK + 34)
        self.assertEqual(advanced['state'], 'Receiving')
        self.assertEqual(advanced['upload_id'], initial['upload_id'])
        self.assertEqual(advanced['snapshot'], initial['snapshot'])
        self.assertEqual(advanced['reserved_bytes'], initial['reserved_bytes'])
        # Cancel is legal in this same incomplete state. Both denied Cancel
        # requests above therefore have a real authorized positive control.
        fixture.view(fixture.cancel(daemon, initial['upload_id']), initial['upload_id'], 'Cancelled')

    def test_complete_receiving_seal_and_other_legal_operations_recheck_current_use(self):
        fixture = self.configured()
        daemon = self.boot()
        big, data = self.big()
        for denial in ('revoke', 'expired'):
            with self.subTest(denial=denial):
                key = 'complete-receiving-' + denial
                initial = fixture.begin(daemon, key)
                upload_id = initial['upload_id']
                complete = fixture.complete_bytes(daemon, upload_id)
                self.assertEqual(complete['state'], 'Receiving')
                self.assertTrue(all(blob['durable_offset'] == blob['size_bytes']
                                    for blob in complete['blobs']))
                path = fixture.staging / 'uploads' / upload_id / 'blobs' / observer.blob_name(big['sha256'])
                original_inode = (path.stat().st_dev, path.stat().st_ino)
                retry_bytes = data[:observer.CHUNK]
                retry = {'schema_version': 1, 'operation': 'PutChunk', 'upload_id': upload_id,
                         'blob_sha256': big['sha256'], 'offset': 0, 'bytes': list(retry_bytes),
                         'chunk_sha256': observer.digest(retry_bytes)}
                self.assertEqual(fixture.view(fixture.request(daemon, retry), upload_id, 'Receiving'), complete)
                if denial == 'revoke':
                    fixture.grant('revoke')
                else:
                    # Use the real operator's persisted expiry; no host clock override.
                    self.assertGreater(observer.time.time(), 1)
                    fixture.grant('add', ['--not-after', '1'])
                requests = [fixture.begin_request(key), retry,
                    *({'schema_version': 1, 'operation': operation, 'upload_id': upload_id}
                      for operation in ('Get', 'Seal', 'Cancel'))]
                before = observer.tree(fixture.staging)
                for request in requests:
                    self.assertTrue(observer.response_fail(fixture.request(daemon, request),
                        'AUTH_DENIED', upload_id=request.get('upload_id')), request['operation'])
                    self.assertEqual(observer.tree(fixture.staging), before,
                                     'each complete-Receiving auth denial must leave staging unchanged')
                fixture.grant('add')
                self.assertEqual(fixture.view(fixture.status(daemon, upload_id), upload_id, 'Receiving'), complete)
                self.assertEqual(fixture.view(fixture.request(daemon, fixture.begin_request(key)),
                                             upload_id, 'Receiving'), complete)
                self.assertEqual(fixture.view(fixture.request(daemon, retry), upload_id, 'Receiving'), complete)
                # This exact Seal request was otherwise valid before grant loss.
                sealed = fixture.view(fixture.operation(daemon, 'Seal', upload_id), upload_id, 'Staged')
                self.assertEqual(sealed['snapshot'], complete['snapshot'])
                self.assertEqual(sealed['reserved_bytes'], complete['reserved_bytes'])
                self.assertEqual(sealed['blobs'], complete['blobs'])
                self.assertEqual((path.stat().st_dev, path.stat().st_ino), original_inode)
                self.assertEqual(path.read_bytes(), data)
                self.assertEqual(fixture.view(fixture.request(daemon, retry), upload_id, 'Staged'), sealed)
                fixture.view(fixture.cancel(daemon, upload_id), upload_id, 'Cancelled')

    def test_missing_or_revoked_or_expired_use_grant_denies_every_operation(self):
        fixture = self.configured(grant=False)
        daemon = self.boot()
        self.assert_denied_unchanged(daemon, fixture.begin_request(), 'AUTH_DENIED')
        fixture.grant('add')
        view = fixture.begin(daemon)
        big, data = self.big()
        fixture.complete_bytes(daemon, view['upload_id'])
        staged = fixture.view(fixture.operation(daemon, 'Seal', view['upload_id']), view['upload_id'], 'Staged')
        for operation in ('revoke', 'expired'):
            self.assertEqual(fixture.view(fixture.chunk(daemon, view['upload_id'], big['sha256'],
                0, data[:observer.CHUNK]), view['upload_id'], 'Staged'), staged,
                'authorized Staged confirmed-range retry is legal')
            if operation == 'revoke':
                fixture.grant('revoke')
            else:
                self.assertGreater(observer.time.time(), 1)
                fixture.grant('add', ['--not-after', '1'])
            before = observer.tree(fixture.staging)
            self.assertTrue(observer.response_fail(fixture.request(daemon, fixture.begin_request()),
                                                  'AUTH_DENIED', upload_id=None))
            self.assertEqual(observer.tree(fixture.staging), before)
            for request in ('Get', 'Seal', 'Cancel'):
                self.assertTrue(observer.response_fail(fixture.operation(daemon, request, view['upload_id']),
                                                      'AUTH_DENIED', upload_id=view['upload_id']))
                self.assertEqual(observer.tree(fixture.staging), before)
            self.assertTrue(observer.response_fail(fixture.chunk(daemon, view['upload_id'], big['sha256'],
                0, data[:observer.CHUNK]), 'AUTH_DENIED', upload_id=view['upload_id']))
            self.assertEqual(observer.tree(fixture.staging), before)
            fixture.grant('add')
            self.assertEqual(fixture.view(fixture.status(daemon, view['upload_id']), view['upload_id'], 'Staged'), staged)
            self.assertEqual(fixture.view(fixture.request(daemon, fixture.begin_request()),
                                         view['upload_id'], 'Staged'), staged)
            self.assertEqual(fixture.view(fixture.operation(daemon, 'Seal', view['upload_id']), view['upload_id'], 'Staged'), staged)
            self.assertEqual(fixture.view(fixture.chunk(daemon, view['upload_id'], big['sha256'],
                0, data[:observer.CHUNK]), view['upload_id'], 'Staged'), staged)
        fixture.view(fixture.cancel(daemon, view['upload_id']), view['upload_id'], 'Cancelled')

    def test_begin_wrong_provider_workspace_resource_and_injected_principal_denied(self):
        fixture = self.configured()
        daemon = self.boot()
        for changes in ({'provider': 'other-provider'}, {'workspace': 'other-workspace'},
                        {'resource': 'ungranted-resource'}, {'principal': 'forged-caller'}):
            with self.subTest(changes=changes):
                self.assert_denied_unchanged(daemon, fixture.begin_request(**changes))

    def test_snapshot_route_missing_wrong_token_and_changed_inode_or_bytes_denied(self):
        fixture = self.configured()
        daemon = self.boot()
        token_path = fixture.root / 'localapi.token'
        original = token_path.read_bytes()
        for authorization in (None, 'Bearer wrong-local-token'):
            before = observer.tree(fixture.staging)
            result = fixture.request(daemon, fixture.begin_request(), headers={'Authorization': authorization})
            self.assertTrue(observer.response_fail(result, upload_id=None), result)
            self.assertEqual(observer.tree(fixture.staging), before)
        # Replacement bytes are identical. Only the inode authority is wrong.
        backup = fixture.base / 'original-token'
        token_path.rename(backup)
        token_path.write_bytes(original)
        token_path.chmod(0o600)
        self.assertNotEqual(token_path.stat().st_ino, backup.stat().st_ino)
        before = observer.tree(fixture.staging)
        result = fixture.request(daemon, fixture.begin_request())
        self.assertTrue(observer.response_fail(result, upload_id=None), result)
        self.assertEqual(observer.tree(fixture.staging), before)
        token_path.unlink()
        backup.rename(token_path)
        inode = token_path.stat().st_ino
        replacement = bytes([original[0] ^ 1]) + original[1:]
        token_path.write_bytes(replacement)
        self.assertEqual(token_path.stat().st_ino, inode)
        before = observer.tree(fixture.staging)
        result = fixture.request(daemon, fixture.begin_request(),
            headers={'Authorization': 'Bearer ' + original.decode().strip()})
        self.assertTrue(observer.response_fail(result, upload_id=None), result)
        self.assertEqual(observer.tree(fixture.staging), before)
        token_path.write_bytes(original)
        # Positive authenticated control proves the route/grant are otherwise valid.
        view = fixture.begin(daemon)
        fixture.view(fixture.cancel(daemon, view['upload_id']), view['upload_id'], 'Cancelled')

    def test_real_unix_socket_authenticated_snapshot_route_and_cli(self):
        fixture = self.configured()
        daemon = self.enterContext(fixture.boot('unix', unix=True))
        self.assertEqual(daemon.socket_path.stat().st_mode & 0o777, 0o600)
        before = observer.tree(fixture.staging)
        bad = fixture.request(daemon, fixture.begin_request(), headers={'Authorization': None})
        self.assertTrue(observer.response_fail(bad, upload_id=None), bad)
        self.assertEqual(observer.tree(fixture.staging), before)
        view = fixture.begin(daemon)
        fixture.view(fixture.status(daemon, view['upload_id']), view['upload_id'], 'Receiving')
        fixture.view(fixture.upload(daemon), view['upload_id'], 'Staged')
        fixture.view(fixture.cancel(daemon, view['upload_id']), view['upload_id'], 'Cancelled')

    def test_raw_tcp_invalid_framing_never_enters_staging_and_closes_within_deadline(self):
        import socket
        import time
        fixture = self.configured()
        daemon = self.boot()
        token = (fixture.root / 'localapi.token').read_text().strip()
        host, port = daemon.addr.rsplit(':', 1)
        def head(body, extra=b'', length=None):
            return (b'POST /localapi/v1/snapshot HTTP/1.1\r\nHost: localhost\r\n'
                    + b'Authorization: Bearer ' + token.encode() + b'\r\nContent-Length: '
                    + str(len(body) if length is None else length).encode()
                    + b'\r\n' + extra + b'\r\n')
        for name in ('transfer-encoding', 'duplicate-content-length', 'pipeline', 'header-bound',
                     'body-bound', 'truncated', 'deadline'):
            with self.subTest(name=name):
                body = observer.canonical(fixture.begin_request('frame-' + name))
                extra = (b'Transfer-Encoding: chunked\r\n' if name == 'transfer-encoding' else
                         b'Content-Length: ' + str(len(body)).encode() + b'\r\n'
                         if name == 'duplicate-content-length' else
                         b'X-Oversize: ' + b'x' * 16_384 + b'\r\n' if name == 'header-bound' else b'')
                length = 1024**2 + 1 if name == 'body-bound' else None
                frame = head(body, extra, length) + body
                if name == 'pipeline':
                    frame += head(body) + body
                if name in ('truncated', 'deadline'):
                    frame = head(body) + body[:len(body) // 2]
                before = observer.tree(fixture.staging)
                start = time.monotonic()
                received = b''
                with socket.create_connection((host, int(port)), timeout=3) as peer:
                    peer.settimeout(8)
                    try:
                        peer.sendall(frame)
                        if name == 'truncated':
                            peer.shutdown(socket.SHUT_WR)
                        while True:
                            block = peer.recv(8192)
                            if not block:
                                break
                            received += block
                            self.assertLessEqual(len(received), 2 * 1024**2)
                    except (ConnectionResetError, BrokenPipeError):
                        pass
                    except socket.timeout:
                        self.fail('§3 bad framing must close within total IO deadline: ' + name)
                self.assertLess(time.monotonic() - start, 8, name)
                self.assertNotIn(b'"verdict":"PASS"', received, 'bad frame returned successful reservation')
                self.assertEqual(observer.tree(fixture.staging), before, 'framing entered staging: ' + name)
                self.assertIsNone(daemon.child.poll(), 'framing killed ordinary daemon')
                # The same boundary remains usable with valid canonical framing.
                view = fixture.begin(daemon, 'positive-' + name)
                fixture.view(fixture.cancel(daemon, view['upload_id']), view['upload_id'], 'Cancelled')

    def test_chunk_wire_exact_offset_and_byte_array_numbers_and_canonical_body(self):
        fixture, daemon, view = self.active()
        big, data = self.big()
        request = {'schema_version': 1, 'operation': 'PutChunk', 'upload_id': view['upload_id'],
                   'blob_sha256': big['sha256'], 'offset': 0, 'bytes': list(data[:3]),
                   'chunk_sha256': observer.digest(data[:3])}
        valid = observer.canonical(request)
        byte_array = observer.canonical(list(data[:3]))
        float_bytes = ('[' + str(data[0]) + '.0,' + str(data[1]) + ',' + str(data[2]) + ']').encode()
        exponent_bytes = ('[' + str(data[0]) + 'e0,' + str(data[1]) + ',' + str(data[2]) + ']').encode()
        cases = [valid.replace(b'"offset":0', b'"offset":0.0'),
                 valid.replace(b'"offset":0', b'"offset":0e0'),
                 valid.replace(b'"offset":0', b'"offset":9007199254740992'),
                 valid.replace(byte_array, float_bytes),
                 valid.replace(byte_array, exponent_bytes),
                 valid.replace(observer.canonical(list(data[:3])), b'[256,2,3]'),
                 valid.replace(observer.canonical(list(data[:3])), b'[-1,2,3]'),
                 b' ' + valid, json.dumps(request).encode()]
        for raw in cases:
            with self.subTest(raw=raw[:100]):
                self.assert_denied_unchanged(daemon, request, raw=raw)
        fixture.view(fixture.chunk(daemon, view['upload_id'], big['sha256'], 0, data[:3]),
                     view['upload_id'], 'Receiving')

    def test_wire_unknown_duplicate_float_exponent_version_are_real_typed_denials(self):
        fixture = self.configured()
        daemon = self.boot()
        valid = observer.canonical(fixture.begin_request())
        cases = [valid[:-1] + b',"principal":"forged"}',
                 valid[:-1] + b',"schema_version":1}',
                 valid.replace(b'"schema_version":1', b'"schema_version":1.0', 1),
                 valid.replace(b'"schema_version":1', b'"schema_version":1e0', 1),
                 valid.replace(b'"schema_version":1', b'"schema_version":2', 1),
                 b' ' + valid, json.dumps(fixture.begin_request(), ensure_ascii=False).encode(),
                 valid.replace(b'n312-provider', b'n312-\\u0070rovider', 1)]
        for raw in cases:
            with self.subTest(raw=raw[:80]):
                self.assert_denied_unchanged(daemon, fixture.begin_request(), raw=raw)

    def test_manifest_semantics_rehashed_to_avoid_digest_precondition_masking(self):
        fixture = self.configured()
        daemon = self.boot()
        base = fixture.manifest
        # Each reference agrees with manifest bytes hash and snapshot_id. Only
        # the named semantic rule is violated, rather than a preceding hash.
        cases = [('order', base[::-1], {}),
                 ('duplicate-path', sorted(base + [base[0]], key=lambda file: file['path']), {}),
                 ('directory-collision', [dict(base[0], path='dir'), dict(base[1], path='dir/file')], {}),
                 ('same-digest-different-size', [base[0], dict(base[0], path='other', size_bytes=1)], {}),
                 ('file-count', base, {'file_count': len(base) + 1}),
                 ('total-bytes', base, {'total_bytes': sum(file['size_bytes'] for file in base) + 1})]
        for name, manifest, changes in cases:
            with self.subTest(name=name):
                snapshot = fixture.snapshot_for_manifest(manifest)
                snapshot.update(changes)
                snapshot.pop('snapshot_id')
                snapshot['snapshot_id'] = observer.digest(observer.canonical(snapshot))
                self.assert_denied_unchanged(daemon, fixture.begin_request(name,
                    snapshot=snapshot, manifest_json=observer.canonical(manifest).decode()))
        raw_manifest = observer.canonical(base) + b' '
        snapshot = fixture.snapshot_for_manifest(base, raw=raw_manifest)
        self.assert_denied_unchanged(daemon, fixture.begin_request('noncanonical-manifest',
            snapshot=snapshot, manifest_json=raw_manifest.decode()))
        oversized = [dict(base[1], path='file-' + str(number).zfill(4) + '-' + 'x' * 64)
                     for number in range(1024)]
        oversized_bytes = observer.canonical(oversized)
        self.assertGreater(len(oversized_bytes), 65_536)
        self.assertLess(len(oversized_bytes), 1024**2)
        self.assert_denied_unchanged(daemon, fixture.begin_request('oversize-manifest',
            snapshot=fixture.snapshot_for_manifest(oversized), manifest_json=oversized_bytes.decode()),
            'CAPACITY_UNAVAILABLE')
        self.assert_denied_unchanged(daemon, fixture.begin_request('wrong-manifest-digest',
            manifest_json='[]'))

    def test_same_key_same_id_offsets_and_changed_valid_binding_conflict(self):
        fixture, daemon, original = self.active()
        before = observer.tree(fixture.staging)
        repeated = fixture.begin(daemon)
        self.assertEqual(repeated, original)
        self.assertEqual(observer.tree(fixture.staging), before)
        self.assert_denied_unchanged(daemon, fixture.begin_request(
            snapshot=fixture.different_snapshot()), 'IDEMPOTENCY_CONFLICT')

    def test_chunk_hash_zero_oversize_gap_wrong_blob_and_overlap_denied(self):
        fixture, daemon, view = self.active()
        big, data = self.big()
        upload_id = view['upload_id']
        cases = [(0, b'', {}), (0, data[:observer.CHUNK + 1], {}),
                 (1, data[:10], {}), (2**53 - 1, b'x', {}),
                 (0, data[:10], {'chunk_sha256': 'sha256:' + '0' * 64}),
                 (0, data[:10], {'blob_sha256': 'sha256:' + '0' * 64})]
        for offset, payload, changes in cases:
            with self.subTest(offset=offset, size=len(payload), changes=changes):
                before = observer.tree(fixture.staging)
                self.assertTrue(observer.response_fail(fixture.chunk(daemon, upload_id,
                    big['sha256'], offset, payload, **changes)))
                self.assertEqual(observer.tree(fixture.staging), before)
        fixture.view(fixture.chunk(daemon, upload_id, big['sha256'], 0, data[:100]), upload_id)
        for offset, payload in ((50, data[50:150]), (0, bytes([data[0] ^ 1]) + data[1:100])):
            before = observer.tree(fixture.staging)
            self.assertTrue(observer.response_fail(fixture.chunk(daemon, upload_id, big['sha256'], offset, payload)))
            self.assertEqual(observer.tree(fixture.staging), before)

    def test_chunk_exact_max_confirmed_retry_and_incomplete_seal(self):
        fixture, daemon, view = self.active()
        big, data = self.big()
        upload_id = view['upload_id']
        committed = fixture.view(fixture.chunk(daemon, upload_id, big['sha256'], 0,
                                 data[:observer.CHUNK]), upload_id, 'Receiving')
        before = observer.tree(fixture.staging)
        self.assertEqual(fixture.view(fixture.chunk(daemon, upload_id, big['sha256'], 0,
            data[:observer.CHUNK]), upload_id), committed)
        self.assertEqual(observer.tree(fixture.staging), before)
        self.assert_denied_unchanged(daemon, {'schema_version': 1, 'operation': 'Seal',
                                            'upload_id': upload_id})

    def test_unknown_and_pathlike_upload_ids_never_touch_external_path(self):
        fixture = self.configured()
        daemon = self.boot()
        external = fixture.base / 'outside'
        external.write_bytes(b'user file\n')
        before = observer.tree(fixture.base)
        for upload_id in ('unknown', '../outside', str(external), '合法/未知'):
            for operation in ('Get', 'Cancel', 'Seal'):
                with self.subTest(upload_id=upload_id, operation=operation):
                    self.assert_denied_unchanged(daemon, {'schema_version': 1,
                        'operation': operation, 'upload_id': upload_id})
        self.assertEqual(external.read_bytes(), b'user file\n')
        # Auth audit is allowed outside staging; don't compare the entire provider tree.
        self.assertEqual(observer.tree(fixture.decoy), {'.': before['decoy']})

    def test_bundle_extra_missing_noncanonical_wronghash_links_fifo_rejected(self):
        fixture = self.configured()
        daemon = self.boot()
        for kind in ('extra', 'missing', 'noncanonical', 'wronghash', 'symlink', 'hardlink', 'fifo',
                     'root-extra', 'metadata-extra', 'metadata-noncanonical', 'metadata-duplicate',
                     'metadata-float', 'metadata-mismatch'):
            with self.subTest(kind=kind):
                bundle = fixture.base / ('bundle-' + kind)
                shutil.copytree(fixture.bundle, bundle)
                digest = next(file['sha256'] for file in fixture.manifest if file['size_bytes'] > 0)
                blob = bundle / 'blobs' / observer.blob_name(digest)
                if kind == 'root-extra':
                    (bundle / 'unknown-root-file').write_bytes(b'unknown bundle member')
                elif kind.startswith('metadata-'):
                    file = bundle / 'bundle-v1.json'
                    metadata = json.loads(file.read_bytes())
                    if kind == 'metadata-extra': metadata['principal'] = 'untrusted-client'
                    elif kind == 'metadata-float': metadata['schema_version'] = 1.0
                    elif kind == 'metadata-mismatch':
                        ref = metadata['snapshot']; ref['manifest_sha256'] = 'sha256:' + '0' * 64
                        ref.pop('snapshot_id'); ref['snapshot_id'] = observer.digest(observer.canonical(ref))
                    raw = observer.canonical(metadata)
                    if kind == 'metadata-noncanonical': raw += b'\n'
                    elif kind == 'metadata-duplicate': raw = raw[:-1] + b',"schema_version":1}'
                    file.write_bytes(raw)
                elif kind == 'extra':
                    (bundle / 'blobs' / ('0' * 64)).write_bytes(b'unknown')
                elif kind == 'missing':
                    blob.unlink()
                elif kind == 'noncanonical':
                    file = bundle / 'manifest-v1.json'
                    file.write_bytes(file.read_bytes() + b'\n')
                elif kind == 'wronghash':
                    with blob.open('r+b') as stream:
                        original = stream.read(1)
                        stream.seek(0)
                        stream.write(bytes([original[0] ^ 1]))
                else:
                    external = fixture.base / ('external-' + kind)
                    external.write_bytes(blob.read_bytes())
                    blob.unlink()
                    if kind == 'symlink':
                        blob.symlink_to(external)
                    elif kind == 'hardlink':
                        os.link(external, blob)
                    else:
                        os.mkfifo(blob, 0o600)
                before = observer.tree(fixture.staging)
                result = fixture.upload(daemon, key='bad-' + kind, bundle=bundle)
                self.assertTrue(observer.response_fail(result, 'INPUT_INTEGRITY_FAILED'), result)
                self.assertEqual(observer.tree(fixture.staging), before)

    def test_staging_flock_busy_typed_failure_and_original_inode_retained(self):
        import fcntl
        fixture = self.configured()
        daemon = self.boot()
        lease = fixture.staging / 'staging.lock'
        before = observer.tree(fixture.staging)
        with lease.open('rb') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = fixture.request(daemon, fixture.begin_request())
            self.assertTrue(observer.response_fail(result), result)
            self.assertEqual(observer.tree(fixture.staging), before)
        fixture.begin(daemon)
        self.assertEqual(lease.stat().st_ino, before['staging.lock'][1])

    def test_optional_json_flag_omission_preserves_all_formal_cli_operations(self):
        fixture = self.fixture
        source_before = observer.tree(fixture.source)
        result = fixture.invoke(fixture.cli, fixture.freeze_args()[:-1], 'freeze-without-json')
        self.assertEqual(result[0], 0)
        fixture.verify_bundle()
        self.assertEqual(observer.tree(fixture.source), source_before)
        fixture.provision_provider()
        result = fixture.invoke(fixture.daemon, ['task-provider', 'staging-init', '--config',
            fixture.root, '--budget', fixture.budget], 'staging-init-without-json')
        self.assertEqual(result[0], 0)
        before = observer.tree(fixture.root)
        fixture.check_staging_status(fixture.staging_init(), changed=False)
        self.assertEqual(observer.tree(fixture.root), before)
        with fixture.boot('optional-json') as daemon:
            execution_before = observer.tree(fixture.root / 'data/n3/tasks')
            result = fixture.invoke(fixture.cli, ['snapshot', 'upload', '--bundle', fixture.bundle,
                '--provider', fixture.provider, '--resource', fixture.resource, '--key', 'human-mode',
                *fixture.target_args(daemon)], 'upload-without-json')
            self.assertEqual(result[0], 0)
            staged = fixture.view(fixture.request(daemon, fixture.begin_request('human-mode')), state='Staged')
            upload_id = staged['upload_id']
            before = observer.tree(fixture.staging)
            result = fixture.invoke(fixture.cli, ['snapshot', 'status', upload_id,
                *fixture.target_args(daemon)], 'status-without-json')
            self.assertEqual(result[0], 0)
            self.assertEqual(observer.tree(fixture.staging), before, 'status is read-only with or without --json')
            result = fixture.invoke(fixture.cli, ['snapshot', 'cancel', upload_id,
                *fixture.target_args(daemon)], 'cancel-without-json')
            self.assertEqual(result[0], 0)
            fixture.view(fixture.operation(daemon, 'Get', upload_id), upload_id, 'Cancelled')
            self.assertFalse((fixture.staging / 'uploads' / upload_id).exists())
            fixture.assert_no_execution(daemon, execution_before)

    def test_unreachable_daemon_keeps_bundle_and_original_prefix_then_same_key_resumes(self):
        fixture = self.configured()
        owner = observer.Daemon(fixture, 'before-offline')
        fixture.children.append(owner)
        try:
            owner.await_ready()
            initial = fixture.begin(owner)
            big, data = self.big()
            prefix_view = fixture.view(fixture.chunk(owner, initial['upload_id'], big['sha256'],
                0, data[:observer.CHUNK]), initial['upload_id'], 'Receiving')
        finally:
            owner.stop()
        before_root, before_bundle = observer.tree(fixture.root), observer.tree(fixture.bundle)
        for operation in ('upload', 'status', 'cancel'):
            with self.subTest(operation=operation):
                result = (fixture.upload(owner) if operation == 'upload' else
                          fixture.status(owner, initial['upload_id']) if operation == 'status' else
                          fixture.cancel(owner, initial['upload_id']))
                self.assertTrue(observer.response_fail(result, upload_id=None if operation == 'upload'
                                                       else initial['upload_id']), result)
                self.assertEqual(observer.tree(fixture.root), before_root)
                self.assertEqual(observer.tree(fixture.bundle), before_bundle)
        with fixture.boot('after-offline') as daemon:
            execution_before = observer.tree(fixture.root / 'data/n3/tasks')
            self.assertEqual(fixture.view(fixture.status(daemon, initial['upload_id']),
                                         initial['upload_id'], 'Receiving'), prefix_view)
            fixture.view(fixture.upload(daemon), initial['upload_id'], 'Staged')
            self.assertEqual(observer.tree(fixture.bundle), before_bundle)
            fixture.view(fixture.cancel(daemon, initial['upload_id']), initial['upload_id'], 'Cancelled')
            fixture.assert_no_execution(daemon, execution_before)

    def test_cli_upload_seal_then_cancel_releases_only_owned_namespace_and_preserves_tombstone(self):
        fixture = self.configured()
        daemon = self.boot()
        execution_before = observer.tree(fixture.root / 'data/n3/tasks')
        fixture.assert_no_execution(daemon, execution_before)
        view = fixture.view(fixture.upload(daemon), state='Staged')
        fixture.assert_no_execution(daemon, execution_before)
        upload_id = view['upload_id']
        cancelled = fixture.view(fixture.cancel(daemon, upload_id), upload_id, 'Cancelled')
        self.assertFalse((fixture.staging / 'uploads' / upload_id).exists())
        self.assertEqual(fixture.view(fixture.cancel(daemon, upload_id), upload_id), cancelled)
        self.assertEqual(fixture.view(fixture.request(daemon, fixture.begin_request()), upload_id), cancelled)
        self.assertNotEqual(fixture.begin(daemon, 'fresh-after-cancel')['upload_id'], upload_id)
        fixture.assert_no_execution(daemon, execution_before)

    def test_cancelled_tombstone_table_is_bounded_and_never_silently_reuses_live_key(self):
        fixture = self.configured()
        daemon = self.boot()
        original = None
        admitted = 0
        for number in range(1025):
            result = fixture.request(daemon, fixture.begin_request('table-' + str(number)))
            if observer.response_fail(result, 'CAPACITY_UNAVAILABLE'):
                break
            view = fixture.view(result, state='Receiving')
            admitted += 1
            cancelled = fixture.view(fixture.cancel(daemon, view['upload_id']), view['upload_id'], 'Cancelled')
            if original is None:
                original = cancelled
            self.assertLessEqual((fixture.staging / 'ledger-v1.json').stat().st_size, 4 * 1024**2)
            self.assertEqual(list((fixture.staging / 'uploads').iterdir()), [])
        else:
            self.fail('§4 more than 1024 retained tombstones admitted')
        self.assertGreaterEqual(admitted, 2, 'ordinary small bindings permit post-cancel admission')
        before = observer.tree(fixture.staging)
        preserved = fixture.view(fixture.status(daemon, original['upload_id']), original['upload_id'], 'Cancelled')
        self.assertEqual(preserved, original)
        self.assertEqual(observer.tree(fixture.staging), before, 'Get must not reclaim unexpired tombstones')
        self.assertEqual(fixture.view(fixture.request(daemon, fixture.begin_request('table-0')),
                                     original['upload_id'], 'Cancelled'), original)

    def test_independent_authenticated_providers_same_key_digest_charge_full_and_cancel_isolated(self):
        fixture = self.configured()
        daemon = self.boot()
        first = fixture.view(fixture.upload(daemon), state='Staged')
        other = observer.Fixture(fixture.base / 'other-owner')
        other.freeze()
        other.provision()
        other_daemon = self.boot(other, 'other-owner')
        second = other.view(other.upload(other_daemon), state='Staged')
        self.assertEqual(first['snapshot'], second['snapshot'])
        self.assertEqual(first['reserved_bytes'], fixture.charge)
        self.assertEqual(second['reserved_bytes'], other.charge)
        before = observer.tree(fixture.staging)
        other.view(other.cancel(other_daemon, second['upload_id']), second['upload_id'], 'Cancelled')
        self.assertEqual(observer.tree(fixture.staging), before)
        fixture.view(fixture.status(daemon, first['upload_id']), first['upload_id'], 'Staged')

    def test_cli_adapter_strict_envelopes_scope_snapshot_id_range_state_and_fail_correlation(self):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        import copy
        import threading
        fixture, daemon, view = self.active()
        # A bounded local observer peer tests the real CLI's adapter. Its views
        # derive from independently checked fixture inputs, never provider seed.
        error = {'code': 'INVALID_REQUEST', 'reason': 'peer contract probe', 'retryable': False}
        def mutate(case, request, payload):
            result = copy.deepcopy(payload)
            upload = result.get('upload')
            if case == 'provider': upload['provider'] = 'different-provider'
            elif case == 'workspace':
                upload['workspace'] = 'different-workspace'
                upload['snapshot']['workspace'] = 'different-workspace'
                ref = upload['snapshot']; ref.pop('snapshot_id')
                ref['snapshot_id'] = observer.digest(observer.canonical(ref))
            elif case == 'resource': upload['resource'] = 'different-resource'
            elif case == 'snapshot': upload['snapshot'] = fixture.different_snapshot()
            elif case == 'id': upload['upload_id'] = 'unrelated-upload'
            elif case == 'range':
                for blob in upload['blobs']:
                    if blob['sha256'] == request['blob_sha256']: blob['durable_offset'] = request['offset']
            elif case == 'digest':
                for blob in upload['blobs']:
                    if blob['sha256'] == request['blob_sha256']: blob['sha256'] = 'sha256:' + 'f' * 64
                upload['blobs'].sort(key=lambda blob: blob['sha256'])
            elif case == 'seal-state': upload['state'] = 'Receiving'
            elif case == 'chunk-state':
                upload.update(state='Cancelled', reserved_bytes=0, blobs=[])
            elif case == 'cancel-state':
                upload.update(state='Staged', reserved_bytes=fixture.charge,
                              blobs=copy.deepcopy(view['blobs']))
                for blob in upload['blobs']: blob['durable_offset'] = blob['size_bytes']
            elif case == 'extra': result['task_id'] = 'invented-task'
            elif case == 'view-extra': upload['task_id'] = 'invented-task'
            elif case == 'schema-float': result['schema_version'] = 1.0
            elif case == 'offset-float': upload['blobs'][0]['durable_offset'] = 0.0
            elif case == 'missing': del result['schema_version']
            elif case.startswith('fail-'):
                result = {'schema_version': 1, 'verdict': 'FAIL', 'error': dict(error),
                          'upload_id': None if request['operation'] == 'Begin' else request['upload_id']}
                if case == 'fail-id': result['upload_id'] = 'unrelated-upload'
                elif case == 'fail-missing-id': del result['upload_id']
                elif case == 'fail-extra': result['task_id'] = 'invented-task'
                elif case == 'fail-error-extra': result['error']['extra'] = 'invented'
                elif case == 'fail-error-bool': result['error']['retryable'] = 1
            return result

        # Every phase must independently decode the same strict wire shape;
        # an earlier Begin rejection cannot stand in for PutChunk or Seal.
        strict_fields = ('extra', 'view-extra', 'schema-float', 'duplicate-key',
                         'missing', 'fail-id', 'fail-missing-id', 'fail-extra',
                         'fail-error-extra', 'fail-error-bool')
        cases = [('upload', 'Begin', field) for field in
                 ('provider', 'workspace', 'resource', 'snapshot') + strict_fields]
        cases += [('upload', 'PutChunk', field) for field in
                  ('id', 'range', 'digest', 'chunk-state') + strict_fields]
        cases += [('upload', 'Seal', field) for field in ('id', 'seal-state') + strict_fields]
        cases += [(verb, operation, field) for verb, operation in (('status', 'Get'), ('cancel', 'Cancel'))
                  for field in ('id',) + strict_fields]
        cases += [('status', 'Get', 'offset-float')]
        cases += [('cancel', 'Cancel', 'cancel-state')]
        # Valid peer round trips are positive controls for each actual CLI command.
        cases += [(verb, None, 'positive') for verb in ('upload', 'status', 'cancel')]
        cases += [('upload', None, 'resume-positive')]
        cases += [(verb, None, 'positive-human') for verb in ('upload', 'status', 'cancel')]
        for verb, target_operation, case in cases:
            with self.subTest(verb=verb, operation=target_operation, case=case):
                state = copy.deepcopy(view)
                resumed_blob = next(blob for blob in state['blobs'] if blob['size_bytes'] > observer.CHUNK)
                if case == 'resume-positive':
                    self.assertEqual(state['state'], 'Receiving')
                    resumed_blob['durable_offset'] = observer.CHUNK
                calls, requests, failures = [], [], []
                class Handler(BaseHTTPRequestHandler):
                    protocol_version = 'HTTP/1.1'
                    def do_POST(inner):
                        try:
                            inner.connection.settimeout(3)
                            size = int(inner.headers.get('Content-Length', '0'))
                            observer.require(0 < size <= 1024**2, 'bounded peer request')
                            body = inner.rfile.read(size)
                            observer.require(len(body) == size, 'complete peer body')
                            request = json.loads(body)
                            observer.require(body == observer.canonical(request), 'CLI canonical request bytes')
                            operation = request['operation']; calls.append(operation)
                            requests.append(request)
                            if operation != 'Begin':
                                observer.require(request['upload_id'] == view['upload_id'],
                                                 '§8 CLI request preserves the original UploadId')
                            if operation == 'Begin':
                                observer.require(request['provider'] == fixture.provider and
                                    request['workspace'] == fixture.workspace and
                                    request['snapshot'] == fixture.snapshot and
                                    request['resource'] == fixture.resource and request['upload_key'] == 'mock-peer',
                                    'explicit provider/resource/key and original request')
                            elif operation == 'PutChunk':
                                blob = next(blob for blob in state['blobs']
                                            if blob['sha256'] == request['blob_sha256'])
                                original = (fixture.bundle / 'blobs' /
                                            observer.blob_name(blob['sha256'])).read_bytes()
                                start = request['offset']; payload_bytes = bytes(request['bytes'])
                                observer.require(type(start) is int and start == blob['durable_offset'],
                                                 '§6 CLI starts each chunk at returned confirmed offset')
                                observer.require(0 < len(payload_bytes) <= observer.CHUNK and
                                    start + len(payload_bytes) <= len(original) and
                                    payload_bytes == original[start:start + len(payload_bytes)] and
                                    request['chunk_sha256'] == observer.digest(payload_bytes),
                                    '§6 CLI sends exact remaining original bytes with correct chunk digest')
                                blob['durable_offset'] = start + len(payload_bytes)
                            elif operation == 'Seal':
                                observer.require(all(blob['durable_offset'] == blob['size_bytes']
                                    for blob in state['blobs']), 'CLI uploaded every original byte before Seal')
                                state['state'] = 'Staged'
                            elif operation == 'Cancel':
                                state.update(state='Cancelled', reserved_bytes=0, blobs=[])
                            payload = {'schema_version': 1, 'verdict': 'PASS', 'upload': copy.deepcopy(state)}
                            if operation == target_operation: payload = mutate(case, request, payload)
                            response = observer.canonical(payload)
                            if operation == target_operation and case == 'duplicate-key':
                                response = response[:-1] + b',"schema_version":1}'
                            inner.send_response(200)
                            inner.send_header('Content-Type', 'application/json')
                            inner.send_header('Content-Length', str(len(response)))
                            inner.send_header('Connection', 'close')
                            inner.end_headers(); inner.wfile.write(response)
                        except Exception as error:
                            failures.append(type(error).__name__ + ': ' + str(error))
                            inner.close_connection = True
                    def log_message(inner, *_): pass
                server = HTTPServer(('127.0.0.1', 0), Handler)
                thread = threading.Thread(target=server.serve_forever)
                thread.start()
                try:
                    addr = '127.0.0.1:' + str(server.server_port)
                    args = (['snapshot', 'upload', '--bundle', fixture.bundle,
                        '--provider', fixture.provider, '--resource', fixture.resource,
                        '--key', 'mock-peer', '--addr', addr, '--json'] if verb == 'upload' else
                        ['snapshot', verb, view['upload_id'], '--addr', addr, '--json'])
                    if case == 'positive-human': args = args[:-1]
                    result = fixture.invoke(fixture.cli, args, 'peer-' + case, timeout=15)
                    self.assertEqual(failures, [], 'observer peer failed: ' + str(failures))
                    if case in ('positive', 'resume-positive', 'positive-human'):
                        self.assertEqual(result[0], 0)
                        if case != 'positive-human' or result[1]:
                            fixture.view(result, view['upload_id'], 'Staged' if verb == 'upload' else
                                         'Cancelled' if verb == 'cancel' else 'Receiving')
                        self.assertIn('Seal' if verb == 'upload' else 'Cancel' if verb == 'cancel' else 'Get', calls)

                        self.assertTrue(calls)
                        if verb == 'upload':
                            self.assertEqual(calls[0], 'Begin')
                            self.assertEqual(calls[-1], 'Seal')
                            chunks = [request for request in requests if request['operation'] == 'PutChunk']
                            self.assertTrue(chunks, 'upload control must send actual content')
                            self.assertEqual([r['blob_sha256'] for r in chunks],
                                             sorted(r['blob_sha256'] for r in chunks))
                            if case == 'resume-positive':
                                resumed_chunks = [r for r in chunks
                                                  if r['blob_sha256'] == resumed_blob['sha256']]
                                self.assertTrue(resumed_chunks, 'nonzero prefix has remaining bytes to upload')
                                self.assertEqual(resumed_chunks[0]['offset'], observer.CHUNK,
                                                 'CLI must use the Begin response nonzero durable offset')
                    else:
                        self.assertIn(target_operation, calls, 'intended adapter phase never reached')
                        # A malformed peer FAIL must become a correlated local
                        # rejection. Forwarding unrelated-upload unchanged is
                        # itself invalid, even when the CLI stops immediately.
                        target_request = requests[calls.index(target_operation)]
                        expected_id = (None if target_operation == 'Begin'
                                       else target_request['upload_id'])
                        self.assertTrue(observer.response_fail(result, upload_id=expected_id),
                                        'CLI accepted invalid response or returned an uncorrelated FAIL: ' + str(result))
                        self.assertEqual(calls[-1], target_operation, 'CLI continued after invalid correlated response')
                        self.assertEqual(calls.count(target_operation), 1,
                                         'CLI retried after the first invalid response')
                finally:
                    server.shutdown(); server.server_close(); thread.join(timeout=3)
                    self.assertFalse(thread.is_alive(), 'owned bounded HTTP observer thread reaped')

    def test_lost_marker_policy_ledger_lock_or_extra_unknown_file_denies_boot_zero_mutation(self):
        for kind in ('policy-v1.json', 'ledger-v1.json', 'staging.lock', 'entire-namespace',
                     'unknown-file', 'marker'):
            with self.subTest(kind=kind):
                fixture = observer.Fixture(self.fixture.base / kind)
                fixture.freeze()
                fixture.provision()
                if kind == 'entire-namespace':
                    shutil.rmtree(fixture.staging)
                elif kind == 'marker':
                    (fixture.root / 'snapshot-staging-required-v1.json').write_bytes(b'broken')
                elif kind == 'unknown-file':
                    (fixture.staging / 'unknown').write_bytes(b'preserve forensic bytes')
                else:
                    (fixture.staging / kind).unlink()
                before = observer.tree(fixture.root)
                with fixture.boot('denied-' + kind, expected=False):
                    pass
                self.assertEqual(observer.tree(fixture.root), before)
                self.assertFalse((fixture.root / 'localapi.token').exists())

    def test_cold_unexplained_tail_missing_confirmed_prefix_and_corruption_deny_without_reset(self):
        for kind in ('tail', 'short', 'corrupt'):
            with self.subTest(kind=kind):
                fixture = observer.Fixture(self.fixture.base / kind)
                fixture.freeze()
                fixture.provision()
                with fixture.boot('prepare-' + kind) as daemon:
                    view = fixture.begin(daemon)
                    big = next(file for file in fixture.manifest if file['size_bytes'] > observer.CHUNK)
                    data = (fixture.bundle / 'blobs' / observer.blob_name(big['sha256'])).read_bytes()
                    fixture.view(fixture.chunk(daemon, view['upload_id'], big['sha256'], 0,
                                              data[:observer.CHUNK]), view['upload_id'])
                blob = fixture.staging / 'uploads' / view['upload_id'] / 'blobs' / observer.blob_name(big['sha256'])
                if kind == 'tail':
                    with blob.open('ab') as stream:
                        stream.write(b'not from any durable intent')
                elif kind == 'short':
                    with blob.open('r+b') as stream:
                        stream.truncate(observer.CHUNK - 1)
                else:
                    with blob.open('r+b') as stream:
                        stream.write(bytes([data[0] ^ 1]))
                (fixture.root / 'localapi.token').unlink(missing_ok=True)
                before = observer.tree(fixture.root)
                with fixture.boot('corrupt-' + kind, expected=False):
                    pass
                self.assertEqual(observer.tree(fixture.root), before)
                self.assertFalse((fixture.root / 'localapi.token').exists())


if __name__ == '__main__':
    unittest.main()

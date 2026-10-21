"""Independent SHA/FNV observer of an existing-API requester export."""
import hashlib
import json
import pathlib

fixture = pathlib.Path(__file__).resolve().parent
facts = dict(line.split('=', 1) for line in (fixture / 'facts.txt').read_text().splitlines())
digest = lambda data: hashlib.sha256(data).hexdigest()
wire_digest = lambda data: 'sha256:' + digest(data)
canonical = lambda value: json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()

def fnv(data):
    value = 0xcbf29ce484222325
    for byte in data:
        value = ((value ^ byte) * 0x100000001b3) & 0xffffffffffffffff
    return f'{value:016x}'

cas = fixture / 'config/data/cas'
for path in cas.iterdir():
    assert fnv(path.read_bytes()) == path.name
state = (cas / facts['state_root']).read_text()
assert state.startswith('nexus-workspace-state v2\nid n312-source\n')
commits = {}
for line in state.splitlines():
    if not line.startswith('commit '):
        continue
    _, identity, root, parents, author, timestamp = line.split()
    parents = sorted(filter(None, parents.removeprefix('parents:').split(',')))
    author = author.removeprefix('author:')
    timestamp = timestamp.removeprefix('ts:')
    data = f'nexus-commit-v1\nparents:{",".join(parents)}\nroot:{root}\nauthor:{author}\ntimestamp:{timestamp}\n'.encode()
    assert fnv(data) == identity
    commits[identity] = root
assert commits[facts['old_commit']] == facts['old_manifest']
assert commits[facts['new_commit']] == facts['new_manifest']
assert f'head {facts["new_commit"]}\n' in state

files = []
for line in (cas / facts['old_manifest']).read_bytes().splitlines():
    path, legacy = line.split(b'\0')
    path, legacy = path.decode(), legacy.decode()
    data = (cas / legacy).read_bytes()
    assert fnv(data) == legacy
    if path.startswith('private/'):
        continue
    files.append({'path': path, 'sha256': wire_digest(data), 'size_bytes': len(data), 'executable': path == 'scripts/run.sh'})
files.sort(key=lambda item: item['path'])
selection = {'schema_version': 1, 'matching': 'exact-or-directory-prefix', 'include': ['.'], 'exclude': ['private'], 'executable': ['scripts/run.sh']}
snapshot = {'schema_version': 1, 'workspace': facts['workspace'], 'commit_id': facts['old_commit'], 'root_manifest_id': facts['old_manifest'], 'manifest_sha256': wire_digest(canonical(files)), 'selection_digest': wire_digest(canonical(selection)), 'file_count': len(files), 'total_bytes': sum(file['size_bytes'] for file in files)}
snapshot['snapshot_id'] = wire_digest(canonical(snapshot))
metadata = json.loads((fixture / 'metadata.json').read_text())
assert snapshot == metadata['expected_snapshot']
assert files == metadata['expected_manifest']
for relative, expected in metadata['fixture_files_sha256'].items():
    assert digest((fixture / relative).read_bytes()) == expected, relative
print(json.dumps({'verdict': 'PASS', 'cas_objects': len(list(cas.iterdir())), 'commit_count': len(commits), 'snapshot_id': snapshot['snapshot_id']}, sort_keys=True))

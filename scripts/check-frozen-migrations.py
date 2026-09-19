#!/usr/bin/env python3
"""Verify the merged migration baseline and unique version allocation.

Upstream 0001-0046 and the approved 1000 block are checksum-frozen.
Future migrations use admission records; existing SQL bytes never change.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
FROZEN_FIRST = 1
FROZEN_LAST = 1044
FROZEN_VERSIONS = set(range(1, 47)) | set(range(1029, 1036)) | set(range(1039, 1045))
FROZEN_LEDGERS = (
    'scripts/migrations-0001-0035.sha256',
    'scripts/migrations-0036-0042.sha256',
    'scripts/migrations-0043-0049.sha256',
)
OPERATION_MAP = 'migrations/operation-map.json'


def frozen_operations(root):
    """Map every frozen semantic operation id to the version that applied it."""
    doc = json.loads((root / OPERATION_MAP).read_text())
    ops = {}
    for entry in doc['fork']:
        if entry['version'] not in FROZEN_VERSIONS:
            continue
        for op in entry['operations']:
            ops.setdefault(op, entry['version'])
    return ops


def check(root=ROOT, admission_map=None):
    frozen = {}
    for ledger_name in FROZEN_LEDGERS:
        ledger = root / ledger_name
        for line in ledger.read_text().splitlines():
            digest, path = line.split()
            frozen[path] = digest
    if (len(frozen) != len(FROZEN_VERSIONS)
            or {int(Path(p).name[:4]) for p in frozen} != FROZEN_VERSIONS):
        raise ValueError(
            'frozen ledger must contain upstream 0001-0046 and the approved fork block')
    versions = set()
    for path in sorted((root / 'migrations').glob('*.sql')):
        match = re.fullmatch(r'(\d{4})_.+\.sql', path.name)
        if not match:
            raise ValueError(f'invalid migration filename: {path.name}')
        version = int(match[1])
        if version in versions:
            raise ValueError(f'duplicate migration version: {version:04}')
        versions.add(version)
        name = path.relative_to(root).as_posix()
        if version in FROZEN_VERSIONS and name not in frozen:
            raise ValueError(f'unrecorded historical migration: {name}')
    for name, digest in frozen.items():
        path = root / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError(f'frozen migration changed or missing: {name}')
    # The operation map is the operator-facing identity ledger used at cutover.
    entries = json.loads((root / OPERATION_MAP).read_text())['fork']
    if len(entries) != len(versions) or {e['version'] for e in entries} != versions:
        raise ValueError('operation map must cover each migration exactly once')
    for entry in entries:
        path = root / entry['file']
        if path.parent != root / 'migrations' or int(path.name[:4]) != entry['version']:
            raise ValueError(f'invalid operation-map path: {path}')
        raw = path.read_bytes()
        if (hashlib.sha256(raw).hexdigest() != entry['sha256']
                or hashlib.sha384(raw).hexdigest() != entry['sqlx_sha384']
                or path.stem[5:].replace('_', ' ') != entry['description']):
            raise ValueError(f'operation-map identity mismatch: {path.name}')
        if any(v not in versions or v >= entry['version'] for v in entry['prerequisites']):
            raise ValueError(f'invalid migration prerequisites: {path.name}')
    if admission_map is not None:
        targets = {}
        for entry in json.loads(Path(admission_map).read_text()):
            target = entry.get('proposed_target')
            if target is None:
                continue
            if not re.fullmatch(r'\d{4}_.+\.sql', target) or int(target[:4]) in FROZEN_VERSIONS or int(target[:4]) < 47:
                raise ValueError(f'unsafe admission target: {target}')
            if target in targets or any(name[:4] == target[:4] for name in targets):
                raise ValueError(f'duplicate admission version: {target[:4]}')
            targets[target] = entry
        frozen_ops = frozen_operations(root)
        for path in (root / 'migrations').glob('*.sql'):
            if int(path.name[:4]) in FROZEN_VERSIONS:
                continue
            entry = targets.get(path.name)
            if entry is None:
                raise ValueError(f'migration missing from admission map: {path.name}')
            for field in ('source_commit', 'source_path', 'source_sha256',
                          'adapted_sql_sha256', 'desired_schema_delta'):
                if not entry.get(field):
                    raise ValueError(f'admission map missing {field}: {path.name}')
            # Prerequisites are a typed list: an independent operation carries
            # an explicit empty list, never a missing key or a dummy entry.
            prerequisites = entry.get('prerequisites')
            if not isinstance(prerequisites, list):
                raise ValueError(f'admission map missing prerequisites: {path.name}')
            operations = entry.get('operations')
            if not isinstance(operations, list) or not operations:
                raise ValueError(f'admission map missing operations: {path.name}')
            supersedes = entry.get('supersedes', [])
            if not isinstance(supersedes, list):
                raise ValueError(f'admission map supersedes must be a list: {path.name}')
            for op in operations:
                if op in frozen_ops and op not in supersedes:
                    raise ValueError(
                        f'duplicate semantic operation {op} from {frozen_ops[op]:04}: {path.name}')
            if hashlib.sha256(path.read_bytes()).hexdigest() != entry['adapted_sql_sha256']:
                raise ValueError(f'admitted migration hash mismatch: {path.name}')
    print(f'frozen migrations: {len(FROZEN_VERSIONS)} files unchanged; '
          'migration versions unique')


if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--map", type=Path, help="foundation admission ledger JSON")
        check(admission_map=parser.parse_args().map)
    except ValueError as error:
        raise SystemExit(str(error)) from error

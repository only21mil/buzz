#!/usr/bin/env python3
"""Verify the frozen Buzz migration prefix and unique version allocation.

The frozen prefix is 0001-0042, pinned by two checksum manifests that must
both be present: the original 0001-0035 ledger (kept byte-identical) and the
audited 0036-0042 extension. Applied migration bytes are never edited,
renumbered, or re-checksummed; new work appends above the verified maximum
through the admission map, which additionally guards against re-executing an
already-applied semantic operation under a new number.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
FROZEN_FIRST = 1
FROZEN_LAST = 42
FROZEN_LEDGERS = (
    'scripts/migrations-0001-0035.sha256',
    'scripts/migrations-0036-0042.sha256',
)
OPERATION_MAP = 'migrations/operation-map.json'


def frozen_operations(root):
    """Map every frozen semantic operation id to the version that applied it."""
    doc = json.loads((root / OPERATION_MAP).read_text())
    ops = {}
    for entry in doc['fork']:
        if entry['version'] > FROZEN_LAST:
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
    if (len(frozen) != FROZEN_LAST
            or {int(Path(p).name[:4]) for p in frozen} != set(range(FROZEN_FIRST, FROZEN_LAST + 1))):
        raise ValueError(
            f'frozen ledger must contain exactly versions {FROZEN_FIRST:04}-{FROZEN_LAST:04}')
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
        if version <= FROZEN_LAST and name not in frozen:
            raise ValueError(f'unrecorded historical migration: {name}')
    for name, digest in frozen.items():
        path = root / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError(f'frozen migration changed or missing: {name}')
    if admission_map is not None:
        targets = {}
        for entry in json.loads(Path(admission_map).read_text()):
            target = entry.get('proposed_target')
            if target is None:
                continue
            if not re.fullmatch(r'\d{4}_.+\.sql', target) or int(target[:4]) <= FROZEN_LAST:
                raise ValueError(f'unsafe admission target: {target}')
            if target in targets or any(name[:4] == target[:4] for name in targets):
                raise ValueError(f'duplicate admission version: {target[:4]}')
            targets[target] = entry
        frozen_ops = frozen_operations(root)
        for path in (root / 'migrations').glob('*.sql'):
            if int(path.name[:4]) <= FROZEN_LAST:
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
    print(f'frozen migrations {FROZEN_FIRST:04}-{FROZEN_LAST:04} unchanged; '
          'migration versions unique')


if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--map", type=Path, help="foundation admission ledger JSON")
        check(admission_map=parser.parse_args().map)
    except ValueError as error:
        raise SystemExit(str(error)) from error

#!/usr/bin/env python3
"""Verify the frozen Buzz main migration prefix and unique version allocation."""
import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def check(root=ROOT, admission_map=None):
    ledger = root / 'scripts/migrations-0001-0035.sha256'
    frozen = {}
    for line in ledger.read_text().splitlines():
        digest, path = line.split()
        frozen[path] = digest
    if len(frozen) != 35 or {int(Path(p).name[:4]) for p in frozen} != set(range(1, 36)):
        raise ValueError('frozen ledger must contain exactly versions 0001-0035')
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
        if version <= 35 and name not in frozen:
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
            if not re.fullmatch(r'\d{4}_.+\.sql', target) or int(target[:4]) <= 35:
                raise ValueError(f'unsafe admission target: {target}')
            if target in targets or any(name[:4] == target[:4] for name in targets):
                raise ValueError(f'duplicate admission version: {target[:4]}')
            targets[target] = entry
        for path in (root / 'migrations').glob('*.sql'):
            if int(path.name[:4]) <= 35:
                continue
            entry = targets.get(path.name)
            if entry is None:
                raise ValueError(f'migration missing from admission map: {path.name}')
            for field in ('source_commit', 'source_path', 'source_sha256',
                          'adapted_sql_sha256', 'prerequisites', 'desired_schema_delta'):
                if not entry.get(field):
                    raise ValueError(f'admission map missing {field}: {path.name}')
            if hashlib.sha256(path.read_bytes()).hexdigest() != entry['adapted_sql_sha256']:
                raise ValueError(f'admitted migration hash mismatch: {path.name}')
    print('frozen migrations 0001-0035 unchanged; migration versions unique')


if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--map", type=Path, help="foundation admission ledger JSON")
        check(admission_map=parser.parse_args().map)
    except ValueError as error:
        raise SystemExit(str(error)) from error

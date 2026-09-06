#!/usr/bin/env python3
"""Compile and reconcile all PostgreSQL libtest targets, then run isolated cases."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile

from postgres_test_inventory import ROOT, reconcile, validate

spec = importlib.util.spec_from_file_location('local', ROOT / 'scripts/postgres-test-local.py')
local = importlib.util.module_from_spec(spec)
spec.loader.exec_module(local)


def artifact_binaries(paths, required):
    binaries = {}
    for path in paths:
        for line in path.read_text().splitlines():
            event = json.loads(line)
            if (event.get('reason') != 'compiler-artifact'
                    or not event.get('profile', {}).get('test') or not event.get('executable')):
                continue
            target = event['target']
            name = target['name'].replace('-', '_')
            if name not in required or not set(target['kind']) & {'lib', 'test'}:
                continue
            binary = Path(event['executable']).resolve(strict=True)
            if name in binaries and binaries[name] != binary:
                raise ValueError(f'ambiguous test artifacts: {name}')
            binaries[name] = binary
    if binaries.keys() != required:
        raise ValueError(f'missing PostgreSQL binaries: {sorted(required - binaries.keys())}')
    return binaries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--task-root', type=Path, required=True)
    parser.add_argument('--pg-bin-dir', type=Path)
    parser.add_argument('--artifacts', type=Path, nargs='+', help='existing cargo JSON; otherwise compile')
    parser.add_argument('--list', action='store_true', help='reconcile compiled inventory without starting PostgreSQL')
    args = parser.parse_args()
    env = local.clean_environment(os.environ)  # refuse targets before any build/discovery
    rows = validate()
    admitted = [r for r in rows if r['mode'] != 'external']
    required = {r['binary'] for r in admitted}
    task_root = args.task_root.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix='pg-build-', dir=task_root) as temporary:
        paths = args.artifacts or []
        if not args.artifacts:
            for package in sorted({r['package'] for r in admitted}):
                command = ['cargo', 'test', '-p', package, '--no-run', '--message-format=json']
                for binary in sorted({r['binary'] for r in admitted if r['package'] == package}):
                    command += ['--lib'] if binary == package.replace('-', '_') else ['--test', binary]
                path = Path(temporary) / (package + '.jsonl')
                with path.open('w') as output:
                    subprocess.run(command, cwd=ROOT, env=env, stdout=output, check=True)
                paths.append(path)
        binaries = artifact_binaries(paths, required)
        selected = []
        for name, binary in sorted(binaries.items()):
            discovered = subprocess.run(
                ['python3', str(ROOT / 'scripts/postgres-test-local.py'), '--list',
                 '--task-root', str(task_root), str(binary)], env=env, text=True,
                capture_output=True, check=True)
            names = [line.split('\t')[1] for line in discovered.stdout.splitlines()
                     if len(line.split('\t')) == 3]
            for test, mode in reconcile(binary, names, rows):
                print(f'{name}\t{test}\t{mode}', flush=True)
                if mode != 'external':
                    selected.append((binary, test))
        if args.list:
            return
        for binary, test in selected:
            command = ['python3', str(ROOT / 'scripts/postgres-test-local.py'),
                       '--task-root', str(task_root), '--filter', test, '--exact', str(binary)]
            if args.pg_bin_dir:
                command += ['--pg-bin-dir', str(args.pg_bin_dir)]
            subprocess.run(command, cwd=ROOT, env=env, check=True)


if __name__ == '__main__':
    try:
        main()
    except ValueError as error:
        raise SystemExit(str(error)) from error
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode if error.returncode > 0 else 128 - error.returncode) from error

#!/usr/bin/env python3
"""Run ignored Rust tests in disposable PostgreSQL databases, one per test.

Adapted from block/buzz bd73490418266f267d9bb3bdf13e64582adc8e80's
postgres-test-{run,setup,wrapper}.sh. No existing database is accepted.
"""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
TARGET_VARS = ('DATABASE_URL', 'TEST_DATABASE_URL', 'BUZZ_TEST_DATABASE_URL',
               'READ_DATABASE_URL', 'BUZZ_POSTGRES_ADMIN_URL')


def clean_environment(source):
    if any(source.get(key) for key in TARGET_VARS):
        raise ValueError('refusing inherited database URL; unset database target variables')
    # libpq can otherwise consult service files, passwords or remote defaults.
    return {key: value for key, value in source.items()
            if not key.startswith('PG') and key not in TARGET_VARS}


def database_name(binary, test):
    identity = str(binary) + '\0' + test
    return 'buzz_nt_' + hashlib.sha256(identity.encode()).hexdigest()[:24]


def schema_mode(test, binary=None):
    # These fork integration fixtures call run_migrations themselves.
    if binary is not None and any(Path(binary).name.startswith(name + '-') for name in (
            'ci_grants_contract', 'workflow_approval_contract',
            'workflow_enabled_persistence', 'workflow_state_contract')):
        return 'migration'
    return 'migration' if ('migration_schema_' in test or
        '::migration::' in '::' + test or
        test == 'populated_migration_preserves_legacy_approval_and_backfills_resume_state') else 'desired'


def command(argv, env, **kwargs):
    return subprocess.run([str(arg) for arg in argv], env=env, check=True, **kwargs)


def discover(binary, env, pattern):
    output = command([binary, '--list', '--ignored', '--format', 'terse'], env,
                     capture_output=True, text=True).stdout
    return [line[:-6] for line in output.splitlines()
            if line.endswith(': test') and pattern in line[:-6]]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--task-root', type=Path, required=True,
                        help='existing task directory for cluster, socket and logs')
    parser.add_argument('--pg-bin-dir', type=Path)
    parser.add_argument('--filter', default='')
    parser.add_argument('--schema-mode', choices=('auto', 'desired', 'migration'), default='auto')
    parser.add_argument('--repo-root', type=Path, default=ROOT, help='desired-schema source worktree')
    parser.add_argument('--list', action='store_true', help='inventory without starting PostgreSQL')
    parser.add_argument('binary', type=Path, nargs='+', help='compiled Rust libtest binaries')
    args = parser.parse_args()
    def mode(test, binary):
        return schema_mode(test, binary) if args.schema_mode == 'auto' else args.schema_mode
    env = clean_environment(os.environ)
    binaries = [path.resolve(strict=True) for path in args.binary]
    tests = [(binary, test) for binary in binaries
             for test in discover(binary, env, args.filter)]
    if not tests:
        parser.error('no ignored tests selected')
    for binary, test in tests:
        print(f'{binary.name}\t{test}\t{mode(test, binary)}', flush=True)
    if args.list:
        return
    pg = {}
    for name in ('initdb', 'pg_ctl', 'psql', 'createdb', 'dropdb'):
        path = str(args.pg_bin_dir / name) if args.pg_bin_dir else shutil.which(name)
        if not path or not os.access(path, os.X_OK):
            parser.error(f'missing PostgreSQL executable: {name}; supply --pg-bin-dir')
        pg[name] = path
    task_root = args.task_root.resolve(strict=True)
    # libpq Unix-domain socket addresses have a short platform limit.
    if len(os.fsencode(task_root)) > 75:
        parser.error('task-root path must be at most 75 bytes for PostgreSQL Unix sockets')
    local = Path(tempfile.mkdtemp(prefix='pg-', dir=task_root))
    safe_to_remove = True
    try:
        data, socket = local / 'data', local / 's'
        socket.mkdir(mode=0o700)
        (local / 'pgpass').touch(mode=0o600)
        env.update(PGHOST=str(socket), PGPORT='5432', PGUSER='buzz_test',
                   PGDATABASE='postgres', PGPASSFILE=str(local / 'pgpass'), PGSERVICEFILE='/dev/null')
        def stop_signal(signum, _frame):
            raise SystemExit(128 + signum)
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(signum, stop_signal)
        started = False
        try:
            command([pg['initdb'], '-D', data, '-U', 'buzz_test', '--auth-local=trust',
                     '--auth-host=reject', '--no-locale', '--encoding=UTF8'], env,
                    stdout=subprocess.DEVNULL)
            # TCP disabled; access is confined to the mode-0700 task-owned socket.
            with (data / 'postgresql.conf').open('a') as config:
                config.write("\nlisten_addresses = ''\nunix_socket_directories = '" +
                             str(socket).replace("'", "''") + "'\n")
            started = True  # also stop a server whose startup wait is interrupted
            safe_to_remove = False
            command([pg['pg_ctl'], '-D', data, '-l', local / 'postgres.log', '-w', 'start'], env)
            for binary, test in tests:
                database = database_name(binary, test)
                command([pg['createdb'], '--template=template0', database], env)
                try:
                    if mode(test, binary) == 'desired':
                        command([pg['psql'], '-X', '-d', database, '-v', 'ON_ERROR_STOP=1',
                                 '-f', args.repo_root.resolve() / 'schema/schema.sql'], env,
                                stdout=subprocess.DEVNULL)
                    url = 'postgresql://buzz_test@buzz-test.invalid/' + database + '?' + urlencode({'host': str(socket)})
                    test_env = dict(env, DATABASE_URL=url, TEST_DATABASE_URL=url,
                                    BUZZ_TEST_DATABASE_URL=url, BUZZ_TEST_SCHEMA_MODE=mode(test, binary))
                    command([binary, '--ignored', '--exact', test, '--nocapture',
                             '--test-threads=1'], test_env)
                finally:
                    command([pg['dropdb'], '--if-exists', '--force', database], env)
        finally:
            if started:
                # Do not delete data unless PostgreSQL has stopped successfully.
                stopped = subprocess.run([pg['pg_ctl'], '-D', str(data), '-m', 'immediate',
                                          '-w', 'stop'], env=env)
                if stopped.returncode and (data / 'postmaster.pid').exists():
                    safe_to_remove = False
                    raise RuntimeError(f'could not stop disposable cluster: {data}')
                safe_to_remove = True

    finally:
        if safe_to_remove:
            shutil.rmtree(local)


if __name__ == '__main__':
    try:
        main()
    except ValueError as error:
        raise SystemExit(str(error)) from error

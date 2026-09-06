#!/usr/bin/env python3
"""Run HTML HTTP acceptance in a disposable network namespace and data tree.

Caller must create a fresh network namespace containing only loopback, bring
loopback up, and drop privileges before invoking this script. Binaries are
supplied explicitly; this script never downloads, compiles, or installs tools.
All credentials below are public synthetic fixture values with no authority
outside this namespace. No ambient environment or credential files are used.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
from urllib.parse import urlencode
from urllib.request import urlopen


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--task-root', type=Path, required=True)
    parser.add_argument('--pg-bin-dir', type=Path, required=True)
    parser.add_argument('--tools-dir', type=Path, required=True)
    parser.add_argument('--relay-binary', type=Path, required=True)
    parser.add_argument('--test-binary', type=Path, required=True)
    parser.add_argument('--host-netns', required=True, help='readlink /proc/self/ns/net before unshare')
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error('run as the ordinary task owner, not root')
    if os.readlink('/proc/self/ns/net') == args.host_netns:
        parser.error('requires a fresh private network namespace')
    interfaces = json.loads(subprocess.check_output(['/usr/bin/ip', '-json', 'link'],
                            env={'PATH': '/usr/bin:/bin'}))
    if [interface['ifname'] for interface in interfaces] != ['lo']:
        parser.error('network namespace must contain only loopback')
    root = args.task_root.resolve(strict=True)
    paths = {name: path.resolve(strict=True) for name, path in {
        'relay': args.relay_binary, 'test': args.test_binary,
        'minio': args.tools_dir / 'minio', 'mc': args.tools_dir / 'mc',
        'redis': args.tools_dir / 'usr/bin/valkey-server',
        **{name: args.pg_bin_dir / name for name in ['initdb', 'pg_ctl', 'createdb', 'psql']},
    }.items()}
    os.umask(0o077)
    local = Path(tempfile.mkdtemp(prefix='html-live-', dir=root))
    logs = root / ('html-acceptance-evidence-' + local.name.removeprefix('html-live-'))
    logs.mkdir(mode=0o700)
    # Whitelist excludes PG*, AWS*, proxy, telemetry, real relay keys and URLs.
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(local / 'home'),
           'LANG': 'C.UTF-8', 'TMPDIR': str(local / 'tmp')}
    for name in ['home', 'tmp', 'socket', 'redis', 's3', 'git']:
        (local / name).mkdir(mode=0o700)
    env.update(PGHOST=str(local / 'socket'), PGPORT='5432', PGUSER='buzz_html',
               PGDATABASE='postgres', PGPASSFILE='/dev/null', PGSERVICEFILE='/dev/null')
    processes, handles = [], []
    pg_started = False
    cleanup_ok = True
    def command(argv, child_env=env):
        return subprocess.run([str(x) for x in argv], env=child_env, cwd=local,
                              check=True, stdout=transcript, stderr=subprocess.STDOUT)
    def start(name, argv, child_env=env):
        output = (logs / (name + '.log')).open('w')
        handles.append(output)
        child = subprocess.Popen([str(x) for x in argv], env=child_env, cwd=local,
                                 stdout=output, stderr=subprocess.STDOUT)
        processes.append(child)
        return child
    def wait_http(url, child):
        for _ in range(150):
            if child.poll() is not None:
                raise RuntimeError(f'fixture process exited: {child.returncode}')
            try:
                with urlopen(url, timeout=1) as response:
                    if response.status == 200:
                        return
            except OSError:
                pass
            time.sleep(0.2)
        raise RuntimeError('fixture readiness timeout')
    def interrupted(signum, _frame):
        raise SystemExit(128 + signum)
    for signum in [signal.SIGTERM, signal.SIGINT, signal.SIGHUP]:
        signal.signal(signum, interrupted)
    print(f'evidence={logs}', flush=True)
    with (logs / 'commands.log').open('w') as transcript:
        try:
            (logs / 'binaries.json').write_text(json.dumps({name: {
                'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()
            } for name, path in paths.items()}, indent=2) + '\n')
            command([paths['initdb'], '-D', local / 'pg', '-U', 'buzz_html',
                     '--auth-local=trust', '--auth-host=reject', '--no-locale', '--encoding=UTF8'])
            with (local / 'pg/postgresql.conf').open('a') as config:
                config.write("\nlisten_addresses = ''\nunix_socket_directories = '" +
                             str(local / 'socket').replace("'", "''") + "'\n")
            pg_started = True
            command([paths['pg_ctl'], '-D', local / 'pg', '-l', logs / 'postgres.log', '-w', 'start'])
            command([paths['createdb'], '--template=template0', 'buzz_html'])
            redis = start('redis', [paths['redis'], '--bind', '127.0.0.1', '--port', '16379',
                          '--dir', local / 'redis', '--save', '', '--appendonly', 'no'])
            fixture_access, fixture_secret = 'html_fixture_only', 'html_fixture_only_not_real'
            minio_env = dict(env, MINIO_ROOT_USER=fixture_access, MINIO_ROOT_PASSWORD=fixture_secret,
                             MINIO_BROWSER='off', MINIO_UPDATE='off')
            minio = start('minio', [paths['minio'], 'server', local / 's3',
                          '--address', '127.0.0.1:19000', '--console-address', '127.0.0.1:19001'], minio_env)
            wait_http('http://127.0.0.1:19000/minio/health/live', minio)
            bucket = 'html-acceptance-' + local.name.removeprefix('html-live-')
            mc_env = dict(env, MC_HOST_fixture=f'http://{fixture_access}:{fixture_secret}@127.0.0.1:19000')
            command([paths['mc'], '--config-dir', local / 'mc', 'mb', 'fixture/' + bucket], mc_env)
            url = 'postgresql://buzz_html@buzz-test.invalid/buzz_html?' + urlencode({'host': str(local / 'socket')})
            base = 'http://127.0.0.1:13000'
            relay_env = dict(env, DATABASE_URL=url, REDIS_URL='redis://127.0.0.1:16379',
                RELAY_URL='ws://127.0.0.1:13000', RELAY_HTTP_URL=base,
                BUZZ_BIND_ADDR='127.0.0.1:13000', BUZZ_HEALTH_PORT='18080', BUZZ_METRICS_PORT='19102',
                BUZZ_AUTO_MIGRATE='true', BUZZ_GIT_REPO_PATH=str(local / 'git'),
                BUZZ_RELAY_PRIVATE_KEY='1'.zfill(64), BUZZ_PUSH_GATEWAY_DELIVERY_URL='',
                BUZZ_S3_ENDPOINT='http://127.0.0.1:19000', BUZZ_S3_ACCESS_KEY=fixture_access,
                BUZZ_S3_SECRET_KEY=fixture_secret, BUZZ_S3_BUCKET=bucket,
                BUZZ_S3_REGION='us-east-1', BUZZ_S3_ADDRESSING_STYLE='path',
                BUZZ_MEDIA_BASE_URL=base + '/media', RUST_LOG='buzz_relay=info')
            relay = start('relay', [paths['relay']], relay_env)
            wait_http(base + '/health', relay)
            command(['/usr/bin/ip', '-brief', 'address'])
            command(['/usr/bin/ss', '-lntp'])
            command([paths['test'], '--ignored', '--exact', 'test_upload_html_served_as_inert_attachment',
                     '--nocapture', '--test-threads=1'], relay_env)
            # The supplemental test uses public synthetic key 2, a member of
            # both explicitly seeded communities. Restart with membership on
            # so a tenant denial cannot be mistaken for an auth-only failure.
            relay.terminate()
            relay.wait(timeout=40)
            seed = local / 'seed.sql'
            seed.write_text("""
INSERT INTO communities (host) VALUES ('127.0.0.1:13000'), ('html-b.localhost:13000')
ON CONFLICT DO NOTHING;
INSERT INTO relay_members (community_id, pubkey, role)
SELECT id, 'c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5', 'member'
FROM communities WHERE host IN ('127.0.0.1:13000', 'html-b.localhost:13000');
SELECT host, role FROM communities JOIN relay_members ON id = community_id ORDER BY host;
""")
            command([paths['psql'], '-X', '-d', 'buzz_html', '-v', 'ON_ERROR_STOP=1', '-f', seed])
            tenant_env = dict(relay_env, BUZZ_REQUIRE_RELAY_MEMBERSHIP='true',
                              RELAY_OWNER_PUBKEY='79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
                              HTML_TEST_OTHER_HOST='html-b.localhost:13000')
            relay = start('relay-membership', [paths['relay']], tenant_env)
            wait_http(base + '/health', relay)
            command([paths['test'], '--ignored', '--exact', 'test_html_tenant_read_denial',
                     '--nocapture', '--test-threads=1'], tenant_env)
            command([paths['mc'], '--config-dir', local / 'mc', 'ls', '--recursive', 'fixture/' + bucket], mc_env)
            (logs / 'result.txt').write_text('PASS: HTML relay HTTP acceptance completed.\n')
        finally:
            for child in reversed(processes):
                if child.poll() is None:
                    child.terminate()
                try:
                    child.wait(timeout=40)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=10)
            if pg_started:
                stopped = subprocess.run([str(paths['pg_ctl']), '-D', str(local / 'pg'),
                    '-m', 'immediate', '-w', 'stop'], env=env, cwd=local,
                    stdout=transcript, stderr=subprocess.STDOUT)
                cleanup_ok = stopped.returncode == 0 or not (local / 'pg/postmaster.pid').exists()
            for handle in handles:
                handle.close()
            if cleanup_ok:
                shutil.rmtree(local)
                (logs / 'cleanup.txt').write_text('All owned processes stopped; private data tree removed.\n')
            else:
                raise RuntimeError(f'PostgreSQL shutdown failed; preserving {local}')


if __name__ == '__main__':
    main()

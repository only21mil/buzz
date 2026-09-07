#!/usr/bin/env python3
"""Run fixed Relay E2E invite or HTML tenant cases with owned fenced services."""
import argparse
import json
import os
from pathlib import Path
import runpy
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlencode
from urllib.request import urlopen

import postgres_test_fence as fence
from postgres_test_inventory import ROOT, read_inventory, reconcile

local = runpy.run_path(str(ROOT / 'scripts/postgres-test-local.py'))
INVITE_TESTS = (
    'test_invite_claim_rejects_invalid_code',
    'test_invite_code_minted_for_one_host_fails_on_another',
    'test_invite_mint_and_claim_admits_new_pubkey',
    'test_invite_mint_requires_owner_or_admin',
    'test_private_channel_admin_can_invite',
    'test_private_channel_member_cannot_invite',
    'test_private_channel_non_member_cannot_invite',
)


def invite_inventory(binary, env):
    # Execute libtest discovery only after the caller has verified the fence.
    tests = local['discover'](binary, env, '')
    reconcile(binary, tests, read_inventory())
    selected = sorted(test for test in tests if 'invite' in test)
    if selected != list(INVITE_TESTS):
        raise ValueError('Relay E2E invite selection changed; update the owned fixture inventory')
    return selected


HTML_TENANT_TEST = 'test_html_tenant_read_denial'


def html_tenant_inventory(binary, env):
    tests = local['discover'](binary, env, '')
    reconcile(binary, tests, read_inventory())
    if HTML_TENANT_TEST not in tests:
        raise ValueError('HTML tenant test missing from compiled discovery')
    return [HTML_TENANT_TEST]


def inside_main(html_tenants=False):
    env = dict(os.environ)  # The production fence supplied a fresh allowlist.
    # reqwest requires a root even for these HTTP-only tests. Use the public
    # test certificate; never mount a host trust store or disable TLS checks.
    env['SSL_CERT_FILE'] = '/fixture-ca.pem'
    binary = Path('/binaries/e2e_media_extended' if html_tenants else '/binaries/e2e_relay')
    tests = html_tenant_inventory(binary, env) if html_tenants else invite_inventory(binary, env)
    work = Path(tempfile.mkdtemp(prefix='invite-', dir='/work'))
    processes, handles = [], []
    pg_started = False
    cleanup_ok = True
    for name in ('socket', 'redis', 's3', 'git'):
        (work / name).mkdir(mode=0o700)
    env.update(PGHOST=str(work / 'socket'), PGPORT='5432', PGUSER='buzz_test',
               PGDATABASE='postgres', PGPASSFILE='/dev/null', PGSERVICEFILE='/dev/null')

    def command(args, child_env=env, **kwargs):
        return local['command'](args, child_env, **kwargs)

    def start(name, args, child_env=env):
        output = (work / (name + '.log')).open('w')
        handles.append(output)
        child = subprocess.Popen([str(arg) for arg in args], env=child_env, cwd=work,
                                 stdout=output, stderr=subprocess.STDOUT)
        processes.append(child)
        return child

    def wait_http(url):
        for _ in range(150):
            if any(child.poll() is not None for child in processes):
                raise RuntimeError('owned fixture process exited before readiness')
            try:
                with urlopen(url, timeout=1) as response:
                    if response.status == 200:
                        return
            except OSError:
                pass
            time.sleep(0.2)
        raise RuntimeError('owned fixture readiness timeout')

    def interrupted(signum, _frame):
        raise SystemExit(128 + signum)

    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, interrupted)
    try:
        command(['/pg/bin/initdb', '-D', work / 'pg', '-U', 'buzz_test',
                 '--auth-local=trust', '--auth-host=reject', '--no-locale', '--encoding=UTF8'],
                stdout=subprocess.DEVNULL)
        with (work / 'pg/postgresql.conf').open('a') as config:
            config.write("\nlisten_addresses = ''\nunix_socket_directories = '" +
                         str(work / 'socket') + "'\n")
        pg_started = True
        cleanup_ok = False
        command(['/pg/bin/pg_ctl', '-D', work / 'pg', '-l', work / 'postgres.log', '-w', 'start'])
        command(['/pg/bin/createdb', '--template=template0', 'buzz_invites'])
        start('redis', ['/binaries/redis-server', '--bind', '127.0.0.1', '--port', '6379',
                        '--dir', work / 'redis', '--save', '', '--appendonly', 'no'])
        # Public synthetic credentials exist only in this private fixture.
        access, secret = 'invite_fixture_only', 'invite_fixture_only_not_real'
        minio_env = dict(env, MINIO_ROOT_USER=access, MINIO_ROOT_PASSWORD=secret,
                         MINIO_BROWSER='off', MINIO_UPDATE='off')
        start('minio', ['/binaries/minio', 'server', work / 's3',
                        '--address', '127.0.0.1:9000', '--console-address', '127.0.0.1:9001'], minio_env)
        wait_http('http://127.0.0.1:9000/minio/health/live')
        command(['/binaries/mc', '--config-dir', work / 'mc', 'mb', 'fixture/buzz-invites'],
                dict(env, MC_HOST_fixture=f'http://{access}:{secret}@127.0.0.1:9000'))
        url = 'postgresql://buzz_test@buzz-test.invalid/buzz_invites?' + urlencode({'host': str(work / 'socket')})
        relay_env = dict(env, DATABASE_URL=url, TEST_DATABASE_URL=url, BUZZ_TEST_DATABASE_URL=url,
                         REDIS_URL='redis://127.0.0.1:6379', RELAY_URL='ws://localhost:3000',
                         RELAY_HTTP_URL='http://localhost:3000', BUZZ_BIND_ADDR='127.0.0.1:3000',
                         BUZZ_AUTO_MIGRATE='true', BUZZ_GIT_REPO_PATH=str(work / 'git'),
                         BUZZ_RELAY_PRIVATE_KEY='1'.zfill(64), BUZZ_PUSH_GATEWAY_DELIVERY_URL='',
                         BUZZ_REQUIRE_AUTH_TOKEN='false', BUZZ_GIT_PROBE_WRITERS='8',
                         BUZZ_S3_ENDPOINT='http://127.0.0.1:9000', BUZZ_S3_ACCESS_KEY=access,
                         BUZZ_S3_SECRET_KEY=secret, BUZZ_S3_BUCKET='buzz-invites',
                         BUZZ_S3_REGION='us-east-1', BUZZ_S3_ADDRESSING_STYLE='path',
                         RUST_LOG='buzz_relay=info')
        relay = start('relay', ['/binaries/buzz-relay'], relay_env)
        wait_http('http://127.0.0.1:3000/_readiness')
        if html_tenants:
            # Migrations ran in the owned relay. Seed only these two synthetic
            # communities, then restart with membership enforcement enabled.
            relay.terminate()
            relay.wait(timeout=40)
            processes.remove(relay)
            seed = work / 'html-tenants.sql'
            seed.write_text("""
INSERT INTO communities (host) VALUES ('localhost:3000'), ('html-b.localhost:3000')
ON CONFLICT DO NOTHING;
INSERT INTO relay_members (community_id, pubkey, role)
SELECT id, 'c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5', 'member'
FROM communities WHERE host IN ('localhost:3000', 'html-b.localhost:3000');
""")
            command(['/pg/bin/psql', '-X', '-d', 'buzz_invites', '-v', 'ON_ERROR_STOP=1', '-f', seed])
            relay_env.update(BUZZ_REQUIRE_RELAY_MEMBERSHIP='true',
                             RELAY_OWNER_PUBKEY='79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
                             HTML_TEST_OTHER_HOST='html-b.localhost:3000')
            relay = start('relay-membership', ['/binaries/buzz-relay'], relay_env)
            wait_http('http://127.0.0.1:3000/_readiness')
        for test in tests:
            result = command([binary, '--ignored', '--exact', test,
                              '--nocapture', '--test-threads=1'], relay_env,
                             capture_output=True, text=True)
            print(result.stdout, end='', flush=True)
            print(result.stderr, end='', file=sys.stderr, flush=True)
            local['require_one_test'](result.stdout, test)
        if relay.poll() is not None:
            raise RuntimeError('owned relay exited during tests')
        label = 'HTML tenant read denial' if html_tenants else 'all seven Relay E2E invite cases'
        print(f'PASS: {label} executed inside PostgreSQL fence', flush=True)
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
            stopped = subprocess.run(['/pg/bin/pg_ctl', '-D', str(work / 'pg'),
                                      '-m', 'immediate', '-w', 'stop'], env=env)
            cleanup_ok = stopped.returncode == 0 or not (work / 'pg/postmaster.pid').exists()
        for handle in handles:
            handle.close()
        for log in sorted(work.glob('*.log')):
            print(f'--- owned {log.name} ---\n{log.read_text()}', flush=True)
        if cleanup_ok:
            shutil.rmtree(work)
            print('CLEANUP: owned relay, Redis and MinIO reaped; PostgreSQL stopped; private data removed', flush=True)
        else:
            raise RuntimeError(f'PostgreSQL shutdown failed; preserving {work}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--html-tenants', action='store_true', help='run the exact two-tenant HTML read denial case')
    parser.add_argument('--task-root', type=Path, required=True)
    parser.add_argument('--pg-bin-dir', type=Path, required=True)
    parser.add_argument('--relay-binary', type=Path, required=True)
    parser.add_argument('--redis-binary', type=Path, default=shutil.which('redis-server'))
    parser.add_argument('--s3-tools-dir', type=Path, required=True, help='directory containing minio and mc')
    parser.add_argument('--test-binary', type=Path, help='otherwise compile the CI libtest target')
    args = parser.parse_args()
    env = local['clean_environment'](os.environ)
    target = 'e2e_media_extended' if args.html_tenants else 'e2e_relay'
    if args.redis_binary is None:
        parser.error('missing redis-server; supply --redis-binary')
    with tempfile.TemporaryDirectory(prefix='relay-invite-fence-', dir=args.task_root.resolve(strict=True)) as temporary:
        test_binary = args.test_binary
        if test_binary is None:
            artifacts = Path(temporary) / 'artifacts.jsonl'
            with artifacts.open('w') as output:
                subprocess.run(['cargo', 'test', '-p', 'buzz-test-client', '--test', target,
                                '--no-run', '--message-format=json'], cwd=ROOT, env=env, stdout=output, check=True)
            compiled = runpy.run_path(str(ROOT / 'scripts/postgres-test-run.py'))
            test_binary = compiled['artifact_binaries']([artifacts], {target})[target]
        mounts = [(ROOT / 'scripts', '/repo/scripts'),
                  (ROOT / 'crates/buzz-push-gateway/tests/fixtures/apns-test-cert-only.pem', '/fixture-ca.pem'),
                  (args.pg_bin_dir.resolve(strict=True).parent, '/pg'),
                  (args.relay_binary.resolve(strict=True), '/binaries/buzz-relay'),
                  (args.redis_binary.resolve(strict=True), '/binaries/redis-server'),
                  (test_binary.resolve(strict=True), '/binaries/' + target),
                  ((args.s3_tools_dir / 'minio').resolve(strict=True), '/binaries/minio'),
                  ((args.s3_tools_dir / 'mc').resolve(strict=True), '/binaries/mc')]
        work = Path(temporary) / 'work'
        work.mkdir(mode=0o700)
        code = ('import sys; sys.path.insert(0,"/repo/scripts"); '
                'from postgres_test_fence import verify; verify(' + repr(fence.namespaces()) + '); '
                'import runpy; runpy.run_path("/repo/scripts/relay-invite-test-local.py")["inside_main"](' + repr(args.html_tenants) + ')')
        result = subprocess.run(fence.argv(mounts, work, ['/usr/bin/python3', '-c', code],
                                          fence.etc_files(temporary)), env={'PATH': '/usr/bin:/bin'}, close_fds=True)
        if any(work.iterdir()):
            retained = args.task_root / (Path(temporary).name + '-retained')
            work.rename(retained)
            raise RuntimeError(f'fixture cleanup incomplete; retained owned data: {retained}')
        result.check_returncode()
        print('CLEANUP: fence exited and owned writable tree is empty', flush=True)


if __name__ == '__main__':
    local['entry'](main)

#!/usr/bin/env python3
"""Real kernel checks against controlled sentinels, never an existing database."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest

import postgres_test_fence as fence


def sentinel_parent():
    # This parent itself lives in private namespaces. Port 5432 and every
    # default socket below are synthetic listeners, never the host database.
    sockets = []
    endpoints = [(socket.AF_INET, ('127.0.0.1', 5432)),
                 (socket.AF_INET6, ('::1', 5432)),
                 (socket.AF_UNIX, '/tmp/.s.PGSQL.5432'),
                 (socket.AF_UNIX, '/run/postgresql/.s.PGSQL.5432'),
                 (socket.AF_UNIX, '/var/run/postgresql/.s.PGSQL.5432'),
                 (socket.AF_UNIX, '\0buzz-pg-sentinel')]
    for family, endpoint in endpoints:
        if family == socket.AF_UNIX and not endpoint.startswith('\0'):
            Path(endpoint).parent.mkdir(parents=True, exist_ok=True)
        listener = socket.socket(family)
        listener.bind(endpoint)
        listener.listen(16)
        sockets.append(listener)
        with socket.socket(family) as probe:
            probe.connect(endpoint)
        accepted, _ = listener.accept()
        accepted.close()
    with tempfile.TemporaryDirectory(dir='/work') as temporary:
        work = Path(temporary) / 'work'; work.mkdir()
        code = '''
import os, socket, subprocess
from pathlib import Path
from postgres_test_fence import verify
verify(HOST)
for family, endpoint in ENDPOINTS:
    with socket.socket(family) as probe:
        probe.settimeout(1)
        try:
            probe.connect(endpoint)
        except OSError:
            continue
        raise AssertionError('escaped to parent sentinel: ' + repr(endpoint))
assert subprocess.run(['/usr/bin/unshare', '--user', '--map-root-user', 'true'], capture_output=True).returncode != 0
assert subprocess.run(['/usr/bin/nsenter', '--net=/proc/1/ns/net', 'true'], capture_output=True).returncode != 0
assert not Path('/proc/1/root/tmp/.s.PGSQL.5432').exists()
assert not Path('/proc/1/root/run/postgresql/.s.PGSQL.5432').exists()
print('PASS: IPv4/IPv6 TCP5432, three default Unix paths, abstract socket, userns and setns escape checks')
'''.replace('HOST', repr(fence.namespaces())).replace('ENDPOINTS', repr([(int(f), e) for f, e in endpoints]))
        command = ['/usr/bin/python3', '-c', 'import sys;sys.path.insert(0,"/repo/scripts");' + code]
        subprocess.run(fence.argv([(Path('/repo/scripts'), '/repo/scripts')], work,
                                 command, fence.etc_files(temporary)), check=True)
    for listener in sockets:
        listener.settimeout(0.05)
        try:
            listener.accept()
        except TimeoutError:
            pass
        else:
            raise AssertionError('sentinel received a sandbox connection')
        listener.close()


class FenceTests(unittest.TestCase):
    def test_controlled_parent_sentinels_are_unreachable(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary) / 'work'; work.mkdir()
            command = ['/usr/bin/python3', '/repo/scripts/test-postgres-test-fence.py', '--sentinel-parent']
            args = fence.argv([(Path(__file__).resolve().parent, '/repo/scripts')], work,
                              command, fence.etc_files(temporary))
            # The controlled sentinel parent must allow creation of the child
            # user namespace. Production child fencing keeps both flags.
            args.remove('--disable-userns'); args.remove('--assert-userns-disabled')
            subprocess.run(args, check=True)

    def test_host_context_fails_before_execution(self):
        with self.assertRaisesRegex(RuntimeError, 'fresh unprivileged namespaces'):
            fence.verify(fence.namespaces())

    def test_mounting_a_host_socket_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(str(Path(temporary) / 'host.sock'))
                with self.assertRaisesRegex(ValueError, 'special file'):
                    fence.reject_special_mounts(Path(temporary))

    def test_missing_enforcement_refuses(self):
        from unittest.mock import patch
        with patch.object(fence.sys, 'platform', 'darwin'):
            with self.assertRaisesRegex(ValueError, 'execution refused'):
                fence.argv([], Path('/tmp'), ['true'], Path('/tmp'))


if __name__ == '__main__':
    if sys.argv[1:] == ['--sentinel-parent']:
        sentinel_parent()
    else:
        unittest.main()

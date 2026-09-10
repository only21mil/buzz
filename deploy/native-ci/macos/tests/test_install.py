import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('installer', Path(__file__).parents[1] / 'install.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class InstallTests(unittest.TestCase):
    def test_restrictive_umask_preserves_public_payload_access(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / 'install'
            prior = os.umask(0o077)
            try:
                installer.publish_package(destination, {'payload.py': b'public payload', 'desktop-build.sh': b'public driver',
                    'policy.json': b'{}', 'buzz-ci-admission-verifier': b'verifier'}, b'{}')
            finally:
                os.umask(prior)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o755)
            for name, mode in [('payload.py', 0o644), ('desktop-build.sh', 0o644),
                               ('policy.json', 0o600), ('installation.json', 0o600),
                               ('buzz-ci-admission-verifier', 0o755)]:
                self.assertEqual((destination / name).stat().st_mode & 0o777, mode)

    @unittest.skipUnless(sys.platform == 'darwin' and os.geteuid() == 0, 'requires macOS root UID-drop regression')
    def test_uid590_can_read_payload_but_not_policy(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as directory:
            parent = Path(directory)
            parent.chmod(0o755)
            destination = parent / 'install'
            prior = os.umask(0o077)
            try:
                installer.publish_package(destination, {'payload.py': b'public payload', 'policy.json': b'{}'}, b'{}')
            finally:
                os.umask(prior)
            pid = os.fork()
            if pid == 0:
                try:
                    os.setgroups([])
                    os.setgid(590)
                    os.setuid(590)
                    assert (destination / 'payload.py').read_bytes() == b'public payload'
                    try:
                        (destination / 'policy.json').read_bytes()
                    except PermissionError:
                        os._exit(0)
                    os._exit(2)
                except BaseException:
                    os._exit(3)
            _, status = os.waitpid(pid, 0)
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/python3
"""Install a reviewed package once; does not start a service or change accounts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

DEST = Path('/usr/local/libexec/buzz-native-macos-ci')
STATE = Path('/private/var/db/buzz-native-macos-ci')
FILES = {'broker.py', 'payload.py', 'desktop-build.sh', 'buzz-ci-admission-verifier', 'policy.json'}
HELPER = Path('/usr/local/libexec/buzz-macos-build/buzz_macos_build_supervisor.py')
HELPER_SHA256 = 'c0d6fcd6d5922b61353e07e4402932099efa8004803c8d09305e2273237a3ef7'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def read_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 64 * 1024 * 1024, 'unsafe package file')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            return stream.read()
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--expected-inventory-sha256', required=True)
    args = parser.parse_args()
    require(sys.platform == 'darwin' and os.geteuid() == 0, 'macOS root installer required')
    os.umask(0o077)
    package = args.package.resolve(strict=True)
    raw = read_file(package / 'installation.json')
    require(hashlib.sha256(raw).hexdigest() == args.expected_inventory_sha256, 'reviewed inventory mismatch')
    inventory = json.loads(raw)
    require(set(inventory) == {'schema_version', 'files'} and inventory['schema_version'] == 1
            and set(inventory['files']) == FILES, 'invalid package inventory')
    snapshot = {name: read_file(package / name) for name in FILES}
    for name, value in snapshot.items():
        require(hashlib.sha256(value).hexdigest() == inventory['files'][name], 'package digest mismatch')
    require(hashlib.sha256(read_file(HELPER)).hexdigest() == HELPER_SHA256, 'existing boundary changed')
    # Do not overwrite old Apple scripts, prior installations, or service state.
    require(not DEST.exists() and not DEST.is_symlink() and not STATE.exists() and not STATE.is_symlink(), 'installation already exists')
    for parent in (DEST.parent, STATE.parent):
        for path in (parent, *parent.parents):
            info = path.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, 'unsafe installation parent')
            listing = subprocess.check_output(['/bin/ls', '-lde', str(path)], text=True)
            require('+' not in listing.split()[0], 'installation parent ACL')
    DEST.mkdir(mode=0o755)
    for name, value in dict(snapshot, **{'installation.json': raw}).items():
        path = DEST / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o755 if name == 'buzz-ci-admission-verifier' else 0o644)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    STATE.mkdir(mode=0o700)
    print(json.dumps({'installed': str(DEST), 'inventory_sha256': args.expected_inventory_sha256,
                      'service_started': False, 'account_changed': False}))


if __name__ == '__main__':
    main()

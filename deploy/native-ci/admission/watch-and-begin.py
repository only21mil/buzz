#!/usr/bin/python3
"""Root staging for one fresh accepted native request; never starts a runner."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

OPERATOR = '/usr/local/libexec/buzz-ci-native-admission'
STORE = Path('/var/lib/buzzci/native-publication')


def protected_directory(path):
    if not path.is_absolute() or path.resolve() != path:
        raise ValueError('canonical root directory required')
    for parent in (path, *path.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('unprotected root directory')


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    if os.geteuid() != 0 or len(sys.argv) != 6:
        raise ValueError('usage: watch-and-begin.py ATTEMPT_DIRECTORY AUTHORITY_SHA256 RELAY_HTTP_URL WAIT_SECONDS OUTPUT_JSON')
    directory = Path(sys.argv[1])
    protected_directory(directory)
    authority_sha, relay, seconds, output = sys.argv[2:]
    if not re.fullmatch('[0-9a-f]{64}', authority_sha) or not 1 <= int(seconds) <= 60:
        raise ValueError('invalid hash or capture timeout')
    # No credential loading. The child uses the existing UID/GID 1201 socket peer.
    prefix = ['/usr/bin/sudo', '-n', '-u', '#1201', '-g', '#1201', OPERATOR]
    captured = subprocess.run(prefix + ['await-request', str(directory / 'authority.json'),
                              authority_sha, str(directory / 'source.event.json'), relay, seconds],
                              stdout=subprocess.PIPE, check=True, timeout=int(seconds) + 2)
    if len(captured.stdout) > 1024 * 1024:
        raise ValueError('oversized accepted request')
    event = json.loads(captured.stdout)
    event_id = event['id']
    if not re.fullmatch('[0-9a-f]{64}', event_id):
        raise ValueError('invalid accepted request identity')
    request = directory / 'request.event.json'
    fd = os.open(request, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(captured.stdout)
        handle.flush()
        os.fsync(handle.fileno())
        os.fchmod(handle.fileno(), 0o444)
    sync_directory(directory)
    protected_directory(STORE.parent)
    STORE.mkdir(mode=0o755, exist_ok=True)
    protected_directory(STORE)
    store = STORE / event_id
    store.mkdir(mode=0o700)
    os.chown(store, 1201, 1201)
    sync_directory(STORE)
    result = subprocess.run(prefix + ['begin', str(directory / 'authority.json'), authority_sha,
                            str(request), str(directory / 'source.event.json'), relay],
                            stdout=subprocess.PIPE, check=True, timeout=60)
    # A create-only public result, with no log bytes or credentials.
    output_path = Path(output)
    protected_directory(output_path.parent)
    fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(result.stdout)
        handle.flush()
        os.fsync(handle.fileno())
        os.fchmod(handle.fileno(), 0o444)
    sync_directory(output_path.parent)
    print(json.dumps({'request_event_id': event_id, 'request_sha256': hashlib.sha256(captured.stdout).hexdigest(),
                      'queued_readback': json.loads(result.stdout)}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError):
        print('native capture/acknowledgement failed; retain staged files and inspect the named attempt', file=sys.stderr)
        sys.exit(1)

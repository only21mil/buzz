#!/usr/bin/python3
"""Fixed root entrypoint for verified v2 unsigned desktop CI admissions.

Only the installed Rust verifier interprets the signed wire frame. The existing
hash-pinned Apple supervisor supplies the UID and filesystem lifecycle helpers.
"""
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

INSTALL = Path('/usr/local/libexec/buzz-native-macos-ci')
STATE = Path('/private/var/db/buzz-native-macos-ci')
LEGACY = Path('/usr/local/libexec/buzz-macos-build')
LEGACY_HASH = 'c0d6fcd6d5922b61353e07e4402932099efa8004803c8d09305e2273237a3ef7'
LEGACY_MANIFEST_HASH = '5a60649f517e6b8db3463e53c5e1af2740107dc19b45410d5be6d3959c84e8e7'
ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'en_US.UTF-8'}
LOG_CAP = 1024 * 1024

FILES = {'broker.py', 'payload.py', 'desktop-build.sh', 'buzz-ci-admission-verifier', 'policy.json'}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def protected(path, directory=False):
    for item in reversed((path, *path.parents)):
        info = item.lstat()
        require(info.st_uid == 0 and not info.st_mode & 0o022
                and not stat.S_ISLNK(info.st_mode), 'unprotected installation')
        result = subprocess.run(['/bin/ls', '-lde', str(item)], env=ENV,
                                capture_output=True, text=True, check=True, timeout=10)
        require('+' not in result.stdout.split()[0], 'installation ACL')
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode), 'wrong path type')
    if not directory:
        require(info.st_nlink == 1, 'hard-linked installation')


def installation():
    protected(INSTALL, True)
    protected(STATE, True)
    protected(INSTALL / 'installation.json')
    manifest = json.loads((INSTALL / 'installation.json').read_bytes())
    require(set(manifest) == {'schema_version', 'files'} and manifest['schema_version'] == 1
            and set(manifest['files']) == FILES, 'invalid installation manifest')
    for name, expected in manifest['files'].items():
        path = INSTALL / name
        protected(path)
        require(hashlib.sha256(path.read_bytes()).hexdigest() == expected, 'installation drift')
    helper = LEGACY / 'buzz_macos_build_supervisor.py'
    protected(helper)
    require(hashlib.sha256(helper.read_bytes()).hexdigest() == LEGACY_HASH, 'legacy boundary drift')
    legacy_manifest = LEGACY / 'installation.json'
    protected(legacy_manifest)
    require(hashlib.sha256(legacy_manifest.read_bytes()).hexdigest() == LEGACY_MANIFEST_HASH, 'legacy manifest drift')
    spec = importlib.util.spec_from_file_location('buzz_legacy_boundary', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_frame(stream):
    frame = stream.read(993)
    require(len(frame) == 992, 'one complete v2 job registration required')
    return frame


def verify(frame, live):
    result = subprocess.run([str(INSTALL / 'buzz-ci-admission-verifier'),
                             str(INSTALL / 'policy.json'), 'live' if live else 'retained'],
                            input=frame, capture_output=True, env=ENV, timeout=10)
    require(result.returncode == 0 and len(result.stdout) <= 8192, 'admission verification failed')
    return json.loads(result.stdout)


def write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as out:
            out.write(data)
            out.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def record_path(request, suffix):
    # Derive replay identity from signed run/attempt, not mutable frame header.
    return STATE / f"{request['run_id']}-{request['attempt']}.{suffix}"


def load_record(request):
    path = record_path(request, 'admitted')
    protected(path)
    value = json.loads(path.read_bytes())
    require(value == request, 'attempt identity mismatch')


def require_no_unfinished():
    # Only root creates these files. A missing receipt means cleanup is unproven,
    # even if a crashed broker left no running process and an empty HOME.
    for path in STATE.glob('*.admitted'):
        protected(path)
        receipt = path.with_suffix('.receipt')
        require(receipt.exists(), 'unfinished prior admission requires operator recovery')
        protected(receipt)
        value = json.loads(receipt.read_bytes())
        require(value.get('cleanup_complete') is True, 'prior cleanup requires operator recovery')


def drain_log(fd, kept, count):
    """Retain the first bounded bytes and count every byte read from the pipe."""
    for _ in range(16):
        try:
            chunk = os.read(fd, 65536)
        except BlockingIOError:
            return count
        if not chunk:
            return count
        count += len(chunk)
        kept.extend(chunk[:max(0, LOG_CAP - len(kept))])
    return count


def log_metadata(request):
    path = record_path(request, 'log')
    protected(path)
    value = path.read_bytes()
    require(len(value) <= LOG_CAP, 'log exceeds cap')
    return {'sha256': hashlib.sha256(value).hexdigest(), 'byte_length': len(value),
            'cap_bytes': LOG_CAP}


def execute(helper, root, request, builder, darwin_parent):
    read_fd, write_fd = os.pipe()
    log_read, log_write = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(write_fd)
            os.dup2(read_fd, 0)
            os.dup2(log_write, 1)
            os.dup2(log_write, 2)
            os.closerange(3, max(256, *map(int, os.listdir('/dev/fd'))) + 1)
            os.setsid()
            os.setgroups([])
            os.setgid(builder.pw_gid)
            os.setuid(builder.pw_uid)
            require(os.getuid() == 590 and os.geteuid() == 590
                    and set(helper.kernel_groups()) <= {590}, 'privilege drop failed')
            os.chdir(root)
            env = dict(ENV, HOME=str(helper.BUILD_HOME), CFFIXED_USER_HOME=str(helper.BUILD_HOME),
                       TMPDIR=str(root / 'tmp') + '/', USER='buzzbuild', LOGNAME='buzzbuild',
                       BUZZ_DARWIN_ROOT=str(darwin_parent))
            os.execve('/usr/bin/python3', ['/usr/bin/python3', '-I', str(INSTALL / 'payload.py'), str(root)], env)
        except BaseException:
            os._exit(125)
    os.close(read_fd)
    os.close(log_write)
    os.set_blocking(log_read, False)
    tail = bytearray()
    count = 0
    try:
        with os.fdopen(write_fd, 'wb') as stream:
            stream.write(json.dumps(request).encode())
        timeout = min(request['wall_timeout_seconds'], request['expires_at'] - time.time())
        deadline = time.monotonic() + timeout
        while True:
            count = drain_log(log_read, tail, count)
            if record_path(request, 'cancel').exists():
                return 'cancelled', None
            if time.monotonic() >= deadline:
                return 'timed_out', None
            found, status = os.waitpid(pid, os.WNOHANG)
            if found:
                count = drain_log(log_read, tail, count)
                code = os.waitstatus_to_exitcode(status)
                return ('success' if code == 0 else 'failure'), code
            time.sleep(0.25)
    finally:
        try:
            with helper.cleanup_signals():
                helper.stop_builder(590, pid)
                count = drain_log(log_read, tail, count)
                # Exact retained bytes and truncation are separate facts.
                write_new(record_path(request, 'log'), bytes(tail))
                write_new(record_path(request, 'log-metadata'), json.dumps(dict(
                    log_metadata(request), observed_bytes=count, truncated=count > len(tail)), sort_keys=True).encode())
        finally:
            os.close(log_read)


def run(helper, request):
    manifest = helper.installed_manifest()
    builder = pwd.getpwnam('buzzbuild')
    require(builder.pw_uid == 590 and builder.pw_gid == 590
            and builder.pw_shell == '/usr/bin/false'
            and builder.pw_dir == str(helper.BUILD_HOME), 'build account changed')
    lock = os.open(helper.STATE / 'supervisor.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    root = None
    scratch = None
    darwin_parent = None
    owned = False
    admitted = False
    conclusion, code, cleaned = 'failure', None, False
    started_at = int(time.time())
    try:
        info = os.fstat(lock)
        require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600
                and stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'unsafe shared lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        require_no_unfinished()
        require(not helper.uid_processes(590), 'build account already active')
        fd = helper.home_directory(manifest['builder_home'])
        try:
            require(not os.listdir(fd), 'build HOME requires operator recovery')
        finally:
            os.close(fd)
        write_new(record_path(request, 'admitted'), json.dumps(request, sort_keys=True).encode())
        admitted = True
        owned = True
        darwin_parent = helper.darwin_scratch_parent(builder)
        helper.stop_builder(590)
        scratch = helper.scratch_snapshot(darwin_parent, 590, 590)
        scratch = helper.clear_darwin_scratch(darwin_parent, scratch, 590, 590)
        root = Path(tempfile.mkdtemp(prefix='native-ci-', dir=helper.STATE))
        for path in (root, root / 'tmp'):
            if path != root:
                path.mkdir(mode=0o700)
            os.chown(path, 590, 590)
        conclusion, code = execute(helper, root, request, builder, darwin_parent)
    finally:
        try:
            with helper.cleanup_signals():
                if owned:
                    helper.stop_builder(590)
                    helper.clear_builder_home(manifest['builder_home'])
                    if scratch is not None:
                        helper.clear_darwin_scratch(darwin_parent, scratch, 590, 590)
                    if root is not None:
                        require(shutil.rmtree.avoids_symlink_attacks, 'safe cleanup unavailable')
                        shutil.rmtree(root)
                    cleaned = True
        finally:
            os.close(lock)
            if admitted:
                receipt = dict(request, job_id='desktop-build-macos-unsigned',
                               conclusion=conclusion if cleaned else 'cleanup_failed',
                               exit_code=code, cleanup_complete=cleaned,
                               started_at=started_at, completed_at=int(time.time()))
                log_path = record_path(request, 'log-metadata')
                if log_path.exists():
                    protected(log_path)
                    receipt['log'] = json.loads(log_path.read_bytes())
                write_new(record_path(request, 'receipt'), json.dumps(receipt, sort_keys=True).encode())
    return receipt


def interrupted(_signal, _frame):
    raise InterruptedError('broker interrupted')


def main():
    require(sys.platform == 'darwin' and os.geteuid() == 0, 'macOS root broker required')
    require(len(sys.argv) == 2 and sys.argv[1] in ('run', 'cancel', 'status', 'log'), 'fixed operation required')
    require(os.environ.get('SUDO_UID') == str(pwd.getpwnam('m5mbp').pw_uid), 'operator transport required')
    os.umask(0o077)
    os.environ.clear()
    os.environ.update(ENV)
    helper = installation()
    signal.alarm(10)
    try:
        frame = read_frame(sys.stdin.buffer)
    finally:
        signal.alarm(0)
    operation = sys.argv[1]
    request = verify(frame, operation == 'run')
    if operation == 'run':
        receipt = run(helper, request)
    else:
        load_record(request)
        if operation == 'cancel':
            if not record_path(request, 'cancel').exists():
                write_new(record_path(request, 'cancel'), b'cancel\n')
            receipt = {'cancellation_requested': True, 'admission_message_digest': request['admission_message_digest']}
        else:
            path = record_path(request, 'receipt')
            protected(path)
            receipt = json.loads(path.read_bytes())
            if operation == 'log':
                log_path = record_path(request, 'log')
                protected(log_path)
                value = log_path.read_bytes()
                require(len(value) <= LOG_CAP and receipt.get('log', {}).get('sha256') == hashlib.sha256(value).hexdigest()
                        and receipt['log']['byte_length'] == len(value), 'log receipt mismatch')
                sys.stdout.buffer.write(value)
                return
    print(json.dumps(receipt, sort_keys=True))


if __name__ == '__main__':
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGALRM):
        signal.signal(sig, interrupted)
    try:
        main()
    except BaseException:
        # Exception text can contain candidate-controlled bytes. Never forward it.
        print('native macOS CI operation failed; inspect root-owned state', file=sys.stderr)
        sys.exit(1)

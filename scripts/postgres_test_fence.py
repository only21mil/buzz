"""Linux boundary for owned PostgreSQL fixtures; no environment-only fallback."""
import json
import os
import stat
from pathlib import Path
import subprocess
import sys
import tempfile


def namespaces():
    return {name: os.readlink('/proc/self/ns/' + name) for name in ('net', 'mnt', 'pid', 'user')}


def verify(host):
    if os.geteuid() == 0 or any(namespaces()[key] == value for key, value in host.items()):
        raise RuntimeError('PostgreSQL fixture requires fresh unprivileged namespaces')
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines())
    if status['NoNewPrivs'].strip() != '1' or int(status['CapBnd'].strip(), 16):
        raise RuntimeError('PostgreSQL fence requires no_new_privs and empty capabilities')
    if subprocess.run(['/usr/bin/unshare', '--user', 'true'], capture_output=True).returncode == 0:
        raise RuntimeError('PostgreSQL fence allows nested user namespaces')
    links = json.loads(subprocess.check_output(['/usr/bin/ip', '-json', 'link']))
    if [link['ifname'] for link in links] != ['lo']:
        raise RuntimeError('PostgreSQL fence must have only private loopback')
    print('postgres-fence=' + json.dumps({'host': host, 'fixture': namespaces(),
          'no_new_privs': True, 'capabilities': 0, 'nested_userns': False}), flush=True)


def argv(mounts, writable, command, etc):
    if sys.platform != 'linux' or not Path('/usr/bin/bwrap').is_file():
        raise ValueError('PostgreSQL isolation requires Linux bubblewrap; execution refused')
    result = ['/usr/bin/bwrap', '--unshare-all', '--unshare-user', '--disable-userns',
              '--assert-userns-disabled', '--die-with-parent', '--new-session', '--cap-drop', 'ALL',
              '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
              '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
              '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--dir', '/run',
              '--dir', '/var/run/postgresql', '--dir', '/home/fixture',
              '--ro-bind', str(etc), '/etc', '--clearenv',
              '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'HOME', '/home/fixture',
              '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'TMPDIR', '/tmp']
    for source, destination in mounts:
        reject_special_mounts(Path(source))
        result += ['--ro-bind', str(source), str(destination)]
    result += ['--bind', str(writable), '/work', '--chdir', '/work']
    return result + command



def reject_special_mounts(source):
    paths = [source]
    if source.is_dir():
        paths.extend(source.rglob('*'))
    for path in paths:
        kind = path.lstat().st_mode
        if not (stat.S_ISREG(kind) or stat.S_ISDIR(kind) or stat.S_ISLNK(kind)):
            raise ValueError('refusing special file in PostgreSQL sandbox input: ' + str(path))

def etc_files(directory):
    etc = Path(directory) / 'etc'
    etc.mkdir(mode=0o700)
    (etc / 'passwd').write_text(f'fixture:x:{os.getuid()}:{os.getgid()}::/home/fixture:/bin/false\n')
    (etc / 'group').write_text(f'fixture:x:{os.getgid()}:\n')
    (etc / 'hosts').write_text('127.0.0.1 localhost\n::1 localhost\n')
    (etc / 'nsswitch.conf').write_text('passwd: files\ngroup: files\nhosts: files\n')
    return etc


def run(args, binaries, pg_bin, root):
    """The public entry always creates the fence, including --list discovery."""
    with tempfile.TemporaryDirectory(prefix='pg-fence-', dir=args.task_root.resolve(strict=True)) as temporary:
        work = Path(temporary) / 'work'
        work.mkdir(mode=0o700)
        mounts = [(root / 'scripts', '/repo/scripts'), (args.repo_root.resolve() / 'schema', '/repo/schema')]
        internal = ['--task-root', '/work', '--repo-root', '/repo', '--filter', args.filter,
                    '--schema-mode', args.schema_mode]
        for option in ('exact', 'list'):
            if getattr(args, option):
                internal.append('--' + option)
        if pg_bin is not None:
            mounts.append((pg_bin.resolve().parent, '/pg'))
            internal += ['--pg-bin-dir', '/pg/' + pg_bin.name]
        for index, binary in enumerate(binaries):
            destination = '/binaries/' + str(index) + '/' + binary.name
            mounts.append((binary, destination))
            internal.append(destination)
        host = namespaces()
        code = ('import sys; sys.path.insert(0,"/repo/scripts"); '
                'from postgres_test_fence import verify; verify(' + repr(host) + '); '
                'import runpy; module=runpy.run_path("/repo/scripts/postgres-test-local.py"); '
                'sys.argv=["postgres-test-local.py"]+' + repr(internal) + '; module["entry"](module["inside_main"])')
        result = subprocess.run(argv(mounts, work, ['/usr/bin/python3', '-c', code], etc_files(temporary)),
                                env={'PATH': '/usr/bin:/bin'}, close_fds=True)
        # PID namespace teardown kills descendants even on abrupt runner exit.
        # Retain a failed cleanup tree for inspection rather than hiding it.
        if any(work.iterdir()):
            retained = Path(args.task_root) / (Path(temporary).name + '-retained')
            work.rename(retained)
            print(f'fixture cleanup incomplete; retained owned data: {retained}', file=sys.stderr)
            if not result.returncode:
                raise RuntimeError('fixture cleanup failed')
        if result.returncode:
            raise subprocess.CalledProcessError(result.returncode, ['postgres-test-fence'])

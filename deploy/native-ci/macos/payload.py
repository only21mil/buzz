"""Runs only after the broker drops privileges to the dedicated build UID."""
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys

INSTALL = Path('/usr/local/libexec/buzz-native-macos-ci')
LEGACY = Path('/usr/local/libexec/buzz-macos-build')
HOME = Path('/private/var/db/buzz-macos-build-home')


def main():
    if len(sys.argv) != 2 or os.getuid() != 590 or os.geteuid() != 590:
        raise ValueError('dedicated build UID required')
    if pwd.getpwuid(590).pw_name != 'buzzbuild':
        raise ValueError('build identity changed')
    root = Path(sys.argv[1]).resolve(strict=True)
    request = json.load(sys.stdin)
    env = {
        'HOME': str(HOME), 'CFFIXED_USER_HOME': str(HOME),
        'TMPDIR': str(root / 'tmp') + '/', 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin',
        'LANG': 'en_US.UTF-8', 'LC_ALL': 'en_US.UTF-8', 'SHELL': '/bin/bash',
        'USER': 'buzzbuild', 'LOGNAME': 'buzzbuild',
        'CARGO_HOME': str(HOME / '.cargo'), 'RUSTUP_HOME': str(HOME / '.rustup'),
        'XDG_CACHE_HOME': str(HOME / '.cache'), 'CI': 'true',
        'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
        'GIT_TERMINAL_PROMPT': '0', 'GIT_ASKPASS': '/usr/bin/false',
        '__CF_USER_TEXT_ENCODING': '0x24E:0:0',
        'SOURCE_SHA': request['candidate_sha'], 'BASE_SHA': request['base_sha'],
        'WORKFLOW_SHA256': request['workflow_file_sha256'],
        'WORKFLOW_PATH': request['workflow_path'], 'DRIVER_SHA256': request['driver_file_sha256'],
        'BUZZ_CI_DRIVER': str(INSTALL / 'desktop-build.sh'),
    }
    command = ['/usr/bin/sandbox-exec', '-D', 'BUILD_ROOT=' + str(root),
               '-D', 'BUILD_HOME=' + str(HOME), '-D', 'CONTROLLER=' + str(INSTALL),
               '-D', 'DARWIN_ROOT=' + os.environ['BUZZ_DARWIN_ROOT'],
               '-f', str(LEGACY / 'buzz_macos_build.sb'),
               '/bin/bash', '--noprofile', '--norc', '-euo', 'pipefail', '-c', '''
mkdir source
cd source
git init --quiet
git -c credential.helper= fetch --depth 1 https://github.com/only21mil/buzz.git "$SOURCE_SHA"
test "$(git rev-parse FETCH_HEAD)" = "$SOURCE_SHA"
git -c credential.helper= fetch --depth 1 https://github.com/only21mil/buzz.git "$BASE_SHA"
test "$(git rev-parse FETCH_HEAD)" = "$BASE_SHA"
git show "FETCH_HEAD:$WORKFLOW_PATH" > ../workflow.yml
test "$(shasum -a 256 ../workflow.yml | cut -d ' ' -f 1)" = "$WORKFLOW_SHA256"
git show FETCH_HEAD:deploy/native-ci/macos/desktop-build.sh > ../trusted-driver.sh
test "$(shasum -a 256 ../trusted-driver.sh | cut -d ' ' -f 1)" = "$DRIVER_SHA256"
git -c core.hooksPath=/dev/null checkout --quiet --detach "$SOURCE_SHA"
exec /bin/bash --noprofile --norc "$BUZZ_CI_DRIVER"
''']
    subprocess.run(command, cwd=root, env=env, close_fds=True, check=True)


if __name__ == '__main__':
    main()

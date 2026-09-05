#!/usr/bin/env python3
"""Local fork release signer. Run signing only after controller promotion binding."""
import argparse
import base64
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import re
import stat
import subprocess

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs12

STORE = Path.home() / '.config/sats/secrets.env'
PREFIX = 'BUZZ_ANDROID_PRIVATE_CANARY_'
KEYS = [PREFIX + name for name in ('KEYSTORE_BASE64', 'KEYSTORE_PASSWORD', 'KEY_ALIAS')]
ALIAS = 'buzz-private-canary'
SOURCE = Path(__file__).resolve().parent.parent


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def verify_store_identity(fd):
    current = os.stat(STORE, follow_symlinks=False)
    opened = os.fstat(fd)
    require(stat.S_ISREG(current.st_mode) and current.st_dev == opened.st_dev and
            current.st_ino == opened.st_ino, 'Secret store path replaced')


def open_store():
    parent = STORE.parent.lstat()
    require(stat.S_ISDIR(parent.st_mode) and stat.S_IMODE(parent.st_mode) == 0o700,
            'Secret directory must be a real mode-0700 directory')
    require(parent.st_uid == os.getuid(), 'Secret directory owner mismatch')
    fd = os.open(STORE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    st = os.fstat(fd)
    require(stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o600,
            'Secret store must be a regular mode-0600 file')
    require(st.st_uid == os.getuid() and st.st_nlink == 1, 'Secret store owner/link mismatch')
    fcntl.flock(fd, fcntl.LOCK_SH)
    verify_store_identity(fd)
    return fd


def read_all(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    pieces = []
    while chunk := os.read(fd, 65536):
        pieces.append(chunk)
    return b''.join(pieces)


def material(contents):
    values = {}
    for line in contents.decode().splitlines():
        if line.startswith(PREFIX):
            require('=' in line, 'Malformed canary field')
            name, value = line.split('=', 1)
            require(name in KEYS and name not in values, 'Unexpected or duplicate canary field')
            values[name] = value
    require(set(values) == set(KEYS), 'Canary secret fields incomplete')
    require(values[KEYS[2]] == ALIAS, 'Unexpected canary alias')
    data = base64.b64decode(values[KEYS[0]], validate=True)
    password = values[KEYS[1]].encode()
    key, cert, extra = pkcs12.load_key_and_certificates(data, password)
    require(key is not None and cert is not None and not extra, 'Canary key/certificate malformed')
    require(key.public_key().public_numbers() == cert.public_key().public_numbers(), 'Key mismatch')
    return data, password, cert


def public_metadata(cert):
    return {'sha256': cert.fingerprint(hashes.SHA256()).hex(),
            'subject': cert.subject.rfc4514_string(), 'alias': ALIAS,
            'not_before': cert.not_valid_before_utc.isoformat(),
            'not_after': cert.not_valid_after_utc.isoformat(),
            'key_bits': cert.public_key().key_size,
            'purpose': 'Victor only21mil Android distribution, adopted from installed canonical private canary'}


def require_isolated_network():
    host = os.environ.get('HOST_NETWORK_NAMESPACE', '')
    require(re.fullmatch(r'net:\[\d+\]', host) is not None,
            'HOST_NETWORK_NAMESPACE must be captured outside the isolated namespace')
    require(os.readlink('/proc/self/ns/net') != host,
            'Mutate only inside an isolated network namespace')
    interfaces = [line.split(':', 1)[0].strip()
                  for line in Path('/proc/net/dev').read_text().splitlines()[2:]]
    require(interfaces == ['lo'], 'Isolated namespace must contain only loopback')
    routes = Path('/proc/net/route').read_text().splitlines()[1:]
    require(not routes, 'Isolated namespace must have no IPv4 routes')


def verify_store_preimage(contents, expected):
    require(expected is not None and re.fullmatch('[0-9a-f]{64}', expected) is not None,
            'A root-bound secret-store preimage SHA-256 is required')
    require(hashlib.sha256(contents).hexdigest() == expected, 'Secret-store preimage mismatch')


def memory_file(label, payload):
    fd = os.memfd_create(label, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        os.fchmod(fd, 0o600)
        require(os.write(fd, payload) == len(payload), 'Incomplete memory write')
        os.lseek(fd, 0, os.SEEK_SET)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                    fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        return fd
    except BaseException:
        os.close(fd)
        raise


def sign_apk(tools, aligned, signed, data, password, env):
    """Sign with inherited, sealed memory files for the key and passwords."""
    with contextlib.ExitStack() as descriptors:
        def sealed(label, payload):
            fd = memory_file(label, payload)
            descriptors.callback(os.close, fd)
            return fd

        keyfd = sealed('buzz-private-canary-keystore', data)
        # apksigner caches a reader per password source and consumes one line.
        # Separate files let both password reads start at their own first line.
        storepassfd = sealed('buzz-private-canary-store-password', password + b'\n')
        keypassfd = sealed('buzz-private-canary-key-password', password + b'\n')
        subprocess.run([str(tools / 'apksigner'), 'sign', '--ks', f'/proc/self/fd/{keyfd}',
                        '--ks-key-alias', ALIAS, '--ks-pass', f'file:/proc/self/fd/{storepassfd}',
                        '--key-pass', f'file:/proc/self/fd/{keypassfd}', '--v4-signing-enabled', 'false',
                        '--out', str(signed), str(aligned)], check=True, env=env,
                       pass_fds=(keyfd, storepassfd, keypassfd))


def bound_candidate(args):
    require(args.candidate_manifest is not None and args.manifest_sha256 is not None,
            'Root-bound candidate manifest and SHA-256 are required')
    manifest_path = Path(args.candidate_manifest)
    require(manifest_path.is_absolute() and manifest_path.resolve() == manifest_path,
            'Candidate manifest path must be canonical and absolute')
    manifest_stat = manifest_path.lstat()
    require(stat.S_ISREG(manifest_stat.st_mode) and stat.S_IMODE(manifest_stat.st_mode) == 0o600,
            'Candidate manifest must be a regular mode-0600 file')
    raw = manifest_path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == args.manifest_sha256, 'Candidate manifest drift')
    manifest = json.loads(raw)
    expected_keys = {'schema', 'source_root', 'source_commit', 'source_tree', 'package',
                     'version_name', 'version_code', 'apk_file', 'apk_sha256',
                     'dependency_file', 'dependency_sha256', 'source_tag'}
    require(set(manifest) == expected_keys and manifest['schema'] == 'buzz-local-android-release-v1',
            'Unsupported candidate manifest')
    require(manifest['package'] == 'xyz.block.buzz.mobile', 'Canonical package required')
    metadata = json.loads(subprocess.check_output(
        [str(SOURCE / 'scripts/android-fork-release-metadata.py'), manifest['source_tag']],
        text=True))
    require(manifest['version_name'] == metadata['version_name'] and
            type(manifest['version_code']) is int and
            manifest['version_code'] == metadata['version_code'],
            'Official tag and package version mismatch')
    source = Path(manifest['source_root'])
    require(source.is_absolute() and source.resolve() == source, 'Source path must be canonical')
    for revision, key in [('HEAD', 'source_commit'), ('HEAD^{tree}', 'source_tree')]:
        actual = subprocess.check_output(['/usr/bin/git', '-C', str(source), 'rev-parse', revision],
                                         text=True).strip()
        require(actual == manifest[key], 'Candidate source provenance mismatch')
    require(not subprocess.check_output(['/usr/bin/git', '-C', str(source), 'status', '--porcelain',
                                         '--untracked-files=all']), 'Candidate source is dirty')
    tagged = subprocess.check_output(['/usr/bin/git', '-C', str(source), 'rev-parse',
                                       manifest['source_tag'] + '^{commit}'], text=True).strip()
    require(tagged == manifest['source_commit'], 'Source tag does not match candidate')
    require(subprocess.check_output(['/usr/bin/git', '-C', str(source), 'cat-file', '-t',
                                     manifest['source_tag']], text=True).strip() == 'tag',
            'Annotated source tag required')
    root = manifest_path.parent
    st = root.stat()
    require(stat.S_IMODE(st.st_mode) == 0o700 and st.st_uid == os.getuid(),
            'Artifact directory must be owned mode 0700')
    for file_key, hash_key in [('apk_file', 'apk_sha256'), ('dependency_file', 'dependency_sha256')]:
        name = manifest[file_key]
        require(name == Path(name).name and name not in ('', '.', '..'), 'Artifact basename required')
        path = root / name
        require(path.resolve() == path and path.is_file(), 'Artifact must be a canonical regular file')
        require(hashlib.sha256(path.read_bytes()).hexdigest() == manifest[hash_key], 'Artifact drift')
    return root, manifest


def inspect_or_sign(args):
    if args.action == 'sign':
        require_isolated_network()
        root, manifest = bound_candidate(args)
        require(args.build_tools is not None, 'Explicit Android build-tools directory required')
        tools = Path(args.build_tools)
        require(tools.is_absolute() and tools.resolve() == tools, 'Build-tools path must be canonical')
        analyzer_dir = tools.parent.parent / 'cmdline-tools/latest/bin'
        require((analyzer_dir / 'apkanalyzer').is_file(), 'SDK apkanalyzer is required')
        env = {'PATH': str(tools) + ':' + str(analyzer_dir) + ':/usr/bin:/bin',
               'HOME': str(Path.home()), 'LANG': 'C.UTF-8'}
        # Run the same maintained artifact gate used by the fork release lane.
        subprocess.run([str(SOURCE / 'scripts/verify-android-fork-release-unsigned-apk.sh'),
                        str(root / manifest['apk_file']), str(root / manifest['dependency_file']),
                        manifest['version_name'], str(manifest['version_code'])], check=True, env=env)
    fd = open_store()
    try:
        contents = read_all(fd)
        if args.action == 'sign':
            verify_store_preimage(contents, args.store_preimage_sha256)
        data, password, cert = material(contents)
    finally:
        os.close(fd)
    metadata = public_metadata(cert)
    if args.action == 'inspect':
        print(json.dumps(metadata, indent=2))
        return
    require(args.cert == metadata['sha256'] ==
            'cc25c85edae8b74a2a81f46e328c381d96af28094b2f1f92f632399e9f46d0db',
            'Adopted release signer and independent root binding mismatch')
    unsigned = root / manifest['apk_file']
    aligned = root / 'app-release-aligned.apk'
    signed = root / 'buzz-release.apk'
    require(not aligned.exists() and not signed.exists(), 'Signing outputs already exist')
    payload = unsigned.read_bytes()
    require(hashlib.sha256(payload).hexdigest() == manifest['apk_sha256'], 'Unsigned APK drift')
    apkfd = memory_file('buzz-private-canary-unsigned', payload)
    del payload
    try:
        subprocess.run([str(tools / 'zipalign'), '-P', '16', '4', f'/proc/self/fd/{apkfd}',
                        str(aligned)], check=True, env=env, pass_fds=(apkfd,))
    finally:
        os.close(apkfd)
    sign_apk(tools, aligned, signed, data, password, env)
    subprocess.run([str(SOURCE / 'scripts/verify-android-fork-release-apk.sh'), str(signed),
                    str(root / manifest['dependency_file']), manifest['version_name'],
                    str(manifest['version_code']), args.cert], check=True, env=env)
    metadata['apk_sha256'] = hashlib.sha256(signed.read_bytes()).hexdigest()
    metadata['candidate_manifest_sha256'] = args.manifest_sha256
    print(json.dumps(metadata, indent=2))


if __name__ == '__main__':
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['inspect', 'sign'])
    parser.add_argument('--cert')
    parser.add_argument('--store-preimage-sha256')
    parser.add_argument('--candidate-manifest')
    parser.add_argument('--manifest-sha256')
    parser.add_argument('--build-tools')
    parsed = parser.parse_args()
    inspect_or_sign(parsed)

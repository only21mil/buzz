#!/usr/bin/env python3
"""Exercise key custody using an anonymous synthetic store, never the live store."""
import argparse
import contextlib
import importlib.util
import io
import json
import os
import hashlib
import resource
from types import SimpleNamespace
from unittest import mock
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--unsigned-apk', type=Path, required=True)
parser.add_argument('--build-tools', type=Path, required=True)
parser.add_argument('--test-output', type=Path, required=True)
options = parser.parse_args()
os.umask(0o077)
options.test_output.mkdir(mode=0o700)

spec = importlib.util.spec_from_file_location(
    'local_release_signer', Path(__file__).with_name('android-local-release.py'))
signer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signer)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

def rejected(action, message):
    try:
        action()
    except SystemExit as error:
        assert str(error) == message, str(error)
    else:
        raise AssertionError('Expected rejection: ' + message)


# Exercise the real guard in the caller's isolated namespace, before any fixture.
signer.require_isolated_network()
host = os.environ['HOST_NETWORK_NAMESPACE']
try:
    for invalid in ('', 'not-a-namespace'):
        os.environ['HOST_NETWORK_NAMESPACE'] = invalid
        rejected(signer.require_isolated_network,
                 'HOST_NETWORK_NAMESPACE must be captured outside the isolated namespace')
    os.environ['HOST_NETWORK_NAMESPACE'] = os.readlink('/proc/self/ns/net')
    rejected(signer.require_isolated_network,
             'Mutate only inside an isolated network namespace')
finally:
    os.environ['HOST_NETWORK_NAMESPACE'] = host
rejected(lambda: signer.material((signer.PREFIX + 'KEY_ALIAS\n').encode()),
         'Malformed canary field')

# Public fixtures check source cleanliness and manifest type/mode enforcement.
with tempfile.TemporaryDirectory(prefix='canary-public-fixture-') as temporary:
    root = Path(temporary)
    source = root / 'source'
    subprocess.run(['/usr/bin/git', 'init', '-q', str(source)], check=True)
    subprocess.run(['/usr/bin/git', '-C', str(source), '-c', 'user.name=Fixture',
                    '-c', 'user.email=fixture@localhost', '-c', 'commit.gpgsign=false',
                    'commit', '-q', '--allow-empty', '-m', 'Public fixture'], check=True)
    manifest = {'schema': 'buzz-local-android-release-v1', 'source_root': str(source),
                'package': 'xyz.block.buzz.mobile', 'version_name': '0.5.9-only21mil.rc.1',
                'version_code': 1000509001, 'source_tag': 'only21mil-android-v0.5.9-rc.1'}
    for revision, key in [('HEAD', 'source_commit'), ('HEAD^{tree}', 'source_tree')]:
        manifest[key] = subprocess.check_output(
            ['/usr/bin/git', '-C', str(source), 'rev-parse', revision], text=True).strip()
    subprocess.run(['/usr/bin/git', '-C', str(source), '-c', 'user.name=Fixture',
                    '-c', 'user.email=fixture@localhost', '-c', 'tag.gpgsign=false',
                    'tag', '-a', manifest['source_tag'], '-m', 'Fixture'], check=True)
    for file_key, hash_key in [('apk_file', 'apk_sha256'), ('dependency_file', 'dependency_sha256')]:
        manifest[file_key] = file_key + '.fixture'
        (root / manifest[file_key]).write_bytes(b'public fixture')
        manifest[hash_key] = hashlib.sha256(b'public fixture').hexdigest()
    path = root / 'manifest.json'
    path.write_text(json.dumps(manifest))
    path.chmod(0o600)
    binding = SimpleNamespace(candidate_manifest=str(path),
                              manifest_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    signer.bound_candidate(binding)
    path.chmod(0o644)
    rejected(lambda: signer.bound_candidate(binding),
             'Candidate manifest must be a regular mode-0600 file')
    path.chmod(0o600)
    alias = root / 'manifest-link.json'
    alias.symlink_to(path)
    rejected(lambda: signer.bound_candidate(SimpleNamespace(
        candidate_manifest=str(alias), manifest_sha256=binding.manifest_sha256)),
        'Candidate manifest path must be canonical and absolute')
    rejected(lambda: signer.bound_candidate(SimpleNamespace(
        candidate_manifest=str(source), manifest_sha256=binding.manifest_sha256)),
        'Candidate manifest must be a regular mode-0600 file')
    original = path.read_bytes()
    for key, wrong in [('version_name', '0.5.9-private.20260905.1'), ('version_code', 2)]:
        changed = dict(manifest)
        changed[key] = wrong
        path.write_text(json.dumps(changed))
        rejected(lambda: signer.bound_candidate(SimpleNamespace(
            candidate_manifest=str(path), manifest_sha256=hashlib.sha256(path.read_bytes()).hexdigest())),
            'Official tag and package version mismatch')
    path.write_bytes(original)
    (source / 'untracked.dart').write_text('// non-ignored application fixture\n')
    rejected(lambda: signer.bound_candidate(binding), 'Candidate source is dirty')

# Generate an ephemeral test identity in memory; never open the retained store.
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
import datetime
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Test only')])
now = datetime.datetime.now(datetime.timezone.utc)
certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
               .sign(key, hashes.SHA256()))
password = b'test-only-memory-password'
data = pkcs12.serialize_key_and_certificates(
    signer.ALIAS.encode(), key, certificate, None,
    serialization.BestAvailableEncryption(password))
contents = (signer.PREFIX + 'KEYSTORE_BASE64=' + signer.base64.b64encode(data).decode() + '\n' +
            signer.PREFIX + 'KEYSTORE_PASSWORD=' + password.decode() + '\n' +
            signer.PREFIX + 'KEY_ALIAS=' + signer.ALIAS + '\n').encode()
parsed_data, parsed_password, parsed_certificate = signer.material(contents)
assert parsed_data == data and parsed_password == password
metadata = signer.public_metadata(parsed_certificate)
rejected(lambda: signer.verify_store_preimage(contents, '0' * 64), 'Secret-store preimage mismatch')
# Real Java/keytool reads the in-memory PKCS12 and password through inherited
# descriptors. Output contains public certificate metadata only and is captured.
key_fd = signer.memory_file('canary-java-key-test', data)
pass_fd = signer.memory_file('canary-java-pass-test', password + b'\n')
try:
    result = subprocess.run(
        ['/usr/bin/keytool', '-list', '-keystore', f'/proc/self/fd/{key_fd}',
         '-storepass:file', f'/proc/self/fd/{pass_fd}'],
        pass_fds=(key_fd, pass_fd), capture_output=True, text=True, check=True)
    assert metadata['sha256'] in result.stdout.lower().replace(':', '')
    assert password.decode() not in result.stdout + result.stderr
    try:
        os.write(key_fd, b'overwrite')
    except PermissionError:
        pass
    else:
        raise AssertionError('Sealed keystore memory was writable')
finally:
    os.close(key_fd)
    os.close(pass_fd)

# Exercise the production signer with real Java/apksigner and an ephemeral key.
# These APKs carry a test-only identity and are never installation candidates.
env = {'PATH': str(options.build_tools) + ':/usr/bin:/bin',
       'HOME': str(Path.home()), 'LANG': 'C.UTF-8'}
aligned = options.test_output / 'TEST-ONLY-aligned.apk'
signed = options.test_output / 'TEST-ONLY-signed.apk'
subprocess.run([str(options.build_tools / 'zipalign'), '-P', '16', '4',
                str(options.unsigned_apk), str(aligned)], check=True, env=env)
fds_before = set(os.listdir('/proc/self/fd'))
signer.sign_apk(options.build_tools, aligned, signed, data, password, env)
assert set(os.listdir('/proc/self/fd')) == fds_before, 'Signing leaked descriptors'
verification = subprocess.run(
    [str(options.build_tools / 'apksigner'), 'verify', '--verbose', '--print-certs', str(signed)],
    check=True, capture_output=True, text=True, env=env)
assert 'Signer #1 certificate SHA-256 digest: ' + metadata['sha256'] in verification.stdout
assert password.decode() not in verification.stdout + verification.stderr
# Allocation and child failures must close every descriptor already created.
original_memory_file = signer.memory_file
for fail_at in (1, 2, 3, 4):
    allocated = []

    def allocate(label, payload):
        if len(allocated) + 1 == fail_at:
            raise OSError('Injected allocation failure')
        fd = original_memory_file(label, payload)
        allocated.append(fd)
        return fd

    with mock.patch.object(signer, 'memory_file', side_effect=allocate), \
            mock.patch.object(signer.subprocess, 'run', side_effect=OSError('Injected child failure')):
        try:
            signer.sign_apk(options.build_tools, aligned, signed, data, password, env)
        except OSError:
            pass
        else:
            raise AssertionError('Injected signing failure was swallowed')
    assert set(os.listdir('/proc/self/fd')) == fds_before, 'Failure leaked descriptors'
with mock.patch.object(signer.os, 'fchmod', side_effect=OSError('Injected setup failure')):
    try:
        signer.memory_file('canary-memory-failure-test', b'public fixture')
    except OSError:
        pass
    else:
        raise AssertionError('Injected memory setup failure was swallowed')
assert set(os.listdir('/proc/self/fd')) == fds_before, 'Memory setup failure leaked descriptor'
print(json.dumps({'test_only': True, 'uid': os.getuid(),
                  'expected_certificate_sha256': metadata['sha256'],
                  'signed_apk_sha256': hashlib.sha256(signed.read_bytes()).hexdigest(),
                  'verification': verification.stdout}))
print('PASS: real isolated-network guard, namespace metadata refusal, public source/manifest guards, malformed field refusal, memory-only synthetic identity, secret-free public output, Java inherited-FD PKCS12/password read, sealed memory, real production apksigner sign/verify and certificate match, descriptor closure')

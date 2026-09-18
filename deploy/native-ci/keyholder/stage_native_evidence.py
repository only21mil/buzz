#!/usr/bin/env python3
"""Root-only exact native read-policy preparation and atomic installation.

The caller owns the complete lane and invokes this between check-completion
and publisher startup. No publisher may be connected during replacement.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import uuid

CONFIG = Path('/etc/buzzci/keyholder-native-v2.json')
UNIT = 'buzz-ci-keyholder.service'
SOCKET = '/run/buzzci/keyholder.sock'
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}
OPS = ['describe', 'sign_ci_event', 'nip98_authorize', 'sign_manifest']
HEX = re.compile('[0-9a-f]{64}')
BINDING_FIELDS = {'not_before', 'expires_at', 'request_event_id', 'run_id', 'job_id', 'attempt', 'authority_sha256', 'bundle_sha256', 'log_sha256', 'artifacts'}
SPEC_FIELDS = {'schema_version', 'operator', 'operator_sha256', 'authority', 'authority_sha256', 'request', 'request_sha256', 'source', 'source_sha256', 'bundle', 'bundle_sha256', 'expected_config_sha256', 'keyholder_binary_sha256', 'accepted_store', 'accepted_store_sha256', 'backup_directory'}


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def decode(raw: bytes) -> dict:
    def pairs(items):
        out = {}
        for key, value in items:
            require(key not in out, 'duplicate JSON field')
            out[key] = value
        return out
    value = json.loads(raw, object_pairs_hook=pairs)
    require(isinstance(value, dict), 'JSON object required')
    return value


def protected(path: Path, limit: int, owners=(0,), modes=(0o444,)) -> bytes:
    require(path.is_absolute() and path.resolve(strict=True) == path, 'canonical protected path required')
    for parent in path.parents:
        m = parent.lstat()
        require(stat.S_ISDIR(m.st_mode) and m.st_uid == 0 and not m.st_mode & 0o022, 'unprotected parent')
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        m = os.fstat(fd)
        require(stat.S_ISREG(m.st_mode) and m.st_uid in owners and m.st_nlink == 1 and stat.S_IMODE(m.st_mode) in modes and 0 < m.st_size <= limit, 'unprotected file')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(limit + 1)
        require(len(raw) == m.st_size, 'file changed during read')
        return raw
    finally:
        os.close(fd)


def run(argv: list[str], timeout=30) -> bytes:
    completed = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV, timeout=timeout)
    require(completed.returncode == 0 and len(completed.stdout) <= 65536, 'bounded command refused')
    return completed.stdout


def validate_plan(plan: dict, spec: dict, config: dict, request: dict, now: int) -> dict:
    require(set(plan) == {'schema_version', 'validated', 'request_event_id', 'state', 'relay_origin', 'keyholder_selectors', 'native_evidence'} and plan['schema_version'] == 1 and plan['validated'] is True, 'completion plan schema')
    require(set(config) in ({'schema_version', 'peer', 'selectors', 'nip98_origin'}, {'schema_version', 'peer', 'selectors', 'nip98_origin', 'native_evidence'}), 'standalone config required')
    require(config['schema_version'] == 2 and config['peer'] == {'uid': 1201, 'gid': 1201, 'allowed_operations': OPS}, 'native peer and operations differ')
    require(plan['keyholder_selectors'] == config['selectors'] and plan['relay_origin'].removesuffix('/') == config['nip98_origin'], 'selector or origin drift')
    p = plan['native_evidence']
    require(isinstance(p, dict) and set(p) == BINDING_FIELDS, 'native policy schema')
    for name in ('request_event_id', 'authority_sha256', 'bundle_sha256', 'log_sha256'):
        require(isinstance(p[name], str) and HEX.fullmatch(p[name]) is not None and p[name] != '0'*64, 'invalid binding digest')
    require(p['request_event_id'] == plan['request_event_id'] == request['id'] and p['authority_sha256'] == spec['authority_sha256'] and p['bundle_sha256'] == spec['bundle_sha256'], 'proof or request binding drift')
    content = decode(request['content'].encode())
    require(p['run_id'] == content['run_id'] and str(uuid.UUID(p['run_id'])) == p['run_id'] and p['job_id'] in content['job_ids'] and p['attempt'] == content['attempt'], 'attempt binding drift')
    require(type(p['attempt']) is int and 1 <= p['attempt'] <= 0xffffffff and re.fullmatch('[A-Za-z_][A-Za-z0-9_-]{0,63}', p['job_id']), 'attempt grammar')
    require(type(p['not_before']) is int and type(p['expires_at']) is int and now-30 <= p['not_before'] <= now and p['expires_at'] == p['not_before'] + 300 and now < p['expires_at'], 'stale read plan')
    require(isinstance(p['artifacts'], list) and 1 <= len(p['artifacts']) <= 16, 'artifact bounds')
    ids = set()
    for a in p['artifacts']:
        require(isinstance(a, dict) and set(a) == {'artifact_id', 'sha256'} and isinstance(a['artifact_id'], str) and re.fullmatch('[A-Za-z0-9_.-]{1,128}', a['artifact_id']) and a['artifact_id'] not in {'.', '..'} and a['artifact_id'] not in ids and isinstance(a['sha256'], str) and HEX.fullmatch(a['sha256']), 'artifact binding')
        ids.add(a['artifact_id'])
    return {**config, 'native_evidence': p}


def paths(policy: dict) -> set[str]:
    prefix = '/'.join(str(policy[k]) for k in ('request_event_id', 'run_id', 'job_id', 'attempt'))
    return {f'/ci/logs/{prefix}/{policy["log_sha256"]}'} | {f'/ci/artifacts/{prefix}/{a["artifact_id"]}/{a["sha256"]}' for a in policy['artifacts']}


def compare_accepted_store(store: dict, config: dict) -> None:
    """A root-pinned recovery snapshot must contain precisely these accepted refs."""
    p = config['native_evidence']
    found = set()
    require(store['schema_version'] == 1, 'store schema')
    for key, value in store['publications'].items():
        if not key.startswith(p['request_event_id'] + ':') or not any(key.startswith(p['request_event_id'] + ':' + kind + ':') for kind in ('log', 'artifact')):
            continue
        require(set(value) == {'Accepted'}, 'evidence publication is not accepted')
        accepted = value['Accepted']
        event = accepted['signed']['signed_event']
        require(accepted['relay_event_id'] == event['id'] and event['pubkey'] == config['selectors']['ci_event']['public_key'], 'accepted reference identity')
        content = decode(event['content'].encode())
        require(content['request_event_id'] == p['request_event_id'] and content['run_id'] == p['run_id'] and content['job_id'] == p['job_id'] and content['attempt'] == p['attempt'], 'accepted reference attempt drift')
        url = content['url']
        require(url.startswith(config['nip98_origin'] + '/'), 'accepted reference origin')
        path = url[len(config['nip98_origin']):]
        require(path in paths(p) and path not in found, 'accepted reference object drift')
        expected_digest = content.get('log_sha256', content.get('sha256'))
        require(path.endswith('/' + expected_digest), 'accepted reference digest drift')
        found.add(path)
    require(found == paths(p), 'accepted evidence set incomplete')


def prepare(spec: dict) -> tuple[bytes, bytes]:
    require(set(spec) == SPEC_FIELDS and spec['schema_version'] == 1, 'stage spec schema')
    for name in ('operator', 'authority', 'request', 'source', 'bundle'):
        raw = protected(Path(spec[name]), 128*1024*1024 if name == 'operator' else 1024*1024, modes=(0o755,) if name == 'operator' else (0o444,))
        require(digest(raw) == spec[name + '_sha256'], 'pinned input drift')
    old = protected(CONFIG, 16384, owners=(0,1202), modes=(0o600,0o640,0o644))
    require(digest(old) == spec['expected_config_sha256'], 'config CAS differs')
    plan = decode(run([spec['operator'], 'check-completion', spec['authority'], spec['authority_sha256'], spec['request'], spec['source'], spec['bundle'], spec['bundle_sha256']]))
    new = validate_plan(plan, spec, decode(old), decode(protected(Path(spec['request']),1024*1024)), int(time.time()))
    if spec['accepted_store'] is not None:
        raw = protected(Path(spec['accepted_store']), 4*1024*1024)
        require(digest(raw) == spec['accepted_store_sha256'], 'accepted snapshot drift')
        compare_accepted_store(decode(raw),new)
    else:
        require(spec['accepted_store_sha256'] is None, 'unexpected accepted snapshot hash')
    raw = (json.dumps(new, sort_keys=True, separators=(',', ':'))+'\n').encode()
    require(len(raw) <= 16384, 'config size')
    return old, raw


def service_identity(expected: str) -> dict:
    values = run(['/usr/bin/systemctl', 'show', UNIT, '--property=ActiveState,SubState,MainPID,InvocationID']).decode().splitlines()
    state = dict(line.split('=',1) for line in values)
    require(state['ActiveState'] == 'active' and state['SubState'] == 'running' and int(state['MainPID']) > 1, 'keyholder not running')
    exe = Path('/proc') / state['MainPID'] / 'exe'
    require(digest(exe.read_bytes()) == expected, 'keyholder process binary drift')
    return state


def backup(spec: dict, old: bytes, before: dict) -> dict:
    directory=Path(spec['backup_directory'])
    require(directory.is_absolute() and directory.resolve(strict=True) == directory, 'backup path')
    for parent in (directory,*directory.parents):
        m=parent.lstat()
        require(stat.S_ISDIR(m.st_mode) and m.st_uid == 0 and not m.st_mode & 0o022, 'unprotected backup directory')
    require(stat.S_IMODE(directory.stat().st_mode) == 0o700 and not any(directory.iterdir()), 'fresh backup directory required')
    metadata=CONFIG.stat()
    receipt={'schema_version':1,'config_sha256':digest(old),'config_uid':metadata.st_uid,'config_gid':metadata.st_gid,'config_mode':stat.S_IMODE(metadata.st_mode),'keyholder_binary_sha256':spec['keyholder_binary_sha256'],'process':before}
    for name,raw in [('config.before.json',old),('before.json',(json.dumps(receipt,sort_keys=True)+'\n').encode())]:
        fd=os.open(directory/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
        with os.fdopen(fd,'wb') as stream:
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    return receipt


def quiesce() -> None:
    run(['/usr/bin/systemctl','stop',UNIT,'buzz-ci-keyholder.socket'],timeout=45)
    states=run(['/usr/bin/systemctl','show',UNIT,'buzz-ci-keyholder.socket','--property=ActiveState','--value']).decode().split()
    require(states == ['inactive','inactive'], 'keyholder shutdown unconfirmed')


def restart_and_verify(spec: dict, before: dict, new: bytes) -> dict:
    try:
        run(['/usr/bin/systemctl','restart',UNIT],timeout=45)
        after=service_identity(spec['keyholder_binary_sha256'])
        require(after['InvocationID'] != before['InvocationID'] and protected(CONFIG,16384,modes=(0o640,)) == new, 'restart or config readback differs')
        result=decode(run(['/usr/bin/setpriv','--reuid=1201','--regid=1201','--clear-groups',spec['operator'],'describe-keyholder',spec['authority'],spec['authority_sha256']]))
        require(result == {'validated':True,'signing':False}, 'native Describe readback refused')
        require(int(time.time()) < decode(new)['native_evidence']['expires_at']-30, 'read window expired during startup')
        return after
    except BaseException:
        # A failed readback never promotes a publisher. If shutdown itself
        # fails, quiesce explicitly reports that state is unconfirmed.
        quiesce()
        raise


def apply(spec: dict, old: bytes, new: bytes) -> dict:
    lock = os.open('/run/buzzci-native-evidence.lock', os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC, 0o600)
    try:
        m=os.fstat(lock)
        require(stat.S_ISREG(m.st_mode) and m.st_uid == 0 and m.st_nlink == 1 and stat.S_IMODE(m.st_mode) == 0o600, 'unsafe lock')
        fcntl.flock(lock, fcntl.LOCK_EX|fcntl.LOCK_NB)
        before=service_identity(spec['keyholder_binary_sha256'])
        require(SOCKET.encode() not in run(['/usr/bin/ss','--unix','--no-header','--numeric','state','connected']), 'keyholder client still connected')
        require(protected(CONFIG,16384,owners=(0,1202),modes=(0o600,0o640,0o644)) == old, 'config CAS changed')
        policy=decode(new)['native_evidence']
        require(int(time.time()) < policy['expires_at']-60, 'read window too short to install')
        retained=backup(spec,old,before)
        # Close admission while replacing the authority. Requires= on the
        # service restarts the existing socket with its unchanged unit policy.
        quiesce()
        temp=CONFIG.with_name('.native-evidence-'+uuid.uuid4().hex)
        fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            with os.fdopen(fd,'wb') as stream:
                stream.write(new);stream.flush();os.fchown(stream.fileno(),0,1202);os.fchmod(stream.fileno(),0o640);os.fsync(stream.fileno())
            require(protected(CONFIG,16384,owners=(0,1202),modes=(0o600,0o640,0o644)) == old, 'config changed before rename')
            os.replace(temp,CONFIG)
            directory=os.open(CONFIG.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try: os.fsync(directory)
            finally: os.close(directory)
        finally:
            if temp.exists(): temp.unlink()
        after=restart_and_verify(spec,before,new)
        return {'schema_version':1,'config_sha256':digest(new),'prior_config_sha256':digest(old),'before':before,'after':after,'native_evidence':policy,'backup':retained,'signing':False}
    finally:
        os.close(lock)


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--spec',type=Path,required=True)
    parser.add_argument('--sha256',required=True)
    parser.add_argument('--apply',action='store_true')
    args=parser.parse_args()
    require(os.geteuid() == 0, 'root required')
    raw=protected(args.spec,16384)
    require(digest(raw) == args.sha256, 'stage spec hash')
    spec=decode(raw)
    old,new=prepare(spec)
    result=apply(spec,old,new) if args.apply else {'config':decode(new),'config_sha256':digest(new),'applied':False}
    print(json.dumps(result,sort_keys=True))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())

"""Match only this hosted admission's AppArmor denial; emit no other audit data."""
import json
from pathlib import Path
import re
import sys


def confirm(preflight, restriction, entries, started_us, ended_us):
    if restriction != '1' or 'bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted' not in preflight:
        raise ValueError('missing restricted-userns loopback failure')
    attempts = [json.loads(line.removeprefix('fence-admission='))
                for line in preflight.splitlines() if line.startswith('fence-admission=')]
    if len(attempts) != 1 or attempts[0]['executable'] != '/usr/bin/bwrap':
        raise ValueError('missing unique system bwrap admission PID')
    pid = attempts[0]['child_pid']
    if type(pid) is not int or pid <= 0:
        raise ValueError('invalid bwrap child PID')
    expected = {'apparmor': 'DENIED', 'operation': 'capable', 'profile': 'unprivileged_userns',
                'comm': 'bwrap', 'capname': 'net_admin', 'pid': str(pid)}
    for entry in entries:
        timestamp = int(entry['__REALTIME_TIMESTAMP'])
        fields = dict(re.findall(r'(\w+)="([^"]*)"', entry['MESSAGE']))
        fields.update(re.findall(r'\b(pid)=([0-9]+)\b', entry['MESSAGE']))
        if started_us <= timestamp <= ended_us and all(fields.get(k) == v for k, v in expected.items()):
            return {**expected, 'timestamp_us': timestamp, 'executable': '/usr/bin/bwrap'}
    raise ValueError('no matching AppArmor denial for this bwrap child and time window')


if __name__ == '__main__':
    try:
        evidence = confirm(Path(sys.argv[1]).read_text(),
                           Path('/proc/sys/kernel/apparmor_restrict_unprivileged_userns').read_text().strip(),
                           [json.loads(line) for line in sys.stdin], int(sys.argv[2]), int(sys.argv[3]))
    except (OSError, ValueError, KeyError, TypeError) as error:
        sys.exit('Unconfirmed AppArmor admission failure; refusing: ' + str(error))
    print('Confirmed AppArmor restriction=1: ' + json.dumps(evidence, sort_keys=True))

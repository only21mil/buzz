#!/usr/bin/env python3
"""Framework controller adapter: send an existing signed v2 frame to the MBP."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

REMOTE = ['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
          '-o', 'ConnectTimeout=10', 'victors-macbook-pro', '/usr/bin/sudo', '-n',
          '/usr/bin/python3', '-I', '/usr/local/libexec/buzz-native-macos-ci/broker.py']


def check_receipt(receipt, expected, operation):
    if operation == 'cancel':
        if receipt != {'cancellation_requested': True,
                       'admission_message_digest': expected['admission_message_digest']}:
            raise ValueError('cancellation receipt mismatch')
        return
    if any(receipt.get(key) != value for key, value in expected.items()):
        raise ValueError('terminal admission identity mismatch')
    if (receipt.get('job_id') != 'desktop-build-macos-unsigned'
            or receipt.get('conclusion') not in ('success', 'failure', 'cancelled', 'timed_out', 'cleanup_failed')
            or type(receipt.get('cleanup_complete')) is not bool):
        raise ValueError('invalid terminal receipt')
    if receipt['conclusion'] == 'success' and (receipt.get('exit_code') != 0 or not receipt['cleanup_complete']):
        raise ValueError('success without clean execution')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--operation', choices=('run', 'cancel', 'status'), required=True)
    parser.add_argument('--verifier', type=Path, required=True)
    parser.add_argument('--policy', type=Path, required=True)
    args = parser.parse_args()
    frame = sys.stdin.buffer.read(993)
    if len(frame) != 992:
        raise ValueError('one v2 job registration frame required')
    verification = subprocess.run([str(args.verifier), str(args.policy),
                                   'live' if args.operation == 'run' else 'retained'],
                                  input=frame, capture_output=True, check=True, timeout=10)
    expected = json.loads(verification.stdout)
    timeout = expected['wall_timeout_seconds'] + 600 if args.operation == 'run' else 30
    try:
        result = subprocess.run(REMOTE + [args.operation], input=frame,
                                capture_output=True, timeout=timeout, check=True)
    except (KeyboardInterrupt, subprocess.TimeoutExpired):
        subprocess.run(REMOTE + ['cancel'], input=frame, capture_output=True, timeout=30, check=True)
        raise
    if len(result.stdout) > 16384:
        raise ValueError('oversized broker result')
    receipt = json.loads(result.stdout)
    check_receipt(receipt, expected, args.operation)
    print(json.dumps(receipt, sort_keys=True))


if __name__ == '__main__':
    main()

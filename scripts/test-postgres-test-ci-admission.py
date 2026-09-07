#!/usr/bin/env python3
"""Synthetic audit records only; no host services or kernel policy changes."""
import json
import unittest

from postgres_test_ci_admission import confirm


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.log = ('bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted\n'
                    'fence-admission=' + json.dumps({'executable': '/usr/bin/bwrap', 'child_pid': 123}) + '\n')
        self.entry = {'__REALTIME_TIMESTAMP': '150', 'MESSAGE':
                      'audit: apparmor="DENIED" operation="capable" profile="unprivileged_userns" '
                      'pid=123 comm="bwrap" capability=12 capname="net_admin" unrelated="PRIVATE"'}

    def test_exact_attempt_returns_only_allowed_evidence(self):
        evidence = confirm(self.log, '1', [self.entry], 100, 200)
        self.assertEqual(evidence['pid'], '123')
        self.assertEqual(evidence['timestamp_us'], 150)
        self.assertNotIn('PRIVATE', json.dumps(evidence))

    def test_other_pid_executable_time_or_denial_cannot_authorize(self):
        for old, new in [('pid=123', 'pid=1234'), ('comm="bwrap"', 'comm="other"'),
                         ('profile="unprivileged_userns"', 'profile="admin-policy"'),
                         ('capname="net_admin"', 'capname="sys_admin"'),
                         ('apparmor="DENIED"', 'apparmor="ALLOWED"')]:
            with self.subTest(new=new), self.assertRaises(ValueError):
                confirm(self.log, '1', [{**self.entry, 'MESSAGE': self.entry['MESSAGE'].replace(old, new)}], 100, 200)
        for timestamp in ['99', '201']:
            with self.subTest(timestamp=timestamp), self.assertRaises(ValueError):
                confirm(self.log, '1', [{**self.entry, '__REALTIME_TIMESTAMP': timestamp}], 100, 200)
        with self.assertRaises(ValueError):
            confirm(self.log.replace('/usr/bin/bwrap', '/other/bwrap'), '1', [self.entry], 100, 200)

    def test_missing_or_ambiguous_admission_refuses(self):
        for log in ['', self.log + self.log, self.log.replace('RTM_NEWADDR', 'OTHER')]:
            with self.subTest(log=log), self.assertRaises(ValueError):
                confirm(log, '1', [self.entry], 100, 200)
        with self.assertRaises(ValueError):
            confirm(self.log, '0', [self.entry], 100, 200)
        with self.assertRaises(ValueError):
            confirm(self.log, '1', [], 100, 200)


if __name__ == '__main__':
    unittest.main()

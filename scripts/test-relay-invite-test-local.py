#!/usr/bin/env python3
"""Service-free checks for fail-closed invite discovery."""
from pathlib import Path
import runpy
import unittest
from unittest.mock import patch

runner = runpy.run_path(str(Path(__file__).with_name('relay-invite-test-local.py')))


class InviteInventoryTests(unittest.TestCase):
    def inventory(self, discovered, rows=None):
        with patch.dict(runner['local'], discover=lambda *_: discovered):
            if rows is None:
                return runner['invite_inventory'](Path('e2e_relay'), {})
            with patch.dict(runner['invite_inventory'].__globals__, read_inventory=lambda: rows):
                return runner['invite_inventory'](Path('e2e_relay'), {})

    def rows(self):
        return [row for row in runner['read_inventory']() if row['binary'] == 'e2e_relay']

    def test_existing_selection_preserves_external_classification(self):
        rows = self.rows()
        selected = self.inventory([row['test'] for row in rows])
        self.assertEqual(selected, list(runner['INVITE_TESTS']))
        self.assertEqual({row['mode'] for row in rows if row['test'] in selected}, {'external'})

    def test_missing_or_duplicate_compiled_test_refuses(self):
        tests = [row['test'] for row in self.rows()]
        for discovered in (tests[1:], tests + tests[:1]):
            with self.subTest(discovered=discovered), self.assertRaisesRegex(ValueError, 'compiled discovery mismatch'):
                self.inventory(discovered)

    def test_new_invite_requires_explicit_fixture_admission(self):
        rows = self.rows()
        rows.append({**rows[0], 'test': 'test_invite_new_dependency'})
        with self.assertRaisesRegex(ValueError, 'invite selection changed'):
            self.inventory([row['test'] for row in rows], rows)


if __name__ == '__main__':
    unittest.main()

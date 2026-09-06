#!/usr/bin/env python3
"""Focused refusal, isolation and frozen-prefix regression checks."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = load('postgres-test-local')
frozen = load('check-frozen-migrations')


class IsolationTests(unittest.TestCase):
    def test_refuses_every_inherited_database_target_without_echoing_it(self):
        for key in runner.TARGET_VARS:
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, '^refusing inherited database URL; unset database target variables$'):
                runner.clean_environment({key: 'postgres://private:secret@live/service'})

    def test_removes_libpq_service_and_host_overrides(self):
        self.assertEqual(runner.clean_environment({'PGHOST': 'live', 'PGSERVICE': 'live',
                          'PGPASSFILE': '/private', 'PATH': '/bin'}), {'PATH': '/bin'})

    def test_tests_and_binaries_have_separate_database_names(self):
        names = {runner.database_name(binary, test) for binary in ('db', 'workflow')
                 for test in ('drops_public', 'reads_public')}
        self.assertEqual(len(names), 4)
        for name in names:
            self.assertRegex(name, '^buzz_nt_[a-f0-9]{24}$')

    def test_destructive_legacy_migration_starts_empty(self):
        self.assertEqual(runner.schema_mode('populated_migration_preserves_legacy_approval_and_backfills_resume_state'), 'migration')
        self.assertEqual(runner.schema_mode('decision_grant_is_atomic_generation_fenced_and_exactly_replayable'), 'desired')

    def test_fork_contract_binaries_own_migrations(self):
        for name in ('ci_grants_contract', 'workflow_approval_contract',
                     'workflow_enabled_persistence', 'workflow_state_contract'):
            self.assertEqual(runner.schema_mode('ordinary_test', name + '-1234'), 'migration')

    def test_admission_map_requires_hash_for_new_migration(self):
        import json
        import shutil
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(frozen.ROOT / 'migrations', root / 'migrations')
            (root / 'scripts').mkdir()
            shutil.copy(frozen.ROOT / 'scripts/migrations-0001-0035.sha256', root / 'scripts')
            (root / 'migrations/0036_new.sql').write_text('-- new migration\n')
            ledger = root / 'map.json'
            ledger.write_text('[]')
            with self.assertRaisesRegex(ValueError, 'missing from admission map'):
                frozen.check(root, ledger)
            ledger.write_text(json.dumps([{'proposed_target': '0036_new.sql'}]))
            with self.assertRaisesRegex(ValueError, 'admission map missing source_commit'):
                frozen.check(root, ledger)

    def test_inventory_selects_each_ignored_test_exactly(self):
        class Result:
            stdout = 'first: test\nnested::second: test\n2 tests, 0 benchmarks\n'
        with patch.object(runner, 'command', return_value=Result()) as command:
            self.assertEqual(runner.discover(Path('/binary'), {}, ''), ['first', 'nested::second'])
            self.assertIn('--ignored', command.call_args.args[0])

    def test_frozen_prefix_rejects_changed_bytes_and_duplicate_versions(self):
        import shutil
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(frozen.ROOT / 'migrations', root / 'migrations')
            (root / 'scripts').mkdir()
            shutil.copy(frozen.ROOT / 'scripts/migrations-0001-0035.sha256', root / 'scripts')
            frozen.check(root)
            original = next((root / 'migrations').glob('0001_*.sql'))
            data = original.read_bytes()
            original.write_bytes(data + b'\n')
            with self.assertRaisesRegex(ValueError, 'frozen migration changed'):
                frozen.check(root)
            original.write_bytes(data)
            (root / 'migrations/0001_collision.sql').write_text('-- collision\n')
            with self.assertRaisesRegex(ValueError, 'duplicate migration version|unrecorded historical'):
                frozen.check(root)


if __name__ == '__main__':
    unittest.main()

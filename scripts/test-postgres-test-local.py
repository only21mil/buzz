#!/usr/bin/env python3
"""Focused refusal, isolation and frozen-prefix regression checks."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
import subprocess
import sys
from unittest.mock import patch


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = load('postgres-test-local')
frozen = load('check-frozen-migrations')


class IsolationTests(unittest.TestCase):
    def test_cluster_is_recreated_per_test_and_removed_on_failure(self):
        for fail, cleanup_failure in ((False, False), (True, False), (True, True), (False, True)):
            with tempfile.TemporaryDirectory(dir='/tmp') as directory:
                root = Path(directory)
                binary = root / 'fixture'
                binary.touch()
                starts, stops = [], []

                def run(argv, env, **kwargs):
                    argv = [str(a) for a in argv]
                    if '--list' in argv:
                        return subprocess.CompletedProcess(argv, 0, 'first: test\nsecond: test\n')
                    if argv[0].endswith('/initdb'):
                        Path(argv[argv.index('-D') + 1]).mkdir()
                    if argv[-1] == 'start':
                        starts.append(argv[argv.index('-D') + 1])
                    if '--exact' in argv and fail:
                        raise subprocess.CalledProcessError(7, argv)
                    if argv[0].endswith('/dropdb') and cleanup_failure is True:
                        raise subprocess.CalledProcessError(9, argv)
                    return subprocess.CompletedProcess(argv, 0, 'test result: ok. 1 passed; 0 failed; 0 ignored;\n', '')

                def stop(argv, **kwargs):
                    stops.append(str(argv[argv.index('-D') + 1]))
                    return subprocess.CompletedProcess(argv, 0)

                args = ['runner', '--task-root', directory, '--pg-bin-dir', '/fixture',
                        '--schema-mode', 'migration', str(binary)]
                with patch.object(sys, 'argv', args), patch.object(runner.os, 'environ', {}), \
                     patch.object(runner.os, 'access', return_value=True), \
                     patch.object(runner.signal, 'signal'), patch.object(runner, 'classify', return_value='migration'), \
                     patch.object(runner, 'command', side_effect=run), \
                     patch.object(runner.subprocess, 'run', side_effect=stop):
                    if fail or cleanup_failure:
                        with self.assertRaises(subprocess.CalledProcessError) as error:
                            runner.inside_main()
                        self.assertEqual(error.exception.returncode, 7 if fail else 9)
                    else:
                        runner.inside_main()
                self.assertEqual(len(starts), 1 if fail or cleanup_failure else 2)
                self.assertEqual(len(set(starts)), len(starts))
                self.assertEqual(starts, stops)
                self.assertEqual(list(root.glob('pg-*')), [])

    def test_external_fixture_cannot_be_forced_into_a_schema_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'fixture'; binary.touch()
            args = ['runner', '--task-root', directory, '--schema-mode', 'desired', str(binary)]
            with patch.object(sys, 'argv', args), patch.object(runner.os, 'environ', {}), \
                 patch.object(runner, 'classify', return_value='external'), \
                 patch.object(runner, 'discover', return_value=['requires_redis']), \
                 patch.object(runner, 'command') as command:
                with self.assertRaisesRegex(ValueError, 'external infrastructure'):
                    runner.inside_main()
                command.assert_not_called()

    def test_zero_skipped_or_multiple_summaries_cannot_qualify(self):
        passing = 'test result: ok. 1 passed; 0 failed; 0 ignored;'
        runner.require_one_test(passing, 'exact_case')
        for output in ('test result: ok. 0 passed; 0 failed; 0 ignored;',
                       'test result: ok. 0 passed; 0 failed; 1 ignored;',
                       passing + '\n' + passing, ''):
            with self.subTest(output=output), self.assertRaisesRegex(RuntimeError, 'one passing test'):
                runner.require_one_test(output, 'exact_case')

    def test_inner_entry_preserves_test_exit_status(self):
        def fail():
            raise subprocess.CalledProcessError(7, ['fixture'])
        with self.assertRaises(SystemExit) as error:
            runner.entry(fail)
        self.assertEqual(error.exception.code, 7)

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
        with self.assertRaisesRegex(ValueError, 'unknown or ambiguous'):
            runner.schema_mode('unknown_migration_fixture')

    def test_fork_contract_binaries_own_migrations(self):
        from postgres_test_inventory import read_inventory
        for row in read_inventory():
            if row['binary'] in ('ci_grants_contract', 'workflow_approval_contract',
                                 'workflow_enabled_persistence', 'workflow_state_contract'):
                self.assertEqual(runner.schema_mode(row['test'], row['binary'] + '-1234'), 'migration')

    def test_self_migrating_library_fixtures_start_empty(self):
        names = [
            'workflow_approval::tests::prior_trace_is_persisted_once_and_replay_does_not_append',
            'push::tests::acceptance_constraint_failure_rolls_back_source_event',
            'push::tests::source_event_collision_is_protocol_outcome_without_event_insert',
            'push::tests::replacement_and_revoke_are_community_scoped_and_dual_ordered',
            'push::tests::concurrent_enqueue_is_atomic_and_community_scoped',
            'push::tests::setwise_enqueue_maps_outcomes_per_request',
            'push::tests::send_revalidation_suppresses_rotated_claim_and_retry_preserves_id',
            'push::tests::endpoint_invalidation_is_scoped_to_community_and_generation',
            'push::tests::matcher_trigger_is_allowlisted_and_deleted_events_are_discarded',
            'push::tests::matcher_load_error_preserves_claimed_job_for_recovery',
            'push::tests::matcher_claim_is_exclusive_across_workers',
            'push::tests::delivered_wake_is_retained_while_rematch_is_queued',
            'push::tests::exhausted_match_job_is_reaped_and_cannot_pin_retention',
            'push::tests::batch_claim_is_single_community_and_setwise_ops_honor_the_fence',
            'push::tests::gate_orders_lease_activation_after_in_flight_event_and_backfills_it',
        ]
        for name in names:
            with self.subTest(name=name):
                self.assertEqual(runner.schema_mode(name, 'buzz_db-1234'), 'migration')

    def test_desired_schema_library_fixtures_remain_desired(self):
        for name in ('tests::test_usage_metrics_lock_has_single_owner_and_releases_on_drop',
                     'replica_fence::tests::sample_writer_fails_closed_when_activity_is_masked',
                     'usage::tests::test_community_count_increases'):
            with self.subTest(name=name):
                self.assertEqual(runner.schema_mode(name, 'buzz_db-1234'), 'desired')

    def test_admission_map_requires_hash_for_new_migration(self):
        import json
        import shutil
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'migrations').mkdir()
            for migration in (frozen.ROOT / 'migrations').glob('*.sql'):
                if int(migration.name.split('_')[0]) <= 35:
                    shutil.copy(migration, root / 'migrations')
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

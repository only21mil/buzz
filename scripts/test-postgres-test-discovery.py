#!/usr/bin/env python3
"""Discovery must reject new, stale or omitted tests, including legacy names."""
import csv
from pathlib import Path
import tempfile
import unittest
import os
import subprocess
import re

import postgres_test_inventory as inventory


class DiscoveryTests(unittest.TestCase):
    def test_existing_ci_context_names_remain_exact(self):
        workflow = (inventory.ROOT / '.github/workflows/ci.yml').read_text()
        names = dict(re.findall(r'^  ([\w-]+):\n    name: (.*)$', workflow, re.M))
        expected = {
            'changes': 'Detect Changed Paths', 'rust-lint': 'Rust Lint',
            'unit-tests': 'Unit Tests', 'desktop-core': 'Desktop Core',
            'desktop-smoke-e2e': 'Desktop Smoke E2E (${{ matrix.shard }})',
            'desktop': 'Desktop', 'desktop-e2e-relay': 'Desktop E2E Relay',
            'desktop-e2e-integration-shard': 'Desktop E2E Integration (${{ matrix.shard }}/2)',
            'desktop-e2e-integration': 'Desktop E2E Integration',
            'backend-integration': 'Backend Integration (relay e2e)',
            'relay-e2e': 'Relay E2E', 'web': 'Web', 'mobile': 'Mobile',
            'security': 'Security', 'dead-token-guard': 'Dead Token Reference Guard',
            'server-cross-compile': 'Server Cross-Compile',
            'desktop-build-macos': 'Desktop Build (macOS)',
        }
        for job, name in expected.items():
            self.assertEqual(names.get(job), name, job)

    def test_native_ci_shared_gate_runs_existing_suites_and_propagates_failure(self):
        helper = inventory.ROOT / 'scripts/test-native-ci-python.sh'
        for entry in ('run-tests.sh', 'pre-freeze.sh'):
            self.assertIn('bash scripts/test-native-ci-python.sh',
                          (inventory.ROOT / 'scripts' / entry).read_text())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trace = root / 'trace'
            for name, body in {
                'check-jsonschema': 'echo "check-jsonschema, version 0.38.0"\n',
                'python3': 'echo "$*" >> "$NATIVE_TRACE"\n'
                           'if [[ -n "${NATIVE_FAIL:-}" && "$*" == *"$NATIVE_FAIL"* ]]; then exit 7; fi\n',
                'bash': 'echo "$*" >> "$NATIVE_TRACE"\n',
            }.items():
                path = root / name
                path.write_text('#!/bin/bash\n' + body)
                path.chmod(0o700)
            env = dict(os.environ, PATH=directory, NATIVE_TRACE=str(trace))
            subprocess.run(['/bin/bash', str(helper)], env=env, check=True)
            calls = trace.read_text().splitlines()
            self.assertEqual(sum(c.startswith('-m unittest discover ') for c in calls), 11)
            self.assertIn('-m unittest discover deploy/native-ci/apple-release/tests -p test_*.py', calls)
            self.assertIn('scripts/test-protected-ci-receipt.py', calls)
            self.assertIn('scripts/test-ci-promotion-readiness.py', calls)
            trace.write_text('')
            failed = subprocess.run(['/bin/bash', str(helper)], env=dict(env, NATIVE_FAIL='activation/tests'))
            self.assertEqual(failed.returncode, 7)
            self.assertNotIn('scripts/test-protected-ci-receipt.py', trace.read_text())

    def test_recovery_exact_names_and_unknown_recovery_rejected(self):
        expected = {
            'effect_recovery_fires_unfired_claim_once_with_same_identity',
            'effect_recovery_reclaimed_run_does_not_refire_prior_message',
            'effect_recovery_skips_fired_message_after_crash_before_finalize',
            'effect_recovery_uses_pinned_message_when_live_resolution_fails',
            'inline_driver_and_recovery_sweep_race_on_one_generation_fence',
            'recovery_sweep_completes_grant_when_inline_continuation_never_starts',
            'recovery_sweep_reclaims_expired_running_generation',
            'replay_reclaims_expired_run_then_conflicts_without_double_execution',
            'thread_effect_recovery_uses_pinned_ancestry_after_workflow_deletion',
            'new_message_claim_uses_authored_text_from_frozen_approval_definition',
        }
        rows = inventory.read_inventory()
        actual = {r['test'].split('::')[-1] for r in rows
                  if r['test'].startswith('workflow_resume::tests::') and r['mode'] == 'migration'}
        self.assertEqual(actual, expected)
        for name in expected:
            self.assertEqual(inventory.classify('workflow_resume::tests::' + name, 'buzz_relay-123abc'), 'migration')
        with self.assertRaisesRegex(ValueError, 'unknown'):
            inventory.classify('workflow_resume::tests::new_unreviewed_fixture', 'buzz_relay-123abc')

    def test_source_lexer_rejects_unknown_bare_and_raw_ignore(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            crate = root / 'crates/fixture'
            (crate / 'src').mkdir(parents=True)
            (root / 'scripts').mkdir()
            (crate / 'Cargo.toml').write_text('[package]\nname = "fixture"\n')
            path = crate / 'src/lib.rs'
            path.write_text('''// #[ignore] fn commented() {}
/* #[ignore = "requires Postgres"] fn also_commented() {} */
mod tests {
#[test] #[ignore = r#"requires PostgreSQL"#] fn raw_fixture() {}
#[test] #[ignore] fn bare_fixture() {}
}
''')
            with (root / 'scripts/postgres-tests.tsv').open('w') as stream:
                writer = csv.DictWriter(stream, fieldnames=inventory.FIELDS, delimiter='\t')
                writer.writeheader()
            with self.assertRaisesRegex(ValueError, 'unclassified ignored tests'):
                inventory.validate(root)
            self.assertEqual(len(inventory.source_tests(root)), 2)
            with (root / 'scripts/postgres-tests.tsv').open('a') as stream:
                writer = csv.DictWriter(stream, fieldnames=inventory.FIELDS, delimiter='\t')
                for name in ('raw_fixture', 'bare_fixture'):
                    writer.writerow(dict(zip(inventory.FIELDS, (
                        'fixture', 'fixture', 'tests::' + name, 'crates/fixture/src/lib.rs',
                        'desired', 'reviewed fixture'))))
            self.assertEqual(len(inventory.validate(root)), 2)
            original = path.read_text()
            path.write_text(original + '#[test] #[ignore = concat!("requires Postgres")] fn unknown() {}')
            with self.assertRaisesRegex(ValueError, 'unsupported ignore attribute'):
                inventory.validate(root)
            path.write_text(original.replace('#[test] #[ignore] fn bare_fixture() {}', ''))
            with self.assertRaisesRegex(ValueError, 'stale or ambiguous'):
                inventory.validate(root)

    def test_compiled_inventory_cannot_drop_or_add_a_case(self):
        rows = inventory.read_inventory()
        names = [r['test'] for r in rows if r['binary'] == 'workflow_approval_contract']
        self.assertGreater(len(names), 20)
        inventory.reconcile('workflow_approval_contract-abc123', names, rows)
        for changed in (names[:-1], names + ['unclassified'], names + names[:1]):
            with self.assertRaisesRegex(ValueError, 'compiled discovery mismatch'):
                inventory.reconcile('workflow_approval_contract-abc123', changed, rows)

    def test_existing_ci_selections_still_admitted(self):
        rows = inventory.read_inventory()
        for module in ('relay_invite::tests::', 'api::invites::tests::', 'handlers::relay_admin::tests::'):
            selected = [r for r in rows if r['test'].startswith(module)]
            self.assertTrue(selected, module)
            self.assertTrue(all(r['mode'] == 'desired' for r in selected))
        selected = [r for r in rows if 'coordinate_delete_spares_head_newer_than_the_deletion' in r['test']]
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0]['mode'], 'desired')
        for binary in ('ci_grants_contract', 'workflow_approval_contract', 'workflow_state_contract',
                       'workflow_enabled_persistence', 'ci_ingest_storage'):
            selected = [r for r in rows if r['binary'] == binary]
            self.assertTrue(selected, binary)
            self.assertTrue(all(r['mode'] == 'migration' for r in selected))

    def test_external_infrastructure_is_explicit(self):
        rows = inventory.read_inventory()
        self.assertTrue(all(r['mode'] == 'external' for r in rows
                            if r['package'] in ('buzz-test-client', 'buzz-pubsub', 'buzz-media', 'buzz-voice')))
        workflow = (inventory.ROOT / '.github/workflows/ci.yml').read_text()
        self.assertIn("-E 'binary(e2e_event_reminder)'", workflow)
        self.assertIn('bash scripts/postgres-test-ci.sh', workflow)
        admission = (inventory.ROOT / 'scripts/postgres-test-ci.sh').read_text()
        self.assertIn('scripts/postgres-test-run.sh --task-root', admission)
        self.assertNotIn('continue-on-error:', workflow.split('  backend-integration:')[1].split('  relay-e2e:')[0])


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3
"""Exercise the workflow inventory parser and drift checks on a small fixture."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("inventory", Path(__file__).with_name("ci-workflow-inventory.py"))
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)
FIXTURES = Path(__file__).with_name("fixtures") / "ci-workflow-inventory"
WORKFLOWS = FIXTURES / "workflows"
DISPOSITIONS = FIXTURES / "dispositions.json"
CHECKS = json.loads((FIXTURES / "required-checks.json").read_text())["checks"]


def rows_by_key():
    return {f"{r['workflow']}:{r['job_id']}": r for r in inventory.parse_all(WORKFLOWS)}


class ParserTests(unittest.TestCase):
    def test_every_fixture_job_is_parsed(self):
        self.assertEqual(sorted(rows_by_key()), [
            "ci.yml:ios", "ci.yml:lint", "ci.yml:mac", "ci.yml:smoke", "publish.yml:image", "publish.yml:windows"])

    def test_triggers_and_concurrency(self):
        rows = rows_by_key()
        self.assertEqual(rows["ci.yml:lint"]["triggers"], ["pull_request", "push[branches=release]"])
        self.assertEqual(rows["ci.yml:lint"]["concurrency"], "ci-${{ github.ref }}")
        self.assertEqual(rows["publish.yml:image"]["triggers"], ["push[tags=thing-v[0-9]*]", "workflow_dispatch"])
        self.assertEqual(rows["publish.yml:image"]["concurrency"], "-")

    def test_list_matrix_expands_names_and_cost(self):
        smoke = rows_by_key()["ci.yml:smoke"]
        self.assertEqual(smoke["names"], ["Smoke (1)", "Smoke (2)"])
        self.assertEqual(smoke["runners"], ["ubuntu-latest"])
        self.assertEqual(smoke["needs"], ["lint"])
        self.assertEqual(smoke["cost"], "M/40")

    def test_include_matrix_expands_runner_labels(self):
        image = rows_by_key()["publish.yml:image"]
        self.assertEqual(image["names"], ["Image (linux/amd64)", "Image (linux/arm64)"])
        self.assertEqual(image["runners"], ["ubuntu-24.04", "ubuntu-24.04-arm"])
        self.assertEqual(image["cost"], "XL/720")
        self.assertEqual(image["permissions"], ["id-token:write", "packages:write"])
        self.assertEqual(image["secrets"], ["GITHUB_TOKEN"])
        self.assertEqual(image["effects"], ["publish", "sign", "environment:production"])
        self.assertEqual(image["gate"], "disabled-for-fork")

    def test_gate_classification(self):
        rows = rows_by_key()
        self.assertEqual(rows["ci.yml:lint"]["gate"], "main-pr, path-filtered")
        self.assertEqual(rows["ci.yml:mac"]["gate"], "fork-only")
        self.assertEqual(rows["ci.yml:ios"]["gate"], "fork-only, vars:RUNNER_LABELS")
        self.assertEqual(rows["publish.yml:windows"]["gate"], "always-false")

    def test_self_hosted_and_default_timeout(self):
        rows = rows_by_key()
        self.assertEqual(rows["ci.yml:ios"]["runners"], ["vars:RUNNER_LABELS"])
        self.assertEqual(rows["ci.yml:ios"]["cost"], "self-hosted")
        self.assertEqual(rows["ci.yml:ios"]["timeout"], "default 360")
        self.assertEqual(rows["ci.yml:mac"]["cost"], "XL/450")
        self.assertEqual(rows["publish.yml:windows"]["cost"], "XL/720")
        self.assertEqual(rows["publish.yml:windows"]["effects"], ["sign"])
        self.assertEqual(rows["publish.yml:windows"]["names"], ["windows"])

    def test_undefined_matrix_reference_refuses(self):
        with self.assertRaises(inventory.InventoryError):
            inventory.expand("Job (${{ matrix.missing }})", {"shard": 1})


class AnnotateTests(unittest.TestCase):
    def setUp(self):
        self.rows = inventory.parse_all(WORKFLOWS)
        self.dispositions = inventory.load_dispositions(DISPOSITIONS)

    def test_required_checks_bind_to_producing_jobs(self):
        produced = inventory.annotate(self.rows, CHECKS, self.dispositions)
        self.assertEqual(produced, {"Lint": ["ci.yml:lint"], "Mac Build": ["ci.yml:mac"]})
        by_key = {f"{r['workflow']}:{r['job_id']}": r for r in self.rows}
        self.assertEqual(by_key["ci.yml:lint"]["required"], ["Lint"])
        self.assertEqual(by_key["ci.yml:smoke"]["required"], [])
        self.assertEqual(by_key["ci.yml:smoke"]["note"], "two shards")
        self.assertEqual(by_key["ci.yml:mac"]["owner"], "apple")

    def test_missing_disposition_refuses(self):
        dispositions = copy.deepcopy(self.dispositions)
        del dispositions["ci.yml:smoke"]
        with self.assertRaisesRegex(inventory.InventoryError, "ci.yml:smoke: no disposition"):
            inventory.annotate(self.rows, CHECKS, dispositions)

    def test_stale_disposition_refuses(self):
        dispositions = copy.deepcopy(self.dispositions)
        dispositions["ci.yml:removed"] = {"disposition": "disabled-for-fork"}
        with self.assertRaisesRegex(inventory.InventoryError, "removed jobs: ci.yml:removed"):
            inventory.annotate(self.rows, CHECKS, dispositions)

    def test_orphaned_required_check_refuses(self):
        checks = CHECKS + [{"context": "Nobody Produces This", "integration_id": 15368}]
        with self.assertRaisesRegex(inventory.InventoryError, "no workflow produces: Nobody Produces This"):
            inventory.annotate(self.rows, checks, self.dispositions)

    def test_native_outside_ci_workflow_refuses(self):
        dispositions = copy.deepcopy(self.dispositions)
        dispositions["publish.yml:windows"] = {"disposition": "native", "native": "windows"}
        with self.assertRaisesRegex(inventory.InventoryError, "native execution covers only ci.yml"):
            inventory.annotate(self.rows, CHECKS, dispositions)

    def test_disposition_file_validation(self):
        for bad in ({"disposition": "maybe"}, {"disposition": "retained-github", "owner": "x"},
                    {"disposition": "native"}):
            with patch.object(Path, "read_text", return_value=json.dumps({"ci.yml:lint": bad})):
                with self.assertRaises(inventory.InventoryError):
                    inventory.load_dispositions(DISPOSITIONS)


class RenderTests(unittest.TestCase):
    def test_render_is_deterministic_and_lists_gaps(self):
        with patch.object(inventory, "load_snapshot", return_value=CHECKS):
            first = inventory.build(True, WORKFLOWS, DISPOSITIONS)[2]
            second = inventory.build(True, WORKFLOWS, DISPOSITIONS)[2]
        self.assertEqual(first, second)
        self.assertTrue(first.startswith("# GitHub workflow inventory\n\nGenerated by"))
        self.assertIn("- Workflows: 2; jobs: 6; job executions after matrix expansion: 8.", first)
        self.assertIn("- Dispositions: native 2, retained-github 2, disabled-for-fork 2.", first)
        self.assertIn("| Lint | 15368 | `ci.yml:lint` | native | lint |", first)
        self.assertIn("| `ci.yml:mac` | Mac Build | apple | apple executor |", first)
        self.assertIn("- `smoke`: two shards", first)
        self.assertNotIn("fetched_at", first)

    def test_check_mode_detects_stale_document_and_passes_when_current(self):
        with tempfile.TemporaryDirectory(prefix="buzz-ci-inventory-test-") as directory:
            doc = Path(directory) / "workflow-inventory.md"
            doc.write_text("stale\n")
            with patch.object(inventory, "load_snapshot", return_value=CHECKS), \
                    patch.object(inventory, "WORKFLOWS", WORKFLOWS), \
                    patch.object(inventory, "DISPOSITIONS", DISPOSITIONS), \
                    patch.object(inventory, "DOC", doc):
                with self.assertRaisesRegex(SystemExit, "is stale"):
                    inventory.main(["--offline", "--check"])
                self.assertEqual(inventory.main(["--offline", "--write"]), 0)
                self.assertEqual(inventory.main(["--offline", "--check"]), 0)
                self.assertTrue(doc.read_text().endswith("\n"))


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import copy
from datetime import timedelta
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ACTIVATION_DIR = Path(__file__).resolve().parents[1]
BRIDGE_PATH = ACTIVATION_DIR / "parent-tier1-activation.py"


def load_bridge():
    spec = importlib.util.spec_from_file_location("mgact_parent_tier1_tests", BRIDGE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load parent Tier 1 bridge")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


BRIDGE = load_bridge()


class ParentTier1ActivationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        receipt = json.loads(BRIDGE.RECEIPT.read_text())
        cls.receipt_time = BRIDGE.parse_instant(receipt["generated_at"], "generated_at")
        cls.now = cls.receipt_time + timedelta(seconds=1)
        cls.bridge_record = {
            "repo": str(BRIDGE.REPO_ROOT),
            "branch": BRIDGE.BRIDGE_BRANCH,
            "commit": "1" * 40,
            "tree": "2" * 40,
            "parent": BRIDGE.SOURCE_COMMIT,
            "script": str(BRIDGE_PATH),
            "script_sha256": "3" * 64,
        }

    def static_inputs(self):
        with mock.patch.object(BRIDGE, "bridge_binding", return_value=self.bridge_record):
            return BRIDGE.validate_static_inputs(self.now)

    def test_exact_package_and_receipt_positive(self) -> None:
        static = self.static_inputs()
        runtime = static.manifest["runtime_targets"]
        ops = static.manifest["ops_targets"]
        self.assertEqual(len(runtime), 22)
        self.assertEqual(len(ops), 1)
        self.assertEqual(
            BRIDGE.sha256_bytes(BRIDGE.canonical_json(runtime)),
            BRIDGE.RUNTIME_TARGET_AGGREGATE,
        )
        self.assertEqual(static.receipt["status"], "READY_FOR_PARENT_TIER1")
        self.assertFalse(static.receipt["installable"])

    def test_manifest_rejects_wrong_identity_hash_source_path_and_closure(self) -> None:
        manifest = json.loads(BRIDGE.MANIFEST.read_text())
        mutations = {
            "identity": lambda value: value["inputs"].__setitem__("genesis", "0" * 64),
            "hash": lambda value: value.__setitem__("package_digest", "0" * 64),
            "source": lambda value: value.__setitem__("source_branch", "wrong"),
            "path": lambda value: value["runtime_targets"][0].__setitem__("target", "/wrong"),
            "closure": lambda value: value["review_files"]["genesis"][0].__setitem__(
                "sha256", "0" * 64
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                changed = copy.deepcopy(manifest)
                mutate(changed)
                with self.assertRaises(ValueError):
                    BRIDGE.validate_manifest_bindings(changed)

    def test_receipt_rejects_wrong_status_stale_and_future_content_time(self) -> None:
        manifest = json.loads(BRIDGE.MANIFEST.read_text())
        receipt = json.loads(BRIDGE.RECEIPT.read_text())
        wrong = copy.deepcopy(receipt)
        wrong["status"] = "PASS"
        with self.assertRaisesRegex(ValueError, "status"):
            BRIDGE.validate_receipt(wrong, manifest, self.now)
        with self.assertRaisesRegex(ValueError, "future"):
            BRIDGE.validate_receipt(receipt, manifest, self.receipt_time - timedelta(microseconds=1))
        with self.assertRaisesRegex(ValueError, "stale"):
            BRIDGE.validate_receipt(
                receipt,
                manifest,
                self.receipt_time + timedelta(seconds=BRIDGE.FRESHNESS_SECONDS, microseconds=1),
            )

    def test_wrong_receipt_bytes_fail_the_immutable_hash(self) -> None:
        with tempfile.TemporaryDirectory(dir="/home/victor/work") as temporary:
            path = Path(temporary) / "receipt.json"
            path.write_bytes(BRIDGE.RECEIPT.read_bytes() + b" ")
            path.chmod(0o600)
            with mock.patch.object(BRIDGE, "RECEIPT", path), mock.patch.object(
                BRIDGE, "bridge_binding", return_value=self.bridge_record
            ):
                with self.assertRaisesRegex(ValueError, "receipt hash"):
                    BRIDGE.validate_static_inputs(self.now)

    def issue_temp_acceptance(self, directory: Path):
        path = directory / "acceptance.json"
        static = self.static_inputs()
        with mock.patch.object(BRIDGE, "ACCEPTANCE", path), mock.patch.object(
            BRIDGE, "validate_static_inputs", return_value=static
        ):
            acceptance = BRIDGE.issue(self.now)
        return static, path, acceptance

    def test_acceptance_positive_exact_match(self) -> None:
        with tempfile.TemporaryDirectory(dir="/home/victor/work") as temporary:
            directory = Path(temporary)
            directory.chmod(0o700)
            static, path, issued = self.issue_temp_acceptance(directory)
            with mock.patch.object(BRIDGE, "ACCEPTANCE", path):
                checked = BRIDGE.validate_acceptance(static, self.now)
            self.assertEqual(checked.digest, issued.digest)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(checked.value["tier"], 1)
            self.assertFalse(checked.value["tier2_state_accepted"])

    def test_acceptance_rejects_wrong_authority_controller_source_path_hash_identity_and_closure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(dir="/home/victor/work") as temporary:
            directory = Path(temporary)
            directory.chmod(0o700)
            static, path, _issued = self.issue_temp_acceptance(directory)
            original = json.loads(path.read_text())
            mutations = {
                "authority": lambda value: value["authority"].__setitem__(
                    "classification_event", "0" * 64
                ),
                "controller": lambda value: value.__setitem__("controller", "wrong"),
                "source": lambda value: value["source"].__setitem__("commit", "0" * 40),
                "path": lambda value: value["package"].__setitem__("bundle", "/wrong"),
                "hash": lambda value: value["package"].__setitem__(
                    "manifest_sha256", "0" * 64
                ),
                "identity": lambda value: value["identities"]["genesis"].__setitem__(
                    "pubkey", "0" * 64
                ),
                "closure": lambda value: value["identities"]["mempool"].__setitem__(
                    "closure_sha256", "0" * 64
                ),
            }
            for name, mutate in mutations.items():
                with self.subTest(name=name):
                    changed = copy.deepcopy(original)
                    mutate(changed)
                    path.write_bytes(BRIDGE.canonical_json(changed))
                    path.chmod(0o600)
                    with mock.patch.object(BRIDGE, "ACCEPTANCE", path):
                        with self.assertRaisesRegex(ValueError, "fields mismatch"):
                            BRIDGE.validate_acceptance(static, self.now)

    def test_acceptance_rejects_unsafe_mode_and_hardlink(self) -> None:
        with tempfile.TemporaryDirectory(dir="/home/victor/work") as temporary:
            directory = Path(temporary)
            directory.chmod(0o700)
            static, path, _issued = self.issue_temp_acceptance(directory)
            path.chmod(0o644)
            with mock.patch.object(BRIDGE, "ACCEPTANCE", path):
                with self.assertRaisesRegex(ValueError, "mode"):
                    BRIDGE.validate_acceptance(static, self.now)
            path.chmod(0o600)
            os.link(path, directory / "copy.json")
            with mock.patch.object(BRIDGE, "ACCEPTANCE", path):
                with self.assertRaisesRegex(ValueError, "unsafe regular"):
                    BRIDGE.validate_acceptance(static, self.now)

    def test_changed_target_rejects_stale_live_snapshot(self) -> None:
        with tempfile.TemporaryDirectory(dir="/home/victor/work") as temporary:
            root = Path(temporary)
            target = root / "etc/example"
            target.parent.mkdir(parents=True)
            target.write_text("before")
            target.chmod(0o644)
            metadata = target.stat()
            receipt = {
                "live_guard": {
                    "after": {
                        "/etc/example": {
                            "exists": True,
                            "type": "regular",
                            "mode": "0644",
                            "uid": metadata.st_uid,
                            "gid": metadata.st_gid,
                            "links": 1,
                            "size": len(b"before"),
                            "sha256": BRIDGE.sha256_file(target),
                        }
                    }
                }
            }
            self.assertEqual(BRIDGE.live_snapshot_blockers(receipt, root), [])
            target.write_text("changed")
            self.assertEqual(
                BRIDGE.live_snapshot_blockers(receipt, root),
                ["stale live snapshot: /etc/example"],
            )

    def test_changed_unreadable_target_must_still_match_the_package(self) -> None:
        with tempfile.TemporaryDirectory(dir="/home/victor/work") as temporary:
            root = Path(temporary)
            target = root / "etc/root-only"
            target.parent.mkdir(parents=True)
            target.write_text("expected")
            target.chmod(0o440)
            record = {
                "target": "/etc/root-only",
                "mode": "0440",
                "uid": os.getuid(),
                "gid": os.getgid(),
                "sha256": BRIDGE.sha256_file(target),
            }
            receipt = {"live_guard": {"after": {"/etc/root-only": {"exists": "unreadable"}}}}
            manifest = {"runtime_targets": [record], "ops_targets": []}
            self.assertEqual(BRIDGE.live_snapshot_blockers(receipt, root, manifest), [])
            target.chmod(0o640)
            target.write_text("changed")
            target.chmod(0o440)
            self.assertEqual(
                BRIDGE.live_snapshot_blockers(receipt, root, manifest),
                ["stale live snapshot: /etc/root-only"],
            )

    def test_single_use_claim_survives_reuse_and_crash_after_claim(self) -> None:
        with tempfile.TemporaryDirectory(dir="/home/victor/work") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            acceptance = BRIDGE.Acceptance({}, "a" * 64, root.stat())
            with mock.patch.dict(os.environ, {"MGACT_TESTING": "1"}):
                claim = BRIDGE.create_claim(root, acceptance)
            self.assertTrue(claim.is_file())
            with mock.patch.dict(os.environ, {"MGACT_TESTING": "1"}):
                with self.assertRaises(FileExistsError):
                    BRIDGE.create_claim(root, acceptance)
            self.assertTrue(claim.is_file(), "the crash/reuse claim must survive")

    def test_consumed_acceptance_blocks_later_preflight(self) -> None:
        with tempfile.TemporaryDirectory(dir="/home/victor/work") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            static = self.static_inputs()
            acceptance = BRIDGE.Acceptance({}, "b" * 64, BRIDGE.RECEIPT.stat())
            with mock.patch.dict(os.environ, {"MGACT_TESTING": "1"}):
                BRIDGE.create_claim(root, acceptance)
            with mock.patch.object(
                BRIDGE, "validate_static_inputs", return_value=static
            ), mock.patch.object(
                BRIDGE, "validate_acceptance", return_value=acceptance
            ), mock.patch.object(
                BRIDGE, "package_targets", return_value=()
            ), mock.patch.object(
                BRIDGE, "ordered_targets", return_value=[]
            ), mock.patch.object(
                BRIDGE.INSTALLER, "service_blockers", return_value=[]
            ), mock.patch.object(
                BRIDGE.INSTALLER, "root_metadata", return_value=root.stat()
            ):
                checked = BRIDGE.preflight(root, enforce_live_snapshot=False)
            self.assertIn("Tier 1 acceptance was already consumed", checked[3])

    def test_shared_identity_counts_closure_last_and_execstartpre(self) -> None:
        static = self.static_inputs()
        acceptance = BRIDGE.Acceptance({}, "a" * 64, BRIDGE.RECEIPT.stat())
        targets = BRIDGE.package_targets(static, acceptance)
        ordered = BRIDGE.ordered_targets(targets)
        self.assertEqual(len(targets), 24)
        self.assertEqual(ordered[-1].target, BRIDGE.CLOSURE_TARGET)
        genesis = {entry["path"] for entry in static.manifest["review_files"]["genesis"]}
        mempool = {entry["path"] for entry in static.manifest["review_files"]["mempool"]}
        self.assertEqual(len(genesis & mempool), 16)
        self.assertEqual(len(genesis ^ mempool), 6)
        unit = (BRIDGE.BUNDLE / "install-root/etc/systemd/system/buzz-agent@.service").read_text()
        self.assertIn(
            "ExecStartPre=+/bin/bash /usr/local/libexec/buzz/verify-installed-agent %i",
            unit,
        )

    def test_next_parent_install_writes_complete_v3_installed_records(self) -> None:
        changed = [
            SimpleNamespace(
                target=SimpleNamespace(
                    target="/etc/one",
                    sha256="1" * 64,
                    mode=0o640,
                    uid=0,
                    gid=0,
                )
            ),
            SimpleNamespace(
                target=SimpleNamespace(
                    target="/usr/local/bin/two",
                    sha256="2" * 64,
                    mode=0o755,
                    uid=0,
                    gid=0,
                )
            ),
        ]
        self.assertEqual(
            BRIDGE.INSTALL_RECEIPT_SCHEMA,
            "buzz-mempool-genesis-install-receipt-v3",
        )
        records = BRIDGE.installed_records(changed)
        self.assertEqual(set(records), {state.target.target for state in changed})
        self.assertEqual(records["/etc/one"]["mode"], "0640")
        self.assertEqual(records["/usr/local/bin/two"]["sha256"], "2" * 64)

    def test_services_are_checked_before_and_again_under_the_one_install_lock(self) -> None:
        source = BRIDGE_PATH.read_text()
        initial = source.index("initial = preflight(root, now=now)")
        lock = source.index("prepare_admin_paths(root)", initial)
        checked = source.index("checked = preflight(root, now=now)", lock)
        claim = source.index("claim = create_claim(root, acceptance)", checked)
        writes = source.index("for state in changed:", claim)
        self.assertLess(initial, lock)
        self.assertLess(lock, checked)
        self.assertLess(checked, claim)
        self.assertLess(claim, writes)
        self.assertEqual(source.count("prepare_admin_paths(root)"), 1)

    def test_tier2_defaults_are_byte_identical_and_bridge_cli_rejects_tier2_inputs(self) -> None:
        manifest = json.loads(BRIDGE.MANIFEST.read_text())
        records = {record["path"]: record for record in manifest["generator_sources"]}
        for relative in (
            "scripts/mempool-genesis/activation/install-activation-bundle.py",
            "scripts/mempool-genesis/activation/tier2-evidence-verifier.py",
        ):
            self.assertEqual(
                BRIDGE.sha256_bytes(BRIDGE.git_blob(relative)),
                records[relative]["sha256"],
            )
        result = subprocess.run(
            [sys.executable, str(BRIDGE_PATH), "check", "--tier2-state", "/wrong"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("unrecognized arguments", result.stderr)


if __name__ == "__main__":
    unittest.main()

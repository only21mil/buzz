#!/usr/bin/env python3
"""Focused tests for descriptor-bound activation input rendering."""

from __future__ import annotations

import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stderr
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "render_inputs.py"
SPEC = importlib.util.spec_from_file_location("render_inputs", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
RENDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RENDER)

CANDIDATE = "c" * 40
HEX = {
    "scenario": "1" * 64,
    "config": "2" * 64,
    "units": "3" * 64,
}


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"


OUTPUT = canonical({"complete": True})


def write_json(root: Path, relative: str, value: object, mode: int = 0o600) -> dict[str, object]:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = canonical(value)
    path.write_bytes(raw)
    path.chmod(mode)
    return {"path": relative, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw), "mode": f"{mode:04o}"}


def file_ref(root: Path, relative: str) -> dict[str, object]:
    path = root / relative
    raw = path.read_bytes()
    return {
        "path": relative,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "mode": f"{path.stat().st_mode & 0o7777:04o}",
    }


def public_binding() -> dict[str, object]:
    keys = ["4" * 64, "5" * 64, "6" * 64, "7" * 64]
    return {
        "schema_version": "buzz-ci-clean-host-e2e-public-binding/v2",
        "relay_url": "wss://relay.test.invalid:3443",
        "relay_http_origin": "https://relay.test.invalid:3443",
        "acceptance_actor": {"public_key": keys[0], "generation": 1},
        "keyholder_public_spec": {
            "schema_version": 1,
            "peer": {"uid": 1201, "gid": 1201, "allowed_operations": [
                "describe", "sign_ci_event", "nip98_authorize", "sign_manifest",
                "describe_acceptance", "sign_acceptance_mutation",
            ]},
            "selectors": {
                "ci_event": {"public_key": keys[1], "generation": 1},
                "nip98": {"public_key": keys[2], "generation": 1},
                "manifest": {"public_key": keys[3], "generation": 1},
            },
            "nip98_origin": "https://relay.test.invalid:3443",
            "acceptance": {
                "binding_receipt_path": "/var/lib/buzzci/activation-controller/controld-acceptance-v1.json",
                "credential_selector": "acceptance-actor.key",
            },
        },
    }


def public_binding_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), allow_nan=False,
    ).encode() + b"\n"


def write_public_binding(root: Path, value: object) -> dict[str, object]:
    path = root / "state/public-binding.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = public_binding_bytes(value)
    path.write_bytes(raw)
    path.chmod(0o444)
    return {
        "path": "state/public-binding.json",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "mode": "0444",
    }


def minimal_manifest(
    name: str, source: str, raw: bytes, mode: int = 0o400,
    candidate: str = CANDIDATE,
) -> dict[str, object]:
    unsigned: dict[str, object] = {
        "schema": f"test-{name}-package-v1",
        "source_commit": candidate,
        "entries": [{
            "role": "payload", "source": source, "source_mode": f"{mode:04o}",
            "sha256": hashlib.sha256(raw).hexdigest(),
        }],
    }
    return {**unsigned, "package_digest": hashlib.sha256(canonical(unsigned)).hexdigest()}


class RendererTests(unittest.TestCase):
    def output_root(self, root: Path) -> RENDER.DescriptorRoot:
        descriptor = root / "descriptor.json"
        descriptor.write_bytes(canonical({"unused": True}))
        descriptor.chmod(0o600)
        return RENDER.DescriptorRoot(descriptor)

    def output_temporaries(self, root: Path) -> list[Path]:
        return list(root.glob(".render-inputs-*.tmp"))

    def test_schema_documents_and_relative_references_are_valid(self) -> None:
        for schema_path in (ROOT / "descriptor.schema.json", ROOT / "output.schema.json"):
            schema = json.loads(schema_path.read_bytes())
            stack: list[object] = [schema]
            while stack:
                value = stack.pop()
                if isinstance(value, dict):
                    pattern = value.get("pattern")
                    if isinstance(pattern, str):
                        re.compile(pattern)
                    reference = value.get("$ref")
                    if isinstance(reference, str) and not reference.startswith("#"):
                        self.assertTrue((schema_path.parent / reference).resolve().is_file(), reference)
                    stack.extend(value.values())
                elif isinstance(value, list):
                    stack.extend(value)

    def make_candidate(self, root: Path) -> tuple[Path, str, dict[str, object]]:
        candidate_root = root / "candidate"
        for name, (relative, git_mode, _maximum) in RENDER.HARNESS_ASSET_SOURCES.items():
            source = (
                RENDER.CLEAN_HOST_ASSET_ROOT / name
                if name not in {"receipt_verifier.py", "expected-stages.json"}
                else ROOT.parents[1] / "acceptance" / (
                    "verify-receipt.py" if name == "receipt_verifier.py" else name
                )
            )
            target = candidate_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            target.chmod(git_mode & 0o777)
        (candidate_root / ".gitignore").write_text(".ignored-build/\n")
        subprocess.run(["/usr/bin/git", "init", "-q", str(candidate_root)], check=True)
        subprocess.run([
            "/usr/bin/git", "-C", str(candidate_root), "config", "user.name", "Test",
        ], check=True)
        subprocess.run([
            "/usr/bin/git", "-C", str(candidate_root), "config", "user.email",
            "test@example.invalid",
        ], check=True)
        subprocess.run(["/usr/bin/git", "-C", str(candidate_root), "add", "."], check=True)
        subprocess.run([
            "/usr/bin/git", "-C", str(candidate_root), "commit", "-q", "-m", "candidate",
        ], check=True)
        candidate = subprocess.check_output([
            "/usr/bin/git", "-C", str(candidate_root), "rev-parse", "HEAD^{commit}",
        ], text=True).strip()
        bindings = RENDER.candidate_clean_host_bindings(candidate_root, candidate)
        return candidate_root, candidate, bindings

    def make_lifecycle(self, root: Path) -> tuple[dict[str, object], str]:
        _candidate_root, candidate, bindings = self.make_candidate(root)
        proof = {
            "configs_sha256": HEX["config"], "units_sha256": HEX["units"],
            "sockets_absent": True, "processes_absent": True,
            "encrypted_credentials_absent": True, "relay_residue_absent": True,
        }
        trees = {name: digit * 64 for name, digit in zip(RENDER.PACKAGE_NAMES, "89abc", strict=True)}
        timing = bindings["timing"]
        harness_sha = bindings["harness_sha256"]
        timing_asset_sha = bindings["timing_asset_sha256"]
        timing_sha = bindings["timing_sha256"]
        contract = {
            "schema_version": "buzz-ci-clean-host-e2e-vm-contract/v3", "candidate_sha": candidate,
            "state": "state", "candidate_root": "candidate",
            "harness_sha256": harness_sha,
            "timing_asset_sha256": timing_asset_sha,
            "timing": timing, "timing_sha256": timing_sha,
            "scenario": {"path": "scenario.json", "sha256": HEX["scenario"]},
            "seccomp_source": {"path": "seccomp.json", "sha256": RENDER.SECCOMP_SHA256},
            "packages": {name: {"path": name, "tree_sha256": trees[name]} for name in RENDER.PACKAGE_NAMES},
        }
        expected_stages = json.loads(
            (ROOT.parents[1] / "acceptance/expected-stages.json").read_bytes(),
        )
        checks = [
            {
                "sequence": sequence, "stage": stage, "outcome": "pass",
                "evidence_sha256": f"{sequence:x}" * 64, "snapshot": {},
                **({"export": {}} if sequence == 7 else {}),
            }
            for sequence, stage in enumerate(expected_stages, start=1)
        ]
        receipt = {
            "schema_version": "buzz-ci-capacity-one-acceptance-receipt/v2",
            "outcome": "pass", "scenario_sha256": HEX["scenario"],
            "integrated_candidate_sha": candidate, "run_id": "1" * 32,
            "checks": checks,
            "zero_transition": {
                "schema_version": "buzz-ci-capacity-one-zero-transition/v1",
                "outcome": "pass", "attempts": 1, "phases": [], "zero_proof": {},
            },
        }
        verifier = {"outcome": "pass", "status": "verified"}
        receipt_ref = write_json(root, "evidence/acceptance-receipt.json", receipt, 0o400)
        verifier_ref = write_json(root, "evidence/verifier.json", verifier, 0o400)
        evidence = {
            "schema_version": "buzz-ci-clean-host-e2e-evidence/v3", "candidate_sha": candidate,
            "image_sha256": "d" * 64,
            "tool_sha256": {
                "qemu": "e" * 64, "qemu_img": "d" * 64, "bwrap": "c" * 64,
                "xorriso": "b" * 64, "cloud_localds": "a" * 64,
            },
            "harness_sha256": harness_sha,
            "harness_asset_sha256": bindings["asset_sha256"],
            "timing_asset_sha256": timing_asset_sha,
            "timing": timing, "timing_sha256": timing_sha,
            "package_tree_sha256": trees, "scenario_sha256": HEX["scenario"],
            "seccomp_source_sha256": RENDER.SECCOMP_SHA256,
            "transfer_bytes": 8 * 1024 * 1024, "transfer_sha256": "7" * 64,
            "receipt_sha256": receipt_ref["sha256"], "verifier_sha256": verifier_ref["sha256"],
            "dormant_proof": proof,
        }
        evidence_ref = write_json(root, "evidence/evidence-manifest.json", evidence, 0o400)
        contract_ref = write_json(root, "evidence/contract.json", contract, 0o400)
        result = {
            "status": "pass", "candidate_sha": candidate, "vm_state_absent": True,
            "harness_sha256": harness_sha, "timing_asset_sha256": timing_asset_sha,
            "timing_sha256": timing_sha,
            "receipt_sha256": receipt_ref["sha256"], "verifier_sha256": verifier_ref["sha256"],
            "evidence_manifest_sha256": evidence_ref["sha256"], "dormant_proof": proof,
        }
        result_ref = write_json(root, "evidence/result.json", result, 0o400)
        return {
            "result": result_ref, "contract": contract_ref, "evidence_manifest": evidence_ref,
            "acceptance_receipt": receipt_ref, "verifier": verifier_ref,
        }, candidate

    def rewrite_lifecycle_member(
        self, root: Path, lifecycle: dict[str, object], name: str, value: object,
    ) -> None:
        reference = lifecycle[name]
        assert isinstance(reference, dict)
        (root / str(reference["path"])).chmod(0o600)
        lifecycle[name] = write_json(root, str(reference["path"]), value, 0o400)
        if name == "verifier":
            verifier_sha = lifecycle[name]["sha256"]
            for dependent in ("evidence_manifest", "result"):
                dependent_ref = lifecycle[dependent]
                assert isinstance(dependent_ref, dict)
                dependent_value = json.loads((root / str(dependent_ref["path"])).read_bytes())
                dependent_value["verifier_sha256"] = verifier_sha
                (root / str(dependent_ref["path"])).chmod(0o600)
                lifecycle[dependent] = write_json(
                    root, str(dependent_ref["path"]), dependent_value, 0o400,
                )
        if name in {"verifier", "evidence_manifest"}:
            result_ref = lifecycle["result"]
            evidence_ref = lifecycle["evidence_manifest"]
            assert isinstance(result_ref, dict) and isinstance(evidence_ref, dict)
            result_value = json.loads((root / str(result_ref["path"])).read_bytes())
            result_value["evidence_manifest_sha256"] = evidence_ref["sha256"]
            (root / str(result_ref["path"])).chmod(0o600)
            lifecycle["result"] = write_json(
                root, str(result_ref["path"]), result_value, 0o400,
            )

    def run_cli(self, root: Path, action: str, descriptor: dict[str, object], output: str) -> subprocess.CompletedProcess[str]:
        descriptor_ref = write_json(root, "descriptor.json", descriptor)
        return subprocess.run(
            ["python3", str(SCRIPT), action, "--descriptor", str(root / descriptor_ref["path"]), "--output", output],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )

    def run_main_with_checkpoint(
        self, root: Path, action: str, descriptor: dict[str, object], output: str,
        checkpoint: object,
    ) -> tuple[int, str]:
        descriptor_ref = write_json(root, "descriptor.json", descriptor)
        arguments = [
            str(SCRIPT), action, "--descriptor", str(root / descriptor_ref["path"]),
            "--output", output,
        ]
        stderr = io.StringIO()
        with (
            mock.patch.object(sys, "argv", arguments),
            mock.patch.object(RENDER, "candidate_checkpoint", side_effect=checkpoint),
            redirect_stderr(stderr),
        ):
            result = RENDER.main()
        return result, stderr.getvalue()

    def test_residue_is_reproducible_and_disclaims_external_gates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lifecycle, candidate = self.make_lifecycle(root)
            descriptor = {
                "schema_version": "buzz-ci-residue-receipt-render-input/v1",
                "candidate_sha": candidate, "lifecycle": lifecycle,
            }
            index = root / "candidate/.git/index"
            index_before = hashlib.sha256(index.read_bytes()).hexdigest()
            first = self.run_cli(root, "record-residue", descriptor, "first.json")
            self.assertEqual(first.returncode, 0, first.stderr)
            second = self.run_cli(root, "record-residue", descriptor, "second.json")
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual((root / "first.json").read_bytes(), (root / "second.json").read_bytes())
            value = json.loads((root / "first.json").read_bytes())
            self.assertEqual(value["claims"], {"protected_ci": False, "tier2": False})
            self.assertEqual(value["lifecycle_status"], "verified_pass")
            self.assertEqual(
                (root / "evidence/verifier.json").read_bytes(),
                b'{"outcome":"pass","status":"verified"}\n',
            )
            self.assertEqual(hashlib.sha256(index.read_bytes()).hexdigest(), index_before)
            self.assertFalse((root / "candidate/.git/index.lock").exists())
            self.assertEqual((root / "first.json").stat().st_mode & 0o7777, 0o600)

    def test_output_publication_fsyncs_file_and_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            root = self.output_root(root_path)
            real_fsync = os.fsync
            fsync_kinds: list[str] = []

            def record_fsync(fd: int) -> None:
                fsync_kinds.append("directory" if os.path.isdir(f"/proc/self/fd/{fd}") else "file")
                real_fsync(fd)

            try:
                with mock.patch.object(RENDER.os, "fsync", side_effect=record_fsync):
                    RENDER.write_output(root, "output.json", OUTPUT)
            finally:
                root.close()
            output = root_path / "output.json"
            self.assertEqual(output.read_bytes(), OUTPUT)
            self.assertEqual(output.stat().st_mode & 0o7777, 0o600)
            self.assertEqual(output.stat().st_nlink, 1)
            self.assertEqual(fsync_kinds, ["file", "directory"])
            self.assertEqual(self.output_temporaries(root_path), [])

    def test_concurrent_publication_has_one_no_clobber_winner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            roots = [self.output_root(root_path), self.output_root(root_path)]
            barrier = threading.Barrier(2)
            real_link = os.link
            failures: list[BaseException] = []

            def racing_link(*args: object, **kwargs: object) -> None:
                barrier.wait(timeout=5)
                real_link(*args, **kwargs)

            def publish(root: RENDER.DescriptorRoot, payload: bytes) -> None:
                try:
                    RENDER.write_output(root, "output.json", payload)
                except BaseException as error:
                    failures.append(error)

            threads = [
                threading.Thread(target=publish, args=(root, payload))
                for root, payload in zip(
                    roots,
                    (canonical({"value": "first"}), canonical({"value": "second"})),
                    strict=True,
                )
            ]
            try:
                with mock.patch.object(RENDER.os, "link", side_effect=racing_link):
                    for thread in threads:
                        thread.start()
                    for thread in threads:
                        thread.join(timeout=10)
                self.assertTrue(all(not thread.is_alive() for thread in threads))
            finally:
                for root in roots:
                    root.close()
            self.assertEqual(len(failures), 1)
            self.assertIsInstance(failures[0], FileExistsError)
            self.assertIn(
                (root_path / "output.json").read_bytes(),
                (canonical({"value": "first"}), canonical({"value": "second"})),
            )
            self.assertEqual((root_path / "output.json").stat().st_nlink, 1)
            self.assertEqual(self.output_temporaries(root_path), [])

    def test_partial_write_failure_cleans_up_and_retry_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            root = self.output_root(root_path)
            real_write = os.write
            writes = 0

            def partial_then_enospc(fd: int, data: object) -> int:
                nonlocal writes
                writes += 1
                if writes == 1:
                    return real_write(fd, bytes(data)[:3])
                raise OSError(errno.ENOSPC, "injected full filesystem")

            try:
                with mock.patch.object(RENDER.os, "write", side_effect=partial_then_enospc):
                    with self.assertRaisesRegex(OSError, "injected full filesystem"):
                        RENDER.write_output(root, "output.json", OUTPUT)
                self.assertFalse((root_path / "output.json").exists())
                self.assertEqual(self.output_temporaries(root_path), [])
                RENDER.write_output(root, "output.json", OUTPUT)
            finally:
                root.close()
            self.assertEqual((root_path / "output.json").read_bytes(), OUTPUT)

    def test_prepublish_fsync_and_link_failures_clean_up(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            root = self.output_root(root_path)
            try:
                with mock.patch.object(RENDER.os, "fsync", side_effect=OSError(errno.EIO, "injected fsync")):
                    with self.assertRaisesRegex(OSError, "injected fsync"):
                        RENDER.write_output(root, "fsync.json", OUTPUT)
                self.assertFalse((root_path / "fsync.json").exists())
                self.assertEqual(self.output_temporaries(root_path), [])

                with mock.patch.object(RENDER.os, "link", side_effect=OSError(errno.EIO, "injected link")):
                    with self.assertRaisesRegex(OSError, "injected link"):
                        RENDER.write_output(root, "link.json", OUTPUT)
                self.assertFalse((root_path / "link.json").exists())
                self.assertEqual(self.output_temporaries(root_path), [])

                RENDER.write_output(root, "fsync.json", OUTPUT)
                RENDER.write_output(root, "link.json", OUTPUT)
            finally:
                root.close()

    def test_cleanup_survives_close_error_and_retries_unlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            root = self.output_root(root_path)
            real_close = os.close
            close_failed = False

            def close_then_fail(fd: int) -> None:
                nonlocal close_failed
                is_file = not os.path.isdir(f"/proc/self/fd/{fd}")
                real_close(fd)
                if is_file and not close_failed:
                    close_failed = True
                    raise OSError(errno.EIO, "injected close")

            try:
                with mock.patch.object(RENDER.os, "close", side_effect=close_then_fail):
                    with self.assertRaisesRegex(OSError, "injected close"):
                        RENDER.write_output(root, "close.json", OUTPUT)
                self.assertEqual((root_path / "close.json").read_bytes(), OUTPUT)
                self.assertEqual(self.output_temporaries(root_path), [])
                RENDER.write_output(root, "close.json", OUTPUT)

                real_unlink = os.unlink
                unlinks = 0

                def unlink_once_then_succeed(path: str, *, dir_fd: int) -> None:
                    nonlocal unlinks
                    unlinks += 1
                    if unlinks == 1:
                        raise OSError(errno.EIO, "injected unlink")
                    real_unlink(path, dir_fd=dir_fd)

                with mock.patch.object(RENDER.os, "unlink", side_effect=unlink_once_then_succeed):
                    RENDER.write_output(root, "output.json", OUTPUT)
                self.assertEqual(unlinks, 2)
                self.assertEqual(self.output_temporaries(root_path), [])
            finally:
                root.close()

    def test_directory_fsync_failure_allows_only_an_exact_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            root = self.output_root(root_path)
            real_fsync = os.fsync

            def fail_directory_fsync(fd: int) -> None:
                if os.path.isdir(f"/proc/self/fd/{fd}"):
                    raise OSError(errno.EIO, "injected directory fsync")
                real_fsync(fd)

            try:
                with mock.patch.object(RENDER.os, "fsync", side_effect=fail_directory_fsync):
                    with self.assertRaisesRegex(OSError, "injected directory fsync"):
                        RENDER.write_output(root, "output.json", OUTPUT)
                output = root_path / "output.json"
                published_inode = output.stat().st_ino
                RENDER.write_output(root, "output.json", OUTPUT)
                self.assertEqual(output.stat().st_ino, published_inode)
                with self.assertRaises(FileExistsError):
                    RENDER.write_output(root, "output.json", canonical({"complete": False}))
            finally:
                root.close()
            output = root_path / "output.json"
            self.assertEqual(output.read_bytes(), OUTPUT)
            self.assertEqual(output.stat().st_mode & 0o7777, 0o600)
            self.assertEqual(self.output_temporaries(root_path), [])

    def test_existing_unsafe_targets_are_never_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            wrong_mode = root_path / "wrong-mode.json"
            wrong_mode.write_bytes(OUTPUT)
            wrong_mode.chmod(0o400)
            truncated = root_path / "truncated.json"
            truncated.write_bytes(OUTPUT[:-1])
            truncated.chmod(0o600)
            noncanonical = root_path / "noncanonical.json"
            noncanonical.write_bytes(b'{"complete": true}\n')
            noncanonical.chmod(0o600)
            wrong_owner = root_path / "wrong-owner.json"
            wrong_owner.write_bytes(OUTPUT)
            wrong_owner.chmod(0o600)
            outside = root_path / "outside.json"
            outside.write_bytes(b"outside\n")
            symlink = root_path / "symlink.json"
            symlink.symlink_to(outside)
            directory = root_path / "directory.json"
            directory.mkdir()
            root = self.output_root(root_path)
            try:
                for name in ("wrong-mode.json", "truncated.json", "noncanonical.json", "symlink.json", "directory.json"):
                    with self.subTest(name=name), self.assertRaises(FileExistsError):
                        RENDER.write_output(root, name, OUTPUT)
                with mock.patch.object(RENDER.os, "geteuid", return_value=os.geteuid() + 1):
                    with self.assertRaises(FileExistsError):
                        RENDER.write_output(root, "wrong-owner.json", OUTPUT)
            finally:
                root.close()
            self.assertEqual(wrong_mode.read_bytes(), OUTPUT)
            self.assertEqual(wrong_mode.stat().st_mode & 0o7777, 0o400)
            self.assertEqual(truncated.read_bytes(), OUTPUT[:-1])
            self.assertEqual(noncanonical.read_bytes(), b'{"complete": true}\n')
            self.assertEqual(wrong_owner.read_bytes(), OUTPUT)
            self.assertTrue(symlink.is_symlink())
            self.assertTrue(directory.is_dir())
            self.assertEqual(outside.read_bytes(), b"outside\n")
            self.assertEqual(self.output_temporaries(root_path), [])

    def test_existing_output_name_swap_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            output = root_path / "output.json"
            replacement = root_path / "replacement.json"
            output.write_bytes(OUTPUT)
            output.chmod(0o600)
            replacement.write_bytes(OUTPUT)
            replacement.chmod(0o600)
            original_inode = output.stat().st_ino
            replacement_inode = replacement.stat().st_ino
            root = self.output_root(root_path)
            real_read_fd = RENDER.DescriptorRoot._read_fd

            def read_then_swap(fd: int, size: int, maximum: int, where: str) -> bytes:
                raw = real_read_fd(fd, size, maximum, where)
                if where == "existing output":
                    os.replace(replacement, output)
                return raw

            try:
                with mock.patch.object(RENDER.DescriptorRoot, "_read_fd", side_effect=read_then_swap):
                    with self.assertRaises(FileExistsError):
                        RENDER.write_output(root, "output.json", OUTPUT)
            finally:
                root.close()
            self.assertNotEqual(original_inode, replacement_inode)
            self.assertEqual(output.stat().st_ino, replacement_inode)
            self.assertEqual(output.read_bytes(), OUTPUT)
            self.assertEqual(self.output_temporaries(root_path), [])

    def test_colliding_temporary_symlink_is_not_followed_or_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            outside = root_path / "outside"
            outside.write_bytes(b"outside\n")
            collision = root_path / f".render-inputs-{'a' * 32}.tmp"
            collision.symlink_to(outside)
            root = self.output_root(root_path)
            try:
                with mock.patch.object(RENDER.secrets, "token_hex", side_effect=["a" * 32, "b" * 32]):
                    RENDER.write_output(root, "output.json", OUTPUT)
            finally:
                root.close()
            self.assertTrue(collision.is_symlink())
            self.assertEqual(outside.read_bytes(), b"outside\n")
            self.assertEqual((root_path / "output.json").read_bytes(), OUTPUT)
            self.assertFalse((root_path / f".render-inputs-{'b' * 32}.tmp").exists())

    def test_bound_lifecycle_mutation_fails_without_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lifecycle, candidate = self.make_lifecycle(root)
            descriptor = {
                "schema_version": "buzz-ci-residue-receipt-render-input/v1",
                "candidate_sha": candidate, "lifecycle": lifecycle,
            }
            write_json(root, "descriptor.json", descriptor)
            evidence = root / "evidence/evidence-manifest.json"
            raw = bytearray(evidence.read_bytes())
            raw[10] ^= 1
            evidence.chmod(0o600)
            evidence.write_bytes(raw)
            evidence.chmod(0o400)
            process = subprocess.run(
                ["python3", str(SCRIPT), "record-residue", "--descriptor", str(root / "descriptor.json"), "--output", "rejected.json"],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            self.assertEqual(process.returncode, 64)
            self.assertIn("digest differs", process.stderr)
            self.assertFalse((root / "rejected.json").exists())

        mutations = (
            (
                "contract", lambda value: value.update(
                    schema_version="buzz-ci-clean-host-e2e-vm-contract/v2",
                ), "lifecycle contract candidate differs",
            ),
            (
                "evidence_manifest", lambda value: value.update(
                    schema_version="buzz-ci-clean-host-e2e-evidence/v2",
                ), "lifecycle evidence candidate differs",
            ),
            (
                "evidence_manifest", lambda value: value.update(harness_sha256="a" * 64),
                "lifecycle frozen asset or timing binding differs",
            ),
            (
                "result", lambda value: value.update(timing_sha256="b" * 64),
                "lifecycle frozen asset or timing binding differs",
            ),
        )
        for member, mutate, message in mutations:
            with self.subTest(member=member, message=message), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                lifecycle, candidate = self.make_lifecycle(root)
                path = root / str(lifecycle[member]["path"])
                value = json.loads(path.read_bytes())
                mutate(value)
                path.chmod(0o600)
                lifecycle[member] = write_json(root, str(lifecycle[member]["path"]), value, 0o400)
                descriptor = {
                    "schema_version": "buzz-ci-residue-receipt-render-input/v1",
                    "candidate_sha": candidate, "lifecycle": lifecycle,
                }
                process = self.run_cli(root, "record-residue", descriptor, "rejected.json")
                self.assertEqual(process.returncode, 64)
                self.assertIn(message, process.stderr)
                self.assertFalse((root / "rejected.json").exists())

        for asset_name in RENDER.HARNESS_ASSET_NAMES:
            with self.subTest(asset=asset_name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                lifecycle, candidate = self.make_lifecycle(root)
                evidence_ref = lifecycle["evidence_manifest"]
                assert isinstance(evidence_ref, dict)
                evidence_value = json.loads((root / str(evidence_ref["path"])).read_bytes())
                current = evidence_value["harness_asset_sha256"][asset_name]
                evidence_value["harness_asset_sha256"][asset_name] = (
                    "a" * 64 if current != "a" * 64 else "b" * 64
                )
                self.rewrite_lifecycle_member(
                    root, lifecycle, "evidence_manifest", evidence_value,
                )
                descriptor = {
                    "schema_version": "buzz-ci-residue-receipt-render-input/v1",
                    "candidate_sha": candidate, "lifecycle": lifecycle,
                }
                process = self.run_cli(root, "record-residue", descriptor, "rejected.json")
                self.assertEqual(process.returncode, 64, process.stderr)
                self.assertIn("lifecycle frozen asset or timing binding differs", process.stderr)
                self.assertFalse((root / "rejected.json").exists())

        verifier_mutations = (
            ({"status": "pass"}, "installed verifier output shape differs"),
            ({"outcome": "pass", "status": "pass"}, "installed verifier lifecycle output did not pass"),
            ({"outcome": "pass"}, "installed verifier output shape differs"),
            (
                {"outcome": "pass", "status": "verified", "detail": "tampered"},
                "installed verifier output shape differs",
            ),
            ({"outcome": "failure", "status": "verified"}, "installed verifier lifecycle output did not pass"),
        )
        for verifier_value, message in verifier_mutations:
            with self.subTest(verifier=verifier_value), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                lifecycle, candidate = self.make_lifecycle(root)
                self.rewrite_lifecycle_member(root, lifecycle, "verifier", verifier_value)
                descriptor = {
                    "schema_version": "buzz-ci-residue-receipt-render-input/v1",
                    "candidate_sha": candidate, "lifecycle": lifecycle,
                }
                process = self.run_cli(root, "record-residue", descriptor, "rejected.json")
                self.assertEqual(process.returncode, 64, process.stderr)
                self.assertIn(message, process.stderr)
                self.assertFalse((root / "rejected.json").exists())

        def mutate_once(stage: str, mutation: object) -> object:
            fired = False

            def checkpoint(observed: str, candidate_root: Path) -> None:
                nonlocal fired
                if observed == stage and not fired:
                    fired = True
                    mutation(candidate_root)

            return checkpoint

        def mutate_on_occurrence(
            stage: str, occurrence: int, mutation: object,
        ) -> object:
            observed_count = 0

            def checkpoint(observed: str, candidate_root: Path) -> None:
                nonlocal observed_count
                if observed == stage:
                    observed_count += 1
                    if observed_count == occurrence:
                        mutation(candidate_root)

            return checkpoint

        def drift_head(candidate_root: Path) -> None:
            subprocess.run(
                ["/usr/bin/git", "-C", str(candidate_root), "commit", "-q", "--allow-empty", "-m", "drift"],
                check=True,
            )

        def same_tree_commit(candidate_root: Path, candidate: str) -> str:
            tree = subprocess.check_output(
                ["/usr/bin/git", "-C", str(candidate_root), "rev-parse", "HEAD^{tree}"],
                text=True,
            ).strip()
            return subprocess.run(
                [
                    "/usr/bin/git", "-C", str(candidate_root), "commit-tree", tree,
                    "-p", candidate,
                ],
                input="same-tree locked-state drift\n", text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            ).stdout.strip()

        def raw_head_mutation(
            candidate_root: Path, candidate: str, *, ref: bool,
        ) -> object:
            drift = same_tree_commit(candidate_root, candidate)
            if ref:
                reference = subprocess.check_output(
                    ["/usr/bin/git", "-C", str(candidate_root), "symbolic-ref", "HEAD"],
                    text=True,
                ).strip()
                target = candidate_root / ".git" / reference
            else:
                target = candidate_root / ".git/HEAD"

            def mutate(_candidate_root: Path) -> None:
                target.write_text(drift + "\n")

            return mutate

        def make_existing_retry(
            root: Path,
        ) -> tuple[dict[str, object], str, Path, tuple[int, int, bytes]]:
            lifecycle, candidate = self.make_lifecycle(root)
            descriptor = {
                "schema_version": "buzz-ci-residue-receipt-render-input/v1",
                "candidate_sha": candidate, "lifecycle": lifecycle,
            }
            first = self.run_cli(root, "record-residue", descriptor, "existing.json")
            self.assertEqual(first.returncode, 0, first.stderr)
            output = root / "existing.json"
            identity = (output.stat().st_ino, output.stat().st_mode & 0o7777, output.read_bytes())
            return descriptor, candidate, output, identity

        def assert_retry_cleanup(root: Path) -> None:
            self.assertEqual(self.output_temporaries(root), [])
            self.assertEqual(list((root / "candidate/.git").rglob("*.lock")), [])

        with self.subTest(existing_retry="exact-match"), tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            descriptor, _candidate, output, identity = make_existing_retry(root)
            retry = self.run_cli(root, "record-residue", descriptor, "existing.json")
            self.assertEqual(retry.returncode, 0, retry.stderr)
            self.assertEqual(
                (output.stat().st_ino, output.stat().st_mode & 0o7777, output.read_bytes()),
                identity,
            )
            assert_retry_cleanup(root)

        with self.subTest(existing_retry="identical-inode-replacement"), tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            descriptor, _candidate, output, identity = make_existing_retry(root)
            original_fd = os.open(output, os.O_RDONLY | os.O_CLOEXEC)
            replacement = root / "replacement.json"
            replacement.write_bytes(identity[2])
            replacement.chmod(0o600)
            replacement_inode = replacement.stat().st_ino

            def replace_existing(_candidate_root: Path) -> None:
                os.replace(replacement, output)

            try:
                result, stderr = self.run_main_with_checkpoint(
                    root, "record-residue", descriptor, "existing.json",
                    mutate_once("after-existing-output-check", replace_existing),
                )
                self.assertEqual(result, 64, stderr)
                self.assertEqual(output.stat().st_ino, replacement_inode)
                self.assertNotEqual(output.stat().st_ino, identity[0])
                self.assertEqual(output.stat().st_mode & 0o7777, 0o600)
                self.assertEqual(output.read_bytes(), identity[2])
                original = os.fstat(original_fd)
                self.assertEqual(original.st_ino, identity[0])
                self.assertEqual(original.st_mode & 0o7777, 0o600)
                os.lseek(original_fd, 0, os.SEEK_SET)
                self.assertEqual(os.read(original_fd, len(identity[2]) + 1), identity[2])
            finally:
                os.close(original_fd)
            assert_retry_cleanup(root)

        with self.subTest(existing_retry="post-acceptance-replacement"), tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            descriptor, _candidate, output, identity = make_existing_retry(root)
            replacement = root / "replacement.json"
            replacement.write_bytes(identity[2])
            replacement.chmod(0o600)
            replacement_inode = replacement.stat().st_ino

            def replace_after_acceptance(_candidate_root: Path) -> None:
                os.replace(replacement, output)

            result, stderr = self.run_main_with_checkpoint(
                root, "record-residue", descriptor, "existing.json",
                mutate_once("after-existing-output-acceptance", replace_after_acceptance),
            )
            self.assertEqual(result, 0, stderr)
            self.assertEqual(output.stat().st_ino, replacement_inode)
            self.assertNotEqual(output.stat().st_ino, identity[0])
            self.assertEqual(output.stat().st_mode & 0o7777, 0o600)
            self.assertEqual(output.read_bytes(), identity[2])
            assert_retry_cleanup(root)

        with self.subTest(existing_retry="reviewer-head-commit"), tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            descriptor, candidate, output, identity = make_existing_retry(root)
            real_accept = RENDER.accept_existing_output
            attempts: list[subprocess.CompletedProcess[str]] = []

            def commit_before_existing_check(parent: int, name: str, payload: bytes) -> bool:
                if not attempts:
                    attempts.append(subprocess.run(
                        [
                            "/usr/bin/git", "-C", str(root / "candidate"), "commit",
                            "-q", "--allow-empty", "-m", "blocked retry drift",
                        ],
                        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        check=False,
                    ))
                    if attempts[0].returncode != 0:
                        raise subprocess.CalledProcessError(
                            attempts[0].returncode, attempts[0].args,
                            output=attempts[0].stdout, stderr=attempts[0].stderr,
                        )
                return real_accept(parent, name, payload)

            with mock.patch.object(
                RENDER, "accept_existing_output", side_effect=commit_before_existing_check,
            ):
                result, stderr = self.run_main_with_checkpoint(
                    root, "record-residue", descriptor, "existing.json",
                    lambda _stage, _candidate_root: None,
                )
            self.assertEqual(result, 64, stderr)
            self.assertIn("candidate acceptance subprocess failed", stderr)
            self.assertEqual(len(attempts), 1)
            self.assertNotEqual(attempts[0].returncode, 0)
            self.assertIn("lock", attempts[0].stderr.lower())
            self.assertEqual(
                subprocess.check_output(
                    ["/usr/bin/git", "-C", str(root / "candidate"), "rev-parse", "HEAD"],
                    text=True,
                ).strip(),
                candidate,
            )
            self.assertEqual(
                (output.stat().st_ino, output.stat().st_mode & 0o7777, output.read_bytes()),
                identity,
            )
            assert_retry_cleanup(root)

        with self.subTest(existing_retry="raw-head-drift"), tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            descriptor, candidate, output, identity = make_existing_retry(root)
            candidate_root = root / "candidate"
            tree = subprocess.check_output(
                ["/usr/bin/git", "-C", str(candidate_root), "rev-parse", "HEAD^{tree}"],
                text=True,
            ).strip()
            drift = subprocess.run(
                [
                    "/usr/bin/git", "-C", str(candidate_root), "commit-tree", tree,
                    "-p", candidate,
                ],
                input="raw retry drift\n", text=True, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, check=True,
            ).stdout.strip()
            real_accept = RENDER.accept_existing_output
            drifted = False

            def drift_head_before_existing_check(parent: int, name: str, payload: bytes) -> bool:
                nonlocal drifted
                if not drifted:
                    drifted = True
                    (candidate_root / ".git/HEAD").write_text(drift + "\n")
                return real_accept(parent, name, payload)

            with mock.patch.object(
                RENDER, "accept_existing_output", side_effect=drift_head_before_existing_check,
            ):
                result, stderr = self.run_main_with_checkpoint(
                    root, "record-residue", descriptor, "existing.json",
                    lambda _stage, _candidate_root: None,
                )
            self.assertEqual(result, 64, stderr)
            self.assertTrue(drifted)
            self.assertIn("candidate Git HEAD, index, or worktree changed", stderr)
            self.assertEqual(
                (output.stat().st_ino, output.stat().st_mode & 0o7777, output.read_bytes()),
                identity,
            )
            assert_retry_cleanup(root)

        with self.subTest(existing_retry="raw-index-drift"), tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            descriptor, _candidate, output, identity = make_existing_retry(root)
            index = root / "candidate/.git/index"
            real_accept = RENDER.accept_existing_output
            drifted = False

            def drift_index_before_existing_check(parent: int, name: str, payload: bytes) -> bool:
                nonlocal drifted
                if not drifted:
                    drifted = True
                    raw = bytearray(index.read_bytes())
                    raw[-1] ^= 1
                    index.write_bytes(raw)
                return real_accept(parent, name, payload)

            with mock.patch.object(
                RENDER, "accept_existing_output", side_effect=drift_index_before_existing_check,
            ):
                result, stderr = self.run_main_with_checkpoint(
                    root, "record-residue", descriptor, "existing.json",
                    lambda _stage, _candidate_root: None,
                )
            self.assertEqual(result, 64, stderr)
            self.assertTrue(drifted)
            self.assertIn("candidate", stderr)
            self.assertEqual(
                (output.stat().st_ino, output.stat().st_mode & 0o7777, output.read_bytes()),
                identity,
            )
            assert_retry_cleanup(root)

        existing_status_mutations = {
            "untracked-status": lambda candidate_root: (
                candidate_root / "untracked-retry-drift"
            ).write_text("drift\n"),
            **{
                f"asset:{asset_name}": (
                    lambda candidate_root, path=relative: (
                        candidate_root / path
                    ).write_bytes((candidate_root / path).read_bytes() + b"\n# retry drift\n")
                )
                for asset_name, (relative, _git_mode, _maximum)
                in RENDER.HARNESS_ASSET_SOURCES.items()
            },
        }
        for mutation_name, mutation in existing_status_mutations.items():
            with self.subTest(existing_retry=mutation_name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                descriptor, _candidate, output, identity = make_existing_retry(root)
                result, stderr = self.run_main_with_checkpoint(
                    root, "record-residue", descriptor, "existing.json",
                    mutate_once("after-existing-output-check", mutation),
                )
                self.assertEqual(result, 64, stderr)
                self.assertIn("candidate Git HEAD, index, or worktree changed", stderr)
                self.assertEqual(
                    (output.stat().st_ino, output.stat().st_mode & 0o7777, output.read_bytes()),
                    identity,
                )
                assert_retry_cleanup(root)

        for mismatch_name, mutate_output, expected_mode in (
            ("byte-mismatch", lambda output: output.write_bytes(b'{"different":true}\n'), 0o600),
            ("mode-mismatch", lambda output: output.chmod(0o400), 0o400),
        ):
            with self.subTest(existing_retry=mismatch_name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                descriptor, _candidate, output, _identity = make_existing_retry(root)
                mutate_output(output)
                retained = (output.stat().st_ino, output.read_bytes())
                retry = self.run_cli(root, "record-residue", descriptor, "existing.json")
                self.assertEqual(retry.returncode, 64, retry.stderr)
                self.assertEqual((output.stat().st_ino, output.read_bytes()), retained)
                self.assertEqual(output.stat().st_mode & 0o7777, expected_mode)
                assert_retry_cleanup(root)

        locked_state_gaps = (
            "locked-state-after-head",
            "locked-state-after-index-info",
            "locked-state-after-index-digest",
            "locked-state-after-status",
        )
        for gap in locked_state_gaps:
            for mutation_name, mutate_ref in (("HEAD", False), ("ref", True)):
                with self.subTest(
                    fresh_locked_state_gap=gap, raw_mutation=mutation_name,
                ), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    lifecycle, candidate = self.make_lifecycle(root)
                    candidate_root = root / "candidate"
                    descriptor = {
                        "schema_version": "buzz-ci-residue-receipt-render-input/v1",
                        "candidate_sha": candidate, "lifecycle": lifecycle,
                    }
                    result, stderr = self.run_main_with_checkpoint(
                        root, "record-residue", descriptor, "retained.json",
                        mutate_on_occurrence(
                            gap, 2,
                            raw_head_mutation(
                                candidate_root, candidate, ref=mutate_ref,
                            ),
                        ),
                    )
                    self.assertEqual(result, 64, stderr)
                    self.assertIn(
                        "candidate changed before acceptance; unreadable output retained",
                        stderr,
                    )
                    self.assertEqual(
                        (root / "retained.json").stat().st_mode & 0o7777,
                        0o000,
                    )
                    with self.assertRaises(PermissionError):
                        (root / "retained.json").read_bytes()
                    assert_retry_cleanup(root)

                with self.subTest(
                    retry_locked_state_gap=gap, raw_mutation=mutation_name,
                ), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    descriptor, candidate, output, identity = make_existing_retry(root)
                    candidate_root = root / "candidate"
                    result, stderr = self.run_main_with_checkpoint(
                        root, "record-residue", descriptor, "existing.json",
                        mutate_on_occurrence(
                            gap, 2,
                            raw_head_mutation(
                                candidate_root, candidate, ref=mutate_ref,
                            ),
                        ),
                    )
                    self.assertEqual(result, 64, stderr)
                    self.assertIn(
                        "locked candidate Git HEAD changed while inspected",
                        stderr,
                    )
                    self.assertEqual(
                        (
                            output.stat().st_ino,
                            output.stat().st_mode & 0o7777,
                            output.read_bytes(),
                        ),
                        identity,
                    )
                    assert_retry_cleanup(root)

        for stage in (
            "after-initial-head-check", "after-blob-read:harness.py",
            "immediately-pre-publication",
        ):
            with self.subTest(head_drift=stage), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                lifecycle, candidate = self.make_lifecycle(root)
                descriptor = {
                    "schema_version": "buzz-ci-residue-receipt-render-input/v1",
                    "candidate_sha": candidate, "lifecycle": lifecycle,
                }
                result, stderr = self.run_main_with_checkpoint(
                    root, "record-residue", descriptor, "rejected.json",
                    mutate_once(stage, drift_head),
                )
                self.assertEqual(result, 64, stderr)
                self.assertIn("candidate Git HEAD, index, or worktree changed", stderr)
                self.assertFalse((root / "rejected.json").exists())
                self.assertEqual(self.output_temporaries(root), [])

        with self.subTest(head_drift="after-publication"), tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lifecycle, candidate = self.make_lifecycle(root)
            descriptor = {
                "schema_version": "buzz-ci-residue-receipt-render-input/v1",
                "candidate_sha": candidate, "lifecycle": lifecycle,
            }
            result, stderr = self.run_main_with_checkpoint(
                root, "record-residue", descriptor, "accepted.json",
                mutate_once("after-publication", drift_head),
            )
            self.assertEqual(result, 0, stderr)
            self.assertTrue((root / "accepted.json").is_file())

        with self.subTest(head_drift="reviewer-final-verify-wrapper"), tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lifecycle, candidate = self.make_lifecycle(root)
            descriptor = {
                "schema_version": "buzz-ci-residue-receipt-render-input/v1",
                "candidate_sha": candidate, "lifecycle": lifecycle,
            }
            real_verify = RENDER.verify_candidate_snapshot
            drifted = False

            def verify_then_drift(
                snapshot: object,
                publication: tuple[int, int, str, str, bytes] | None = None,
            ) -> None:
                nonlocal drifted
                real_verify(snapshot, publication)
                if publication is not None and not drifted:
                    drifted = True
                    drift_head(root / "candidate")

            with mock.patch.object(
                RENDER, "verify_candidate_snapshot", side_effect=verify_then_drift,
            ):
                result, stderr = self.run_main_with_checkpoint(
                    root, "record-residue", descriptor, "accepted.json",
                    lambda _stage, _candidate_root: None,
                )
            self.assertEqual(result, 0, stderr)
            self.assertTrue(drifted)
            self.assertEqual((root / "accepted.json").stat().st_mode & 0o7777, 0o600)
            self.assertEqual(self.output_temporaries(root), [])
            observed_head = subprocess.check_output(
                ["/usr/bin/git", "-C", str(root / "candidate"), "rev-parse", "HEAD"],
                text=True,
            ).strip()
            self.assertNotEqual(observed_head, candidate)

        for mutation_name, command in (
            (
                "head-lock",
                lambda candidate_root: [
                    "/usr/bin/git", "-C", str(candidate_root), "commit", "-q",
                    "--allow-empty", "-m", "blocked drift",
                ],
            ),
            (
                "index-lock",
                lambda candidate_root: [
                    "/usr/bin/git", "-C", str(candidate_root), "add", ".gitignore",
                ],
            ),
        ):
            with self.subTest(acceptance_lock=mutation_name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                lifecycle, candidate = self.make_lifecycle(root)
                descriptor = {
                    "schema_version": "buzz-ci-residue-receipt-render-input/v1",
                    "candidate_sha": candidate, "lifecycle": lifecycle,
                }
                real_link = os.link
                attempted: list[subprocess.CompletedProcess[str]] = []

                def attempt_git_mutation_then_link(*args: object, **kwargs: object) -> None:
                    candidate_root = root / "candidate"
                    attempted.append(subprocess.run(
                        command(candidate_root), text=True, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, check=False,
                    ))
                    real_link(*args, **kwargs)

                with mock.patch.object(
                    RENDER.os, "link", side_effect=attempt_git_mutation_then_link,
                ):
                    result, stderr = self.run_main_with_checkpoint(
                        root, "record-residue", descriptor, "accepted.json",
                        lambda _stage, _candidate_root: None,
                    )
                self.assertEqual(result, 0, stderr)
                self.assertEqual(len(attempted), 1)
                self.assertEqual(attempted[0].returncode, 128)
                self.assertIn("lock", attempted[0].stderr.lower())
                self.assertEqual((root / "accepted.json").stat().st_mode & 0o7777, 0o600)
                self.assertEqual(self.output_temporaries(root), [])

        with self.subTest(worktree_drift="inside-pending-link"), tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lifecycle, candidate = self.make_lifecycle(root)
            descriptor = {
                "schema_version": "buzz-ci-residue-receipt-render-input/v1",
                "candidate_sha": candidate, "lifecycle": lifecycle,
            }
            real_link = os.link

            def mutate_asset_then_link(*args: object, **kwargs: object) -> None:
                asset = (
                    root / "candidate"
                    / RENDER.HARNESS_ASSET_SOURCES["guest_entry.py"][0]
                )
                asset.write_bytes(asset.read_bytes() + b"\n# acceptance gap drift\n")
                real_link(*args, **kwargs)

            with mock.patch.object(RENDER.os, "link", side_effect=mutate_asset_then_link):
                result, stderr = self.run_main_with_checkpoint(
                    root, "record-residue", descriptor, "retained.json",
                    lambda _stage, _candidate_root: None,
                )
            self.assertEqual(result, 64, stderr)
            self.assertIn(
                "candidate changed before acceptance; unreadable output retained",
                stderr,
            )
            self.assertEqual((root / "retained.json").stat().st_mode & 0o7777, 0o000)
            with self.assertRaises(PermissionError):
                (root / "retained.json").read_bytes()
            self.assertEqual(self.output_temporaries(root), [])

        with self.subTest(worktree_drift="after-acceptance-mode"), tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lifecycle, candidate = self.make_lifecycle(root)
            descriptor = {
                "schema_version": "buzz-ci-residue-receipt-render-input/v1",
                "candidate_sha": candidate, "lifecycle": lifecycle,
            }

            def mutate_asset_after_mode(candidate_root: Path) -> None:
                asset = (
                    candidate_root
                    / RENDER.HARNESS_ASSET_SOURCES["guest_entry.py"][0]
                )
                asset.write_bytes(asset.read_bytes() + b"\n# final acceptance drift\n")

            result, stderr = self.run_main_with_checkpoint(
                root, "record-residue", descriptor, "accepted.json",
                mutate_once("after-acceptance-mode", mutate_asset_after_mode),
            )
            self.assertEqual(result, 0, stderr)
            self.assertEqual((root / "accepted.json").stat().st_mode & 0o7777, 0o600)
            self.assertEqual(self.output_temporaries(root), [])

        with self.subTest(replacement="immediately-pre-publication"), tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lifecycle, candidate = self.make_lifecycle(root)
            descriptor = {
                "schema_version": "buzz-ci-residue-receipt-render-input/v1",
                "candidate_sha": candidate, "lifecycle": lifecycle,
            }
            unrelated = b"unrelated prepublication content\n"

            def occupy_output(_candidate_root: Path) -> None:
                target = root / "retained.json"
                target.write_bytes(unrelated)
                target.chmod(0o600)

            result, stderr = self.run_main_with_checkpoint(
                root, "record-residue", descriptor, "retained.json",
                mutate_once("immediately-pre-publication", occupy_output),
            )
            self.assertEqual(result, 64, stderr)
            self.assertEqual((root / "retained.json").read_bytes(), unrelated)

        with self.subTest(replacement="before-former-metadata-check"), tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lifecycle, candidate = self.make_lifecycle(root)
            descriptor = {
                "schema_version": "buzz-ci-residue-receipt-render-input/v1",
                "candidate_sha": candidate, "lifecycle": lifecycle,
            }
            unrelated = b"unrelated postpublication content\n"

            def replace_after_publication(_candidate_root: Path) -> None:
                replacement = root / "replacement.json"
                replacement.write_bytes(unrelated)
                replacement.chmod(0o600)
                os.replace(replacement, root / "retained.json")

            result, stderr = self.run_main_with_checkpoint(
                root, "record-residue", descriptor, "retained.json",
                mutate_once("after-publication", replace_after_publication),
            )
            self.assertEqual(result, 64, stderr)
            self.assertIn(
                "published output namespace changed; no rollback performed", stderr,
            )
            self.assertEqual((root / "retained.json").read_bytes(), unrelated)

        with self.subTest(replacement="between-former-check-delete"), tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lifecycle, candidate = self.make_lifecycle(root)
            descriptor = {
                "schema_version": "buzz-ci-residue-receipt-render-input/v1",
                "candidate_sha": candidate, "lifecycle": lifecycle,
            }
            unrelated = b"unrelated during temporary cleanup\n"
            real_unlink = os.unlink
            replaced = False

            def replace_before_temporary_unlink(path: object, *, dir_fd: int) -> None:
                nonlocal replaced
                if (
                    isinstance(path, str)
                    and path.startswith(".render-inputs-")
                    and (root / "retained.json").exists()
                    and not replaced
                ):
                    replaced = True
                    replacement = root / "replacement.json"
                    replacement.write_bytes(unrelated)
                    replacement.chmod(0o600)
                    os.replace(replacement, root / "retained.json")
                real_unlink(path, dir_fd=dir_fd)

            with mock.patch.object(
                RENDER.os, "unlink", side_effect=replace_before_temporary_unlink,
            ):
                result, stderr = self.run_main_with_checkpoint(
                    root, "record-residue", descriptor, "retained.json",
                    lambda _stage, _candidate_root: None,
                )
            self.assertEqual(result, 0, stderr)
            self.assertTrue(replaced)
            self.assertEqual((root / "retained.json").read_bytes(), unrelated)

        for asset_name, (relative, _git_mode, _maximum) in RENDER.HARNESS_ASSET_SOURCES.items():
            def mutate_asset(candidate_root: Path, path: str = relative) -> None:
                asset = candidate_root / path
                asset.write_bytes(asset.read_bytes() + b"\n# injected drift\n")

            with self.subTest(asset_worktree_drift=asset_name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                lifecycle, candidate = self.make_lifecycle(root)
                descriptor = {
                    "schema_version": "buzz-ci-residue-receipt-render-input/v1",
                    "candidate_sha": candidate, "lifecycle": lifecycle,
                }
                result, stderr = self.run_main_with_checkpoint(
                    root, "record-residue", descriptor, "rejected.json",
                    mutate_once(f"after-blob-read:{asset_name}", mutate_asset),
                )
                self.assertEqual(result, 64, stderr)
                self.assertIn("candidate Git HEAD, index, or worktree changed", stderr)
                self.assertFalse((root / "rejected.json").exists())

        with self.subTest(index_drift="before-write"), tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lifecycle, candidate = self.make_lifecycle(root)
            descriptor = {
                "schema_version": "buzz-ci-residue-receipt-render-input/v1",
                "candidate_sha": candidate, "lifecycle": lifecycle,
            }

            def drift_index(candidate_root: Path) -> None:
                ignore = candidate_root / ".gitignore"
                ignore.write_text(ignore.read_text() + "another-ignored-path/\n")
                subprocess.run(
                    ["/usr/bin/git", "-C", str(candidate_root), "add", ".gitignore"],
                    check=True,
                )

            result, stderr = self.run_main_with_checkpoint(
                root, "record-residue", descriptor, "rejected.json",
                mutate_once("before-write", drift_index),
            )
            self.assertEqual(result, 64, stderr)
            self.assertIn("candidate Git HEAD, index, or worktree changed", stderr)
            self.assertFalse((root / "rejected.json").exists())

        with self.subTest(ignored_artifact="allowed"), tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lifecycle, candidate = self.make_lifecycle(root)
            descriptor = {
                "schema_version": "buzz-ci-residue-receipt-render-input/v1",
                "candidate_sha": candidate, "lifecycle": lifecycle,
            }

            def add_ignored_artifact(candidate_root: Path) -> None:
                artifact = candidate_root / ".ignored-build/cache.bin"
                artifact.parent.mkdir()
                artifact.write_bytes(b"ignored build output\n")

            result, stderr = self.run_main_with_checkpoint(
                root, "record-residue", descriptor, "accepted.json",
                mutate_once("after-blob-read:harness.py", add_ignored_artifact),
            )
            self.assertEqual(result, 0, stderr)
            self.assertTrue((root / "accepted.json").is_file())

    def test_symlinked_reference_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lifecycle, candidate = self.make_lifecycle(root)
            target = root / "evidence/verifier.json"
            link = root / "verifier-link.json"
            link.symlink_to(target)
            lifecycle["verifier"] = {
                **lifecycle["verifier"], "path": "verifier-link.json",
            }
            descriptor = {
                "schema_version": "buzz-ci-residue-receipt-render-input/v1",
                "candidate_sha": candidate, "lifecycle": lifecycle,
            }
            process = self.run_cli(root, "record-residue", descriptor, "rejected.json")
            self.assertEqual(process.returncode, 64)
            self.assertFalse((root / "rejected.json").exists())

    def test_template_cycle_and_unknown_directive_are_rejected(self) -> None:
        cycle = {
            "schema_version": "buzz-ci-checked-render-template/v1", "kind": "activation-draft",
            "definitions": {"a": {"$ref": "#/definitions/b"}, "b": {"$ref": "#/definitions/a"}},
            "document": {"$ref": "#/definitions/a"},
        }
        with self.assertRaisesRegex(RENDER.RenderError, "cycle"):
            RENDER.resolve_template(cycle, "activation-draft", {"candidate_sha": CANDIDATE})
        cycle["document"] = {"$env": "SECRET"}
        with self.assertRaisesRegex(RENDER.RenderError, "unknown"):
            RENDER.resolve_template(cycle, "activation-draft", {"candidate_sha": CANDIDATE})

    def test_package_tree_rejects_extra_and_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            package = root_path / "runner"
            (package / "assets").mkdir(parents=True)
            package.chmod(0o700)
            (package / "assets").chmod(0o700)
            payload = b"payload\n"
            source = package / "assets/payload"
            source.write_bytes(payload)
            source.chmod(0o400)
            manifest = minimal_manifest("runner", "assets/payload", payload)
            manifest_ref = write_json(root_path, "runner/package-manifest.json", manifest)
            descriptor = {
                "path": "runner", "manifest_sha256": manifest_ref["sha256"],
                "manifest_bytes": manifest_ref["bytes"], "manifest_mode": manifest_ref["mode"],
            }
            descriptor_path = root_path / "descriptor.json"
            descriptor_path.write_bytes(canonical({"unused": True}))
            descriptor_path.chmod(0o600)
            root = RENDER.DescriptorRoot(descriptor_path)
            try:
                with mock.patch.object(RENDER, "validate_manifest"):
                    _manifest, _manifest_sha, digest = RENDER.validate_package_tree(root, "runner", descriptor, CANDIDATE)
                self.assertRegex(digest, r"^[0-9a-f]{64}$")
                extra = package / "extra"
                extra.write_bytes(b"extra")
                extra.chmod(0o400)
                with mock.patch.object(RENDER, "validate_manifest"), self.assertRaisesRegex(RENDER.RenderError, "extra"):
                    RENDER.validate_package_tree(root, "runner", descriptor, CANDIDATE)
                extra.unlink()
                source.chmod(0o600)
                source.write_bytes(b"PAYLOAD\n")
                source.chmod(0o400)
                with mock.patch.object(RENDER, "validate_manifest"), self.assertRaisesRegex(RENDER.RenderError, "metadata differs"):
                    RENDER.validate_package_tree(root, "runner", descriptor, CANDIDATE)
            finally:
                root.close()

    def test_public_binding_rejects_secret_fields(self) -> None:
        binding = public_binding()
        RENDER.validate_public_binding(binding)
        binding["secret_key"] = "8" * 64
        with self.assertRaisesRegex(RENDER.RenderError, "shape differs|private"):
            RENDER.validate_public_binding(binding)

    def test_public_binding_parser_requires_prepare_order_and_exact_encoding(self) -> None:
        binding = public_binding()
        self.assertEqual(RENDER.parse_public_binding_json(public_binding_bytes(binding)), binding)
        reordered = canonical(binding)
        with self.assertRaisesRegex(RENDER.RenderError, "key order differs"):
            RENDER.parse_public_binding_json(reordered)
        pretty = json.dumps(binding, indent=2).encode() + b"\n"
        with self.assertRaisesRegex(RENDER.RenderError, "canonical schema-order"):
            RENDER.parse_public_binding_json(pretty)
        duplicate = public_binding_bytes(binding).replace(
            b'{"schema_version":', b'{"schema_version":"duplicate","schema_version":', 1,
        )
        with self.assertRaisesRegex(RENDER.RenderError, "duplicate JSON key"):
            RENDER.parse_public_binding_json(duplicate)
        extra = public_binding()
        extra["unexpected"] = True
        with self.assertRaisesRegex(RENDER.RenderError, "shape differs"):
            RENDER.parse_public_binding_json(public_binding_bytes(extra))
        with self.assertRaisesRegex(RENDER.RenderError, "valid JSON"):
            RENDER.parse_public_binding_json(b'{"schema_version":\n')

    def test_keyholder_manifest_must_bind_the_exact_external_public_binding(self) -> None:
        raw = public_binding_bytes(public_binding())
        valid = {"keyholder": {"public_binding_sha256": hashlib.sha256(raw).hexdigest()}}
        RENDER.bind_keyholder_manifest_to_public_binding(valid, raw)
        with self.assertRaisesRegex(RENDER.RenderError, "legacy keyholder package"):
            RENDER.bind_keyholder_manifest_to_public_binding(
                {"keyholder": {"public_binding_sha256": None}}, raw,
            )
        with self.assertRaisesRegex(RENDER.RenderError, "public binding digest differs"):
            RENDER.bind_keyholder_manifest_to_public_binding(
                {"keyholder": {"public_binding_sha256": "a" * 64}}, raw,
            )

    def test_execd_preactivation_input_is_candidate_bound_and_canonical(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            value = {
                "schema": "buzz-ci-execd-preactivation-input-v1",
                "source_commit": CANDIDATE,
                "binary_sha256": "8" * 64,
                "provenance_sha256": "9" * 64,
            }
            reference = write_json(root_path, "execd-preactivation.json", value)
            root = self.output_root(root_path)
            try:
                loaded, digest = RENDER.load_execd_preactivation(root, reference, CANDIDATE)
                self.assertEqual(loaded, value)
                self.assertEqual(digest, reference["sha256"])
                with self.assertRaisesRegex(RENDER.RenderError, "candidate differs"):
                    RENDER.load_execd_preactivation(root, reference, "d" * 40)
            finally:
                root.close()

    def test_sealed_freeze_requires_cross_bound_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            lifecycle, candidate = self.make_lifecycle(root_path)
            public_ref = write_public_binding(root_path, public_binding())
            refs: dict[str, object] = {}
            manifests: dict[str, object] = {}
            activation_digest = "a" * 64
            for name in RENDER.PACKAGE_NAMES:
                payload = name.encode()
                manifest = minimal_manifest(name, f"assets/{name}", payload, candidate=candidate)
                if name == "keyholder":
                    manifest["public_binding_sha256"] = public_ref["sha256"]
                if name == "activation":
                    unsigned = dict(manifest)
                    unsigned.pop("package_digest")
                    unsigned["schema"] = "buzz-ci-capacity-one-activation-draft-v1"
                    activation_digest = hashlib.sha256(canonical(unsigned)).hexdigest()
                    manifest = {
                        **unsigned, "schema": "buzz-ci-capacity-one-activation-package-v1",
                        "activation_id": f"buzz-ci-capacity-one-{candidate[:12]}-{activation_digest[:12]}",
                        "package_digest": activation_digest,
                    }
                manifest_name = "activation-manifest.json" if name == "activation" else "package-manifest.json"
                refs[name] = write_json(root_path, f"{name}/{manifest_name}", manifest, 0o400)
                manifests[name] = manifest
            execd = json.loads((root_path / "execd/package-manifest.json").read_bytes())
            unsigned_execd = dict(execd)
            unsigned_execd.pop("package_digest")
            unsigned_execd["activation_binding"] = {
                "source_commit": candidate, "package_digest": activation_digest,
                "activation_id": f"buzz-ci-capacity-one-{candidate[:12]}-{activation_digest[:12]}",
            }
            execd = {**unsigned_execd, "package_digest": hashlib.sha256(canonical(unsigned_execd)).hexdigest()}
            (root_path / "execd/package-manifest.json").chmod(0o600)
            refs["execd"] = write_json(root_path, "execd/package-manifest.json", execd, 0o400)
            manifests["execd"] = execd
            descriptor = {
                "schema_version": "buzz-ci-sealed-freeze-receipt-render-input/v1", "candidate_sha": candidate,
                "lifecycle": lifecycle, "public_binding": public_ref, "package_manifests": refs,
            }
            descriptor_path = root_path / "descriptor.json"
            descriptor_path.write_bytes(canonical(descriptor))
            descriptor_path.chmod(0o600)
            root = RENDER.DescriptorRoot(descriptor_path)
            validator = mock.Mock()
            validator.validate_manifest.return_value = None
            trees = {name: digit * 64 for name, digit in zip(RENDER.PACKAGE_NAMES, "89abc", strict=True)}
            def fake_tree(_root: object, name: str, _descriptor: object, _candidate: str) -> tuple[object, str, str]:
                return manifests[name], refs[name]["sha256"], trees[name]
            try:
                with (
                    mock.patch.object(RENDER, "activation_package_module", return_value=validator),
                    mock.patch.object(RENDER, "validate_manifest"),
                    mock.patch.object(RENDER, "validate_package_tree", side_effect=fake_tree),
                ):
                    output = RENDER.record_sealed_freeze(root, descriptor)
                self.assertEqual(output["claims"], {"protected_ci": False, "tier2": False})
                self.assertEqual(set(output["package_manifest_sha256"]), set(RENDER.PACKAGE_NAMES))
                guest = (
                    root_path / "candidate"
                    / RENDER.HARNESS_ASSET_SOURCES["guest_entry.py"][0]
                )
                guest.write_bytes(guest.read_bytes() + b"\n# sealed drift\n")
                with self.assertRaisesRegex(
                    RENDER.RenderError, "candidate Git HEAD, index, or worktree changed",
                ):
                    RENDER.write_output(root, "rejected-sealed.json", canonical(output))
                self.assertFalse((root_path / "rejected-sealed.json").exists())
            finally:
                root.close()


if __name__ == "__main__":
    unittest.main()

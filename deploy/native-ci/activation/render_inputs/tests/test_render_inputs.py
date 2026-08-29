#!/usr/bin/env python3
"""Focused tests for descriptor-bound activation input rendering."""

from __future__ import annotations

import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import threading
import unittest
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


def minimal_manifest(name: str, source: str, raw: bytes, mode: int = 0o400) -> dict[str, object]:
    unsigned: dict[str, object] = {
        "schema": f"test-{name}-package-v1",
        "source_commit": CANDIDATE,
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

    def make_lifecycle(self, root: Path) -> dict[str, object]:
        proof = {
            "configs_sha256": HEX["config"], "units_sha256": HEX["units"],
            "sockets_absent": True, "processes_absent": True,
            "encrypted_credentials_absent": True, "relay_residue_absent": True,
        }
        trees = {name: digit * 64 for name, digit in zip(RENDER.PACKAGE_NAMES, "89abc", strict=True)}
        contract = {
            "schema_version": "buzz-ci-clean-host-e2e-vm-contract/v2", "candidate_sha": CANDIDATE,
            "state": "state", "candidate_root": "candidate",
            "scenario": {"path": "scenario.json", "sha256": HEX["scenario"]},
            "seccomp_source": {"path": "seccomp.json", "sha256": RENDER.SECCOMP_SHA256},
            "packages": {name: {"path": name, "tree_sha256": trees[name]} for name in RENDER.PACKAGE_NAMES},
        }
        receipt = {"outcome": "pass", "integrated_candidate_sha": CANDIDATE, "scenario_sha256": HEX["scenario"]}
        verifier = {"status": "pass"}
        receipt_ref = write_json(root, "evidence/acceptance-receipt.json", receipt, 0o400)
        verifier_ref = write_json(root, "evidence/verifier.json", verifier, 0o400)
        evidence = {
            "schema_version": "buzz-ci-clean-host-e2e-evidence/v2", "candidate_sha": CANDIDATE,
            "image_sha256": "d" * 64, "tool_sha256": {"qemu": "e" * 64},
            "harness_asset_sha256": {"guest_entry.py": "f" * 64},
            "package_tree_sha256": trees, "scenario_sha256": HEX["scenario"],
            "seccomp_source_sha256": RENDER.SECCOMP_SHA256,
            "receipt_sha256": receipt_ref["sha256"], "verifier_sha256": verifier_ref["sha256"],
            "dormant_proof": proof,
        }
        evidence_ref = write_json(root, "evidence/evidence-manifest.json", evidence, 0o400)
        contract_ref = write_json(root, "evidence/contract.json", contract, 0o400)
        result = {
            "status": "pass", "candidate_sha": CANDIDATE, "vm_state_absent": True,
            "receipt_sha256": receipt_ref["sha256"], "verifier_sha256": verifier_ref["sha256"],
            "evidence_manifest_sha256": evidence_ref["sha256"], "dormant_proof": proof,
        }
        result_ref = write_json(root, "evidence/result.json", result, 0o400)
        return {
            "result": result_ref, "contract": contract_ref, "evidence_manifest": evidence_ref,
            "acceptance_receipt": receipt_ref, "verifier": verifier_ref,
        }

    def run_cli(self, root: Path, action: str, descriptor: dict[str, object], output: str) -> subprocess.CompletedProcess[str]:
        descriptor_ref = write_json(root, "descriptor.json", descriptor)
        return subprocess.run(
            ["python3", str(SCRIPT), action, "--descriptor", str(root / descriptor_ref["path"]), "--output", output],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )

    def test_residue_is_reproducible_and_disclaims_external_gates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lifecycle = self.make_lifecycle(root)
            descriptor = {
                "schema_version": "buzz-ci-residue-receipt-render-input/v1",
                "candidate_sha": CANDIDATE, "lifecycle": lifecycle,
            }
            first = self.run_cli(root, "record-residue", descriptor, "first.json")
            self.assertEqual(first.returncode, 0, first.stderr)
            second = self.run_cli(root, "record-residue", descriptor, "second.json")
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual((root / "first.json").read_bytes(), (root / "second.json").read_bytes())
            value = json.loads((root / "first.json").read_bytes())
            self.assertEqual(value["claims"], {"protected_ci": False, "tier2": False})
            self.assertEqual(value["lifecycle_status"], "verified_pass")
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
                    RENDER.write_output(root, "output.json", b"complete\n")
            finally:
                root.close()
            output = root_path / "output.json"
            self.assertEqual(output.read_bytes(), b"complete\n")
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
                for root, payload in zip(roots, (b"first\n", b"second\n"), strict=True)
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
            self.assertIn((root_path / "output.json").read_bytes(), (b"first\n", b"second\n"))
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
                        RENDER.write_output(root, "output.json", b"complete\n")
                self.assertFalse((root_path / "output.json").exists())
                self.assertEqual(self.output_temporaries(root_path), [])
                RENDER.write_output(root, "output.json", b"complete\n")
            finally:
                root.close()
            self.assertEqual((root_path / "output.json").read_bytes(), b"complete\n")

    def test_prepublish_fsync_and_link_failures_clean_up(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            root = self.output_root(root_path)
            try:
                with mock.patch.object(RENDER.os, "fsync", side_effect=OSError(errno.EIO, "injected fsync")):
                    with self.assertRaisesRegex(OSError, "injected fsync"):
                        RENDER.write_output(root, "fsync.json", b"complete\n")
                self.assertFalse((root_path / "fsync.json").exists())
                self.assertEqual(self.output_temporaries(root_path), [])

                with mock.patch.object(RENDER.os, "link", side_effect=OSError(errno.EIO, "injected link")):
                    with self.assertRaisesRegex(OSError, "injected link"):
                        RENDER.write_output(root, "link.json", b"complete\n")
                self.assertFalse((root_path / "link.json").exists())
                self.assertEqual(self.output_temporaries(root_path), [])

                RENDER.write_output(root, "fsync.json", b"complete\n")
                RENDER.write_output(root, "link.json", b"complete\n")
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
                        RENDER.write_output(root, "close.json", b"complete\n")
                self.assertFalse((root_path / "close.json").exists())
                self.assertEqual(self.output_temporaries(root_path), [])

                real_unlink = os.unlink
                unlinks = 0

                def unlink_once_then_succeed(path: str, *, dir_fd: int) -> None:
                    nonlocal unlinks
                    unlinks += 1
                    if unlinks == 1:
                        raise OSError(errno.EIO, "injected unlink")
                    real_unlink(path, dir_fd=dir_fd)

                with mock.patch.object(RENDER.os, "unlink", side_effect=unlink_once_then_succeed):
                    RENDER.write_output(root, "output.json", b"complete\n")
                self.assertEqual(unlinks, 2)
                self.assertEqual(self.output_temporaries(root_path), [])
            finally:
                root.close()

    def test_directory_fsync_failure_leaves_only_complete_publication(self) -> None:
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
                        RENDER.write_output(root, "output.json", b"complete\n")
            finally:
                root.close()
            output = root_path / "output.json"
            self.assertEqual(output.read_bytes(), b"complete\n")
            self.assertEqual(output.stat().st_mode & 0o7777, 0o600)
            self.assertEqual(self.output_temporaries(root_path), [])

    def test_existing_target_and_symlink_are_never_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            existing = root_path / "existing.json"
            existing.write_bytes(b"keep\n")
            existing.chmod(0o400)
            outside = root_path / "outside.json"
            outside.write_bytes(b"outside\n")
            symlink = root_path / "symlink.json"
            symlink.symlink_to(outside)
            root = self.output_root(root_path)
            try:
                with self.assertRaises(FileExistsError):
                    RENDER.write_output(root, "existing.json", b"replace\n")
                with self.assertRaises(FileExistsError):
                    RENDER.write_output(root, "symlink.json", b"replace\n")
            finally:
                root.close()
            self.assertEqual(existing.read_bytes(), b"keep\n")
            self.assertEqual(existing.stat().st_mode & 0o7777, 0o400)
            self.assertTrue(symlink.is_symlink())
            self.assertEqual(outside.read_bytes(), b"outside\n")
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
                    RENDER.write_output(root, "output.json", b"complete\n")
            finally:
                root.close()
            self.assertTrue(collision.is_symlink())
            self.assertEqual(outside.read_bytes(), b"outside\n")
            self.assertEqual((root_path / "output.json").read_bytes(), b"complete\n")
            self.assertFalse((root_path / f".render-inputs-{'b' * 32}.tmp").exists())

    def test_bound_lifecycle_mutation_fails_without_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lifecycle = self.make_lifecycle(root)
            descriptor = {
                "schema_version": "buzz-ci-residue-receipt-render-input/v1",
                "candidate_sha": CANDIDATE, "lifecycle": lifecycle,
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

    def test_symlinked_reference_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lifecycle = self.make_lifecycle(root)
            target = root / "evidence/verifier.json"
            link = root / "verifier-link.json"
            link.symlink_to(target)
            lifecycle["verifier"] = {
                **lifecycle["verifier"], "path": "verifier-link.json",
            }
            descriptor = {
                "schema_version": "buzz-ci-residue-receipt-render-input/v1",
                "candidate_sha": CANDIDATE, "lifecycle": lifecycle,
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
            lifecycle = self.make_lifecycle(root_path)
            public_ref = write_json(root_path, "state/public-binding.json", public_binding(), 0o444)
            refs: dict[str, object] = {}
            manifests: dict[str, object] = {}
            activation_digest = "a" * 64
            for name in RENDER.PACKAGE_NAMES:
                payload = name.encode()
                manifest = minimal_manifest(name, f"assets/{name}", payload)
                if name == "activation":
                    unsigned = dict(manifest)
                    unsigned.pop("package_digest")
                    unsigned["schema"] = "buzz-ci-capacity-one-activation-draft-v1"
                    activation_digest = hashlib.sha256(canonical(unsigned)).hexdigest()
                    manifest = {
                        **unsigned, "schema": "buzz-ci-capacity-one-activation-package-v1",
                        "activation_id": f"buzz-ci-capacity-one-{CANDIDATE[:12]}-{activation_digest[:12]}",
                        "package_digest": activation_digest,
                    }
                manifest_name = "activation-manifest.json" if name == "activation" else "package-manifest.json"
                refs[name] = write_json(root_path, f"{name}/{manifest_name}", manifest, 0o400)
                manifests[name] = manifest
            execd = json.loads((root_path / "execd/package-manifest.json").read_bytes())
            unsigned_execd = dict(execd)
            unsigned_execd.pop("package_digest")
            unsigned_execd["activation_binding"] = {
                "source_commit": CANDIDATE, "package_digest": activation_digest,
                "activation_id": f"buzz-ci-capacity-one-{CANDIDATE[:12]}-{activation_digest[:12]}",
            }
            execd = {**unsigned_execd, "package_digest": hashlib.sha256(canonical(unsigned_execd)).hexdigest()}
            (root_path / "execd/package-manifest.json").chmod(0o600)
            refs["execd"] = write_json(root_path, "execd/package-manifest.json", execd, 0o400)
            manifests["execd"] = execd
            descriptor = {
                "schema_version": "buzz-ci-sealed-freeze-receipt-render-input/v1", "candidate_sha": CANDIDATE,
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
            finally:
                root.close()


if __name__ == "__main__":
    unittest.main()

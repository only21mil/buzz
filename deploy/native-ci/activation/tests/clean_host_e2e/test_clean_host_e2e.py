#!/usr/bin/env python3
"""Adversarial checks for the isolated clean-host VM harness."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, HERE / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


harness = load("harness")
relay = load("local_tls_relay")
guest = load("guest_entry")


def state_record(trusted_digest: str = "1" * 64) -> dict[str, object]:
    digest = "1" * 64
    return {
        "schema_version": harness.STATE_SCHEMA,
        "challenge": digest,
        "image_sha256": digest,
        "qemu_sha256": digest,
        "qemu_img_sha256": digest,
        "qemu_version": "test",
        "tool_sha256": {name: digest for name in harness.TOOLS},
        "harness_asset_sha256": {name: digest for name in harness.FROZEN_ASSETS},
        "trusted_image_sha256": trusted_digest,
    }


def make_destroyable_state(parent: Path) -> Path:
    state = parent / "state"
    state.mkdir(mode=0o700)
    (state / "state.json").write_bytes(harness.canonical(state_record()))
    return state


def make_prepared_state(parent: Path) -> Path:
    state = parent / "state"
    frozen = state / "frozen-assets"
    frozen.mkdir(mode=0o700, parents=True)
    asset_digests = {}
    for name in harness.FROZEN_ASSETS:
        path = frozen / name
        path.write_bytes(("trusted-" + name).encode())
        asset_digests[name] = harness.file_sha256(path)
    trusted = state / "trusted.qcow2"
    trusted.write_bytes(b"trusted-image")
    trusted.chmod(0o400)
    tool_digests = {
        name: harness.file_sha256(Path(path))
        for name, path in harness.TOOLS.items()
    }
    record = state_record(harness.file_sha256(trusted))
    record.update({
        "qemu_sha256": tool_digests["qemu"],
        "qemu_img_sha256": tool_digests["qemu_img"],
        "tool_sha256": tool_digests,
        "harness_asset_sha256": asset_digests,
    })
    (state / "state.json").write_bytes(harness.canonical(record))
    return state


def make_run_contract(parent: Path, state: Path) -> tuple[Path, dict[str, object], str]:
    candidate = HERE.parents[4]
    candidate_sha = harness.bounded([
        "/usr/bin/git", "-C", str(candidate), "rev-parse", "HEAD^{commit}",
    ]).decode().strip()
    packages = {}
    for name in harness.PACKAGE_NAMES:
        package = parent / f"package-{name}"
        package.mkdir(mode=0o700)
        (package / "payload").write_bytes(name.encode())
        packages[name] = {
            "path": str(package),
            "tree_sha256": harness.tree_digest(harness.tree_records(package)),
        }
    scenario = parent / "scenario.json"
    scenario.write_bytes(b"{}\n")
    seccomp = parent / "seccomp.json"
    seccomp.write_bytes(b'{"defaultAction":"SCMP_ACT_ERRNO"}\n')
    seccomp_sha = harness.file_sha256(seccomp)
    value = {
        "schema_version": harness.SCHEMA,
        "state": str(state),
        "candidate_root": str(candidate),
        "candidate_sha": candidate_sha,
        "scenario": {"path": str(scenario), "sha256": harness.file_sha256(scenario)},
        "seccomp_source": {"path": str(seccomp), "sha256": seccomp_sha},
        "packages": packages,
    }
    contract = parent / "contract.json"
    contract.write_bytes(harness.canonical(value))
    return contract, value, seccomp_sha


def rewrite_contract(path: Path, value: dict[str, object]) -> None:
    path.write_bytes(harness.canonical(value))


def passing_frame(contract: dict[str, object]) -> dict[str, object]:
    proof = {
        "configs_sha256": "5" * 64,
        "units_sha256": "6" * 64,
        "sockets_absent": True,
        "processes_absent": True,
        "encrypted_credentials_absent": True,
        "relay_residue_absent": True,
    }
    receipt = {
        "schema_version": "buzz-ci-capacity-one-acceptance-receipt/v2",
        "outcome": "pass",
        "scenario_sha256": contract["scenario"]["sha256"],
        "integrated_candidate_sha": contract["candidate_sha"],
        "run_id": "4" * 32,
        "checks": [],
        "zero_transition": {},
    }
    verifier = {"outcome": "pass", "status": "verified"}
    return {
        "schema_version": harness.FRAME_SCHEMA,
        "phase": "run",
        "challenge": "1" * 64,
        "outcome": "pass",
        "receipt_base64": base64.b64encode(harness.canonical(receipt)).decode(),
        "verifier_base64": base64.b64encode(harness.canonical(verifier)).decode(),
        "dormant_proof": proof,
    }


def mount_pairs(command: list[str], option: str) -> list[tuple[str, str]]:
    return [
        (command[index + 1], command[index + 2])
        for index, value in enumerate(command[:-2])
        if value == option
    ]


def schnorr_sign(message: bytes, secret: int) -> tuple[str, str]:
    point = relay.point_mul(secret)
    assert point is not None
    adjusted = secret if point[1] % 2 == 0 else relay.N - secret
    public = point[0].to_bytes(32, "big")
    aux = b"\0" * 32
    mask = relay.tagged_hash("BIP0340/aux", aux)
    masked = bytes(a ^ b for a, b in zip(adjusted.to_bytes(32, "big"), mask, strict=True))
    nonce = int.from_bytes(relay.tagged_hash("BIP0340/nonce", masked + public + message), "big") % relay.N
    nonce_point = relay.point_mul(nonce)
    assert nonce_point is not None
    if nonce_point[1] % 2:
        nonce = relay.N - nonce
        nonce_point = relay.point_mul(nonce)
        assert nonce_point is not None
    r = nonce_point[0].to_bytes(32, "big")
    challenge = int.from_bytes(relay.tagged_hash("BIP0340/challenge", r + public + message), "big") % relay.N
    signature = r + ((nonce + challenge * adjusted) % relay.N).to_bytes(32, "big")
    return public.hex(), signature.hex()


def signed_event(secret: int, kind: int, tags: list[list[str]], content: str, created_at: int) -> dict[str, object]:
    point = relay.point_mul(secret)
    assert point is not None
    public = point[0].to_bytes(32, "big").hex()
    unsigned = {"pubkey": public, "created_at": created_at, "kind": kind, "tags": tags, "content": content}
    identifier = relay.event_id(unsigned)
    _, signature = schnorr_sign(bytes.fromhex(identifier), secret)
    return {"id": identifier, **unsigned, "sig": signature}


def nip98(secret: int, method: str, url: str, body: bytes, now: int) -> str:
    tags = [["u", url], ["method", method]]
    if body:
        tags.append(["payload", hashlib.sha256(body).hexdigest()])
    event = signed_event(secret, 27235, tags, "", now)
    return "Nostr " + base64.b64encode(json.dumps(event, separators=(",", ":")).encode()).decode()


class BoundaryTests(unittest.TestCase):
    def test_qemu_boundary_has_no_container_network_or_host_share(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            command = harness.qemu_command(
                Path(temporary), overlay="ceremony.qcow2", evidence=True,
            )
        joined = " ".join(command)
        self.assertIn("--unshare-net", command)
        self.assertIn("--dev-bind /dev/kvm /dev/kvm", joined)
        self.assertIn("-nic none", joined)
        self.assertIn("-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny", joined)
        self.assertNotIn("docker", joined)
        self.assertNotIn("--privileged", joined)
        self.assertNotIn("virtfs", joined)
        self.assertNotIn(("/home", "/home"), mount_pairs(command, "--ro-bind"))
        self.assertNotIn("--bind /home/victor /home/victor", joined)
        candidate_command = " ".join(harness.qemu_command(
            Path("/private-state"), overlay="candidate.qcow2",
            evidence=False, transfer="read-write",
        ))
        verifier_command = " ".join(harness.qemu_command(
            Path("/private-state"), overlay="verifier.qcow2",
            evidence=True, transfer="read-only",
        ))
        self.assertNotIn("evidence.bin", candidate_command)
        self.assertNotIn("virtserialport", candidate_command)
        self.assertIn("candidate.qcow2", candidate_command)
        self.assertNotIn("verifier.qcow2", candidate_command)
        self.assertIn("verifier.qcow2", verifier_command)
        self.assertIn("readonly=on", verifier_command)
        self.assertIn("evidence.bin", verifier_command)

    def test_hostile_candidate_can_write_only_overlay_and_transfer(self) -> None:
        state = Path("/private/state")
        candidate = harness.qemu_command(
            state, overlay="candidate.qcow2", evidence=False, transfer="read-write",
        )
        verifier = harness.qemu_command(
            state, overlay="verifier.qcow2", evidence=True, transfer="read-only",
        )
        self.assertIn((str(state), "/work"), mount_pairs(candidate, "--ro-bind"))
        self.assertEqual(
            mount_pairs(candidate, "--bind"),
            [
                (str(state / "candidate.qcow2"), "/work/candidate.qcow2"),
                (str(state / "transfer.raw"), "/work/transfer.raw"),
            ],
        )
        self.assertEqual(
            mount_pairs(verifier, "--bind"),
            [
                (str(state / "verifier.qcow2"), "/work/verifier.qcow2"),
                (str(state / "evidence.bin"), "/work/evidence.bin"),
            ],
        )
        for protected in (
            "trusted.qcow2", "state.json", "public-binding.json",
            *[f"frozen-assets/{name}" for name in harness.FROZEN_ASSETS],
        ):
            self.assertNotIn((str(state / protected), f"/work/{protected}"), mount_pairs(candidate, "--bind"))

    def test_bubblewrap_rejects_hostile_writes_to_verifier_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            frozen = state / "frozen-assets"
            frozen.mkdir()
            protected = {
                "trusted.qcow2": b"trusted-image",
                "state.json": b"trusted-state",
                "frozen-assets/receipt_verifier.py": b"trusted-verifier",
            }
            for relative, raw in protected.items():
                (state / relative).write_bytes(raw)
            (state / "candidate.qcow2").write_bytes(b"overlay")
            (state / "transfer.raw").write_bytes(b"transfer")
            command = harness.bwrap_prefix(
                state, writable_files=("candidate.qcow2", "transfer.raw"),
            ) + [
                "--", "/bin/sh", "-c",
                "printf overlay-write > /work/candidate.qcow2 && "
                "printf transfer-write > /work/transfer.raw && "
                "! printf hostile > /work/trusted.qcow2 && "
                "! printf hostile > /work/state.json && "
                "! printf hostile > /work/frozen-assets/receipt_verifier.py",
            ]
            harness.bounded(command, timeout=10, maximum=4096)
            self.assertEqual((state / "candidate.qcow2").read_bytes(), b"overlay-write")
            self.assertEqual((state / "transfer.raw").read_bytes(), b"transfer-write")
            for relative, raw in protected.items():
                self.assertEqual((state / relative).read_bytes(), raw)

    def test_evidence_destination_exists_before_qemu_is_spawned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)

            def command(*_args, **_kwargs):
                evidence = state / "evidence.bin"
                self.assertTrue(evidence.is_file())
                self.assertEqual(evidence.stat().st_mode & 0o777, 0o600)
                return ["/usr/bin/true"]

            with mock.patch.object(harness, "qemu_command", side_effect=command):
                with self.assertRaisesRegex(harness.HarnessError, "truncated"):
                    harness.boot(state, 1, overlay="verifier.qcow2", evidence_expected=True)

    def test_hostile_candidate_persistence_has_no_verifier_overlay_or_evidence_path(self) -> None:
        candidate = " ".join(harness.qemu_command(
            Path("/state"), overlay="candidate.qcow2",
            evidence=False, transfer="read-write",
        ))
        verifier = " ".join(harness.qemu_command(
            Path("/state"), overlay="verifier.qcow2",
            evidence=True, transfer="read-only",
        ))
        self.assertIn("candidate.qcow2", candidate)
        self.assertNotIn("trusted.qcow2,if=virtio", candidate)
        self.assertNotIn("verifier.qcow2", candidate)
        self.assertNotIn("evidence.bin", candidate)
        self.assertIn("verifier.qcow2", verifier)
        self.assertNotIn("candidate.qcow2", verifier)
        self.assertIn("transfer.raw", verifier)
        self.assertIn("readonly=on", verifier)

    def test_host_capability_proof_is_exact_and_missing_tool_fails_closed(self) -> None:
        proof = harness.capabilities()
        self.assertEqual((proof["boundary"], proof["network"]), ("bubblewrap+qemu-kvm", "unshared-and-no-nic"))
        original = harness.TOOLS["qemu"]
        harness.TOOLS["qemu"] = "/definitely/absent/qemu"
        try:
            with self.assertRaisesRegex(harness.HarnessError, "capability unavailable"):
                harness.capabilities()
        finally:
            harness.TOOLS["qemu"] = original

    def test_bounded_command_kills_timeout_and_rejects_output_flood(self) -> None:
        started = time.monotonic()
        with self.assertRaisesRegex(harness.HarnessError, "timed out"):
            harness.bounded(["/usr/bin/sleep", "10"], timeout=1)
        self.assertLess(time.monotonic() - started, 3)
        with self.assertRaisesRegex(harness.HarnessError, "output exceeded"):
            harness.bounded(["/usr/bin/yes"], timeout=5, maximum=1024)

    def test_keyboard_interrupt_always_kills_and_reaps_host_and_guest_groups(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            original_scratch = guest.SCRATCH_ROOT
            guest.SCRATCH_ROOT = Path(scratch)
            try:
                self._assert_keyboard_interrupt_cleanup(harness, harness.bounded)
                self._assert_keyboard_interrupt_cleanup(guest, guest.command)
            finally:
                guest.SCRATCH_ROOT = original_scratch

    def _assert_keyboard_interrupt_cleanup(self, module, function) -> None:
        spawned = []
        real_popen = module.subprocess.Popen

        def capture(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            spawned.append(process)
            return process

        with mock.patch.object(module.subprocess, "Popen", side_effect=capture), mock.patch.object(
            module.time, "sleep", side_effect=KeyboardInterrupt,
        ):
            with self.assertRaises(KeyboardInterrupt):
                function(["/usr/bin/sleep", "30"], timeout=10)
        self.assertEqual(len(spawned), 1)
        self.assertIsNotNone(spawned[0].poll())
        with self.assertRaises(ProcessLookupError):
            os.killpg(spawned[0].pid, 0)

    def test_guest_secret_scratch_is_tmpfs_and_swap_must_be_absent(self) -> None:
        self.assertEqual(guest.SCRATCH_ROOT, Path("/run"))
        source = (HERE / "guest_entry.py").read_text()
        self.assertIn("tempfile.TemporaryFile(dir=SCRATCH_ROOT)", source)
        self.assertIn('dir="/run"', source)
        with tempfile.TemporaryDirectory() as temporary:
            swaps = Path(temporary) / "swaps"
            swaps.write_text("Filename\tType\tSize\tUsed\tPriority\n")
            original = guest.SWAPS_PATH
            guest.SWAPS_PATH = swaps
            try:
                with mock.patch.object(guest, "command") as command:
                    guest.disable_swap()
                    command.assert_called_once_with(["swapoff", "-a"])
                swaps.write_text("Filename\tType\tSize\tUsed\tPriority\n/dev/vda2 partition 1 0 -2\n")
                with mock.patch.object(guest, "command"):
                    with self.assertRaisesRegex(guest.GuestError, "swap remains"):
                        guest.disable_swap()
            finally:
                guest.SWAPS_PATH = original

    def test_systemd_readback_never_masks_driver_failure_as_absence(self) -> None:
        failed = __import__("subprocess").CompletedProcess(["systemctl"], 1, b"", b"")
        with mock.patch.object(guest, "command", return_value=failed):
            with self.assertRaisesRegex(guest.GuestError, "readback failed"):
                guest.unit_state()

    def test_strict_verifier_verdict_rejects_status_and_outcome_mutation(self) -> None:
        valid = guest.canonical({"outcome": "pass", "status": "verified"})
        self.assertEqual(guest.parse_verdict(valid), {"outcome": "pass", "status": "verified"})
        for value in (
            {"outcome": "pass", "status": "pass"},
            {"outcome": "failure", "status": "verified"},
            {"outcome": "pass", "status": "verified", "detail": "secret"},
        ):
            with self.assertRaisesRegex(guest.GuestError, "verdict differs"):
                guest.parse_verdict(guest.canonical(value))


class InputTests(unittest.TestCase):
    def test_created_private_path_rejects_symbolic_parent_before_writing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.mkdir(mode=0o700)
            linked = root / "linked"
            linked.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(harness.HarnessError, "parent is unsafe"):
                harness.safe_directory(linked / "state", create=True)
            self.assertFalse((real / "state").exists())

    def test_guest_assets_are_staged_only_from_prepared_frozen_copies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            frozen = state / "frozen-assets"
            stage = state / "stage"
            frozen.mkdir(parents=True)
            stage.mkdir()
            for name in harness.FROZEN_ASSETS:
                (frozen / name).write_bytes(("frozen-" + name).encode())
            harness.stage_common(state, stage, {"phase": "test"})
            for name in harness.FROZEN_ASSETS:
                self.assertEqual((stage / name).read_bytes(), ("frozen-" + name).encode())

    def test_tree_digest_rejects_links_and_binds_mode_name_and_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            item = root / "asset"
            item.write_bytes(b"one")
            item.chmod(0o400)
            first = harness.tree_digest(harness.tree_records(root))
            item.chmod(0o500)
            second = harness.tree_digest(harness.tree_records(root))
            item.chmod(0o600)
            item.write_bytes(b"two")
            third = harness.tree_digest(harness.tree_records(root))
            self.assertEqual(len({first, second, third}), 3)
            (root / "link").symlink_to(item)
            with self.assertRaisesRegex(harness.HarnessError, "not one regular"):
                harness.tree_records(root)

    def test_tree_read_retains_root_dirfd_across_parent_swap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "package"
            original = parent / "original"
            attacker = parent / "attacker"
            root.mkdir()
            attacker.mkdir()
            (root / "value").write_bytes(b"trusted")
            (root / "value").chmod(0o644)
            (attacker / "value").write_bytes(b"secret")
            real_scandir = os.scandir
            swapped = False

            def swap_then_scan(fd):
                nonlocal swapped
                if not swapped:
                    root.rename(original)
                    root.symlink_to(attacker, target_is_directory=True)
                    swapped = True
                return real_scandir(fd)

            try:
                with mock.patch.object(harness.os, "scandir", side_effect=swap_then_scan):
                    records = harness.tree_records(root)
                self.assertEqual(records, [("value", 0o644, b"trusted")])
            finally:
                if root.is_symlink():
                    root.unlink()
                if original.exists():
                    original.rename(root)

    def test_authoritative_parent_contains_complete_execd_package(self) -> None:
        candidate = HERE.parents[4]
        missing = [relative for relative in harness.REQUIRED_CANDIDATE if not (candidate / relative).is_file()]
        self.assertEqual(missing, [])

    def test_hardlinked_package_member_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first"
            first.write_bytes(b"same")
            os.link(first, root / "second")
            with self.assertRaisesRegex(harness.HarnessError, "not one regular"):
                harness.tree_records(root)

    def test_manifest_member_cannot_escape_or_traverse_a_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "package"
            package.mkdir()
            (package / "assets").mkdir()
            (package / "assets/value").write_bytes(b"value")
            self.assertEqual(guest.package_member(package, "assets/value"), package / "assets/value")
            for source in ("../outside", "/etc/passwd", "assets/../outside"):
                with self.assertRaisesRegex(guest.GuestError, "escapes"):
                    guest.package_member(package, source)
            (package / "linked").symlink_to(package / "assets", target_is_directory=True)
            with self.assertRaises(guest.GuestError):
                guest.package_member(package, "linked/value")

    def test_frame_rejects_trailing_bytes_digest_and_oversize(self) -> None:
        value = {"schema_version": harness.FRAME_SCHEMA, "phase": "ceremony"}
        payload = harness.canonical(value)
        valid = struct.pack(">I", len(payload)) + payload + hashlib.sha256(payload).digest()
        self.assertEqual(harness.parse_frame(valid), value)
        malformed_values = (
            valid + b"x",
            valid[:-1] + bytes([valid[-1] ^ 1]),
            struct.pack(">I", harness.MAX_FRAME + 1) + b"x" * 32,
        )
        for malformed in malformed_values:
            with self.assertRaises(harness.HarnessError):
                harness.parse_frame(malformed)

    def test_self_consistent_but_semantically_invalid_receipt_fails_frozen_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            results = root / "results"
            results.mkdir(mode=0o700)
            scenario = root / "scenario.json"
            scenario.write_bytes(b"{}\n")
            candidate = "1" * 40
            scenario_sha = harness.file_sha256(scenario)
            receipt = {
                "schema_version": "buzz-ci-capacity-one-acceptance-receipt/v2",
                "outcome": "pass", "scenario_sha256": scenario_sha,
                "integrated_candidate_sha": candidate, "run_id": "2" * 32,
                "checks": [], "zero_transition": {},
            }
            verifier = {"outcome": "pass", "status": "verified"}
            proof = {
                "configs_sha256": "3" * 64, "units_sha256": "4" * 64,
                "sockets_absent": True, "processes_absent": True,
                "encrypted_credentials_absent": True, "relay_residue_absent": True,
            }
            receipt_raw = harness.canonical(receipt)
            verifier_raw = harness.canonical(verifier)
            here = Path(harness.__file__).resolve().parent
            assets = {
                name: harness.file_sha256(harness.asset_source(here, name))
                for name in harness.FROZEN_ASSETS
            }
            evidence = {
                "schema_version": "buzz-ci-clean-host-e2e-evidence/v2",
                "candidate_sha": candidate, "image_sha256": "5" * 64,
                "tool_sha256": {name: "6" * 64 for name in harness.TOOLS},
                "harness_asset_sha256": assets, "package_tree_sha256": {},
                "scenario_sha256": scenario_sha,
                "seccomp_source_sha256": harness.SECCOMP_SHA256,
                "transfer_bytes": harness.TRANSFER_SIZE, "transfer_sha256": "7" * 64,
                "receipt_sha256": hashlib.sha256(receipt_raw).hexdigest(),
                "verifier_sha256": hashlib.sha256(verifier_raw).hexdigest(),
                "dormant_proof": proof,
            }
            (results / "acceptance-receipt.json").write_bytes(receipt_raw)
            (results / "verifier.json").write_bytes(verifier_raw)
            (results / "evidence-manifest.json").write_bytes(harness.canonical(evidence))
            for path in results.iterdir():
                path.chmod(0o400)
            contract = {
                "state": str(root / "state"), "candidate_sha": candidate,
                "scenario": {"path": str(scenario), "sha256": scenario_sha},
            }
            with self.assertRaisesRegex(harness.HarnessError, "frozen receipt verifier rejected"):
                harness.validate_result_set(contract, results)

    def test_state_cleanup_requires_marker_and_proves_absence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            unknown = parent / "unknown"
            unknown.mkdir(mode=0o700)
            with self.assertRaisesRegex(harness.HarnessError, "unrecognized"):
                harness.destroy_state(unknown)
            unknown.rmdir()
            state = parent / "state"
            state.mkdir(mode=0o700)
            digest = "1" * 64
            (state / "state.json").write_bytes(harness.canonical({
                "schema_version": harness.STATE_SCHEMA,
                "challenge": digest,
                "image_sha256": digest,
                "qemu_sha256": digest,
                "qemu_img_sha256": digest,
                "qemu_version": "test",
                "tool_sha256": {name: digest for name in harness.TOOLS},
                "harness_asset_sha256": {name: digest for name in harness.FROZEN_ASSETS},
                "trusted_image_sha256": digest,
            }))
            (state / "candidate.qcow2").write_bytes(b"ephemeral")
            harness.destroy_state(state)
            self.assertFalse(state.exists())

    def test_terminal_run_rejects_malicious_state_paths_without_destroying_targets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_prepared_state(root)
            contract, value, _seccomp_sha = make_run_contract(root, state)
            linked = root / "linked-state"
            linked.symlink_to(state, target_is_directory=True)
            value["state"] = str(linked)
            rewrite_contract(contract, value)
            with self.assertRaises(harness.HarnessError):
                harness.terminal_run(contract, root / "results")
            self.assertTrue(state.exists())
            self.assertTrue(linked.is_symlink())

    def test_contract_envelope_failures_do_not_select_or_destroy_state(self) -> None:
        mutations = (
            lambda value: value.update(schema_version="wrong"),
            lambda value: value.update(candidate_sha="not-a-commit"),
            lambda value: value.update(state=["not", "a", "path"]),
            lambda value: value.update(extra="rejected"),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                state = make_prepared_state(root)
                contract, value, _seccomp_sha = make_run_contract(root, state)
                mutate(value)
                rewrite_contract(contract, value)
                with self.assertRaises(harness.HarnessError):
                    harness.terminal_run(contract, root / "results")
                self.assertTrue(state.exists())

    def test_every_post_selection_validation_boundary_destroys_state(self) -> None:
        def candidate_failure(value):
            value["candidate_root"] = "/definitely/absent/candidate"

        def package_set_failure(value):
            value["packages"].pop("runner")

        def package_descriptor_failure(value):
            value["packages"]["runner"]["tree_sha256"] = "0" * 64

        def package_path_failure(value):
            value["packages"]["runner"]["path"] = "/definitely/absent/package"

        def scenario_descriptor_failure(value):
            value["scenario"]["sha256"] = "0" * 64

        def scenario_path_failure(value):
            value["scenario"]["path"] = "/definitely/absent/scenario"

        def seccomp_descriptor_failure(value):
            value["seccomp_source"]["sha256"] = "0" * 64

        def seccomp_path_failure(value):
            value["seccomp_source"]["path"] = "/definitely/absent/seccomp"

        mutations = (
            candidate_failure, package_set_failure, package_descriptor_failure,
            package_path_failure, scenario_descriptor_failure, scenario_path_failure,
            seccomp_descriptor_failure, seccomp_path_failure,
        )
        for mutate in mutations:
            with self.subTest(boundary=mutate.__name__), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                state = make_prepared_state(root)
                contract, value, seccomp_sha = make_run_contract(root, state)
                mutate(value)
                rewrite_contract(contract, value)
                with mock.patch.object(harness, "SECCOMP_SHA256", seccomp_sha), mock.patch.object(
                    harness, "validate_flat_qcow2",
                ):
                    with self.assertRaises((OSError, harness.HarnessError, __import__("subprocess").SubprocessError)):
                        harness.terminal_run(contract, root / "results")
                self.assertFalse(state.exists())
                self.assertFalse(any(path.name.startswith(".state.terminal-") for path in root.iterdir()))

    def test_concurrent_run_state_replacement_is_preserved_and_cleanup_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_prepared_state(root)
            contract, _value, seccomp_sha = make_run_contract(root, state)
            stolen = root / "stolen-selected-state"
            replacement = None

            def replace_then_fail(selected, _name, _backing):
                nonlocal replacement
                selected.rename(stolen)
                selected.mkdir(mode=0o700)
                marker = state_record()
                marker["challenge"] = "2" * 64
                (selected / "state.json").write_bytes(harness.canonical(marker))
                replacement = selected
                raise harness.HarnessError("simulated setup failure after replacement")

            with mock.patch.object(harness, "SECCOMP_SHA256", seccomp_sha), mock.patch.object(
                harness, "validate_flat_qcow2",
            ), mock.patch.object(harness, "qemu_img_create", side_effect=replace_then_fail):
                with self.assertRaisesRegex(harness.HarnessError, "terminal run cleanup failed") as caught:
                    harness.terminal_run(contract, root / "results")
            self.assertIn("setup failure", str(caught.exception.__cause__))
            self.assertIsNotNone(replacement)
            self.assertTrue(replacement.exists())
            self.assertTrue(stolen.exists())
            self.assertFalse((root / "results").exists())
            harness.destroy_state(replacement)
            harness.destroy_state(stolen)

    def test_state_cleanup_quarantine_never_deletes_a_swapped_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_destroyable_state(root)
            expected = harness.state_identity(state)
            stolen = root / "stolen-state"
            replacement = root / "replacement"
            replacement.mkdir(mode=0o700)
            (replacement / "sentinel").write_text("unrelated")
            real_rename = harness.rename_noreplace

            def swap_before_quarantine(source, target):
                if source == state:
                    state.rename(stolen)
                    replacement.rename(state)
                return real_rename(source, target)

            with mock.patch.object(harness, "rename_noreplace", side_effect=swap_before_quarantine):
                with self.assertRaisesRegex(harness.HarnessError, "replaced VM state"):
                    harness.destroy_state(state, expected)
            quarantined = [path for path in root.iterdir() if ".state.delete-" in path.name]
            self.assertEqual(len(quarantined), 1)
            self.assertEqual((quarantined[0] / "sentinel").read_text(), "unrelated")
            self.assertTrue((stolen / "state.json").is_file())

    def test_descriptor_cleanup_never_unlinks_a_swapped_member(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            owned = root / "owned"
            owned.mkdir(mode=0o700)
            (owned / "member").write_text("selected")
            identity = harness.directory_identity(owned)
            real_rename_at = harness.rename_noreplace_at

            def swap_member(source_fd, source, target_fd, target, label):
                if source == b"member":
                    os.rename("member", "stolen", src_dir_fd=source_fd, dst_dir_fd=source_fd)
                    descriptor = os.open(
                        "member", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600,
                        dir_fd=source_fd,
                    )
                    os.write(descriptor, b"unrelated")
                    os.close(descriptor)
                return real_rename_at(source_fd, source, target_fd, target, label)

            with mock.patch.object(harness, "rename_noreplace_at", side_effect=swap_member):
                with self.assertRaisesRegex(harness.HarnessError, "cleanup file was replaced"):
                    harness.destroy_identified_directory(owned, identity, "owned directory")
            quarantined = [path for path in root.iterdir() if ".owned.delete-" in path.name]
            self.assertEqual(len(quarantined), 1)
            self.assertEqual((quarantined[0] / "stolen").read_text(), "selected")
            replacements = [path for path in quarantined[0].iterdir() if path.name.startswith(".delete-")]
            self.assertEqual(len(replacements), 1)
            self.assertEqual(replacements[0].read_text(), "unrelated")

    def test_publication_cleanup_quarantine_never_deletes_swapped_staging(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract = {"state": str(root / "state")}
            binding = harness.run_binding(contract, root / "results")
            staging = harness.safe_directory(Path(binding["staging"]), create=True)
            (staging / "owned").write_text("owned")
            identity = harness.directory_identity(staging)
            harness.write_new_private_json(
                Path(binding["journal"]),
                harness.publication_record(binding, "running", staging_identity=identity),
            )
            stolen = root / "stolen-staging"
            replacement = root / "replacement-staging"
            replacement.mkdir(mode=0o700)
            (replacement / "sentinel").write_text("unrelated")
            real_rename = harness.rename_noreplace

            def swap_before_quarantine(source, target):
                if source == staging:
                    staging.rename(stolen)
                    replacement.rename(staging)
                return real_rename(source, target)

            with mock.patch.object(harness, "rename_noreplace", side_effect=swap_before_quarantine):
                with self.assertRaisesRegex(harness.HarnessError, "replaced private result staging"):
                    harness.cleanup_publication(binding)
            quarantined = [path for path in root.iterdir() if ".clean-host-staging.delete-" in path.name]
            self.assertEqual(len(quarantined), 1)
            self.assertEqual((quarantined[0] / "sentinel").read_text(), "unrelated")
            self.assertEqual((stolen / "owned").read_text(), "owned")

    def test_early_run_setup_failure_destroys_state_and_partial_results(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_prepared_state(root)
            contract, _value, seccomp_sha = make_run_contract(root, state)
            with mock.patch.object(harness, "SECCOMP_SHA256", seccomp_sha), mock.patch.object(
                harness, "validate_flat_qcow2",
            ), mock.patch.object(
                harness, "qemu_img_create", side_effect=harness.HarnessError("simulated setup failure"),
            ):
                with self.assertRaisesRegex(harness.HarnessError, "setup failure"):
                    harness.terminal_run(contract, root / "results")
            self.assertFalse(state.exists())
            self.assertFalse((root / "results").exists())
            self.assertFalse(any(path.name.startswith(".state.terminal-") for path in root.iterdir()))

    def test_post_first_file_restart_exposes_nothing_and_cleans_exact_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_prepared_state(root)
            contract_path, contract, seccomp_sha = make_run_contract(root, state)
            results = root / "results"
            binding = harness.run_binding(contract, results)
            with mock.patch.object(harness, "validate_flat_qcow2"):
                claimed, _expected, _resumed = harness.claim_run_state(binding)
            staging = harness.safe_directory(Path(binding["staging"]), create=True)
            (staging / "acceptance-receipt.json").write_bytes(b"private partial evidence")
            harness.write_new_private_json(
                Path(binding["journal"]), harness.publication_record(
                    binding, "running", staging_identity=harness.directory_identity(staging),
                ),
            )
            self.assertFalse(results.exists())
            self.assertEqual({path.name for path in staging.iterdir()}, {"acceptance-receipt.json"})
            with mock.patch.object(harness, "SECCOMP_SHA256", seccomp_sha), mock.patch.object(
                harness, "validate_flat_qcow2",
            ):
                with self.assertRaisesRegex(harness.HarnessError, "interrupted terminal result staging"):
                    harness.terminal_run(contract_path, results)
                with self.assertRaises(FileNotFoundError):
                    harness.terminal_run(contract_path, results)
            self.assertFalse(results.exists())
            self.assertFalse(staging.exists())
            self.assertFalse(Path(binding["journal"]).exists())
            self.assertFalse(claimed.exists())

    def test_post_third_file_ready_retry_cleans_state_then_atomically_publishes_exact_set(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_prepared_state(root)
            contract_path, contract, seccomp_sha = make_run_contract(root, state)
            results = root / "results"
            frame = passing_frame(contract)
            checkpoints = []

            def create_image(image_state, name, _backing):
                (image_state / name).write_bytes(b"overlay")

            def boot(_state, _timeout, *, overlay, **_kwargs):
                return frame if overlay == "verifier.qcow2" else None

            def checkpoint(name, staging, final):
                checkpoints.append(name)
                self.assertFalse(final.exists())
                expected_count = 1 if name == "after-first-file" else 3
                self.assertEqual(len(tuple(staging.iterdir())), expected_count)

            with mock.patch.object(harness, "SECCOMP_SHA256", seccomp_sha), mock.patch.object(
                harness, "validate_flat_qcow2",
            ), mock.patch.object(harness, "qemu_img_create", side_effect=create_image), mock.patch.object(
                harness, "create_run_stage",
            ), mock.patch.object(harness, "create_verify_stage"), mock.patch.object(
                harness, "boot", side_effect=boot,
            ), mock.patch.object(harness, "publication_checkpoint", side_effect=checkpoint), mock.patch.object(
                harness, "replay_frozen_verifier",
            ):
                outcome = harness.terminal_run(contract_path, results)
            self.assertEqual(checkpoints, ["after-first-file", "after-third-file"])
            published = {path.name: path.read_bytes() for path in results.iterdir()}
            self.assertEqual(set(published), {
                "acceptance-receipt.json", "verifier.json", "evidence-manifest.json",
            })

            state = make_prepared_state(root)
            binding = harness.run_binding(contract, results)
            staging = Path(binding["staging"])
            results.rename(staging)
            with mock.patch.object(harness, "validate_flat_qcow2"):
                claimed, _expected, _resumed = harness.claim_run_state(binding)
            harness.write_new_private_json(
                Path(binding["journal"]), harness.publication_record(
                    binding, "ready", outcome, harness.directory_identity(staging),
                ),
            )
            self.assertFalse(results.exists())
            self.assertTrue(claimed.exists())
            with mock.patch.object(harness, "SECCOMP_SHA256", seccomp_sha), mock.patch.object(
                harness, "validate_flat_qcow2",
            ), mock.patch.object(harness, "replay_frozen_verifier"):
                recovered = harness.terminal_run(contract_path, results)
                recovered_again = harness.terminal_run(contract_path, results)
            self.assertEqual(recovered, outcome)
            self.assertEqual(recovered_again, outcome)
            self.assertFalse(claimed.exists())
            self.assertFalse(staging.exists())
            self.assertFalse(Path(binding["journal"]).exists())
            self.assertEqual({path.name: path.read_bytes() for path in results.iterdir()}, published)

    def test_publish_swap_after_validation_never_exposes_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            results = root / "results"
            contract = {"state": str(root / "state")}
            binding = harness.run_binding(contract, results)
            staging = harness.safe_directory(Path(binding["staging"]), create=True)
            (staging / "validated").write_text("validated")
            identity = harness.directory_identity(staging)
            outcome = {"status": "pass"}
            harness.write_new_private_json(
                Path(binding["journal"]),
                harness.publication_record(binding, "ready", outcome, identity),
            )
            stolen = root / "stolen-validated"
            replacement = root / "replacement-publication"
            replacement.mkdir(mode=0o700)
            (replacement / "sentinel").write_text("unrelated")
            real_rename = harness.rename_noreplace

            def swap_before_publication(source, target):
                if ".publish-" in source.name and target == results:
                    source.rename(stolen)
                    replacement.rename(source)
                return real_rename(source, target)

            with mock.patch.object(harness, "validate_result_set_fd", return_value=outcome), mock.patch.object(
                harness, "rename_noreplace", side_effect=swap_before_publication,
            ):
                with self.assertRaisesRegex(harness.HarnessError, "published result identity differs"):
                    harness.finish_publication(contract, binding, outcome)
            self.assertFalse(results.exists())
            self.assertEqual((stolen / "validated").read_text(), "validated")
            rejected = [path for path in root.iterdir() if ".results.rejected-" in path.name]
            self.assertEqual(len(rejected), 1)
            self.assertEqual((rejected[0] / "sentinel").read_text(), "unrelated")

    def test_state_cleanup_retry_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = make_destroyable_state(Path(temporary))
            expected = harness.state_identity(state)
            harness.destroy_state(state, expected)
            harness.destroy_state(state, expected)
            self.assertFalse(state.exists())

    def test_prepare_failure_cleans_state_and_success_intentionally_retains_it(self) -> None:
        for succeeds in (False, True):
            with self.subTest(succeeds=succeeds), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                image = root / "base.qcow2"
                image.write_bytes(b"base image")
                state = root / "state"
                tool_sha = {name: harness.file_sha256(Path(path)) for name, path in harness.TOOLS.items()}
                arguments = __import__("argparse").Namespace(
                    state=state,
                    image=image,
                    image_sha256=harness.file_sha256(image),
                    qemu_sha256=tool_sha["qemu"],
                    qemu_img_sha256=tool_sha["qemu_img"],
                    controld_uid=1201,
                    controld_gid=1201,
                )
                proof = {"qemu_version": "test", "tool_sha256": tool_sha}
                frame = {
                    "schema_version": harness.FRAME_SCHEMA,
                    "phase": "ceremony",
                    "challenge": "unused",
                    "outcome": "pass",
                    "public_binding": {},
                    "raw_key_absence": True,
                }

                def boot(_state, _timeout, **_kwargs):
                    if not succeeds:
                        raise harness.HarnessError("simulated prepare failure")
                    marker = harness.load_json(state / "state.json")
                    return {**frame, "challenge": marker["challenge"]}

                def create_image(image_state, name, _backing):
                    (image_state / name).write_bytes(b"overlay")

                with mock.patch.object(harness, "capabilities", return_value=proof), mock.patch.object(
                    harness, "validate_flat_qcow2",
                ), mock.patch.object(harness, "qemu_img_create", side_effect=create_image), mock.patch.object(
                    harness, "make_iso",
                ), mock.patch.object(harness, "make_seed"), mock.patch.object(
                    harness, "boot", side_effect=boot,
                ), mock.patch.object(harness, "flatten_ceremony", return_value="3" * 64):
                    if succeeds:
                        outcome = harness.prepare(arguments)
                        self.assertEqual(outcome["status"], "prepared")
                    else:
                        with self.assertRaisesRegex(harness.HarnessError, "prepare failure"):
                            harness.prepare(arguments)
                self.assertEqual(state.exists(), succeeds)

    def test_prepare_create_write_and_marker_chmod_failures_leave_no_state(self) -> None:
        for boundary in ("create", "write", "chmod"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                image = root / "base.qcow2"
                image.write_bytes(b"base image")
                state = root / "state"
                tool_sha = {name: harness.file_sha256(Path(path)) for name, path in harness.TOOLS.items()}
                arguments = __import__("argparse").Namespace(
                    state=state, image=image, image_sha256=harness.file_sha256(image),
                    qemu_sha256=tool_sha["qemu"], qemu_img_sha256=tool_sha["qemu_img"],
                    controld_uid=1201, controld_gid=1201,
                )
                proof = {"qemu_version": "test", "tool_sha256": tool_sha}
                real_mkdir = Path.mkdir
                real_write = Path.write_bytes
                real_chmod = Path.chmod

                def mkdir(path, *args, **kwargs):
                    if boundary == "create" and path == state:
                        raise OSError("simulated directory creation failure")
                    return real_mkdir(path, *args, **kwargs)

                def write(path, raw):
                    if boundary == "write" and path == state / "state.json":
                        raise OSError("simulated marker write failure")
                    return real_write(path, raw)

                def chmod(path, mode, *args, **kwargs):
                    if boundary == "chmod" and path == state / "state.json" and mode == 0o400:
                        raise OSError("simulated marker chmod failure")
                    return real_chmod(path, mode, *args, **kwargs)

                with mock.patch.object(harness, "capabilities", return_value=proof), mock.patch.object(
                    Path, "mkdir", autospec=True, side_effect=mkdir,
                ), mock.patch.object(Path, "write_bytes", autospec=True, side_effect=write), mock.patch.object(
                    Path, "chmod", autospec=True, side_effect=chmod,
                ):
                    with self.assertRaisesRegex(OSError, "simulated"):
                        harness.prepare(arguments)
                self.assertFalse(state.exists())

    def test_post_candidate_drift_blocks_verifier_and_destroys_state(self) -> None:
        cases = (
            ("frozen-assets/receipt_verifier.py", "frozen harness asset"),
            ("trusted.qcow2", "trusted ceremony image"),
        )
        for relative, expected_error in cases:
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                state = make_prepared_state(root)
                results = root / "results"
                boots = []

                def create_image(image_state, name, _backing):
                    (image_state / name).write_bytes(b"overlay")

                def hostile_boot(image_state, _timeout, *, overlay, **_kwargs):
                    boots.append(overlay)
                    if overlay == "candidate.qcow2":
                        target = image_state / relative
                        target.chmod(0o600)
                        target.write_bytes(b"hostile")
                        return None
                    self.fail("verifier booted after trusted verifier drift")

                with mock.patch.object(harness, "validate_flat_qcow2"), mock.patch.object(
                    harness, "qemu_img_create", side_effect=create_image,
                ), mock.patch.object(harness, "create_run_stage"), mock.patch.object(
                    harness, "boot", side_effect=hostile_boot,
                ):
                    with self.assertRaisesRegex(harness.HarnessError, expected_error):
                        harness.run_vm({}, state, {}, b"{}\n", b"{}\n", results)
                self.assertEqual(boots, ["candidate.qcow2"])
                self.assertFalse(state.exists())
                self.assertFalse(results.exists())

    def test_existing_results_setup_failure_destroys_state_but_preserves_results(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_prepared_state(root)
            contract, _value, seccomp_sha = make_run_contract(root, state)
            results = root / "results"
            results.mkdir(mode=0o700)
            sentinel = results / "owned-by-caller"
            sentinel.write_text("keep")
            with mock.patch.object(harness, "SECCOMP_SHA256", seccomp_sha), mock.patch.object(
                harness, "validate_flat_qcow2",
            ):
                with self.assertRaises(FileExistsError):
                    harness.terminal_run(contract, results)
            self.assertFalse(state.exists())
            self.assertEqual(sentinel.read_text(), "keep")

    def test_cleanup_failure_removes_results_and_cannot_report_success(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_destroyable_state(root)
            (state / "candidate.qcow2").write_bytes(b"residue")
            results = root / "results"
            cleanup_error = harness.HarnessError("simulated state cleanup failure")
            with mock.patch.object(harness, "destroy_state", side_effect=cleanup_error):
                with self.assertRaisesRegex(harness.HarnessError, "terminal run cleanup failed") as caught:
                    harness.run_vm({}, state, {}, b"", b"", results)
            self.assertIsInstance(caught.exception.__cause__, harness.HarnessError)
            self.assertIn("prior VM run residue", str(caught.exception.__cause__))
            self.assertFalse(results.exists())
            self.assertTrue(state.exists())

    def test_success_publishes_evidence_only_after_state_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_destroyable_state(root)
            results = root / "results"
            candidate_sha = "2" * 40
            scenario_sha = "3" * 64
            contract = {"candidate_sha": candidate_sha, "scenario": {"sha256": scenario_sha}}
            records = {
                name: [("payload", 0o400, name.encode())]
                for name in harness.PACKAGE_NAMES
            }
            receipt = {
                "schema_version": "buzz-ci-capacity-one-acceptance-receipt/v2",
                "outcome": "pass", "scenario_sha256": scenario_sha,
                "integrated_candidate_sha": candidate_sha, "run_id": "4" * 32,
                "checks": [], "zero_transition": {},
            }
            verifier = {"outcome": "pass", "status": "verified"}
            proof = {
                "configs_sha256": "5" * 64, "units_sha256": "6" * 64,
                "sockets_absent": True, "processes_absent": True,
                "encrypted_credentials_absent": True, "relay_residue_absent": True,
            }
            frame = {
                "schema_version": harness.FRAME_SCHEMA, "phase": "run",
                "challenge": "1" * 64, "outcome": "pass",
                "receipt_base64": base64.b64encode(harness.canonical(receipt)).decode(),
                "verifier_base64": base64.b64encode(harness.canonical(verifier)).decode(),
                "dormant_proof": proof,
            }

            def create_image(image_state, name, _backing):
                (image_state / name).write_bytes(b"overlay")

            def boot(_state, _timeout, *, overlay, **_kwargs):
                return frame if overlay == "verifier.qcow2" else None

            with mock.patch.object(harness, "qemu_img_create", side_effect=create_image), mock.patch.object(
                harness, "create_run_stage",
            ), mock.patch.object(harness, "create_verify_stage"), mock.patch.object(
                harness, "validate_prepared_state", return_value=state_record(),
            ), mock.patch.object(harness, "boot", side_effect=boot), mock.patch.object(
                harness, "replay_frozen_verifier",
            ):
                outcome = harness.run_vm(contract, state, records, b"{}\n", b"{}\n", results)
            self.assertEqual(outcome["status"], "pass")
            self.assertTrue(outcome["vm_state_absent"])
            self.assertFalse(state.exists())
            self.assertEqual(
                {path.name for path in results.iterdir()},
                {"acceptance-receipt.json", "verifier.json", "evidence-manifest.json"},
            )
            self.assertEqual((results / "acceptance-receipt.json").read_bytes(), harness.canonical(receipt))

    def test_backed_or_external_data_qcow2_is_rejected(self) -> None:
        base = {"format": "qcow2", "virtual-size": 1024 * 1024, "backing-filename": "parent.qcow2"}
        with mock.patch.object(harness, "qemu_image_info", return_value=base):
            with self.assertRaisesRegex(harness.HarnessError, "backing"):
                harness.validate_flat_qcow2(Path("/unused"), "base.qcow2")
        external = {
            "format": "qcow2", "virtual-size": 1024 * 1024,
            "format-specific": {"data": {"data-file": "payload.raw"}},
        }
        with mock.patch.object(harness, "qemu_image_info", return_value=external):
            with self.assertRaisesRegex(harness.HarnessError, "data file"):
                harness.validate_flat_qcow2(Path("/unused"), "base.qcow2")

    def test_fixed_transfer_rejects_digest_padding_bounds_and_extra_secret(self) -> None:
        value = {
            "schema_version": "buzz-ci-clean-host-e2e-pending-evidence/v2",
            "challenge": "1" * 64,
        }
        raw = guest.encode_transfer(value)
        self.assertEqual(guest.decode_transfer(raw), value)
        for malformed in (
            raw[:-1] + b"x",
            raw[:len(guest.TRANSFER_MAGIC) + 4] + bytes([raw[len(guest.TRANSFER_MAGIC) + 4] ^ 1]) + raw[len(guest.TRANSFER_MAGIC) + 5:],
            raw[:-1],
        ):
            with self.assertRaises(guest.GuestError):
                guest.decode_transfer(malformed)
        with mock.patch.object(guest, "MAX_COMMAND", 1):
            with self.assertRaisesRegex(guest.GuestError, "payload exceeds"):
                guest.encode_transfer({"secret": "must-not-cross"})

    def test_transfer_file_capacity_and_mode_are_fixed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            harness.create_transfer(state)
            harness.validate_transfer(state)
            with (state / "transfer.raw").open("r+b") as stream:
                stream.truncate(harness.TRANSFER_SIZE - 1)
            with self.assertRaisesRegex(harness.HarnessError, "fixed-capacity"):
                harness.validate_transfer(state)

    def test_pending_transfer_rejects_extra_secret_before_verification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary) / "stage"
            state = Path(temporary) / "state"
            stage.mkdir()
            state.mkdir()
            scenario = b"{}\n"
            (stage / "scenario.json").write_bytes(scenario)
            phase = {
                "challenge": "1" * 64, "candidate_sha": "2" * 40,
                "scenario_sha256": hashlib.sha256(scenario).hexdigest(),
            }
            pending = {
                "schema_version": "buzz-ci-clean-host-e2e-pending-evidence/v2",
                "challenge": phase["challenge"], "candidate_sha": phase["candidate_sha"],
                "scenario_sha256": phase["scenario_sha256"], "receipt_base64": "e30=",
                "dormant_proof": {}, "secret": "must-not-cross",
            }
            original_state = guest.STATE_ROOT
            guest.STATE_ROOT = state
            try:
                with mock.patch.object(guest, "read_transfer", return_value=pending):
                    with self.assertRaisesRegex(guest.GuestError, "binding differs"):
                        guest.verify_pending(phase, stage)
            finally:
                guest.STATE_ROOT = original_state

    def test_final_frame_rejects_candidate_cross_binding_drift(self) -> None:
        contract = {"candidate_sha": "1" * 40, "scenario": {"sha256": "2" * 64}}
        receipt = {"outcome": "pass", "integrated_candidate_sha": "3" * 40, "scenario_sha256": "2" * 64}
        verifier = {"status": "pass"}
        frame = {
            "schema_version": harness.FRAME_SCHEMA, "phase": "run", "challenge": "4" * 64,
            "outcome": "pass", "receipt_base64": base64.b64encode(harness.canonical(receipt)).decode(),
            "verifier_base64": base64.b64encode(harness.canonical(verifier)).decode(),
            "dormant_proof": {"processes_absent": True},
        }
        with self.assertRaisesRegex(harness.HarnessError, "identity"):
            harness.validate_final_frame(frame, contract, "4" * 64)

    def test_final_frame_rejects_extra_receipt_and_verdict_fields(self) -> None:
        contract = {"candidate_sha": "1" * 40, "scenario": {"sha256": "2" * 64}}
        proof = {
            "configs_sha256": "3" * 64, "units_sha256": "4" * 64,
            "sockets_absent": True, "processes_absent": True,
            "encrypted_credentials_absent": True, "relay_residue_absent": True,
        }
        receipt = {
            "schema_version": "buzz-ci-capacity-one-acceptance-receipt/v2",
            "outcome": "pass", "scenario_sha256": "2" * 64,
            "integrated_candidate_sha": "1" * 40, "run_id": "5" * 32,
            "checks": [], "zero_transition": {}, "secret": "do-not-export",
        }
        verifier = {"outcome": "pass", "status": "verified", "secret": "do-not-export"}
        frame = {
            "schema_version": harness.FRAME_SCHEMA, "phase": "run", "challenge": "6" * 64,
            "outcome": "pass", "receipt_base64": base64.b64encode(harness.canonical(receipt)).decode(),
            "verifier_base64": base64.b64encode(harness.canonical(verifier)).decode(),
            "dormant_proof": proof,
        }
        with self.assertRaisesRegex(harness.HarnessError, "identity"):
            harness.validate_final_frame(frame, contract, "6" * 64)


class RelayCryptoTests(unittest.TestCase):
    def test_bip340_signature_and_mutation(self) -> None:
        message = hashlib.sha256(b"message").digest()
        public, signature = schnorr_sign(message, 3)
        self.assertTrue(relay.schnorr_verify(message, public, signature))
        mutated = signature[:-2] + ("00" if signature[-2:] != "00" else "01")
        self.assertFalse(relay.schnorr_verify(message, public, mutated))

    def test_nip98_binds_signature_key_url_method_payload_and_time(self) -> None:
        now = 1_800_000_000
        body = b"fixture"
        url = "https://relay.test.invalid:3443/events"
        header = nip98(7, "POST", url, body, now)
        public = signed_event(7, 1, [], "", now)["pubkey"]
        relay.verify_nip98(header, "POST", url, body, public, now=now)
        cases = (
            ("GET", url, body, public, now),
            ("POST", url + "?x=1", body, public, now),
            ("POST", url, b"other", public, now),
            ("POST", url, body, "f" * 64, now),
            ("POST", url, body, public, now + 61),
        )
        for method, candidate_url, candidate_body, candidate_public, candidate_now in cases:
            with self.assertRaises(relay.RelayError):
                relay.verify_nip98(header, method, candidate_url, candidate_body, candidate_public, now=candidate_now)

    def test_published_event_requires_real_id_and_signature(self) -> None:
        event = signed_event(11, 46100, [["h", "channel"]], "{}", 1_800_000_000)
        self.assertEqual(relay.verify_event(event), event)
        event["content"] = "drift"
        with self.assertRaisesRegex(relay.RelayError, "signature"):
            relay.verify_event(event)


if __name__ == "__main__":
    unittest.main()

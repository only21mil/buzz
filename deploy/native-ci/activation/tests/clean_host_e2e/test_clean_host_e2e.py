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
        self.assertNotIn("--ro-bind /home", joined)
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

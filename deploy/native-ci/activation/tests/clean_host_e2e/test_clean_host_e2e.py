#!/usr/bin/env python3
"""Adversarial checks for the isolated clean-host VM harness."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
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
HOST_TOOLS = harness.TOOLS.copy()
TEST_TOOL_DIRECTORY: tempfile.TemporaryDirectory[str] | None = None


def setUpModule() -> None:
    global TEST_TOOL_DIRECTORY
    TEST_TOOL_DIRECTORY = tempfile.TemporaryDirectory(prefix="buzzci-clean-host-tools.")
    root = Path(TEST_TOOL_DIRECTORY.name)
    tools = {}
    for name in HOST_TOOLS:
        path = root / name
        path.write_bytes(("deterministic clean-host test tool: " + name + "\n").encode())
        path.chmod(0o500)
        tools[name] = str(path)
    harness.TOOLS = tools


def tearDownModule() -> None:
    harness.TOOLS = HOST_TOOLS.copy()
    if TEST_TOOL_DIRECTORY is not None:
        TEST_TOOL_DIRECTORY.cleanup()


def state_record(trusted_digest: str = "1" * 64) -> dict[str, object]:
    digest = "1" * 64
    assets = {name: digest for name in harness.FROZEN_ASSETS}
    assets["harness.py"] = harness.current_harness_sha256()
    assets["timing-contract.json"] = harness.timing_asset_sha256()
    return {
        "schema_version": harness.STATE_SCHEMA,
        "challenge": digest,
        "image_sha256": digest,
        "qemu_sha256": digest,
        "qemu_img_sha256": digest,
        "qemu_version": "test",
        "tool_sha256": {name: digest for name in harness.TOOLS},
        "harness_sha256": harness.current_harness_sha256(),
        "harness_asset_sha256": assets,
        "timing_asset_sha256": harness.timing_asset_sha256(),
        "timing": harness.TIMING_CONTRACT,
        "timing_sha256": harness.timing_sha256(),
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
    state.mkdir(mode=0o700)
    frozen.mkdir(mode=0o700)
    asset_digests = {}
    for name in harness.FROZEN_ASSETS:
        path = frozen / name
        path.write_bytes(
            Path(harness.__file__).read_bytes()
            if name == "harness.py" else
            (HERE / "timing-contract.json").read_bytes()
            if name == "timing-contract.json" else ("trusted-" + name).encode()
        )
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
        "harness_sha256": harness.current_harness_sha256(),
        "harness_asset_sha256": asset_digests,
        "timing_asset_sha256": harness.timing_asset_sha256(),
    })
    (state / "state.json").write_bytes(harness.canonical(record))
    return state


def make_run_contract(parent: Path, state: Path) -> tuple[Path, dict[str, object], str]:
    candidate = HERE.parents[4]
    candidate_sha = harness.bounded([
        "/usr/bin/git", "-C", str(candidate), "stash", "create", "clean-host-unit-test",
    ]).decode().strip()
    if not candidate_sha:
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
    scenario.write_bytes(harness.canonical({
        "driver": {"timeout_seconds": harness.TIMING_CONTRACT["leaf_seconds"]["driver_operation"]},
    }))
    seccomp = parent / "seccomp.json"
    seccomp.write_bytes(b'{"defaultAction":"SCMP_ACT_ERRNO"}\n')
    seccomp_sha = harness.file_sha256(seccomp)
    value = {
        "schema_version": harness.SCHEMA,
        "state": str(state),
        "candidate_root": str(candidate),
        "candidate_sha": candidate_sha,
        "harness_sha256": harness.current_harness_sha256(),
        "timing_asset_sha256": harness.timing_asset_sha256(),
        "timing": harness.TIMING_CONTRACT,
        "timing_sha256": harness.timing_sha256(),
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


def progress_frame(
    boot: str, sequence: int, phase: str, event: str, elapsed_ms: int,
    **extra: object,
) -> bytes:
    value = {
        "schema_version": harness.PROGRESS_SCHEMA,
        "boot": boot,
        "sequence": sequence,
        "phase": phase,
        "event": event,
        "elapsed_ms": elapsed_ms,
        **extra,
    }
    payload = harness.canonical(value)
    return struct.pack(">I", len(payload)) + payload + hashlib.sha256(payload).digest()


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
        self.assertIn("name=buzzci.progress", candidate_command)
        self.assertNotIn("name=buzzci.evidence", candidate_command)
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
                (str(state / "progress.bin"), "/work/progress.bin"),
                (str(state / "transfer.raw"), "/work/transfer.raw"),
            ],
        )
        self.assertEqual(
            mount_pairs(verifier, "--bind"),
            [
                (str(state / "verifier.qcow2"), "/work/verifier.qcow2"),
                (str(state / "progress.bin"), "/work/progress.bin"),
                (str(state / "evidence.bin"), "/work/evidence.bin"),
            ],
        )
        for protected in (
            "trusted.qcow2", "state.json", "public-binding.json",
            *[f"frozen-assets/{name}" for name in harness.FROZEN_ASSETS],
        ):
            self.assertNotIn((str(state / protected), f"/work/{protected}"), mount_pairs(candidate, "--bind"))

    def test_bubblewrap_rejects_hostile_writes_to_verifier_inputs(self) -> None:
        kvm = Path("/dev/kvm")
        if (
            not Path(HOST_TOOLS["bwrap"]).is_file()
            or not kvm.exists()
            or not stat.S_ISCHR(kvm.stat().st_mode)
            or not os.access(kvm, os.R_OK | os.W_OK)
        ):
            self.skipTest("clean-host bubblewrap+KVM boundary is unavailable")
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
            with mock.patch.dict(harness.TOOLS, {"bwrap": HOST_TOOLS["bwrap"]}):
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
                    harness.boot(
                        state, harness.watchdog_seconds("verifier"),
                        overlay="verifier.qcow2", evidence_expected=True,
                    )

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

    def test_host_capability_proof_is_exact_when_supported(self) -> None:
        with mock.patch.dict(harness.TOOLS, HOST_TOOLS, clear=True):
            try:
                proof = harness.capabilities()
            except harness.HarnessError as error:
                if str(error).startswith("safe KVM capability unavailable:"):
                    self.skipTest(str(error))
                raise
        self.assertEqual((proof["boundary"], proof["network"]), ("bubblewrap+qemu-kvm", "unshared-and-no-nic"))

    def test_missing_tool_fails_closed(self) -> None:
        original = harness.TOOLS["qemu"]
        harness.TOOLS["qemu"] = "/definitely/absent/qemu"
        try:
            with self.assertRaisesRegex(
                harness.HarnessError,
                "safe KVM capability unavailable: /definitely/absent/qemu",
            ):
                harness.capabilities()
        finally:
            harness.TOOLS["qemu"] = original

    def test_unit_tool_fixture_is_private_regular_and_complete(self) -> None:
        self.assertEqual(set(harness.TOOLS), set(HOST_TOOLS))
        for path in harness.TOOLS.values():
            metadata = Path(path).stat()
            self.assertTrue(stat.S_ISREG(metadata.st_mode))
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o500)

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
                keywords = {"inventory": False} if module is guest else {}
                function(["/usr/bin/sleep", "30"], timeout=10, **keywords)
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

    def test_guest_ca_backend_selects_debian_or_fedora_and_rejects_uncertainty(self) -> None:
        cases = (
            (
                "update-ca-certificates",
                Path("/usr/local/share/ca-certificates/buzzci-disposable-e2e.crt"),
                ("update-ca-certificates",),
                ("update-ca-certificates", "--fresh"),
            ),
            (
                "update-ca-trust",
                Path("/etc/pki/ca-trust/source/anchors/buzzci-disposable-e2e.crt"),
                ("update-ca-trust", "extract"),
                ("update-ca-trust", "extract"),
            ),
        )
        with mock.patch.object(Path, "is_dir", return_value=True):
            for tool, anchor, install, remove in cases:
                with self.subTest(tool=tool), mock.patch.object(
                    guest.shutil, "which", side_effect=lambda name, selected=tool: "/usr/bin/" + name if name == selected else None,
                ):
                    self.assertEqual(guest.ca_backend(), (anchor, install, remove))
            for available in (set(), {case[0] for case in cases}):
                with self.subTest(available=available), mock.patch.object(
                    guest.shutil, "which", side_effect=lambda name, selected=available: "/usr/bin/" + name if name in selected else None,
                ):
                    with self.assertRaisesRegex(guest.GuestError, "absent or ambiguous"):
                        guest.ca_backend()

    def test_guest_ca_backend_rejects_missing_anchor_directory(self) -> None:
        with mock.patch.object(
            guest.shutil, "which", side_effect=lambda name: "/usr/bin/" + name if name == "update-ca-trust" else None,
        ), mock.patch.object(Path, "is_dir", return_value=False):
            with self.assertRaisesRegex(guest.GuestError, "anchor directory is absent"):
                guest.ca_backend()

    def test_evidence_device_accepts_only_safe_relative_udev_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dev = Path(temporary) / "dev"
            ports = dev / "virtio-ports"
            ports.mkdir(parents=True)
            target = dev / "vport12p34"
            target.write_bytes(b"")
            link = ports / "buzzci.evidence"
            link.symlink_to("../vport12p34")
            original = guest.EVIDENCE_DEVICE
            guest.EVIDENCE_DEVICE = link
            real_open = os.open
            opened: list[tuple[object, int, int | None]] = []

            def recording_open(path, flags, *args, dir_fd=None, **kwargs):
                opened.append((path, flags, dir_fd))
                return real_open(path, flags, *args, dir_fd=dir_fd, **kwargs)

            fake_character = os.stat_result((stat.S_IFCHR | 0o600, 0, 0, 1, 0, 0, 0, 0, 0, 0))
            try:
                with mock.patch.object(guest.os, "open", side_effect=recording_open), mock.patch.object(
                    guest.os, "fstat", return_value=fake_character,
                ):
                    fd = guest.open_evidence_device()
                os.close(fd)
            finally:
                guest.EVIDENCE_DEVICE = original
            target_opens = [call for call in opened if call[0] == "vport12p34"]
            self.assertEqual(len(target_opens), 1)
            self.assertIsNotNone(target_opens[0][2])
            self.assertTrue(target_opens[0][1] & os.O_NOFOLLOW)

    def test_evidence_device_rejects_unsafe_link_targets_and_non_character_device(self) -> None:
        rejected = (
            "/dev/vport0p1", "vport0p1", "../../vport0p1", "../vport0p1/extra",
            "../vport0p", "../vportXpY", "../other0p1",
        )
        with tempfile.TemporaryDirectory() as temporary:
            dev = Path(temporary) / "dev"
            ports = dev / "virtio-ports"
            ports.mkdir(parents=True)
            target = dev / "vport0p1"
            target.write_bytes(b"not a device")
            link = ports / "buzzci.evidence"
            original = guest.EVIDENCE_DEVICE
            guest.EVIDENCE_DEVICE = link
            try:
                for value in rejected:
                    with self.subTest(target=value):
                        link.unlink(missing_ok=True)
                        link.symlink_to(value)
                        with self.assertRaisesRegex(guest.GuestError, "link target is unsafe"):
                            guest.open_evidence_device()
                link.unlink()
                link.symlink_to("../vport0p1")
                with self.assertRaisesRegex(guest.GuestError, "not a character device"):
                    guest.open_evidence_device()
            finally:
                guest.EVIDENCE_DEVICE = original

    def test_emit_completes_partial_writes_without_fsyncing_character_device(self) -> None:
        chunks: list[bytes] = []

        def partial_write(_fd, view):
            count = min(7, len(view))
            chunks.append(bytes(view[:count]))
            return count

        value = {"phase": "verify", "outcome": "pass"}
        payload = guest.canonical({"schema_version": guest.FRAME_SCHEMA, **value})
        expected = struct.pack(">I", len(payload)) + payload + hashlib.sha256(payload).digest()
        with mock.patch.object(guest, "open_evidence_device", return_value=91), mock.patch.object(
            guest.os, "write", side_effect=partial_write,
        ), mock.patch.object(guest.os, "close") as close, mock.patch.object(guest.os, "fsync") as fsync:
            guest.emit(value)
        self.assertEqual(b"".join(chunks), expected)
        close.assert_called_once_with(91)
        fsync.assert_not_called()

    def test_emit_closes_device_on_zero_progress_or_write_error(self) -> None:
        for result, message in ((0, "made no progress"), (OSError("write failed"), "write failed")):
            with self.subTest(message=message), mock.patch.object(
                guest, "open_evidence_device", return_value=92,
            ), mock.patch.object(guest.os, "write") as write, mock.patch.object(guest.os, "close") as close:
                if isinstance(result, BaseException):
                    write.side_effect = result
                else:
                    write.return_value = result
                with self.assertRaisesRegex(guest.GuestError, message):
                    guest.emit({"phase": "verify", "outcome": "pass"})
                close.assert_called_once_with(92)
        with mock.patch.object(guest, "MAX_JSON", 1), mock.patch.object(
            guest, "open_evidence_device",
        ) as open_device:
            with self.assertRaisesRegex(guest.GuestError, "frame exceeds bound"):
                guest.emit({"phase": "verify", "outcome": "pass"})
            open_device.assert_not_called()

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


class TimingAndProgressTests(unittest.TestCase):
    def test_timing_source_recursively_matches_actual_leaf_counts(self) -> None:
        harness.validate_timing_contract()
        timing = harness.TIMING_CONTRACT
        terms = timing["phase_terms"]
        inventory = timing["command_inventory"]
        expected_stages = json.loads((HERE.parents[2] / "acceptance/expected-stages.json").read_bytes())
        scenario = json.loads((HERE.parents[2] / "acceptance/scenario.template.json").read_bytes())
        self.assertEqual(terms["canary"]["driver_operation"], len(expected_stages))
        self.assertEqual(timing["leaf_seconds"]["driver_operation"], scenario["driver"]["timeout_seconds"])
        self.assertEqual(inventory["ceremony"]["command_default"], len(guest.KEY_NAMES) * 4 + 5)
        self.assertEqual(inventory["install"]["command_default"], 3 + len(guest.UNITS) * 2 + 1 + 5)
        self.assertEqual(inventory["controller_stage"]["command_default"], len(guest.UNITS))
        self.assertEqual(inventory["cleanup"]["unit_stop"], len(guest.UNITS) + 1)
        self.assertEqual(inventory["cleanup"]["command_default"], len(guest.UNITS) + 4)
        self.assertEqual(inventory["cleanup"]["guest_command_reap"], len(guest.UNITS) * 2 + 5)
        self.assertEqual(json.loads((HERE / "timing-contract.json").read_bytes()), timing)
        schema = json.loads((HERE / "contract.schema.json").read_bytes())
        self.assertEqual(schema["properties"]["timing"]["const"], timing)
        self.assertEqual(guest.TIMING_CONTRACT, timing)

    def test_command_call_mutations_fail_exact_phase_inventory(self) -> None:
        source = Path(guest.__file__).read_text()
        self.assertEqual(source.count("inventory=False"), 1)
        self.assertIn('"openssl", "s_client"', source)
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            guest, "SCRATCH_ROOT", Path(temporary),
        ), mock.patch.object(guest.subprocess, "Popen") as popen, mock.patch.object(
            guest, "reap_process_group",
        ):
            popen.return_value.poll.return_value = 0
            for phase in ("ceremony", "install", "controller_stage", "cleanup"):
                with self.subTest(phase=phase):
                    guest._ACTIVE_PHASE = phase
                    guest._PHASE_DEADLINE = None
                    guest._OBSERVED_COMMAND_TERMS = dict(
                        guest.TIMING_CONTRACT["command_inventory"][phase],
                    )
                    guest.command(["/usr/bin/true"], allow_failure=True)
                    with self.assertRaisesRegex(guest.GuestError, f"inventory differs: {phase}"):
                        guest.verify_command_inventory()
        guest.abandon_command_inventory()

    def test_canary_stage_mutations_change_nested_bound(self) -> None:
        stages = json.loads((HERE.parents[2] / "acceptance/expected-stages.json").read_bytes())

        def operations(candidate_stages: list[str]) -> int:
            return len(candidate_stages)

        declared = harness.TIMING_CONTRACT["phase_terms"]["canary"]["driver_operation"]
        self.assertEqual(operations(stages), declared)
        self.assertNotEqual(operations([*stages, "mutated_stage"]), declared)
        self.assertNotEqual(operations(stages[:-1]), declared)

    def test_watchdog_boundaries_cover_legal_sequences_cleanup_poweroff_and_reap(self) -> None:
        expected = {"ceremony": 1130, "candidate": 5472, "verifier": 320}
        for role, phases in harness.TIMING_CONTRACT["role_phases"].items():
            legal_boundary = sum(harness.phase_seconds(phase) for phase in phases)
            complete_boundary = legal_boundary + harness.REAP_TIMEOUT
            self.assertEqual(harness.watchdog_seconds(role), complete_boundary)
            self.assertLess(harness.watchdog_seconds(role) - 1, complete_boundary)
            self.assertEqual(harness.watchdog_seconds(role), expected[role])
        canary_inner = 13 * harness.TIMING_CONTRACT["leaf_seconds"]["driver_operation"]
        self.assertEqual(guest.canary_command_seconds(), canary_inner + 30)
        self.assertGreater(harness.phase_seconds("canary"), guest.canary_command_seconds() + 10)
        self.assertGreater(harness.phase_seconds("ceremony"), 21 * 30 + 21 * 10)
        self.assertGreater(harness.phase_seconds("install"), 35 * 30 + 36 * 10 + 12)
        self.assertGreater(harness.phase_seconds("controller_stage"), 120 + 13 * 30 + 14 * 10)
        self.assertGreater(harness.phase_seconds("cleanup"), 17 * 30 + 14 * 10 + 31 * 10)

    def test_inner_timeout_is_recorded_before_rollback_and_cleanup(self) -> None:
        events: list[tuple[str, str]] = []
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            guest, "SCRATCH_ROOT", Path(temporary),
        ), mock.patch.object(
            guest, "emit_progress", side_effect=lambda phase, event="start": events.append((phase, event)),
        ), mock.patch.object(
            guest.time, "monotonic", side_effect=[0.0, 0.0, 0.0, 1831.0, 1831.0, 1831.0]
        ), mock.patch.object(guest.subprocess, "Popen") as popen, mock.patch.object(
            guest, "reap_process_group",
        ):
            process = popen.return_value
            process.poll.return_value = None
            guest._ACTIVE_PHASE = None
            guest._PHASE_DEADLINE = None
            guest.begin_phase("canary")
            with self.assertRaisesRegex(guest.GuestError, "timed out"):
                guest.command(
                    ["/usr/libexec/buzz-ci-capacity-one-canary"],
                    timeout=guest.canary_command_seconds(),
                )
            guest.abandon_command_inventory()
            guest.begin_phase("rollback")
            guest.record_command_timing({"rollback": 1})
            guest.begin_phase("cleanup")
        self.assertEqual(
            events,
            [("canary", "start"), ("canary", "timeout"), ("rollback", "start"), ("cleanup", "start")],
        )

    def test_progress_schema_order_caps_truncation_and_secret_fields(self) -> None:
        valid = b"".join((
            progress_frame("candidate", 0, "guest_started", "start", 1),
            progress_frame("candidate", 1, "install", "start", 2),
            progress_frame("candidate", 2, "canary", "start", 3),
            progress_frame("candidate", 3, "canary", "timeout", 613_000),
            progress_frame("candidate", 4, "rollback", "start", 613_001),
            progress_frame("candidate", 5, "cleanup", "start", 613_002),
        ))
        parsed = harness.parse_progress(valid, "candidate")
        self.assertEqual(parsed["status"], "valid")
        self.assertEqual(len(parsed["records"]), 6)
        self.assertEqual(harness.parse_progress(b"", "candidate")["status"], "missing")
        self.assertEqual(harness.parse_progress(valid[:-1], "candidate")["status"], "invalid")
        tampered = bytearray(valid)
        tampered[-1] ^= 1
        self.assertEqual(harness.parse_progress(bytes(tampered), "candidate")["status"], "invalid")
        stale = progress_frame("candidate", 0, "canary", "start", 5) + progress_frame(
            "candidate", 1, "install", "start", 6,
        )
        self.assertEqual(harness.parse_progress(stale, "candidate")["status"], "invalid")
        secret = progress_frame("candidate", 0, "guest_started", "start", 1, private_key="forbidden")
        self.assertEqual(harness.parse_progress(secret, "candidate")["status"], "invalid")
        too_many = b"".join(
            progress_frame("candidate", sequence, "install", "start", sequence)
            for sequence in range(harness.MAX_PROGRESS_RECORDS + 1)
        )
        self.assertEqual(harness.parse_progress(too_many, "candidate")["status"], "invalid")

    def test_host_error_names_boot_inner_and_cleanup_timeouts(self) -> None:
        missing = harness.progress_failure(
            "verifier", {"status": "missing", "records": []}, timed_out=True,
        )
        self.assertIn("verifier boot_cloud_init watchdog timeout", str(missing))
        for phase in (
            "install", "controller_stage", "canary", "receipt_verifier", "rollback", "cleanup",
        ):
            raw = progress_frame("candidate", 0, phase, "start", 1) + progress_frame(
                "candidate", 1, phase, "timeout", 2,
            )
            error = harness.progress_failure(
                "candidate", harness.parse_progress(raw, "candidate"), timed_out=False,
            )
            self.assertIn(f"candidate {phase} inner timeout", str(error))

    def test_prepared_harness_drift_fails_before_vm_reuse(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = make_prepared_state(Path(temporary))
            with mock.patch.object(harness, "current_harness_sha256", return_value="f" * 64):
                with self.assertRaisesRegex(harness.HarnessError, "prepared harness"):
                    harness.validate_prepared_state(state)

    def test_candidate_timing_asset_only_drift_fails_before_vm(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_prepared_state(root)
            contract_path, _contract, _seccomp = make_run_contract(root, state)
            real_bounded = harness.bounded
            timing_probes = 0

            def bounded(argv, **keywords):
                nonlocal timing_probes
                if argv[:4] == ["/usr/bin/git", "-C", str(HERE.parents[4]), "show"] and str(argv[4]).endswith("timing-contract.json"):
                    timing_probes += 1
                    mutated = json.loads((HERE / "timing-contract.json").read_bytes())
                    mutated["leaf_seconds"]["phase_margin"] += 1
                    return harness.canonical(mutated)
                return real_bounded(argv, **keywords)

            with mock.patch.object(harness, "bounded", side_effect=bounded), mock.patch.object(
                harness, "validate_flat_qcow2",
            ), mock.patch.object(
                harness, "boot",
            ) as boot:
                with self.assertRaisesRegex(harness.HarnessError, "candidate commit timing asset binding"):
                    harness.validate_contract(contract_path)
            self.assertEqual(timing_probes, 1)
            boot.assert_not_called()

    def test_seed_contract_uses_distinct_instances_stage_mount_and_poweroff(self) -> None:
        observed: list[tuple[str, str]] = []
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)

            def cloud_localds(_argv, **_kwargs):
                observed.append((
                    (state / "seed-source/meta-data").read_text(),
                    (state / "seed-source/user-data").read_text(),
                ))
                (state / "seed.iso").write_bytes(b"seed")
                return b""

            with mock.patch.object(harness, "bounded", side_effect=cloud_localds):
                for instance_id in ("buzzci-ceremony-a", "buzzci-run-a", "buzzci-verify-a"):
                    harness.make_seed(state, instance_id)
                    (state / "seed.iso").unlink()
        self.assertEqual(
            [metadata.splitlines()[0] for metadata, _user_data in observed],
            [
                "instance-id: buzzci-ceremony-a", "instance-id: buzzci-run-a",
                "instance-id: buzzci-verify-a",
            ],
        )
        for _metadata, user_data in observed:
            self.assertIn("LABEL=BUZZCI_STAGE, /mnt/buzzci-stage, iso9660", user_data)
            self.assertIn("python3, /mnt/buzzci-stage/guest_entry.py", user_data)
            self.assertIn("mode: poweroff", user_data)
            self.assertIn("timeout: 30", user_data)
        candidate = " ".join(harness.qemu_command(
            Path("/state"), overlay="candidate.qcow2", evidence=False, transfer="read-write",
        ))
        self.assertIn("serial=buzzci-transfer", candidate)
        self.assertIn("file=/work/transfer.raw", candidate)

    def test_candidate_timeout_still_destroys_state_and_partial_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_destroyable_state(root)
            results = root / "results"

            def create_image(image_state, name, _backing):
                (image_state / name).write_bytes(b"overlay")

            with mock.patch.object(harness, "qemu_img_create", side_effect=create_image), mock.patch.object(
                harness, "create_run_stage",
            ), mock.patch.object(
                harness, "boot", side_effect=harness.HarnessError("candidate canary watchdog timeout"),
            ):
                with self.assertRaisesRegex(harness.HarnessError, "candidate canary watchdog timeout"):
                    harness.run_vm({}, state, {}, b"", b"", results)
            self.assertFalse(state.exists())
            self.assertFalse(results.exists())
            self.assertFalse(results.with_name(f".{results.name}.clean-host-staging").exists())


class InputTests(unittest.TestCase):
    def test_guest_cross_binds_keyholder_client_and_service_identities(self) -> None:
        public_spec = {"peer": {"uid": 1201, "gid": 1201}}
        activation = {"identities": {
            "controld": {"uid": 1201, "gid": 1201},
            "keyholder": {"uid": 1202, "gid": 1202},
        }}
        keyholder = {"identities": {
            "controld_uid": 1201, "controld_gid": 1201,
            "keyholder_uid": 1202, "keyholder_gid": 1202,
        }}
        controld = {"keyholder_uid": 1202, "keyholder_gid": 1202}
        guest.validate_ceremony_identities(public_spec, activation, keyholder, controld)
        cases = (
            ({"peer": {"uid": 961, "gid": 961}}, activation, keyholder, controld),
            (public_spec, {"identities": {
                "controld": {"uid": 961, "gid": 961},
                "keyholder": {"uid": 1202, "gid": 1202},
            }}, keyholder, controld),
            (public_spec, activation, {"identities": {
                "controld_uid": 961, "controld_gid": 961,
                "keyholder_uid": 1202, "keyholder_gid": 1202,
            }}, controld),
            (public_spec, activation, keyholder, {"keyholder_uid": 1201, "keyholder_gid": 1201}),
        )
        for values in cases:
            with self.assertRaisesRegex(guest.GuestError, "provider differs"):
                guest.validate_ceremony_identities(*values)

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
            for name in harness.GUEST_ASSETS:
                self.assertEqual((stage / name).read_bytes(), ("frozen-" + name).encode())
            self.assertFalse((stage / "harness.py").exists())

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
                "schema_version": "buzz-ci-clean-host-e2e-evidence/v3",
                "candidate_sha": candidate, "image_sha256": "5" * 64,
                "tool_sha256": {name: "6" * 64 for name in harness.TOOLS},
                "harness_sha256": assets["harness.py"],
                "timing_asset_sha256": assets["timing-contract.json"],
                "harness_asset_sha256": assets, "package_tree_sha256": {},
                "timing": harness.TIMING_CONTRACT,
                "timing_sha256": harness.timing_sha256(),
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
                "harness_sha256": assets["harness.py"],
                "timing_asset_sha256": assets["timing-contract.json"],
                "timing": harness.TIMING_CONTRACT,
                "timing_sha256": harness.timing_sha256(),
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
                "harness_sha256": harness.current_harness_sha256(),
                "harness_asset_sha256": {name: digest for name in harness.FROZEN_ASSETS},
                "timing_asset_sha256": digest,
                "timing": harness.TIMING_CONTRACT,
                "timing_sha256": harness.timing_sha256(),
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
            quarantined = [path for path in root.iterdir() if ".state.tombstone-" in path.name]
            self.assertEqual(len(quarantined), 1)
            self.assertEqual((quarantined[0] / "sentinel").read_text(), "unrelated")
            stolen.chmod(0o700)
            self.assertEqual((stolen / "state.json").stat().st_size, 0)

    def test_clear_directory_swap_sanitizes_selected_member_and_preserves_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            owned = root / "owned"
            owned.mkdir(mode=0o700)
            (owned / "member").write_text("selected")
            identity = harness.directory_identity(owned)
            swapped = False

            def swap_member(name, path, _descriptor):
                nonlocal swapped
                if name == "clear-directory-member" and not swapped:
                    path.rename(path.with_name("stolen"))
                    path.write_text("unrelated")
                    swapped = True

            with mock.patch.object(harness, "cleanup_checkpoint", side_effect=swap_member), mock.patch.object(
                harness.os, "unlink", side_effect=AssertionError("cleanup must not unlink by name"),
            ):
                with self.assertRaisesRegex(harness.HarnessError, "cleanup member was replaced"):
                    harness.destroy_identified_directory(owned, identity, "owned directory")
            quarantined = [path for path in root.iterdir() if ".owned.tombstone-" in path.name]
            self.assertEqual(len(quarantined), 1)
            quarantined[0].chmod(0o700)
            self.assertEqual((quarantined[0] / "stolen").stat().st_size, 0)
            self.assertEqual(stat.S_IMODE((quarantined[0] / "stolen").stat().st_mode), 0)
            self.assertEqual((quarantined[0] / "member").read_text(), "unrelated")

    def test_clear_directory_swap_retains_nested_replacement_and_erases_selected_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            owned = root / "owned"
            child = owned / "child"
            owned.mkdir(mode=0o700)
            child.mkdir(mode=0o700)
            (child / "secret").write_text("selected")
            identity = harness.directory_identity(owned)
            swapped = False

            def swap_directory(name, path, descriptor):
                nonlocal swapped
                if (
                    name == "clear-directory-member"
                    and stat.S_ISDIR(os.fstat(descriptor).st_mode)
                    and not swapped
                ):
                    path.rename(path.with_name("stolen-child"))
                    path.mkdir(mode=0o700)
                    (path / "sentinel").write_text("unrelated")
                    swapped = True

            with mock.patch.object(
                harness, "cleanup_checkpoint", side_effect=swap_directory,
            ), mock.patch.object(
                harness.os, "rmdir", side_effect=AssertionError("cleanup must not rmdir by name"),
            ):
                with self.assertRaisesRegex(harness.HarnessError, "cleanup member was replaced"):
                    harness.destroy_identified_directory(owned, identity, "owned directory")
            tombstones = [path for path in root.iterdir() if ".owned.tombstone-" in path.name]
            self.assertEqual(len(tombstones), 1)
            tombstones[0].chmod(0o700)
            selected = tombstones[0] / "stolen-child"
            selected.chmod(0o700)
            self.assertEqual((selected / "secret").stat().st_size, 0)
            self.assertEqual(stat.S_IMODE((selected / "secret").stat().st_mode), 0)
            self.assertEqual((tombstones[0] / "child" / "sentinel").read_text(), "unrelated")

    def test_final_rmdir_swap_retains_replacement_and_erases_selected_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_destroyable_state(root)
            expected = harness.state_identity(state)
            stolen = root / "stolen-selected-state"
            swapped_path = None

            def swap_at_final_boundary(name, path, _descriptor):
                nonlocal swapped_path
                if name == "before-directory-tombstone-retention":
                    path.rename(stolen)
                    path.mkdir(mode=0o700)
                    (path / "sentinel").write_text("unrelated")
                    swapped_path = path

            with mock.patch.object(
                harness, "cleanup_checkpoint", side_effect=swap_at_final_boundary,
            ), mock.patch.object(
                harness.os, "rmdir", side_effect=AssertionError("cleanup must not rmdir by name"),
            ):
                with self.assertRaisesRegex(harness.HarnessError, "tombstone was replaced"):
                    harness.destroy_state(state, expected)
            self.assertIsNotNone(swapped_path)
            self.assertEqual((swapped_path / "sentinel").read_text(), "unrelated")
            stolen.chmod(0o700)
            self.assertEqual((stolen / "state.json").stat().st_size, 0)
            self.assertEqual(stat.S_IMODE((stolen / "state.json").stat().st_mode), 0)
            residue = sorted(path.name for path in root.iterdir())
            harness.destroy_state(state, expected)
            self.assertEqual(sorted(path.name for path in root.iterdir()), residue)

    def test_final_unlink_swap_retains_replacement_and_erases_selected_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            journal = root / "publication.json"
            journal.write_text("sensitive")
            journal.chmod(0o400)
            stolen = root / "stolen-selected-record"
            swapped_path = None

            def swap_at_final_boundary(name, path, _descriptor):
                nonlocal swapped_path
                if name == "before-file-tombstone-retention":
                    path.rename(stolen)
                    path.write_text("unrelated")
                    swapped_path = path

            with mock.patch.object(
                harness, "cleanup_checkpoint", side_effect=swap_at_final_boundary,
            ), mock.patch.object(
                harness.os, "unlink", side_effect=AssertionError("cleanup must not unlink by name"),
            ):
                with self.assertRaisesRegex(harness.HarnessError, "tombstone was replaced"):
                    harness.unlink_identified_file(journal)
            self.assertIsNotNone(swapped_path)
            self.assertEqual(swapped_path.read_text(), "unrelated")
            self.assertEqual(stolen.stat().st_size, 0)
            self.assertEqual(stat.S_IMODE(stolen.stat().st_mode), 0)
            residue = sorted(path.name for path in root.iterdir())
            harness.unlink_identified_file(journal)
            self.assertEqual(sorted(path.name for path in root.iterdir()), residue)

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
            quarantined = [path for path in root.iterdir() if ".clean-host-staging.tombstone-" in path.name]
            self.assertEqual(len(quarantined), 1)
            self.assertEqual((quarantined[0] / "sentinel").read_text(), "unrelated")
            stolen.chmod(0o700)
            self.assertEqual((stolen / "owned").stat().st_size, 0)

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

    def test_claim_ownership_open_write_and_fsync_failures_are_restart_safe(self) -> None:
        boundaries = ("open", "partial-write", "file-fsync", "directory-fsync")
        for boundary in boundaries:
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                state = make_prepared_state(root)
                binding = harness.run_binding({"state": str(state)}, root / "results")
                real_writer = harness.write_pending_run_ownership
                real_fsync = os.fsync
                failed = False

                def writer(directory_fd, pending_name, ownership, acquired):
                    if boundary == "open":
                        raise PermissionError("simulated ownership open failure")
                    if boundary == "partial-write":
                        descriptor = os.open(
                            pending_name,
                            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                            0o600,
                            dir_fd=directory_fd,
                        )
                        acquired()
                        try:
                            os.write(descriptor, b'{"schema_version":')
                        finally:
                            os.close(descriptor)
                        raise OSError("simulated ownership partial write")
                    return real_writer(directory_fd, pending_name, ownership, acquired)

                def fsync(descriptor):
                    nonlocal failed
                    mode = os.fstat(descriptor).st_mode
                    selected = stat.S_ISREG(mode) if boundary == "file-fsync" else stat.S_ISDIR(mode)
                    if boundary.endswith("fsync") and selected and not failed:
                        failed = True
                        raise OSError(f"simulated ownership {boundary}")
                    return real_fsync(descriptor)

                with mock.patch.object(harness, "validate_flat_qcow2"), mock.patch.object(
                    harness, "write_pending_run_ownership", side_effect=writer,
                ), mock.patch.object(harness.os, "fsync", side_effect=fsync):
                    with self.assertRaises((OSError, PermissionError)):
                        harness.claim_run_state(binding)
                if boundary == "open":
                    self.assertTrue(state.exists())
                    self.assertFalse((state / harness.RUN_OWNERSHIP).exists())
                    self.assertFalse(any(
                        path.name.startswith(harness.RUN_OWNERSHIP_PENDING_PREFIX)
                        for path in state.iterdir()
                    ))
                    with mock.patch.object(harness, "validate_flat_qcow2"):
                        claimed, expected, _resumed = harness.claim_run_state(binding)
                    harness.destroy_state(claimed, expected)
                    continue
                self.assertFalse(state.exists())
                residue = [path for path in root.iterdir() if ".state.tombstone-" in path.name]
                self.assertEqual(len(residue), 1)
                residue[0].chmod(0o700)
                ownership = residue[0] / harness.RUN_OWNERSHIP
                if ownership.exists():
                    self.assertEqual(ownership.stat().st_size, 0)

    def test_claim_recovers_exact_empty_and_partial_pending_publications(self) -> None:
        for raw in (b"", b'{"schema_version":'):
            with self.subTest(bytes=len(raw)), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                state = make_prepared_state(root)
                binding = harness.run_binding({"state": str(state)}, root / "results")
                expected = harness.state_identity(state)
                ownership = harness.run_ownership_record(binding, expected)
                pending = state / harness.run_ownership_pending_name(ownership, expected)
                pending.write_bytes(raw)
                pending.chmod(0o600)
                with mock.patch.object(harness, "validate_flat_qcow2"):
                    claimed, observed, resumed = harness.claim_run_state(binding)
                self.assertEqual(observed, expected)
                self.assertTrue(resumed)
                self.assertFalse(pending.exists())
                self.assertEqual(
                    (claimed / harness.RUN_OWNERSHIP).read_bytes(), harness.canonical(ownership),
                )
                harness.destroy_state(claimed, expected)

    def test_claim_foreign_pending_transaction_never_authorizes_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_prepared_state(root)
            first = harness.run_binding({"state": str(state)}, root / "first-results")
            second = harness.run_binding({"state": str(state)}, root / "second-results")
            expected = harness.state_identity(state)
            pending = state / harness.run_ownership_pending_name(
                harness.run_ownership_record(first, expected), expected,
            )
            pending.write_bytes(b"partial foreign transaction")
            pending.chmod(0o600)
            before = pending.read_bytes()
            with mock.patch.object(harness, "validate_flat_qcow2"):
                with self.assertRaisesRegex(harness.HarnessError, "pending transaction differs"):
                    harness.claim_run_state(second)
            self.assertTrue(state.exists())
            self.assertEqual(pending.read_bytes(), before)
            self.assertFalse((state / harness.RUN_OWNERSHIP).exists())

            state.rename(root / "prior-state")
            replacement = make_prepared_state(root)
            replaced_pending = replacement / pending.name
            replaced_pending.write_bytes(before)
            replaced_pending.chmod(0o600)
            with mock.patch.object(harness, "validate_flat_qcow2"):
                with self.assertRaisesRegex(harness.HarnessError, "pending transaction differs"):
                    harness.claim_run_state(first)
            self.assertTrue(replacement.exists())
            self.assertEqual(replaced_pending.read_bytes(), before)

    def test_claim_lock_serializes_overlapping_same_binding_processes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_prepared_state(root)
            binding = harness.run_binding({"state": str(state)}, root / "results")
            claimed = Path(binding["claimed_state"])
            paused = root / "a-paused"
            release = root / "release-a"
            b_started = root / "b-started"
            a_result = root / "a-result"
            b_result = root / "b-result"

            def run_child(role, result):
                try:
                    def checkpoint(name, _path, _descriptor):
                        if role == "A" and name == "before-claim-rename":
                            paused.write_text("paused")
                            deadline = time.monotonic() + 5
                            while not release.exists():
                                if time.monotonic() >= deadline:
                                    raise RuntimeError("claim overlap release timed out")
                                time.sleep(0.01)

                    if role == "B":
                        b_started.write_text("started")
                    with mock.patch.object(harness, "validate_flat_qcow2"), mock.patch.object(
                        harness, "claim_checkpoint", side_effect=checkpoint,
                    ):
                        selected, _expected, resumed = harness.claim_run_state(binding)
                    result.write_text(f"return:{selected}:{resumed}")
                    os._exit(0)
                except BaseException as error:
                    result.write_text(f"error:{type(error).__name__}:{error}")
                    os._exit(1)

            a_pid = os.fork()
            if a_pid == 0:
                run_child("A", a_result)
            deadline = time.monotonic() + 5
            while not paused.exists():
                if time.monotonic() >= deadline:
                    os.kill(a_pid, 9)
                    self.fail("first claimant did not pause")
                time.sleep(0.01)
            b_pid = os.fork()
            if b_pid == 0:
                run_child("B", b_result)
            deadline = time.monotonic() + 5
            while not b_started.exists():
                if time.monotonic() >= deadline:
                    os.kill(a_pid, 9)
                    os.kill(b_pid, 9)
                    self.fail("second claimant did not start")
                time.sleep(0.01)
            time.sleep(0.1)
            self.assertFalse(b_result.exists())
            release.write_text("release")
            a_status = os.waitpid(a_pid, 0)[1]
            b_status = os.waitpid(b_pid, 0)[1]
            self.assertEqual((a_status, b_status), (0, 0))
            self.assertTrue(a_result.read_text().startswith(f"return:{claimed}:"))
            self.assertTrue(b_result.read_text().startswith(f"return:{claimed}:True"))
            self.assertFalse(state.exists())
            self.assertTrue(claimed.exists())
            harness.destroy_state(claimed, harness.state_identity(claimed))

    def test_claim_lock_timeout_is_finite_and_crash_releases_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_prepared_state(root)
            binding = harness.run_binding({"state": str(state)}, root / "results")
            held = harness.acquire_claim_lock(binding)
            try:
                with mock.patch.object(harness, "CLAIM_LOCK_TIMEOUT", 0.05), mock.patch.object(
                    harness, "CLAIM_LOCK_POLL", 0.005,
                ), mock.patch.object(harness, "validate_flat_qcow2"):
                    with self.assertRaisesRegex(harness.HarnessError, "timed out waiting"):
                        harness.claim_run_state(binding)
            finally:
                harness.release_claim_lock(held)
            crash_pid = os.fork()
            if crash_pid == 0:
                def crash_after_lock(name, _path, _descriptor):
                    if name == "after-claim-lock":
                        os._exit(73)

                with mock.patch.object(harness, "claim_checkpoint", side_effect=crash_after_lock):
                    harness.claim_run_state(binding)
                os._exit(1)
            crash_status = os.waitpid(crash_pid, 0)[1]
            self.assertEqual(os.waitstatus_to_exitcode(crash_status), 73)
            with mock.patch.object(harness, "validate_flat_qcow2"):
                claimed, expected, _resumed = harness.claim_run_state(binding)
            harness.destroy_state(claimed, expected)

    def test_cleanup_crash_after_ownership_zero_has_no_public_prepared_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_prepared_state(root)
            binding = harness.run_binding({"state": str(state)}, root / "results")
            with mock.patch.object(harness, "validate_flat_qcow2"):
                claimed, expected, _resumed = harness.claim_run_state(binding)
            crash_pid = os.fork()
            if crash_pid == 0:
                def crash_after_zero(name, _path, _descriptor):
                    if name == "after-run-ownership-zero":
                        os._exit(74)

                with mock.patch.object(harness, "cleanup_checkpoint", side_effect=crash_after_zero):
                    harness.destroy_state(claimed, expected)
                os._exit(1)
            crash_status = os.waitpid(crash_pid, 0)[1]
            self.assertEqual(os.waitstatus_to_exitcode(crash_status), 74)
            self.assertFalse(state.exists())
            self.assertFalse(claimed.exists())
            residue = [path for path in root.iterdir() if ".terminal-run.tombstone-" in path.name]
            self.assertEqual(len(residue), 1)
            ownership = residue[0] / harness.RUN_OWNERSHIP
            self.assertEqual(ownership.stat().st_size, 0)
            with mock.patch.object(harness, "validate_flat_qcow2"):
                with self.assertRaises(FileNotFoundError):
                    harness.claim_run_state(binding)

    def test_cleanup_never_zeroes_ownership_before_tombstone_fsync(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_prepared_state(root)
            binding = harness.run_binding({"state": str(state)}, root / "results")
            with mock.patch.object(harness, "validate_flat_qcow2"):
                claimed, expected, _resumed = harness.claim_run_state(binding)
            ownership_before = (claimed / harness.RUN_OWNERSHIP).read_bytes()
            with mock.patch.object(
                harness, "fsync_parent", side_effect=OSError("simulated tombstone fsync failure"),
            ):
                with self.assertRaisesRegex(harness.CleanupDurabilityError, "durability failed"):
                    harness.destroy_state(claimed, expected)
            self.assertFalse(claimed.exists())
            residue = [path for path in root.iterdir() if ".terminal-run.tombstone-" in path.name]
            self.assertEqual(len(residue), 1)
            self.assertEqual((residue[0] / harness.RUN_OWNERSHIP).read_bytes(), ownership_before)

    def test_claim_rename_rejects_every_oserror_class_and_cleans_exact_state(self) -> None:
        failures = (
            PermissionError("simulated rename permission failure"),
            FileExistsError("simulated rename collision"),
            OSError("simulated rename I/O failure"),
        )
        for failure in failures:
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                state = make_prepared_state(root)
                binding = harness.run_binding({"state": str(state)}, root / "results")
                claimed = Path(binding["claimed_state"])
                real_rename = harness.rename_noreplace_at

                def fail_claim(source_fd, source, target_fd, target, target_label):
                    if target_label == str(claimed):
                        raise failure
                    return real_rename(source_fd, source, target_fd, target, target_label)

                with mock.patch.object(harness, "validate_flat_qcow2"), mock.patch.object(
                    harness, "rename_noreplace_at", side_effect=fail_claim,
                ):
                    with self.assertRaises(type(failure)):
                        harness.claim_run_state(binding)
                self.assertFalse(state.exists())
                self.assertFalse(claimed.exists())

    def test_claim_lost_rename_acknowledgement_resumes_durable_exact_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_prepared_state(root)
            binding = harness.run_binding({"state": str(state)}, root / "results")
            claimed = Path(binding["claimed_state"])
            real_rename = harness.rename_noreplace_at
            lost = False

            def lose_ack(source_fd, source, target_fd, target, target_label):
                nonlocal lost
                result = real_rename(source_fd, source, target_fd, target, target_label)
                if target_label == str(claimed) and not lost:
                    lost = True
                    raise OSError("simulated lost rename acknowledgement")
                return result

            with mock.patch.object(harness, "validate_flat_qcow2"), mock.patch.object(
                harness, "rename_noreplace_at", side_effect=lose_ack,
            ):
                selected, expected, resumed = harness.claim_run_state(binding)
            self.assertEqual(selected, claimed)
            self.assertTrue(resumed)
            self.assertFalse(state.exists())
            self.assertEqual(
                harness.load_json(claimed / harness.RUN_OWNERSHIP),
                harness.run_ownership_record(binding, expected),
            )
            with mock.patch.object(harness, "validate_flat_qcow2"):
                retried, retried_expected, retried_resumed = harness.claim_run_state(binding)
            self.assertEqual((retried, retried_expected, retried_resumed), (claimed, expected, True))
            harness.destroy_state(claimed, expected)

    def test_claim_state_replacement_before_during_and_after_rename_preserves_replacement(self) -> None:
        for boundary in ("before", "during", "after"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                state = make_prepared_state(root)
                replacement_parent = root / "replacement-parent"
                replacement_parent.mkdir(mode=0o700)
                replacement = make_prepared_state(replacement_parent)
                (replacement / "sentinel").write_text("unrelated")
                binding = harness.run_binding({"state": str(state)}, root / "results")
                claimed = Path(binding["claimed_state"])
                stolen = root / "selected-stolen"
                real_rename = harness.rename_noreplace_at

                def checkpoint(name, _path, _descriptor):
                    if name == "before-claim-rename" and boundary == "before":
                        state.rename(stolen)
                        replacement.rename(state)
                    elif name == "after-claim-rename" and boundary == "after":
                        claimed.rename(stolen)
                        replacement.rename(claimed)

                def rename_with_swap(source_fd, source, target_fd, target, target_label):
                    if target_label == str(claimed) and boundary == "during":
                        state.rename(stolen)
                        replacement.rename(state)
                    return real_rename(source_fd, source, target_fd, target, target_label)

                with mock.patch.object(harness, "validate_flat_qcow2"), mock.patch.object(
                    harness, "claim_checkpoint", side_effect=checkpoint,
                ), mock.patch.object(harness, "rename_noreplace_at", side_effect=rename_with_swap):
                    with self.assertRaisesRegex(harness.HarnessError, "prepared VM state"):
                        harness.claim_run_state(binding)
                replacement_path = state if boundary == "before" else claimed
                self.assertEqual((replacement_path / "sentinel").read_text(), "unrelated")
                self.assertFalse((replacement_path / harness.RUN_OWNERSHIP).exists())
                stolen.chmod(0o700)
                self.assertEqual((stolen / harness.RUN_OWNERSHIP).stat().st_size, 0)

    def test_claim_post_validation_failure_cleans_selected_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_prepared_state(root)
            binding = harness.run_binding({"state": str(state)}, root / "results")
            real_validate = harness.validate_prepared_state
            calls = 0

            def validate(path):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("simulated post-claim validation failure")
                return real_validate(path)

            with mock.patch.object(harness, "validate_flat_qcow2"), mock.patch.object(
                harness, "validate_prepared_state", side_effect=validate,
            ):
                with self.assertRaisesRegex(OSError, "post-claim validation"):
                    harness.claim_run_state(binding)
            self.assertFalse(state.exists())
            self.assertFalse(Path(binding["claimed_state"]).exists())

    def test_claim_cleanup_failure_reports_failure_after_zeroing_ownership(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_prepared_state(root)
            binding = harness.run_binding({"state": str(state)}, root / "results")
            claimed = Path(binding["claimed_state"])
            real_rename = harness.rename_noreplace_at

            def fail_claim(source_fd, source, target_fd, target, target_label):
                if target_label == str(claimed):
                    raise OSError("simulated claim failure")
                return real_rename(source_fd, source, target_fd, target, target_label)

            def cleanup_failure(name, _path, _descriptor):
                if name == "before-directory-tombstone-retention":
                    raise OSError("simulated cleanup acknowledgement failure")

            with mock.patch.object(harness, "validate_flat_qcow2"), mock.patch.object(
                harness, "rename_noreplace_at", side_effect=fail_claim,
            ), mock.patch.object(harness, "cleanup_checkpoint", side_effect=cleanup_failure):
                with self.assertRaisesRegex(harness.HarnessError, "terminal run cleanup failed"):
                    harness.claim_run_state(binding)
            residue = [path for path in root.iterdir() if ".state.tombstone-" in path.name]
            self.assertEqual(len(residue), 1)
            residue[0].chmod(0o700)
            self.assertEqual((residue[0] / harness.RUN_OWNERSHIP).stat().st_size, 0)

    def test_claim_mismatched_ownership_is_preserved_unmodified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_prepared_state(root)
            ownership = state / harness.RUN_OWNERSHIP
            harness.write_new_private_json(ownership, {"schema_version": "unrelated/v1"})
            before = ownership.read_bytes()
            binding = harness.run_binding({"state": str(state)}, root / "results")
            with mock.patch.object(harness, "validate_flat_qcow2"):
                with self.assertRaisesRegex(harness.HarnessError, "ownership differs"):
                    harness.claim_run_state(binding)
            self.assertTrue(state.exists())
            self.assertEqual(ownership.read_bytes(), before)

    def test_claim_noncanonical_matching_ownership_is_not_cleanup_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_prepared_state(root)
            binding = harness.run_binding({"state": str(state)}, root / "results")
            ownership = state / harness.RUN_OWNERSHIP
            expected = harness.state_identity(state)
            raw = json.dumps(
                harness.run_ownership_record(binding, expected), indent=2,
            ).encode() + b"\n"
            ownership.write_bytes(raw)
            ownership.chmod(0o400)
            with mock.patch.object(harness, "validate_flat_qcow2"):
                with self.assertRaisesRegex(harness.HarnessError, "encoding differs"):
                    harness.claim_run_state(binding)
            self.assertTrue(state.exists())
            self.assertEqual(ownership.read_bytes(), raw)

    def test_claim_stale_canonical_identity_never_authorizes_replacement_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_prepared_state(root)
            binding = harness.run_binding({"state": str(state)}, root / "results")
            with mock.patch.object(harness, "validate_flat_qcow2"):
                claimed, old_identity, _resumed = harness.claim_run_state(binding)
            stale_ownership = (claimed / harness.RUN_OWNERSHIP).read_bytes()
            harness.destroy_state(claimed, old_identity)

            replacement = make_prepared_state(root)
            sentinel = replacement / "sentinel"
            sentinel.write_text("unrelated replacement")
            new_identity = harness.state_identity(replacement)
            self.assertNotEqual(new_identity.inode, old_identity.inode)
            self.assertEqual(new_identity.marker_sha256, old_identity.marker_sha256)
            ownership = replacement / harness.RUN_OWNERSHIP
            ownership.write_bytes(stale_ownership)
            ownership.chmod(0o400)
            checkpoints = []

            def fail_if_claimed(name, _path, _descriptor):
                checkpoints.append(name)
                if name == "after-claim-rename":
                    raise OSError("stale ownership reached cleanup authority")

            with mock.patch.object(harness, "validate_flat_qcow2"), mock.patch.object(
                harness, "claim_checkpoint", side_effect=fail_if_claimed,
            ):
                with self.assertRaisesRegex(harness.HarnessError, "ownership differs"):
                    harness.claim_run_state(binding)
            self.assertNotIn("after-claim-rename", checkpoints)
            self.assertTrue(replacement.exists())
            self.assertFalse(Path(binding["claimed_state"]).exists())
            self.assertEqual(sentinel.read_text(), "unrelated replacement")
            self.assertEqual(ownership.read_bytes(), stale_ownership)

    def test_claim_canonical_marker_mismatch_preserves_same_inode_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_prepared_state(root)
            binding = harness.run_binding({"state": str(state)}, root / "results")
            original_identity = harness.state_identity(state)
            ownership = state / harness.RUN_OWNERSHIP
            ownership.write_bytes(harness.canonical(
                harness.run_ownership_record(binding, original_identity),
            ))
            ownership.chmod(0o400)
            record = harness.load_json(state / "state.json")
            record["challenge"] = "f" * 64
            (state / "state.json").write_bytes(harness.canonical(record))
            changed_identity = harness.state_identity(state)
            self.assertEqual(changed_identity.inode, original_identity.inode)
            self.assertNotEqual(changed_identity.marker_sha256, original_identity.marker_sha256)
            before = ownership.read_bytes()
            with mock.patch.object(harness, "validate_flat_qcow2"):
                with self.assertRaisesRegex(harness.HarnessError, "ownership differs"):
                    harness.claim_run_state(binding)
            self.assertTrue(state.exists())
            self.assertEqual(ownership.read_bytes(), before)

    def test_claim_legacy_canonical_ownership_is_preserved_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_prepared_state(root)
            binding = harness.run_binding({"state": str(state)}, root / "results")
            legacy = harness.publication_record(binding, "running")
            legacy.pop("schema_version")
            legacy.pop("phase")
            legacy["schema_version"] = "buzz-ci-clean-host-e2e-run-ownership/v1"
            ownership = state / harness.RUN_OWNERSHIP
            ownership.write_bytes(harness.canonical(legacy))
            ownership.chmod(0o400)
            before = ownership.read_bytes()
            with mock.patch.object(harness, "validate_flat_qcow2"):
                with self.assertRaisesRegex(harness.HarnessError, "ownership differs"):
                    harness.claim_run_state(binding)
            self.assertTrue(state.exists())
            self.assertEqual(ownership.read_bytes(), before)

    def test_claim_rechecks_canonical_identity_before_failure_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_prepared_state(root)
            sentinel = state / "sentinel"
            sentinel.write_text("preserve selected state")
            binding = harness.run_binding({"state": str(state)}, root / "results")
            ownership = state / harness.RUN_OWNERSHIP

            def replace_authority(name, _path, _descriptor):
                if name != "before-claim-rename":
                    return
                value = harness.load_json(ownership)
                value["state_identity"]["inode"] += 1
                ownership.chmod(0o600)
                ownership.write_bytes(harness.canonical(value))
                ownership.chmod(0o400)
                raise OSError("induced failure after authority replacement")

            with mock.patch.object(harness, "validate_flat_qcow2"), mock.patch.object(
                harness, "claim_checkpoint", side_effect=replace_authority,
            ):
                with self.assertRaisesRegex(harness.HarnessError, "terminal run cleanup failed"):
                    harness.claim_run_state(binding)
            self.assertTrue(state.exists())
            self.assertFalse(Path(binding["claimed_state"]).exists())
            self.assertEqual(sentinel.read_text(), "preserve selected state")

    def test_destroy_run_state_rechecks_authority_after_verifier_returns(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_prepared_state(root)
            binding = harness.run_binding({"state": str(state)}, root / "results")
            with mock.patch.object(harness, "validate_flat_qcow2"):
                claimed, expected, _resumed = harness.claim_run_state(binding)
            sentinel = claimed / "sentinel"
            sentinel.write_text("preserve terminal state")
            real_verify = harness.verify_run_ownership_cleanup_authority
            replaced = False

            def replace_after_verify(directory_fd, ownership, selected):
                nonlocal replaced
                real_verify(directory_fd, ownership, selected)
                if replaced:
                    return
                replaced = True
                authority = Path(f"/proc/self/fd/{directory_fd}") / harness.RUN_OWNERSHIP
                value = json.loads(authority.read_bytes())
                value["state_identity"]["marker_sha256"] = "f" * 64
                authority.chmod(0o600)
                authority.write_bytes(harness.canonical(value))
                authority.chmod(0o400)

            with mock.patch.object(
                harness, "verify_run_ownership_cleanup_authority",
                side_effect=replace_after_verify,
            ):
                with self.assertRaisesRegex(harness.HarnessError, "authority differs"):
                    harness.destroy_run_state(claimed, expected, binding)
            self.assertFalse(claimed.exists())
            residue = [
                path for path in root.iterdir()
                if ".terminal-run.tombstone-" in path.name
            ]
            self.assertEqual(len(residue), 1)
            self.assertEqual((residue[0] / "sentinel").read_text(), "preserve terminal state")
            self.assertGreater((residue[0] / harness.RUN_OWNERSHIP).stat().st_size, 0)

    def test_claim_failure_rechecks_authority_after_verifier_returns(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_prepared_state(root)
            sentinel = state / "sentinel"
            sentinel.write_text("preserve failed claim")
            binding = harness.run_binding({"state": str(state)}, root / "results")
            real_verify = harness.verify_run_ownership_cleanup_authority
            replaced = False

            def fail_after_claim(name, _path, _descriptor):
                if name == "after-claim-rename":
                    raise OSError("induced failure after claim rename")

            def replace_after_verify(directory_fd, ownership, selected):
                nonlocal replaced
                real_verify(directory_fd, ownership, selected)
                if replaced:
                    return
                replaced = True
                authority = Path(f"/proc/self/fd/{directory_fd}") / harness.RUN_OWNERSHIP
                value = json.loads(authority.read_bytes())
                value["state_identity"]["marker_sha256"] = "f" * 64
                authority.chmod(0o600)
                authority.write_bytes(harness.canonical(value))
                authority.chmod(0o400)

            with mock.patch.object(harness, "validate_flat_qcow2"), mock.patch.object(
                harness, "claim_checkpoint", side_effect=fail_after_claim,
            ), mock.patch.object(
                harness, "verify_run_ownership_cleanup_authority",
                side_effect=replace_after_verify,
            ):
                with self.assertRaisesRegex(harness.HarnessError, "terminal run cleanup failed"):
                    harness.claim_run_state(binding)
            self.assertFalse(state.exists())
            self.assertFalse(Path(binding["claimed_state"]).exists())
            residue = [
                path for path in root.iterdir()
                if ".terminal-run.tombstone-" in path.name
            ]
            self.assertEqual(len(residue), 1)
            self.assertEqual((residue[0] / "sentinel").read_text(), "preserve failed claim")
            self.assertGreater((residue[0] / harness.RUN_OWNERSHIP).stat().st_size, 0)

    def test_destroy_run_state_rejects_noncooperating_marker_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_prepared_state(root)
            binding = harness.run_binding({"state": str(state)}, root / "results")
            with mock.patch.object(harness, "validate_flat_qcow2"):
                claimed, expected, _resumed = harness.claim_run_state(binding)
            sentinel = claimed / "sentinel"
            sentinel.write_text("preserve marker replacement")

            def replace_marker(name, path, _descriptor):
                if name != "before-owned-directory-sanitization":
                    return
                marker = harness.load_json(path / "state.json")
                marker["challenge"] = "f" * 64
                (path / "state.json").write_bytes(harness.canonical(marker))

            with mock.patch.object(
                harness, "cleanup_checkpoint", side_effect=replace_marker,
            ):
                with self.assertRaisesRegex(harness.HarnessError, "state identity differs"):
                    harness.destroy_run_state(claimed, expected, binding)
            self.assertFalse(claimed.exists())
            residue = [
                path for path in root.iterdir()
                if ".terminal-run.tombstone-" in path.name
            ]
            self.assertEqual(len(residue), 1)
            self.assertEqual(
                (residue[0] / "sentinel").read_text(), "preserve marker replacement",
            )
            self.assertGreater((residue[0] / harness.RUN_OWNERSHIP).stat().st_size, 0)

    def test_destroy_run_state_preserves_noncooperating_path_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = make_prepared_state(root)
            binding = harness.run_binding({"state": str(state)}, root / "results")
            with mock.patch.object(harness, "validate_flat_qcow2"):
                claimed, expected, _resumed = harness.claim_run_state(binding)
            displaced = root / "displaced-selected-state"
            real_verify = harness.verify_run_ownership_cleanup_authority
            replaced = False

            def replace_path_after_verify(directory_fd, ownership, selected):
                nonlocal replaced
                real_verify(directory_fd, ownership, selected)
                if replaced:
                    return
                replaced = True
                claimed.rename(displaced)
                replacement = make_prepared_state(root)
                sentinel = replacement / "sentinel"
                sentinel.write_text("unrelated replacement")
                replacement.rename(claimed)

            with mock.patch.object(
                harness, "verify_run_ownership_cleanup_authority",
                side_effect=replace_path_after_verify,
            ):
                with self.assertRaisesRegex(harness.HarnessError, "replaced VM state"):
                    harness.destroy_run_state(claimed, expected, binding)
            self.assertFalse(claimed.exists())
            replacement_residue = [
                path for path in root.iterdir()
                if ".terminal-run.tombstone-" in path.name
                and (path / "sentinel").exists()
            ]
            self.assertEqual(len(replacement_residue), 1)
            self.assertEqual(
                (replacement_residue[0] / "sentinel").read_text(), "unrelated replacement",
            )
            self.assertTrue(displaced.exists())
            displaced.chmod(0o700)
            self.assertEqual((displaced / harness.RUN_OWNERSHIP).stat().st_size, 0)

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
            root = Path(temporary)
            state = make_destroyable_state(root)
            expected = harness.state_identity(state)
            harness.destroy_state(state, expected)
            residue = [path for path in root.iterdir() if ".state.tombstone-" in path.name]
            self.assertEqual(len(residue), 1)
            residue[0].chmod(0o700)
            self.assertTrue(all(path.stat().st_size == 0 for path in residue[0].iterdir()))
            names = sorted(path.name for path in root.iterdir())
            harness.destroy_state(state, expected)
            self.assertFalse(state.exists())
            self.assertEqual(sorted(path.name for path in root.iterdir()), names)

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
                proof = {
                    "qemu_version": "test", "tool_sha256": tool_sha,
                    "harness_sha256": harness.current_harness_sha256(),
                    "timing_asset_sha256": harness.timing_asset_sha256(),
                    "timing": harness.TIMING_CONTRACT,
                    "timing_sha256": harness.timing_sha256(),
                }
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
                proof = {
                    "qemu_version": "test", "tool_sha256": tool_sha,
                    "harness_sha256": harness.current_harness_sha256(),
                    "timing_asset_sha256": harness.timing_asset_sha256(),
                    "timing": harness.TIMING_CONTRACT,
                    "timing_sha256": harness.timing_sha256(),
                }
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
            contract = {
                "candidate_sha": candidate_sha, "scenario": {"sha256": scenario_sha},
                "harness_sha256": harness.current_harness_sha256(),
                "timing_asset_sha256": harness.timing_asset_sha256(),
                "timing": harness.TIMING_CONTRACT,
                "timing_sha256": harness.timing_sha256(),
            }
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
            manifest = json.loads((results / "evidence-manifest.json").read_bytes())
            self.assertEqual(manifest["harness_sha256"], harness.current_harness_sha256())
            self.assertEqual(manifest["harness_asset_sha256"]["harness.py"], manifest["harness_sha256"])
            self.assertEqual(manifest["timing_asset_sha256"], harness.timing_asset_sha256())
            self.assertEqual(manifest["harness_asset_sha256"]["timing-contract.json"], manifest["timing_asset_sha256"])
            self.assertEqual(manifest["timing"], harness.TIMING_CONTRACT)
            self.assertEqual(manifest["timing_sha256"], harness.timing_sha256())

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

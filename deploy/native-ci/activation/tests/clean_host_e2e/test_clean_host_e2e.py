#!/usr/bin/env python3
"""Adversarial checks for the isolated clean-host VM harness."""

from __future__ import annotations

import base64
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import tarfile
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
sys.path.insert(0, str(HERE.parents[1]))
import controller as stage_controller
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


PRIOR_ACTIVATION = {"activation_id": "buzz-ci-capacity-one-" + "a" * 12 + "-" + "b" * 12, "package_digest": "b" * 64}
CURRENT_ACTIVATION = {"activation_id": "buzz-ci-capacity-one-" + "a" * 12 + "-" + "c" * 12, "package_digest": "c" * 64}


def activation_manifest_record(binding: dict[str, str]) -> tuple[str, int, bytes]:
    return ("activation-manifest.json", 0o400, harness.canonical(binding))


def package_records() -> dict[str, list[tuple[str, int, bytes]]]:
    records = {name: [("payload", 0o400, name.encode())] for name in harness.PACKAGE_NAMES}
    records["activation"].append(activation_manifest_record(CURRENT_ACTIVATION))
    records["prior/execd"] = [("payload", 0o400, b"prior-execd")]
    records["prior/activation"] = [("payload", 0o400, b"prior-activation"), activation_manifest_record(PRIOR_ACTIVATION)]
    return {name: sorted(items) for name, items in records.items()}


def prior_activation_proof() -> dict[str, object]:
    return {
        **PRIOR_ACTIVATION, "receipt_state": "rolled_back",
        "rollback_cleanup_sha256": "7" * 64, "execd_reinstall": "installed",
    }


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
    prior_packages = {}
    for key, records in package_records().items():
        package = parent / ("package-" + key.replace("/", "-"))
        harness.materialize_tree(records, package)
        descriptor = {"path": str(package), "tree_sha256": harness.tree_digest(records)}
        if key.startswith("prior/"):
            prior_packages[key.removeprefix("prior/")] = descriptor
        else:
            packages[key] = descriptor
    scenario = parent / "scenario.json"
    scenario.write_bytes(harness.canonical({
        "driver": {"timeout_seconds": harness.TIMING_CONTRACT["leaf_seconds"]["driver_operation"]},
    }))
    prior_scenario = parent / "prior-scenario.json"
    prior_scenario.write_bytes(harness.canonical({
        "driver": {"timeout_seconds": harness.TIMING_CONTRACT["leaf_seconds"]["driver_operation"]},
        "fixture": {"activation_id": PRIOR_ACTIVATION["activation_id"]},
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
        "platform_systemd": copy.deepcopy(harness.PLATFORM_SYSTEMD),
        "scenario": {"path": str(scenario), "sha256": harness.file_sha256(scenario)},
        "seccomp_source": {"path": str(seccomp), "sha256": seccomp_sha},
        "packages": packages,
        "prior_packages": prior_packages,
        "prior_scenario": {"path": str(prior_scenario), "sha256": harness.file_sha256(prior_scenario)},
    }
    contract = parent / "contract.json"
    contract.write_bytes(harness.canonical(value))
    return contract, value, seccomp_sha


def rewrite_contract(path: Path, value: dict[str, object]) -> None:
    path.write_bytes(harness.canonical(value))


def write_guest_package(
    inputs: Path, name: str, entries: list[tuple[str, str, bytes]],
) -> Path:
    package = inputs / name
    package.mkdir(parents=True)
    manifest_entries = []
    for index, (source, target, payload) in enumerate(entries):
        member = package / source
        member.parent.mkdir(parents=True, exist_ok=True)
        member.write_bytes(payload)
        manifest_entries.append({
            "role": f"test_{index}",
            "source": source,
            "target": target,
            "sha256": hashlib.sha256(payload).hexdigest(),
        })
    manifest_name = "activation-manifest.json" if name == "activation" else "package-manifest.json"
    (package / manifest_name).write_bytes(harness.canonical({"entries": manifest_entries}))
    return package


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
        "prior_activation": prior_activation_proof(),
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


def systemd_process(
    lines: list[str], *, returncode: int = 0, stderr: bytes = b"",
) -> subprocess.CompletedProcess[bytes]:
    stdout = ("\n".join(lines) + "\n").encode()
    return subprocess.CompletedProcess(["systemctl", "show"], returncode, stdout, stderr)


def rock_ridge_metadata(image: Path, root: str) -> dict[str, tuple[str, int, int]]:
    process = subprocess.run(
        [
            HOST_TOOLS["xorriso"], "-indev", str(image),
            "-find", root, "-exec", "lsdl", "--",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    result: dict[str, tuple[str, int, int]] = {}
    pattern = re.compile(
        r"^([d-][rwx-]{9})\s+\d+\s+(\d+)\s+(\d+)\s+\d+\s+"
        r"\S+\s+\S+\s+\S+\s+'([^']+)'$",
    )
    for line in (process.stdout + process.stderr).splitlines():
        match = pattern.fullmatch(line)
        if match is not None:
            result[match.group(4)] = (
                match.group(1), int(match.group(2)), int(match.group(3)),
            )
    if not result:
        raise AssertionError("Rock Ridge metadata listing is empty")
    return result


def require_root_owned_iso_paths(
    metadata: dict[str, tuple[str, int, int]], expected: dict[str, str],
) -> None:
    if set(metadata) != set(expected):
        raise AssertionError("Rock Ridge path inventory differs")
    for path, expected_mode in expected.items():
        mode, uid, gid = metadata[path]
        if (uid, gid) != (0, 0):
            raise AssertionError(f"Rock Ridge owner differs: {path}")
        if mode != expected_mode:
            raise AssertionError(f"Rock Ridge mode differs: {path}")


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
    def test_qemu_boots_only_the_os_disk_before_the_transfer_disk(self) -> None:
        for overlay, transfer in (
            ("ceremony.qcow2", None),
            ("candidate.qcow2", "read-write"),
            ("verifier.qcow2", "read-only"),
        ):
            with self.subTest(overlay=overlay, transfer=transfer):
                command = harness.qemu_command(
                    Path("/private-state"), overlay=overlay,
                    evidence=overlay != "candidate.qcow2", transfer=transfer,
                )
                qemu = command[command.index("--") + 1:]
                os_drive = f"file=/work/{overlay},if=none,format=qcow2,cache=none,id=os"
                os_index = qemu.index(os_drive)
                self.assertEqual(qemu[os_index - 1:os_index + 3], [
                    "-drive", os_drive,
                    "-device", "virtio-blk-pci,drive=os,bootindex=1",
                ])
                self.assertEqual(
                    [value for value in qemu if "bootindex=" in value],
                    ["virtio-blk-pci,drive=os,bootindex=1"],
                )
                if transfer is not None:
                    transfer_drive = (
                        "file=/work/transfer.raw,if=none,format=raw,cache=none,id=transfer"
                        + (",readonly=on" if transfer == "read-only" else "")
                    )
                    transfer_index = qemu.index(transfer_drive)
                    self.assertEqual(qemu[transfer_index - 1:transfer_index + 3], [
                        "-drive", transfer_drive,
                        "-device", "virtio-blk-pci,drive=transfer,serial=buzzci-transfer",
                    ])

    def test_stage_iso_normalizes_root_ownership_and_preserves_package_tree(self) -> None:
        if not Path(HOST_TOOLS["xorriso"]).is_file():
            self.skipTest("clean-host xorriso is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage = root / "stage"
            package = stage / "inputs/runner"
            assets = package / "assets"
            assets.mkdir(mode=0o700, parents=True)
            stage.chmod(0o700)
            (stage / "inputs").chmod(0o700)
            package.chmod(0o700)
            manifest = package / "package-manifest.json"
            manifest.write_bytes(harness.canonical({"schema": "test"}))
            manifest.chmod(0o600)
            payload = assets / "payload"
            payload.write_bytes(b"exact package payload\n")
            payload.chmod(0o400)

            source_uid, source_gid = os.geteuid(), os.getegid()
            if source_uid == 0 or source_gid == 0:
                source_uid = source_gid = 1
                for path in (stage, stage / "inputs", package, assets, manifest, payload):
                    os.chown(path, source_uid, source_gid)
            self.assertNotEqual(source_uid, 0)
            self.assertNotEqual(source_gid, 0)
            self.assertEqual(
                (package.stat().st_uid, package.stat().st_gid),
                (source_uid, source_gid),
            )

            original_digest = harness.tree_digest(harness.tree_records(package))
            image = root / "stage.iso"
            observed_commands: list[list[str]] = []
            real_bounded = harness.bounded

            def bounded(argv, **keywords):
                observed_commands.append(list(argv))
                return real_bounded(argv, **keywords)

            with mock.patch.dict(
                harness.TOOLS, {"xorriso": HOST_TOOLS["xorriso"]}, clear=False,
            ), mock.patch.object(harness, "bounded", side_effect=bounded):
                harness.make_iso(stage, image, "BUZZCI_STAGE_TEST")

            self.assertEqual(observed_commands, [[
                HOST_TOOLS["xorriso"], "-as", "mkisofs", "-quiet", "-J", "-R",
                "-uid", "0", "-gid", "0", "-V", "BUZZCI_STAGE_TEST",
                "-o", str(image), str(stage),
            ]])
            self.assertEqual(stat.S_IMODE(image.stat().st_mode), 0o400)
            expected = {
                "/inputs/runner": "drwx------",
                "/inputs/runner/assets": "drwx------",
                "/inputs/runner/assets/payload": "-r--------",
                "/inputs/runner/package-manifest.json": "-rw-------",
            }
            require_root_owned_iso_paths(
                rock_ridge_metadata(image, "/inputs/runner"), expected,
            )

            extracted = root / "extracted-runner"
            subprocess.run(
                [
                    HOST_TOOLS["xorriso"], "-osirrox", "on", "-indev", str(image),
                    "-extract", "/inputs/runner", str(extracted),
                ],
                check=True,
                capture_output=True,
            )
            self.assertEqual(
                harness.tree_digest(harness.tree_records(extracted)), original_digest,
            )

            for name, owner_flags in (
                ("omitted", []),
                ("mutated", ["-uid", "1", "-gid", "1"]),
            ):
                hostile = root / f"{name}.iso"
                subprocess.run(
                    [
                        HOST_TOOLS["xorriso"], "-as", "mkisofs", "-quiet", "-J", "-R",
                        *owner_flags, "-V", "BUZZCI_STAGE_TEST",
                        "-o", str(hostile), str(stage),
                    ],
                    check=True,
                    capture_output=True,
                )
                with self.subTest(owner_flags=owner_flags), self.assertRaisesRegex(
                    AssertionError, "Rock Ridge owner differs",
                ):
                    require_root_owned_iso_paths(
                        rock_ridge_metadata(hostile, "/inputs/runner"), expected,
                    )

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
                (state / "progress.bin").write_bytes(b"".join((
                    progress_frame("verifier", 0, "guest_started", "start", 1),
                    progress_frame("verifier", 1, "verifier", "start", 2),
                    progress_frame("verifier", 2, "complete", "complete", 3),
                )))
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

    def test_systemd259_absent_unit_shapes_normalize_only_nonservice_main_pid(self) -> None:
        common = [
            "LoadState=not-found", "ActiveState=inactive", "SubState=dead",
            "FragmentPath=", "UnitFileState=", "InvocationID=",
        ]

        def show(argv, **_keywords):
            unit = argv[2]
            lines = list(common)
            if unit.endswith(".service"):
                lines.append("MainPID=0")
            return systemd_process(lines)

        with mock.patch.object(guest, "command", side_effect=show) as command:
            observed = guest.unit_state()
        self.assertEqual(set(observed), set(guest.UNITS))
        self.assertTrue(all(value["MainPID"] == "0" for value in observed.values()))
        self.assertEqual(command.call_count, len(guest.UNITS))
        for call in command.call_args_list:
            self.assertEqual(
                call.args[0][3], "--property=" + ",".join(guest.SYSTEMD_UNIT_PROPERTIES),
            )

    def test_systemd_unit_readback_accepts_loaded_service_and_active_socket(self) -> None:
        loaded_service = systemd_process([
            "LoadState=loaded", "ActiveState=active", "SubState=running",
            "UnitFileState=enabled", "MainPID=123", "InvocationID=" + "a" * 32,
            "FragmentPath=/usr/lib/systemd/system/buzz-ci-runner.service",
        ])
        service = guest.systemd_unit_values("buzz-ci-runner.service", loaded_service)
        self.assertEqual(service["MainPID"], "123")
        self.assertEqual(service["LoadState"], "loaded")

        active_socket = systemd_process([
            "LoadState=loaded", "ActiveState=active", "SubState=listening",
            "UnitFileState=enabled", "InvocationID=" + "b" * 32,
            "FragmentPath=/usr/lib/systemd/system/buzz-ci-runner.socket",
        ])
        socket = guest.systemd_unit_values("buzz-ci-runner.socket", active_socket)
        self.assertEqual(socket["MainPID"], "0")
        self.assertEqual(socket["SubState"], "listening")
        active_socket_with_pid = systemd_process([
            *active_socket.stdout.decode().splitlines(), "MainPID=456",
        ])
        self.assertEqual(
            guest.systemd_unit_values(
                "buzz-ci-runner.socket", active_socket_with_pid,
            )["MainPID"],
            "456",
        )

    def test_systemd_unit_readback_rejects_missing_service_pid_and_hostile_output(self) -> None:
        valid = [
            "LoadState=not-found", "ActiveState=inactive", "SubState=dead",
            "UnitFileState=", "MainPID=0", "InvocationID=", "FragmentPath=",
        ]
        for missing in set(guest.SYSTEMD_UNIT_PROPERTIES) - {"MainPID"}:
            lines = [line for line in valid if not line.startswith(missing + "=")]
            with self.subTest(missing=missing), self.assertRaisesRegex(
                guest.GuestError, "readback failed",
            ):
                guest.systemd_unit_values("buzz-ci-runner.service", systemd_process(lines))

        omitted_pid = [line for line in valid if not line.startswith("MainPID=")]
        hostile = (
            (omitted_pid, 0, b""),
            ([*valid, "LoadState=not-found"], 0, b""),
            ([*valid, "Description=hostile"], 0, b""),
            ([*valid, "malformed"], 0, b""),
            ([line.replace("MainPID=0", "MainPID=7") for line in valid], 0, b""),
            ([line.replace("MainPID=0", "MainPID=invalid") for line in valid], 0, b""),
            ([line.replace("LoadState=not-found", "LoadState=loaded") for line in valid], 1, b""),
            (valid, 0, b"unexpected stderr"),
        )
        for lines, returncode, stderr in hostile:
            with self.subTest(lines=lines, returncode=returncode, stderr=stderr), self.assertRaisesRegex(
                guest.GuestError, "readback failed",
            ):
                guest.systemd_unit_values(
                    "buzz-ci-runner.service",
                    systemd_process(lines, returncode=returncode, stderr=stderr),
                )

        absent_nonzero = systemd_process(valid, returncode=1)
        self.assertEqual(
            guest.systemd_unit_values("buzz-ci-runner.service", absent_nonzero)["LoadState"],
            "not-found",
        )
        with self.assertRaisesRegex(guest.GuestError, "readback failed"):
            guest.systemd_unit_values(
                "buzz-ci-runner.service",
                subprocess.CompletedProcess(["systemctl"], 0, b"\xff", b""),
            )

    def test_dormant_relay_accepts_exact_absence_for_zero_or_nonzero_return(self) -> None:
        exact = ["LoadState=not-found", "ActiveState=inactive", "MainPID=0"]
        units = {
            unit: {
                "LoadState": "not-found", "ActiveState": "inactive",
                "UnitFileState": "", "MainPID": "0",
            }
            for unit in guest.UNITS
        }
        baseline = {
            unit: {"LoadState": "not-found", "UnitFileState": ""}
            for unit in guest.UNITS
        }
        for returncode in (0, 1):
            with self.subTest(returncode=returncode), mock.patch.object(
                guest, "tree_state", return_value={},
            ), mock.patch.object(
                guest, "unit_state", return_value=units,
            ), mock.patch.object(
                Path, "exists", return_value=False,
            ), mock.patch.object(
                guest, "command", side_effect=(
                    systemd_process(exact, returncode=returncode),
                    subprocess.CompletedProcess(["pgrep"], 1, b"", b""),
                ),
            ):
                proof = guest.dormant_proof({}, baseline)
            self.assertTrue(proof["relay_residue_absent"])

    def test_dormant_relay_rejects_residue_and_malformed_absence(self) -> None:
        exact = ["LoadState=not-found", "ActiveState=inactive", "MainPID=0"]
        units = {
            unit: {
                "LoadState": "not-found", "ActiveState": "inactive",
                "UnitFileState": "", "MainPID": "0",
            }
            for unit in guest.UNITS
        }
        baseline = {
            unit: {"LoadState": "not-found", "UnitFileState": ""}
            for unit in guest.UNITS
        }
        hostile = (
            ["LoadState=loaded", "ActiveState=inactive", "MainPID=0"],
            ["LoadState=not-found", "ActiveState=active", "MainPID=0"],
            ["LoadState=not-found", "ActiveState=inactive", "MainPID=7"],
            exact[:-1],
            [*exact, "LoadState=not-found"],
            [*exact, "Description=hostile"],
            [*exact, "malformed"],
        )
        for lines in hostile:
            with self.subTest(lines=lines), mock.patch.object(
                guest, "tree_state", return_value={},
            ), mock.patch.object(
                guest, "unit_state", return_value=units,
            ), mock.patch.object(
                Path, "exists", return_value=False,
            ), mock.patch.object(
                guest, "command", return_value=systemd_process(lines),
            ), self.assertRaisesRegex(guest.GuestError, "relay unit residue remains"):
                guest.dormant_proof({}, baseline)
        with mock.patch.object(
            guest, "tree_state", return_value={},
        ), mock.patch.object(
            guest, "unit_state", return_value=units,
        ), mock.patch.object(
            Path, "exists", return_value=False,
        ), mock.patch.object(
            guest, "command", return_value=systemd_process(exact, stderr=b"unexpected stderr"),
        ), self.assertRaisesRegex(guest.GuestError, "relay unit residue remains"):
            guest.dormant_proof({}, baseline)

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
    INSTALL_CHECKPOINTS = (
        "relay_ready", "preinstall_units_clean", "package_units_validated",
        "principals_created", "seccomp_ready", "runner_installed",
        "controld_installed", "keyholder_installed", "execd_installed",
        "installed_units_verified",
    )
    PRIOR_CHECKPOINTS = (
        "prior_controller_check", "prior_controller_stage", "prior_controller_activate",
        "prior_rollback", "reinstall", "execd_reinstalled",
    )
    CANDIDATE_PHASES = (
        "install", *INSTALL_CHECKPOINTS, *PRIOR_CHECKPOINTS, "controller_check", "controller_stage",
        "controller_activate", "canary", "receipt_verifier", "rollback", "cleanup",
        "cleanup_return",
    )

    def run_mocked_acceptance(
        self, *, fail_at: str | None = None, cleanup_errors: tuple[str, ...] = (),
        stage_failure: bool = False, stage_subphase: str | None = None,
    ) -> tuple[list[tuple[str, str]], BaseException | None]:
        events: list[tuple[str, str]] = []
        descriptor = {
            "schema_version": guest.STAGE_SCHEMA,
            "candidate_sha": "a" * 40,
            "harness_sha256": "b" * 64,
            "timing_asset_sha256": "c" * 64,
            "timing_sha256": "d" * 64,
            "candidate_tar_sha256": "e" * 64,
            "scenario_sha256": "f" * 64,
            "seccomp_source_sha256": guest.SECCOMP_SHA256,
            "public_binding_sha256": "1" * 64,
            "package_tree_sha256": {name: "2" * 64 for name in guest.PACKAGE_NAMES},
            "platform_systemd": copy.deepcopy(guest.PLATFORM_SYSTEMD),
            "prior_package_tree_sha256": {name: "7" * 64 for name in guest.PRIOR_PACKAGE_NAMES},
            "prior_scenario_sha256": "8" * 64,
        }
        phase = {
            "challenge": "3" * 64,
            "descriptor_sha256": hashlib.sha256(guest.canonical(descriptor)).hexdigest(),
            "timing_sha256": descriptor["timing_sha256"],
        }
        expected_units = {
            unit: {"fragment_path": f"/usr/lib/systemd/system/{unit}", "sha256": "4" * 64}
            for unit in guest.UNITS
        }

        def completed(name: str, value=None):
            if fail_at == name:
                raise guest.GuestError("injected boundary failure")
            return value

        def command(argv, **_keywords):
            for component in ("runner", "controld", "keyholder", "execd"):
                if f"/{component}/install.py" in str(argv[1]) and fail_at == f"{component}_installed":
                    raise guest.GuestError("injected boundary failure")
            prior_actions = {
                "check": "prior_controller_check", "stage": "prior_controller_stage",
                "activate": "prior_controller_activate", "rollback": "prior_rollback",
            }
            action = next((item for item in argv if item in prior_actions), None)
            if action is not None and "inputs/prior/activation" in " ".join(str(item) for item in argv):
                if fail_at == prior_actions[action]:
                    raise guest.GuestError("injected boundary failure")
            return subprocess.CompletedProcess(argv, 0, b"verifier", b"")

        def prior_proof(_manifest, _stdout):
            return dict(prior_activation_proof(), execd_reinstall="pending")

        def reinstall(_candidate, prior_package, package):
            self.assertEqual(Path(prior_package), stage / "inputs/prior/execd")
            self.assertEqual(Path(package), stage / "inputs/execd")
            if fail_at == "execd_reinstalled":
                raise guest.GuestError("injected boundary failure")
            return "installed"

        unit_inventory_calls = 0

        def expected_unit_fragments(_inputs, _names):
            nonlocal unit_inventory_calls
            unit_inventory_calls += 1
            if fail_at == "package_units_validated":
                raise guest.GuestError("injected boundary failure")
            return expected_units if unit_inventory_calls == 1 else {}

        def cleanup(_candidate, _activation, attempted_stage, _hosts_added):
            if attempted_stage:
                guest.emit_progress("rollback")
            guest.emit_progress("cleanup")
            return list(cleanup_errors)

        def staged(argv, **_keywords):
            self.assertEqual(argv[2:4], ["stage", "--package"])
            self.assertEqual(Path(argv[4]), stage / "inputs/activation")
            self.assertEqual(argv[5], "--scenario")
            self.assertEqual(Path(argv[6]), stage / "inputs/scenario.json")
            if stage_failure:
                if stage_subphase:
                    guest.emit_progress(f"controller_stage:{stage_subphase}")
                raise guest.StageCommandFailure(
                    "guest command failed: controller_stage", stage_subphase,
                )
            return completed(
                "controller_stage", subprocess.CompletedProcess(argv, 0, b"", b""),
            )

        error: BaseException | None = None
        with tempfile.TemporaryDirectory() as temporary, contextlib.ExitStack() as stack:
            root = Path(temporary)
            state = root / "state"
            stage = root / "stage"
            state.mkdir()
            stage.mkdir()
            candidate = root / "candidate"
            stack.enter_context(mock.patch.object(guest, "STATE_ROOT", state))
            stack.enter_context(mock.patch.object(guest, "load_json", return_value=descriptor))
            stack.enter_context(mock.patch.object(
                guest, "cross_bind", return_value=(candidate, {}, {}, "12345678-1234-4abc-8def-123456789abc"),
            ))
            stack.enter_context(mock.patch.object(guest, "relay_mapping_present", return_value=False))
            stack.enter_context(mock.patch.object(
                guest, "start_relay", side_effect=lambda _public, _channel, _fault=None: completed("relay_ready"),
            ))
            stack.enter_context(mock.patch.object(
                guest, "unit_state", side_effect=lambda: completed(
                    "preinstall_units_clean",
                    {unit: {"LoadState": "not-found"} for unit in guest.UNITS},
                ),
            ))
            stack.enter_context(mock.patch.object(
                guest, "expected_unit_fragments", side_effect=expected_unit_fragments,
            ))
            stack.enter_context(mock.patch.object(
                guest, "create_principals",
                side_effect=lambda _package: completed("principals_created"),
            ))
            stack.enter_context(mock.patch.object(
                guest, "provision_seccomp",
                side_effect=lambda _source: completed("seccomp_ready"),
            ))
            stack.enter_context(mock.patch.object(guest, "command", side_effect=command))
            stack.enter_context(mock.patch.object(
                guest, "stage_command",
                side_effect=staged,
            ))
            stack.enter_context(mock.patch.object(guest, "tree_state", return_value={}))
            stack.enter_context(mock.patch.object(
                guest, "prove_installed_units",
                side_effect=lambda _expected: completed("installed_units_verified", expected_units),
            ))
            stack.enter_context(mock.patch.object(guest, "prior_rollback_proof", side_effect=prior_proof))
            stack.enter_context(mock.patch.object(guest, "reinstall_execd", side_effect=reinstall))
            stack.enter_context(mock.patch.object(guest, "run_capacity_one_canary", return_value=b"receipt"))
            stack.enter_context(mock.patch.object(guest, "read_file", return_value=b"scenario"))
            stack.enter_context(mock.patch.object(guest, "parse_verdict"))
            stack.enter_context(mock.patch.object(guest, "cleanup", side_effect=cleanup))
            stack.enter_context(mock.patch.object(guest, "dormant_proof", return_value={"proof": True}))
            stack.enter_context(mock.patch.object(guest, "write_transfer"))
            stack.enter_context(mock.patch.object(
                guest, "emit_progress", side_effect=lambda name, event="start": events.append((name, event)),
            ))
            stack.enter_context(mock.patch.object(
                guest, "begin_phase", side_effect=lambda name, **_keywords: guest.emit_progress(name),
            ))
            stack.enter_context(mock.patch.object(
                guest, "complete_progress", side_effect=lambda: guest.emit_progress("complete", "complete"),
            ))
            stack.enter_context(mock.patch.object(guest, "abandon_command_inventory"))
            try:
                guest.run_acceptance(phase, stage)
            except BaseException as caught:
                error = caught
        return events, error

    def test_prior_activation_must_differ_and_share_components(self) -> None:
        components = [
            {"name": "runner", "package_manifest_sha256": "1" * 64, "package_digest": "2" * 64},
            {"name": "controld", "package_manifest_sha256": "3" * 64, "package_digest": "4" * 64},
            {"name": "execd", "binary_sha256": "5" * 64},
        ]
        identities = {"controld": {"uid": 1201}}
        current = {
            "activation_id": "buzz-ci-capacity-one-" + "a" * 12 + "-" + "c" * 12, "package_digest": "c" * 64,
            "components": components, "identities": identities, "access_group": {"gid": 1204},
        }
        prior = {**current, "activation_id": "buzz-ci-capacity-one-" + "a" * 12 + "-" + "b" * 12, "package_digest": "b" * 64}
        guest.validate_prior_activation(prior, current)
        for label, mutated in (
            ("same id", {**prior, "activation_id": current["activation_id"]}),
            ("same digest", {**prior, "package_digest": current["package_digest"]}),
            ("bad digest", {**prior, "package_digest": "short"}),
        ):
            with self.subTest(label=label), self.assertRaisesRegex(guest.GuestError, "does not differ"):
                guest.validate_prior_activation(mutated, current)
        other_runner = [dict(components[0], package_digest="9" * 64), *components[1:]]
        for label, mutated in (
            ("other runner package", {**prior, "components": other_runner}),
            ("no component packages", {**prior, "components": [components[2]]}),
            ("other principals", {**prior, "identities": {"controld": {"uid": 1}}}),
            ("other access group", {**prior, "access_group": {"gid": 1}}),
        ):
            with self.subTest(label=label), self.assertRaisesRegex(guest.GuestError, "different component packages or principals"):
                guest.validate_prior_activation(mutated, current)
        with self.assertRaisesRegex(guest.GuestError, "components differ"):
            guest.validate_prior_activation({**prior, "components": None}, current)

    def test_candidate_checkpoint_contract_is_shared_role_scoped_and_ordered(self) -> None:
        self.assertEqual(guest.PROGRESS_PHASES, harness.PROGRESS_PHASES)
        self.assertEqual(
            guest.STAGE_PROGRESS_SUBPHASES,
            harness.STAGE_PROGRESS_SUBPHASES,
        )
        self.assertEqual(
            guest.STAGE_PROGRESS_SUBPHASES,
            stage_controller.STAGE_PROGRESS_NAMES,
        )
        phases = ("guest_started", *self.CANDIDATE_PHASES)
        raw = b"".join(
            progress_frame("candidate", sequence, phase, "start", sequence + 1)
            for sequence, phase in enumerate(phases)
        ) + progress_frame("candidate", len(phases), "complete", "complete", len(phases) + 1)
        parsed = harness.parse_progress(raw, "candidate")
        self.assertEqual(parsed["status"], "valid")
        self.assertTrue(harness.progress_completed(parsed))

        for role in ("ceremony", "verifier"):
            hostile = progress_frame(role, 0, "relay_ready", "start", 1)
            self.assertEqual(harness.parse_progress(hostile, role)["reason"], "boot-phase")
        backward = progress_frame("candidate", 0, "seccomp_ready", "start", 1) + progress_frame(
            "candidate", 1, "principals_created", "start", 2,
        )
        self.assertEqual(harness.parse_progress(backward, "candidate")["reason"], "order")
        stale_timeout = progress_frame("candidate", 0, "seccomp_ready", "start", 1) + progress_frame(
            "candidate", 1, "principals_created", "timeout", 2,
        )
        self.assertEqual(harness.parse_progress(stale_timeout, "candidate")["reason"], "order")
        no_terminal = harness.parse_progress(raw.rsplit(progress_frame(
            "candidate", len(phases), "complete", "complete", len(phases) + 1,
        ), 1)[0], "candidate")
        self.assertFalse(harness.progress_completed(no_terminal))

    def test_stage_progress_protocol_rejects_hostile_streams_and_maps_only_prefixes(self) -> None:
        magic = guest.STAGE_PROGRESS_MAGIC
        record = lambda ordinal: bytes((ordinal, ordinal ^ 0xFF))
        full_prefix = magic + b"".join(record(value) for value in range(1, 47))
        complete = full_prefix + record(0x80)
        unchanged_prefix = magic + b"".join(record(value) for value in range(1, 7))
        unchanged = unchanged_prefix + record(0x81)
        self.assertEqual((len(complete), len(unchanged)), (98, 18))
        self.assertEqual(
            guest.parse_stage_progress(complete, require_complete=True),
            "stage_complete",
        )
        self.assertEqual(
            guest.parse_stage_progress(unchanged, require_complete=True),
            "stage_unchanged",
        )
        prefix = magic + b"".join(record(value) for value in range(1, 16))
        self.assertEqual(
            guest.parse_stage_progress(prefix, require_complete=False), "tmpfiles",
        )
        self.assertIsNone(guest.parse_stage_progress(prefix, require_complete=True))
        self.assertEqual(guest.parse_stage_progress(magic, require_complete=False), "")
        hostile = (
            b"",
            b"BSP\x01" + b"".join(record(value) for value in range(1, 47)),
            magic + b"\x01",
            magic + record(2),
            magic + record(1) + record(1),
            magic + record(1) + record(3),
            magic + bytes((1, 1)),
            full_prefix,
            unchanged_prefix,
            full_prefix + record(0x81),
            full_prefix + record(0x82),
            unchanged_prefix + record(0x80),
            magic + record(0x81),
            full_prefix + bytes((0x80, 0x80)),
            complete + record(0x80),
            unchanged + record(7),
            complete + b"x",
            b"x" * 129,
        )
        for raw in hostile:
            with self.subTest(raw=raw[:12]):
                self.assertIsNone(guest.parse_stage_progress(raw, require_complete=True))
        self.assertIsNone(guest.parse_stage_progress(complete, require_complete=False))
        self.assertIsNone(guest.parse_stage_progress(unchanged, require_complete=False))

        diagnostic = "controller_stage:tmpfiles"
        raw = b"".join((
            progress_frame("candidate", 0, "controller_stage", "start", 1),
            progress_frame("candidate", 1, diagnostic, "start", 2),
            progress_frame("candidate", 2, "rollback", "start", 3),
            progress_frame("candidate", 3, "cleanup", "start", 4),
            progress_frame("candidate", 4, "cleanup_return", "start", 5),
        ))
        parsed = harness.parse_progress(raw, "candidate")
        self.assertEqual(parsed["status"], "valid")
        failure = harness.progress_failure("candidate", parsed, timed_out=False)
        self.assertIn(f"candidate {diagnostic} guest failure", str(failure))
        self.assertNotIn("sentinel-private", str(failure))

        timeout_raw = b"".join((
            progress_frame("candidate", 0, "controller_stage", "start", 1),
            progress_frame("candidate", 1, diagnostic, "timeout", 2),
            progress_frame("candidate", 2, "rollback", "start", 3),
            progress_frame("candidate", 3, "cleanup", "start", 4),
        ))
        timeout_progress = harness.parse_progress(timeout_raw, "candidate")
        self.assertEqual(timeout_progress["status"], "valid")
        timeout_failure = harness.progress_failure(
            "candidate", timeout_progress, timed_out=True,
        )
        self.assertIn(f"candidate {diagnostic} watchdog timeout", str(timeout_failure))
        self.assertFalse(harness.progress_completed(timeout_progress))

    def test_stage_command_emits_only_authenticated_mapped_failure(self) -> None:
        record = lambda ordinal: bytes((ordinal, ordinal ^ 0xFF))
        complete = guest.STAGE_PROGRESS_MAGIC + b"".join(
            record(value) for value in range(1, 47)
        ) + record(0x80)
        unchanged = guest.STAGE_PROGRESS_MAGIC + b"".join(
            record(value) for value in range(1, 7)
        ) + record(0x81)
        prefix = guest.STAGE_PROGRESS_MAGIC + b"".join(
            record(value) for value in range(1, 16)
        )
        scenario_prefix = guest.STAGE_PROGRESS_MAGIC + b"".join(
            record(value) for value in range(1, 4)
        )
        staged_stdout = guest.canonical({
            "status": "staged", "state": "staged_zero", "capacity": 0,
        })
        unchanged_stdout = guest.canonical({
            "status": "unchanged", "state": "staged_zero", "capacity": 0,
        })

        class Process:
            def __init__(self, returncode: int | None) -> None:
                self.returncode = returncode

            def poll(self):
                return self.returncode

        def invoke(
            raw: bytes, returncode: int | None, timeout: int,
            *, stdout_payload: bytes = b"", stderr_payload: bytes = b"",
        ):
            process = Process(returncode)
            descriptors: list[int] = []
            reap_calls = 0
            real_pipe2 = os.pipe2

            def pipe2(flags: int):
                pair = real_pipe2(flags)
                descriptors.extend(pair)
                return pair

            def spawn(_argv, **kwargs):
                os.write(kwargs["pass_fds"][0], raw)
                kwargs["stdout"].write(stdout_payload)
                kwargs["stderr"].write(stderr_payload)
                return process

            def reap(value, **_kwargs):
                nonlocal reap_calls
                reap_calls += 1
                value.returncode = -9 if value.returncode is None else value.returncode

            with tempfile.TemporaryDirectory() as scratch, mock.patch.object(
                guest, "SCRATCH_ROOT", Path(scratch),
            ), mock.patch.object(
                guest.os, "pipe2", side_effect=pipe2,
            ), mock.patch.object(
                guest, "record_command_timing",
            ), mock.patch.object(
                guest.subprocess, "Popen", side_effect=spawn,
            ), mock.patch.object(
                guest, "reap_process_group", side_effect=reap,
            ), mock.patch.object(guest, "emit_progress") as emitted:
                error = None
                result = None
                try:
                    result = guest.stage_command(["controller", "stage"], timeout=timeout)
                except guest.GuestError as caught:
                    error = caught
            self.assertFalse(Path(scratch).exists())
            self.assertEqual(reap_calls, 1)
            self.assertEqual(len(descriptors), 2)
            for descriptor in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
            return result, error, emitted.call_args_list

        result, error, emitted = invoke(complete, 0, 1, stdout_payload=staged_stdout)
        self.assertIsNotNone(result)
        self.assertIsNone(error)
        self.assertEqual(emitted, [])

        result, error, emitted = invoke(unchanged, 0, 1, stdout_payload=unchanged_stdout)
        self.assertIsNotNone(result)
        self.assertIsNone(error)
        self.assertEqual(emitted, [])

        rejected_successes = (
            (prefix, staged_stdout),
            (complete, unchanged_stdout),
            (unchanged, staged_stdout),
            (complete + record(0x80), staged_stdout),
            (complete, b'{"status":"staged","status":"staged","state":"staged_zero","capacity":0}\n'),
            (complete, b'{"status": "staged", "state":"staged_zero","capacity":0}\n'),
            (complete, b'{"status":"staged","state":"staged_zero","capacity":NaN}\n'),
            (complete, b'{"status":"staged","state":"staged_zero"}\n'),
            (complete, b'{"status":"staged","state":"staged_zero","capacity":true}\n'),
        )
        for raw, stdout_payload in rejected_successes:
            with self.subTest(raw=raw[-8:], stdout=stdout_payload[:24]):
                _result, error, emitted = invoke(
                    raw, 0, 1, stdout_payload=stdout_payload,
                )
                self.assertIsInstance(error, guest.GuestError)
                self.assertEqual(emitted, [])

        _result, error, emitted = invoke(complete, 1, 1)
        self.assertIsInstance(error, guest.GuestError)
        self.assertEqual(emitted, [])

        _result, error, emitted = invoke(prefix, 1, 1)
        self.assertIsInstance(error, guest.StageCommandFailure)
        self.assertEqual(error.subphase, "tmpfiles")
        self.assertTrue(error.rollback_required)
        self.assertNotIn("tmpfiles", str(error))
        self.assertEqual(
            emitted,
            [mock.call("controller_stage:tmpfiles", "start")],
        )

        _result, error, emitted = invoke(scenario_prefix, 1, 1)
        self.assertIsInstance(error, guest.StageCommandFailure)
        self.assertEqual(error.subphase, "scenario_binding")
        self.assertFalse(error.rollback_required)
        self.assertEqual(
            emitted,
            [mock.call("controller_stage:scenario_binding", "start")],
        )

        _result, error, emitted = invoke(b"sentinel-private-stderr", 1, 1)
        self.assertIsInstance(error, guest.GuestError)
        self.assertNotIn("sentinel-private", str(error))
        self.assertEqual(emitted, [])

        _result, error, emitted = invoke(
            prefix, 1, 1,
            stdout_payload=b"sentinel-private-stdout",
            stderr_payload=b"sentinel-private-stderr",
        )
        self.assertIsInstance(error, guest.GuestError)
        self.assertNotIn("sentinel-private", str(error))
        self.assertEqual(
            emitted,
            [mock.call("controller_stage:tmpfiles", "start")],
        )

        _result, error, emitted = invoke(prefix, None, 0)
        self.assertIsInstance(error, guest.GuestError)
        self.assertEqual(
            emitted,
            [mock.call("controller_stage:tmpfiles", "timeout")],
        )

    def test_guest_checkpoint_emitter_rejects_unknown_and_backward_phases(self) -> None:
        original = (
            guest._PROGRESS_BOOT, guest._PROGRESS_LAST_PHASE, guest._ACTIVE_PHASE,
        )
        try:
            guest._PROGRESS_BOOT = "candidate"
            guest._PROGRESS_LAST_PHASE = "seccomp_ready"
            guest._ACTIVE_PHASE = "install"
            with self.assertRaisesRegex(guest.GuestError, "progress order differs"):
                guest.emit_progress("caller-controlled")
            with self.assertRaisesRegex(guest.GuestError, "progress order differs"):
                guest.emit_progress("principals_created")
            with mock.patch.object(guest, "emit_progress") as emitted:
                guest.emit_timeout_progress()
            emitted.assert_called_once_with("seccomp_ready", "timeout")
        finally:
            guest._PROGRESS_BOOT, guest._PROGRESS_LAST_PHASE, guest._ACTIVE_PHASE = original

    def test_run_acceptance_checkpoints_follow_completed_boundaries(self) -> None:
        events, error = self.run_mocked_acceptance()
        self.assertIsNone(error)
        self.assertEqual([name for name, _event in events], [*self.CANDIDATE_PHASES, "complete"])

        previous = "install"
        for checkpoint in self.INSTALL_CHECKPOINTS:
            with self.subTest(checkpoint=checkpoint):
                events, error = self.run_mocked_acceptance(fail_at=checkpoint)
                names = [name for name, _event in events]
                self.assertIsInstance(error, guest.GuestError)
                self.assertNotIn(checkpoint, names)
                self.assertIn(previous, names)
                self.assertEqual(names[-2:], ["cleanup", "cleanup_return"])
                raw = b"".join(
                    progress_frame("candidate", sequence, name, event, sequence + 1)
                    for sequence, (name, event) in enumerate(events)
                )
                parsed = harness.parse_progress(raw, "candidate")
                self.assertEqual(parsed["status"], "valid")
                failure = harness.progress_failure("candidate", parsed, timed_out=False)
                self.assertIn(f"candidate {previous} guest failure", str(failure))
                self.assertIn('"cleanup_returned":true', str(failure))
                self.assertNotIn("injected boundary failure", str(failure))
            previous = checkpoint

        # The prior cycle: a failure inside a staged prior phase rolls the prior activation back;
        # a failure before its stage or after its terminal rollback cleans up without one.
        for checkpoint, rolls_back in (
            ("prior_controller_check", False), ("prior_controller_stage", True),
            ("prior_controller_activate", True), ("prior_rollback", True),
            ("execd_reinstalled", False),
        ):
            with self.subTest(checkpoint=checkpoint):
                events, error = self.run_mocked_acceptance(fail_at=checkpoint)
                names = [name for name, _event in events]
                self.assertIsInstance(error, guest.GuestError)
                self.assertNotIn("complete", names)
                self.assertNotIn("controller_check", names)
                reported = "reinstall" if checkpoint == "execd_reinstalled" else checkpoint
                self.assertIn(reported, names)
                self.assertNotIn(checkpoint if checkpoint == "execd_reinstalled" else "execd_reinstalled", names)
                expected_tail = ["rollback", "cleanup", "cleanup_return"] if rolls_back else ["cleanup", "cleanup_return"]
                self.assertEqual(names[-len(expected_tail) - 1:], [reported, *expected_tail])
                raw = b"".join(
                    progress_frame("candidate", sequence, name, event, sequence + 1)
                    for sequence, (name, event) in enumerate(events)
                )
                parsed = harness.parse_progress(raw, "candidate")
                self.assertEqual(parsed["status"], "valid")
                failure = harness.progress_failure("candidate", parsed, timed_out=False)
                self.assertIn(f"candidate {reported} guest failure", str(failure))

        events, error = self.run_mocked_acceptance(fail_at="controller_stage")
        names = [name for name, _event in events]
        self.assertIsInstance(error, guest.GuestError)
        self.assertEqual(
            names[-4:], ["controller_stage", "rollback", "cleanup", "cleanup_return"],
        )
        self.assertNotIn("complete", names)

        events, error = self.run_mocked_acceptance(
            stage_failure=True, stage_subphase="scenario_binding",
        )
        names = [name for name, _event in events]
        self.assertIsInstance(error, guest.GuestError)
        self.assertEqual(
            names[-4:], [
                "controller_stage", "controller_stage:scenario_binding",
                "cleanup", "cleanup_return",
            ],
        )
        self.assertNotIn("rollback", names)

        for subphase in ("preflight", "fixed_package_install", None):
            with self.subTest(stage_subphase=subphase):
                events, error = self.run_mocked_acceptance(
                    stage_failure=True, stage_subphase=subphase,
                )
                names = [name for name, _event in events]
                self.assertIsInstance(error, guest.GuestError)
                self.assertIn("rollback", names)
                self.assertEqual(names[-2:], ["cleanup", "cleanup_return"])

    def test_cleanup_return_requires_successful_cleanup(self) -> None:
        events, error = self.run_mocked_acceptance(cleanup_errors=("cleanup failed",))
        self.assertIsInstance(error, guest.GuestError)
        names = [name for name, _event in events]
        self.assertEqual(names[-1], "cleanup")
        self.assertNotIn("cleanup_return", names)
        self.assertNotIn("complete", names)

    def test_cleanup_tail_reports_last_authenticated_operational_phase(self) -> None:
        raw = b"".join((
            progress_frame("candidate", 0, "controller_stage", "start", 1),
            progress_frame("candidate", 1, "rollback", "start", 2),
            progress_frame("candidate", 2, "cleanup", "start", 3),
        ))
        failure = harness.progress_failure(
            "candidate", harness.parse_progress(raw, "candidate"), timed_out=False,
        )
        self.assertIn("candidate controller_stage guest failure", str(failure))
        self.assertIn('"cleanup_returned":false', str(failure))

        events, error = self.run_mocked_acceptance(
            cleanup_errors=("cleanup transport failed", "dormant proof failed"),
        )
        self.assertIsInstance(error, guest.GuestError)
        self.assertEqual([name for name, _event in events][-2:], ["rollback", "cleanup"])
        self.assertNotIn("cleanup_return", [name for name, _event in events])
        progress = b"".join(
            progress_frame("candidate", sequence, name, event, sequence + 1)
            for sequence, (name, event) in enumerate(events)
        )
        cleanup_failure = harness.progress_failure(
            "candidate", harness.parse_progress(progress, "candidate"), timed_out=False,
        )
        self.assertIn("candidate receipt_verifier guest failure", str(cleanup_failure))
        self.assertIn('"cleanup_returned":false', str(cleanup_failure))
        self.assertNotIn("transport", str(cleanup_failure))
        self.assertNotIn("dormant proof", str(cleanup_failure))

    def test_cleanup_enters_rollback_then_cleanup_without_filesystem_access(self) -> None:
        events: list[str] = []
        completed = subprocess.CompletedProcess(["mocked"], 0, b"", b"")
        with mock.patch.object(
            guest, "begin_phase", side_effect=events.append,
        ), mock.patch.object(
            guest, "command", return_value=completed,
        ), mock.patch.object(
            guest.shutil, "rmtree",
        ), mock.patch.object(
            Path, "is_file", return_value=False,
        ), mock.patch.object(
            Path, "exists", return_value=False,
        ), mock.patch.object(
            Path, "unlink", side_effect=FileNotFoundError,
        ):
            errors = guest.cleanup(
                Path("/not-accessed/candidate"), Path("/not-accessed/activation"), True, False,
            )
        self.assertEqual(errors, [])
        self.assertEqual(events, ["rollback", "cleanup"])

    def test_rc_zero_requires_one_timeout_free_terminal_progress_record(self) -> None:
        evidence_value = {"schema_version": harness.FRAME_SCHEMA, "outcome": "pass"}
        evidence_payload = harness.canonical(evidence_value)
        evidence_frame = (
            struct.pack(">I", len(evidence_payload))
            + evidence_payload
            + hashlib.sha256(evidence_payload).digest()
        )
        cases = {
            "candidate": (
                "candidate.qcow2", False, "read-write",
                (
                    ("missing", b"", "boot_cloud_init guest failure"),
                    ("truncated", progress_frame("candidate", 0, "install", "start", 1)[:-1], "boot_cloud_init guest failure"),
                    ("install-only", progress_frame("candidate", 0, "install", "start", 1), "install guest failure"),
                    ("no-complete", b"".join((
                        progress_frame("candidate", 0, "guest_started", "start", 1),
                        progress_frame("candidate", 1, "install", "start", 2),
                        progress_frame("candidate", 2, "cleanup", "start", 3),
                    )), "install guest failure"),
                    ("timeout-then-complete", b"".join((
                        progress_frame("candidate", 0, "canary", "start", 1),
                        progress_frame("candidate", 1, "canary", "timeout", 2),
                        progress_frame("candidate", 2, "cleanup", "start", 3),
                        progress_frame("candidate", 3, "complete", "complete", 4),
                    )), "canary inner timeout"),
                    ("duplicate-complete", b"".join((
                        progress_frame("candidate", 0, "complete", "complete", 1),
                        progress_frame("candidate", 1, "complete", "complete", 2),
                    )), "complete guest failure"),
                ),
            ),
            "verifier": (
                "verifier.qcow2", True, "read-only",
                (
                    ("missing", b"", "boot_cloud_init guest failure"),
                    ("truncated", progress_frame("verifier", 0, "verifier", "start", 1)[:-1], "boot_cloud_init guest failure"),
                    ("install-only", progress_frame("verifier", 0, "install", "start", 1), "install guest failure"),
                    ("no-complete", b"".join((
                        progress_frame("verifier", 0, "guest_started", "start", 1),
                        progress_frame("verifier", 1, "verifier", "start", 2),
                    )), "verifier guest failure"),
                    ("timeout-then-complete", b"".join((
                        progress_frame("verifier", 0, "verifier", "start", 1),
                        progress_frame("verifier", 1, "verifier", "timeout", 2),
                        progress_frame("verifier", 2, "complete", "complete", 3),
                    )), "verifier inner timeout"),
                    ("duplicate-complete", b"".join((
                        progress_frame("verifier", 0, "complete", "complete", 1),
                        progress_frame("verifier", 1, "complete", "complete", 2),
                    )), "complete guest failure"),
                ),
            ),
        }
        for role, (overlay, evidence_expected, transfer, mutations) in cases.items():
            for name, raw_progress, expected in mutations:
                with self.subTest(role=role, mutation=name), tempfile.TemporaryDirectory() as temporary:
                    state = Path(temporary)
                    process = mock.Mock()
                    process.poll.return_value = 0

                    def spawn(*_args, **_kwargs):
                        (state / "progress.bin").write_bytes(raw_progress)
                        if evidence_expected:
                            (state / "evidence.bin").write_bytes(evidence_frame)
                        return process

                    with mock.patch.object(harness.subprocess, "Popen", side_effect=spawn), mock.patch.object(
                        harness, "reap_process_group",
                    ), mock.patch.object(harness, "parse_frame", wraps=harness.parse_frame) as parse_frame:
                        with self.assertRaisesRegex(harness.HarnessError, expected):
                            harness.boot(
                                state, harness.watchdog_seconds(role), overlay=overlay,
                                evidence_expected=evidence_expected, transfer=transfer,
                            )
                    parse_frame.assert_not_called()

    def test_rc_zero_with_exact_terminal_progress_preserves_each_boot_role(self) -> None:
        evidence_value = {"schema_version": harness.FRAME_SCHEMA, "outcome": "pass"}
        evidence_payload = harness.canonical(evidence_value)
        evidence_frame = (
            struct.pack(">I", len(evidence_payload))
            + evidence_payload
            + hashlib.sha256(evidence_payload).digest()
        )
        cases = (
            ("ceremony", "ceremony.qcow2", True, None, ("guest_started", "ceremony")),
            (
                "candidate", "candidate.qcow2", False, "read-write",
                ("guest_started", *self.CANDIDATE_PHASES),
            ),
            ("verifier", "verifier.qcow2", True, "read-only", ("guest_started", "verifier")),
        )
        for role, overlay, evidence_expected, transfer, phases in cases:
            raw_progress = b"".join(
                progress_frame(role, sequence, phase, "start", sequence + 1)
                for sequence, phase in enumerate(phases)
            ) + progress_frame(role, len(phases), "complete", "complete", len(phases) + 1)
            with self.subTest(role=role), tempfile.TemporaryDirectory() as temporary:
                state = Path(temporary)
                process = mock.Mock()
                process.poll.return_value = 0

                def spawn(*_args, **_kwargs):
                    (state / "progress.bin").write_bytes(raw_progress)
                    if evidence_expected:
                        (state / "evidence.bin").write_bytes(evidence_frame)
                    return process

                with mock.patch.object(harness.subprocess, "Popen", side_effect=spawn), mock.patch.object(
                    harness, "reap_process_group",
                ):
                    result = harness.boot(
                        state, harness.watchdog_seconds(role), overlay=overlay,
                        evidence_expected=evidence_expected, transfer=transfer,
                    )
                self.assertEqual(result, evidence_value if evidence_expected else None)

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
        self.assertEqual(inventory["prior_controller_stage"], inventory["controller_stage"])
        self.assertEqual(inventory["prior_controller_check"], inventory["controller_check"])
        self.assertEqual(inventory["prior_controller_activate"], inventory["controller_activate"])
        self.assertEqual(inventory["prior_rollback"], inventory["rollback"])
        self.assertEqual(inventory["reinstall"]["command_default"], 4 + len(guest.UNITS))
        self.assertEqual(inventory["reinstall"]["guest_command_reap"], 4 + len(guest.UNITS))
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

    def test_canary_command_forwards_exact_qualification_credentials(self) -> None:
        activation = {"manifest": "exact"}
        public = {"binding": "exact"}
        scenario = b'{"scenario":"exact"}'
        completed = subprocess.CompletedProcess(
            ["/usr/libexec/buzz-ci-capacity-one-canary"], 0, b"receipt", b"",
        )
        with mock.patch.object(
            guest, "assert_live_acceptance_roles", return_value=(961, 961, [62005]),
        ) as credentials, mock.patch.object(
            guest, "command", return_value=completed,
        ) as command:
            self.assertEqual(
                guest.run_capacity_one_canary(activation, scenario, public),
                b"receipt",
            )
        credentials.assert_called_once_with(activation, public)
        command.assert_called_once_with(
            ["/usr/libexec/buzz-ci-capacity-one-canary"],
            stdin=scenario,
            timeout=guest.canary_command_seconds(),
            timing_terms={},
            uid=961,
            gid=961,
            supplementary_gids=[62005],
        )

    def test_qualification_credentials_are_exact_and_minimal(self) -> None:
        activation = {
            "identities": {
                "qualification": {
                    "uid": 961,
                    "gid": 961,
                    "supplementary_groups": ["buzzci-execd"],
                },
            },
            "access_group": {
                "group": "buzzci-execd",
                "gid": 62005,
                "members": ["buzzci-ctl", "buzzci-runner"],
            },
        }
        self.assertEqual(guest.qualification_credentials(activation), (961, 961, [62005]))
        identity_mutations = (
            ("uid", 0),
            ("gid", 0),
            ("supplementary_groups", []),
            ("supplementary_groups", ["buzzci-execd", "extra"]),
        )
        for field, value in identity_mutations:
            changed = copy.deepcopy(activation)
            changed["identities"]["qualification"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(
                guest.GuestError, "qualification credentials differ",
            ):
                guest.qualification_credentials(changed)
        for field, value in (
            ("group", "wrong"),
            ("gid", 0),
            ("gid", True),
            ("members", ["buzzci-ctl"]),
        ):
            changed = copy.deepcopy(activation)
            changed["access_group"][field] = value
            with self.subTest(access_group=field), self.assertRaisesRegex(
                guest.GuestError, "qualification credentials differ",
            ):
                guest.qualification_credentials(changed)

    def assert_live_acceptance_roles_for_status(
        self,
        status: str | None = None,
        *,
        prepared: tuple[int, int] = (62002, 62002),
        activation_controld: tuple[int, int] | None = None,
        controld_account: tuple[int, int] | None = None,
        actor_account: tuple[int, int] | None = None,
        binding_peer: tuple[int, int] | None = None,
        keyholder_peer: tuple[int, int] | None = None,
        process: tuple[int, int] | None = None,
    ) -> tuple[int, int, list[int]]:
        """Drive the live role assertion against one prepared controld identity.

        `prepared` is the identity the key ceremony recorded in the public
        binding. Every live value defaults to that identity; a keyword override
        models one live value that differs from the prepared one.
        """
        activation_controld = activation_controld or prepared
        controld_account = controld_account or prepared
        actor_account = actor_account or (961, 961)
        binding_peer = binding_peer or prepared
        keyholder_peer = keyholder_peer or prepared
        process = process or prepared
        if status is None:
            status = (
                f"Uid:\t{process[0]}\t{process[0]}\t{process[0]}\t{process[0]}\n"
                f"Gid:\t{process[1]}\t{process[1]}\t{process[1]}\t{process[1]}\n"
                "Groups:\t\n"
            )
        public = {
            "keyholder_public_spec": {
                "peer": {"uid": prepared[0], "gid": prepared[1], "allowed_operations": ["describe"]},
            },
        }
        activation = {
            "identities": {
                "controld": {
                    "uid": activation_controld[0],
                    "gid": activation_controld[1],
                    "supplementary_groups": [],
                },
                "qualification": {
                    "uid": 961,
                    "gid": 961,
                    "supplementary_groups": ["buzzci-execd"],
                },
            },
            "access_group": {
                "group": "buzzci-execd",
                "gid": 62005,
                "members": ["buzzci-ctl", "buzzci-runner"],
            },
        }
        accounts = {
            "buzzci-controld": mock.Mock(pw_uid=controld_account[0], pw_gid=controld_account[1]),
            "buzzci-ctl": mock.Mock(pw_uid=actor_account[0], pw_gid=actor_account[1]),
        }
        binding = {
            "schema_version": "buzz-ci-activation-acceptance-binding/v2",
            "keyholder_peer_uid": binding_peer[0],
            "keyholder_peer_gid": binding_peer[1],
            "acceptance_peer_uid": 961,
            "acceptance_peer_gid": 961,
        }
        keyholder = {"peer": {"uid": keyholder_peer[0], "gid": keyholder_peer[1]}}
        socket_metadata = mock.Mock(
            st_mode=stat.S_IFSOCK | 0o620,
            st_uid=0,
            st_gid=961,
        )
        socket_path = mock.Mock()
        socket_path.lstat.return_value = socket_metadata
        real_path = Path
        with tempfile.TemporaryDirectory() as temporary:
            proc_root = Path(temporary) / "proc"
            process_root = proc_root / "123"
            process_root.mkdir(parents=True)
            (process_root / "exe").symlink_to("/usr/libexec/buzz-ci-controld")
            (process_root / "status").write_text(status)

            def mapped_path(value: object) -> object:
                if str(value) == "/proc":
                    return proc_root
                if str(value) == "/run/buzzci/controld-acceptance.sock":
                    return socket_path
                return real_path(value)

            with mock.patch.object(guest, "Path", side_effect=mapped_path), mock.patch.object(
                guest.pwd, "getpwnam", side_effect=accounts.__getitem__,
            ), mock.patch.object(guest, "load_json", side_effect=(binding, keyholder)):
                return guest.assert_live_acceptance_roles(activation, public)

    def test_live_acceptance_roles_derive_controld_identity_from_the_prepared_binding(self) -> None:
        for prepared in ((1201, 1201), (62002, 62002)):
            with self.subTest(prepared=prepared):
                self.assertEqual(
                    self.assert_live_acceptance_roles_for_status(prepared=prepared),
                    (961, 961, [62005]),
                )

    def test_live_acceptance_roles_reject_any_role_that_differs_from_the_prepared_binding(self) -> None:
        for prepared, other in (((1201, 1201), (62002, 62002)), ((62002, 62002), (1201, 1201))):
            for field, message in (
                ("activation_controld", "installed acceptance identities differ"),
                ("controld_account", "installed acceptance identities differ"),
                ("binding_peer", "acceptance role binding differs"),
                ("keyholder_peer", "acceptance role binding differs"),
                ("process", "live controld credentials differ"),
            ):
                with self.subTest(prepared=prepared, field=field), self.assertRaisesRegex(
                    guest.GuestError, message,
                ):
                    self.assert_live_acceptance_roles_for_status(prepared=prepared, **{field: other})
            with self.subTest(prepared=prepared, field="actor_account"), self.assertRaisesRegex(
                guest.GuestError, "installed acceptance identities differ",
            ):
                self.assert_live_acceptance_roles_for_status(prepared=prepared, actor_account=(962, 961))

    def test_prepared_controld_identity_rejects_an_unusable_binding_peer(self) -> None:
        activation = {"identities": {"controld": {"uid": 1201, "gid": 1201, "supplementary_groups": []}}}
        for peer in ({}, {"uid": 0, "gid": 1201}, {"uid": True, "gid": 1201}, {"uid": 1201, "gid": "1201"}, None):
            public = {"keyholder_public_spec": {"peer": peer}}
            with self.subTest(peer=peer), self.assertRaisesRegex(guest.GuestError, "prepared controld identity differs"):
                guest.prepared_controld_identity(public, activation)
        with self.assertRaisesRegex(guest.GuestError, "prepared controld identity differs"):
            guest.prepared_controld_identity({}, activation)
        self.assertEqual(
            guest.prepared_controld_identity({"keyholder_public_spec": {"peer": {"uid": 1201, "gid": 1201}}}, activation),
            (1201, 1201),
        )
        grouped = copy.deepcopy(activation)
        grouped["identities"]["controld"]["supplementary_groups"] = ["buzzci-execd"]
        with self.assertRaisesRegex(guest.GuestError, "installed acceptance identities differ"):
            guest.prepared_controld_identity({"keyholder_public_spec": {"peer": {"uid": 1201, "gid": 1201}}}, grouped)

    def test_guest_entry_carries_no_literal_acceptance_role_identity(self) -> None:
        source = Path(guest.__file__).read_text()
        for literal in ("62002", "961", "1201"):
            self.assertIsNone(re.search(rf"\b{literal}\b", source), literal)

    def test_live_acceptance_roles_accepts_a_groups_record_without_extra_groups(self) -> None:
        for prepared, groups_record in (
            ((62002, 62002), "Groups:\t\n"),
            ((62002, 62002), "Groups:\t62002 \n"),
            ((1201, 1201), "Groups:\t\n"),
            ((1201, 1201), "Groups:\t1201 \n"),
        ):
            with self.subTest(prepared=prepared, groups=groups_record):
                self.assertEqual(
                    self.assert_live_acceptance_roles_for_status(
                        f"Uid:\t{prepared[0]}\t{prepared[0]}\t{prepared[0]}\t{prepared[0]}\n"
                        f"Gid:\t{prepared[1]}\t{prepared[1]}\t{prepared[1]}\t{prepared[1]}\n"
                        + groups_record,
                        prepared=prepared,
                    ),
                    (961, 961, [62005]),
                )

    def test_live_acceptance_roles_accepts_the_systemd_259_primary_gid_groups_record(self) -> None:
        """systemd 259 starts a User= service with `Groups: <primary gid>` (initgroups semantics)."""
        self.assertEqual(
            self.assert_live_acceptance_roles_for_status(
                "Uid:\t1201\t1201\t1201\t1201\n"
                "Gid:\t1201\t1201\t1201\t1201\n"
                "Groups:\t1201 \n",
                prepared=(1201, 1201),
            ),
            (961, 961, [62005]),
        )

    def test_live_acceptance_roles_rejects_a_groups_record_with_an_extra_group(self) -> None:
        for prepared, groups_record in (
            ((62002, 62002), "Groups:\t62005\n"),
            ((62002, 62002), "Groups:\t62002 62005 \n"),
            ((1201, 1201), "Groups:\t1201 1204 \n"),
            ((1201, 1201), "Groups:\t1204 \n"),
            ((1201, 1201), "Groups:\t0 \n"),
            ((1201, 1201), "Groups:\t62002 \n"),
            ((1201, 1201), "Groups:\tbuzzci-controld\n"),
        ):
            with self.subTest(prepared=prepared, groups=groups_record), self.assertRaisesRegex(
                guest.GuestError, "live controld credentials differ",
            ):
                self.assert_live_acceptance_roles_for_status(
                    f"Uid:\t{prepared[0]}\t{prepared[0]}\t{prepared[0]}\t{prepared[0]}\n"
                    f"Gid:\t{prepared[1]}\t{prepared[1]}\t{prepared[1]}\t{prepared[1]}\n"
                    + groups_record,
                    prepared=prepared,
                )

    def test_live_supplementary_gids_drop_only_the_primary_gid(self) -> None:
        self.assertEqual(guest.live_supplementary_gids("\t\n", 1201), set())
        self.assertEqual(guest.live_supplementary_gids("\t1201 \n", 1201), set())
        self.assertEqual(guest.live_supplementary_gids("\t1201 1204 \n", 1201), {1204})
        self.assertEqual(guest.live_supplementary_gids("\t1204 \n", 1201), {1204})
        with self.assertRaises(ValueError):
            guest.live_supplementary_gids("\tbuzzci-execd\n", 1201)

    def test_manifest_supplementary_gids_resolve_the_role_groups(self) -> None:
        activation = {
            "identities": {
                "controld": {"supplementary_groups": []},
                "qualification": {"supplementary_groups": ["buzzci-execd"]},
            },
        }
        self.assertEqual(guest.manifest_supplementary_gids(activation, "controld"), set())
        with mock.patch.object(guest.grp, "getgrnam", return_value=mock.Mock(gr_gid=1204)) as getgrnam:
            self.assertEqual(guest.manifest_supplementary_gids(activation, "qualification"), {1204})
        getgrnam.assert_called_once_with("buzzci-execd")
        for broken in ({}, {"identities": {}}, {"identities": {"controld": {}}}, {"identities": {"controld": {"supplementary_groups": [1204]}}}):
            with self.subTest(activation=broken), self.assertRaisesRegex(
                guest.GuestError, "installed acceptance identities differ",
            ):
                guest.manifest_supplementary_gids(broken, "controld")

    def test_live_acceptance_roles_rejects_missing_groups_record(self) -> None:
        with self.assertRaisesRegex(guest.GuestError, "live controld credentials differ"):
            self.assert_live_acceptance_roles_for_status(
                "Uid:\t62002\t62002\t62002\t62002\n"
                "Gid:\t62002\t62002\t62002\t62002\n",
            )

    def test_canary_stage_mutations_change_nested_bound(self) -> None:
        stages = json.loads((HERE.parents[2] / "acceptance/expected-stages.json").read_bytes())

        def operations(candidate_stages: list[str]) -> int:
            return len(candidate_stages)

        declared = harness.TIMING_CONTRACT["phase_terms"]["canary"]["driver_operation"]
        self.assertEqual(operations(stages), declared)
        self.assertNotEqual(operations([*stages, "mutated_stage"]), declared)
        self.assertNotEqual(operations(stages[:-1]), declared)

    def test_watchdog_boundaries_cover_legal_sequences_cleanup_poweroff_and_reap(self) -> None:
        expected = {"ceremony": 1130, "candidate": 7222, "verifier": 320}
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
        self.assertEqual(harness.phase_seconds("prior_controller_stage"), harness.phase_seconds("controller_stage"))
        self.assertGreater(harness.phase_seconds("reinstall"), 17 * 30 + 17 * 10)
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
            "install", *self.INSTALL_CHECKPOINTS, *self.PRIOR_CHECKPOINTS, "controller_stage", "canary",
            "receipt_verifier", "rollback", "cleanup", "cleanup_return",
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
            self.assertIn("ro,nosuid,nodev,noexec", user_data)
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
    def test_guest_unit_inventory_accepts_direct_unit_and_valid_drop_in(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inputs = Path(temporary) / "inputs"
            write_guest_package(inputs, "runner", [
                (
                    "buzz-ci-runner.service", "/usr/lib/systemd/system/buzz-ci-runner.service",
                    b"[Service]\nExecStart=/usr/libexec/buzz-ci-runner\n",
                ),
                (
                    "20-capacity-one.conf",
                    "/etc/systemd/system/buzz-ci-runner.service.d/20-capacity-one.conf",
                    b"[Service]\nEnvironment=BUZZ_CI_CAPACITY=1\n",
                ),
            ])

            expected = guest.expected_unit_fragments(inputs, ("runner",))

            self.assertEqual(set(expected), {"buzz-ci-runner.service"})
            self.assertEqual(
                expected["buzz-ci-runner.service"]["fragment_path"],
                "/usr/lib/systemd/system/buzz-ci-runner.service",
            )

    def test_guest_unit_inventory_rejects_malformed_or_nested_paths(self) -> None:
        invalid = (
            "/usr/lib/systemd/system/buzz-ci-runner.timer",
            "/etc/systemd/system/buzz-ci-runner.service.d/nested/20-capacity-one.conf",
            "/etc/systemd/system/buzz-ci-runner.service.d/../20-capacity-one.conf",
            "/etc/systemd/system//buzz-ci-runner.service",
        )
        for target in invalid:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                inputs = Path(temporary) / "inputs"
                write_guest_package(inputs, "runner", [("payload", target, b"payload")])
                with self.assertRaisesRegex(guest.GuestError, "unit inventory differs"):
                    guest.expected_unit_fragments(inputs, ("runner",))

    def test_guest_unit_inventory_rejects_invalid_drop_in_parent_suffix(self) -> None:
        invalid = (
            "/etc/systemd/system/buzz-ci-runner.timer.d/20-capacity-one.conf",
            "/etc/systemd/system/buzz-ci-runner.service/20-capacity-one.conf",
            "/etc/systemd/system/.service.d/20-capacity-one.conf",
        )
        for target in invalid:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                inputs = Path(temporary) / "inputs"
                write_guest_package(inputs, "runner", [("payload", target, b"payload")])
                with self.assertRaisesRegex(guest.GuestError, "unit inventory differs"):
                    guest.expected_unit_fragments(inputs, ("runner",))

    def test_guest_unit_inventory_rejects_invalid_drop_in_name(self) -> None:
        invalid = (
            "/etc/systemd/system/buzz-ci-runner.service.d/20-capacity-one.txt",
            "/etc/systemd/system/buzz-ci-runner.service.d/.conf",
            "/etc/systemd/system/buzz-ci-runner.service.d/-hostile.conf",
        )
        for target in invalid:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                inputs = Path(temporary) / "inputs"
                write_guest_package(inputs, "runner", [("payload", target, b"payload")])
                with self.assertRaisesRegex(guest.GuestError, "unit inventory differs"):
                    guest.expected_unit_fragments(inputs, ("runner",))

    def test_guest_unit_inventory_retains_digest_and_conflict_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inputs = Path(temporary) / "inputs"
            package = write_guest_package(inputs, "runner", [(
                "drop-in", "/etc/systemd/system/buzz-ci-runner.service.d/20-capacity-one.conf",
                b"trusted",
            )])
            (package / "drop-in").write_bytes(b"changed")
            with self.assertRaisesRegex(guest.GuestError, "unit digest differs"):
                guest.expected_unit_fragments(inputs, ("runner",))

        with tempfile.TemporaryDirectory() as temporary:
            inputs = Path(temporary) / "inputs"
            write_guest_package(inputs, "runner", [(
                "runner-unit", "/usr/lib/systemd/system/buzz-ci-runner.service", b"first",
            )])
            write_guest_package(inputs, "controld", [(
                "runner-unit", "/etc/systemd/system/buzz-ci-runner.service", b"second",
            )])
            with self.assertRaisesRegex(guest.GuestError, "unit binding conflicts"):
                guest.expected_unit_fragments(inputs, ("runner", "controld"))

    def test_guest_requires_exact_fedora_global_service_drop_in(self) -> None:
        self.assertEqual(guest.PLATFORM_SYSTEMD, harness.PLATFORM_SYSTEMD)
        schema = json.loads((HERE / "contract.schema.json").read_bytes())
        self.assertEqual(schema["properties"]["platform_systemd"]["const"], guest.PLATFORM_SYSTEMD)
        expected = (
            HERE.parents[1]
            / "platform/fedora-44-systemd-259/10-timeout-abort.conf"
        ).read_bytes()
        with mock.patch.object(guest, "read_file", return_value=expected) as opened:
            guest.verify_platform_systemd(copy.deepcopy(guest.PLATFORM_SYSTEMD))
        opened.assert_called_once_with(
            Path("/usr/lib/systemd/system/service.d/10-timeout-abort.conf"),
            guest.MAX_JSON,
        )

        mutations = []
        for field, value in (
            ("path", "/etc/systemd/system/service.d/10-timeout-abort.conf"),
            ("sha256", "0" * 64),
        ):
            changed = copy.deepcopy(guest.PLATFORM_SYSTEMD)
            changed["service_drop_ins"][0][field] = value
            mutations.append(changed)
        extra = copy.deepcopy(guest.PLATFORM_SYSTEMD)
        extra["service_drop_ins"].append({
            "owner": "platform",
            "path": "/usr/lib/systemd/system/service.d/99-hostile.conf",
            "sha256": "1" * 64,
        })
        mutations.append(extra)
        mutations.append({**copy.deepcopy(guest.PLATFORM_SYSTEMD), "service_drop_ins": []})
        for changed in mutations:
            with self.subTest(changed=changed), self.assertRaisesRegex(
                guest.GuestError, "platform binding differs",
            ):
                guest.verify_platform_systemd(changed)
        with mock.patch.object(guest, "read_file", return_value=b"[Service]\nHostile=yes\n"):
            with self.assertRaisesRegex(guest.GuestError, "platform file digest differs"):
                guest.verify_platform_systemd(copy.deepcopy(guest.PLATFORM_SYSTEMD))

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

    def test_run_stage_archive_matches_guest_scope_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate"
            candidate.mkdir()
            subprocess.run(["/usr/bin/git", "init", "--quiet", str(candidate)], check=True)
            source = candidate / "deploy/native-ci/probe.txt"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"candidate-bound\n")
            subprocess.run(
                ["/usr/bin/git", "-C", str(candidate), "add", "deploy/native-ci/probe.txt"],
                check=True,
            )
            subprocess.run(
                [
                    "/usr/bin/git", "-C", str(candidate),
                    "-c", "user.name=Clean Host Test",
                    "-c", "user.email=clean-host@example.invalid",
                    "commit", "--quiet", "-m", "candidate",
                ],
                check=True,
            )
            candidate_sha = subprocess.run(
                ["/usr/bin/git", "-C", str(candidate), "rev-parse", "HEAD^{commit}"],
                check=True, capture_output=True, text=True,
            ).stdout.strip()
            source.write_bytes(b"uncommitted\n")

            state = root / "state"
            state.mkdir()
            (state / "state.json").write_bytes(harness.canonical({"challenge": "1" * 64}))
            (state / "public-binding.json").write_bytes(b"{}\n")
            frozen = state / "frozen-assets"
            frozen.mkdir()
            for name in harness.GUEST_ASSETS:
                (frozen / name).write_bytes(("frozen-" + name).encode())
            records = package_records()
            contract = {
                "candidate_root": str(candidate),
                "candidate_sha": candidate_sha,
                "harness_sha256": "2" * 64,
                "timing_asset_sha256": "3" * 64,
                "timing_sha256": harness.timing_sha256(),
                "scenario": {"sha256": hashlib.sha256(b"{}\n").hexdigest()},
                "prior_scenario": {"sha256": hashlib.sha256(b"{\"prior\":true}\n").hexdigest()},
                "platform_systemd": copy.deepcopy(harness.PLATFORM_SYSTEMD),
            }
            archive = b""
            staged: dict[str, object] = {}

            def capture_archive(stage: Path, _output: Path, _label: str) -> None:
                nonlocal archive
                archive = (stage / "candidate.tar").read_bytes()
                staged["descriptor"] = json.loads((stage / "descriptor.json").read_bytes())
                staged["prior_scenario"] = (stage / "inputs/prior/scenario.json").read_bytes()
                staged["prior_trees"] = {
                    name: harness.tree_digest(harness.tree_records(stage / "inputs/prior" / name))
                    for name in harness.PRIOR_PACKAGE_NAMES
                }

            with mock.patch.object(harness, "make_iso", side_effect=capture_archive), mock.patch.object(
                harness, "make_seed",
            ):
                harness.create_run_stage(contract, state, records, b"{}\n", b"seccomp\n", b"{\"prior\":true}\n")
            self.assertEqual(staged["descriptor"]["schema_version"], guest.STAGE_SCHEMA)
            self.assertEqual(staged["prior_scenario"], b"{\"prior\":true}\n")
            self.assertEqual(staged["descriptor"]["prior_scenario_sha256"], contract["prior_scenario"]["sha256"])
            self.assertEqual(
                staged["descriptor"]["prior_package_tree_sha256"],
                {name: harness.tree_digest(records[f"prior/{name}"]) for name in harness.PRIOR_PACKAGE_NAMES},
            )
            self.assertEqual(staged["prior_trees"], staged["descriptor"]["prior_package_tree_sha256"])

            extracted = root / "extracted"
            guest.extract_candidate(archive, extracted)
            self.assertEqual(
                (extracted / "deploy/native-ci/probe.txt").read_bytes(),
                b"candidate-bound\n",
            )
            with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as handle:
                self.assertEqual(handle.getmembers()[0].name, "deploy/native-ci")

            hostile = io.BytesIO()
            with tarfile.open(fileobj=hostile, mode="w:") as handle:
                member = tarfile.TarInfo("outside.txt")
                member.size = len(b"hostile\n")
                handle.addfile(member, io.BytesIO(b"hostile\n"))
            with self.assertRaisesRegex(guest.GuestError, "archive scope differs"):
                guest.extract_candidate(hostile.getvalue(), root / "hostile")

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
                "schema_version": harness.EVIDENCE_SCHEMA,
                "candidate_sha": candidate, "image_sha256": "5" * 64,
                "tool_sha256": {name: "6" * 64 for name in harness.TOOLS},
                "harness_sha256": assets["harness.py"],
                "timing_asset_sha256": assets["timing-contract.json"],
                "harness_asset_sha256": assets, "package_tree_sha256": {},
                "prior_package_tree_sha256": {}, "prior_scenario_sha256": "8" * 64,
                "prior_activation": prior_activation_proof(),
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
            lambda value: value["platform_systemd"]["service_drop_ins"][0].update(sha256="0" * 64),
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
            records = package_records()
            contract["prior_packages"] = {
                name: {"path": "unused", "tree_sha256": harness.tree_digest(records[f"prior/{name}"])}
                for name in harness.PRIOR_PACKAGE_NAMES
            }
            contract["prior_scenario"] = {"path": "unused", "sha256": "8" * 64}
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
                "prior_activation": prior_activation_proof(),
            }

            def create_image(image_state, name, _backing):
                (image_state / name).write_bytes(b"overlay")

            def boot(_state, _timeout, *, overlay, **_kwargs):
                return frame if overlay == "verifier.qcow2" else None

            verify_stages = []
            with mock.patch.object(harness, "qemu_img_create", side_effect=create_image), mock.patch.object(
                harness, "create_run_stage",
            ), mock.patch.object(
                harness, "create_verify_stage", side_effect=lambda *arguments: verify_stages.append(arguments),
            ), mock.patch.object(
                harness, "validate_prepared_state", return_value=state_record(),
            ), mock.patch.object(harness, "boot", side_effect=boot), mock.patch.object(
                harness, "replay_frozen_verifier",
            ):
                outcome = harness.run_vm(contract, state, records, b"{}\n", b"{}\n", results)
            self.assertEqual([arguments[3] for arguments in verify_stages], [PRIOR_ACTIVATION])
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
            self.assertEqual(manifest["schema_version"], harness.EVIDENCE_SCHEMA)
            self.assertEqual(manifest["prior_activation"], prior_activation_proof())
            self.assertEqual(manifest["prior_scenario_sha256"], "8" * 64)
            self.assertEqual(
                manifest["prior_package_tree_sha256"],
                {name: harness.tree_digest(records[f"prior/{name}"]) for name in harness.PRIOR_PACKAGE_NAMES},
            )
            drifted = dict(frame, prior_activation={**prior_activation_proof(), "activation_id": "other"})
            with self.assertRaisesRegex(harness.HarnessError, "prior activation proof differs"):
                harness.validate_final_frame(drifted, contract, "1" * 64, PRIOR_ACTIVATION)

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
            "prior_activation": prior_activation_proof(),
        }
        with self.assertRaisesRegex(harness.HarnessError, "identity"):
            harness.validate_final_frame(frame, contract, "4" * 64)
        for mutation in (
            {"receipt_state": "staged_zero"}, {"execd_reinstall": "pending"},
            {"rollback_cleanup_sha256": "short"}, {"extra": True},
        ):
            with self.subTest(mutation=mutation):
                mutated = dict(frame, prior_activation={**prior_activation_proof(), **mutation})
                with self.assertRaisesRegex(harness.HarnessError, "prior activation proof differs"):
                    harness.validate_final_frame(mutated, contract, "4" * 64)
        with self.assertRaisesRegex(harness.HarnessError, "final evidence frame differs"):
            harness.validate_final_frame({key: value for key, value in frame.items() if key != "prior_activation"}, contract, "4" * 64)

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
            "prior_activation": prior_activation_proof(),
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

    def test_nip98_binds_signature_url_method_payload_time_and_returns_the_signer(self) -> None:
        now = 1_800_000_000
        body = b"fixture"
        url = "https://relay.test.invalid:3443/events"
        header = nip98(7, "POST", url, body, now)
        public = signed_event(7, 1, [], "", now)["pubkey"]
        token = relay.verify_nip98(header, "POST", url, body, now=now)
        self.assertEqual(token["pubkey"], public)
        cases = (
            ("GET", url, body, now),
            ("POST", url + "?x=1", body, now),
            ("POST", url, b"other", now),
            ("POST", url, body, now + 61),
        )
        for method, candidate_url, candidate_body, candidate_now in cases:
            with self.assertRaises(relay.RelayError):
                relay.verify_nip98(header, method, candidate_url, candidate_body, now=candidate_now)

    def test_published_event_requires_real_id_and_signature(self) -> None:
        event = signed_event(11, 46100, [["h", "channel"]], "{}", 1_800_000_000)
        self.assertEqual(relay.verify_event(event), event)
        event["content"] = "drift"
        with self.assertRaisesRegex(relay.RelayError, "signature"):
            relay.verify_event(event)


ACTOR = 4
CI_EVENT = 1
NIP98 = 2
STRANGER = 5
CHANNEL = "123e4567-e89b-12d3-a456-426614174099"
REPOSITORY = "30617:" + "22" * 32 + ":buzz"
RUN_ID = "123e4567-e89b-12d3-a456-426614174011"


def public_hex(secret: int) -> str:
    point = relay.point_mul(secret)
    assert point is not None
    return point[0].to_bytes(32, "big").hex()


def request_event(secret: int, created_at: int, *, attempt: int = 1, channel: str = CHANNEL) -> dict[str, object]:
    content = {"actor": public_hex(secret), "run_id": RUN_ID, "target_repo_a": REPOSITORY, "attempt": attempt}
    tags = [["h", channel], ["a", REPOSITORY], ["run", RUN_ID], ["attempt", str(attempt)]]
    return signed_event(secret, 46100, tags, json.dumps(content, separators=(",", ":")), created_at)


def grant_event(secret: int, created_at: int, signer: int, *, valid_until: int | None) -> dict[str, object]:
    content = {
        "schema_version": 1, "target_repo_a": REPOSITORY, "signer_pubkey": public_hex(signer),
        "valid_from": created_at, "valid_until": valid_until,
    }
    return signed_event(secret, 46107, [["h", CHANNEL]], json.dumps(content, separators=(",", ":")), created_at)


def status_event(
    secret: int, created_at: int, *, relay_signer: int | None = None, state: str | None = None,
) -> dict[str, object]:
    content = {"relay_signer": public_hex(relay_signer or secret), "target_repo_a": REPOSITORY, "run_id": RUN_ID}
    if state is not None:
        content["state"] = state
    return signed_event(secret, 46101, [["h", CHANNEL], ["run", RUN_ID]], json.dumps(content, separators=(",", ":")), created_at)


class RelayAdmissionTests(unittest.TestCase):
    """The loopback relay refuses what crates/buzz-relay refuses on POST /events."""

    def setUp(self) -> None:
        self.now = 1_800_000_000
        self.state = relay.RelayState(
            Path("/nonexistent"), "https://relay.test.invalid:3443", CHANNEL, "private",
            {public_hex(ACTOR): "admin", public_hex(CI_EVENT): "member"}, {public_hex(NIP98)},
        )

    def admit(self, token: int, event: dict[str, object], *, now: int | None = None) -> tuple[str | None, bool]:
        return relay.admit_event(self.state, public_hex(token), event, self.now if now is None else now)

    def refused(self, token: int, event: dict[str, object], status: int, message: str, *, now: int | None = None) -> None:
        with self.assertRaises(relay.Refusal) as caught:
            self.admit(token, event, now=now)
        self.assertEqual((caught.exception.status, caught.exception.message), (status, message))

    def test_old_pairing_nip98_token_with_actor_event_is_refused(self) -> None:
        # Before this change controld sent the actor's Run event under a
        # nip98.key token; the production relay refuses that pairing.
        self.refused(
            NIP98, request_event(ACTOR, self.now), 403,
            "invalid: event pubkey does not match authenticated identity",
        )
        self.assertEqual(self.state.accepted, [])

    def test_new_pairing_actor_token_with_actor_event_is_accepted_and_indexed(self) -> None:
        run = request_event(ACTOR, self.now)
        self.assertEqual(self.admit(ACTOR, run), (CHANNEL, True))
        self.assertEqual(self.state.accepted, [(1, CHANNEL, run)])
        self.assertEqual(self.admit(ACTOR, run), (CHANNEL, False))
        rerun = request_event(ACTOR, self.now + 10, attempt=2)
        self.assertEqual(self.admit(ACTOR, rerun), (CHANNEL, True))
        self.assertEqual([cursor for cursor, _channel, _event in self.state.accepted], [1, 2])

    def test_membership_drift_and_channel_rules(self) -> None:
        self.refused(STRANGER, request_event(STRANGER, self.now), 400, "restricted: not a channel member")
        self.refused(
            ACTOR, request_event(ACTOR, self.now, channel="123e4567-e89b-12d3-a456-426614174000"),
            400, "restricted: not a channel member",
        )
        self.refused(
            ACTOR, request_event(ACTOR, self.now - 901), 400,
            "invalid: event timestamp too far from server time",
        )
        self.assertEqual(self.admit(ACTOR, request_event(ACTOR, self.now - 900)), (CHANNEL, True))
        self.refused(
            ACTOR, signed_event(ACTOR, 46100, [], "{}", self.now), 400,
            "invalid: CI events require a channel h tag",
        )
        actor_signed_for_ci = signed_event(
            ACTOR, 46100, [["h", CHANNEL], ["a", REPOSITORY], ["run", RUN_ID]],
            json.dumps({"actor": public_hex(CI_EVENT), "run_id": RUN_ID, "target_repo_a": REPOSITORY}),
            self.now,
        )
        self.refused(ACTOR, actor_signed_for_ci, 400, "invalid: request actor does not match event signer")

    def test_grant_needs_owner_or_admin_and_authorizes_status_signers_for_its_window(self) -> None:
        self.refused(CI_EVENT, status_event(CI_EVENT, self.now), 400, "invalid: unauthorized CI status signer")
        self.refused(
            CI_EVENT, grant_event(CI_EVENT, self.now, CI_EVENT, valid_until=self.now + 600), 403,
            "restricted: only a channel owner or admin may issue a CI signer grant",
        )
        self.refused(
            NIP98, grant_event(NIP98, self.now, CI_EVENT, valid_until=self.now + 600), 400,
            "restricted: not a channel member",
        )
        grant = grant_event(ACTOR, self.now + 1, CI_EVENT, valid_until=self.now + 601)
        self.assertEqual(self.admit(ACTOR, grant, now=self.now + 1), (CHANNEL, True))
        self.refused(CI_EVENT, status_event(CI_EVENT, self.now), 400, "invalid: unauthorized CI status signer", now=self.now)
        self.assertEqual(self.admit(CI_EVENT, status_event(CI_EVENT, self.now + 2), now=self.now + 2), (CHANNEL, True))
        self.refused(
            CI_EVENT, status_event(CI_EVENT, self.now + 601), 400,
            "invalid: unauthorized CI status signer", now=self.now + 601,
        )
        self.refused(
            CI_EVENT, status_event(CI_EVENT, self.now + 3, relay_signer=NIP98), 400,
            "invalid: status signer does not match event signer", now=self.now + 3,
        )
        self.refused(
            NIP98, status_event(CI_EVENT, self.now + 3), 403,
            "invalid: event pubkey does not match authenticated identity", now=self.now + 3,
        )
        self.assertEqual(
            self.state.active_signers(REPOSITORY, self.now + 2), {public_hex(NIP98), public_hex(CI_EVENT)},
        )
        self.refused(
            ACTOR, grant_event(ACTOR, self.now + 4, CI_EVENT, valid_until=self.now + 3), 400,
            "invalid: CI grant content rejected", now=self.now + 4,
        )

    def test_tombstone_must_target_the_authors_own_stored_event(self) -> None:
        rerun = request_event(ACTOR, self.now + 10, attempt=2)
        missing = signed_event(ACTOR, 5, [["e", rerun["id"]]], "", self.now + 20)
        self.refused(ACTOR, missing, 400, "invalid: target event not found", now=self.now + 20)
        # A rerun extends an existing run; without the initial request it is refused.
        self.refused(ACTOR, rerun, 400, "invalid: CI rerun names an unknown run", now=self.now + 10)
        self.assertEqual(self.admit(ACTOR, request_event(ACTOR, self.now)), (CHANNEL, True))
        self.refused(
            ACTOR, request_event(ACTOR, self.now + 1), 400,
            "invalid: CI run ID or initial request event ID already exists", now=self.now + 1,
        )
        self.assertEqual(self.admit(ACTOR, rerun, now=self.now + 10), (CHANNEL, True))
        foreign = signed_event(CI_EVENT, 5, [["e", rerun["id"]]], "", self.now + 20)
        self.refused(CI_EVENT, foreign, 400, "invalid: must be event author", now=self.now + 20)
        tombstone = signed_event(ACTOR, 5, [["e", rerun["id"]]], "", self.now + 20)
        self.assertEqual(self.admit(ACTOR, tombstone, now=self.now + 20), (CHANNEL, True))
        two_targets = signed_event(ACTOR, 5, [["e", rerun["id"]], ["e", tombstone["id"]]], "", self.now + 21)
        self.refused(
            ACTOR, two_targets, 400,
            "invalid: deletion events must reference exactly one target via e or a tag", now=self.now + 21,
        )

    def test_accepted_read_and_evidence_writes_need_a_static_or_granted_signer(self) -> None:
        run = request_event(ACTOR, self.now)
        self.assertEqual(self.admit(ACTOR, run), (CHANNEL, True))
        self.state.require_signer(REPOSITORY, public_hex(NIP98), self.now)
        with self.assertRaises(relay.Refusal) as caught:
            self.state.require_signer(REPOSITORY, public_hex(ACTOR), self.now)
        self.assertEqual((caught.exception.status, caught.exception.message), (403, "CI signer is not authorized"))
        self.assertEqual(self.state.request_repository(run["id"]), REPOSITORY)
        with self.assertRaises(relay.Refusal) as caught:
            self.state.request_repository("ab" * 32)
        self.assertEqual(caught.exception.status, 404)

    def test_guest_roster_names_the_three_production_facts(self) -> None:
        public = {
            "relay_http_origin": "https://relay.test.invalid:3443",
            "acceptance_actor": {"public_key": public_hex(ACTOR), "generation": 1},
            "keyholder_public_spec": {"selectors": {
                "ci_event": {"public_key": public_hex(CI_EVENT), "generation": 1},
                "nip98": {"public_key": public_hex(NIP98), "generation": 1},
                "manifest": {"public_key": public_hex(3), "generation": 1},
            }},
        }
        config = guest.relay_public_config(public, CHANNEL)
        self.assertEqual(config, {
            "origin": "https://relay.test.invalid:3443",
            "channel": {
                "id": CHANNEL, "visibility": "private",
                "members": {public_hex(ACTOR): "admin", public_hex(CI_EVENT): "member"},
            },
            "ci_status_signer_pubkeys": [public_hex(NIP98)],
        })
        state = relay.state_from_config(config, Path("/nonexistent"))
        self.assertEqual(state.members, config["channel"]["members"])
        self.assertEqual(state.static_signers, {public_hex(NIP98)})
        for broken in (
            {**config, "extra": 1},
            {**config, "channel": {**config["channel"], "visibility": "hidden"}},
            {**config, "channel": {**config["channel"], "members": {"zz": "admin"}}},
            {**config, "channel": {**config["channel"], "members": {public_hex(ACTOR): "guest"}}},
            {**config, "ci_status_signer_pubkeys": ["nope"]},
        ):
            with self.assertRaises(ValueError):
                relay.state_from_config(broken, Path("/nonexistent"))


class RelayQueryAndFaultTests(unittest.TestCase):
    """POST /query mirrors api/bridge.rs; the stale-terminal fault reproduces M11."""

    STALE = "invalid: event timestamp too far from server time"

    def setUp(self) -> None:
        self.now = 1_800_000_000
        self.state = relay.RelayState(
            Path("/nonexistent"), "https://relay.test.invalid:3443", CHANNEL, "private",
            {public_hex(ACTOR): "admin", public_hex(CI_EVENT): "member"}, {public_hex(NIP98), public_hex(CI_EVENT)},
        )

    def admit(self, token: int, event: dict[str, object]) -> tuple[str | None, bool]:
        return relay.admit_event(self.state, public_hex(token), event, self.now)

    def query(self, token: int, filters: object) -> list[dict[str, object]]:
        return relay.query_events(self.state, public_hex(token), json.dumps(filters).encode())

    def test_query_is_gated_on_kinds_and_channel_access_and_finds_exact_ids(self) -> None:
        run = request_event(ACTOR, self.now)
        self.assertEqual(self.admit(ACTOR, run), (CHANNEL, True))
        exact = [{"ids": [run["id"]], "kinds": [46100], "limit": 1}]
        self.assertEqual(self.query(CI_EVENT, exact), [run])
        self.assertEqual(self.query(ACTOR, exact), [run])
        self.assertEqual(self.query(NIP98, exact), [], "a non-member sees nothing from the private channel")
        self.assertEqual(self.query(CI_EVENT, [{"ids": ["ab" * 32], "kinds": [46100], "limit": 1}]), [])
        self.assertEqual(self.query(CI_EVENT, [{"ids": [run["id"]], "kinds": [46101], "limit": 1}]), [])
        # `authors` narrows the match to events that pubkey signed; controld's
        # exact-event read-back names the ci-event key, so an actor-authored
        # event is not returned to it even by exact id.
        by_author = [{"ids": [run["id"]], "authors": [public_hex(ACTOR)], "kinds": [46100], "limit": 1}]
        self.assertEqual(self.query(CI_EVENT, by_author), [run])
        as_ci_event = [{"ids": [run["id"]], "authors": [public_hex(CI_EVENT)], "kinds": [46100], "limit": 1}]
        self.assertEqual(self.query(CI_EVENT, as_ci_event), [], "another author's event is not the read-back")
        for body, status in (
            ([{"ids": [run["id"]], "limit": 1}], 403),
            ([{"ids": [run["id"]], "kinds": [], "limit": 1}], 403),
            ([{"ids": ["nope"], "kinds": [46100]}], 400),
            ([], 400),
            ({"kinds": [46100]}, 400),
        ):
            with self.assertRaises(relay.Refusal) as caught:
                self.query(CI_EVENT, body)
            self.assertEqual(caught.exception.status, status, body)

    def test_stale_terminal_fault_refuses_the_first_terminal_publish_once_and_records_the_read_back(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            flag = Path(temporary) / "fault"
            record = Path(temporary) / "fault-fired.json"
            flag.write_text("stale-terminal-publication-recovery\n")
            self.state.arm_fault(flag)
            queued = status_event(CI_EVENT, self.now, state="queued")
            self.assertEqual(self.admit(CI_EVENT, queued), (CHANNEL, True), "open states are never stale")
            self.assertFalse(record.exists())
            stale = status_event(CI_EVENT, self.now + 1, state="success")
            with self.assertRaises(relay.Refusal) as caught:
                self.admit(CI_EVENT, stale)
            self.assertEqual((caught.exception.status, caught.exception.message), (400, self.STALE))
            self.assertNotIn(stale["id"], self.state.events, "a refused event is not stored")
            expected = {"mode": "stale-terminal-publication-recovery", "refused_event_id": stale["id"], "queried": False}
            self.assertEqual(json.loads(record.read_bytes()), expected)
            self.assertEqual(self.query(CI_EVENT, [{"ids": [stale["id"]], "kinds": [46100], "limit": 1}]), [])
            self.assertEqual(json.loads(record.read_bytes()), expected, "another kind is not the read-back")
            read_back = [{"ids": [stale["id"]], "authors": [public_hex(CI_EVENT)], "kinds": [46101], "limit": 1}]
            self.assertEqual(self.query(CI_EVENT, read_back), [])
            self.assertEqual(json.loads(record.read_bytes()), {**expected, "queried": True})
            # controld re-signs the same content; within one second the id is unchanged.
            self.assertEqual(self.admit(CI_EVENT, stale), (CHANNEL, True), "the fault fires once")
            self.assertEqual(self.query(CI_EVENT, [{"ids": [stale["id"]], "kinds": [46101]}]), [stale])
            later = status_event(CI_EVENT, self.now + 2, state="success")
            self.assertEqual(self.admit(CI_EVENT, later), (CHANNEL, True))
            with self.assertRaises(ValueError):
                flag.write_text("unknown-mode\n")
                self.state.arm_fault(flag)

    def test_guest_requires_the_read_back_record_and_an_accepted_terminal_publication(self) -> None:
        def signed(event_id: str) -> dict[str, object]:
            return {"event_id": event_id, "kind": 46101, "content": "{}", "tags": [], "signed_event": {"id": event_id}}

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = root / "control-store-v1.json"
            record = root / "fault-fired.json"
            with mock.patch.object(guest, "RELAY_ROOT", root), mock.patch.object(guest, "CONTROLD_SNAPSHOT", snapshot):
                guest.prove_relay_fault_recovery(None)
                with self.assertRaisesRegex(guest.GuestError, "did not fire"):
                    guest.prove_relay_fault_recovery("stale-terminal-publication-recovery")
                record.write_bytes(guest.canonical({"mode": "stale-terminal-publication-recovery", "refused_event_id": "2" * 64, "queried": False}))
                with self.assertRaisesRegex(guest.GuestError, "not read back"):
                    guest.prove_relay_fault_recovery("stale-terminal-publication-recovery")
                record.write_bytes(guest.canonical({"mode": "stale-terminal-publication-recovery", "refused_event_id": "2" * 64, "queried": True}))
                # An attempt and its rerun: two accepted requests, two run:terminal keys.
                good = {"schema_version": 1, "cursors": {}, "runs": {}, "finalizations": {}, "publications": {
                    "9" * 64 + ":run:queued": {"Accepted": {"signed": signed("3" * 64), "relay_event_id": "3" * 64}},
                    "9" * 64 + ":run:terminal": {"Accepted": {"signed": signed("2" * 64), "relay_event_id": "2" * 64}},
                    "8" * 64 + ":run:terminal": {"Accepted": {"signed": signed("5" * 64), "relay_event_id": "5" * 64}},
                }}
                snapshot.write_bytes(guest.canonical(good))
                guest.prove_relay_fault_recovery("stale-terminal-publication-recovery")
                for mutate, message in (
                    (lambda value: [value["publications"].pop(key) for key in list(value["publications"]) if key.endswith(":run:terminal")], "not accepted"),
                    (lambda value: value["publications"].__setitem__("9" * 64 + ":run:terminal", {"Pending": signed("2" * 64)}), "not accepted"),
                    (lambda value: value["publications"].__setitem__("9" * 64 + ":run:terminal", {"Accepted": {"signed": signed("4" * 64), "relay_event_id": "2" * 64}}), "inconsistent"),
                ):
                    broken = copy.deepcopy(good)
                    mutate(broken)
                    snapshot.write_bytes(guest.canonical(broken))
                    with self.assertRaisesRegex(guest.GuestError, message):
                        guest.prove_relay_fault_recovery("stale-terminal-publication-recovery")

    def test_run_accepts_only_known_relay_faults_and_hands_them_to_the_terminal_run(self) -> None:
        calls: list[tuple[object, ...]] = []
        with mock.patch.object(harness, "terminal_run", side_effect=lambda *arguments: calls.append(arguments) or {"status": "pass"}):
            for extra, expected in (([], None), (["--relay-fault", "stale-terminal-publication-recovery"], "stale-terminal-publication-recovery")):
                with mock.patch.object(sys, "argv", ["harness.py", "run", "--contract", "c.json", "--results", "r", *extra]), \
                        contextlib.redirect_stdout(io.TextIOWrapper(io.BytesIO())):
                    self.assertEqual(harness.main(), 0)
                self.assertEqual(calls[-1][2], expected)
            with mock.patch.object(sys, "argv", ["harness.py", "run", "--contract", "c.json", "--results", "r", "--relay-fault", "other"]), \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                harness.main()
        with self.assertRaisesRegex(harness.HarnessError, "relay fault mode differs"):
            harness.create_run_stage({}, Path("/nonexistent"), {}, b"", b"", b"", "other")


if __name__ == "__main__":
    unittest.main()

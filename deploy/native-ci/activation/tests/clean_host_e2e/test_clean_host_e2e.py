#!/usr/bin/env python3
"""Adversarial checks for the isolated clean-host VM harness."""

from __future__ import annotations

import base64
import contextlib
import copy
import hashlib
import http.client
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
import threading
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
    protocol = protocol_verdict(harness.canonical(receipt))
    return {
        "schema_version": harness.FRAME_SCHEMA,
        "phase": "run",
        "challenge": "1" * 64,
        "outcome": "pass",
        "receipt_base64": base64.b64encode(harness.canonical(receipt)).decode(),
        "verifier_base64": base64.b64encode(harness.canonical(verifier)).decode(),
        "dormant_proof": proof,
        "prior_activation": prior_activation_proof(),
        "protocol_verdict": protocol,
        "protocol_verdict_sha256": hashlib.sha256(harness.canonical(protocol)).hexdigest(),
    }


def protocol_verdict(receipt_raw: bytes) -> dict[str, object]:
    api = [str(index) * 64 for index in range(1, 6)]
    bound = [f"{index:064x}" for index in range(10, 20)]
    return {
        "schema_version": "buzz-ci-loopback-relay-verdict/v2", "state": "green",
        "reason": None, "sealed": True, "template_set_sha256": "1" * 64,
        "actor_event_ids": {"api_order": api, "live_order": [api[index] for index in (0, 1, 4, 2, 3)]},
        "observed_actor_event_ids": [str(index) * 64 for index in (1, 2, 5, 3, 4)],
        "run_ids": {"run_a": RUN_ID, "run_b": "123e4567-e89b-12d3-a456-426614174012"},
        "transcript": {"sha256": "6" * 64, "event_count": 28, "last_cursor": 28},
        "receipt": {"sha256": hashlib.sha256(receipt_raw).hexdigest(), "run_id": "4" * 32, "checks": 16, "zero_phases": [17, 18], "manifest_digest": "7" * 64, "export_subject": "8" * 64, "export_authorization_digest": "9" * 64, "export_request_digest": "a" * 64, "export_attempt_id": "b" * 32, "export_evidence_set_digest": "c" * 64, "export_objects_sha256": "d" * 64, "export_generation": 1},
        "run_a": {"request_event_id": api[0], "selected_job_attempts": [{"job_id": "job", "attempt": 1}], "log_event_ids": [bound[0]], "artifact_event_ids": [bound[1]], "evidence_finalized_event_id": bound[2], "teardown_attestation_event_id": bound[3], "terminal_event_id": bound[4]},
        "run_b": {"initial_request_event_id": api[4], "final_request_event_id": api[2], "failure_log_event_id": bound[5], "failure_job_event_id": bound[6], "failure_run_event_id": bound[7], "rerun_request_event_id": api[2], "cancel_job_event_id": bound[8], "cancel_run_event_id": bound[9], "tombstone_event_id": api[3], "final_fact_count": 0},
        "sealed_projection_sha256": "a" * 64,
        "foreign_pending_event_id": None,
    }


def valid_closed_verdict_substitutions(value: dict[str, object]) -> list[tuple[str, dict[str, object]]]:
    mutations: list[tuple[str, tuple[str, ...], str]] = [
        ("template-set", ("template_set_sha256",), "a1" * 32),
        ("sealed-projection", ("sealed_projection_sha256",), "b1" * 32),
        ("run-a-terminal", ("run_a", "terminal_event_id"), "c1" * 32),
        ("foreign-pending", ("foreign_pending_event_id",), "d1" * 32),
        ("export-subject", ("receipt", "export_subject"), "e1" * 32),
    ]
    results = []
    for name, path, replacement in mutations:
        changed = copy.deepcopy(value)
        target = changed
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = replacement
        results.append((name, changed))
    return results


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
                guest, "cross_bind", return_value=(candidate, {"fixture": {}}, {}, "12345678-1234-4abc-8def-123456789abc"),
            ))
            stack.enter_context(mock.patch.object(
                guest, "package_manifest", return_value={"acceptance_template": {}},
            ))
            stack.enter_context(mock.patch.object(guest, "relay_mapping_present", return_value=False))
            stack.enter_context(mock.patch.object(
                guest, "start_relay", side_effect=lambda *_arguments: completed("relay_ready"),
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
            stack.enter_context(mock.patch.object(
                guest, "close_relay_protocol_verdict", return_value=({"state": "green"}, {"input": True}),
            ))
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
        # Two exemptions from the frozen inventory: the relay readiness probe
        # and the prior canary that only the replay-before-grant fault runs.
        self.assertEqual(source.count("inventory=False"), 2)
        self.assertIn('"openssl", "s_client"', source)
        self.assertIn('def run_prior_canary_expecting_stale_terminal', source)
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
        expected = {"ceremony": 1130, "candidate": 7582, "verifier": 320}
        for role, phases in harness.TIMING_CONTRACT["role_phases"].items():
            legal_boundary = sum(harness.phase_seconds(phase) for phase in phases)
            complete_boundary = legal_boundary + harness.REAP_TIMEOUT
            self.assertEqual(harness.watchdog_seconds(role), complete_boundary)
            self.assertLess(harness.watchdog_seconds(role) - 1, complete_boundary)
            self.assertEqual(harness.watchdog_seconds(role), expected[role])
        canary_inner = 16 * harness.TIMING_CONTRACT["leaf_seconds"]["driver_operation"]
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
            guest.time, "monotonic", side_effect=[0.0, 0.0, 0.0, 2191.0, 2191.0, 2191.0]
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
    def test_guest_dynamic_import_uses_its_sibling_without_search_path(self) -> None:
        script = """
import importlib.util
from pathlib import Path
import sys
import types

before = list(sys.path)
if sys.argv[2] == "poison":
    sys.modules["local_tls_relay"] = types.ModuleType("local_tls_relay")
path = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("isolated_guest", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert Path(module.relay_protocol.__file__) == path.with_name("local_tls_relay.py")
assert module.EVIDENCE_READS.name == module.relay_protocol.EVIDENCE_READS_RECORD_NAME
assert sys.path == before
"""
        with tempfile.TemporaryDirectory() as temporary:
            for mode in ("absent", "poison"):
                with self.subTest(module_cache=mode):
                    result = subprocess.run(
                        [sys.executable, "-I", "-B", "-c", script, str(HERE / "guest_entry.py"), mode],
                        cwd=temporary, capture_output=True, text=True, timeout=15,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)

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
                "protocol_verdict": protocol_verdict(receipt_raw),
                "protocol_verdict_sha256": hashlib.sha256(harness.canonical(protocol_verdict(receipt_raw))).hexdigest(),
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
                "protocol_verdict": protocol_verdict(harness.canonical(receipt)),
                "protocol_verdict_sha256": hashlib.sha256(harness.canonical(protocol_verdict(harness.canonical(receipt)))).hexdigest(),
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
            "protocol_verdict": protocol_verdict(harness.canonical(receipt)),
            "protocol_verdict_sha256": hashlib.sha256(harness.canonical(protocol_verdict(harness.canonical(receipt)))).hexdigest(),
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
            "protocol_verdict": protocol_verdict(harness.canonical(receipt)),
            "protocol_verdict_sha256": hashlib.sha256(harness.canonical(protocol_verdict(harness.canonical(receipt)))).hexdigest(),
        }
        with self.assertRaisesRegex(harness.HarnessError, "identity"):
            harness.validate_final_frame(frame, contract, "6" * 64)

    def test_host_rejects_valid_hex_verdict_substitutions_against_verifier_digest(self) -> None:
        contract = {"candidate_sha": "2" * 40, "scenario": {"sha256": "3" * 64}}
        frame = passing_frame(contract)
        harness.validate_final_frame(frame, contract, "1" * 64)
        for name, changed in valid_closed_verdict_substitutions(frame["protocol_verdict"]):
            with self.subTest(field=name):
                relay.validate_closed_verdict(changed)
                mutated = copy.deepcopy(frame)
                mutated["protocol_verdict"] = changed
                with self.assertRaisesRegex(harness.HarnessError, "digest differs"):
                    harness.validate_final_frame(mutated, contract, "1" * 64)


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


def request_event(
    secret: int, created_at: int, *, attempt: int = 1, channel: str = CHANNEL,
    run_id: str = RUN_ID,
) -> dict[str, object]:
    content = {
        "schema_version": 1, "actor": public_hex(secret), "run_id": run_id,
        "target_repo_a": REPOSITORY,
        "request_type": "run" if attempt == 1 else "rerun", "attempt": attempt,
        "job_ids": ["capacity-one-fixture"],
        "workflow_id": "workflow", "tip_oid": "1" * 40, "base_oid": "2" * 40,
        "workflow_digest": "3" * 64, "pr_root_event_id": "4" * 64,
        "source_clone_url": "https://example.invalid/repo.git",
        "immutable_source_ref": "refs/buzz-ci/source", "source_branch": "topic",
        "base_ref": "refs/heads/main", "trigger_event_id": "4" * 64,
        "timeout_seconds": 60, "idempotency_key": f"stage7-{run_id}-{attempt}",
        "issued_at": created_at, "expires_at": created_at + 600,
    }
    if attempt > 1:
        content.update({"parent_attempt": attempt - 1, "parent_run_id": run_id})
    tags = [
        ["h", channel], ["a", REPOSITORY], ["run", run_id], ["workflow", "workflow"],
        ["c", "1" * 40], ["attempt", str(attempt)],
    ]
    return signed_event(secret, 46100, tags, json.dumps(content, separators=(",", ":")), created_at)


def acceptance_template(
    secret: int = ACTOR, now: int = 1_800_000_000, *, run_id: str = RUN_ID,
    failure_run_id: str = "123e4567-e89b-12d3-a456-426614174012",
) -> dict[str, object]:
    run = request_event(secret, now, run_id=run_id)
    grant = grant_event(secret, now + 1, CI_EVENT, valid_until=now + 600)
    failure = request_event(secret, now, run_id=failure_run_id)
    rerun = request_event(secret, now, attempt=2, run_id=failure_run_id)
    tombstone = signed_event(secret, 5, [["e", rerun["id"]]], "", now + 20)
    template = {
        "actor": {"public_key": public_hex(secret), "generation": 1},
        "time_reference": now,
        "run_event": relay.template_preimage(run), "grant_event": relay.template_preimage(grant),
        "rerun_event": relay.template_preimage(rerun), "tombstone_event": relay.template_preimage(tombstone),
        "failure_run_event": relay.template_preimage(failure),
        "export_subject": public_hex(NIP98), "export_generation": 1,
    }
    request_id = hashlib.sha256(relay.canonical_json(template["run_event"])).hexdigest()
    template["export_authorization_digest"] = relay.export_authorization_digest(
        relay.EXPORT_ORIGIN, template["export_subject"], template["export_generation"],
        request_id, run_id, "capacity-one-fixture",
    )
    template["failure_selector"] = failure_selector(template)
    return template


def failure_selector(template: dict[str, object]) -> dict[str, object]:
    failure = json.loads(template["failure_run_event"][5])
    selector = {
        "schema_version": "buzz-ci-capacity-one-fixture-selector/v1",
        "selector": "deterministic-failure", "job_id": failure["job_ids"][0],
        "run_id": failure["run_id"], "attempt": 1,
    }
    preimage = (
        "buzz-ci:capacity-one:fixture-selector:v1\n"
        f"{selector['schema_version']}\n{selector['selector']}\n{selector['job_id']}\n"
        f"{selector['run_id'].replace('-', '')}\n1\n"
    ).encode()
    selector["sha256"] = hashlib.sha256(preimage).hexdigest()
    return selector


def acceptance_fixture(template: dict[str, object]) -> dict[str, object]:
    ids = [hashlib.sha256(relay.canonical_json(template[name])).hexdigest() for name in relay.TEMPLATE_NAMES]
    return {
        "run_id": RUN_ID.replace("-", ""),
        "failure_run_id": "123e4567e89b12d3a456426614174012",
        "request_digest": ids[0], "grant_event_id": ids[1], "failure_request_digest": ids[4],
        "job_id": "capacity-one-fixture", "manifest_digest": "a" * 64,
        "export_subject": template["export_subject"],
        "export_authorization_digest": template["export_authorization_digest"],
        "export_generation": template["export_generation"],
        "failure_selector": copy.deepcopy(template["failure_selector"]),
        "expected_log": {"name": relay.EXPORT_LOG[0], "sha256": relay.EXPORT_LOG[1], "bytes": relay.EXPORT_LOG[2]},
        "expected_failure_log": {"name": "job.log", "sha256": "e" * 64, "bytes": 1},
        "expected_artifacts": [{"name": relay.EXPORT_ARTIFACT[1], "sha256": relay.EXPORT_ARTIFACT[2], "bytes": relay.EXPORT_ARTIFACT[3]}],
    }


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


def ci_fact_event(secret: int, kind: int, created_at: int, content: dict[str, object]) -> dict[str, object]:
    envelope = {
        "schema_version": 1, "relay_signer": public_hex(secret), "target_repo_a": REPOSITORY,
        "run_id": RUN_ID, "workflow_id": "workflow", "tip_oid": "1" * 40, **content,
    }
    return signed_event(secret, kind, [["h", CHANNEL], ["run", RUN_ID]], json.dumps(envelope, separators=(",", ":")), created_at)


def protocol_close_inputs() -> tuple[dict[str, object], dict[str, object], bytes, bytes, bytes]:
    template = acceptance_template()
    fixture = acceptance_fixture(template)
    authority = relay.validate_acceptance_template(template, label="test")
    run_a, run_b = authority["run_id"], authority["failure_run_id"]
    run_request, grant_id, rerun_request, tombstone_id, failure_request = authority["api_ids"]
    actor_events = {
        hashlib.sha256(relay.canonical_json(template[name])).hexdigest(): signed_event(
            ACTOR, template[name][3], template[name][4], template[name][5], template[name][2],
        )
        for name in relay.TEMPLATE_NAMES
    }
    events: list[dict[str, object]] = []

    def append_actor(identifier: str) -> None:
        events.append(actor_events[identifier])

    def append(kind: int, run_id: str, request_id: str, **content: object) -> str:
        request = json.loads(actor_events[request_id]["content"])
        body = {
            "schema_version": 1, "relay_signer": public_hex(CI_EVENT),
            "target_repo_a": request["target_repo_a"], "run_id": run_id,
            "request_event_id": request_id, "workflow_id": request["workflow_id"],
            "tip_oid": request["tip_oid"], **content,
        }
        if kind == relay.KIND_CI_RUN_STATUS:
            body.update({"base_oid": request["base_oid"], "job_ids": request["job_ids"]})
        elif kind == relay.KIND_CI_JOB_STATUS:
            body.update({
                "base_oid": request["base_oid"], "name": "Capacity one", "required": True,
                "skip_policy": "forbid", "selected_job_instance": fixture["job_id"],
                "also_reruns": [],
            })
        elif kind == relay.KIND_CI_LOG_REFERENCE:
            body.update({
                "cap_bytes": body["byte_length"], "truncated": False,
                "created_at": 1_800_000_100 + len(events),
            })
        elif kind == relay.KIND_CI_ARTIFACT_REFERENCE:
            body.update({
                "media_type": "application/json", "created_at": 1_800_000_100 + len(events),
            })
        elif kind == relay.KIND_CI_EVIDENCE_FINALIZED:
            body["finalized_at"] = 1_800_000_100 + len(events)
        elif kind == relay.KIND_CI_TEARDOWN_ATTESTATION:
            body.update({
                "base_oid": request["base_oid"], "workflow_digest": request["workflow_digest"],
                "teardown_at": 1_800_000_100 + len(events),
            })
        event_time = 1_800_000_100 + len(events)
        if kind in {relay.KIND_CI_RUN_STATUS, relay.KIND_CI_JOB_STATUS} \
                and body.get("state") not in relay.OPEN_RUN_STATES:
            body.update({"started_at": event_time - 1, "finished_at": event_time})
        tags = [
            ["h", CHANNEL], ["a", request["target_repo_a"]], ["run", run_id],
            ["workflow", request["workflow_id"]], ["c", request["tip_oid"]],
            ["attempt", str(body["attempt"])],
        ]
        if kind in {relay.KIND_CI_JOB_STATUS, relay.KIND_CI_LOG_REFERENCE, relay.KIND_CI_ARTIFACT_REFERENCE}:
            tags.append(["job", str(body["job_id"])])
        tags.append(["e", request_id, "", "request"])
        if kind == relay.KIND_CI_LOG_REFERENCE:
            tags.append(["x", str(body["log_sha256"])])
        elif kind == relay.KIND_CI_ARTIFACT_REFERENCE:
            tags.append(["x", str(body["sha256"])])
        event = signed_event(
            CI_EVENT, kind, tags, json.dumps(body, separators=(",", ":")), event_time,
        )
        events.append(event)
        return str(event["id"])

    append_actor(run_request)
    append(46101, run_a, run_request, attempt=1, sequence=1, state="queued")
    append_actor(grant_id)
    append(46101, run_a, run_request, attempt=1, sequence=2, state="running")
    append(46102, run_a, run_request, job_id=fixture["job_id"], attempt=1, sequence=1, state="queued", artifact_refs=[])
    append(46102, run_a, run_request, job_id=fixture["job_id"], attempt=1, sequence=2, state="running", artifact_refs=[])
    log_path = f"/ci/logs/{run_request}/{run_a}/{fixture['job_id']}/1/{fixture['expected_log']['sha256']}"
    artifact_path = f"/ci/artifacts/{run_request}/{run_a}/{fixture['job_id']}/1/result/{fixture['expected_artifacts'][0]['sha256']}"
    log_id = append(46103, run_a, run_request, job_id=fixture["job_id"], attempt=1, log_sha256=fixture["expected_log"]["sha256"], byte_length=fixture["expected_log"]["bytes"], url="https://relay.test.invalid:3443" + log_path)
    artifact_id = append(46104, run_a, run_request, job_id=fixture["job_id"], attempt=1, artifact_id="result", name="result.json", sha256=fixture["expected_artifacts"][0]["sha256"], byte_length=fixture["expected_artifacts"][0]["bytes"], url="https://relay.test.invalid:3443" + artifact_path)
    append(46102, run_a, run_request, job_id=fixture["job_id"], attempt=1, sequence=3, state="success", log_ref=log_id, artifact_refs=[artifact_id])
    append(46105, run_a, run_request, attempt=1, finalized_job_attempts=[{"job_id": fixture["job_id"], "attempt": 1, "log_ref": log_id, "artifact_refs": [artifact_id]}])
    append(46106, run_a, run_request, attempt=1, lease_empty=True, leases=[{"job_id": fixture["job_id"], "attempt": 1, "lease_id": "lease-a"}])
    append(46101, run_a, run_request, attempt=1, sequence=3, state="success")
    append_actor(failure_request)
    append(46101, run_b, failure_request, attempt=1, sequence=1, state="queued")
    append(46101, run_b, failure_request, attempt=1, sequence=2, state="running")
    append(46102, run_b, failure_request, job_id=fixture["job_id"], attempt=1, sequence=1, state="queued", artifact_refs=[])
    append(46102, run_b, failure_request, job_id=fixture["job_id"], attempt=1, sequence=2, state="running", artifact_refs=[])
    failure_log_path = f"/ci/logs/{failure_request}/{run_b}/{fixture['job_id']}/1/{fixture['expected_failure_log']['sha256']}"
    failure_log_id = append(46103, run_b, failure_request, job_id=fixture["job_id"], attempt=1, log_sha256=fixture["expected_failure_log"]["sha256"], byte_length=fixture["expected_failure_log"]["bytes"], url=relay.EXPORT_ORIGIN + failure_log_path)
    append(46102, run_b, failure_request, job_id=fixture["job_id"], attempt=1, sequence=3, state="failure", log_ref=failure_log_id, artifact_refs=[])
    append(46101, run_b, failure_request, attempt=1, sequence=3, state="failure")
    append_actor(rerun_request)
    append(46101, run_b, rerun_request, attempt=2, sequence=1, state="queued")
    append(46101, run_b, rerun_request, attempt=2, sequence=2, state="running")
    append(46102, run_b, rerun_request, job_id=fixture["job_id"], attempt=2, parent_attempt=1, sequence=1, state="queued", artifact_refs=[])
    append(46102, run_b, rerun_request, job_id=fixture["job_id"], attempt=2, parent_attempt=1, sequence=2, state="running", artifact_refs=[])
    append(46102, run_b, rerun_request, job_id=fixture["job_id"], attempt=2, parent_attempt=1, sequence=3, state="cancelled", artifact_refs=[])
    append(46101, run_b, rerun_request, attempt=2, sequence=3, state="cancelled")
    append_actor(tombstone_id)
    records = [{"cursor": index, "event": event} for index, event in enumerate(events, 1)]
    transcript = {
        "schema_version": relay.TRANSCRIPT_SCHEMA,
        "template_set_sha256": authority["template_set_sha256"],
        "actor_event_ids": {"api_order": authority["api_ids"], "live_order": authority["live_ids"]},
        "observed_actor_event_ids": authority["live_ids"], "events": records,
        "sealed": True,
        "sealed_projection_sha256": hashlib.sha256(relay.canonical_json(records)).hexdigest(),
        "foreign_pending_event_ids": [],
        "foreign_pending_event": None,
    }
    terminal_attempt = {
        "attempt_id": "1" * 32, "evidence_set_digest": "2" * 64,
        "manifest_digest": fixture["manifest_digest"],
    }
    checks = [
        {"sequence": index, "stage": stage, "outcome": "pass", **({
            "export": {
                "authenticated": True,
                "generation": fixture["export_generation"],
                "manifest_digest": fixture["manifest_digest"], "request_digest": fixture["request_digest"],
                "subject": fixture["export_subject"], "authorization_digest": fixture["export_authorization_digest"],
                "attempt_id": terminal_attempt["attempt_id"],
                "evidence_set_digest": terminal_attempt["evidence_set_digest"],
                "objects": [fixture["expected_log"], *fixture["expected_artifacts"]],
            },
        } if index == 7 else {}), **({"snapshot": {"run": {"attempts": [terminal_attempt]}}} if index in (6, 7) else {})}
        for index, stage in enumerate(relay.EXPECTED_RECEIPT_STAGES, 1)
    ]
    receipt = {
        "schema_version": "buzz-ci-capacity-one-acceptance-receipt/v2", "outcome": "pass",
        "scenario_sha256": "1" * 64, "integrated_candidate_sha": "2" * 40,
        "run_id": fixture["run_id"], "checks": checks,
        "zero_transition": {"phases": [
            {"sequence": 17, "operation": "finalize_capacity_zero", "outcome": "pass"},
            {"sequence": 18, "operation": "prove_capacity_zero", "outcome": "pass"},
        ]},
    }
    reads = {
        "schema_version": relay.EVIDENCE_READS_SCHEMA,
        "export_generation": fixture["export_generation"],
        "reads": [{
            "type": kind, "path": path, "request_event_id": run_request,
            "run_id": run_a, "job_id": fixture["job_id"], "attempt": 1,
            "artifact_id": artifact, "sha256": descriptor["sha256"],
            "byte_length": descriptor["bytes"], "subject": fixture["export_subject"],
        } for kind, path, artifact, descriptor in (
            ("log", log_path, None, fixture["expected_log"]),
            ("artifact", artifact_path, "result", fixture["expected_artifacts"][0]),
        )],
    }
    return (
        template, fixture, relay.canonical_json(transcript) + b"\n",
        relay.canonical_json(receipt) + b"\n", relay.canonical_json(reads) + b"\n",
    )


def evidence_read_fixture(
    root: Path, now: int, *, request: dict[str, object] | None = None,
    log_raw: bytes = b"exact stage-7 log\n", artifact_raw: bytes = b'{"outcome":"pass"}\n',
) -> tuple[relay.RelayState, dict[str, object]]:
    state = relay.RelayState(
        root, "https://relay.test.invalid:3443", CHANNEL, "private",
        {
            public_hex(ACTOR): "admin", public_hex(CI_EVENT): "member",
            public_hex(NIP98): "member",
        },
        {public_hex(CI_EVENT), public_hex(NIP98)},
        export_generation=1,
    )
    if request is None:
        request_content = {
            "schema_version": 1, "actor": public_hex(ACTOR), "run_id": RUN_ID,
            "target_repo_a": REPOSITORY,
            "request_type": "run", "attempt": 1, "job_ids": ["capacity_one"],
            "workflow_id": "workflow", "tip_oid": "1" * 40, "base_oid": "2" * 40,
            "workflow_digest": "3" * 64, "pr_root_event_id": "4" * 64,
            "source_clone_url": "https://example.invalid/repo.git",
            "immutable_source_ref": "refs/buzz-ci/source", "source_branch": "topic",
            "base_ref": "refs/heads/main", "trigger_event_id": "4" * 64,
            "timeout_seconds": 60, "idempotency_key": "stage7", "issued_at": now,
            "expires_at": now + 600,
        }
        request_tags = [
            ["h", CHANNEL], ["a", REPOSITORY], ["run", RUN_ID], ["workflow", "workflow"],
            ["c", "1" * 40], ["attempt", "1"],
        ]
        request = signed_event(
            ACTOR, 46100, request_tags,
            json.dumps(request_content, separators=(",", ":")), now,
        )
    else:
        request_content = json.loads(request["content"])
    relay.admit_event(state, public_hex(ACTOR), request, int(request["created_at"]))
    run_id = str(request_content["run_id"])
    repository = str(request_content["target_repo_a"])
    workflow_id = str(request_content["workflow_id"])
    tip_oid = str(request_content["tip_oid"])
    base_oid = str(request_content["base_oid"])
    job_id = str(request_content["job_ids"][0])
    log_sha, artifact_sha = hashlib.sha256(log_raw).hexdigest(), hashlib.sha256(artifact_raw).hexdigest()
    log_path = f"/ci/logs/{request['id']}/{run_id}/{job_id}/1/{log_sha}"
    artifact_path = f"/ci/artifacts/{request['id']}/{run_id}/{job_id}/1/result/{artifact_sha}"

    def ci_event(kind: int, content: dict[str, object], created_at: int) -> dict[str, object]:
        envelope = {
            "schema_version": 1, "relay_signer": public_hex(CI_EVENT),
            "request_event_id": request["id"],
            "run_id": run_id, "workflow_id": workflow_id, "target_repo_a": repository,
            "tip_oid": tip_oid, "job_id": job_id, "attempt": 1, **content,
        }
        digest = envelope.get("log_sha256", envelope.get("sha256"))
        tags = [
            ["h", CHANNEL], ["a", repository], ["run", run_id], ["workflow", workflow_id],
            ["c", tip_oid], ["attempt", "1"], ["job", job_id],
            ["e", request["id"], "", "request"],
        ]
        if digest is not None:
            tags.append(["x", digest])
        return signed_event(
            CI_EVENT, kind, tags,
            json.dumps(envelope, separators=(",", ":")), created_at,
        )

    log_ref = ci_event(46103, {
        "log_sha256": log_sha, "byte_length": len(log_raw), "cap_bytes": len(log_raw),
        "truncated": False, "url": state.origin + log_path, "created_at": now + 1,
    }, now + 1)
    artifact_ref = ci_event(46104, {
        "artifact_id": "result", "sha256": artifact_sha, "byte_length": len(artifact_raw),
        "name": "result.json", "media_type": "application/json",
        "url": state.origin + artifact_path, "created_at": now + 2,
    }, now + 2)
    terminal = ci_event(46102, {
        "base_oid": base_oid, "sequence": 1, "state": "success",
        "name": "Capacity one", "required": True, "skip_policy": "forbid",
        "selected_job_instance": job_id, "also_reruns": [],
        "started_at": now + 1, "finished_at": now + 3,
        "log_ref": log_ref["id"], "artifact_refs": [artifact_ref["id"]],
    }, now + 3)
    for event in (log_ref, artifact_ref, terminal):
        relay.admit_event(state, public_hex(CI_EVENT), event, int(event["created_at"]))
    parsed_log = relay.parse_evidence_path(log_path)
    parsed_artifact = relay.parse_evidence_path(artifact_path)
    relay.store_evidence_object(state, parsed_log, request_content, CHANNEL, log_raw)
    relay.store_evidence_object(state, parsed_artifact, request_content, CHANNEL, artifact_raw)
    return state, {
        "request": request, "log_ref": log_ref, "artifact_ref": artifact_ref, "terminal": terminal,
        "log_path": log_path, "artifact_path": artifact_path,
        "log_raw": log_raw, "artifact_raw": artifact_raw,
    }


SNAPSHOT_MAX_PATHS = 256
SNAPSHOT_MAX_FILE_BYTES = harness.MAX_JSON
SNAPSHOT_MAX_TOTAL_BYTES = 4 * harness.MAX_JSON


def relay_evidence_snapshot(state: relay.RelayState) -> tuple[object, ...]:
    root = state.object_root.parent
    paths = sorted(root.rglob("*"))
    if len(paths) > SNAPSHOT_MAX_PATHS:
        raise AssertionError(f"evidence snapshot exceeds {SNAPSHOT_MAX_PATHS} paths: {root}")
    files = []
    total = 0
    for path in paths:
        metadata = path.lstat()
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            value: object = ("symlink", os.readlink(path))
        elif path.is_file():
            raw = path.read_bytes()
            if len(raw) > SNAPSHOT_MAX_FILE_BYTES:
                raise AssertionError(
                    f"evidence snapshot file exceeds {SNAPSHOT_MAX_FILE_BYTES} bytes: {relative}"
                )
            total += len(raw)
            if total > SNAPSHOT_MAX_TOTAL_BYTES:
                raise AssertionError(f"evidence snapshot exceeds {SNAPSHOT_MAX_TOTAL_BYTES} bytes: {root}")
            value = ("file", raw)
        else:
            value = ("directory", None)
        files.append((relative, stat.S_IMODE(metadata.st_mode), metadata.st_nlink, value))
    return (
        copy.deepcopy(state.events), copy.deepcopy(state.event_channels),
        copy.deepcopy(state.object_owners), set(state.seen_tokens),
        set(state.pending_tokens), copy.deepcopy(state.evidence_reads),
        copy.deepcopy(state.query_callers), tuple(files),
    )


class RelayAdmissionTests(unittest.TestCase):
    """The loopback relay refuses what crates/buzz-relay refuses on POST /events."""

    def setUp(self) -> None:
        self.now = 1_800_000_000
        self.relay_temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.relay_temporary.cleanup)
        object_root = Path(self.relay_temporary.name) / "objects"
        object_root.mkdir()
        self.state = relay.RelayState(
            object_root, "https://relay.test.invalid:3443", CHANNEL, "private",
            {public_hex(ACTOR): "admin", public_hex(CI_EVENT): "member"}, {public_hex(NIP98)},
        )

    def admit(self, token: int, event: dict[str, object], *, now: int | None = None) -> tuple[str | None, bool]:
        return relay.admit_event(self.state, public_hex(token), event, self.now if now is None else now)

    def refused(self, token: int, event: dict[str, object], status: int, message: str, *, now: int | None = None) -> None:
        with self.assertRaises(relay.Refusal) as caught:
            self.admit(token, event, now=now)
        self.assertEqual((caught.exception.status, caught.exception.message), (status, message))

    def query(self, token: int, filters: object) -> list[dict[str, object]]:
        return relay.query_events(self.state, public_hex(token), json.dumps(filters).encode())

    def test_evidence_get_paths_are_exact_and_canonical(self) -> None:
        request_id, digest = "a" * 64, "b" * 64
        valid_log = f"/ci/logs/{request_id}/{RUN_ID}/job_1/1/{digest}"
        valid_artifact = f"/ci/artifacts/{request_id}/{RUN_ID}/job_1/4294967295/result/{digest}"
        self.assertEqual(relay.parse_evidence_path(valid_log)["attempt"], 1)
        self.assertEqual(relay.parse_evidence_path(valid_artifact)["artifact_id"], "result")
        invalid = (
            valid_log.replace(request_id, "a" * 63),
            valid_log.replace(request_id, "a" * 65),
            valid_log.replace(request_id, "A" * 64),
            valid_log.replace(RUN_ID, RUN_ID.upper()),
            valid_log.replace(RUN_ID, RUN_ID.replace("-", "")),
            valid_log.replace("/job_1/", "/1job/"),
            valid_log.replace("/job_1/", "/job.1/"),
            valid_log.replace("/job_1/1/", "/job_1/0/"),
            valid_log.replace("/job_1/1/", "/job_1/01/"),
            valid_log.replace("/job_1/1/", "/job_1/4294967296/"),
            valid_artifact.replace("/result/", "//"),
            valid_artifact.replace("/result/", "/result%2fjson/"),
            valid_log.replace(digest, "B" * 64),
            valid_log.replace(digest, "b" * 63),
            valid_log.replace(digest, "b" * 65),
            valid_log + "/extra",
        )
        for path in invalid:
            with self.subTest(path=path), self.assertRaises(relay.Refusal):
                relay.parse_evidence_path(path)

    def test_evidence_read_requires_one_time_auth_and_repo_channel_membership_without_lookup_mutation(self) -> None:
        state, fixture = evidence_read_fixture(Path(self.relay_temporary.name) / "objects", self.now)
        path = relay.parse_evidence_path(fixture["log_path"])
        url = state.origin + fixture["log_path"]
        bad_token = nip98(NIP98, "GET", url + "/wrong", b"", self.now)
        tokens_before = set(state.seen_tokens)
        with self.assertRaisesRegex(relay.Refusal, "NIP-98"):
            relay.authenticate_once(state, bad_token, "GET", url, b"", now=self.now)
        self.assertEqual(state.seen_tokens, tokens_before)
        token = nip98(NIP98, "GET", url, b"", self.now)
        caller = relay.authenticate_once(state, token, "GET", url, b"", now=self.now)
        events_before = copy.deepcopy(state.events)
        owners_before = copy.deepcopy(state.object_owners)
        raw, headers = relay.read_evidence_object(state, caller, path, now=self.now)
        self.assertEqual(raw, fixture["log_raw"])
        self.assertEqual(headers["Content-Length"], str(len(raw)))
        self.assertEqual(headers["Digest"], "sha-256=" + base64.b64encode(hashlib.sha256(raw).digest()).decode())
        self.assertEqual((state.events, state.object_owners), (events_before, owners_before))
        with self.assertRaisesRegex(relay.Refusal, "replayed authorization"):
            relay.authenticate_once(state, token, "GET", url, b"", now=self.now)

        state.members.pop(public_hex(NIP98))
        self.assertIn(public_hex(NIP98), state.static_signers)
        later = nip98(NIP98, "GET", url, b"", self.now + 1)
        static_only = relay.authenticate_once(state, later, "GET", url, b"", now=self.now + 1)
        with self.assertRaisesRegex(relay.Refusal, "CI log not found"):
            relay.read_evidence_object(state, static_only, path, now=self.now + 1)
        self.assertEqual((state.events, state.object_owners), (events_before, owners_before))

        missing_url = url[:-64] + "0" * 64
        missing_token = nip98(CI_EVENT, "GET", missing_url, b"", self.now + 2)
        missing_caller = relay.authenticate_once(state, missing_token, "GET", missing_url, b"", now=self.now + 2)
        with self.assertRaisesRegex(relay.Refusal, "not found"):
            relay.read_evidence_object(
                state, missing_caller, relay.parse_evidence_path(missing_url.removeprefix(state.origin)),
                now=self.now + 2,
            )
        with self.assertRaisesRegex(relay.Refusal, "replayed authorization"):
            relay.authenticate_once(state, missing_token, "GET", missing_url, b"", now=self.now + 2)

    def test_evidence_read_rejects_unsigned_unselected_unowned_and_corrupt_objects_without_mutation(self) -> None:
        mutations = (
            "zero-reference", "unsigned-reference", "duplicate-reference", "unselected", "owner-missing",
            "owner-content", "owner-mode", "owner-hardlink", "object-hardlink",
            "corrupt", "object-fifo", "symlink",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                object_root = Path(temporary) / "objects"
                object_root.mkdir()
                state, fixture = evidence_read_fixture(object_root, self.now)
                path = relay.parse_evidence_path(fixture["artifact_path"])
                if mutation == "zero-reference":
                    state.events.pop(fixture["artifact_ref"]["id"])
                    state.event_channels.pop(fixture["artifact_ref"]["id"])
                elif mutation == "unsigned-reference":
                    state.events[fixture["artifact_ref"]["id"]]["content"] += " "
                elif mutation == "duplicate-reference":
                    original = fixture["artifact_ref"]
                    duplicate = signed_event(
                        CI_EVENT, original["kind"], original["tags"], original["content"],
                        original["created_at"] + 10,
                    )
                    state.events[duplicate["id"]] = duplicate
                    state.event_channels[duplicate["id"]] = CHANNEL
                elif mutation == "unselected":
                    original = state.events.pop(fixture["terminal"]["id"])
                    state.event_channels.pop(fixture["terminal"]["id"])
                    body = json.loads(original["content"])
                    body["artifact_refs"] = []
                    replacement = signed_event(
                        CI_EVENT, original["kind"], original["tags"],
                        json.dumps(body, separators=(",", ":")), original["created_at"],
                    )
                    state.events[replacement["id"]] = replacement
                    state.event_channels[replacement["id"]] = CHANNEL
                elif mutation == "owner-missing":
                    state.object_owners.clear()
                    owner_name, _owner_raw = relay._owner_record(CHANNEL, json.loads(fixture["request"]["content"]), path)
                    (state.object_root / owner_name).unlink()
                elif mutation.startswith("owner-"):
                    owner_name, _owner_raw = relay._owner_record(CHANNEL, json.loads(fixture["request"]["content"]), path)
                    owner = state.object_root / owner_name
                    if mutation == "owner-content":
                        owner.chmod(0o600)
                        owner.write_bytes(b"{}\n")
                        owner.chmod(0o400)
                    elif mutation == "owner-mode":
                        owner.chmod(0o600)
                    else:
                        os.link(owner, Path(temporary) / "owner-link")
                elif mutation == "object-hardlink":
                    os.link(state.object_root / path["sha256"], Path(temporary) / "object-link")
                elif mutation == "corrupt":
                    target = state.object_root / path["sha256"]
                    target.chmod(0o600)
                    target.write_bytes(b"corrupt")
                    target.chmod(0o400)
                elif mutation == "object-fifo":
                    target = state.object_root / path["sha256"]
                    target.unlink()
                    os.mkfifo(target, 0o400)
                else:
                    target = state.object_root / path["sha256"]
                    target.unlink()
                    outside = Path(temporary) / "outside"
                    outside.write_bytes(fixture["artifact_raw"])
                    target.symlink_to(outside)
                before = relay_evidence_snapshot(state)
                expected = "unavailable" if mutation == "corrupt" else "not found"
                with self.assertRaisesRegex(relay.Refusal, expected):
                    relay.read_evidence_object(state, public_hex(NIP98), path, now=self.now)
                self.assertEqual(relay_evidence_snapshot(state), before)

    def test_evidence_store_rejects_hostile_owner_before_object_publication(self) -> None:
        object_root = Path(self.relay_temporary.name) / "fresh-objects"
        object_root.mkdir()
        state = relay.RelayState(
            object_root, relay.EXPORT_ORIGIN, CHANNEL, "private",
            {public_hex(ACTOR): "admin"}, {public_hex(CI_EVENT)},
        )
        raw = b"new evidence"
        digest = hashlib.sha256(raw).hexdigest()
        path = relay.parse_evidence_path(f"/ci/logs/{'a' * 64}/{RUN_ID}/capacity_one/1/{digest}")
        request = {"target_repo_a": REPOSITORY, "tip_oid": "1" * 40}
        owner_name, _owner_raw = relay._owner_record(CHANNEL, request, path)
        hostile = object_root / owner_name
        hostile.write_bytes(b"{}\n")
        hostile.chmod(0o400)
        before = relay_evidence_snapshot(state)
        with self.assertRaisesRegex(relay.Refusal, "ownership collision"):
            relay.store_evidence_object(state, path, request, CHANNEL, raw)
        self.assertEqual(relay_evidence_snapshot(state), before)
        self.assertFalse((object_root / digest).exists())

    def test_evidence_read_record_recovers_after_publish_before_memory_commit(self) -> None:
        object_root = Path(self.relay_temporary.name) / "record-recovery" / "objects"
        object_root.mkdir(parents=True)
        state = relay.RelayState(
            object_root, relay.EXPORT_ORIGIN, CHANNEL, "private",
            {public_hex(NIP98): "member"}, {public_hex(NIP98)}, export_generation=1,
        )
        stale = object_root.parent / (relay.EVIDENCE_READS_RECORD_NAME + ".next")
        stale.write_bytes(b"stale")
        path = relay.parse_evidence_path(f"/ci/logs/{'a' * 64}/{RUN_ID}/capacity_one/1/{'b' * 64}")
        state.record_evidence_read(public_hex(NIP98), path, 1)
        self.assertEqual(len(state.evidence_reads), 1)
        artifact = relay.parse_evidence_path(
            f"/ci/artifacts/{'a' * 64}/{RUN_ID}/capacity_one/1/result/{'c' * 64}",
        )
        real_fsync = os.fsync
        calls = 0

        def crash_after_replace(descriptor: int) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("simulated directory fsync crash")
            real_fsync(descriptor)

        with mock.patch.object(relay.os, "fsync", side_effect=crash_after_replace):
            with self.assertRaisesRegex(OSError, "simulated"):
                state.record_evidence_read(public_hex(NIP98), artifact, 1)
        self.assertEqual(len(state.evidence_reads), 1)
        restarted = relay.RelayState(
            object_root, relay.EXPORT_ORIGIN, CHANNEL, "private",
            {public_hex(NIP98): "member"}, {public_hex(NIP98)}, export_generation=1,
        )
        self.assertEqual(len(restarted.evidence_reads), 2)
        self.assertEqual(restarted.evidence_reads[-1]["path"], artifact["path"])

    def test_atomic_object_publish_recovers_link_before_temporary_unlink(self) -> None:
        object_root = Path(self.relay_temporary.name) / "link-recovery" / "objects"
        object_root.mkdir(parents=True)
        state = relay.RelayState(
            object_root, relay.EXPORT_ORIGIN, CHANNEL, "private",
            {public_hex(ACTOR): "admin"}, {public_hex(CI_EVENT)},
        )
        raw = b"recoverable object"
        digest = hashlib.sha256(raw).hexdigest()
        path = relay.parse_evidence_path(f"/ci/logs/{'a' * 64}/{RUN_ID}/capacity_one/1/{digest}")
        request = {"target_repo_a": REPOSITORY, "tip_oid": "1" * 40}
        with mock.patch.object(relay.os, "unlink", side_effect=OSError("simulated crash")):
            with self.assertRaisesRegex(OSError, "simulated crash"):
                relay.store_evidence_object(state, path, request, CHANNEL, raw)
        self.assertEqual((object_root / digest).stat().st_nlink, 2)
        restarted = relay.RelayState(
            object_root, relay.EXPORT_ORIGIN, CHANNEL, "private",
            {public_hex(ACTOR): "admin"}, {public_hex(CI_EVENT)},
        )
        relay.store_evidence_object(restarted, path, request, CHANNEL, raw)
        self.assertEqual((object_root / digest).stat().st_nlink, 1)
        self.assertEqual((object_root / digest).read_bytes(), raw)

    def test_evidence_read_rejects_wrong_signed_graph_fields_without_mutation(self) -> None:
        cases = (
            ("request-schema", "request", lambda body, tags: body.__setitem__("schema_version", 2)),
            ("request-tag", "request", lambda body, tags: tags.__setitem__(0, ["h", RUN_ID])),
            ("ref-schema", "artifact_ref", lambda body, tags: body.__setitem__("schema_version", 2)),
            ("ref-signer", "artifact_ref", lambda body, tags: body.__setitem__("relay_signer", public_hex(NIP98))),
            ("ref-created-at", "artifact_ref", lambda body, tags: body.__setitem__("created_at", 0)),
            ("ref-tag", "artifact_ref", lambda body, tags: tags[-1].__setitem__(1, "0" * 64)),
            ("ref-url", "artifact_ref", lambda body, tags: body.__setitem__("url", body["url"] + "/wrong")),
            ("ref-length", "artifact_ref", lambda body, tags: body.__setitem__("byte_length", body["byte_length"] + 1)),
            ("ref-media", "artifact_ref", lambda body, tags: body.__setitem__("media_type", "application/json\r\nX: y")),
            ("terminal-state", "terminal", lambda body, tags: body.__setitem__("state", "failure")),
            ("terminal-sequence", "terminal", lambda body, tags: body.__setitem__("sequence", 0)),
            ("terminal-parent", "terminal", lambda body, tags: body.__setitem__("parent_attempt", 99)),
            ("terminal-shape", "terminal", lambda body, tags: body.pop("selected_job_instance")),
        )
        for name, event_name, mutate in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                object_root = Path(temporary) / "objects"
                object_root.mkdir()
                state, fixture = evidence_read_fixture(object_root, self.now)
                original = fixture[event_name]
                body = json.loads(original["content"])
                tags = copy.deepcopy(original["tags"])
                mutate(body, tags)
                replacement = signed_event(
                    ACTOR if event_name == "request" else CI_EVENT,
                    original["kind"], tags, json.dumps(body, separators=(",", ":")),
                    original["created_at"],
                )
                state.events.pop(original["id"])
                state.event_channels.pop(original["id"])
                state.events[replacement["id"]] = replacement
                state.event_channels[replacement["id"]] = CHANNEL
                path = relay.parse_evidence_path(fixture["artifact_path"])
                before = relay_evidence_snapshot(state)
                with self.assertRaisesRegex(relay.Refusal, "not found"):
                    relay.read_evidence_object(state, public_hex(NIP98), path, now=self.now)
                self.assertEqual(relay_evidence_snapshot(state), before)

    def test_artifact_media_type_matches_header_value_semantics(self) -> None:
        self.assertTrue(relay.valid_header_value("application/json; charset=utf-8"))
        self.assertTrue(relay.valid_header_value("opaque header value\t"))
        for value in ("", "snowman-☃", "application/json\r", "application/json\n", "x\x7f"):
            with self.subTest(value=value):
                self.assertFalse(relay.valid_header_value(value))

    def test_evidence_get_serves_exact_raw_bytes_headers_and_rejects_token_replay(self) -> None:
        state, fixture = evidence_read_fixture(Path(self.relay_temporary.name) / "objects", self.now)
        server = relay.RelayServer(("127.0.0.1", 0), state)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            path = fixture["artifact_path"]
            now = int(time.time())
            unauthorized = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            unauthorized.request("GET", path)
            unauthorized_response = unauthorized.getresponse()
            self.assertEqual(unauthorized_response.status, 401)
            unauthorized_response.read()
            unauthorized.close()
            self.assertEqual(state.seen_tokens, set())
            token = nip98(NIP98, "GET", state.origin + path, b"", now)
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            connection.request("GET", path, headers={"Authorization": token})
            response = connection.getresponse()
            raw = response.read()
            self.assertEqual(response.status, 200)
            self.assertEqual(raw, fixture["artifact_raw"])
            self.assertEqual(response.getheader("Content-Type"), "application/json")
            self.assertEqual(response.getheader("Content-Length"), str(len(raw)))
            self.assertEqual(response.getheader("Digest"), "sha-256=" + base64.b64encode(hashlib.sha256(raw).digest()).decode())
            connection.close()
            log_path = fixture["log_path"]
            log_token = nip98(NIP98, "GET", state.origin + log_path, b"", now + 1)
            log_connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            log_connection.request("GET", log_path, headers={"Authorization": log_token})
            log_response = log_connection.getresponse()
            self.assertEqual((log_response.status, log_response.read()), (200, fixture["log_raw"]))
            log_connection.close()
            # Stage 7 consumes log then artifact. Reorder the deliberately
            # artifact-first probe to prove closure enforces that plan.
            record_path = state.object_root.parent / relay.EVIDENCE_READS_RECORD_NAME
            reversed_record = json.loads(record_path.read_bytes())
            with self.assertRaisesRegex(relay.RelayError, "GET plan"):
                relay.validate_evidence_reads(
                    record_path.read_bytes(), 1, public_hex(NIP98),
                    {"event": fixture["log_ref"]}, {"event": fixture["artifact_ref"]},
                )
            reversed_record["reads"].reverse()
            ordered_raw = relay.canonical_json(reversed_record) + b"\n"
            relay.validate_evidence_reads(
                ordered_raw, 1, public_hex(NIP98),
                {"event": fixture["log_ref"]}, {"event": fixture["artifact_ref"]},
            )
            replay = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            replay.request("GET", path, headers={"Authorization": token})
            replay_response = replay.getresponse()
            self.assertEqual(replay_response.status, 401)
            self.assertIn(b"replayed authorization", replay_response.read())
            replay.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_evidence_handler_authenticates_before_coordinate_parse_and_lookup(self) -> None:
        state, fixture = evidence_read_fixture(Path(self.relay_temporary.name) / "objects", self.now)
        server = relay.RelayServer(("127.0.0.1", 0), state)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def get(path: str, header: str | None) -> tuple[int, bytes]:
            connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
            headers = {} if header is None else {"Authorization": header}
            connection.request("GET", path, headers=headers)
            response = connection.getresponse()
            result = response.status, response.read()
            connection.close()
            return result

        try:
            malformed = fixture["log_path"].replace(fixture["request"]["id"], fixture["request"]["id"].upper())
            now = int(time.time())
            malformed_token = nip98(NIP98, "GET", state.origin + malformed, b"", now)
            token_id = relay.verify_nip98(
                malformed_token, "GET", state.origin + malformed, b"", now=now,
            )["id"]
            before = relay_evidence_snapshot(state)
            self.assertEqual(get(malformed, malformed_token)[0], 404)
            after = relay_evidence_snapshot(state)
            self.assertEqual(after[:3] + after[4:], before[:3] + before[4:])
            self.assertEqual(after[3], before[3] | {token_id})
            self.assertEqual(get(malformed, malformed_token)[0], 401)

            wrong_arity = fixture["log_path"] + "/extra"
            wrong_arity_token = nip98(NIP98, "GET", state.origin + wrong_arity, b"", now + 1)
            wrong_arity_id = relay.verify_nip98(
                wrong_arity_token, "GET", state.origin + wrong_arity, b"", now=now + 1,
            )["id"]
            wrong_arity_before = relay_evidence_snapshot(state)
            self.assertEqual(get(wrong_arity, wrong_arity_token)[0], 404)
            wrong_arity_after = relay_evidence_snapshot(state)
            self.assertEqual(
                wrong_arity_after[:3] + wrong_arity_after[4:],
                wrong_arity_before[:3] + wrong_arity_before[4:],
            )
            self.assertEqual(wrong_arity_after[3], wrong_arity_before[3] | {wrong_arity_id})
            self.assertEqual(get(wrong_arity, wrong_arity_token)[0], 401)

            bad_auth_before = relay_evidence_snapshot(state)
            self.assertEqual(get(wrong_arity, "Nostr !!!")[0], 401)
            self.assertEqual(relay_evidence_snapshot(state), bad_auth_before)

            missing = fixture["log_path"][:-64] + "0" * 64
            missing_token = nip98(NIP98, "GET", state.origin + missing, b"", now + 2)
            missing_id = relay.verify_nip98(missing_token, "GET", state.origin + missing, b"", now=now + 2)["id"]
            missing_before = relay_evidence_snapshot(state)
            self.assertEqual(get(missing, missing_token)[0], 404)
            missing_after = relay_evidence_snapshot(state)
            self.assertEqual(missing_after[:3] + missing_after[4:], missing_before[:3] + missing_before[4:])
            self.assertEqual(missing_after[3], missing_before[3] | {missing_id})
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_evidence_handler_concurrent_replay_and_fresh_token_behavior(self) -> None:
        state, fixture = evidence_read_fixture(Path(self.relay_temporary.name) / "objects", self.now)
        server = relay.RelayServer(("127.0.0.1", 0), state)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            path = fixture["log_path"]
            now = int(time.time())
            token = nip98(NIP98, "GET", state.origin + path, b"", now)
            barrier = threading.Barrier(3)
            results: list[int] = []

            def request(header: str) -> None:
                barrier.wait()
                connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
                connection.request("GET", path, headers={"Authorization": header})
                response = connection.getresponse()
                response.read()
                results.append(response.status)
                connection.close()

            workers = [threading.Thread(target=request, args=(token,)) for _ in range(2)]
            for worker in workers:
                worker.start()
            barrier.wait()
            for worker in workers:
                worker.join(timeout=5)
            self.assertEqual(sorted(results), [200, 401])
            self.assertEqual(len(state.evidence_reads), 1)
            fresh = nip98(NIP98, "GET", state.origin + path, b"", now + 1)
            barrier = threading.Barrier(2)
            one = threading.Thread(target=request, args=(fresh,))
            one.start()
            barrier.wait()
            one.join(timeout=5)
            self.assertEqual(results[-1], 200)
            self.assertEqual(len(state.evidence_reads), 2)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_evidence_put_preauthenticates_before_body_and_accepts_over_64k(self) -> None:
        state, fixture = evidence_read_fixture(Path(self.relay_temporary.name) / "objects", self.now)
        server = relay.RelayServer(("127.0.0.1", 0), state)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            oversized_path = fixture["log_path"]
            before = relay_evidence_snapshot(state)
            unauthenticated = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            unauthenticated.putrequest("PUT", oversized_path)
            unauthenticated.putheader("Content-Length", str(relay.MAX_EVIDENCE_BYTES + 1))
            unauthenticated.endheaders()
            response = unauthenticated.getresponse()
            self.assertEqual(response.status, 401)
            response.read()
            unauthenticated.close()
            self.assertEqual(relay_evidence_snapshot(state), before)

            raw = b"x" * 65_537
            digest = hashlib.sha256(raw).hexdigest()
            request = fixture["request"]
            path = (
                f"/ci/logs/{request['id']}/{RUN_ID}/capacity_one/1/{digest}"
            )
            now = int(time.time())
            token = nip98(NIP98, "PUT", state.origin + path, raw, now)
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            connection.request("PUT", path, body=raw, headers={"Authorization": token})
            accepted = connection.getresponse()
            self.assertEqual(accepted.status, 200)
            accepted.read()
            connection.close()
            self.assertEqual((state.object_root / digest).read_bytes(), raw)
            self.assertEqual(state.pending_tokens, set())
            self.assertEqual(len(state.seen_tokens), 1)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

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
        self.assertEqual(self.admit(ACTOR, grant_event(ACTOR, self.now + 1, CI_EVENT, valid_until=self.now + 600), now=self.now + 1), (CHANNEL, True))
        failed = ci_fact_event(CI_EVENT, 46102, self.now + 2, {
            "job_id": "capacity-one-fixture", "attempt": 1, "state": "failure",
        })
        self.assertEqual(self.admit(CI_EVENT, failed, now=self.now + 2), (CHANNEL, True))
        rerun = request_event(ACTOR, self.now + 10, attempt=2)
        self.assertEqual(self.admit(ACTOR, rerun), (CHANNEL, True))
        self.assertEqual([cursor for cursor, _channel, _event in self.state.accepted], [1, 2])

    def test_rerun_requires_one_failed_parent_and_final_facts_seal_the_run(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            self.state = relay.RelayState(
                Path(temporary) / "objects", "https://relay.test.invalid:3443", CHANNEL, "private",
                {public_hex(ACTOR): "admin", public_hex(CI_EVENT): "member"}, {public_hex(NIP98)},
            )
            self.state.object_root.mkdir()
            initial = request_event(ACTOR, self.now)
            self.assertEqual(self.admit(ACTOR, initial), (CHANNEL, True))
            self.assertEqual(self.admit(ACTOR, grant_event(ACTOR, self.now + 1, CI_EVENT, valid_until=self.now + 600), now=self.now + 1), (CHANNEL, True))
            rerun = request_event(ACTOR, self.now + 4, attempt=2)
            before = (
                self.state.cursor, self.state.ci_cursor, dict(self.state.events),
                list(self.state.accepted), copy.deepcopy(self.state.run_requests),
                copy.deepcopy(self.state.run_events), copy.deepcopy(self.state.final_facts),
            )
            self.refused(ACTOR, rerun, 400, "invalid: CI rerun does not extend the selected failed job attempt", now=self.now + 4)
            self.assertEqual((
                self.state.cursor, self.state.ci_cursor, self.state.events,
                self.state.accepted, self.state.run_requests, self.state.run_events,
                self.state.final_facts,
            ), before)
            failure = ci_fact_event(CI_EVENT, 46102, self.now + 2, {
                "job_id": "capacity-one-fixture", "attempt": 1, "state": "failure",
            })
            self.assertEqual(self.admit(CI_EVENT, failure, now=self.now + 2), (CHANNEL, True))
            fact = ci_fact_event(CI_EVENT, 46105, self.now + 3, {
                "attempt": 1, "finalized_at": self.now + 3, "finalized_job_attempts": [{
                    "job_id": "capacity-one-fixture", "attempt": 1, "log_ref": "a" * 64, "artifact_refs": [],
                }],
            })
            self.assertEqual(self.admit(CI_EVENT, fact, now=self.now + 3), (CHANNEL, True))
            before = (
                self.state.cursor, self.state.ci_cursor, dict(self.state.events),
                list(self.state.accepted), copy.deepcopy(self.state.run_requests),
                copy.deepcopy(self.state.run_events), copy.deepcopy(self.state.final_facts),
            )
            self.refused(ACTOR, rerun, 409, "conflict: CI run is already bound to terminal evidence and cannot be rerun", now=self.now + 4)
            self.assertEqual((
                self.state.cursor, self.state.ci_cursor, self.state.events,
                self.state.accepted, self.state.run_requests, self.state.run_events,
                self.state.final_facts,
            ), before)

    def test_teardown_fact_alone_seals_the_run_without_mutating_on_refusal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            self.state = relay.RelayState(
                Path(temporary) / "objects", "https://relay.test.invalid:3443", CHANNEL, "private",
                {public_hex(ACTOR): "admin", public_hex(CI_EVENT): "member"}, {public_hex(NIP98)},
            )
            self.state.object_root.mkdir()
            self.assertEqual(self.admit(ACTOR, request_event(ACTOR, self.now)), (CHANNEL, True))
            self.assertEqual(self.admit(ACTOR, grant_event(ACTOR, self.now + 1, CI_EVENT, valid_until=self.now + 600), now=self.now + 1), (CHANNEL, True))
            failure = ci_fact_event(CI_EVENT, 46102, self.now + 2, {
                "job_id": "capacity-one-fixture", "attempt": 1, "state": "failure",
            })
            self.assertEqual(self.admit(CI_EVENT, failure, now=self.now + 2), (CHANNEL, True))
            teardown = ci_fact_event(CI_EVENT, 46106, self.now + 3, {"attempt": 1})
            self.assertEqual(self.admit(CI_EVENT, teardown, now=self.now + 3), (CHANNEL, True))
            before = (
                self.state.cursor, self.state.ci_cursor, dict(self.state.events),
                list(self.state.accepted), copy.deepcopy(self.state.run_requests),
                copy.deepcopy(self.state.run_events), copy.deepcopy(self.state.final_facts),
            )
            self.refused(
                ACTOR, request_event(ACTOR, self.now + 4, attempt=2), 409,
                "conflict: CI run is already bound to terminal evidence and cannot be rerun", now=self.now + 4,
            )
            self.assertEqual((
                self.state.cursor, self.state.ci_cursor, self.state.events,
                self.state.accepted, self.state.run_requests, self.state.run_events,
                self.state.final_facts,
            ), before)

    def test_closed_green_verdict_uses_cursor_order_and_accepts_same_second_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            self.state = relay.RelayState(
                Path(temporary) / "objects", "https://relay.test.invalid:3443", CHANNEL, "private",
                {public_hex(ACTOR): "admin", public_hex(CI_EVENT): "member"}, {public_hex(NIP98)},
            )
            self.state.object_root.mkdir()
            self.assertEqual(self.admit(ACTOR, request_event(ACTOR, self.now)), (CHANNEL, True))
            self.assertEqual(self.admit(ACTOR, grant_event(ACTOR, self.now + 1, CI_EVENT, valid_until=self.now + 600), now=self.now + 1), (CHANNEL, True))
            log = ci_fact_event(CI_EVENT, 46103, self.now + 2, {
                "job_id": "capacity-one-fixture", "attempt": 1, "created_at": self.now + 2,
            })
            artifact = ci_fact_event(CI_EVENT, 46104, self.now + 2, {
                "job_id": "capacity-one-fixture", "attempt": 1, "created_at": self.now + 2,
            })
            for event in (log, artifact):
                self.assertEqual(self.admit(CI_EVENT, event, now=self.now + 2), (CHANNEL, True))
            terminal_job = ci_fact_event(CI_EVENT, 46102, self.now + 2, {
                "job_id": "capacity-one-fixture", "attempt": 1, "state": "success",
                "log_ref": log["id"], "artifact_refs": [artifact["id"]],
            })
            self.assertEqual(self.admit(CI_EVENT, terminal_job, now=self.now + 2), (CHANNEL, True))
            evidence = ci_fact_event(CI_EVENT, 46105, self.now + 2, {
                "attempt": 1, "finalized_at": self.now + 2, "finalized_job_attempts": [{
                    "job_id": "capacity-one-fixture", "attempt": 1,
                    "log_ref": log["id"], "artifact_refs": [artifact["id"]],
                }],
            })
            teardown = ci_fact_event(CI_EVENT, 46106, self.now + 2, {"attempt": 1})
            self.assertEqual(self.admit(CI_EVENT, evidence, now=self.now + 2), (CHANNEL, True))
            self.assertEqual(self.admit(CI_EVENT, teardown, now=self.now + 2), (CHANNEL, True))
            terminal = status_event(CI_EVENT, self.now + 2, state="success")
            terminal_content = json.loads(terminal["content"])
            terminal_content["attempt"] = 1
            terminal = signed_event(CI_EVENT, 46101, terminal["tags"], json.dumps(terminal_content, separators=(",", ":")), self.now + 2)
            self.assertEqual(self.admit(CI_EVENT, terminal, now=self.now + 2), (CHANNEL, True))
            self.assertEqual(self.state.closed_verdict(RUN_ID), {"state": "green", "reason": None})
            self.assertFalse((Path(temporary) / "protocol-verdict.json").exists(), "Run A cannot emit the close verdict")
            self.state.run_events[RUN_ID][2][2]["created_at"] = self.now + 3
            self.assertEqual(
                self.state.closed_verdict(RUN_ID),
                {"state": "infrastructure_failure", "reason": "evidence-finalized fact does not link the selected durable evidence"},
            )

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
        self.refused(CI_EVENT, status_event(CI_EVENT, self.now), 400, relay.UNAUTHORIZED_STATUS_SIGNER)
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
        self.refused(CI_EVENT, status_event(CI_EVENT, self.now), 400, relay.UNAUTHORIZED_STATUS_SIGNER, now=self.now)
        self.assertEqual(self.admit(CI_EVENT, status_event(CI_EVENT, self.now + 2), now=self.now + 2), (CHANNEL, True))
        self.refused(
            CI_EVENT, status_event(CI_EVENT, self.now + 601), 400,
            relay.UNAUTHORIZED_STATUS_SIGNER, now=self.now + 601,
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

    def test_unauthorized_signer_message_is_the_relay_envelope_error(self) -> None:
        # buzz-core ci.rs: CiValidationError("unauthorized CI status signer")
        # displayed as "invalid CI envelope: {0}"; controld matches it exactly.
        self.assertEqual(relay.UNAUTHORIZED_STATUS_SIGNER, "invalid CI envelope: unauthorized CI status signer")

    def test_replay_before_grant_fault_expires_grants_at_the_first_terminal_and_records_the_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            flag = Path(temporary) / "fault"
            record = Path(temporary) / "fault-fired.json"
            flag.write_text("stale-terminal-replay-before-grant\n")
            self.state.arm_fault(flag)
            grant = grant_event(ACTOR, self.now, CI_EVENT, valid_until=self.now + 600)
            self.assertEqual(self.admit(ACTOR, grant), (CHANNEL, True))
            queued = status_event(CI_EVENT, self.now + 1, state="queued")
            self.assertEqual(self.admit(CI_EVENT, queued, now=self.now + 1), (CHANNEL, True), "open states never fire the fault")
            self.assertFalse(record.exists())
            terminal = status_event(CI_EVENT, self.now + 2, state="success")
            self.refused(CI_EVENT, terminal, 400, relay.UNAUTHORIZED_STATUS_SIGNER, now=self.now + 2)
            self.assertNotIn(terminal["id"], self.state.events, "a refused event is not stored")
            expected = {
                "mode": "stale-terminal-replay-before-grant", "grants_expired_at": self.now + 2,
                "refused_event_ids": [terminal["id"]], "queried_event_ids": [], "replayed_event_id": None,
            }
            self.assertEqual(json.loads(record.read_bytes()), expected)
            self.assertEqual(self.state.active_signers(REPOSITORY, self.now + 2), {public_hex(NIP98)}, "the grant expired at the fault")
            self.assertEqual(self.query(CI_EVENT, [{"ids": [terminal["id"]], "kinds": [46100], "limit": 1}]), [])
            self.assertEqual(json.loads(record.read_bytes()), expected, "another kind is not the read-back")
            read_back = [{"ids": [terminal["id"]], "authors": [public_hex(CI_EVENT)], "kinds": [46101], "limit": 1}]
            self.assertEqual(self.query(CI_EVENT, read_back), [])
            expected["queried_event_ids"] = [terminal["id"]]
            self.assertEqual(json.loads(record.read_bytes()), expected)
            self.assertEqual(self.query(CI_EVENT, read_back), [])
            self.assertEqual(json.loads(record.read_bytes()), expected, "a repeated read-back is recorded once")
            # controld re-signs after the read-back: still no grant, refused again.
            resigned = status_event(CI_EVENT, self.now + 3, state="success")
            self.refused(CI_EVENT, resigned, 400, relay.UNAUTHORIZED_STATUS_SIGNER, now=self.now + 3)
            running = status_event(CI_EVENT, self.now + 3, state="running")
            self.refused(CI_EVENT, running, 400, relay.UNAUTHORIZED_STATUS_SIGNER, now=self.now + 3)
            expected["refused_event_ids"] = [terminal["id"], resigned["id"], running["id"]]
            self.assertEqual(json.loads(record.read_bytes()), expected, "every unauthorized refusal after the expiry is recorded")
            # The next activation approves its own grant; the first terminal
            # status accepted after the expiry is the replayed pending event.
            renewed = grant_event(ACTOR, self.now + 4, CI_EVENT, valid_until=self.now + 604)
            self.assertEqual(self.admit(ACTOR, renewed, now=self.now + 4), (CHANNEL, True))
            self.assertEqual(self.admit(CI_EVENT, status_event(CI_EVENT, self.now + 4, state="queued"), now=self.now + 4), (CHANNEL, True))
            self.assertEqual(json.loads(record.read_bytes()), expected, "an open state is not the replay")
            self.assertEqual(self.admit(CI_EVENT, resigned, now=self.now + 4), (CHANNEL, True), "the fault fires once")
            expected["replayed_event_id"] = resigned["id"]
            self.assertEqual(json.loads(record.read_bytes()), expected)
            later = status_event(CI_EVENT, self.now + 5, state="failure")
            self.assertEqual(self.admit(CI_EVENT, later, now=self.now + 5), (CHANNEL, True))
            self.assertEqual(json.loads(record.read_bytes()), expected, "later terminals do not replace the replay")
            self.assertEqual(self.query(CI_EVENT, [{"ids": [resigned["id"]], "kinds": [46101]}]), [resigned])

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
        self.assertEqual(self.admit(ACTOR, grant_event(ACTOR, self.now + 2, CI_EVENT, valid_until=self.now + 600), now=self.now + 2), (CHANNEL, True))
        failure = ci_fact_event(CI_EVENT, 46102, self.now + 3, {
            "job_id": "capacity-one-fixture", "attempt": 1, "state": "failure",
        })
        self.assertEqual(self.admit(CI_EVENT, failure, now=self.now + 3), (CHANNEL, True))
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
        template = acceptance_template()
        fixture = acceptance_fixture(template)
        config = guest.relay_public_config(public, CHANNEL, template, fixture, None)
        self.assertEqual(config, {
            "origin": "https://relay.test.invalid:3443",
            "channel": {
                "id": CHANNEL, "visibility": "private",
                "members": {
                    public_hex(ACTOR): "admin", public_hex(CI_EVENT): "member",
                    public_hex(NIP98): "member",
                },
            },
            "ci_status_signer_pubkeys": [public_hex(NIP98)],
            "export_generation": 1,
            "candidate_acceptance": template,
            "prior_acceptance": None,
            "acceptance_fixture": fixture,
        })
        state = relay.state_from_config(config, Path("/nonexistent"))
        self.assertEqual(state.members, config["channel"]["members"])
        self.assertEqual(state.static_signers, {public_hex(NIP98)})
        query = b'[{"kinds":[46100]}]'
        self.assertEqual(relay.query_events(state, public_hex(CI_EVENT), query), [])
        self.assertEqual(state.query_callers, [public_hex(CI_EVENT)])
        with self.assertRaisesRegex(relay.Refusal, "query signer differs"):
            relay.query_events(state, public_hex(NIP98), query)
        self.assertEqual(state.query_callers, [public_hex(CI_EVENT)])
        wrong_subject_fixture = copy.deepcopy(fixture)
        wrong_subject_fixture["export_subject"] = public_hex(CI_EVENT)
        with self.assertRaisesRegex(guest.GuestError, "export authority differs"):
            guest.relay_public_config(public, CHANNEL, template, wrong_subject_fixture, None)
        for broken in (
            {**config, "extra": 1},
            {**config, "channel": {**config["channel"], "visibility": "hidden"}},
            {**config, "channel": {**config["channel"], "members": {"zz": "admin"}}},
            {**config, "channel": {**config["channel"], "members": {public_hex(ACTOR): "guest"}}},
            {**config, "ci_status_signer_pubkeys": ["nope"]},
            {**config, "acceptance_fixture": {**fixture, "export_subject": public_hex(CI_EVENT)}},
        ):
            with self.assertRaises(ValueError):
                relay.state_from_config(broken, Path("/nonexistent"))

    def test_close_verdict_binds_both_runs_five_events_failure_and_zero_phases(self) -> None:
        template, fixture, transcript, receipt, evidence_reads = protocol_close_inputs()
        verdict = relay.build_closed_verdict(template, fixture, transcript, receipt, evidence_reads)
        authority = relay.validate_acceptance_template(template, label="test")
        self.assertEqual(verdict["state"], "green")
        self.assertTrue(verdict["sealed"])
        self.assertEqual(verdict["actor_event_ids"]["api_order"], authority["api_ids"])
        self.assertEqual(verdict["observed_actor_event_ids"], authority["live_ids"])
        self.assertEqual(verdict["run_ids"], {"run_a": authority["run_id"], "run_b": authority["failure_run_id"]})
        self.assertEqual(verdict["run_b"]["final_fact_count"], 0)
        self.assertEqual(verdict["receipt"]["zero_phases"], [17, 18])
        self.assertEqual(verdict["receipt"]["export_request_digest"], fixture["request_digest"])

    def test_real_evidence_gets_produce_the_record_consumed_by_verdict_closure(self) -> None:
        template, fixture, transcript, receipt, _synthetic_reads = protocol_close_inputs()
        run = signed_event(
            ACTOR, template["run_event"][3], template["run_event"][4],
            template["run_event"][5], template["run_event"][2],
        )
        log_raw = (
            b"fixture=buzz-ci-capacity-one-v1 "
            b"input_sha256=967723f42ed249ff3c4b81884d8fc3b9601a426dead66a5925bb9c7d4cb136f6 "
            b"artifact=result.json\n"
        )
        artifact_raw = (
            b'{"fixture_version":"v1","input_sha256":'
            b'"967723f42ed249ff3c4b81884d8fc3b9601a426dead66a5925bb9c7d4cb136f6"}\n'
        )
        self.assertEqual((hashlib.sha256(log_raw).hexdigest(), len(log_raw)), relay.EXPORT_LOG[1:])
        self.assertEqual(
            (hashlib.sha256(artifact_raw).hexdigest(), len(artifact_raw)), relay.EXPORT_ARTIFACT[2:],
        )
        object_root = Path(self.relay_temporary.name) / "closure-objects"
        object_root.mkdir()
        state, reads = evidence_read_fixture(
            object_root, int(run["created_at"]), request=run,
            log_raw=log_raw, artifact_raw=artifact_raw,
        )
        server = relay.RelayServer(("127.0.0.1", 0), state)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            now = int(time.time())
            for offset, path in enumerate((reads["log_path"], reads["artifact_path"])):
                token = nip98(NIP98, "GET", state.origin + path, b"", now + offset)
                connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
                connection.request("GET", path, headers={"Authorization": token})
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                response.read()
                connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        read_record = (object_root.parent / relay.EVIDENCE_READS_RECORD_NAME).read_bytes()
        verdict = relay.build_closed_verdict(template, fixture, transcript, receipt, read_record)
        self.assertEqual(verdict["state"], "green")
        self.assertEqual(len(state.evidence_reads), 2)

    def test_close_requires_exact_two_authenticated_evidence_reads(self) -> None:
        template, fixture, transcript, receipt, evidence_reads = protocol_close_inputs()
        relay.build_closed_verdict(template, fixture, transcript, receipt, evidence_reads)
        def append_third(value: dict[str, object]) -> None:
            third = copy.deepcopy(value["reads"][1])
            third["artifact_id"] = "third"
            third["path"] = third["path"].replace("/result/", "/third/")
            value["reads"].append(third)

        cases = {
            "missing": lambda value: value["reads"].pop(),
            "extra": lambda value: value["reads"].append(copy.deepcopy(value["reads"][0])),
            "duplicate": lambda value: value["reads"].__setitem__(1, copy.deepcopy(value["reads"][0])),
            "third": append_third,
            "order": lambda value: value["reads"].reverse(),
            "subject": lambda value: value["reads"][0].__setitem__("subject", "0" * 64),
            "path": lambda value: value["reads"][0].__setitem__("path", value["reads"][0]["path"] + "/wrong"),
            "generation": lambda value: value.__setitem__("export_generation", 2),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                changed = json.loads(evidence_reads)
                mutate(changed)
                with self.assertRaises(relay.RelayError):
                    relay.build_closed_verdict(
                        template, fixture, transcript, receipt,
                        relay.canonical_json(changed) + b"\n",
                    )

    def test_acceptance_export_authority_is_exact_and_fixture_bound(self) -> None:
        template, fixture, transcript, receipt, evidence_reads = protocol_close_inputs()
        authority = relay.validate_acceptance_template(template, label="candidate")
        self.assertEqual(authority["export_subject"], public_hex(NIP98))
        for field in template:
            with self.subTest(required=field):
                changed = copy.deepcopy(template)
                changed.pop(field)
                with self.assertRaisesRegex(ValueError, "shape rejected"):
                    relay.validate_acceptance_template(changed, label="candidate")
        for field, value in (
            ("export_subject", "1" * 64),
            ("export_generation", 0),
            ("export_generation", 9_007_199_254_740_992),
            ("export_authorization_digest", "2" * 64),
        ):
            with self.subTest(field=field, value=value):
                changed = copy.deepcopy(template)
                changed[field] = value
                with self.assertRaises(ValueError):
                    relay.validate_acceptance_template(changed, label="candidate")
        for field in ("export_subject", "export_generation", "export_authorization_digest"):
            with self.subTest(fixture=field):
                changed_fixture = copy.deepcopy(fixture)
                changed_fixture[field] = 2 if field == "export_generation" else "3" * 64
                with self.assertRaises(relay.RelayError):
                    relay.build_closed_verdict(
                        template, changed_fixture, transcript, receipt, evidence_reads,
                    )

    def test_close_rejects_resigned_evidence_references_at_a_different_origin(self) -> None:
        template, fixture, transcript_raw, receipt, evidence_reads = protocol_close_inputs()
        transcript = json.loads(transcript_raw)
        authority = relay.validate_acceptance_template(template, label="candidate")
        changed = 0
        replacements: dict[str, str] = {}
        for record in transcript["events"]:
            event = record["event"]
            if event["kind"] not in {relay.KIND_CI_LOG_REFERENCE, relay.KIND_CI_ARTIFACT_REFERENCE}:
                continue
            content = json.loads(event["content"])
            if content.get("run_id") != authority["run_id"]:
                continue
            url = content.get("url")
            if not isinstance(url, str):
                continue
            content["url"] = url.replace(relay.EXPORT_ORIGIN, "https://wrong.invalid")
            replacement = signed_event(
                CI_EVENT, event["kind"], event["tags"],
                json.dumps(content, separators=(",", ":")), event["created_at"],
            )
            record["event"] = replacement
            replacements[event["id"]] = replacement["id"]
            changed += 1
        self.assertEqual(changed, 2)
        for record in transcript["events"]:
            event = record["event"]
            if event["kind"] not in {relay.KIND_CI_JOB_STATUS, relay.KIND_CI_EVIDENCE_FINALIZED}:
                continue
            content = json.loads(event["content"])
            altered = False
            if content.get("log_ref") in replacements:
                content["log_ref"] = replacements[content["log_ref"]]
                altered = True
            if isinstance(content.get("artifact_refs"), list):
                replaced = [replacements.get(identifier, identifier) for identifier in content["artifact_refs"]]
                altered = altered or replaced != content["artifact_refs"]
                content["artifact_refs"] = replaced
            attempts = content.get("finalized_job_attempts")
            if isinstance(attempts, list):
                for attempt in attempts:
                    if not isinstance(attempt, dict):
                        continue
                    if attempt.get("log_ref") in replacements:
                        attempt["log_ref"] = replacements[attempt["log_ref"]]
                        altered = True
                    if isinstance(attempt.get("artifact_refs"), list):
                        replaced = [replacements.get(identifier, identifier) for identifier in attempt["artifact_refs"]]
                        altered = altered or replaced != attempt["artifact_refs"]
                        attempt["artifact_refs"] = replaced
            if altered:
                record["event"] = signed_event(
                    CI_EVENT, event["kind"], event["tags"],
                    json.dumps(content, separators=(",", ":")), event["created_at"],
                )
        transcript["sealed_projection_sha256"] = hashlib.sha256(
            relay.canonical_json(transcript["events"]),
        ).hexdigest()
        with self.assertRaisesRegex(relay.RelayError, "read URL differs"):
            relay.build_closed_verdict(
                template, fixture, relay.canonical_json(transcript) + b"\n", receipt, evidence_reads,
            )

    def test_export_attempt_id_is_exactly_32_lowercase_hex(self) -> None:
        template, fixture, transcript_raw, receipt_raw, evidence_reads = protocol_close_inputs()
        good = relay.build_closed_verdict(template, fixture, transcript_raw, receipt_raw, evidence_reads)
        self.assertEqual(len(good["receipt"]["export_attempt_id"]), 32)
        for bad in ("a" * 31, "a" * 33, "a" * 64, "A" * 32):
            with self.subTest(source="verdict", bad=bad):
                changed = copy.deepcopy(good)
                changed["receipt"]["export_attempt_id"] = bad
                with self.assertRaises(relay.RelayError):
                    relay.validate_closed_verdict(changed)
            with self.subTest(source="receipt", bad=bad):
                changed_receipt = json.loads(receipt_raw)
                for index in (5, 6):
                    changed_receipt["checks"][index]["snapshot"]["run"]["attempts"][0]["attempt_id"] = bad
                changed_receipt["checks"][6]["export"]["attempt_id"] = bad
                with self.assertRaisesRegex(relay.RelayError, "authenticated export binding rejected"):
                    relay.build_closed_verdict(
                        template, fixture, transcript_raw,
                        relay.canonical_json(changed_receipt) + b"\n",
                        evidence_reads,
                    )

    def test_exact_binding_rejects_valid_hex_substitutions_at_transfer_and_construction_readback(self) -> None:
        template, fixture, transcript_raw, receipt_raw, evidence_reads = protocol_close_inputs()
        binding = {
            "schema_version": guest.PROTOCOL_INPUT_SCHEMA,
            "acceptance_template": template, "prior_acceptance_template": None,
            "transcript_base64": base64.b64encode(transcript_raw).decode(),
            "evidence_reads_base64": base64.b64encode(evidence_reads).decode(),
            "foreign_pending_event_id": None, "fault_mode": None,
        }
        good = guest.recompute_protocol_verdict(binding, fixture, receipt_raw)
        self.assertEqual(
            guest.validate_bound_protocol_verdict(good, binding, fixture, receipt_raw), good,
        )
        for name, changed in valid_closed_verdict_substitutions(good):
            with self.subTest(reader="transfer", field=name):
                relay.validate_closed_verdict(changed)
                with self.assertRaisesRegex(guest.GuestError, "binding differs"):
                    guest.validate_bound_protocol_verdict(changed, binding, fixture, receipt_raw)

        for name, changed in valid_closed_verdict_substitutions(good):
            with self.subTest(reader="construction", field=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                transcript_path = root / "protocol-transcript.json"
                reads_path = root / "evidence-reads.json"
                verdict_path = root / "protocol-verdict.json"
                transcript_path.write_bytes(transcript_raw)
                reads_path.write_bytes(evidence_reads)

                def publish(_path: Path, _raw: bytes, _mode: int, changed=changed) -> None:
                    verdict_path.write_bytes(guest.canonical(changed))

                with mock.patch.object(guest, "PROTOCOL_TRANSCRIPT", transcript_path), mock.patch.object(
                    guest, "EVIDENCE_READS", reads_path,
                ), mock.patch.object(
                    guest, "PROTOCOL_VERDICT", verdict_path,
                ), mock.patch.object(guest, "publish_atomic_create_once", side_effect=publish):
                    with self.assertRaisesRegex(guest.GuestError, "did not close"):
                        guest.close_relay_protocol_verdict(
                            {"acceptance_template": template}, {"fixture": fixture}, receipt_raw, None,
                        )

    def test_transfer_recomputation_requires_current_candidate_failure_selector(self) -> None:
        template, fixture, transcript_raw, receipt_raw, evidence_reads = protocol_close_inputs()
        binding = {
            "schema_version": guest.PROTOCOL_INPUT_SCHEMA,
            "acceptance_template": template, "prior_acceptance_template": None,
            "transcript_base64": base64.b64encode(transcript_raw).decode(),
            "evidence_reads_base64": base64.b64encode(evidence_reads).decode(),
            "foreign_pending_event_id": None, "fault_mode": None,
        }
        omitted = copy.deepcopy(binding)
        omitted["acceptance_template"].pop("failure_selector")
        with self.assertRaisesRegex(ValueError, "template shape rejected"):
            relay.validate_acceptance_template(omitted["acceptance_template"], label="candidate")
        with self.assertRaisesRegex(ValueError, "template shape rejected"):
            relay.build_closed_verdict(
                omitted["acceptance_template"], fixture, transcript_raw, receipt_raw, evidence_reads,
            )
        with self.assertRaisesRegex(guest.GuestError, "protocol close input binding differs"):
            guest.recompute_protocol_verdict(omitted, fixture, receipt_raw)

    def test_transfer_recomputation_rejects_internally_valid_selector_that_differs_from_fixture(self) -> None:
        template, fixture, transcript_raw, receipt_raw, evidence_reads = protocol_close_inputs()
        changed_template = copy.deepcopy(template)
        failure = json.loads(changed_template["failure_run_event"][5])
        failure["job_ids"] = ["other-capacity-one-fixture"]
        changed_template["failure_run_event"][5] = json.dumps(failure, separators=(",", ":"))
        changed_template["failure_selector"] = failure_selector(changed_template)
        self.assertEqual(
            relay.validate_acceptance_template(changed_template, label="internally-valid")["failure_selector"],
            changed_template["failure_selector"],
        )
        binding = {
            "schema_version": guest.PROTOCOL_INPUT_SCHEMA,
            "acceptance_template": changed_template, "prior_acceptance_template": None,
            "transcript_base64": base64.b64encode(transcript_raw).decode(),
            "evidence_reads_base64": base64.b64encode(evidence_reads).decode(),
            "foreign_pending_event_id": None, "fault_mode": None,
        }
        with self.assertRaisesRegex(relay.RelayError, "failure selector differs"):
            relay.build_closed_verdict(
                changed_template, fixture, transcript_raw, receipt_raw, evidence_reads,
            )
        with self.assertRaisesRegex(guest.GuestError, "protocol close input binding differs"):
            guest.recompute_protocol_verdict(binding, fixture, receipt_raw)

    def test_shared_closed_verdict_validator_rejects_nested_mutation_matrix(self) -> None:
        template, fixture, transcript, receipt, evidence_reads = protocol_close_inputs()
        good = relay.build_closed_verdict(template, fixture, transcript, receipt, evidence_reads)
        relay.validate_closed_verdict(good)
        mutations = []
        for index in range(5):
            mutations.append((f"actor-id-{index}", lambda value, index=index: value["actor_event_ids"]["api_order"].__setitem__(index, "z" * 64)))
        mutations.extend((
            ("live-order", lambda value: value["actor_event_ids"]["live_order"].reverse()),
            ("observed-order", lambda value: value["observed_actor_event_ids"].reverse()),
            ("run-a-id", lambda value: value["run_ids"].__setitem__("run_a", value["run_ids"]["run_b"])),
            ("selected-attempt", lambda value: value["run_a"]["selected_job_attempts"][0].__setitem__("attempt", 2)),
            ("selected-artifact", lambda value: value["run_a"].__setitem__("artifact_event_ids", [])),
            ("rerun-request", lambda value: value["run_b"].__setitem__("rerun_request_event_id", "f" * 64)),
            ("tombstone", lambda value: value["run_b"].__setitem__("tombstone_event_id", "f" * 64)),
            ("run-b-final-fact", lambda value: value["run_b"].__setitem__("final_fact_count", 1)),
            ("forged-seal", lambda value: value.__setitem__("sealed", False)),
            ("seal-digest", lambda value: value.__setitem__("sealed_projection_sha256", "short")),
            ("checks", lambda value: value["receipt"].__setitem__("checks", 15)),
            ("phases", lambda value: value["receipt"].__setitem__("zero_phases", [17])),
            ("export-request", lambda value: value["receipt"].__setitem__("export_request_digest", "short")),
            ("export-attempt", lambda value: value["receipt"].__setitem__("export_attempt_id", "short")),
            ("missing-nested", lambda value: value["run_a"].pop("terminal_event_id")),
            ("extra-nested", lambda value: value["run_b"].__setitem__("extra", True)),
        ))
        for name, mutate in mutations:
            with self.subTest(name=name):
                broken = copy.deepcopy(good)
                mutate(broken)
                with self.assertRaises(relay.RelayError):
                    relay.validate_closed_verdict(broken)

    def test_protocol_verdict_publish_is_complete_create_once_and_directory_durable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "protocol-verdict.json"
            guest.publish_atomic_create_once(path, b"first\n", 0o400)
            self.assertEqual(path.read_bytes(), b"first\n")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
            with self.assertRaises(FileExistsError):
                guest.publish_atomic_create_once(path, b"second\n", 0o400)
            self.assertEqual(path.read_bytes(), b"first\n")
            self.assertEqual([item.name for item in path.parent.iterdir()], [path.name])

    def test_prior_replay_exception_requires_exact_prefix_mode_and_one_named_terminal(self) -> None:
        template, fixture, transcript_raw, receipt, evidence_reads = protocol_close_inputs()
        prior = acceptance_template(
            now=1_800_001_000, run_id="123e4567-e89b-12d3-a456-426614174021",
            failure_run_id="123e4567-e89b-12d3-a456-426614174022",
        )
        prior_authority = relay.validate_acceptance_template(prior, label="prior")
        transcript = json.loads(transcript_raw)
        transcript["foreign_pending_event_ids"] = prior_authority["live_ids"][:2]
        foreign_event = signed_event(
            CI_EVENT, 46101, [["h", CHANNEL], ["run", prior_authority["run_id"]]],
            json.dumps({
                "relay_signer": public_hex(CI_EVENT), "target_repo_a": REPOSITORY,
                "run_id": prior_authority["run_id"],
                "request_event_id": prior_authority["api_ids"][0],
                "attempt": 1, "state": "success",
            }, separators=(",", ":")), 1_800_001_900,
        )
        transcript["foreign_pending_event"] = foreign_event
        transcript_raw = relay.canonical_json(transcript) + b"\n"
        foreign = foreign_event["id"]
        verdict = relay.build_closed_verdict(
            template, fixture, transcript_raw, receipt, evidence_reads,
            foreign_pending_event_id=foreign, prior_acceptance_template=prior,
            fault_mode=relay.FAULT_REPLAY_BEFORE_GRANT,
        )
        self.assertEqual(verdict["foreign_pending_event_id"], foreign)
        for name, kwargs in (
            ("missing-mode", {"foreign_pending_event_id": foreign, "prior_acceptance_template": prior}),
            ("missing-id", {"prior_acceptance_template": prior, "fault_mode": relay.FAULT_REPLAY_BEFORE_GRANT}),
            ("wrong-prior", {"foreign_pending_event_id": foreign, "prior_acceptance_template": acceptance_template(now=1_800_002_000, run_id="123e4567-e89b-12d3-a456-426614174031", failure_run_id="123e4567-e89b-12d3-a456-426614174032"), "fault_mode": relay.FAULT_REPLAY_BEFORE_GRANT}),
        ):
            with self.subTest(name=name), self.assertRaises(relay.RelayError):
                relay.build_closed_verdict(template, fixture, transcript_raw, receipt, evidence_reads, **kwargs)

        for name, mutate in (
            ("wrong-id", lambda value: value["foreign_pending_event"].__setitem__("id", "9" * 64)),
            ("wrong-state", lambda value: value["foreign_pending_event"].__setitem__("content", value["foreign_pending_event"]["content"].replace('"success"', '"failure"'))),
            ("missing-event", lambda value: value.__setitem__("foreign_pending_event", None)),
            ("extra-event-standard", lambda value: value.__setitem__("foreign_pending_event_ids", [])),
        ):
            with self.subTest(name=name):
                changed = json.loads(transcript_raw)
                mutate(changed)
                kwargs = {} if name == "extra-event-standard" else {
                    "foreign_pending_event_id": foreign,
                    "prior_acceptance_template": prior,
                    "fault_mode": relay.FAULT_REPLAY_BEFORE_GRANT,
                }
                with self.assertRaises(relay.RelayError):
                    relay.build_closed_verdict(
                        template, fixture, relay.canonical_json(changed) + b"\n", receipt,
                        evidence_reads, **kwargs,
                    )

    def test_close_rejects_run_a_only_receipt_echo_and_every_mutated_required_field(self) -> None:
        template, fixture, transcript_raw, receipt_raw, evidence_reads = protocol_close_inputs()
        transcript = json.loads(transcript_raw)
        receipt = json.loads(receipt_raw)
        run_b = relay.validate_acceptance_template(template, label="test")["failure_run_id"]
        run_a_only = copy.deepcopy(transcript)
        run_a_only["events"] = [
            record for record in run_a_only["events"]
            if record["event"]["id"] not in set(run_a_only["actor_event_ids"]["live_order"][2:])
            and (record["event"]["kind"] == 5 or relay._content(record).get("run_id") != run_b)
        ]
        run_a_only["observed_actor_event_ids"] = run_a_only["actor_event_ids"]["live_order"][:2]
        run_a_only["sealed"] = False
        run_a_only["sealed_projection_sha256"] = None
        cases = {
            "run-a-only": (run_a_only, receipt),
            "missing-terminal-fact": ({**transcript, "events": [record for record in transcript["events"] if record["event"]["kind"] != 46106]}, receipt),
            "fixture-only-export": (transcript, {**receipt, "checks": [{key: value for key, value in item.items() if key != "export"} for item in receipt["checks"]]}),
            "missing-phase-18": (transcript, {**receipt, "zero_transition": {"phases": receipt["zero_transition"]["phases"][:1]}}),
        }
        for name, (changed_transcript, changed_receipt) in cases.items():
            with self.subTest(name=name), self.assertRaises((relay.RelayError, relay.Refusal)):
                relay.build_closed_verdict(
                    template, fixture,
                    relay.canonical_json(changed_transcript) + b"\n",
                    relay.canonical_json(changed_receipt) + b"\n",
                    evidence_reads,
                )

    def test_close_rejects_signed_transcript_graph_order_and_cardinality_mutations(self) -> None:
        template, fixture, transcript_raw, receipt_raw, evidence_reads = protocol_close_inputs()
        authority = relay.validate_acceptance_template(template, label="test")

        def content(record: dict[str, object]) -> dict[str, object]:
            return json.loads(record["event"]["content"])

        def find_record(
            transcript: dict[str, object], kind: int, run_id: str, *,
            state: str | None = None, request_id: str | None = None,
        ) -> dict[str, object]:
            for record in transcript["events"]:
                event = record["event"]
                if event["kind"] != kind:
                    continue
                body = content(record)
                if body.get("run_id") != run_id or state is not None and body.get("state") != state:
                    continue
                if request_id is None or body.get("request_event_id") == request_id:
                    return record
            raise AssertionError("test transcript record not found")

        def resign(record: dict[str, object], **changes: object) -> None:
            event = record["event"]
            body = content(record)
            body.update(changes)
            record["event"] = signed_event(
                CI_EVENT, event["kind"], event["tags"],
                json.dumps(body, separators=(",", ":")), event["created_at"],
            )

        def run_b_missing_running(value: dict[str, object]) -> None:
            target = find_record(value, 46101, authority["failure_run_id"], state="running", request_id=authority["api_ids"][4])
            value["events"].remove(target)

        def duplicate_run_a_log(value: dict[str, object]) -> None:
            value["events"].append(copy.deepcopy(find_record(value, 46103, authority["run_id"])))

        def wrong_failure_log(value: dict[str, object]) -> None:
            resign(find_record(value, 46103, authority["failure_run_id"]), log_sha256="0" * 64)

        def wrong_cancel(value: dict[str, object]) -> None:
            resign(find_record(value, 46102, authority["failure_run_id"], state="cancelled", request_id=authority["api_ids"][2]), state="success")

        def run_b_final_fact(value: dict[str, object]) -> None:
            body = {
                "relay_signer": public_hex(CI_EVENT), "target_repo_a": REPOSITORY,
                "run_id": authority["failure_run_id"], "request_event_id": authority["api_ids"][4],
                "attempt": 1, "finalized_job_attempts": [],
            }
            value["events"].append(signed_event(
                CI_EVENT, 46105, [["h", CHANNEL], ["run", authority["failure_run_id"]]],
                json.dumps(body, separators=(",", ":")), 1_800_000_900,
            ))

        def wrong_selected_graph(value: dict[str, object]) -> None:
            resign(find_record(value, 46105, authority["run_id"]), finalized_job_attempts=[])

        def stale_final_request(value: dict[str, object]) -> None:
            resign(find_record(value, 46106, authority["run_id"]), request_event_id=authority["api_ids"][4])

        def wrong_evidence_attempt(value: dict[str, object]) -> None:
            resign(find_record(value, 46105, authority["run_id"]), attempt=2)

        def wrong_teardown_attempt(value: dict[str, object]) -> None:
            resign(find_record(value, 46106, authority["run_id"]), attempt=2)

        def missing_run_context(value: dict[str, object]) -> None:
            record = find_record(
                value, 46101, authority["failure_run_id"], state="failure",
                request_id=authority["api_ids"][4],
            )
            event = record["event"]
            body = content(record)
            body.pop("workflow_id")
            record["event"] = signed_event(
                CI_EVENT, event["kind"], event["tags"],
                json.dumps(body, separators=(",", ":")), event["created_at"],
            )

        def evidence_before_successful_job(value: dict[str, object]) -> None:
            success = find_record(
                value, 46102, authority["run_id"], state="success",
                request_id=authority["api_ids"][0],
            )
            evidence = find_record(value, 46105, authority["run_id"])
            value["events"].remove(success)
            value["events"].insert(value["events"].index(evidence) + 1, success)

        def tombstone_before_cancel(value: dict[str, object]) -> None:
            tombstone = next(record for record in value["events"] if record["event"]["id"] == authority["api_ids"][3])
            cancel = find_record(value, 46101, authority["failure_run_id"], state="cancelled", request_id=authority["api_ids"][2])
            value["events"].remove(tombstone)
            value["events"].insert(value["events"].index(cancel), tombstone)

        def tombstone_before_job_cancel(value: dict[str, object]) -> None:
            tombstone = next(record for record in value["events"] if record["event"]["id"] == authority["api_ids"][3])
            run_cancel = find_record(
                value, 46101, authority["failure_run_id"], state="cancelled",
                request_id=authority["api_ids"][2],
            )
            job_cancel = find_record(
                value, 46102, authority["failure_run_id"], state="cancelled",
                request_id=authority["api_ids"][2],
            )
            value["events"].remove(run_cancel)
            value["events"].remove(tombstone)
            index = value["events"].index(job_cancel)
            value["events"].insert(index, run_cancel)
            value["events"].insert(index + 1, tombstone)

        def unknown_signed_event(value: dict[str, object]) -> None:
            body = {
                "relay_signer": public_hex(CI_EVENT), "target_repo_a": REPOSITORY,
                "run_id": authority["run_id"], "request_event_id": authority["api_ids"][0],
                "attempt": 1,
            }
            value["events"].append(signed_event(
                CI_EVENT, 46999, [["h", CHANNEL], ["run", authority["run_id"]]],
                json.dumps(body, separators=(",", ":")), 1_800_000_901,
            ))

        def bad_signature(value: dict[str, object]) -> None:
            signature = value["events"][3]["event"]["sig"]
            value["events"][3]["event"]["sig"] = signature[:-1] + ("0" if signature[-1] != "0" else "1")

        mutations = (
            ("signature", bad_signature),
            ("missing-run-b-running", run_b_missing_running),
            ("duplicate-log", duplicate_run_a_log),
            ("failure-log", wrong_failure_log),
            ("cancel-state", wrong_cancel),
            ("run-b-final-fact", run_b_final_fact),
            ("selected-evidence", wrong_selected_graph),
            ("stale-final-request", stale_final_request),
            ("evidence-attempt", wrong_evidence_attempt),
            ("teardown-attempt", wrong_teardown_attempt),
            ("run-b-run-schema", lambda value: resign(find_record(value, 46101, authority["failure_run_id"], state="failure", request_id=authority["api_ids"][4]), schema_version=2)),
            ("run-b-job-schema", lambda value: resign(find_record(value, 46102, authority["failure_run_id"], state="failure", request_id=authority["api_ids"][4]), schema_version=2)),
            ("evidence-schema", lambda value: resign(find_record(value, 46105, authority["run_id"]), schema_version=2)),
            ("teardown-schema", lambda value: resign(find_record(value, 46106, authority["run_id"]), schema_version=2)),
            ("missing-run-context", missing_run_context),
            ("evidence-before-job-success", evidence_before_successful_job),
            ("tombstone-order", tombstone_before_cancel),
            ("tombstone-before-job-cancel", tombstone_before_job_cancel),
            ("unknown-signed-event", unknown_signed_event),
        )
        for name, mutate in mutations:
            with self.subTest(name=name):
                changed = json.loads(transcript_raw)
                mutate(changed)
                for cursor, record in enumerate(changed["events"], 1):
                    record["cursor"] = cursor
                changed["sealed_projection_sha256"] = hashlib.sha256(relay.canonical_json(changed["events"])).hexdigest()
                with self.assertRaises(relay.RelayError):
                    relay.build_closed_verdict(
                        template, fixture, relay.canonical_json(changed) + b"\n", receipt_raw,
                        evidence_reads,
                    )

    def test_template_ids_are_exact_unique_and_unknown_sixth_actor_event_is_refused(self) -> None:
        template = acceptance_template()
        fixture = acceptance_fixture(template)
        config = guest.relay_public_config({
            "relay_http_origin": "https://relay.test.invalid:3443",
            "acceptance_actor": template["actor"],
            "keyholder_public_spec": {"selectors": {
                "ci_event": {"public_key": public_hex(CI_EVENT), "generation": 1},
                "nip98": {"public_key": public_hex(NIP98), "generation": 1},
                "manifest": {"public_key": public_hex(3), "generation": 1},
            }},
        }, CHANNEL, template, fixture, None)
        state = relay.state_from_config(config, Path(self.relay_temporary.name) / "objects")
        authority = state.candidate_acceptance
        self.assertEqual(len(set(authority["api_ids"])), 5)
        run = signed_event(ACTOR, template["run_event"][3], template["run_event"][4], template["run_event"][5], template["run_event"][2])
        self.assertEqual(relay.admit_event(state, public_hex(ACTOR), run, self.now), (CHANNEL, True))
        unknown = request_event(ACTOR, self.now, run_id="123e4567-e89b-12d3-a456-426614174013")
        before = copy.deepcopy(state.events)
        with self.assertRaisesRegex(relay.Refusal, "unknown acceptance actor event"):
            relay.admit_event(state, public_hex(ACTOR), unknown, self.now)
        self.assertEqual(state.events, before)

    def test_failure_selector_is_exactly_bound_to_run_b_job_attempt_and_digest(self) -> None:
        template = acceptance_template()
        failure = json.loads(template["failure_run_event"][5])
        selector = {
            "schema_version": "buzz-ci-capacity-one-fixture-selector/v1",
            "selector": "deterministic-failure", "job_id": failure["job_ids"][0],
            "run_id": failure["run_id"], "attempt": 1,
        }
        preimage = (
            "buzz-ci:capacity-one:fixture-selector:v1\n"
            f"{selector['schema_version']}\n{selector['selector']}\n{selector['job_id']}\n"
            f"{selector['run_id'].replace('-', '')}\n1\n"
        ).encode()
        selector["sha256"] = hashlib.sha256(preimage).hexdigest()
        template["failure_selector"] = selector
        self.assertEqual(
            relay.validate_acceptance_template(template, label="test")["failure_selector"], selector,
        )
        for field, value in (("job_id", "other"), ("run_id", RUN_ID), ("attempt", 2), ("sha256", "f" * 64)):
            broken = copy.deepcopy(template)
            broken["failure_selector"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                relay.validate_acceptance_template(broken, label="test")
        reordered = copy.deepcopy(template)
        reordered["failure_selector"] = {
            name: reordered["failure_selector"][name]
            for name in ("selector", "schema_version", "job_id", "run_id", "attempt", "sha256")
        }
        with self.assertRaises(ValueError):
            relay.validate_acceptance_template(reordered, label="test")

    def test_stale_final_fact_and_post_seal_status_refuse_without_mutation(self) -> None:
        template = acceptance_template()
        fixture = acceptance_fixture(template)
        config = guest.relay_public_config({
            "relay_http_origin": "https://relay.test.invalid:3443", "acceptance_actor": template["actor"],
            "keyholder_public_spec": {"selectors": {
                "ci_event": {"public_key": public_hex(CI_EVENT), "generation": 1},
                "nip98": {"public_key": public_hex(NIP98), "generation": 1},
                "manifest": {"public_key": public_hex(3), "generation": 1},
            }},
        }, CHANNEL, template, fixture, None)
        state = relay.state_from_config(config, Path(self.relay_temporary.name) / "objects")
        run = signed_event(ACTOR, template["run_event"][3], template["run_event"][4], template["run_event"][5], template["run_event"][2])
        grant = signed_event(ACTOR, template["grant_event"][3], template["grant_event"][4], template["grant_event"][5], template["grant_event"][2])
        relay.admit_event(state, public_hex(ACTOR), run, self.now)
        relay.admit_event(state, public_hex(ACTOR), grant, self.now + 1)
        fake_latest = copy.deepcopy(run)
        fake_latest["id"] = "f" * 64
        state.events[fake_latest["id"]] = fake_latest
        state.run_requests[(CHANNEL, RUN_ID)][2] = fake_latest["id"]
        stale = ci_fact_event(CI_EVENT, 46105, self.now + 2, {
            "request_event_id": run["id"], "attempt": 1,
        })
        before = (
            copy.deepcopy(state.events), copy.deepcopy(state.run_events),
            copy.deepcopy(state.final_facts), list(state.transcript_events),
        )
        with self.assertRaisesRegex(relay.Refusal, "latest request"):
            relay.admit_event(state, public_hex(CI_EVENT), stale, self.now + 2)
        self.assertEqual((state.events, state.run_events, state.final_facts, state.transcript_events), before)
        state.run_requests[(CHANNEL, RUN_ID)].pop(2)
        state.events.pop(fake_latest["id"])
        state.candidate_sealed = True
        late = status_event(CI_EVENT, self.now + 3, state="running")
        late_content = json.loads(late["content"])
        late_content.update({"request_event_id": run["id"], "attempt": 1})
        late = signed_event(CI_EVENT, 46101, late["tags"], json.dumps(late_content, separators=(",", ":")), self.now + 3)
        before = copy.deepcopy(state.events)
        with self.assertRaisesRegex(relay.Refusal, "sealed acceptance transcript"):
            relay.admit_event(state, public_hex(CI_EVENT), late, self.now + 3)
        self.assertEqual(state.events, before)
        post_seal_rerun = request_event(ACTOR, self.now + 4, attempt=3)
        before = (
            copy.deepcopy(state.events), copy.deepcopy(state.run_requests),
            list(state.transcript_events), list(state.observed_actor_event_ids),
        )
        with self.assertRaisesRegex(relay.Refusal, "unknown acceptance actor event"):
            relay.admit_event(state, public_hex(ACTOR), post_seal_rerun, self.now + 4)
        self.assertEqual((
            state.events, state.run_requests, state.transcript_events, state.observed_actor_event_ids,
        ), before)


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

    def test_guest_cannot_close_without_the_sealed_transcript_and_validated_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            template = acceptance_template()
            fixture = acceptance_fixture(template)
            with mock.patch.object(guest, "PROTOCOL_TRANSCRIPT", root / "missing-transcript.json"), mock.patch.object(
                guest, "PROTOCOL_VERDICT", root / "protocol-verdict.json",
            ):
                with self.assertRaisesRegex(guest.GuestError, "did not close"):
                    guest.close_relay_protocol_verdict(
                        {"acceptance_template": template}, {"fixture": fixture}, b"{}\n", None,
                    )
            self.assertFalse((root / "protocol-verdict.json").exists())

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
                    (lambda value: value.__setitem__("deferred_publications", ["9" * 64 + ":run:terminal"]), "still defers"),
                ):
                    broken = copy.deepcopy(good)
                    mutate(broken)
                    snapshot.write_bytes(guest.canonical(broken))
                    with self.assertRaisesRegex(guest.GuestError, message):
                        guest.prove_relay_fault_recovery("stale-terminal-publication-recovery")

    def test_guest_replay_fault_proofs_require_expiry_refusal_read_back_and_the_replayed_terminal(self) -> None:
        mode = "stale-terminal-replay-before-grant"

        def signed(event_id: str) -> dict[str, object]:
            return {"event_id": event_id, "kind": 46101, "content": "{}", "tags": [], "signed_event": {"id": event_id}}

        def accepted(event_id: str) -> dict[str, object]:
            return {"Accepted": {"signed": signed(event_id), "relay_event_id": event_id}}

        first, resigned, replayed = "a" * 64, "b" * 64, "c" * 64
        after_prior = {
            "mode": mode, "grants_expired_at": 1_800_000_002, "refused_event_ids": [first, resigned],
            "queried_event_ids": [first], "replayed_event_id": None,
        }
        # A re-sign within the same second keeps the id, so the prior canary's
        # two refusals and the candidate's exact retry can share one id.
        after_candidate = {
            **after_prior, "refused_event_ids": [first, first, first, replayed],
            "queried_event_ids": [first], "replayed_event_id": replayed,
        }
        pending_snapshot = {"schema_version": 1, "cursors": {}, "runs": {}, "finalizations": {}, "publications": {
            "9" * 64 + ":run:queued": accepted("3" * 64),
            "9" * 64 + ":run:terminal": {"Pending": signed(resigned)},
        }}
        settled_snapshot = {"schema_version": 1, "cursors": {}, "runs": {}, "finalizations": {}, "publications": {
            "9" * 64 + ":run:terminal": accepted(replayed),
            "8" * 64 + ":run:terminal": accepted("5" * 64),
            "7" * 64 + ":run:terminal": accepted("6" * 64),
        }}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = root / "control-store-v1.json"
            record = root / "fault-fired.json"
            with mock.patch.object(guest, "RELAY_ROOT", root), mock.patch.object(guest, "CONTROLD_SNAPSHOT", snapshot):
                with self.assertRaisesRegex(guest.GuestError, "did not fire"):
                    guest.prove_stale_terminal_left_pending()
                record.write_bytes(guest.canonical(after_prior))
                snapshot.write_bytes(guest.canonical(pending_snapshot))
                guest.prove_stale_terminal_left_pending()
                for mutate_record, message in (
                    (lambda value: value.__setitem__("replayed_event_id", replayed), "not refused and read back"),
                    (lambda value: value.__setitem__("queried_event_ids", []), "not refused and read back"),
                    (lambda value: value.__setitem__("refused_event_ids", []), "grant expiry was not recorded"),
                    (lambda value: value.__setitem__("queried_event_ids", ["d" * 64]), "grant expiry was not recorded"),
                    (lambda value: value.__setitem__("grants_expired_at", None), "grant expiry was not recorded"),
                    (lambda value: value.__setitem__("mode", "stale-terminal-publication-recovery"), "grant expiry was not recorded"),
                    (lambda value: value.pop("queried_event_ids"), "grant expiry was not recorded"),
                ):
                    broken = copy.deepcopy(after_prior)
                    mutate_record(broken)
                    record.write_bytes(guest.canonical(broken))
                    with self.assertRaisesRegex(guest.GuestError, message):
                        guest.prove_stale_terminal_left_pending()
                record.write_bytes(guest.canonical(after_prior))
                for mutate_snapshot, message in (
                    (lambda value: value["publications"].__setitem__("8" * 64 + ":run:terminal", {"Pending": signed(first)}), "unexpected terminal publication state"),
                    (lambda value: value.__setitem__("deferred_publications", ["9" * 64 + ":run:terminal"]), "unexpected terminal publication state"),
                    (lambda value: value["publications"].__setitem__("9" * 64 + ":run:terminal", {"Pending": signed(first)}), "not the pending refused event"),
                    (lambda value: value["publications"].__setitem__("9" * 64 + ":run:terminal", accepted(resigned)), "not the pending refused event"),
                ):
                    broken = copy.deepcopy(pending_snapshot)
                    mutate_snapshot(broken)
                    snapshot.write_bytes(guest.canonical(broken))
                    with self.assertRaisesRegex(guest.GuestError, message):
                        guest.prove_stale_terminal_left_pending()

                # After the candidate canary: the replay record and a settled snapshot.
                record.write_bytes(guest.canonical(after_candidate))
                snapshot.write_bytes(guest.canonical(settled_snapshot))
                guest.prove_relay_fault_recovery(mode)
                for mutate_record, message in (
                    (lambda value: value.__setitem__("replayed_event_id", None), "not replayed after the grant"),
                    (lambda value: value.__setitem__("replayed_event_id", resigned), "not replayed after the grant"),
                    (lambda value: value.__setitem__("refused_event_ids", [first, first, replayed, first]), "not replayed after the grant"),
                    (lambda value: value.__setitem__("refused_event_ids", [first, replayed]), "not replayed after the grant"),
                    (lambda value: value.__setitem__("queried_event_ids", []), "not replayed after the grant"),
                ):
                    broken = copy.deepcopy(after_candidate)
                    mutate_record(broken)
                    record.write_bytes(guest.canonical(broken))
                    with self.assertRaisesRegex(guest.GuestError, message):
                        guest.prove_relay_fault_recovery(mode)
                record.write_bytes(guest.canonical(after_candidate))
                for mutate_snapshot, message in (
                    (lambda value: value["publications"].__setitem__("9" * 64 + ":run:terminal", {"Pending": signed(replayed)}), "not accepted"),
                    (lambda value: value["publications"].__setitem__("9" * 64 + ":run:terminal", accepted("d" * 64)), "not the accepted one"),
                    (lambda value: value["publications"].pop("7" * 64 + ":run:terminal"), "not the accepted one"),
                    (lambda value: value.__setitem__("deferred_publications", ["9" * 64 + ":run:terminal"]), "still defers"),
                ):
                    broken = copy.deepcopy(settled_snapshot)
                    mutate_snapshot(broken)
                    snapshot.write_bytes(guest.canonical(broken))
                    with self.assertRaisesRegex(guest.GuestError, message):
                        guest.prove_relay_fault_recovery(mode)

    def test_guest_prior_canary_under_the_replay_fault_must_fail_and_leave_the_pending_terminal(self) -> None:
        def completed(returncode: int, stdout: bytes) -> subprocess.CompletedProcess[bytes]:
            return subprocess.CompletedProcess(["/usr/libexec/buzz-ci-capacity-one-canary"], returncode, stdout, b"")

        failed = guest.canonical({"outcome": "fail", "checks": []})
        with mock.patch.object(guest, "assert_live_acceptance_roles", return_value=(1203, 1203, [1201])), \
                mock.patch.object(guest, "prove_stale_terminal_left_pending") as proof, \
                mock.patch.object(guest, "command", return_value=completed(1, failed)) as command:
            guest.run_prior_canary_expecting_stale_terminal({}, b"scenario", {})
            proof.assert_called_once_with()
            self.assertEqual(command.call_args.args, (["/usr/libexec/buzz-ci-capacity-one-canary"],))
            keywords = command.call_args.kwargs
            self.assertEqual(keywords["stdin"], b"scenario")
            self.assertTrue(keywords["allow_failure"])
            self.assertFalse(keywords["inventory"], "the fault-only canary is outside the frozen command inventory")
            self.assertEqual(keywords["timeout"], guest.timing_leaf("driver_operation") + guest.timing_leaf("canary_orchestration_margin"))
            self.assertEqual((keywords["uid"], keywords["gid"], keywords["supplementary_gids"]), (1203, 1203, [1201]))
        for result, message in (
            (completed(0, guest.canonical({"outcome": "pass"})), "did not fail"),
            (completed(1, guest.canonical({"outcome": "pass"})), "did not fail"),
            (completed(2, failed), "did not fail"),
            (completed(1, b"not json"), "unreadable"),
        ):
            with mock.patch.object(guest, "assert_live_acceptance_roles", return_value=(1203, 1203, [1201])), \
                    mock.patch.object(guest, "prove_stale_terminal_left_pending") as proof, \
                    mock.patch.object(guest, "command", return_value=result):
                with self.assertRaisesRegex(guest.GuestError, message):
                    guest.run_prior_canary_expecting_stale_terminal({}, b"scenario", {})
                proof.assert_not_called()

    def test_run_accepts_only_known_relay_faults_and_hands_them_to_the_terminal_run(self) -> None:
        calls: list[tuple[object, ...]] = []
        with mock.patch.object(harness, "terminal_run", side_effect=lambda *arguments: calls.append(arguments) or {"status": "pass"}):
            self.assertEqual(set(harness.RELAY_FAULTS), relay.RELAY_FAULTS)
            self.assertEqual(guest.RELAY_FAULTS, relay.RELAY_FAULTS)
            for extra, expected in (
                ([], None),
                (["--relay-fault", "stale-terminal-publication-recovery"], "stale-terminal-publication-recovery"),
                (["--relay-fault", "stale-terminal-replay-before-grant"], "stale-terminal-replay-before-grant"),
            ):
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

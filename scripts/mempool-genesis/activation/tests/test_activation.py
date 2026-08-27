from __future__ import annotations

import contextlib
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ACTIVATION_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = ACTIVATION_DIR.parents[2]
TEST_ROOT = Path(os.environ.get("MGACT_TEST_ROOT", tempfile.gettempdir()))
TEST_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
TEST_ROOT.chmod(0o700)


def load_module(name: str, filename: str):
    path = ACTIVATION_DIR / filename
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


GENERATOR = load_module("mgact_generator_r3_normal", "generate-activation-bundle.py")
PREFLIGHT = load_module("mgact_preflight_r3_normal", "make-tier1-receipt.py")
INSTALLER = load_module("mgact_installer_r3_normal", "install-activation-bundle.py")

SYSTEM_SOURCES = {
    "/usr/local/libexec/buzz/run-buzz-agent": 0o755,
    "/usr/local/libexec/buzz/buzz-agent-key-handoff": 0o755,
    "/usr/local/libexec/buzz/export-managed-agent-key": 0o755,
    "/usr/local/sbin/buzz-install-agent-key": 0o755,
    "/usr/local/libexec/buzz/node": 0o755,
    "/usr/local/libexec/buzz/codex": 0o755,
    "/usr/local/libexec/buzz/codex-acp": 0o755,
    "/usr/local/libexec/buzz/codex-code-mode-host": 0o755,
    "/usr/local/libexec/buzz/buzz-acp": 0o755,
    "/usr/local/libexec/buzz/buzz-dev-mcp": 0o755,
    "/usr/lib/systemd/system/service.d/10-timeout-abort.conf": 0o644,
}
CLOSURE_TARGET = "/etc/buzz-agents/review-closure.json"
UNCHANGED_SNAPSHOT = {"fixture": {"exists": False}}


def current_artifact_owner() -> object:
    account = pwd.getpwuid(os.getuid())
    return INSTALLER.ArtifactOwner(os.getuid(), os.getgid(), account.pw_name, account.pw_dir)


def write_file(path: Path, payload: bytes, mode: int) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(payload)
    path.chmod(mode)


def write_private_json(path: Path, value: object) -> None:
    write_file(
        path,
        (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(),
        0o600,
    )


def create_system_sources(root: Path) -> None:
    for absolute, mode in SYSTEM_SOURCES.items():
        payload = f"fixture {absolute}\n".encode()
        if absolute == "/usr/local/libexec/buzz/codex-acp":
            payload = b"#!/usr/bin/env node\nconsole.log('fixture');\n"
        write_file(root / absolute.lstrip("/"), payload, mode)


def write_inputs(path: Path, mempool: str, genesis: str) -> None:
    write_private_json(
        path,
        {
            "schema": GENERATOR.INPUT_SCHEMA,
            "mempool_pubkey": mempool,
            "genesis_pubkey": genesis,
        },
    )


def tree_fingerprint(root: Path) -> str:
    records: list[str] = []
    for path in sorted(root.rglob("*"), key=lambda value: str(value.relative_to(root)).encode()):
        relative = path.relative_to(root)
        metadata = path.lstat()
        if path.is_dir():
            records.append(f"d\t{stat.S_IMODE(metadata.st_mode):04o}\t{relative}\n")
        else:
            records.append(
                f"f\t{stat.S_IMODE(metadata.st_mode):04o}\t"
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}\t{relative}\n"
            )
    return hashlib.sha256("".join(records).encode()).hexdigest()


def target_names(manifest: dict[str, object]) -> list[str]:
    return [
        str(record["target"])
        for record in list(manifest["runtime_targets"]) + list(manifest["ops_targets"])
    ] + [CLOSURE_TARGET]


def target_snapshot(root: Path, targets: list[str]) -> dict[str, tuple[int, int, int, int, str] | None]:
    result: dict[str, tuple[int, int, int, int, str] | None] = {}
    for target in targets:
        path = root / target.lstrip("/")
        if not os.path.lexists(path):
            result[target] = None
            continue
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            result[target] = (
                metadata.st_ino,
                metadata.st_mtime_ns,
                stat.S_IMODE(metadata.st_mode),
                metadata.st_size,
                "non-regular",
            )
            continue
        result[target] = (
            metadata.st_ino,
            metadata.st_mtime_ns,
            stat.S_IMODE(metadata.st_mode),
            metadata.st_size,
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )
    return result


def prepare_install_root(root: Path, manifest: dict[str, object]) -> None:
    for target in target_names(manifest):
        parent = (root / target.lstrip("/")).parent
        parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        current = root
        for part in parent.relative_to(root).parts:
            current = current / part
            current.chmod(0o755)


class PackageFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=TEST_ROOT)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.system_root = self.root / "system-source"
        self.system_root.mkdir(mode=0o700)
        create_system_sources(self.system_root)
        self.inputs = self.root / "inputs.json"
        write_inputs(self.inputs, "1" * 64, "2" * 64)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def generate(
        self,
        name: str = "bundle",
        *,
        inputs: Path | None = None,
        allow_placeholders: bool = False,
    ) -> tuple[Path, dict[str, object]]:
        output = self.root / name
        manifest = GENERATOR.generate(
            inputs or self.inputs,
            output,
            self.system_root,
            REPO_ROOT,
            allow_placeholders,
            False,
        )
        return output, manifest

    def evidence_path(self, name: str) -> Path:
        return self.root / f"{name}-tier2-evidence.json"

    def make_receipt(
        self,
        bundle: Path,
        name: str = "preflight",
    ) -> tuple[Path, dict[str, object]]:
        receipt_path = self.root / f"{name}-receipt.json"
        pass_results = [
            {"command": command, "exit": 0, "stdout": "ok\n", "stderr": ""}
            for command in PREFLIGHT.gate_commands(bundle)
        ]
        receipt = PREFLIGHT.generate_receipt(
            bundle,
            receipt_path,
            REPO_ROOT,
            tier2_bundle_output=self.evidence_path(name),
            command_results=pass_results,
            before_snapshot=UNCHANGED_SNAPSHOT,
            after_snapshot=UNCHANGED_SNAPSHOT,
        )
        return receipt_path, receipt

    def make_tier2(
        self,
        _bundle: Path,
        manifest: dict[str, object],
        name: str = "accepted",
        verdict: str = "PASS",
    ) -> tuple[Path, Path]:
        evidence_path = self.evidence_path(name)
        state_dir = self.root / f"{name}-tier2-state"
        engine = str(manifest["tier2_engine"]["path"])
        completed = subprocess.run(
            [
                sys.executable,
                engine,
                "prepare",
                "--bundle",
                str(evidence_path),
                "--producer-provider",
                "gpt",
                "--controller",
                "mgact-test-controller",
                "--state-dir",
                str(state_dir),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
            env={
                "HOME": str(Path.home()),
                "LC_ALL": "C",
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )
        if completed.returncode != 0:
            raise AssertionError(f"tier2 prepare failed: {completed.stderr}")
        state_path = Path(completed.stdout.strip())
        state = json.loads(state_path.read_text())
        reviewer_identity = str(state["route"]["reviewer_identity"])
        Path(str(state["token_path"])).unlink()
        state["status"] = "closed"
        state["verdict"] = {
            "verdict": verdict,
            "findings": (
                []
                if verdict == "PASS"
                else [
                    {
                        "severity": "LOW" if verdict == "PASS WITH RISKS" else "MEDIUM",
                        "description": "Synthetic bounded finding.",
                    }
                ]
            ),
            "evidence_gaps": [],
            "reviewer_identity": reviewer_identity,
        }
        write_private_json(state_path, state)
        return evidence_path, state_path

    def closed_package(
        self,
        name: str = "closed",
    ) -> tuple[Path, dict[str, object], Path, Path, Path]:
        bundle, manifest = self.generate(name)
        receipt, _receipt_value = self.make_receipt(bundle, name)
        evidence, state = self.make_tier2(bundle, manifest, name)
        return bundle, manifest, receipt, evidence, state


class ActivationBundleTests(PackageFixture):
    def test_generator_is_deterministic_and_emits_exact_review_inventory(self) -> None:
        first, manifest = self.generate("first")
        second, second_manifest = self.generate("second")
        self.assertEqual(manifest, second_manifest)
        self.assertEqual(tree_fingerprint(first), tree_fingerprint(second))
        self.assertTrue(manifest["ready_for_parent_tier1"])
        self.assertFalse(manifest["installable"])
        self.assertEqual(len(manifest["runtime_targets"]), 24)
        for slug in ("mempool", "genesis"):
            self.assertEqual(len(manifest["review_files"][slug]), 21)
            self.assertEqual(
                [entry["path"] for entry in manifest["review_files"][slug]],
                manifest["expected_closure_paths"][slug],
            )
        self.assertEqual(manifest["tier2_review"], GENERATOR.TIER2_REVIEW)
        self.assertEqual(
            manifest["tier2_review"],
            {
                "producer_provider": "gpt",
                "reviewer_provider": "claude",
                "model": "claude-opus-5",
                "effort": "high",
                "engine_subcommands": ["prepare", "review", "check"],
            },
        )
        self.assertEqual(manifest["tier2_evidence_schema"], "tier2-evidence-v2")
        self.assertEqual(
            manifest["tier2_candidate_paths"],
            ["bundle-manifest.json", "metadata/review-files.json"],
        )
        self.assertFalse((first / "metadata/tier2-evidence-inputs.json").exists())
        with self.assertRaisesRegex(ValueError, "current GPT-to-Claude Opus 5 high"):
            PREFLIGHT.validate_tier2_review(
                {
                    "producer_provider": "gpt",
                    "reviewer_provider": "claude",
                    "model": "claude-fable-5",
                    "effort": "high",
                    "engine_subcommands": ["prepare", "review", "check"],
                }
            )
        self.assertEqual(
            manifest["ops_targets"][0]["scope"],
            "Codex-R-matched open and eligible Sats/Victor private membership",
        )
        self.assertEqual(
            manifest["capability_parity"],
            {
                "manifest_schema": "buzz-agent-capability-manifest-v1",
                "receipt_schema": "buzz-agent-capability-parity-receipt-v1",
                "tool": "/usr/local/libexec/buzz/verify-agent-capability-parity",
                "policy": "/etc/buzz-agents/capability-parity-policy.json",
                "receipt_binding": {
                    "status": "pending-live-capture",
                    "path": "metadata/capability-parity-receipt.json",
                    "sha256": None,
                    "required_before_activation": True,
                },
            },
        )
        self.assertEqual(
            manifest["source_commit"],
            subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=REPO_ROOT,
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            ).stdout.strip(),
        )
        self.assertEqual(
            manifest["source_tree"],
            subprocess.run(
                ["git", "rev-parse", "HEAD^{tree}"],
                cwd=REPO_ROOT,
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            ).stdout.strip(),
        )
        self.assertEqual(
            manifest["acp_state_dirs"],
            {
                "mempool": "/home/buzz-mempool/.local/state/buzz-acp",
                "genesis": "/home/buzz-genesis/.local/state/buzz-acp",
            },
        )
        for slug, public_key in (("mempool", "1" * 64), ("genesis", "2" * 64)):
            self.assertEqual(
                manifest["identities"][slug],
                {
                    "public_key": public_key,
                    "user": f"buzz-{slug}",
                    "home": f"/home/buzz-{slug}",
                    "credential_path": f"/etc/buzz-agents/credentials/{slug}.key",
                    "environment_path": f"/etc/buzz-agents/{slug}.env",
                    "prompt_path": f"/etc/buzz-agents/prompts/{slug}.md",
                    "acp_state_dir": f"/home/buzz-{slug}/.local/state/buzz-acp",
                    "systemd_unit": f"buzz-agent@{slug}.service",
                },
            )
        codex_acp = first / "install-root/usr/local/libexec/buzz/codex-acp"
        self.assertTrue(codex_acp.read_bytes().startswith(b"#!/usr/local/libexec/buzz/node\n"))
        self.assertNotIn(b"#!/usr/bin/env node", codex_acp.read_bytes())

    def test_public_key_validation_rejects_malformed_duplicate_equal_and_reserved(self) -> None:
        cases = {
            "uppercase": ("A" * 64, "2" * 64, "lowercase"),
            "short": ("1" * 63, "2" * 64, "64 lowercase"),
            "equal": ("1" * 64, "1" * 64, "must differ"),
            "reserved": (GENERATOR.OWNER_PUBKEY, "2" * 64, "reserved responder"),
        }
        for name, (mempool, genesis, message) in cases.items():
            with self.subTest(name=name):
                path = self.root / f"{name}.json"
                write_inputs(path, mempool, genesis)
                with self.assertRaisesRegex(ValueError, message):
                    GENERATOR.generate(
                        path,
                        self.root / f"out-{name}",
                        self.system_root,
                        REPO_ROOT,
                        False,
                        False,
                    )
        duplicate = self.root / "duplicate.json"
        write_file(
            duplicate,
            (
                '{"schema":"buzz-mempool-genesis-activation-input-v1",'
                '"mempool_pubkey":"' + "1" * 64 + '",'
                '"mempool_pubkey":"' + "3" * 64 + '",'
                '"genesis_pubkey":"' + "2" * 64 + '"}\n'
            ).encode(),
            0o600,
        )
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            GENERATOR.generate(
                duplicate,
                self.root / "out-duplicate",
                self.system_root,
                REPO_ROOT,
                False,
                False,
            )

    def test_placeholder_package_and_receipt_are_incomplete_and_noninstallable(self) -> None:
        write_inputs(
            self.inputs,
            GENERATOR.PLACEHOLDERS["mempool"],
            GENERATOR.PLACEHOLDERS["genesis"],
        )
        bundle, manifest = self.generate("placeholder", allow_placeholders=True)
        self.assertEqual(manifest["input_status"], "desktop-save-required")
        self.assertFalse(manifest["ready_for_parent_tier1"])
        self.assertFalse(manifest["installable"])
        receipt_path, receipt = self.make_receipt(bundle, "placeholder")
        self.assertEqual(receipt["status"], "BLOCKED_ON_DESKTOP_PUBKEYS")
        self.assertIsNone(receipt["tier2_bundle"])
        self.assertFalse(self.evidence_path("placeholder").exists())
        fake_state = self.root / "placeholder-state.json"
        write_private_json(fake_state, {"state_schema": "not-a-tier2-state"})
        with self.assertRaisesRegex(ValueError, "incomplete"):
            INSTALLER.load_bundle(
                bundle,
                receipt_path,
                receipt_path,
                fake_state,
                REPO_ROOT,
            )

    def test_templates_bind_owner_only_host_state_and_memory_boundary(self) -> None:
        bundle, _manifest = self.generate()
        for slug in ("mempool", "genesis"):
            env = (bundle / f"install-root/etc/buzz-agents/{slug}.env").read_text()
            values = dict(line.split("=", 1) for line in env.splitlines())
            self.assertEqual(values["BUZZ_ACP_RESPOND_TO"], "owner-only")
            self.assertNotIn("BUZZ_ACP_RESPOND_TO_ALLOWLIST", values)
            self.assertEqual(values["BUZZ_ACP_ALLOWED_RESPOND_TO"], "owner-only")
            self.assertEqual(
                values["BUZZ_ACP_STATE_DIR"],
                f"/home/buzz-{slug}/.local/state/buzz-acp",
            )
            self.assertEqual(values["BUZZ_RELAY_URL"], "wss://framework-desktop.tail69757d.ts.net:38443")
            self.assertEqual(values["BUZZ_ACP_AGENT_COMMAND"], "/usr/local/libexec/buzz/codex-acp")
            self.assertEqual(
                values["BUZZ_ACP_MCP_COMMAND"], "/usr/local/libexec/buzz/buzz-dev-mcp"
            )
            self.assertEqual(
                values["BUZZ_ACP_STATE_DIR"],
                f"/home/buzz-{slug}/.local/state/buzz-acp",
            )
            self.assertEqual(values["CODEX_PATH"], "/usr/local/libexec/buzz/codex")
            self.assertNotIn("PATH", values)
            env_path = bundle / f"install-root/etc/buzz-agents/{slug}.env"
            self.assertEqual(stat.S_IMODE(env_path.stat().st_mode), 0o600)
            env_record = next(
                record
                for record in _manifest["runtime_targets"]
                if record["target"] == f"/etc/buzz-agents/{slug}.env"
            )
            self.assertEqual((env_record["mode"], env_record["uid"], env_record["gid"]), ("0600", 0, 0))
            prompt = (bundle / f"install-root/etc/buzz-agents/prompts/{slug}.md").read_text()
            source_prompt = (ACTIVATION_DIR / f"templates/{slug}.md").read_text()
            self.assertEqual(prompt, source_prompt)
            self.assertIn("Victor remains your sole cryptographic owner.", prompt)
            self.assertIn("Your identity and memory scope are Sats/Victor only.", prompt)
            self.assertIn("assignment authority never widens that scope", prompt)
            self.assertIn("framework-desktop", prompt)
            self.assertIn("GPT-5.6 Sol at high reasoning for the root seat", prompt)
            self.assertIn("canon-approved worker profiles and transports", prompt)
            self.assertIn("current opposite-provider runbook", prompt)
            self.assertIn("Claude Opus 5 reviewer at high reasoning", prompt)
            self.assertIn("Fable 5 is not a review or escalation route", prompt)
            self.assertIn("Claude- or parent-produced work", prompt)
            self.assertIn("GPT-5.6 Sol reviewer at high reasoning", prompt)
            self.assertIn("Reviewer identity must differ from producer identity", prompt)
            self.assertIn("Sol `xhigh` is allowed only on explicit Victor or Rachel instruction", prompt)
            self.assertIn("Luna is producer-only and never a reviewer", prompt)
            self.assertNotIn("reviewer at explicit `xhigh`", prompt)
            self.assertNotIn("opposite-provider review, and double-model review are retired", prompt)

        with self.assertRaisesRegex(ValueError, "must not override the reviewed service PATH"):
            GENERATOR.validate_env(
                (
                    ACTIVATION_DIR / "templates/genesis.env"
                ).read_bytes()
                + b"PATH=/home/buzz-genesis/.local/bin:/usr/bin\n",
                "genesis",
            )

        expected = b"/home/buzz-genesis/.local/state/buzz-acp"
        genesis_env = (ACTIVATION_DIR / "templates/genesis.env").read_bytes()
        cases = {
            "relative": b".buzz-acp/state",
            "shared": b"/home/buzz-shared/.local/state/buzz-acp",
            "wrong identity": b"/home/buzz-mempool/.local/state/buzz-acp",
        }
        for label, replacement in cases.items():
            with self.subTest(label=label), self.assertRaisesRegex(
                ValueError, "wrong BUZZ_ACP_STATE_DIR"
            ):
                GENERATOR.validate_env(genesis_env.replace(expected, replacement), "genesis")

        with self.assertRaisesRegex(ValueError, "invalid or duplicate env line"):
            GENERATOR.validate_env(
                genesis_env + b"BUZZ_ACP_STATE_DIR=/home/buzz-genesis/.local/state/buzz-acp\n",
                "genesis",
            )

    def test_installer_revalidates_state_dir_before_building_closure(self) -> None:
        targets = []
        for slug in ("mempool", "genesis"):
            source = self.root / f"installer-{slug}.env"
            payload = f"BUZZ_ACP_STATE_DIR=/home/buzz-{slug}/.local/state/buzz-acp\n".encode()
            write_file(source, payload, 0o600)
            targets.append(
                INSTALLER.Target(
                    f"/etc/buzz-agents/{slug}.env",
                    source,
                    None,
                    0o600,
                    0,
                    0,
                    hashlib.sha256(payload).hexdigest(),
                )
            )
        INSTALLER.validate_runtime_state_dirs(tuple(targets))

        genesis = targets[1]
        wrong = b"BUZZ_ACP_STATE_DIR=.buzz-acp/state\n"
        write_file(genesis.source, wrong, 0o600)
        with self.assertRaisesRegex(ValueError, "wrong BUZZ_ACP_STATE_DIR"):
            INSTALLER.validate_runtime_state_dirs(tuple(targets))

    def test_state_dir_override_survives_bridge_with_read_only_home(self) -> None:
        write_file(
            self.system_root / "usr/local/libexec/buzz/run-buzz-agent",
            b"#!/usr/bin/env bash\nexec /usr/local/libexec/buzz/buzz-acp\n",
            0o755,
        )
        bundle, _manifest = self.generate("state-dir-bridge")
        service = (
            bundle / "install-root/etc/systemd/system/buzz-agent@.service"
        ).read_text()
        bridge = (
            bundle / "install-root/usr/local/libexec/buzz/run-buzz-agent"
        ).read_text()

        self.assertIn("ProtectHome=read-only\n", service)
        self.assertIn(" /home/buzz-%i/.local/state ", service)
        self.assertIn("exec /usr/local/libexec/buzz/buzz-acp\n", bridge)
        self.assertNotIn("unset BUZZ_ACP_STATE_DIR", bridge)
        for slug in ("mempool", "genesis"):
            env = (bundle / f"install-root/etc/buzz-agents/{slug}.env").read_text()
            values = dict(line.split("=", 1) for line in env.splitlines())
            self.assertEqual(
                values["BUZZ_ACP_STATE_DIR"],
                f"/home/buzz-{slug}/.local/state/buzz-acp",
            )

    def test_instance_dropins_are_exact_and_fully_covered(self) -> None:
        bundle, manifest = self.generate("dropin-closure")
        service = (bundle / "install-root/etc/systemd/system/buzz-agent@.service").read_text()
        self.assertEqual(
            [line for line in service.splitlines() if line.startswith("ReadWritePaths=")],
            [
                "ReadWritePaths=/home/buzz-%i/.codex /home/buzz-%i/.config "
                "/home/buzz-%i/.cache /home/buzz-%i/.local/state /home/buzz-%i/.tmp "
                "/run/buzz-agents-%i"
            ],
        )
        cases = {
            "mempool": (
                "/etc/systemd/system/buzz-agent@mempool.service.d/ci-migration.conf",
                [f"/home/victor/work/ci-mig/a{index}" for index in range(1, 7)],
            ),
            "genesis": (
                "/etc/systemd/system/buzz-agent@genesis.service.d/capability-parity.conf",
                [],
            ),
        }
        for slug, (dropin, victor_paths) in cases.items():
            closure = {entry["path"] for entry in manifest["review_files"][slug]}
            self.assertIn("/etc/systemd/system/buzz-agent@.service", closure)
            self.assertIn("/usr/lib/systemd/system/service.d/10-timeout-abort.conf", closure)
            self.assertIn(dropin, closure)
            payload = (bundle / f"install-root/{dropin.lstrip('/')}").read_text()
            self.assertIn("ReadWritePaths=\n", payload)
            read_write_lines = [
                line for line in payload.splitlines() if line.startswith("ReadWritePaths=")
            ]
            self.assertEqual(len(read_write_lines), 2)
            self.assertEqual(read_write_lines[0], "ReadWritePaths=")
            write_paths = read_write_lines[1].partition("=")[2].split()
            self.assertNotIn(f"/home/buzz-{slug}", write_paths)
            self.assertEqual(
                write_paths[:6],
                [
                    f"/home/buzz-{slug}/.codex",
                    f"/home/buzz-{slug}/.config",
                    f"/home/buzz-{slug}/.cache",
                    f"/home/buzz-{slug}/.local/state",
                    f"/home/buzz-{slug}/.tmp",
                    f"/run/buzz-agents-{slug}",
                ],
            )
            for path in victor_paths:
                self.assertIn(path, payload)
            if slug == "genesis":
                self.assertNotIn("/home/victor", payload)
                self.assertNotIn("/home/buzz-genesis/.npm-global", payload)
                self.assertIn(
                    "Environment=PATH=/usr/local/libexec/buzz:/usr/local/bin:/usr/bin:/bin",
                    payload,
                )

    def test_effective_systemd_paths_cannot_escape_inventory_or_closure(self) -> None:
        bundle, _manifest = self.generate("effective-systemd")
        self.assertEqual(
            PREFLIGHT.verify_staged_systemd(bundle),
            {
                "mempool": {
                    "fragment": "/etc/systemd/system/buzz-agent@.service",
                    "dropins": [
                        "/usr/lib/systemd/system/service.d/10-timeout-abort.conf",
                        "/etc/systemd/system/buzz-agent@mempool.service.d/ci-migration.conf",
                    ],
                },
                "genesis": {
                    "fragment": "/etc/systemd/system/buzz-agent@.service",
                    "dropins": [
                        "/usr/lib/systemd/system/service.d/10-timeout-abort.conf",
                        "/etc/systemd/system/buzz-agent@genesis.service.d/capability-parity.conf",
                    ],
                },
            },
        )
        write_file(
            bundle
            / "install-root/etc/systemd/system/buzz-agent@mempool.service.d/99-unreviewed.conf",
            b"[Service]\nEnvironment=UNREVIEWED=1\n",
            0o644,
        )
        with self.assertRaisesRegex(ValueError, "escape the staged inventory"):
            PREFLIGHT.verify_staged_systemd(bundle)

    def test_root_only_closure_paths_require_privileged_prestart(self) -> None:
        bundle, manifest = self.generate("privileged-prestart")
        by_target = {
            str(record["target"]): record for record in manifest["runtime_targets"]
        }
        self.assertEqual(by_target["/etc/buzz-agents/enrollment-keys.json"]["mode"], "0600")
        self.assertEqual(by_target["/etc/sudoers.d/buzz-agent-key-handoff"]["mode"], "0440")
        for slug in ("mempool", "genesis"):
            closure_paths = manifest["expected_closure_paths"][slug]
            self.assertIn("/etc/buzz-agents/enrollment-keys.json", closure_paths)
            self.assertIn("/etc/sudoers.d/buzz-agent-key-handoff", closure_paths)

        service = (
            bundle / "install-root/etc/systemd/system/buzz-agent@.service"
        ).read_text()
        verifier = (REPO_ROOT / "scripts/mempool-genesis/verify-installed-agent").read_text()
        self.assertIn("--property=FragmentPath", verifier)
        self.assertIn("--property=DropInPaths", verifier)
        self.assertIn('test "${#effective_dropins[@]}" = 2', verifier)
        self.assertIn("User=buzz-%i\n", service)
        self.assertIn(
            "ExecStartPre=+/bin/bash /usr/local/libexec/buzz/verify-installed-agent %i\n",
            service,
        )
        self.assertIn(
            "ExecStart=/bin/bash /usr/local/libexec/buzz/run-buzz-agent %i\n",
            service,
        )
        self.assertNotIn(
            "ExecStart=+/bin/bash /usr/local/libexec/buzz/run-buzz-agent %i",
            service,
        )

    def test_preflight_receipt_reports_readiness_without_review_or_install_claim(self) -> None:
        bundle, _manifest = self.generate()
        receipt_path, receipt = self.make_receipt(bundle)
        self.assertEqual(receipt["status"], "READY_FOR_PARENT_TIER1")
        self.assertFalse(receipt["installable"])
        self.assertEqual(receipt["next_gate"], "parent-tier1-readback")
        evidence_path = self.evidence_path("preflight")
        evidence = json.loads(evidence_path.read_text())
        self.assertEqual(
            set(evidence),
            {"schema", "candidate_root", "summary", "paths", "invariants", "commands", "known_limits"},
        )
        self.assertEqual(evidence["schema"], "tier2-evidence-v2")
        self.assertEqual(evidence["candidate_root"], str(bundle))
        self.assertEqual(evidence["paths"], ["bundle-manifest.json", "metadata/review-files.json"])
        self.assertEqual(receipt["tier2_bundle"]["path"], str(evidence_path))
        payload = receipt_path.read_text()
        self.assertNotIn('"accepted"', payload)
        self.assertNotIn('"verdict"', payload)
        self.assertFalse((self.root / "review-closure.json").exists())

    def test_normal_tier2_acceptance_derives_exact_installed_closure(self) -> None:
        bundle, manifest, receipt, evidence, state = self.closed_package()
        loaded_manifest, acceptance, targets = INSTALLER.load_bundle(
            bundle,
            receipt,
            evidence,
            state,
            REPO_ROOT,
        )
        self.assertEqual(loaded_manifest, manifest)
        state_value = json.loads(state.read_text())
        self.assertEqual(state_value["state_schema"], "tier2-state-v2")
        self.assertEqual(state_value["producer_provider"], "gpt")
        self.assertNotIn("escalate", state_value)
        self.assertEqual(
            {key: state_value["route"][key] for key in ("provider", "model", "effort")},
            {"provider": "claude", "model": "claude-opus-5", "effort": "high"},
        )
        self.assertEqual(acceptance.verdict, "PASS")
        closure = next(target for target in targets if target.target == CLOSURE_TARGET)
        self.assertIsNotNone(closure.payload)
        value = json.loads(bytes(closure.payload).decode())
        self.assertTrue(value["accepted"])
        self.assertEqual(value["lineage_id"], acceptance.lineage_id)
        self.assertEqual(value["state_id"], acceptance.state_id)
        self.assertEqual(value["verdict_digest"], acceptance.verdict_digest)
        self.assertEqual(value["candidate_fingerprint"], acceptance.candidate_fingerprint)
        self.assertEqual(value["bundle_digest"], manifest["package_digest"])
        self.assertEqual(value["source_commit"], manifest["source_commit"])
        self.assertEqual(value["source_tree"], manifest["source_tree"])
        self.assertEqual(value["identities"], manifest["identities"])
        self.assertEqual(value["acp_state_dirs"], manifest["acp_state_dirs"])
        self.assertEqual(value["capability_parity"], manifest["capability_parity"])
        for slug in ("mempool", "genesis"):
            self.assertEqual(len(value["files"][slug]), 21)
            self.assertEqual(value["files"][slug], manifest["review_files"][slug])

    def test_derived_closure_satisfies_the_installed_runtime_contract(self) -> None:
        bundle, _manifest, receipt, evidence, state = self.closed_package("runtime-contract")
        _loaded, _acceptance, targets = INSTALLER.load_bundle(
            bundle,
            receipt,
            evidence,
            state,
            REPO_ROOT,
        )
        closure = next(target for target in targets if target.target == CLOSURE_TARGET)
        self.assertIsNotNone(closure.payload)
        closure_text = bytes(closure.payload).decode()

        verifier = (REPO_ROOT / "scripts/mempool-genesis/verify-installed-agent").read_text()
        prefix = "jq -e --arg slug \"$slug\" --argjson count \"${#expected_paths[@]}\" '\n"
        suffix = "\n' \"$closure\" >/dev/null"
        self.assertEqual(verifier.count(prefix), 1)
        self.assertEqual(verifier.count(suffix), 1)
        contract = verifier.split(prefix, 1)[1].split(suffix, 1)[0]

        for slug in ("mempool", "genesis"):
            completed = subprocess.run(
                ["jq", "-e", "--arg", "slug", slug, "--argjson", "count", "21", contract],
                input=closure_text,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

        retired = json.loads(closure_text)
        retired["schema"] = "buzz-agent-review-closure-v1"
        rejected = subprocess.run(
            ["jq", "-e", "--arg", "slug", "mempool", "--argjson", "count", "21", contract],
            input=json.dumps(retired),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(rejected.returncode, 0)

    def test_tier2_v2_pass_with_risks_is_terminal_and_accepted(self) -> None:
        bundle, manifest = self.generate("accepted-risks")
        receipt, _ = self.make_receipt(bundle, "accepted-risks")
        evidence, state = self.make_tier2(
            bundle,
            manifest,
            "accepted-risks",
            verdict="PASS WITH RISKS",
        )
        _loaded, acceptance, _targets = INSTALLER.load_bundle(
            bundle,
            receipt,
            evidence,
            state,
            REPO_ROOT,
        )
        self.assertEqual(acceptance.verdict, "PASS WITH RISKS")

    def test_normal_tier2_rejection_blocks_preflight(self) -> None:
        bundle, manifest = self.generate("rejected")
        receipt, _ = self.make_receipt(bundle, "rejected")
        evidence, state = self.make_tier2(bundle, manifest, "rejected", verdict="FAIL")
        install_root = self.root / "install-root"
        install_root.mkdir(mode=0o700)
        prepare_install_root(install_root, manifest)
        with mock.patch.dict(os.environ, {"MGACT_TESTING": "1"}):
            value = INSTALLER.preflight(
                bundle,
                receipt,
                evidence,
                state,
                install_root,
                REPO_ROOT,
            )
        self.assertTrue(value.blockers)
        self.assertIn("closure rejected", value.blockers[0])

    def test_arbitrary_accepted_json_cannot_replace_normal_tier2_state(self) -> None:
        bundle, manifest = self.generate("fake")
        receipt, _ = self.make_receipt(bundle, "fake")
        evidence = self.evidence_path("fake")
        state = self.root / "fake-state.json"
        write_private_json(state, {"accepted": True, "terminal": True, "consumable": True})
        with self.assertRaisesRegex(ValueError, "closure rejected"):
            INSTALLER.load_bundle(bundle, receipt, evidence, state, REPO_ROOT)

    def test_exact_package_mismatch_rejects_an_otherwise_accepted_review(self) -> None:
        bundle_one, manifest_one = self.generate("one")
        _receipt_one, _ = self.make_receipt(bundle_one, "one")
        evidence, state = self.make_tier2(bundle_one, manifest_one, "one")
        inputs_two = self.root / "inputs-two.json"
        write_inputs(inputs_two, "3" * 64, "4" * 64)
        bundle_two, _manifest_two = self.generate("two", inputs=inputs_two)
        receipt_two, _ = self.make_receipt(bundle_two, "two")
        with self.assertRaisesRegex(ValueError, "evidence binding mismatch"):
            INSTALLER.load_bundle(
                bundle_two,
                receipt_two,
                evidence,
                state,
                REPO_ROOT,
            )

    def test_review_file_mutation_invalidates_package_and_closure(self) -> None:
        bundle, _manifest, receipt, evidence, state = self.closed_package("mutated")
        review_file = bundle / "metadata/review-files.json"
        review_file.write_bytes(review_file.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "source hash mismatch"):
            INSTALLER.load_bundle(bundle, receipt, evidence, state, REPO_ROOT)

    def test_retired_escalate_field_is_rejected(self) -> None:
        bundle, _manifest, receipt, evidence, state = self.closed_package("retired-escalate")
        value = json.loads(state.read_text())
        value["escalate"] = True
        write_private_json(state, value)
        with self.assertRaisesRegex(ValueError, "closure rejected"):
            INSTALLER.load_bundle(bundle, receipt, evidence, state, REPO_ROOT)

    def test_retired_sol_xhigh_route_is_rejected(self) -> None:
        bundle, _manifest, receipt, evidence, state = self.closed_package("retired-route")
        value = json.loads(state.read_text())
        value["route"] = {
            "provider": "gpt",
            "model": "gpt-5.6-sol",
            "effort": "xhigh",
            "reviewer_identity": "gpt:retired-reviewer",
        }
        value["verdict"]["reviewer_identity"] = "gpt:retired-reviewer"
        write_private_json(state, value)
        with self.assertRaisesRegex(ValueError, "closure rejected"):
            INSTALLER.load_bundle(bundle, receipt, evidence, state, REPO_ROOT)

    def test_expired_tier2_v2_state_is_rejected(self) -> None:
        bundle, _manifest, receipt, evidence, state = self.closed_package("expired")
        value = json.loads(state.read_text())
        value["prepared_at_ns"] = 1
        write_private_json(state, value)
        with self.assertRaisesRegex(ValueError, "closed review state is stale"):
            INSTALLER.load_bundle(bundle, receipt, evidence, state, REPO_ROOT)


class ActivationCorrectionRegressionTests(PackageFixture):
    def test_shellcheck_gate_is_fixed_and_independent_of_caller_path(self) -> None:
        bundle, manifest = self.generate("path-independent")
        with mock.patch.dict(os.environ, {"PATH": "/bin"}):
            receipt_commands = PREFLIGHT.gate_commands(bundle)
        with mock.patch.dict(os.environ, {"PATH": "/usr/sbin:/usr/bin"}):
            installer_commands = PREFLIGHT.gate_commands(bundle)
        self.assertEqual(receipt_commands, installer_commands)
        self.assertEqual(receipt_commands[-1][0], PREFLIGHT.SHELLCHECK_PATH)

        results = [
            {"command": command, "exit": 0, "stdout": "ok\n", "stderr": ""}
            for command in receipt_commands
        ]
        receipt_path = self.root / "path-independent-receipt.json"
        evidence_path = self.root / "path-independent-tier2-evidence.json"
        with mock.patch.dict(os.environ, {"PATH": "/bin"}):
            PREFLIGHT.generate_receipt(
                bundle,
                receipt_path,
                REPO_ROOT,
                tier2_bundle_output=evidence_path,
                command_results=results,
                before_snapshot=UNCHANGED_SNAPSHOT,
                after_snapshot=UNCHANGED_SNAPSHOT,
            )
        with mock.patch.dict(os.environ, {"PATH": "/usr/sbin:/usr/bin"}):
            INSTALLER.validate_preflight_receipt(
                receipt_path,
                bundle,
                manifest,
                evidence_path,
                current_artifact_owner(),
            )

    def test_receipt_generation_refuses_root_shellcheck_execution(self) -> None:
        bundle, _manifest = self.generate("root-receipt")
        with mock.patch.object(PREFLIGHT.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(ValueError, "non-root artifact owner"):
                PREFLIGHT.generate_receipt(
                    bundle,
                    self.root / "root-receipt.json",
                    REPO_ROOT,
                    command_results=[],
                    before_snapshot=UNCHANGED_SNAPSHOT,
                    after_snapshot=UNCHANGED_SNAPSHOT,
                )

    def test_sealed_package_verifier_survives_post_freeze_in_place_mutation(self) -> None:
        verifier_source = ACTIVATION_DIR / "tier2-evidence-verifier.py"
        self.assertEqual(INSTALLER.TIER2_VERIFIER_MODE, 0o755)
        self.assertEqual(stat.S_IMODE(verifier_source.lstat().st_mode), 0o755)
        repo = self.root / "verifier-repo"
        verifier = repo / INSTALLER.TIER2_VERIFIER_RELATIVE
        write_file(verifier, b'print("FROZEN_VERIFIER")\n', INSTALLER.TIER2_VERIFIER_MODE)
        manifest = {
            "generator_sources": [
                {
                    "path": str(INSTALLER.TIER2_VERIFIER_RELATIVE),
                    "mode": f"{INSTALLER.TIER2_VERIFIER_MODE:04o}",
                    "sha256": hashlib.sha256(verifier.read_bytes()).hexdigest(),
                }
            ]
        }
        descriptor = INSTALLER.open_bound_tier2_verifier(manifest, repo)
        marker = self.root / "malicious-executed"
        write_file(
            verifier,
            f'from pathlib import Path\nPath({str(marker)!r}).write_text("bad")\n'.encode(),
            INSTALLER.TIER2_VERIFIER_MODE,
        )
        required_seals = (
            fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SEAL
        )
        self.assertEqual(fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & required_seals, required_seals)
        try:
            completed = subprocess.run(
                [sys.executable, f"/proc/self/fd/{descriptor}"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                pass_fds=(descriptor,),
                timeout=30,
            )
        finally:
            os.close(descriptor)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "FROZEN_VERIFIER")
        self.assertFalse(marker.exists())

    def test_artifact_owner_accepts_authenticated_sudo_and_direct_root(self) -> None:
        account = pwd.getpwuid(os.getuid())
        sudo_environment = {
            "SUDO_UID": str(account.pw_uid),
            "SUDO_GID": str(account.pw_gid),
            "SUDO_USER": account.pw_name,
        }
        with mock.patch.object(INSTALLER.os, "geteuid", return_value=0), mock.patch.dict(
            os.environ, sudo_environment, clear=True
        ), mock.patch.object(
            INSTALLER, "parent_executable", return_value=INSTALLER.SUDO_PATH
        ), mock.patch.object(
            INSTALLER,
            "parent_process_ids",
            return_value=((account.pw_uid, 0, 0, 0), (0, 0, 0, 0)),
        ):
            owner = INSTALLER.artifact_owner()
        self.assertEqual((owner.uid, owner.gid, owner.user), (account.pw_uid, account.pw_gid, account.pw_name))

        with mock.patch.object(INSTALLER.os, "geteuid", return_value=0), mock.patch.object(
            INSTALLER.os, "getuid", return_value=0
        ), mock.patch.object(INSTALLER.os, "getgid", return_value=0), mock.patch.dict(
            os.environ, {}, clear=True
        ):
            root_owner = INSTALLER.artifact_owner()
        self.assertEqual((root_owner.uid, root_owner.gid), (0, 0))

    def test_artifact_owner_rejects_malformed_and_forged_sudo_uid(self) -> None:
        account = pwd.getpwuid(os.getuid())
        base = {
            "SUDO_UID": str(account.pw_uid),
            "SUDO_GID": str(account.pw_gid),
            "SUDO_USER": account.pw_name,
        }
        malformed = {**base, "SUDO_UID": f"0{account.pw_uid}"}
        with mock.patch.object(INSTALLER.os, "geteuid", return_value=0), mock.patch.dict(
            os.environ, malformed, clear=True
        ):
            with self.assertRaisesRegex(ValueError, "malformed SUDO_UID"):
                INSTALLER.artifact_owner()
        with mock.patch.object(INSTALLER.os, "geteuid", return_value=0), mock.patch.dict(
            os.environ, base, clear=True
        ), mock.patch.object(INSTALLER, "parent_executable", return_value=Path("/usr/bin/python3")):
            with self.assertRaisesRegex(ValueError, "authenticated sudo parent"):
                INSTALLER.artifact_owner()
        with mock.patch.object(INSTALLER.os, "geteuid", return_value=0), mock.patch.dict(
            os.environ, base, clear=True
        ), mock.patch.object(
            INSTALLER, "parent_executable", return_value=INSTALLER.SUDO_PATH
        ), mock.patch.object(
            INSTALLER,
            "parent_process_ids",
            return_value=((account.pw_uid + 1, 0, 0, 0), (0, 0, 0, 0)),
        ):
            with self.assertRaisesRegex(ValueError, "authenticated sudo process"):
                INSTALLER.artifact_owner()

    def test_sudo_owner_contract_accepts_user_artifacts_and_rejects_wrong_owner(self) -> None:
        bundle, manifest, receipt, evidence, state = self.closed_package("sudo-owner")
        owner = current_artifact_owner()
        receipt_value = json.loads(receipt.read_text())
        acceptance = INSTALLER.validate_tier2_acceptance(
            bundle,
            manifest,
            receipt_value,
            evidence,
            state,
            REPO_ROOT,
            owner,
        )
        self.assertEqual(acceptance.verdict, "PASS")
        wrong = INSTALLER.ArtifactOwner(owner.uid + 1, owner.gid, owner.user, owner.home)
        with self.assertRaisesRegex(ValueError, "wrong owner"):
            INSTALLER.validate_preflight_receipt(receipt, bundle, manifest, evidence, wrong)
        with self.assertRaisesRegex(ValueError, "unsafe Tier 2 v2 evidence bundle"):
            INSTALLER.validate_tier2_acceptance(
                bundle,
                manifest,
                receipt_value,
                evidence,
                state,
                REPO_ROOT,
                wrong,
            )

    def test_fedora_lock_layout_uses_canonical_run_lock(self) -> None:
        var_lock = Path("/var/lock")
        run_lock = Path("/run/lock")
        self.assertTrue(stat.S_ISLNK(var_lock.lstat().st_mode))
        self.assertEqual(var_lock.resolve(strict=True), run_lock)
        metadata = run_lock.lstat()
        self.assertTrue(stat.S_ISDIR(metadata.st_mode))
        self.assertFalse(stat.S_ISLNK(metadata.st_mode))
        self.assertEqual((metadata.st_uid, metadata.st_gid), (0, 0))
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o755)
        self.assertEqual(
            INSTALLER.lock_path_for(Path("/")),
            Path("/run/lock/buzz-mgact-install.lock"),
        )


class InstallerSafetyTests(PackageFixture):
    def setUp(self) -> None:
        super().setUp()
        (
            self.bundle,
            self.manifest,
            self.receipt,
            self.evidence,
            self.state,
        ) = self.closed_package("installer")
        self.install_root = self.root / "install-root"
        self.install_root.mkdir(mode=0o700)
        prepare_install_root(self.install_root, self.manifest)

    def preflight(self) -> object:
        with mock.patch.dict(os.environ, {"MGACT_TESTING": "1"}):
            return INSTALLER.preflight(
                self.bundle,
                self.receipt,
                self.evidence,
                self.state,
                self.install_root,
                REPO_ROOT,
            )

    def install(self) -> int:
        with mock.patch.dict(os.environ, {"MGACT_TESTING": "1"}):
            return INSTALLER.install(
                self.bundle,
                self.receipt,
                self.evidence,
                self.state,
                self.install_root,
                REPO_ROOT,
            )

    def rollback(self, backup_id: str) -> int:
        with mock.patch.dict(os.environ, {"MGACT_TESTING": "1"}):
            return INSTALLER.rollback(backup_id, self.install_root)

    def only_backup_id(self) -> str:
        backup_root = self.install_root / "var/lib/buzz-mgact-backups"
        backup_ids = [path.name for path in backup_root.iterdir() if path.is_dir()]
        self.assertEqual(len(backup_ids), 1)
        return backup_ids[0]

    def target_record(self, target: str) -> dict[str, object]:
        records = list(self.manifest["runtime_targets"]) + list(self.manifest["ops_targets"])
        return next(record for record in records if record["target"] == target)

    def test_check_and_dry_run_share_read_only_preflight(self) -> None:
        targets = target_names(self.manifest)
        before = target_snapshot(self.install_root, targets)
        check = self.preflight()
        dry_run = self.preflight()
        self.assertEqual(check, dry_run)
        self.assertFalse(check.blockers)
        self.assertTrue(all(target.status == "add" for target in check.targets))
        self.assertEqual(before, target_snapshot(self.install_root, targets))
        self.assertIn("writes=0", INSTALLER.render_preflight(check, "dry-run"))
        self.assertFalse((self.install_root / "var/lib/buzz-mgact-backups").exists())
        self.assertFalse((self.install_root / "run/lock/buzz-mgact-install.lock").exists())

    def test_non_root_install_root_requires_explicit_test_guard(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("MGACT_TESTING", None)
            value = INSTALLER.preflight(
                self.bundle,
                self.receipt,
                self.evidence,
                self.state,
                self.install_root,
                REPO_ROOT,
            )
        self.assertTrue(value.blockers)
        self.assertTrue(any("MGACT_TESTING" in blocker for blocker in value.blockers))

    def test_wrong_owner_mode_hardlink_target_and_symlink_are_classified_safely(self) -> None:
        target_path = self.install_root / "etc/buzz-agents/mempool.env"
        write_file(target_path, b"old\n", 0o600)
        value = self.preflight()
        state = next(item for item in value.targets if item.target.target == "/etc/buzz-agents/mempool.env")
        self.assertEqual(state.status, "replace")
        target_path.unlink()
        other = self.root / "other"
        write_file(other, b"old\n", 0o644)
        os.link(other, target_path)
        value = self.preflight()
        state = next(item for item in value.targets if item.target.target == "/etc/buzz-agents/mempool.env")
        self.assertEqual(state.status, "blocked")
        self.assertIn("unsafe existing", state.reason)
        target_path.unlink()
        other.unlink()
        target_path.symlink_to(self.root / "missing")
        value = self.preflight()
        state = next(item for item in value.targets if item.target.target == "/etc/buzz-agents/mempool.env")
        self.assertEqual(state.status, "blocked")
        target_path.unlink()
        with mock.patch.object(INSTALLER, "expected_owner", return_value=(os.getuid() + 1, os.getgid())):
            value = self.preflight()
        self.assertTrue(any("owner mismatch" in blocker for blocker in value.blockers))

    def test_symlink_in_parent_path_blocks_preflight(self) -> None:
        prompts = self.install_root / "etc/buzz-agents/prompts"
        prompts.rmdir()
        real = self.root / "real-prompts"
        real.mkdir(mode=0o755)
        prompts.symlink_to(real, target_is_directory=True)
        value = self.preflight()
        self.assertTrue(any("symlink in parent path" in blocker for blocker in value.blockers))

    def test_trusted_sibling_usr_local_sbin_link_installs_and_rolls_back(self) -> None:
        sbin = self.install_root / "usr/local/sbin"
        sbin.rmdir()
        binary_directory = self.install_root / "usr/local/agent-bin"
        binary_directory.mkdir(mode=0o755)
        sbin.symlink_to("agent-bin", target_is_directory=True)

        value = self.preflight()
        self.assertFalse(value.blockers)
        for target_text in (
            "/usr/local/sbin/buzz-install-agent-key",
            "/usr/local/sbin/install-enrollment-map",
        ):
            state = next(item for item in value.targets if item.target.target == target_text)
            self.assertEqual(state.status, "add")
            self.assertEqual(state.resolved_parent, binary_directory)

        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.install(), 0)
        self.assertTrue((binary_directory / "buzz-install-agent-key").is_file())
        self.assertTrue((binary_directory / "install-enrollment-map").is_file())
        backup_id = self.only_backup_id()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.rollback(backup_id), 0)
        self.assertFalse((binary_directory / "buzz-install-agent-key").exists())
        self.assertFalse((binary_directory / "install-enrollment-map").exists())
        self.assertTrue(sbin.is_symlink())
        self.assertEqual(os.readlink(sbin), "agent-bin")

    def test_cross_tree_usr_local_sbin_link_remains_blocked(self) -> None:
        sbin = self.install_root / "usr/local/sbin"
        sbin.rmdir()
        sbin.symlink_to("../../etc", target_is_directory=True)
        value = self.preflight()
        self.assertTrue(
            any(
                blocker.startswith("/usr/local/sbin/") and "symlink in parent path" in blocker
                for blocker in value.blockers
            )
        )

    def test_wrong_package_source_mode_is_rejected(self) -> None:
        source = self.bundle / "install-root/etc/buzz-agents/mempool.env"
        source.chmod(0o644)
        value = self.preflight()
        self.assertTrue(value.blockers)
        self.assertIn("wrong mode", value.blockers[0])

    def test_install_is_atomic_idempotent_and_rollbackable_with_exact_closure(self) -> None:
        old_env = self.install_root / "etc/buzz-agents/mempool.env"
        write_file(old_env, b"old env\n", 0o644)
        targets = target_names(self.manifest)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.install(), 0)
        current = self.preflight()
        self.assertFalse(current.blockers)
        self.assertTrue(all(target.status == "current" for target in current.targets))
        closure = json.loads((self.install_root / CLOSURE_TARGET.lstrip("/")).read_text())
        self.assertTrue(closure["accepted"])
        self.assertEqual(closure["bundle_digest"], self.manifest["package_digest"])
        for slug in ("mempool", "genesis"):
            self.assertEqual(len(closure["files"][slug]), 21)
        first_snapshot = target_snapshot(self.install_root, targets)
        backup_root = self.install_root / "var/lib/buzz-mgact-backups"
        backup_ids = [path.name for path in backup_root.iterdir() if path.is_dir()]
        self.assertEqual(len(backup_ids), 1)
        v3_receipt = json.loads((backup_root / backup_ids[0] / "receipt.json").read_text())
        self.assertEqual(v3_receipt["schema"], INSTALLER.INSTALL_RECEIPT_SCHEMA)
        self.assertEqual(v3_receipt["source_commit"], self.manifest["source_commit"])
        self.assertEqual(v3_receipt["source_tree"], self.manifest["source_tree"])
        self.assertEqual(
            v3_receipt["manifest_sha256"],
            INSTALLER.sha256_file(self.bundle / "bundle-manifest.json"),
        )
        self.assertEqual(v3_receipt["identities"], self.manifest["identities"])
        self.assertEqual(v3_receipt["acp_state_dirs"], self.manifest["acp_state_dirs"])
        self.assertEqual(v3_receipt["capability_parity"], self.manifest["capability_parity"])
        self.assertEqual(set(v3_receipt["changed_targets"]), set(v3_receipt["previous"]))
        self.assertEqual(set(v3_receipt["changed_targets"]), set(v3_receipt["installed"]))
        backup_files = v3_receipt["backup_inventory"]["files"]
        self.assertEqual([record["target"] for record in backup_files], [str(old_env).replace(str(self.install_root), "")])
        self.assertEqual(
            v3_receipt["backup_inventory"]["sha256"],
            INSTALLER.sha256_bytes(INSTALLER.canonical_json(backup_files)),
        )
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(self.install(), 0)
        self.assertIn("ALREADY_INSTALLED writes=0", output.getvalue())
        self.assertEqual(first_snapshot, target_snapshot(self.install_root, targets))
        with mock.patch.dict(os.environ, {"MGACT_TESTING": "1"}), contextlib.redirect_stdout(
            io.StringIO()
        ):
            self.assertEqual(INSTALLER.rollback(backup_ids[0], self.install_root), 0)
        rollback_receipt = json.loads((backup_root / backup_ids[0] / "receipt.json").read_text())
        self.assertEqual(rollback_receipt["state"], "rolled_back")
        self.assertEqual(rollback_receipt["rollback"]["status"], "verified")
        self.assertEqual(
            rollback_receipt["rollback"]["restored_targets"],
            rollback_receipt["changed_targets"],
        )
        self.assertEqual(
            rollback_receipt["rollback"]["backup_inventory_sha256"],
            rollback_receipt["backup_inventory"]["sha256"],
        )
        self.assertEqual(old_env.read_bytes(), b"old env\n")
        for target in targets:
            if target == "/etc/buzz-agents/mempool.env":
                continue
            self.assertFalse(os.path.lexists(self.install_root / target.lstrip("/")), target)

    def test_failed_install_restores_mode_only_replacement(self) -> None:
        target_text = "/etc/buzz-agents/mempool.env"
        record = self.target_record(target_text)
        target_path = self.install_root / target_text.lstrip("/")
        payload = (self.bundle / str(record["source"])).read_bytes()
        installed_mode = int(str(record["mode"]), 8)
        previous_mode = 0o600 if installed_mode != 0o600 else 0o644
        write_file(target_path, payload, previous_mode)
        previous_owner = (target_path.lstat().st_uid, target_path.lstat().st_gid)
        original = INSTALLER.atomic_copy_source
        failed = False

        def fail_after_mode_only_target(target, state, root):
            nonlocal failed
            original(target, state, root)
            if target.target == target_text and not failed:
                failed = True
                raise OSError("injected failure after mode-only replacement")

        with mock.patch.object(
            INSTALLER,
            "atomic_copy_source",
            side_effect=fail_after_mode_only_target,
        ):
            with self.assertRaisesRegex(OSError, "mode-only replacement"):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.install()

        self.assertEqual(target_path.read_bytes(), payload)
        restored_metadata = target_path.lstat()
        self.assertEqual(stat.S_IMODE(restored_metadata.st_mode), previous_mode)
        self.assertEqual((restored_metadata.st_uid, restored_metadata.st_gid), previous_owner)
        for target in target_names(self.manifest):
            if target == target_text:
                continue
            self.assertFalse(os.path.lexists(self.install_root / target.lstrip("/")), target)
        receipt_path = next(
            (self.install_root / "var/lib/buzz-mgact-backups").glob("*/receipt.json")
        )
        self.assertEqual(json.loads(receipt_path.read_text())["state"], "rolled_back")

    def test_v3_rollback_rejects_wrong_identity_state_binding(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.install(), 0)
        backup_id = self.only_backup_id()
        receipt_path = (
            self.install_root / "var/lib/buzz-mgact-backups" / backup_id / "receipt.json"
        )
        receipt = json.loads(receipt_path.read_text())
        receipt["identities"]["genesis"]["acp_state_dir"] = (
            "/home/buzz-mempool/.local/state/buzz-acp"
        )
        write_private_json(receipt_path, receipt)
        with self.assertRaisesRegex(ValueError, "genesis identity descriptor mismatch"):
            self.rollback(backup_id)

    def test_v3_rollback_rejects_backup_inventory_tamper(self) -> None:
        old_env = self.install_root / "etc/buzz-agents/mempool.env"
        write_file(old_env, b"old env\n", 0o644)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.install(), 0)
        backup_id = self.only_backup_id()
        backup = self.install_root / "var/lib/buzz-mgact-backups" / backup_id
        receipt = json.loads((backup / "receipt.json").read_text())
        backup_name = receipt["previous"]["/etc/buzz-agents/mempool.env"]["backup_name"]
        (backup / "files" / backup_name).write_bytes(b"tampered\n")
        with self.assertRaisesRegex(ValueError, "backup inventory mismatch"):
            self.rollback(backup_id)

    def test_manual_rollback_restores_matching_content_metadata(self) -> None:
        target_text = "/etc/buzz-agents/mempool.env"
        record = self.target_record(target_text)
        target_path = self.install_root / target_text.lstrip("/")
        payload = (self.bundle / str(record["source"])).read_bytes()
        installed_mode = int(str(record["mode"]), 8)
        previous_mode = 0o600 if installed_mode != 0o600 else 0o644
        write_file(target_path, payload, previous_mode)
        previous_owner = (target_path.lstat().st_uid, target_path.lstat().st_gid)

        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.install(), 0)
        self.assertEqual(stat.S_IMODE(target_path.lstat().st_mode), installed_mode)
        backup_id = self.only_backup_id()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.rollback(backup_id), 0)

        self.assertEqual(target_path.read_bytes(), payload)
        restored_metadata = target_path.lstat()
        self.assertEqual(stat.S_IMODE(restored_metadata.st_mode), previous_mode)
        self.assertEqual((restored_metadata.st_uid, restored_metadata.st_gid), previous_owner)

    def test_manual_rollback_refuses_complete_installed_metadata_drift(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.install(), 0)
        backup_id = self.only_backup_id()
        receipt_path = (
            self.install_root / "var/lib/buzz-mgact-backups" / backup_id / "receipt.json"
        )
        target_text = "/etc/buzz-agents/mempool.env"
        target_path = self.install_root / target_text.lstrip("/")

        def assert_rollback_refused() -> None:
            with self.assertRaises(ValueError):
                self.rollback(backup_id)
            self.assertEqual(json.loads(receipt_path.read_text())["state"], "installed")

        original_require_regular = INSTALLER.require_regular

        def require_with_owner_drift(path, **kwargs):
            metadata = original_require_regular(path, **kwargs)
            if Path(path) != target_path:
                return metadata
            drifted = mock.Mock()
            drifted.st_mode = metadata.st_mode
            drifted.st_nlink = metadata.st_nlink
            drifted.st_uid = metadata.st_uid + 1
            drifted.st_gid = metadata.st_gid
            return drifted

        def require_with_group_drift(path, **kwargs):
            metadata = original_require_regular(path, **kwargs)
            if Path(path) != target_path:
                return metadata
            drifted = mock.Mock()
            drifted.st_mode = metadata.st_mode
            drifted.st_nlink = metadata.st_nlink
            drifted.st_uid = metadata.st_uid
            drifted.st_gid = metadata.st_gid + 1
            return drifted

        with mock.patch.object(
            INSTALLER,
            "require_regular",
            side_effect=require_with_owner_drift,
        ):
            assert_rollback_refused()
        with mock.patch.object(
            INSTALLER,
            "require_regular",
            side_effect=require_with_group_drift,
        ):
            assert_rollback_refused()

        hard_link = self.root / "installed-hard-link"
        os.link(target_path, hard_link)
        assert_rollback_refused()
        hard_link.unlink()

        saved_target = self.root / "installed-symlink-source"
        target_path.rename(saved_target)
        target_path.symlink_to(saved_target)
        assert_rollback_refused()
        target_path.unlink()
        saved_target.rename(target_path)

        installed_mode = stat.S_IMODE(target_path.lstat().st_mode)
        target_path.chmod(0o600 if installed_mode != 0o600 else 0o644)
        assert_rollback_refused()

    def test_manual_rollback_still_restores_different_content(self) -> None:
        target_text = "/etc/buzz-agents/mempool.env"
        record = self.target_record(target_text)
        target_path = self.install_root / target_text.lstrip("/")
        previous_payload = b"previous different content\n"
        previous_mode = int(str(record["mode"]), 8)
        write_file(target_path, previous_payload, previous_mode)

        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.install(), 0)
        backup_id = self.only_backup_id()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.rollback(backup_id), 0)

        self.assertEqual(target_path.read_bytes(), previous_payload)
        self.assertEqual(stat.S_IMODE(target_path.lstat().st_mode), previous_mode)
        for target in target_names(self.manifest):
            if target == target_text:
                continue
            self.assertFalse(os.path.lexists(self.install_root / target.lstrip("/")), target)

    def test_interrupted_write_restores_applied_targets(self) -> None:
        original = INSTALLER.atomic_copy_source
        calls = 0

        def fail_second(target, state, root):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected copy failure")
            return original(target, state, root)

        with mock.patch.object(INSTALLER, "atomic_copy_source", side_effect=fail_second):
            with self.assertRaisesRegex(OSError, "injected copy failure"):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.install()
        for target in target_names(self.manifest):
            self.assertFalse(os.path.lexists(self.install_root / target.lstrip("/")), target)
        receipts = list((self.install_root / "var/lib/buzz-mgact-backups").glob("*/receipt.json"))
        self.assertEqual(len(receipts), 1)
        self.assertEqual(json.loads(receipts[0].read_text())["state"], "rolled_back")

    def test_failure_after_atomic_replace_still_rolls_back(self) -> None:
        original = INSTALLER.atomic_copy_source
        calls = 0

        def fail_after_first_replace(target, state, root):
            nonlocal calls
            calls += 1
            original(target, state, root)
            if calls == 1:
                raise OSError("injected post-replace failure")

        with mock.patch.object(INSTALLER, "atomic_copy_source", side_effect=fail_after_first_replace):
            with self.assertRaisesRegex(OSError, "injected post-replace failure"):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.install()
        for target in target_names(self.manifest):
            self.assertFalse(os.path.lexists(self.install_root / target.lstrip("/")), target)
        receipts = list((self.install_root / "var/lib/buzz-mgact-backups").glob("*/receipt.json"))
        self.assertEqual(len(receipts), 1)
        self.assertEqual(json.loads(receipts[0].read_text())["state"], "rolled_back")

    def test_rollback_refuses_installed_file_drift(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.install(), 0)
        backup_root = self.install_root / "var/lib/buzz-mgact-backups"
        backup_id = next(path.name for path in backup_root.iterdir() if path.is_dir())
        drifted = self.install_root / "etc/buzz-agents/mempool.env"
        drifted.write_text("drift\n")
        with mock.patch.dict(os.environ, {"MGACT_TESTING": "1"}):
            with self.assertRaisesRegex(ValueError, "drift blocks rollback"):
                INSTALLER.rollback(backup_id, self.install_root)


class LegacyV1RollbackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=TEST_ROOT)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.addCleanup(self.temporary.cleanup)
        self.installed_payloads: dict[str, bytes] = {}
        self.previous_payloads: dict[str, bytes] = {}

        previous: dict[str, dict[str, object]] = {}
        installed: dict[str, dict[str, object]] = {}
        for index, target_text in enumerate(INSTALLER.LEGACY_V1_CHANGED_TARGETS):
            destination = self.root / target_text.lstrip("/")
            self.ensure_directory(destination.parent, 0o755)
            installed_payload = f"installed-{index}-{target_text}\n".encode()
            previous_payload = f"previous-{index}-{target_text}\n".encode()
            installed_mode = 0o755 if target_text.startswith("/usr/local/libexec/") else 0o644
            if target_text.endswith(".env"):
                installed_mode = 0o600
            previous_mode = 0o755 if target_text.startswith("/usr/local/libexec/") else 0o644
            write_file(destination, installed_payload, installed_mode)
            backup_name = hashlib.sha256(target_text.encode()).hexdigest()
            previous[target_text] = {
                "exists": True,
                "backup_name": backup_name,
                "sha256": hashlib.sha256(previous_payload).hexdigest(),
                "mode": f"{previous_mode:04o}",
                "uid": 0,
                "gid": 0,
            }
            installed[target_text] = {
                "sha256": hashlib.sha256(installed_payload).hexdigest(),
                "mode": f"{installed_mode:04o}",
                "uid": 0,
                "gid": 0,
            }
            self.installed_payloads[target_text] = installed_payload
            self.previous_payloads[target_text] = previous_payload

        self.stack.enter_context(mock.patch.object(INSTALLER, "LEGACY_V1_PREVIOUS", previous))
        self.stack.enter_context(mock.patch.object(INSTALLER, "LEGACY_V1_INSTALLED", installed))
        inventory_digest = INSTALLER.legacy_v1_inventory_digest()
        self.stack.enter_context(
            mock.patch.object(INSTALLER, "LEGACY_V1_INVENTORY_SHA256", inventory_digest)
        )

        self.backup = (
            self.root
            / "var/lib/buzz-mgact-backups"
            / INSTALLER.LEGACY_V1_BACKUP_ID
        )
        self.ensure_directory(self.backup.parent, 0o700)
        self.ensure_directory(self.backup, 0o700)
        files = self.backup / "files"
        self.ensure_directory(files, 0o700)
        for target_text, payload in self.previous_payloads.items():
            write_file(files / str(previous[target_text]["backup_name"]), payload, 0o600)

        receipt_payload = INSTALLER.canonical_json(INSTALLER.legacy_v1_contract_receipt())
        self.receipt = self.backup / "receipt.json"
        write_file(self.receipt, receipt_payload, 0o600)
        self.backup.parent.chmod(0o700)
        self.backup.chmod(0o700)
        files.chmod(0o700)
        self.stack.enter_context(
            mock.patch.object(
                INSTALLER,
                "LEGACY_V1_RECEIPT_SHA256",
                hashlib.sha256(receipt_payload).hexdigest(),
            )
        )

        self.claim_directory = self.root / INSTALLER.LEGACY_V1_RECOVERY_CLAIM_DIRECTORY.lstrip(
            "/"
        )
        self.ensure_directory(self.claim_directory, 0o700)
        acceptance_claim = self.root / INSTALLER.LEGACY_V1_CLAIM.lstrip("/")
        write_file(
            acceptance_claim,
            INSTALLER.canonical_json(INSTALLER.legacy_v1_acceptance_claim()),
            0o600,
        )

    def ensure_directory(self, path: Path, mode: int) -> None:
        path.mkdir(mode=0o755, parents=True, exist_ok=True)
        current = self.root
        for part in path.relative_to(self.root).parts:
            current = current / part
            current.chmod(0o755)
        path.chmod(mode)

    def rollback(self, *, dry_run: bool = False) -> int:
        with mock.patch.dict(os.environ, {"MGACT_TESTING": "1"}):
            return INSTALLER.rollback(
                INSTALLER.LEGACY_V1_BACKUP_ID,
                self.root,
                dry_run=dry_run,
            )

    def recovery_claim(self) -> Path:
        return INSTALLER.legacy_v1_recovery_claim_path(self.root)

    def test_dry_run_is_reachable_and_writes_nothing(self) -> None:
        before = tree_fingerprint(self.root)
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(self.rollback(dry_run=True), 0)
        self.assertIn("targets=10 writes=0", output.getvalue())
        self.assertEqual(tree_fingerprint(self.root), before)
        self.assertFalse(self.recovery_claim().exists())
        self.assertFalse((self.root / "run/lock/buzz-mgact-install.lock").exists())
        argv = [
            str(INSTALLER.__file__),
            "rollback",
            "--backup-id",
            INSTALLER.LEGACY_V1_BACKUP_ID,
            "--dry-run",
            "--root",
            str(self.root),
        ]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(
            INSTALLER,
            "rollback",
            return_value=0,
        ) as rollback:
            with self.assertRaises(SystemExit) as exited:
                INSTALLER.main()
        self.assertEqual(exited.exception.code, 0)
        rollback.assert_called_once_with(
            INSTALLER.LEGACY_V1_BACKUP_ID,
            self.root.absolute(),
            dry_run=True,
        )

    def test_only_exact_legacy_backup_dispatches_to_the_v1_path(self) -> None:
        wrong = INSTALLER.LEGACY_V1_BACKUP_ID[:-2] + "0Z"
        before = tree_fingerprint(self.root)
        with mock.patch.dict(os.environ, {"MGACT_TESTING": "1"}):
            with self.assertRaisesRegex(ValueError, "only supports the exact legacy v1 backup"):
                INSTALLER.rollback(wrong, self.root, dry_run=True)
        self.assertEqual(tree_fingerprint(self.root), before)

    def test_wrong_receipt_and_incomplete_backup_inventory_fail_closed(self) -> None:
        original = self.receipt.read_bytes()
        self.receipt.write_bytes(original + b" ")
        self.receipt.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "receipt hash mismatch"):
            self.rollback(dry_run=True)
        self.receipt.write_bytes(original)
        self.receipt.chmod(0o600)
        extra = self.backup / "files/unexpected"
        write_file(extra, b"unexpected\n", 0o600)
        with self.assertRaisesRegex(ValueError, "backup file inventory mismatch"):
            self.rollback(dry_run=True)
        self.assertFalse(self.recovery_claim().exists())

    def test_consumed_acceptance_claim_and_installed_drift_are_validated(self) -> None:
        acceptance_claim = self.root / INSTALLER.LEGACY_V1_CLAIM.lstrip("/")
        original_claim = acceptance_claim.read_bytes()
        acceptance_claim.write_bytes(b"{}\n")
        acceptance_claim.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "consumed acceptance claim mismatch"):
            self.rollback(dry_run=True)
        acceptance_claim.write_bytes(original_claim)
        acceptance_claim.chmod(0o600)
        drifted_target = INSTALLER.LEGACY_V1_CHANGED_TARGETS[0]
        drifted = self.root / drifted_target.lstrip("/")
        drifted.write_bytes(b"drift\n")
        with self.assertRaisesRegex(ValueError, "installed target drift"):
            self.rollback(dry_run=True)
        installed_record = INSTALLER.LEGACY_V1_INSTALLED[drifted_target]
        drifted.write_bytes(self.installed_payloads[drifted_target])
        drifted.chmod(int(str(installed_record["mode"]), 8) ^ 0o040)
        with self.assertRaisesRegex(ValueError, "installed target drift"):
            self.rollback(dry_run=True)
        drifted.chmod(int(str(installed_record["mode"]), 8))

        original_require_regular = INSTALLER.require_regular

        def require_with_owner_drift(path, **kwargs):
            metadata = original_require_regular(path, **kwargs)
            if Path(path) != drifted:
                return metadata
            changed = mock.Mock()
            changed.st_mode = metadata.st_mode
            changed.st_nlink = metadata.st_nlink
            changed.st_uid = metadata.st_uid + 1
            changed.st_gid = metadata.st_gid
            return changed

        with mock.patch.object(
            INSTALLER,
            "require_regular",
            side_effect=require_with_owner_drift,
        ):
            with self.assertRaisesRegex(ValueError, "installed target drift"):
                self.rollback(dry_run=True)
        self.assertFalse(self.recovery_claim().exists())

    def test_service_state_is_validated_before_legacy_recovery(self) -> None:
        before = tree_fingerprint(self.root)
        with mock.patch.object(
            INSTALLER,
            "service_blockers",
            return_value=["service must be stopped", "service must be disabled"],
        ):
            with self.assertRaisesRegex(ValueError, "service must be stopped"):
                self.rollback(dry_run=True)
        self.assertEqual(tree_fingerprint(self.root), before)
        self.assertFalse(self.recovery_claim().exists())

    def test_success_restores_exactly_ten_targets_and_claim_blocks_reuse(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(self.rollback(), 0)
        self.assertIn("LEGACY_V1_ROLLED_BACK", output.getvalue())
        self.assertEqual(len(INSTALLER.LEGACY_V1_CHANGED_TARGETS), 10)
        for target_text in INSTALLER.LEGACY_V1_CHANGED_TARGETS:
            destination = self.root / target_text.lstrip("/")
            self.assertEqual(destination.read_bytes(), self.previous_payloads[target_text])
        self.assertTrue(self.recovery_claim().is_file())
        with self.assertRaisesRegex(ValueError, "already claimed"):
            self.rollback()

    def test_partial_restore_is_detected_and_remains_single_use(self) -> None:
        def restore_only_nine(changed, previous, backup, root):
            for state in changed[:9]:
                record = previous[state.target.target]
                INSTALLER.atomic_restore(
                    backup / "files" / str(record["backup_name"]),
                    state,
                    int(str(record["mode"]), 8),
                    int(record["uid"]),
                    int(record["gid"]),
                    root,
                )

        with mock.patch.object(INSTALLER, "restore_targets", side_effect=restore_only_nine):
            with self.assertRaisesRegex(ValueError, "restore verification failed"):
                self.rollback()
        self.assertTrue(self.recovery_claim().is_file())
        last = INSTALLER.LEGACY_V1_CHANGED_TARGETS[-1]
        self.assertEqual(
            (self.root / last.lstrip("/")).read_bytes(),
            self.installed_payloads[last],
        )
        with self.assertRaisesRegex(ValueError, "already claimed"):
            self.rollback()

    def test_atomic_restore_failure_claims_before_any_target_write(self) -> None:
        with mock.patch.object(
            INSTALLER,
            "atomic_restore",
            side_effect=OSError("injected atomic restore failure"),
        ):
            with self.assertRaisesRegex(OSError, "injected atomic restore failure"):
                self.rollback()
        self.assertTrue(self.recovery_claim().is_file())
        for target_text in INSTALLER.LEGACY_V1_CHANGED_TARGETS:
            destination = self.root / target_text.lstrip("/")
            self.assertEqual(destination.read_bytes(), self.installed_payloads[target_text])


class ServiceGateTests(unittest.TestCase):
    def test_stopped_service_gate_requires_persistent_state_and_prestart_checks_runtime(
        self,
    ) -> None:
        verifier = (REPO_ROOT / "scripts/mempool-genesis/verify-installed-agent").read_text()
        for slug in ("mempool", "genesis"):
            with self.subTest(slug=slug):
                expected_user = f"buzz-{slug}"
                self.assertEqual(
                    list(INSTALLER.IDENTITY_STATE_MODES[slug]),
                    [
                        f"/home/{expected_user}",
                        f"/home/{expected_user}/.codex",
                        f"/home/{expected_user}/.config",
                        f"/home/{expected_user}/.cache",
                        f"/home/{expected_user}/.local/state",
                        f"/home/{expected_user}/.local/state/buzz-acp",
                        f"/home/{expected_user}/.tmp",
                    ],
                )
                self.assertNotIn(
                    f"/run/buzz-agents-{slug}", INSTALLER.IDENTITY_STATE_MODES[slug]
                )
        self.assertIn('  "/run/buzz-agents-$slug"\n', verifier)
        self.assertIn('for state_path in "${state_paths[@]}"; do\n', verifier)
        self.assertIn(
            'expected_acp_state_dir="/home/$expected_user/.local/state/buzz-acp"\n',
            verifier,
        )
        self.assertIn(
            'test "$(grep -c \'^BUZZ_ACP_STATE_DIR=\' "$env_file")" = 1\n', verifier
        )
        self.assertIn(
            'test "${BUZZ_ACP_STATE_DIR:?missing BUZZ_ACP_STATE_DIR}" = '
            '"$expected_acp_state_dir"\n', verifier
        )

    def test_identity_runtime_preflight_accepts_exact_metadata_access_and_tools(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_ROOT) as temporary:
            state_path = Path(temporary)
            state_path.chmod(0o700)
            account = SimpleNamespace(
                pw_dir="/home/buzz-mempool",
                pw_uid=os.getuid(),
                pw_gid=os.getgid(),
            )

            def accessible(_user: str, *command: str) -> subprocess.CompletedProcess[str]:
                output = ""
                if command[0:2] == ("/usr/bin/readlink", "-e"):
                    output = f"{command[-1]}\n"
                elif command[0] == "/usr/bin/python3":
                    output = "/usr/local/libexec/buzz/codex\n"
                return subprocess.CompletedProcess(command, 0, output, "")

            with mock.patch.object(
                INSTALLER, "IDENTITY_STATE_MODES", {"mempool": {str(state_path): 0o700}}
            ), mock.patch.object(
                INSTALLER, "ROOT_TOOL_PATHS", ("/usr/local/libexec/buzz/codex",)
            ), mock.patch.object(
                INSTALLER,
                "ROOT_PATH_COMMANDS",
                (("codex", "/usr/local/libexec/buzz/codex"),),
            ), mock.patch.object(
                INSTALLER.pwd, "getpwnam", return_value=account
            ), mock.patch.object(
                INSTALLER, "identity_command", side_effect=accessible
            ):
                self.assertEqual(INSTALLER.identity_runtime_blockers(), [])

    def test_identity_runtime_preflight_reports_metadata_access_and_resolution_drift(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_ROOT) as temporary:
            state_path = Path(temporary)
            state_path.chmod(0o755)
            account = SimpleNamespace(
                pw_dir="/home/buzz-mempool",
                pw_uid=os.getuid(),
                pw_gid=os.getgid(),
            )

            def blocked(_user: str, *command: str) -> subprocess.CompletedProcess[str]:
                if command[0] == "/usr/bin/readlink":
                    return subprocess.CompletedProcess(command, 0, "/unexpected/tool\n", "")
                if command[0] == "/usr/bin/python3":
                    return subprocess.CompletedProcess(command, 0, "/unexpected/tool\n", "")
                if command[0:2] == ("/usr/bin/test", "-w"):
                    return subprocess.CompletedProcess(command, 1, "", "denied")
                return subprocess.CompletedProcess(command, 0, "", "")

            with mock.patch.object(
                INSTALLER, "IDENTITY_STATE_MODES", {"mempool": {str(state_path): 0o700}}
            ), mock.patch.object(
                INSTALLER, "ROOT_TOOL_PATHS", ("/usr/local/libexec/buzz/codex",)
            ), mock.patch.object(
                INSTALLER,
                "ROOT_PATH_COMMANDS",
                (("codex", "/usr/local/libexec/buzz/codex"),),
            ), mock.patch.object(
                INSTALLER.pwd, "getpwnam", return_value=account
            ), mock.patch.object(
                INSTALLER, "identity_command", side_effect=blocked
            ):
                blockers = INSTALLER.identity_runtime_blockers()
        self.assertTrue(any("mode mismatch" in blocker for blocker in blockers))
        self.assertTrue(any("lacks write access" in blocker for blocker in blockers))
        self.assertTrue(any("resolution mismatch" in blocker for blocker in blockers))
        self.assertTrue(any("PATH resolution mismatch" in blocker for blocker in blockers))

    def test_wrong_host_blocks_real_root(self) -> None:
        def stopped(action: str, _unit: str) -> tuple[int, str]:
            return (3, "inactive") if action == "is-active" else (1, "disabled")

        with mock.patch.object(INSTALLER, "host_name", return_value="wrong-host"), mock.patch.object(
            INSTALLER.os, "geteuid", return_value=0
        ), mock.patch.object(INSTALLER, "systemctl_readback", side_effect=stopped):
            blockers = INSTALLER.service_blockers(Path("/"))
        self.assertIn("real-root operation requires framework-desktop", blockers)

    def test_active_or_enabled_service_blocks_real_root(self) -> None:
        def active(action: str, unit: str) -> tuple[int, str]:
            if unit.endswith("mempool.service") and action == "is-active":
                return 0, "active"
            if unit.endswith("genesis.service") and action == "is-enabled":
                return 0, "enabled"
            return (3, "inactive") if action == "is-active" else (1, "disabled")

        with mock.patch.object(INSTALLER, "host_name", return_value="framework-desktop"), mock.patch.object(
            INSTALLER.os, "geteuid", return_value=0
        ), mock.patch.object(INSTALLER, "systemctl_readback", side_effect=active):
            blockers = INSTALLER.service_blockers(Path("/"))
        self.assertTrue(any("service must be stopped" in blocker for blocker in blockers))
        self.assertTrue(any("service must be disabled" in blocker for blocker in blockers))


class SweepCandidateTests(PackageFixture):
    def setUp(self) -> None:
        super().setUp()
        self.bundle, _manifest = self.generate("sweep")
        self.script = self.bundle / "ops-root/home/victor/.agents/tools/buzz-sats-channel-sweep.sh"
        self.tools = self.root / "tools"
        self.tools.mkdir(mode=0o700)
        (self.tools / "nostr_min.py").write_text(
            "def pubkey_xonly(value):\n"
            "    return bytes.fromhex('9' * 64) if value == bytes.fromhex('d' * 64) "
            f"else bytes.fromhex('{GENERATOR.OWNER_PUBKEY}')\n"
        )
        self.secret_dir = self.root / "secret"
        self.secret_dir.mkdir(mode=0o700)
        self.secret_file = self.secret_dir / "secrets.env"
        self.owner_private = "a" * 64
        self.mempool_private = "b" * 64
        self.genesis_private = "c" * 64
        self.codexr_private = "d" * 64
        self.secret_file.write_text(
            f"BUZZ_OWNER_PRIVATE_KEY={self.owner_private}\n"
            f"BUZZ_SATS_MEMPOOL_PRIVATE_KEY={self.mempool_private}\n"
            f"BUZZ_SATS_GENESIS_PRIVATE_KEY={self.genesis_private}\n"
            f"BUZZ_SATS_CODEX_R_PRIVATE_KEY={self.codexr_private}\n"
        )
        self.secret_file.chmod(0o600)
        self.state_file = self.root / "state.json"
        write_private_json(
            self.state_file,
            {
                "writes": 0,
                "seen_private_keys": [],
                "channels": {
                    "11111111-1111-1111-1111-111111111111": [
                        {"pubkey": GENERATOR.OWNER_PUBKEY, "role": "owner"},
                        {"pubkey": "9" * 64, "role": "member"}
                    ],
                    "22222222-2222-2222-2222-222222222222": [
                        {"pubkey": GENERATOR.OWNER_PUBKEY, "role": "owner"},
                        {"pubkey": "9" * 64, "role": "member"}
                    ],
                    "44444444-4444-4444-4444-444444444444": [
                        {"pubkey": GENERATOR.OWNER_PUBKEY, "role": "admin"},
                        {"pubkey": "9" * 64, "role": "member"}
                    ],
                },
            },
        )
        self.skip = self.root / "skip"
        self.skip.write_text("11111111-1111-1111-1111-111111111111\n")
        self.buzz = self.root / "buzz-mock.py"
        self.buzz.write_text(
            "#!/usr/bin/env python3\n"
            "import json,os,sys\n"
            "path=os.environ['SWEEP_STATE']\n"
            "state=json.load(open(path))\n"
            "key=os.environ.get('BUZZ_PRIVATE_KEY','')\n"
            "state['seen_private_keys'].append(key)\n"
            "json.dump(state,open(path,'w'))\n"
            "args=sys.argv[1:]\n"
            "if args[:4] == ['channels','list','--visibility','open']:\n"
            " print(json.dumps([\n"
            "  {'channel_id':'11111111-1111-1111-1111-111111111111','name':'one','archived':False},\n"
            "  {'channel_id':'22222222-2222-2222-2222-222222222222','name':'two','archived':False},\n"
            "  {'channel_id':'33333333-3333-3333-3333-333333333333','name':'old','archived':True}]))\n"
            "elif args[:5] == ['channels','list','--visibility','private','--member']:\n"
            " print(json.dumps([{'channel_id':'44444444-4444-4444-4444-444444444444','name':'private','archived':False}]))\n"
            "elif args[:2] == ['channels','members']:\n"
            " cid=args[args.index('--channel')+1]; print(json.dumps(state['channels'][cid]))\n"
            "elif args[:2] == ['channels','add-member']:\n"
            " if os.environ.get('SWEEP_LEAK') == '1':\n"
            "  print('nsec1SECRET '+key, file=sys.stderr); raise SystemExit(1)\n"
            " cid=args[args.index('--channel')+1]; target=args[args.index('--pubkey')+1]; role=args[args.index('--role')+1]\n"
            " assert role == 'member'\n"
            " if not any(m['pubkey']==target for m in state['channels'][cid]):\n"
            "  state['channels'][cid].append({'pubkey':target,'role':role}); state['writes']+=1; json.dump(state,open(path,'w'))\n"
            " print(json.dumps({'accepted':True}))\n"
            "else: raise SystemExit('unexpected args: '+repr(args))\n"
        )
        self.buzz.chmod(0o755)

    def run_sweep(self, mode: str, **extra: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update(
            {
                "SATS_SECRET_FILE": str(self.secret_file),
                "SATS_TOOLS_DIR": str(self.tools),
                "SATS_SKIP_FILE": str(self.skip),
                "SATS_SWEEP_LOG": str(self.root / "sweep.log"),
                "BUZZ_BIN": str(self.buzz),
                "SWEEP_STATE": str(self.state_file),
                **extra,
            }
        )
        return subprocess.run(
            [str(self.script), mode],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
            timeout=60,
        )

    def test_fixed_public_roster_matches_codexr_open_and_private_membership(self) -> None:
        before = self.state_file.read_bytes()
        check = self.run_sweep("--check")
        self.assertEqual(check.returncode, 0, check.stderr)
        self.assertIn("PREFLIGHT OK", check.stdout)
        self.assertEqual(json.loads(before)["writes"], json.loads(self.state_file.read_text())["writes"])
        self.assertFalse((self.root / "sweep.log").exists())
        dry_run = self.run_sweep("--dry-run")
        self.assertEqual(dry_run.returncode, 0, dry_run.stderr)
        self.assertEqual(dry_run.stdout.count("PLAN owner add-member"), 4)
        self.assertNotIn("11111111-1111-1111-1111-111111111111", dry_run.stdout)
        self.assertIn("22222222-2222-2222-2222-222222222222", dry_run.stdout)
        self.assertIn("44444444-4444-4444-4444-444444444444", dry_run.stdout)
        self.assertNotIn("33333333-3333-3333-3333-333333333333", dry_run.stdout)
        self.assertEqual(json.loads(self.state_file.read_text())["writes"], 0)
        first = self.run_sweep("--mempool-genesis-apply")
        self.assertEqual(first.returncode, 0, first.stderr + first.stdout)
        state = json.loads(self.state_file.read_text())
        self.assertEqual(state["writes"], 4)
        self.assertTrue(state["seen_private_keys"])
        self.assertEqual(set(state["seen_private_keys"]), {self.owner_private})
        second = self.run_sweep("--mempool-genesis-apply")
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(json.loads(self.state_file.read_text())["writes"], 4)
        self.assertIn("planned=0 writes=0 already=4 blocked=0", second.stdout)

    def test_non_owner_or_admin_role_blocks_owner_authority(self) -> None:
        value = json.loads(self.state_file.read_text())
        for members in value["channels"].values():
            members[0]["role"] = "member"
        write_private_json(self.state_file, value)
        result = self.run_sweep("--dry-run")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("owner authority UNMET", result.stdout)
        self.assertNotIn("PLAN owner add-member", result.stdout)

    def test_failure_output_redacts_owner_private_key(self) -> None:
        result = self.run_sweep("--mempool-genesis-apply", SWEEP_LEAK="1")
        self.assertNotEqual(result.returncode, 0)
        output = result.stdout + result.stderr
        self.assertNotIn(self.owner_private, output)
        self.assertNotIn("nsec1SECRET", output)
        self.assertIn("<hex>", output)

    def test_full_sweep_private_key_loop_excludes_mempool_and_genesis_names(self) -> None:
        script = self.script.read_text()
        exclusion = "grep -vE '^BUZZ_SATS_(MEMPOOL|GENESIS)_PRIVATE_KEY$'"
        self.assertIn(exclusion, script)
        self.assertLess(script.index(exclusion), script.index("key=${!var}"))


if __name__ == "__main__":
    unittest.main()

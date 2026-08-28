from __future__ import annotations

import contextlib
import copy
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
TRANSACTION = load_module("mgact_activation_transaction", "activation-transaction.py")

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
TEST_MEMPOOL_PUBKEY = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
TEST_GENESIS_PUBKEY = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
TEST_ALT_MEMPOOL_PUBKEY = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
TEST_ALT_GENESIS_PUBKEY = "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13"


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


def write_inputs(
    path: Path,
    mempool: str,
    genesis: str,
    binding: str = GENERATOR.INPUT_BINDING_DESKTOP_SAVED,
) -> None:
    write_private_json(
        path,
        {
            "schema": GENERATOR.INPUT_SCHEMA,
            "identity_binding": binding,
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
        write_inputs(self.inputs, TEST_MEMPOOL_PUBKEY, TEST_GENESIS_PUBKEY)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def generate(
        self,
        name: str = "bundle",
        *,
        inputs: Path | None = None,
        allow_placeholders: bool = False,
    ) -> tuple[Path, dict[str, object]]:
        candidate_root = self.root / f"{name}-candidate"
        candidate_root.mkdir(mode=0o700)
        subprocess.run(
            ["git", "init", "-q", str(candidate_root)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        subprocess.run(
            ["git", "-C", str(candidate_root), "config", "user.name", "MGACT Test"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(candidate_root), "config", "user.email", "mgact-test.invalid"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(candidate_root), "commit", "-q", "--allow-empty", "-m", "base"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        output = candidate_root / "bundle"
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
        ledger_dir = self.root / f"{name}-tier2-ledger"
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
                "--claude-auth-source",
                "profile",
                "--controller",
                "mgact-test-controller",
                "--state-dir",
                str(state_dir),
                "--scope-id",
                f"mgact-test-{name}",
                "--scope-ledger-dir",
                str(ledger_dir),
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
        ledger_path = Path(str(state["ledger_path"]))
        ledger = json.loads(ledger_path.read_text())
        entry = next(
            item for item in ledger["lineages"] if item["lineage_id"] == state["lineage_id"]
        )
        entry["status"] = "passed" if verdict in {"PASS", "PASS WITH RISKS"} else "awaiting_revision2"
        entry["verdict"] = verdict
        write_private_json(ledger_path, ledger)
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
    def test_generator_rejects_policy_channel_injection_before_rendering(self) -> None:
        policy = json.loads(
            (ACTIVATION_DIR / "capability-parity-policy.json").read_text()
        )
        policy["eligible_channels"][0]["channel_id"] = (
            "03f28d12-d392-4147-a9d6-9f23426dcde0';touch injected;'"
        )
        with self.assertRaisesRegex(ValueError, "policy.*invalid|channel ID"):
            GENERATOR.validate_policy_for_generation(policy)
    def test_readme_reports_the_enforced_22_path_closure(self) -> None:
        readme = (REPO_ROOT / "scripts/mempool-genesis/activation/README.md").read_text()
        self.assertIn("installed closure inventory has exactly 22 paths", readme)
        self.assertNotIn("installed closure inventory still has exactly 18 paths", readme)

    def test_readme_sweep_examples_use_the_package_candidate_root(self) -> None:
        readme = (REPO_ROOT / "scripts/mempool-genesis/activation/README.md").read_text()
        package_sweep = (
            '"$PACKAGE_WT/candidate-final/ops-root/home/victor/.local/libexec/buzz/'
            'buzz-sats-channel-sweep"'
        )
        self.assertIn(f"{package_sweep} --check", readme)
        self.assertIn(f"{package_sweep} --dry-run", readme)
        self.assertNotIn('"$STAGE/candidate-final/ops-root/', readme)

    def test_readme_documents_separate_service_enablement_approval(self) -> None:
        readme = (REPO_ROOT / "scripts/mempool-genesis/activation/README.md").read_text()
        self.assertIn("Enabling is a separate live service mutation", readme)
        self.assertIn("does not authorize it", readme)
        self.assertIn("once when `default.target` is reached for each user-manager start", readme)
        self.assertIn("every such run loads Victor's sanctioned owner credential", readme)
        self.assertIn("With `loginctl enable-linger`", readme)
        self.assertIn("without an interactive login", readme)
        self.assertIn("Additional concurrent sessions do not", readme)
        self.assertIn("retrigger the unit", readme)
        self.assertNotIn("each applicable user-session start", readme)
        self.assertIn("installer deliberately does not enable the unit", readme)

    def test_readme_rollback_requires_all_three_services_stopped_and_disabled(self) -> None:
        readme = (REPO_ROOT / "scripts/mempool-genesis/activation/README.md").read_text()
        precondition = (
            "Roll back only while `buzz-agent@mempool.service`, "
            "`buzz-agent@genesis.service`, and the user unit "
            "`buzz-sats-channel-sweep.service` all remain stopped and disabled."
        )
        self.assertIn(precondition, readme)
        self.assertNotIn("Roll back only while both services remain stopped and disabled", readme)

    def test_readme_documents_linger_network_failure_and_no_retry_contract(self) -> None:
        readme = (REPO_ROOT / "scripts/mempool-genesis/activation/README.md").read_text()
        self.assertIn("no `network-online.target` readiness guarantee", readme)
        self.assertIn("linger boot run can occur before the relay is reachable", readme)
        self.assertIn("fails closed with a nonzero exit", readme)
        self.assertIn("never prints `PREFLIGHT OK`", readme)
        self.assertIn("does not retry automatically", readme)
        self.assertIn("separately designed and explicitly approved contract", readme)
        self.assertIn("None is included here", readme)

    def test_readme_names_selective_transaction_write_modes(self) -> None:
        readme = (REPO_ROOT / "scripts/mempool-genesis/activation/README.md").read_text()
        self.assertIn("The former combined mutation mode is rejected", readme)
        for mode in (
            "--mempool-apply STATE",
            "--mempool-complete STATE GATE",
            "--genesis-apply STATE",
            "--genesis-complete STATE GATE",
        ):
            self.assertIn(mode, readme)

    def test_adapter_required_route_summary_binds_profile_auth(self) -> None:
        readme = (REPO_ROOT / "scripts/mempool-genesis/activation/README.md").read_text()
        self.assertIn(
            "route `claude`, `claude-opus-5`, `high`, with `auth_source=profile`",
            readme,
        )

    def test_generator_is_deterministic_and_emits_exact_review_inventory(self) -> None:
        first, manifest = self.generate("first")
        second, second_manifest = self.generate("second")
        self.assertEqual(manifest, second_manifest)
        self.assertEqual(tree_fingerprint(first), tree_fingerprint(second))
        self.assertTrue(manifest["ready_for_parent_tier1"])
        self.assertFalse(manifest["installable"])
        self.assertEqual(len(manifest["runtime_targets"]), 25)
        self.assertEqual(len(manifest["ops_targets"]), 4)
        sweep = (
            first / "ops-root/home/victor/.local/libexec/buzz/buzz-sats-channel-sweep"
        ).read_text()
        channel_policy = json.loads(
            (ACTIVATION_DIR / "capability-parity-policy.json").read_text()
        )["eligible_channels"]
        policy = json.loads(
            (ACTIVATION_DIR / "capability-parity-policy.json").read_text()
        )
        self.assertEqual(len(channel_policy), 25)
        self.assertEqual(len(policy["reference_channels"]), 26)
        self.assertEqual(len(policy["authority_exclusions"]), 1)
        self.assertTrue(all(channel["channel_id"] in sweep for channel in channel_policy))
        rendered_channel_lines = [
            line.strip() for line in sweep.splitlines()
            if line.strip() in {channel["channel_id"] for channel in channel_policy}
        ]
        self.assertEqual(rendered_channel_lines, [channel["channel_id"] for channel in channel_policy])
        self.assertNotIn("__MG_CHANNEL_ALLOWLIST__", sweep)
        self.assertNotIn("__MG_AUTHORITY_EXCLUSIONS__", sweep)
        self.assertEqual(manifest["identity_binding"], GENERATOR.INPUT_BINDING_DESKTOP_SAVED)
        self.assertEqual(manifest["input_status"], "complete")
        for slug in ("mempool", "genesis"):
            self.assertEqual(len(manifest["review_files"][slug]), 22)
            self.assertEqual(
                [entry["path"] for entry in manifest["review_files"][slug]],
                manifest["expected_closure_paths"][slug],
            )
        self.assertEqual(manifest["tier2_review"], GENERATOR.TIER2_REVIEW)
        self.assertEqual(manifest["tier2_engine"]["mode"], "0755")
        self.assertEqual(manifest["tier2_engine"]["sha256"], GENERATOR.TIER2_ENGINE_SHA256)
        self.assertEqual(
            manifest["tier2_engine"]["source_commit"],
            GENERATOR.TIER2_ENGINE_SOURCE_COMMIT,
        )
        self.assertEqual(
            manifest["tier2_engine"]["source_tree"],
            GENERATOR.TIER2_ENGINE_SOURCE_TREE,
        )
        with self.assertRaisesRegex(ValueError, "Tier 2 engine mode mismatch"):
            PREFLIGHT.validate_tier2_engine(
                {**manifest["tier2_engine"], "mode": "0700"}
            )
        self.assertEqual(
            manifest["tier2_review"],
            {
                "producer_provider": "gpt",
                "reviewer_provider": "claude",
                "model": "claude-opus-5",
                "effort": "high",
                "auth_source": "profile",
                "engine_subcommands": ["prepare", "review", "check"],
            },
        )
        self.assertEqual(manifest["tier2_evidence_schema"], "tier2-evidence-v3")
        self.assertEqual(
            manifest["tier2_engine"],
            {
                "path": "/home/victor/.agents/skills/codex-review/scripts/tier2",
                "mode": "0755",
                "sha256": "10222c7a28c71232d65695562d28f68b158307bbac0e6f0c0e67bd8c57a08ef0",
                "source_commit": "8614f91296a8258ddba1c37d6ad0fd72b172619f",
                "source_tree": "d7ab1633c3bcf1e64b1725e82fd84470ceafe3c6",
            },
        )
        for validator in (PREFLIGHT, INSTALLER):
            self.assertEqual(validator.TIER2_ENGINE_SHA256, GENERATOR.TIER2_ENGINE_SHA256)
            self.assertEqual(
                validator.TIER2_ENGINE_SOURCE_COMMIT,
                GENERATOR.TIER2_ENGINE_SOURCE_COMMIT,
            )
            self.assertEqual(
                validator.TIER2_ENGINE_SOURCE_TREE,
                GENERATOR.TIER2_ENGINE_SOURCE_TREE,
            )
        self.assertEqual(
            PREFLIGHT.validate_tier2_engine(manifest["tier2_engine"]),
            manifest["tier2_engine"],
        )
        self.assertEqual(
            INSTALLER.tier2_engine_record(manifest),
            manifest["tier2_engine"],
        )
        tampered_engine = dict(manifest["tier2_engine"])
        tampered_engine["mode"] = "0750"
        with self.assertRaisesRegex(ValueError, "mode mismatch"):
            PREFLIGHT.validate_tier2_engine(tampered_engine)
        tampered_engine = dict(manifest["tier2_engine"])
        tampered_engine["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "reviewed fleet source"):
            PREFLIGHT.validate_tier2_engine(tampered_engine)
        tampered_engine = dict(manifest["tier2_engine"])
        tampered_engine["source_commit"] = "0" * 40
        with self.assertRaisesRegex(ValueError, "source commit mismatch"):
            PREFLIGHT.validate_tier2_engine(tampered_engine)
        tampered_engine = dict(manifest["tier2_engine"])
        tampered_engine["source_tree"] = "0" * 40
        with self.assertRaisesRegex(ValueError, "source tree mismatch"):
            PREFLIGHT.validate_tier2_engine(tampered_engine)
        self.assertEqual(
            manifest["tier2_candidate_paths"],
            sorted(
                [str(record["source"]) for record in manifest["runtime_targets"]]
                + [str(record["source"]) for record in manifest["ops_targets"]]
                + ["bundle-manifest.json", "input-contract.json", "metadata/review-files.json"],
                key=str.encode,
            ),
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
        parity = manifest["capability_parity"]
        self.assertEqual(parity["owner_signer_target"], "/home/victor/.agents/tools/buzz-parity-owner-signer")
        self.assertEqual(parity["owner_verifier_target"], "/home/victor/.agents/tools/buzz-parity-owner-verifier")
        self.assertEqual(parity["payload_transport"], "anonymous-pipe-stdin")
        self.assertEqual(parity["owner_private_input"]["mode"], "0600")
        self.assertEqual(set(parity["no_af_netlink"]), {"template", "mempool_dropin", "genesis_dropin"})
        self.assertRegex(parity["eligible_channels_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(parity["reference_channels"], policy["reference_channels"])
        self.assertEqual(parity["eligible_channels"], policy["eligible_channels"])
        self.assertEqual(parity["authority_exclusions"], policy["authority_exclusions"])
        self.assertEqual(parity["canonical_json_contract"], "buzz-canonical-json-ascii-v1")
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
                ["git", "write-tree"],
                cwd=REPO_ROOT,
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            ).stdout.strip(),
        )
        self.assertEqual(len(manifest["ops_targets"]), 4)
        service = next(
            record
            for record in manifest["ops_targets"]
            if record["target"].endswith("buzz-sats-channel-sweep.service")
        )
        service_path = first / service["source"]
        self.assertEqual(hashlib.sha256(service_path.read_bytes()).hexdigest(), service["sha256"])
        self.assertIn(
            "ExecStart=/home/victor/.local/libexec/buzz/buzz-sats-channel-sweep --check",
            service_path.read_text(),
        )
        self.assertEqual(
            manifest["acp_state_dirs"],
            {
                "mempool": "/home/buzz-mempool/.local/state/buzz-acp",
                "genesis": "/home/buzz-genesis/.local/state/buzz-acp",
            },
        )
        for slug, public_key in (
            ("mempool", TEST_MEMPOOL_PUBKEY),
            ("genesis", TEST_GENESIS_PUBKEY),
        ):
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
            "uppercase": (TEST_MEMPOOL_PUBKEY.upper(), TEST_GENESIS_PUBKEY, "lowercase"),
            "short": (TEST_MEMPOOL_PUBKEY[:-1], TEST_GENESIS_PUBKEY, "64 lowercase"),
            "repeated-mempool": ("1" * 64, TEST_GENESIS_PUBKEY, "repeated-nibble"),
            "repeated-genesis": (TEST_MEMPOOL_PUBKEY, "2" * 64, "repeated-nibble"),
            "equal": (TEST_MEMPOOL_PUBKEY, TEST_MEMPOOL_PUBKEY, "must differ"),
            "reserved": (GENERATOR.OWNER_PUBKEY, TEST_GENESIS_PUBKEY, "assignment-roster"),
            "invalid-curve": (
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
                TEST_GENESIS_PUBKEY,
                "valid secp256k1",
            ),
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
                '"identity_binding":"desktop-saved",'
                '"mempool_pubkey":"' + TEST_MEMPOOL_PUBKEY + '",'
                '"mempool_pubkey":"' + TEST_ALT_MEMPOOL_PUBKEY + '",'
                '"genesis_pubkey":"' + TEST_GENESIS_PUBKEY + '"}\n'
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

    def test_unbound_placeholder_and_missing_inputs_fail_before_package_write(self) -> None:
        write_inputs(
            self.inputs,
            GENERATOR.PLACEHOLDERS["mempool"],
            GENERATOR.PLACEHOLDERS["genesis"],
            binding=GENERATOR.INPUT_BINDING_PENDING,
        )
        for allow_placeholders in (False, True):
            output = self.root / f"placeholder-{allow_placeholders}"
            with self.assertRaisesRegex(ValueError, "not explicitly bound"):
                GENERATOR.generate(
                    self.inputs,
                    output,
                    self.system_root,
                    REPO_ROOT,
                    allow_placeholders,
                    False,
                )
            self.assertFalse(output.exists())

        missing = self.root / "missing.json"
        write_private_json(
            missing,
            {
                "schema": GENERATOR.INPUT_SCHEMA,
                "identity_binding": GENERATOR.INPUT_BINDING_DESKTOP_SAVED,
                "mempool_pubkey": TEST_MEMPOOL_PUBKEY,
            },
        )
        missing_output = self.root / "missing-output"
        with self.assertRaisesRegex(ValueError, "wrong fields"):
            GENERATOR.generate(
                missing,
                missing_output,
                self.system_root,
                REPO_ROOT,
                False,
                False,
            )
        self.assertFalse(missing_output.exists())

    def test_templates_bind_exact_allowlist_host_and_memory_boundary(self) -> None:
        bundle, manifest = self.generate()
        for slug in ("mempool", "genesis"):
            env = (bundle / f"install-root/etc/buzz-agents/{slug}.env").read_text()
            values = dict(line.split("=", 1) for line in env.splitlines())
            self.assertEqual(values["BUZZ_ACP_RESPOND_TO"], "allowlist")
            self.assertEqual(
                values["BUZZ_ACP_RESPOND_TO_ALLOWLIST"], GENERATOR.OWNER_PUBKEY
            )
            self.assertEqual(values["BUZZ_ACP_ALLOWED_RESPOND_TO"], "allowlist")
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
                for record in manifest["runtime_targets"]
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
            self.assertNotIn("moves that Claude leg to Claude Fable 5", prompt)
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
        for prefix in (b" ", b"\t"):
            with self.subTest(prefix=prefix), self.assertRaisesRegex(
                ValueError, "systemd-equivalent leading whitespace"
            ):
                GENERATOR.validate_env(
                    genesis_env + prefix + b"BUZZ_ACP_RESPOND_TO=everyone\n",
                    "genesis",
                )

    def test_simple_env_grammar_rejects_systemd_quoting_and_continuations(self) -> None:
        response_line = b"BUZZ_ACP_RESPOND_TO=allowlist\n"
        for slug in ("mempool", "genesis"):
            payload = (ACTIVATION_DIR / f"templates/{slug}.env").read_bytes()
            cases = {
                "multiline double quote": payload.replace(
                    response_line,
                    b'UNRELATED="open\n' + response_line + b'CLOSE=value"\n',
                    1,
                ),
                "backslash continuation": payload.replace(
                    response_line,
                    b"UNRELATED=continued\\\n" + response_line,
                    1,
                ),
                "unbalanced double quote": payload + b'UNRELATED="unterminated\n',
                "single quoted value": payload + b"UNRELATED='unsupported'\n",
                "escaped quote": payload + b'UNRELATED="escaped\\\"quote"\n',
                "embedded unquoted whitespace": payload + b"UNRELATED=two words\n",
                "carriage return": payload.replace(b"\n", b"\r\n", 1),
                "nul control": payload + b"UNRELATED=value\x00\n",
                "delete control": payload + b"UNRELATED=value\x7f\n",
                "non-ASCII byte": payload + b"UNRELATED=value\x80\n",
            }
            for label, invalid in cases.items():
                with self.subTest(slug=slug, syntax=label), self.assertRaisesRegex(
                    ValueError, "unsupported|reviewed ASCII grammar|control syntax"
                ):
                    GENERATOR.validate_env(invalid, slug)

    def test_prestart_response_contract_matches_both_envs_and_rejects_drift(self) -> None:
        verifier = REPO_ROOT / "scripts/mempool-genesis/verify-installed-agent"
        policy = ACTIVATION_DIR / "capability-parity-policy.json"
        expected_owner = GENERATOR.OWNER_PUBKEY.encode()
        for slug in ("mempool", "genesis"):
            source = ACTIVATION_DIR / f"templates/{slug}.env"
            valid = subprocess.run(
                [
                    "/usr/bin/bash",
                    str(verifier),
                    "--verify-response-contract",
                    str(source),
                    str(policy),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            )
            self.assertEqual(valid.returncode, 0, valid.stderr.decode())

            payload = source.read_bytes()
            drift_cases = {
                "respond-to mode": payload.replace(
                    b"BUZZ_ACP_RESPOND_TO=allowlist",
                    b"BUZZ_ACP_RESPOND_TO=owner-only",
                    1,
                ),
                "allowed-respond-to mode": payload.replace(
                    b"BUZZ_ACP_ALLOWED_RESPOND_TO=allowlist",
                    b"BUZZ_ACP_ALLOWED_RESPOND_TO=owner-only",
                    1,
                ),
                "owner allowlist": payload.replace(
                    b"BUZZ_ACP_RESPOND_TO_ALLOWLIST=" + expected_owner,
                    b"BUZZ_ACP_RESPOND_TO_ALLOWLIST=" + b"0" * 64,
                    1,
                ),
                "missing allowlist": payload.replace(
                    b"BUZZ_ACP_RESPOND_TO_ALLOWLIST=" + expected_owner + b"\n",
                    b"",
                    1,
                ),
                "duplicate allowlist": (
                    payload + b"BUZZ_ACP_RESPOND_TO_ALLOWLIST=" + expected_owner + b"\n"
                ),
                "space-prefixed duplicate respond-to": payload
                + b" BUZZ_ACP_RESPOND_TO=everyone\n",
                "tab-prefixed duplicate allowed-respond-to": payload
                + b"\tBUZZ_ACP_ALLOWED_RESPOND_TO=everyone\n",
                "multiline double quote": payload.replace(
                    b"BUZZ_ACP_RESPOND_TO=allowlist\n",
                    b'UNRELATED="open\nBUZZ_ACP_RESPOND_TO=allowlist\nCLOSE=value"\n',
                    1,
                ),
                "backslash continuation": payload.replace(
                    b"BUZZ_ACP_RESPOND_TO=allowlist\n",
                    b"UNRELATED=continued\\\nBUZZ_ACP_RESPOND_TO=allowlist\n",
                    1,
                ),
                "unbalanced double quote": payload + b'UNRELATED="unterminated\n',
                "single quoted value": payload + b"UNRELATED='unsupported'\n",
                "escaped quote": payload + b'UNRELATED="escaped\\\"quote"\n',
                "nul control": payload + b"UNRELATED=value\x00\n",
                "delete control": payload + b"UNRELATED=value\x7f\n",
                "non-ASCII byte": payload + b"UNRELATED=value\x80\n",
            }
            for label, drifted_payload in drift_cases.items():
                with self.subTest(slug=slug, drift=label):
                    drifted = self.root / f"{slug}-{label.replace(' ', '-')}.env"
                    write_file(drifted, drifted_payload, 0o600)
                    rejected = subprocess.run(
                        [
                            "/usr/bin/bash",
                            str(verifier),
                            "--verify-response-contract",
                            str(drifted),
                            str(policy),
                        ],
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                    )
                    self.assertNotEqual(rejected.returncode, 0)

        drifted_policy_value = json.loads(policy.read_text())
        drifted_policy_value["response_policy"]["respond_to"] = "owner-only"
        drifted_policy = self.root / "response-policy-drift.json"
        write_private_json(drifted_policy, drifted_policy_value)
        for slug in ("mempool", "genesis"):
            source = ACTIVATION_DIR / f"templates/{slug}.env"
            rejected = subprocess.run(
                [
                    "/usr/bin/bash",
                    str(verifier),
                    "--verify-response-contract",
                    str(source),
                    str(drifted_policy),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            )
            self.assertNotEqual(rejected.returncode, 0)

    def test_package_worktree_requires_full_reviewed_source_commit(self) -> None:
        readme = (ACTIVATION_DIR / "README.md").read_text()
        self.assertNotRegex(readme, r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])")
        self.assertIn(
            ': "${FULL_REVIEWED_SOURCE_COMMIT:?set to the full reviewed source commit}"',
            readme,
        )
        self.assertIn('if [ "${#FULL_REVIEWED_SOURCE_COMMIT}" -ne 40 ]', readme)
        self.assertIn('*[!0-9a-f]*)', readme)
        self.assertIn('"${FULL_REVIEWED_SOURCE_COMMIT}^{commit}"', readme)
        self.assertIn(
            'worktree add --detach "$PACKAGE_WT" "$FULL_REVIEWED_SOURCE_COMMIT"',
            readme,
        )
        self.assertIn(
            'echo "failed to create package worktree from '
            'FULL_REVIEWED_SOURCE_COMMIT" >&2',
            readme,
        )
        self.assertIn('if [ "$PACKAGE_HEAD" != "$FULL_REVIEWED_SOURCE_COMMIT" ]', readme)
        self.assertIn(
            'echo "package worktree HEAD mismatch; refusing to continue" >&2',
            readme,
        )

    def test_package_worktree_runbook_block_fails_closed(self) -> None:
        readme = (ACTIVATION_DIR / "README.md").read_text()
        block = readme.split("```sh\n", 1)[1].split("\n```", 1)[0]
        mock_bin = self.root / "runbook-bin"
        mock_bin.mkdir(mode=0o700)
        write_file(
            mock_bin / "git",
            b"""#!/bin/sh
case "$*" in
  *" cat-file -e "*) exit 0 ;;
  *" worktree add "*)
    if [ "${RUNBOOK_GIT_MODE:-}" = add-fail ]; then exit 12; fi
    exit 0
    ;;
  *" rev-parse HEAD")
    if [ "${RUNBOOK_GIT_MODE:-}" = head-fail ]; then exit 13; fi
    printf '%s\\n' "${RUNBOOK_HEAD:-}"
    exit 0
    ;;
esac
exit 14
""",
            0o755,
        )
        write_file(mock_bin / "install", b"#!/bin/sh\nexit 0\n", 0o755)
        reviewed = "a" * 40

        def run(mode: str, head: str) -> subprocess.CompletedProcess[bytes]:
            return subprocess.run(
                ["/bin/sh"],
                input=block.encode(),
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={
                    "PATH": str(mock_bin),
                    "FULL_REVIEWED_SOURCE_COMMIT": reviewed,
                    "RUNBOOK_GIT_MODE": mode,
                    "RUNBOOK_HEAD": head,
                },
            )

        accepted = run("ok", reviewed)
        self.assertEqual(accepted.returncode, 0, accepted.stderr.decode())

        add_failed = run("add-fail", reviewed)
        self.assertNotEqual(add_failed.returncode, 0)
        self.assertIn(b"failed to create package worktree", add_failed.stderr)

        head_failed = run("head-fail", reviewed)
        self.assertNotEqual(head_failed.returncode, 0)
        self.assertIn(b"failed to read package worktree HEAD", head_failed.stderr)

        mismatched = run("ok", "b" * 40)
        self.assertNotEqual(mismatched.returncode, 0)
        self.assertIn(b"package worktree HEAD mismatch", mismatched.stderr)

    def test_runbook_shell_and_path_state_contract_is_consistent(self) -> None:
        readme = (ACTIVATION_DIR / "README.md").read_text()
        blocks = [part.split("\n```", 1)[0] for part in readme.split("```sh\n")[1:]]
        syntax = subprocess.run(
            ["/bin/sh", "-n"],
            input="\n".join(blocks).encode(),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr.decode())

        self.assertIn('PACKAGE_DIR="$PACKAGE_WT/candidate-final"', readme)
        self.assertGreaterEqual(readme.count('$PACKAGE_WT/candidate-final'), 3)
        self.assertNotIn('$STAGE/candidate-final', readme)
        self.assertIn('--output "$PACKAGE_DIR"', readme)
        self.assertIn('--bundle-manifest "$PACKAGE_DIR/bundle-manifest.json"', readme)
        self.assertIn(
            '"$PACKAGE_WT/candidate-final/ops-root/home/victor/.local/libexec/buzz/'
            'buzz-sats-channel-sweep" --check',
            readme,
        )
        self.assertEqual(readme.count('--bundle "$PACKAGE_DIR"'), 4)

        self.assertIn('PARITY_DIR="$STAGE/capability-parity"', readme)
        self.assertIn('TIER2_STATE_DIR="$STAGE/tier2-r1"', readme)
        self.assertIn('TIER2_LEDGER_DIR="$STAGE/tier2-scope-ledgers"', readme)
        self.assertIn(
            'install -d -m 0700 "$TIER2_STATE_DIR" "$TIER2_LEDGER_DIR"',
            readme,
        )
        self.assertLess(
            readme.index('install -d -m 0700 "$TIER2_STATE_DIR" "$TIER2_LEDGER_DIR"'),
            readme.index('TIER2_STATE_FILE=$("$TIER2" prepare'),
        )
        self.assertIn('TIER2_STATE_FILE=$("$TIER2" prepare', readme)
        self.assertNotIn('$STATE/', readme)
        self.assertNotIn('\nSTATE=$("$TIER2" prepare', readme)
        self.assertNotIn('--tier2-state "$STATE"', readme)
        self.assertNotIn('\nSTATE_DIR="$STAGE/tier2-r1"', readme)

    def test_tier2_auth_route_is_explicitly_profile_backed(self) -> None:
        readme = (ACTIVATION_DIR / "README.md").read_text()
        self.assertIn("--claude-auth-source profile", readme)
        self.assertEqual(GENERATOR.TIER2_REVIEW["auth_source"], "profile")
        self.assertEqual(PREFLIGHT.TIER2_REVIEW["auth_source"], "profile")

        reviewed_paths = (
            ACTIVATION_DIR / "README.md",
            ACTIVATION_DIR / "generate-activation-bundle.py",
            ACTIVATION_DIR / "install-activation-bundle.py",
            ACTIVATION_DIR / "make-tier1-receipt.py",
            ACTIVATION_DIR / "tier2-evidence-verifier.py",
        )
        retired_source = "dedi" + "cated"
        for path in reviewed_paths:
            self.assertNotIn(retired_source, path.read_text(), path)

    def test_placeholder_preview_is_retired(self) -> None:
        readme = (ACTIVATION_DIR / "README.md").read_text()
        self.assertNotIn("PLACEHOLDER_DIR=", readme)
        self.assertNotIn('$PACKAGE_WT/candidate-placeholder', readme)
        self.assertNotIn('$PACKAGE_DIR/candidate-placeholder', readme)
        self.assertIn("never writes a preview", readme)

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

    def test_enrollment_map_installer_uses_bundle_canonical_bytes_and_diagnoses_mismatch(self) -> None:
        bundle, _manifest = self.generate("canonical-enrollment")
        enrollment = bundle / "install-root/etc/buzz-agents/enrollment-keys.json"
        self.assertEqual(
            enrollment.read_bytes(),
            GENERATOR.canonical_json(
                {
                    "schema": "buzz-agent-enrollment-keys-v1",
                    "keys": {
                        "mempool": TEST_MEMPOOL_PUBKEY,
                        "genesis": TEST_GENESIS_PUBKEY,
                    },
                }
            ),
        )
        installer = (REPO_ROOT / "scripts/mempool-genesis/install-enrollment-map").read_text()
        self.assertIn(
            "{\"keys\":{\"genesis\":\"%s\",\"mempool\":\"%s\"},"
            "\"schema\":\"buzz-agent-enrollment-keys-v1\"}",
            installer,
        )
        self.assertIn("existing enrollment map does not match canonical expected bytes", installer)

    def test_preflight_receipt_reports_readiness_without_review_or_install_claim(self) -> None:
        bundle, manifest = self.generate()
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
        self.assertEqual(evidence["schema"], "tier2-evidence-v3")
        self.assertEqual(evidence["candidate_root"], str(bundle.parent))
        self.assertEqual(
            evidence["paths"],
            [f"bundle/{path}" for path in manifest["tier2_candidate_paths"]],
        )
        self.assertEqual(
            evidence["invariants"][0],
            "The review binds the exact package manifest and 22 review-file paths per agent, "
            "covering 25 distinct installed paths.",
        )
        self.assertNotIn("21-path", json.dumps(evidence))
        self.assertTrue(all(command["kind"] == "result" for command in evidence["commands"]))
        self.assertEqual(receipt["tier2_bundle"]["path"], str(evidence_path))
        payload = receipt_path.read_text()
        self.assertNotIn('"accepted"', payload)
        self.assertNotIn('"verdict"', payload)
        self.assertFalse((self.root / "review-closure.json").exists())

    def test_tier2_v3_check_only_creates_no_state_or_scope_ledger(self) -> None:
        bundle, manifest = self.generate("check-only")
        self.make_receipt(bundle, "check-only")
        state_dir = self.root / "check-only-state"
        ledger_dir = self.root / "check-only-ledger"
        completed = subprocess.run(
            [
                sys.executable,
                str(manifest["tier2_engine"]["path"]),
                "prepare",
                "--bundle",
                str(self.evidence_path("check-only")),
                "--producer-provider",
                "gpt",
                "--controller",
                "mgact-test-controller",
                "--state-dir",
                str(state_dir),
                "--scope-id",
                "mgact-test-check-only",
                "--scope-ledger-dir",
                str(ledger_dir),
                "--check-only",
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
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.splitlines(), ["OK"])
        self.assertFalse(state_dir.exists())
        self.assertFalse(ledger_dir.exists())

    def test_tier2_v3_prepare_requires_scope_argument_shape(self) -> None:
        bundle, manifest = self.generate("missing-scope")
        self.make_receipt(bundle, "missing-scope")
        state_dir = self.root / "missing-scope-state"
        completed = subprocess.run(
            [
                sys.executable,
                str(manifest["tier2_engine"]["path"]),
                "prepare",
                "--bundle",
                str(self.evidence_path("missing-scope")),
                "--producer-provider",
                "gpt",
                "--controller",
                "mgact-test-controller",
                "--state-dir",
                str(state_dir),
                "--check-only",
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
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("--scope-id", completed.stderr)
        self.assertIn("--scope-ledger-dir", completed.stderr)
        self.assertFalse(state_dir.exists())

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
        self.assertEqual(state_value["state_schema"], "tier2-state-v3")
        self.assertEqual(state_value["producer_provider"], "gpt")
        self.assertNotIn("escalate", state_value)
        self.assertEqual(
            {
                key: state_value["route"][key]
                for key in ("provider", "model", "effort", "auth_source")
            },
            {
                "provider": "claude",
                "model": "claude-opus-5",
                "effort": "high",
                "auth_source": "profile",
            },
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
            self.assertEqual(len(value["files"][slug]), 22)
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
                ["jq", "-e", "--arg", "slug", slug, "--argjson", "count", "22", contract],
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
            ["jq", "-e", "--arg", "slug", "mempool", "--argjson", "count", "22", contract],
            input=json.dumps(retired),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(rejected.returncode, 0)

    def test_shell_expected_paths_match_generator_element_for_element(self) -> None:
        verifier = REPO_ROOT / "scripts/mempool-genesis/verify-installed-agent"
        for slug in ("mempool", "genesis"):
            completed = subprocess.run(
                ["/usr/bin/bash", str(verifier), "--print-expected-paths", slug],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            fields = completed.stdout.split(b"\0")
            self.assertEqual(fields.pop(), b"")
            self.assertEqual(
                [field.decode() for field in fields],
                list(GENERATOR.EXPECTED_PATHS[slug]),
            )

    def test_tier2_v3_pass_with_risks_is_terminal_and_accepted(self) -> None:
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
        write_inputs(inputs_two, TEST_ALT_MEMPOOL_PUBKEY, TEST_ALT_GENESIS_PUBKEY)
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

    def test_expired_tier2_v3_state_is_rejected(self) -> None:
        bundle, _manifest, receipt, evidence, state = self.closed_package("expired")
        value = json.loads(state.read_text())
        value["lease_expires_at_ns"] = 1
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
        with self.assertRaisesRegex(ValueError, "unsafe Tier 2 v3 evidence bundle"):
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
            self.assertEqual(len(closure["files"][slug]), 22)
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


class ActivationTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=TEST_ROOT)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.credential_dir = self.root / "etc/buzz-agents/credentials"
        self.credential_dir.mkdir(mode=0o700, parents=True)
        self.genesis_credential = self.credential_dir / "genesis.key"
        self.genesis_before = b"3" * 64 + b"\n"
        write_file(self.genesis_credential, self.genesis_before, 0o600)
        self.manifest_path = self.root / "manifest.json"
        self.receipt_path = self.root / "sealed.json"
        self.policy_path = self.root / "policy.json"
        self.parity_path = ACTIVATION_DIR / "capability-parity.py"
        self.binding = {
            "schema": "buzz-agent-activation-binding-v1",
            "source_commit": "a" * 40,
            "source_tree": "b" * 40,
            "package_digest": "c" * 64,
            "runtime_artifact_fingerprint": "d" * 64,
            "bundle_manifest_sha256": "e" * 64,
        }
        self.channel_set = "f" * 64
        self.reference_set = "a" * 64
        self.exclusion_set = "b" * 64
        self.authority_receipt = "8" * 64
        eligible_channels = [
            {"channel_id": "0ed53b38-d6f7-44ba-a2b4-1e685d1fbb1e"},
            {"channel_id": "1ec68cd0-3051-45cd-8297-76803e34add0"},
        ]
        write_private_json(
            self.manifest_path,
            {
                "inputs": {"mempool": "1" * 64, "genesis": "2" * 64},
                "identities": {
                    "mempool": {
                        "public_key": "1" * 64,
                        "credential_path": "/etc/buzz-agents/credentials/mempool.key",
                    },
                    "genesis": {
                        "public_key": "2" * 64,
                        "credential_path": "/etc/buzz-agents/credentials/genesis.key",
                    },
                },
                "capability_parity": {
                    "reference_channels_sha256": self.reference_set,
                    "eligible_channels": eligible_channels,
                    "eligible_channels_sha256": self.channel_set,
                    "authority_exclusions_sha256": self.exclusion_set,
                },
            },
        )
        self.receipt_payload = {
            "schema": TRANSACTION.PARITY_RECEIPT_SCHEMA,
            "canonical_json_contract": "buzz-canonical-json-ascii-v1",
            "status": "PASS",
            "manifest_sha256": {},
            "policy_sha256": "0" * 64,
            "reference_channels": [],
            "reference_channels_sha256": self.reference_set,
            "eligible_channels": [],
            "eligible_channels_sha256": self.channel_set,
            "authority_exclusions": [],
            "authority_exclusions_sha256": self.exclusion_set,
            "authority_receipt": {},
            "authority_receipt_sha256": self.authority_receipt,
            "allowed_identity_differences": {},
            "approved_exceptions": {},
            "checks": {},
            "systemd_comparison": {},
            "unexplained_differences": {},
            "activation_binding": self.binding,
            "payload_sha256": "6" * 64,
        }
        ops_record = {
            "argv_sha256": "1" * 64,
            "executable": "/fixture",
            "executable_sha256": "2" * 64,
            "mode": "0700",
            "uid": os.getuid(),
            "gid": os.getgid(),
            "ops_record_sha256": "3" * 64,
        }
        write_private_json(
            self.receipt_path,
            {
                "schema": TRANSACTION.SEALED_RECEIPT_SCHEMA,
                "receipt": self.receipt_payload,
                "signature": {
                    "schema": "buzz-agent-capability-parity-signature-v1",
                    "algorithm": "schnorr-secp256k1",
                    "signer_pubkey": "4" * 64,
                    "payload_sha256": self.receipt_payload["payload_sha256"],
                    "signature": "5" * 128,
                    "signed_at": "2026-08-27T00:00:00Z",
                },
                "signer": ops_record,
                "verifier": ops_record,
                "verified": True,
                "sealed_sha256": "9" * 64,
            },
        )
        write_private_json(self.policy_path, {"synthetic": True})
        self.state_dir = self.root / "transaction"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def gate(self, slug: str) -> Path:
        path = self.root / f"{slug}-gate.json"
        write_private_json(
            path,
            {
                "schema": TRANSACTION.PHASE_SCHEMA,
                "status": "PASS",
                "slug": slug,
                "binding": self.binding,
                "gates": {
                    "config": True,
                    "credential": True,
                    "membership": True,
                    "parity": True,
                },
                "reference_channels_sha256": self.reference_set,
                "eligible_channels_sha256": self.channel_set,
                "authority_exclusions_sha256": self.exclusion_set,
                "authority_receipt_sha256": self.authority_receipt,
            },
        )
        return path

    def prepare(self) -> None:
        def verify_fixture_envelope(receipt, policy, manifest, verifier, root):
            TRANSACTION.sealed_authority_digest(receipt)
            if set(receipt["receipt"]) != set(self.receipt_payload):
                raise ValueError("fixture sealed receipt payload schema mismatch")
            if set(receipt["signature"]) != {
                "schema", "algorithm", "signer_pubkey", "payload_sha256",
                "signature", "signed_at",
            }:
                raise ValueError("fixture sealed receipt signature schema mismatch")
            ops_fields = {
                "argv_sha256", "executable", "executable_sha256", "mode", "uid",
                "gid", "ops_record_sha256",
            }
            if set(receipt["signer"]) != ops_fields or set(receipt["verifier"]) != ops_fields:
                raise ValueError("fixture sealed receipt operations schema mismatch")
            return receipt

        parity = SimpleNamespace(
            ParityError=ValueError,
            ROOT_VERIFIER_TARGET="/usr/local/libexec/buzz/buzz-agent-key-handoff",
            validate_policy=lambda value: value,
            verify_sealed_receipt=verify_fixture_envelope,
            activation_binding=lambda manifest: self.binding,
        )
        with mock.patch.object(
            TRANSACTION, "manifest_bound_runtime_tool"
        ), mock.patch.object(TRANSACTION, "load_parity_module", return_value=parity):
            TRANSACTION.prepare(
                self.manifest_path,
                self.receipt_path,
                self.policy_path,
                self.parity_path,
                self.state_dir,
                self.root,
            )

    def ready_mempool_for_completion(self) -> None:
        self.prepare()
        TRANSACTION.begin_phase(self.state_dir, "mempool")
        write_file(self.credential_dir / "mempool.key", b"4" * 64 + b"\n", 0o600)
        TRANSACTION.record_credential(self.state_dir, "mempool", self.root)

    def test_prepare_binds_nested_live_authority_digest(self) -> None:
        self.prepare()
        state = TRANSACTION.read_state(self.state_dir)
        self.assertEqual(
            state["channel_contract"]["authority_receipt_sha256"],
            self.receipt_envelope()["receipt"]["authority_receipt_sha256"],
        )

    def receipt_envelope(self) -> dict:
        return json.loads(self.receipt_path.read_text())

    def test_prepare_rejects_flat_legacy_receipt_fixture(self) -> None:
        write_private_json(
            self.receipt_path,
            {
                "sealed_sha256": "9" * 64,
                "authority_receipt_sha256": self.authority_receipt,
            },
        )
        with self.assertRaisesRegex(
            TRANSACTION.TransactionError, "envelope schema mismatch"
        ):
            self.prepare()

    def test_complete_phase_rejects_missing_nested_live_authority_digest(self) -> None:
        self.ready_mempool_for_completion()
        path = self.state_dir / "capability-parity-receipt.json"
        envelope = json.loads(path.read_text())
        del envelope["receipt"]["authority_receipt_sha256"]
        write_private_json(path, envelope)
        with self.assertRaisesRegex(
            TRANSACTION.TransactionError, "live authority digest is invalid"
        ):
            TRANSACTION.complete_phase(self.state_dir, "mempool", self.gate("mempool"))

    def test_complete_phase_rejects_tampered_nested_live_authority_digest(self) -> None:
        self.ready_mempool_for_completion()
        path = self.state_dir / "capability-parity-receipt.json"
        envelope = json.loads(path.read_text())
        envelope["receipt"]["authority_receipt_sha256"] = "7" * 64
        write_private_json(path, envelope)
        with self.assertRaisesRegex(
            TRANSACTION.TransactionError, "not manifest-bound"
        ):
            TRANSACTION.complete_phase(self.state_dir, "mempool", self.gate("mempool"))

    def test_complete_phase_rejects_live_authority_gate_mismatch(self) -> None:
        self.ready_mempool_for_completion()
        gate = self.gate("mempool")
        value = json.loads(gate.read_text())
        value["authority_receipt_sha256"] = "7" * 64
        write_private_json(gate, value)
        with self.assertRaisesRegex(
            TRANSACTION.TransactionError, "not manifest-bound"
        ):
            TRANSACTION.complete_phase(self.state_dir, "mempool", gate)

    def test_mempool_must_complete_before_genesis_and_rollback_is_exact(self) -> None:
        self.prepare()
        with self.assertRaisesRegex(TRANSACTION.TransactionError, "blocked by state"):
            TRANSACTION.begin_phase(self.state_dir, "genesis")
        TRANSACTION.begin_phase(self.state_dir, "mempool")
        mempool_credential = self.credential_dir / "mempool.key"
        mempool_secret = b"4" * 64 + b"\n"
        write_file(mempool_credential, mempool_secret, 0o600)
        TRANSACTION.record_credential(self.state_dir, "mempool", self.root)
        TRANSACTION.plan_membership(
            self.state_dir,
            "mempool",
            "0ed53b38-d6f7-44ba-a2b4-1e685d1fbb1e",
            "1" * 64,
        )
        TRANSACTION.confirm_membership(
            self.state_dir,
            "mempool",
            "0ed53b38-d6f7-44ba-a2b4-1e685d1fbb1e",
            "1" * 64,
        )
        TRANSACTION.complete_phase(self.state_dir, "mempool", self.gate("mempool"))
        TRANSACTION.begin_phase(self.state_dir, "genesis")
        genesis_after = b"5" * 64 + b"\n"
        self.genesis_credential.write_bytes(genesis_after)
        TRANSACTION.record_credential(self.state_dir, "genesis", self.root)
        TRANSACTION.plan_membership(
            self.state_dir,
            "genesis",
            "1ec68cd0-3051-45cd-8297-76803e34add0",
            "2" * 64,
        )
        TRANSACTION.confirm_membership(
            self.state_dir,
            "genesis",
            "1ec68cd0-3051-45cd-8297-76803e34add0",
            "2" * 64,
        )
        TRANSACTION.complete_phase(self.state_dir, "genesis", self.gate("genesis"))
        receipt_text = (self.state_dir / "state.json").read_text()
        self.assertNotIn(mempool_secret.decode().strip(), receipt_text)
        self.assertNotIn(genesis_after.decode().strip(), receipt_text)
        TRANSACTION.begin_rollback(self.state_dir, self.root)
        plan = TRANSACTION.rollback_plan(self.state_dir)
        self.assertEqual([item["slug"] for item in plan], ["genesis", "mempool"])
        for item in plan:
            TRANSACTION.mark_membership_rolled_back(
                self.state_dir, item["slug"], item["channel_id"], item["pubkey"]
            )
        interrupted = TRANSACTION.read_state(self.state_dir)
        TRANSACTION.restore_credential(
            self.state_dir, interrupted["credentials"]["genesis"], self.root
        )
        result = TRANSACTION.finish_rollback(self.state_dir, self.root)
        self.assertEqual(result["state"], "rolled_back")
        self.assertFalse(mempool_credential.exists())
        self.assertEqual(self.genesis_credential.read_bytes(), self.genesis_before)
        with self.assertRaisesRegex(TRANSACTION.TransactionError, "already rolled back"):
            TRANSACTION.begin_rollback(self.state_dir, self.root)

    def test_credential_drift_refuses_rollback_without_consuming_claim(self) -> None:
        self.prepare()
        TRANSACTION.begin_phase(self.state_dir, "mempool")
        credential = self.credential_dir / "mempool.key"
        write_file(credential, b"6" * 64 + b"\n", 0o600)
        TRANSACTION.record_credential(self.state_dir, "mempool", self.root)
        credential.write_bytes(b"7" * 64 + b"\n")
        with self.assertRaisesRegex(TRANSACTION.TransactionError, "drift blocks rollback"):
            TRANSACTION.begin_rollback(self.state_dir, self.root)
        state = TRANSACTION.read_state(self.state_dir)
        self.assertFalse(state["claim_used"])
        self.assertTrue((self.state_dir / "rollback.claim").exists())

    def test_excluded_or_unknown_membership_plan_is_rejected(self) -> None:
        self.prepare()
        TRANSACTION.begin_phase(self.state_dir, "mempool")
        for channel_id in (
            "9f7d9f1d-df0f-490f-8e32-1e3dbf261f1f",
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        ):
            with self.subTest(channel_id=channel_id), self.assertRaisesRegex(
                TRANSACTION.TransactionError, "excluded or unknown"
            ):
                TRANSACTION.plan_membership(
                    self.state_dir, "mempool", channel_id, "1" * 64
                )

    def test_parity_runtime_tool_must_match_manifest_path_metadata_and_digest(self) -> None:
        tool = (
            self.root
            / "usr/local/libexec/buzz/verify-agent-capability-parity"
        )
        write_file(tool, b"#!/usr/bin/python3\n", 0o755)
        metadata = tool.lstat()
        manifest = {
            "runtime_targets": [
                {
                    "target": "/usr/local/libexec/buzz/verify-agent-capability-parity",
                    "sha256": hashlib.sha256(tool.read_bytes()).hexdigest(),
                    "mode": "0755",
                    "uid": metadata.st_uid,
                    "gid": metadata.st_gid,
                }
            ]
        }
        TRANSACTION.manifest_bound_runtime_tool(manifest, tool, self.root)
        manifest["runtime_targets"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(TRANSACTION.TransactionError, "manifest-bound"):
            TRANSACTION.manifest_bound_runtime_tool(manifest, tool, self.root)

    def test_package_rollback_requires_matching_completed_activation_rollback(self) -> None:
        receipt = {
            "source_commit": "a" * 40,
            "source_tree": "b" * 40,
            "package_digest": "c" * 64,
        }
        with mock.patch.dict(os.environ, {"MGACT_TESTING": "1"}):
            INSTALLER.require_activation_transaction_rolled_back(self.root, receipt)
            transaction = (
                self.root / INSTALLER.ACTIVATION_TRANSACTION_DIR.lstrip("/")
            )
            transaction.mkdir(mode=0o700, parents=True)
            write_private_json(
                transaction / "state.json",
                {
                    "schema": TRANSACTION.STATE_SCHEMA,
                    "state": "mempool_complete",
                    "claim_used": False,
                    "binding": receipt,
                    "memberships": [],
                    "credentials": {
                        "mempool": {"restored": False},
                        "genesis": {"restored": False},
                    },
                },
            )
            with self.assertRaisesRegex(ValueError, "must be rolled back"):
                INSTALLER.require_activation_transaction_rolled_back(self.root, receipt)
            state = json.loads((transaction / "state.json").read_text())
            state["state"] = "rolled_back"
            state["claim_used"] = True
            state["credentials"]["mempool"]["restored"] = True
            state["credentials"]["genesis"]["restored"] = True
            write_private_json(transaction / "state.json", state)
            INSTALLER.require_activation_transaction_rolled_back(self.root, receipt)
            receipt["package_digest"] = "d" * 64
            with self.assertRaisesRegex(ValueError, "does not match"):
                INSTALLER.require_activation_transaction_rolled_back(self.root, receipt)


class SweepCandidateTests(PackageFixture):
    def setUp(self) -> None:
        super().setUp()
        self.bundle, _manifest = self.generate("sweep")
        self.script = self.bundle / "ops-root/home/victor/.local/libexec/buzz/buzz-sats-channel-sweep"
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
        self.transaction_index = 0
        write_private_json(
            self.state_file,
            {
                "writes": 0,
                "seen_private_keys": [],
                "channels": {
                    "9f7d9f1d-df0f-490f-8e32-1e3dbf261f1f": [
                        {"pubkey": GENERATOR.OWNER_PUBKEY, "role": "member"},
                        {"pubkey": "9" * 64, "role": "bot"}
                    ],
                    "03f28d12-d392-4147-a9d6-9f23426dcde0": [
                        {"pubkey": GENERATOR.OWNER_PUBKEY, "role": "owner"},
                        {"pubkey": "9" * 64, "role": "member"}
                    ],
                    "0ed53b38-d6f7-44ba-a2b4-1e685d1fbb1e": [
                        {"pubkey": GENERATOR.OWNER_PUBKEY, "role": "owner"},
                        {"pubkey": "9" * 64, "role": "member"}
                    ],
                    "1ec68cd0-3051-45cd-8297-76803e34add0": [
                        {"pubkey": GENERATOR.OWNER_PUBKEY, "role": "owner"},
                        {"pubkey": "9" * 64, "role": "member"}
                    ],
                },
            },
        )
        self.skip = self.root / "skip"
        self.skip.write_text("03f28d12-d392-4147-a9d6-9f23426dcde0\n")
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
            "mode=os.environ.get('SWEEP_LIST_MODE','normal')\n"
            "if args[:2] == ['channels','list'] and mode == 'unreachable': raise SystemExit(1)\n"
            "if args[:4] == ['channels','list','--visibility','open']:\n"
            " if mode == 'empty': print('[]')\n"
            " else: print(json.dumps([\n"
            "   {'channel_id':'9f7d9f1d-df0f-490f-8e32-1e3dbf261f1f','name':'authority-excluded','archived':False},\n"
            "   {'channel_id':'03f28d12-d392-4147-a9d6-9f23426dcde0','name':'one','archived':False},\n"
            "   {'channel_id':'0ed53b38-d6f7-44ba-a2b4-1e685d1fbb1e','name':'two','archived':False},\n"
            "   {'channel_id':'33333333-3333-3333-3333-333333333333','name':'unreviewed','archived':False}]))\n"
            "elif args[:5] == ['channels','list','--visibility','private','--member']:\n"
            " if mode == 'empty': print('[]')\n"
            " else: print(json.dumps([{'channel_id':'1ec68cd0-3051-45cd-8297-76803e34add0','name':'private','archived':False}]))\n"
            "elif args[:2] == ['channels','members']:\n"
            " cid=args[args.index('--channel')+1]; members=state['channels'][cid]\n"
            " if os.environ.get('SWEEP_MEMBER_PROJECTION') == 'malformed': members=members+['malformed']\n"
            " targets={os.environ.get('TEST_MEMPOOL_PUBKEY'),os.environ.get('TEST_GENESIS_PUBKEY')}\n"
            " if os.environ.get('SWEEP_POST_WRITE_MEMBER_PROJECTION') == 'malformed' and any(m.get('pubkey') in targets for m in members): members=members+['malformed']\n"
            " print(json.dumps(members))\n"
            "elif args[:2] == ['channels','add-member']:\n"
            " if os.environ.get('SWEEP_LEAK') == '1':\n"
            "  print('nsec1SECRET '+key, file=sys.stderr); raise SystemExit(1)\n"
            " cid=args[args.index('--channel')+1]; target=args[args.index('--pubkey')+1]; role=args[args.index('--role')+1]\n"
            " assert role == 'member'\n"
            " if not any(m['pubkey']==target for m in state['channels'][cid]):\n"
            "  projected_role=os.environ.get('SWEEP_POST_WRITE_PROJECTION', role)\n"
            "  if projected_role != 'absent': state['channels'][cid].append({'pubkey':target,'role':projected_role})\n"
            "  state['writes']+=1; json.dump(state,open(path,'w'))\n"
            " print(json.dumps({'accepted':True}))\n"
            "else: raise SystemExit('unexpected args: '+repr(args))\n"
        )
        self.buzz.chmod(0o755)

    def run_sweep(
        self, *arguments: str | None, **extra: str
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update(
            {
                "SATS_SECRET_FILE": str(self.secret_file),
                "SATS_TOOLS_DIR": str(self.tools),
                "SATS_SKIP_FILE": str(self.skip),
                "SATS_SWEEP_LOG": str(self.root / "sweep.log"),
                "BUZZ_BIN": str(self.buzz),
                "SWEEP_STATE": str(self.state_file),
                "TEST_MEMPOOL_PUBKEY": TEST_MEMPOOL_PUBKEY,
                "TEST_GENESIS_PUBKEY": TEST_GENESIS_PUBKEY,
                "SATS_ACTIVATION_TRANSACTION_TOOL": str(
                    self.bundle
                    / "install-root/usr/local/libexec/buzz/mempool-genesis-activation-transaction"
                ),
                **extra,
            }
        )
        command = [str(self.script), *(arg for arg in arguments if arg is not None)]
        return subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
            timeout=60,
        )

    def make_transaction(self) -> Path:
        self.transaction_index += 1
        transaction = self.root / f"transaction-{self.transaction_index}"
        transaction.mkdir(mode=0o700)
        write_private_json(
            transaction / "bundle-manifest.json",
            {
                "inputs": {
                    "mempool": TEST_MEMPOOL_PUBKEY,
                    "genesis": TEST_GENESIS_PUBKEY,
                },
                "capability_parity": {
                    "eligible_channels": json.loads(
                        (ACTIVATION_DIR / "capability-parity-policy.json").read_text()
                    )["eligible_channels"]
                },
            },
        )
        write_private_json(
            transaction / "state.json",
            {
                "schema": TRANSACTION.STATE_SCHEMA,
                "state": "prepared",
                "binding": {},
                "sealed_receipt_sha256": "f" * 64,
                "claim_sha256": "e" * 64,
                "claim_used": False,
                "credentials": {"mempool": {}, "genesis": {}},
                "memberships": [],
                "phase_receipts": {},
            },
        )
        return transaction

    def apply_both(self, **extra: str) -> subprocess.CompletedProcess[str]:
        transaction = self.make_transaction()
        mempool = self.run_sweep("--mempool-apply", str(transaction), **extra)
        if mempool.returncode != 0:
            return mempool
        transaction_state = json.loads((transaction / "state.json").read_text())
        transaction_state["state"] = "mempool_complete"
        write_private_json(transaction / "state.json", transaction_state)
        genesis = self.run_sweep("--genesis-apply", str(transaction), **extra)
        return subprocess.CompletedProcess(
            args=[mempool.args, genesis.args],
            returncode=genesis.returncode,
            stdout=mempool.stdout + genesis.stdout,
            stderr=mempool.stderr + genesis.stderr,
        )

    def disable_script_errexit(self) -> None:
        payload = self.script.read_text()
        self.assertEqual(payload.count("set -euo pipefail"), 1)
        self.script.write_text(payload.replace("set -euo pipefail", "set -uo pipefail", 1))
        self.script.chmod(0o700)

    def path_with_failing_tool(self, name: str) -> str:
        tool_dir = self.root / f"fail-{name}"
        tool_dir.mkdir(mode=0o700)
        tool = tool_dir / name
        tool.write_text("#!/bin/sh\nexit 1\n")
        tool.chmod(0o700)
        return f"{tool_dir}:{os.environ['PATH']}"

    def test_fixed_public_roster_covers_all_open_channels_and_is_idempotent(self) -> None:
        before = self.state_file.read_bytes()
        check = self.run_sweep("--check")
        self.assertEqual(check.returncode, 0, check.stderr)
        self.assertIn("PREFLIGHT OK", check.stdout)
        self.assertEqual(json.loads(before)["writes"], json.loads(self.state_file.read_text())["writes"])
        self.assertFalse((self.root / "sweep.log").exists())
        dry_run = self.run_sweep("--dry-run")
        self.assertEqual(dry_run.returncode, 0, dry_run.stderr)
        self.assertEqual(dry_run.stdout.count("PLAN owner add-member"), 6)
        self.assertIn("03f28d12-d392-4147-a9d6-9f23426dcde0", dry_run.stdout)
        self.assertIn("0ed53b38-d6f7-44ba-a2b4-1e685d1fbb1e", dry_run.stdout)
        self.assertIn("1ec68cd0-3051-45cd-8297-76803e34add0", dry_run.stdout)
        self.assertNotIn("33333333-3333-3333-3333-333333333333", dry_run.stdout)
        self.assertEqual(json.loads(self.state_file.read_text())["writes"], 0)
        combined = self.run_sweep("--mempool-genesis-apply")
        self.assertEqual(combined.returncode, 64)
        self.assertIn("selective transaction modes", combined.stderr)
        transaction = self.make_transaction()
        blocked_genesis = self.run_sweep("--genesis-apply", str(transaction))
        self.assertNotEqual(blocked_genesis.returncode, 0)
        self.assertEqual(json.loads(self.state_file.read_text())["writes"], 0)
        first = self.run_sweep("--mempool-apply", str(transaction))
        self.assertEqual(first.returncode, 0, first.stderr + first.stdout)
        state = json.loads(self.state_file.read_text())
        self.assertEqual(state["writes"], 3)
        for members in state["channels"].values():
            self.assertFalse(any(member["pubkey"] == TEST_GENESIS_PUBKEY for member in members))
        self.assertTrue(state["seen_private_keys"])
        self.assertEqual(set(state["seen_private_keys"]), {self.owner_private})
        transaction_state = json.loads((transaction / "state.json").read_text())
        transaction_state["state"] = "mempool_complete"
        write_private_json(transaction / "state.json", transaction_state)
        second = self.run_sweep("--genesis-apply", str(transaction))
        self.assertEqual(second.returncode, 0, second.stderr + second.stdout)
        self.assertEqual(json.loads(self.state_file.read_text())["writes"], 6)
        self.assertLess(first.stdout.find("Mempool open roster"), first.stdout.find("Mempool private roster"))

    def test_default_and_service_invocations_are_read_only(self) -> None:
        before = self.state_file.read_bytes()
        default = self.run_sweep(None)
        self.assertEqual(default.returncode, 0, default.stderr + default.stdout)
        self.assertIn("PREFLIGHT OK", default.stdout)
        self.assertEqual(json.loads(before)["writes"], json.loads(self.state_file.read_text())["writes"])
        service = (
            self.bundle
            / "ops-root/home/victor/.config/systemd/user/buzz-sats-channel-sweep.service"
        ).read_text()
        self.assertIn("ExecStart=/home/victor/.local/libexec/buzz/buzz-sats-channel-sweep --check", service)
        self.assertNotIn("ExecStart=/home/victor/.local/libexec/buzz/buzz-sats-channel-sweep\n", service)

    def test_service_has_default_target_enablement_contract(self) -> None:
        service = (
            self.bundle
            / "ops-root/home/victor/.config/systemd/user/buzz-sats-channel-sweep.service"
        ).read_text()
        self.assertIn("\n[Install]\nWantedBy=default.target\n", service)

    def test_service_does_not_claim_user_manager_network_readiness(self) -> None:
        service = (
            self.bundle
            / "ops-root/home/victor/.config/systemd/user/buzz-sats-channel-sweep.service"
        ).read_text()
        self.assertNotIn("network-online.target", service)
        self.assertNotIn("After=", service)
        self.assertNotIn("Wants=", service)

    def test_check_dry_run_and_apply_fail_closed_when_relay_is_unreachable(self) -> None:
        self.disable_script_errexit()
        for mode in ("--check", "--dry-run"):
            with self.subTest(mode=mode):
                result = self.run_sweep(mode, SWEEP_LIST_MODE="unreachable")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout.count("failed or relay unreachable"), 2)
                self.assertNotIn("live open channel list empty", result.stdout)
                self.assertNotIn("PREFLIGHT OK", result.stdout)
                self.assertNotIn("DRY RUN OK", result.stdout)
                self.assertNotIn("PLAN owner add-member", result.stdout)
                self.assertEqual(json.loads(self.state_file.read_text())["writes"], 0)
        result = self.apply_both(SWEEP_LIST_MODE="unreachable")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout.count("failed or relay unreachable"), 2)
        self.assertEqual(json.loads(self.state_file.read_text())["writes"], 0)

    def test_check_dry_run_and_apply_fail_closed_when_relay_returns_no_open_channels(self) -> None:
        self.disable_script_errexit()
        for mode in ("--check", "--dry-run"):
            with self.subTest(mode=mode):
                result = self.run_sweep(mode, SWEEP_LIST_MODE="empty")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("live open channel list empty", result.stdout)
                self.assertNotIn("PREFLIGHT OK", result.stdout)
                self.assertNotIn("DRY RUN OK", result.stdout)
                self.assertNotIn("PLAN owner add-member", result.stdout)
                self.assertEqual(json.loads(self.state_file.read_text())["writes"], 0)
        result = self.apply_both(SWEEP_LIST_MODE="empty")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout.count("live open channel list empty"), 1)
        self.assertEqual(json.loads(self.state_file.read_text())["writes"], 0)

    def test_post_write_verification_accepts_truthful_bot_projection(self) -> None:
        result = self.apply_both(SWEEP_POST_WRITE_PROJECTION="bot")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(result.stdout.count("planned=2 writes=2 already=0 blocked=0"), 2)
        self.assertEqual(result.stdout.count("planned=3 writes=3 already=0 blocked=0"), 2)
        state = json.loads(self.state_file.read_text())
        self.assertEqual(state["writes"], 6)
        for channel_id in (
            "0ed53b38-d6f7-44ba-a2b4-1e685d1fbb1e",
            "1ec68cd0-3051-45cd-8297-76803e34add0",
        ):
            projected = [
                member["role"]
                for member in state["channels"][channel_id]
                if member["pubkey"] in {TEST_MEMPOOL_PUBKEY, TEST_GENESIS_PUBKEY}
            ]
            self.assertEqual(projected, ["bot", "bot"])

    def test_malformed_member_projection_fails_before_write_without_errexit(self) -> None:
        self.disable_script_errexit()
        result = self.apply_both(SWEEP_MEMBER_PROJECTION="malformed")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout.count("authority exclusion member projection INVALID"), 1)
        self.assertNotIn("joined open", result.stdout)
        self.assertEqual(json.loads(self.state_file.read_text())["writes"], 0)

    def test_apply_success_bounds_sweep_log(self) -> None:
        log = self.root / "sweep.log"
        log.write_text("".join(f"old success line {index}\n" for index in range(600)))
        result = self.apply_both()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        lines = log.read_text().splitlines()
        self.assertEqual(len(lines), 500)
        self.assertIn("Genesis private roster", lines[-1])
        self.assertFalse((self.root / "sweep.log.tmp").exists())

    def test_apply_failure_bounds_sweep_log(self) -> None:
        self.disable_script_errexit()
        log = self.root / "sweep.log"
        log.write_text("".join(f"old failure line {index}\n" for index in range(600)))
        result = self.apply_both(SWEEP_LIST_MODE="unreachable")
        self.assertNotEqual(result.returncode, 0)
        lines = log.read_text().splitlines()
        self.assertEqual(len(lines), 500)
        self.assertTrue(any("failed or relay unreachable" in line for line in lines[-5:]))
        self.assertIn("authority exclusion visibility/archive drift", lines[-1])
        self.assertFalse((self.root / "sweep.log.tmp").exists())

    def test_apply_tail_failure_removes_temp_and_returns_nonzero(self) -> None:
        self.disable_script_errexit()
        log = self.root / "sweep.log"
        original = "".join(f"tail failure line {index}\n" for index in range(600))
        log.write_text(original)
        result = self.apply_both(PATH=self.path_with_failing_tool("tail"))
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(log.read_text().startswith(original))
        self.assertIn("Mempool private roster", log.read_text())
        self.assertFalse((self.root / "sweep.log.tmp").exists())

    def test_apply_mv_failure_removes_temp_and_returns_nonzero(self) -> None:
        self.disable_script_errexit()
        log = self.root / "sweep.log"
        original = "".join(f"mv failure line {index}\n" for index in range(600))
        log.write_text(original)
        result = self.apply_both(PATH=self.path_with_failing_tool("mv"))
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(log.read_text().startswith(original))
        self.assertIn("Mempool private roster", log.read_text())
        self.assertFalse((self.root / "sweep.log.tmp").exists())

    def test_malformed_post_write_projection_fails_after_intended_writes(self) -> None:
        self.disable_script_errexit()
        result = self.apply_both(SWEEP_POST_WRITE_MEMBER_PROJECTION="malformed")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout.count("add-member verification FAILED"), 3)
        self.assertNotIn("member projection INVALID", result.stdout)
        self.assertNotIn("joined open", result.stdout)
        self.assertEqual(json.loads(self.state_file.read_text())["writes"], 3)

    def test_post_write_verification_rejects_every_other_projection(self) -> None:
        self.disable_script_errexit()
        initial = json.loads(self.state_file.read_text())
        for projection in ("guest", "admin", "absent", "owner"):
            with self.subTest(projection=projection):
                write_private_json(self.state_file, initial)
                result = self.apply_both(SWEEP_POST_WRITE_PROJECTION=projection)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout.count("add-member verification FAILED"), 3)
                self.assertNotIn("joined open", result.stdout)
                state = json.loads(self.state_file.read_text())
                self.assertEqual(state["writes"], 3)

    def test_repeated_nibble_roster_fails_before_any_write(self) -> None:
        self.disable_script_errexit()
        payload = self.script.read_text()
        payload = payload.replace(TEST_MEMPOOL_PUBKEY, "1" * 64)
        payload = payload.replace(TEST_GENESIS_PUBKEY, "2" * 64)
        self.script.write_text(payload)
        self.script.chmod(0o700)
        result = self.apply_both()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("repeated-nibble placeholder", result.stdout)
        self.assertEqual(json.loads(self.state_file.read_text())["writes"], 0)

    def test_roster_cardinality_guard_returns_failure_before_any_write(self) -> None:
        self.disable_script_errexit()
        payload = self.script.read_text()
        genesis_line = f'  "{TEST_GENESIS_PUBKEY}"\n'
        self.assertEqual(payload.count(genesis_line), 1)
        self.script.write_text(payload.replace(genesis_line, "", 1))
        self.script.chmod(0o700)
        result = self.apply_both()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must contain exactly two public keys", result.stdout)
        self.assertEqual(json.loads(self.state_file.read_text())["writes"], 0)

    def test_duplicate_roster_guard_returns_failure_before_any_write(self) -> None:
        self.disable_script_errexit()
        payload = self.script.read_text()
        genesis_line = f'  "{TEST_GENESIS_PUBKEY}"\n'
        mempool_line = f'  "{TEST_MEMPOOL_PUBKEY}"\n'
        self.assertEqual(payload.count(genesis_line), 1)
        self.script.write_text(payload.replace(genesis_line, mempool_line, 1))
        self.script.chmod(0o700)
        result = self.apply_both()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("public keys must be distinct", result.stdout)
        self.assertEqual(json.loads(self.state_file.read_text())["writes"], 0)

    def test_two_consecutive_reconciliations_make_zero_writes_when_roles_are_authoritative(self) -> None:
        state = json.loads(self.state_file.read_text())
        for channel_id in (
            "03f28d12-d392-4147-a9d6-9f23426dcde0",
            "0ed53b38-d6f7-44ba-a2b4-1e685d1fbb1e",
            "1ec68cd0-3051-45cd-8297-76803e34add0",
        ):
            state["channels"][channel_id].extend(
                [
                    {"pubkey": TEST_MEMPOOL_PUBKEY, "role": "member"},
                    {"pubkey": TEST_GENESIS_PUBKEY, "role": "member"},
                ]
            )
        write_private_json(self.state_file, state)

        for _cycle in range(2):
            result = self.apply_both()
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertEqual(
                result.stdout.count("planned=0 writes=0 already=2 blocked=0"),
                2,
            )
            self.assertEqual(
                result.stdout.count("planned=0 writes=0 already=3 blocked=0"),
                2,
            )
        self.assertEqual(json.loads(self.state_file.read_text())["writes"], 0)

    def test_authority_exclusion_is_live_checked_and_generic_skips_cannot_suppress_mg(self) -> None:
        script = self.script.read_text()
        self.assertIn("9f7d9f1d-df0f-490f-8e32-1e3dbf261f1f", script)
        self.assertIn("446dba03-c038-4e8c-b05e-245deb1d5ac5", script)
        mg_body = script.split("reconcile_mg_channels()", 1)[1].split("reconcile_mg_parity()", 1)[0]
        self.assertNotIn('in_skips "$cid" && continue', mg_body)
        self.assertIn('in_mg_exclusions "$cid" && continue', mg_body)
        self.skip.write_text("0ed53b38-d6f7-44ba-a2b4-1e685d1fbb1e\n")
        result = self.run_sweep("--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("channel=0ed53b38-d6f7-44ba-a2b4-1e685d1fbb1e", result.stdout)

    def test_authority_exclusion_role_and_candidate_drift_block_before_writes(self) -> None:
        original = json.loads(self.state_file.read_text())
        channel_id = "9f7d9f1d-df0f-490f-8e32-1e3dbf261f1f"
        cases = {
            "actor-role": lambda value: value["channels"][channel_id][0].update(role="owner"),
            "Codex-R-role": lambda value: value["channels"][channel_id][1].update(role="member"),
            "candidate-presence": lambda value: value["channels"][channel_id].append(
                {"pubkey": TEST_MEMPOOL_PUBKEY, "role": "member"}
            ),
        }
        for label, mutate in cases.items():
            value = copy.deepcopy(original)
            mutate(value)
            write_private_json(self.state_file, value)
            result = self.run_sweep("--dry-run")
            with self.subTest(label=label):
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("authority exclusion", result.stdout)
                self.assertNotIn("PLAN owner add-member", result.stdout)
                self.assertEqual(json.loads(self.state_file.read_text())["writes"], 0)

    def test_non_owner_or_admin_role_blocks_owner_authority(self) -> None:
        value = json.loads(self.state_file.read_text())
        for channel_id, members in value["channels"].items():
            if channel_id == "9f7d9f1d-df0f-490f-8e32-1e3dbf261f1f":
                continue
            members[0]["role"] = "admin"
        write_private_json(self.state_file, value)
        result = self.run_sweep("--dry-run")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("owner authority UNMET", result.stdout)
        self.assertNotIn("PLAN owner add-member", result.stdout)

    def test_failure_output_redacts_owner_private_key(self) -> None:
        transaction = self.make_transaction()
        result = self.run_sweep(
            "--mempool-apply", str(transaction), SWEEP_LEAK="1"
        )
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

from __future__ import annotations

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[4]
VERIFY_PATH = ROOT / "deploy/native-ci/execd/verify.py"
SPEC = importlib.util.spec_from_file_location("execd_verify", VERIFY_PATH)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)

EXECD_DIR = ROOT / "deploy/native-ci/execd"
sys.path.insert(0, str(EXECD_DIR))
import freeze_package as FREEZER  # noqa: E402
import install as INSTALL  # noqa: E402

EXECD_TMPFILES = ROOT / "deploy/native-ci/execd/templates/buzzci-execd.tmpfiles"
SHARED_ANCESTOR = "d /var/lib/buzzci 0711 root root - -"
# Frozen from activation package commit 7c6d9fa6db0d92c9e33714868cbe928f19e16764.
ACTIVATION_DIRECTORY_PLAN = (
    SHARED_ANCESTOR,
    "d /var/lib/buzzci/activation-controller 0711 root root -",
    "d /var/lib/buzzci/seccomp 0711 root root - -",
    "d /var/lib/buzzci/activation 0700 root root - -",
    "d /var/lib/buzzci/activation/receipts 0700 root root - -",
    "d /var/lib/buzzci/execd-v2 0711 root root - -",
    "d /var/lib/buzzci/execd-v2/intents 0700 root root - -",
    "d /var/lib/buzzci/execd-v2/bindings 0700 root root - -",
    "d /var/lib/buzzci/execd-v2/evidence 0700 root root - -",
    "d /var/lib/buzzci/execd-v2/teardown 0700 root root - -",
    "d /var/lib/buzzci/execd-v2/attempts 0711 root root - -",
    "d /var/lib/buzzci/execd-v2/qualification 0700 root root - -",
)


def _copy_execd_package(fake: Path) -> Path:
    target = fake / "deploy/native-ci/execd"
    target.mkdir(parents=True)
    for source in (ROOT / "deploy/native-ci/execd").rglob("*"):
        if source.is_file() and "__pycache__" not in source.parts:
            destination = target / source.relative_to(ROOT / "deploy/native-ci/execd")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
            destination.chmod(stat.S_IMODE(source.stat().st_mode))
    return target


def _apply_directory_plan(root: Path, lines: tuple[str, ...] | list[str]) -> None:
    for line in lines:
        fields = line.split()
        if len(fields) not in (6, 7):
            raise AssertionError(f"unsupported fake-root tmpfiles entry: {line}")
        kind, absolute, mode, user, group, age = fields[:6]
        if (
            kind != "d"
            or user != "root"
            or group != "root"
            or age != "-"
            or (len(fields) == 7 and fields[6] != "-")
        ):
            raise AssertionError(f"unsupported fake-root tmpfiles entry: {line}")
        target = root / absolute.removeprefix("/")
        target.mkdir(parents=True, exist_ok=True)
        target.chmod(int(mode, 8))


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat(follow_symlinks=False).st_mode)


def _activation_package(path: Path, source_commit: str, binary_sha256: str, provenance_sha256: str) -> Path:
    path.mkdir(mode=0o700)
    entries = [
        {"role": f"owned-{index}", "source": f"assets/{index}", "source_mode": "0400", "sha256": hashlib.sha256(target.encode()).hexdigest(), "target": target, "install_mode": "0644", "uid": 0, "gid": 0}
        for index, target in enumerate(FREEZER.ACTIVATION_OWNED_TARGETS)
    ]
    draft = {
        "schema": FREEZER.ACTIVATION_DRAFT_SCHEMA,
        "source_commit": source_commit,
        "components": [{
            "name": "execd", "binary_path": "/usr/libexec/buzz-ci-execd",
            "binary_sha256": binary_sha256, "source_commit": source_commit,
            "provenance_sha256": provenance_sha256, "uid": 0, "gid": 0, "mode": "0755",
        }],
        "entries": entries,
    }
    package_digest = FREEZER.sha256(FREEZER.canonical_json(draft))
    manifest = dict(draft)
    manifest["schema"] = FREEZER.ACTIVATION_SCHEMA
    manifest["activation_id"] = f"buzz-ci-capacity-one-{source_commit[:12]}-{package_digest[:12]}"
    manifest["package_digest"] = package_digest
    target = path / "activation-manifest.json"
    target.write_bytes(FREEZER.canonical_json(manifest))
    target.chmod(0o600)
    return path


def _manual_execd_package(path: Path, binary: bytes) -> dict[str, object]:
    path.mkdir(mode=0o700)
    assets = path / "assets"
    assets.mkdir(mode=0o700)
    binary_path = assets / "buzz-ci-execd"
    binary_path.write_bytes(binary)
    binary_path.chmod(0o500)
    binary_sha256 = hashlib.sha256(binary).hexdigest()
    provenance = {
        "binary": "buzz-ci-execd", "profile": "release",
        "schema": FREEZER.PROVENANCE_SCHEMA, "sha256": binary_sha256,
        "source_commit": "a" * 40,
    }
    provenance_raw = FREEZER.canonical_json(provenance)
    provenance_path = path / "binary-provenance.json"
    provenance_path.write_bytes(provenance_raw)
    provenance_path.chmod(0o600)
    target_digests = [
        {"target": target, "sha256": hashlib.sha256(target.encode()).hexdigest()}
        for target in FREEZER.ACTIVATION_OWNED_TARGETS
    ]
    binding = {
        "activation_id": "buzz-ci-capacity-one-aaaaaaaaaaaa-" + "b" * 12,
        "package_digest": "b" * 64,
        "manifest_sha256": "c" * 64,
        "source_commit": "a" * 40,
        "execd_binary_sha256": binary_sha256,
        "execd_provenance_sha256": hashlib.sha256(provenance_raw).hexdigest(),
        "preactivation_input_sha256": "e" * 64,
        "owned_entries_sha256": "d" * 64,
        "owned_target_sha256": target_digests,
        "receipt_path": "/var/lib/buzzci/activation-controller/receipt-v1.json",
        "receipt_schema": "buzz-ci-capacity-one-activation-receipt-v1",
    }
    manifest: dict[str, object] = {
        "schema": FREEZER.SCHEMA,
        "package_id": f"buzz-ci-execd-aaaaaaaaaaaa-{binary_sha256[:12]}",
        "source_commit": "a" * 40,
        "binary_provenance_sha256": hashlib.sha256(provenance_raw).hexdigest(),
        "default_state": FREEZER.DEFAULT_STATE,
        "runtime_contract": FREEZER.RUNTIME_CONTRACT,
        "activation_owned_targets": FREEZER.ACTIVATION_OWNED_TARGETS,
        "activation_binding": binding,
        "seccomp_contract": FREEZER.SECCOMP_CONTRACT,
        "install_receipt": FREEZER.INSTALL_RECEIPT,
        "package_uid": 0,
        "package_gid": 0,
        "directories": FREEZER.DIRECTORIES,
        "entries": [{
            "role": "binary", "source": "assets/buzz-ci-execd",
            "target": "/usr/libexec/buzz-ci-execd", "source_mode": "0500",
            "install_mode": "0755", "uid": 0, "gid": 0, "sha256": binary_sha256,
        }],
    }
    manifest["package_digest"] = FREEZER.sha256(FREEZER.canonical_json(manifest))
    manifest_path = path / "package-manifest.json"
    manifest_path.write_bytes(FREEZER.canonical_json(manifest))
    manifest_path.chmod(0o600)
    return manifest


def _manual_install_fixture(base: Path, binary: bytes, seccomp: bytes) -> tuple[Path, Path]:
    package = base / "package"
    _manual_execd_package(package, binary)
    root = base / "root"
    root.mkdir(mode=0o700)
    seccomp_path = root / "usr/share/containers/seccomp.json"
    seccomp_path.parent.mkdir(parents=True)
    for parent in (root / "usr", root / "usr/share", root / "usr/share/containers"):
        parent.chmod(0o755)
    seccomp_path.write_bytes(seccomp)
    seccomp_path.chmod(0o644)
    return package, root


class ExecdPackageTests(unittest.TestCase):
    def test_checked_in_contract(self) -> None:
        VERIFY.verify(ROOT)

    def test_fake_root_service_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory)
            target = _copy_execd_package(fake)
            service = target / "templates/buzz-ci-executor.service"
            service.write_text(service.read_text().replace("User=buzzci-job", "User=buzzci-runner"))
            with self.assertRaisesRegex(ValueError, "misses"):
                VERIFY.verify(fake)

    def test_execd_unit_grants_exactly_the_materialization_capabilities(self) -> None:
        """H8 clean host, canary stage 5: buzz-ci-execd.service ran root with an
        empty bounding set, so materialize's fchown of the attempt directory to
        buzzci-job failed with EPERM and every admission ended in crash
        recovery. The unit now grants exactly CAP_CHOWN, CAP_DAC_OVERRIDE and
        CAP_FOWNER; the executor keeps none."""
        def capability_lines(relative: str) -> dict[str, list[str]]:
            lines: dict[str, list[str]] = {"CapabilityBoundingSet": [], "AmbientCapabilities": []}
            for line in (EXECD_DIR / relative).read_text().splitlines():
                key, _, value = line.partition("=")
                if key in lines:
                    lines[key].append(value)
            return lines

        expected = "CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER"
        self.assertEqual(
            capability_lines("templates/buzz-ci-execd.service"),
            {"CapabilityBoundingSet": [expected], "AmbientCapabilities": [expected]},
        )
        self.assertEqual(
            capability_lines("templates/buzz-ci-executor.service"),
            {"CapabilityBoundingSet": [""], "AmbientCapabilities": [""]},
        )
        for original, replacement in (
            (f"CapabilityBoundingSet={expected}", "CapabilityBoundingSet="),
            (f"CapabilityBoundingSet={expected}", f"CapabilityBoundingSet={expected} CAP_SYS_ADMIN"),
            (f"AmbientCapabilities={expected}", "AmbientCapabilities=CAP_CHOWN CAP_DAC_OVERRIDE"),
        ):
            with self.subTest(replacement=replacement):
                with tempfile.TemporaryDirectory() as directory:
                    fake = Path(directory)
                    target = _copy_execd_package(fake)
                    service = target / "templates/buzz-ci-execd.service"
                    service.write_text(service.read_text().replace(original, replacement))
                    with self.assertRaisesRegex(ValueError, "misses"):
                        VERIFY.verify(fake)

    def test_static_execution_and_sandbox_drift_are_rejected(self) -> None:
        mutations = (
            (
                "execd-config.schema.json",
                '"max_processes":{"const":16}',
                '"max_processes":{"const":17}',
            ),
            (
                "execd-config.schema.json",
                '"relative_name":{"const":"result.json"}',
                '"relative_name":{"type":"string"}',
            ),
            (
                "templates/buzz-ci-executor.service",
                "ReadWritePaths=/var/lib/buzzci/execd-v2/attempts",
                "ReadWritePaths=/var/lib/buzzci/execd-v2",
            ),
            (
                "templates/buzz-ci-executor.service",
                "MemoryMax=134217728",
                "MemoryMax=infinity",
            ),
        )
        for relative, original, replacement in mutations:
            with self.subTest(relative=relative, replacement=replacement):
                with tempfile.TemporaryDirectory() as directory:
                    fake = Path(directory)
                    target = _copy_execd_package(fake)
                    path = target / relative
                    path.write_text(path.read_text().replace(original, replacement))
                    with self.assertRaises(ValueError):
                        VERIFY.verify(fake)

    def test_execd_and_activation_directory_plans_converge_in_either_order_and_umask(self) -> None:
        execd = tuple(EXECD_TMPFILES.read_text().splitlines())
        orders = (
            ("execd-first", (execd, ACTIVATION_DIRECTORY_PLAN)),
            ("activation-first", (ACTIVATION_DIRECTORY_PLAN, execd)),
        )
        for umask in (0o000, 0o077):
            for label, order in orders:
                with self.subTest(umask=oct(umask), order=label):
                    with tempfile.TemporaryDirectory() as directory:
                        previous = os.umask(umask)
                        try:
                            for plan in order:
                                _apply_directory_plan(Path(directory), plan)
                        finally:
                            os.umask(previous)
                        state = Path(directory) / "var/lib/buzzci"
                        self.assertEqual(_mode(state), 0o711)
                        self.assertEqual(_mode(state / "activation-controller"), 0o711)
                        self.assertEqual(_mode(state / "seccomp"), 0o711)
                        self.assertEqual(_mode(state / "execd-v2"), 0o711)
                        for private in (
                            "activation",
                            "activation/receipts",
                            "execd-v2/intents",
                            "execd-v2/bindings",
                            "execd-v2/evidence",
                            "execd-v2/teardown",
                            "execd-v2/qualification",
                        ):
                            self.assertEqual(_mode(state / private), 0o700, private)

    def test_shared_traversal_exposes_only_the_explicit_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _apply_directory_plan(root, tuple(EXECD_TMPFILES.read_text().splitlines()))
            _apply_directory_plan(root, ACTIVATION_DIRECTORY_PLAN)
            shared = root / "var/lib/buzzci"
            receipt_root = shared / "activation-controller"
            receipt = receipt_root / "controld-acceptance-v2.json"
            receipt.write_bytes(b'{"schema_version":1}\n')
            receipt.chmod(0o444)
            private_state = receipt_root / "controller-state-v1.json"
            private_state.write_bytes(b'{"private":true}\n')
            private_state.chmod(0o600)

            self.assertTrue(_mode(shared) & stat.S_IXOTH)
            self.assertFalse(_mode(shared) & stat.S_IROTH)
            self.assertTrue(_mode(receipt_root) & stat.S_IXOTH)
            self.assertFalse(_mode(receipt_root) & stat.S_IROTH)
            self.assertTrue(_mode(receipt) & stat.S_IROTH)
            self.assertFalse(_mode(receipt) & stat.S_IWOTH)
            self.assertFalse(_mode(private_state) & stat.S_IROTH)
            self.assertTrue(_mode(shared / "execd-v2") & stat.S_IXOTH)
            self.assertFalse(_mode(shared / "execd-v2") & stat.S_IROTH)
            self.assertTrue(_mode(shared / "seccomp") & stat.S_IXOTH)
            self.assertFalse(_mode(shared / "seccomp") & stat.S_IROTH)
            self.assertFalse(_mode(shared / "execd-v2/intents") & stat.S_IXOTH)
            self.assertFalse(_mode(shared / "activation") & stat.S_IXOTH)

    def test_all_packaged_direct_children_are_directories(self) -> None:
        templates = ROOT.glob("deploy/native-ci/*/templates/*tmpfiles*")
        for template in templates:
            for line in template.read_text().splitlines():
                fields = line.split()
                if len(fields) >= 2 and Path(fields[1]).parent == Path("/var/lib/buzzci"):
                    self.assertEqual(fields[0], "d", f"direct-child file in {template}: {line}")

    def test_unsafe_ancestor_private_root_and_direct_file_drift_are_rejected(self) -> None:
        mutations = (
            (SHARED_ANCESTOR, "d /var/lib/buzzci 0700 root root - -"),
            (SHARED_ANCESTOR, "d /var/lib/buzzci 0755 root root - -"),
            (
                "d /var/lib/buzzci/execd-v2 0711 root root - -",
                "d /var/lib/buzzci/execd-v2 0700 root root - -",
            ),
            (
                "d /var/lib/buzzci/seccomp 0711 root root - -",
                "d /var/lib/buzzci/seccomp 0755 root root - -",
            ),
            (SHARED_ANCESTOR, "f /var/lib/buzzci/leaked-secret 0600 root root - payload"),
        )
        for original, replacement in mutations:
            with self.subTest(replacement=replacement):
                with tempfile.TemporaryDirectory() as directory:
                    fake = Path(directory)
                    target = _copy_execd_package(fake)
                    tmpfiles = target / "templates/buzzci-execd.tmpfiles"
                    tmpfiles.write_text(tmpfiles.read_text().replace(original, replacement))
                    with self.assertRaises(ValueError):
                        VERIFY.verify(fake)

    def test_binary_only_freezer_binds_the_central_activation_package(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "source"
            package_source = repository / "deploy/native-ci/execd"
            package_source.mkdir(parents=True)
            (package_source / "marker").write_text("tracked\n")
            subprocess.run(["git", "init", "-q", repository], check=True)
            subprocess.run(["git", "-C", repository, "config", "user.name", "Test"], check=True)
            subprocess.run(["git", "-C", repository, "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", repository, "add", "."], check=True)
            subprocess.run(["git", "-C", repository, "commit", "-q", "-m", "fixture"], check=True)
            source_commit = subprocess.check_output(
                ["git", "-C", repository, "rev-parse", "HEAD"], text=True
            ).strip()
            binary = root / "buzz-ci-execd"
            binary.write_bytes(b"fixed execd binary\n")
            binary.chmod(0o755)
            binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
            provenance_value = {
                "binary": "buzz-ci-execd", "profile": "release",
                "schema": FREEZER.PROVENANCE_SCHEMA, "sha256": binary_sha256,
                "source_commit": source_commit,
            }
            provenance = root / "binary-provenance.json"
            provenance.write_bytes(FREEZER.canonical_json(provenance_value))
            provenance.chmod(0o600)
            activation = _activation_package(
                root / "activation", source_commit, binary_sha256,
                hashlib.sha256(provenance.read_bytes()).hexdigest(),
            )
            preactivation = root / "execd-preactivation.json"
            prepared = FREEZER.prepare_preactivation_input(
                repository, source_commit, binary, provenance, preactivation
            )
            output = root / "execd-package"
            manifest = FREEZER.freeze_package(
                repository, source_commit, binary, provenance, preactivation, activation, output
            )
            parsed, entry = INSTALL.parse_package(output)
            self.assertEqual(parsed, manifest)
            self.assertEqual(entry.target, "/usr/libexec/buzz-ci-execd")
            self.assertEqual(
                parsed["activation_binding"]["package_digest"],
                json.loads((activation / "activation-manifest.json").read_bytes())["package_digest"],
            )
            self.assertEqual(
                parsed["activation_binding"]["preactivation_input_sha256"],
                hashlib.sha256(preactivation.read_bytes()).hexdigest(),
            )
            self.assertEqual(prepared["binary_sha256"], binary_sha256)
            self.assertNotIn("/usr/libexec/buzz-ci-executor", [item["target"] for item in parsed["entries"]])

    def test_final_freeze_rejects_mismatched_replayed_and_tampered_preactivation_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "source"
            package_source = repository / "deploy/native-ci/execd"
            package_source.mkdir(parents=True)
            (package_source / "marker").write_text("tracked\n")
            subprocess.run(["git", "init", "-q", repository], check=True)
            subprocess.run(["git", "-C", repository, "config", "user.name", "Test"], check=True)
            subprocess.run(["git", "-C", repository, "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", repository, "add", "."], check=True)
            subprocess.run(["git", "-C", repository, "commit", "-q", "-m", "fixture"], check=True)
            source_commit = subprocess.check_output(
                ["git", "-C", repository, "rev-parse", "HEAD"], text=True
            ).strip()
            binary = root / "buzz-ci-execd"
            binary.write_bytes(b"fixed execd binary\n")
            binary.chmod(0o755)
            binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
            provenance = root / "binary-provenance.json"
            provenance.write_bytes(FREEZER.canonical_json({
                "binary": "buzz-ci-execd", "profile": "release",
                "schema": FREEZER.PROVENANCE_SCHEMA, "sha256": binary_sha256,
                "source_commit": source_commit,
            }))
            provenance.chmod(0o600)
            provenance_sha256 = hashlib.sha256(provenance.read_bytes()).hexdigest()
            activation = _activation_package(
                root / "activation", source_commit, binary_sha256, provenance_sha256,
            )
            preactivation = root / "preactivation.json"
            FREEZER.prepare_preactivation_input(
                repository, source_commit, binary, provenance, preactivation,
            )

            replayed = root / "replayed.json"
            replayed.write_bytes(FREEZER.canonical_json({
                **json.loads(preactivation.read_bytes()), "source_commit": "f" * 40,
            }))
            replayed.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "tuple differs"):
                FREEZER.freeze_package(
                    repository, source_commit, binary, provenance, replayed,
                    activation, root / "replayed-package",
                )

            tampered = root / "tampered.json"
            tampered.write_bytes(preactivation.read_bytes()[:-1] + b" \n")
            tampered.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "canonical"):
                FREEZER.freeze_package(
                    repository, source_commit, binary, provenance, tampered,
                    activation, root / "tampered-package",
                )

            mismatched = root / "mismatched.json"
            mismatch_value = json.loads(preactivation.read_bytes())
            mismatch_value["binary_sha256"] = "d" * 64
            mismatched.write_bytes(FREEZER.canonical_json(mismatch_value))
            mismatched.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "tuple differs"):
                FREEZER.freeze_package(
                    repository, source_commit, binary, provenance, mismatched,
                    activation, root / "mismatched-package",
                )

    def test_installer_is_create_once_dormant_and_central_receipt_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            package = base / "package"
            seccomp = b"test immutable seccomp\n"
            with mock.patch.dict(
                FREEZER.SECCOMP_CONTRACT,
                {"source_sha256": hashlib.sha256(seccomp).hexdigest()},
            ):
                manifest = _manual_execd_package(package, b"fixed execd binary\n")
                root = base / "root"
                root.mkdir(mode=0o700)
                seccomp_path = root / "usr/share/containers/seccomp.json"
                seccomp_path.parent.mkdir(parents=True)
                for parent in (root / "usr", root / "usr/share", root / "usr/share/containers"):
                    parent.chmod(0o755)
                seccomp_path.write_bytes(seccomp)
                seccomp_path.chmod(0o644)

                result = INSTALL.install(package, root)
                self.assertEqual(result["status"], "installed")
                self.assertEqual(result["activation_receipt"], "pending")
                self.assertEqual(result["install_receipt"], "verified")
                installed = root / "usr/libexec/buzz-ci-execd"
                self.assertEqual(installed.read_bytes(), b"fixed execd binary\n")
                self.assertEqual(_mode(installed), 0o755)
                self.assertEqual(INSTALL.install(package, root)["status"], "unchanged")

                binding = manifest["activation_binding"]
                receipt = {
                    "schema": binding["receipt_schema"],
                    "activation_id": binding["activation_id"],
                    "package_digest": binding["package_digest"],
                    "source_commit": binding["source_commit"],
                    "targets": [
                        {"target": item["target"], "staged_sha256": item["sha256"]}
                        for item in binding["owned_target_sha256"]
                    ],
                    "state": "staged",
                    "created_at": "2026-08-29T00:00:00Z",
                    "updated_at": "2026-08-29T00:00:00Z",
                    "principals_retained_on_rollback": True,
                    "acceptance_generated": [],
                    "acceptance_ledger_prior": None,
                    "fixed_package": {
                        "path": "/var/lib/buzzci/activation-controller/package",
                        "manifest_sha256": binding["manifest_sha256"],
                    },
                    "systemd_before": {},
                    "qualification": None,
                    "capacity_one": None,
                    "persistent_authorization": None,
                    "persistent_activation": None,
                    "qualification_zero": None,
                    "last_error": None,
                }
                receipt_path = root / "var/lib/buzzci/activation-controller/receipt-v1.json"
                receipt_path.parent.mkdir(mode=0o711)
                receipt_path.parent.chmod(0o711)
                receipt_path.write_bytes(FREEZER.canonical_json(receipt))
                receipt_path.chmod(0o600)
                self.assertEqual(INSTALL.inspect(package, root)["activation_receipt"], "verified")
                receipt["targets"][0]["staged_sha256"] = "f" * 64
                receipt_path.write_bytes(FREEZER.canonical_json(receipt))
                with self.assertRaisesRegex(ValueError, "managed bindings"):
                    INSTALL.inspect(package, root)

    def test_installer_takes_a_rolled_back_foreign_receipt_only_with_its_cleanup_marker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            seccomp = b"test immutable seccomp\n"
            with mock.patch.dict(
                FREEZER.SECCOMP_CONTRACT,
                {"source_sha256": hashlib.sha256(seccomp).hexdigest()},
            ):
                package, root = _manual_install_fixture(base, b"fixed execd binary\n", seccomp)
                manifest = json.loads((package / "package-manifest.json").read_bytes())
                binding = manifest["activation_binding"]
                controller = root / "var/lib/buzzci/activation-controller"
                controller.mkdir(parents=True)
                for parent in (root / "var", root / "var/lib"):
                    parent.chmod(0o755)
                (root / "var/lib/buzzci").chmod(0o711)
                controller.chmod(0o711)
                receipt_path = controller / "receipt-v1.json"
                marker_path = controller / "rollback-cleanup-v1.json"
                prior_manifest = {
                    "schema": "buzz-ci-capacity-one-activation-v2",
                    "activation_id": "buzz-ci-capacity-one-ffffffffffff-" + "9" * 12,
                    "package_digest": "9" * 64,
                    "source_commit": "f" * 40,
                    "entries": [],
                }
                prior_manifest_sha256 = hashlib.sha256(FREEZER.canonical_json(prior_manifest)).hexdigest()

                def write_receipt(state: str, manifest_sha256: str = prior_manifest_sha256) -> None:
                    receipt = {
                        "schema": binding["receipt_schema"],
                        "activation_id": prior_manifest["activation_id"],
                        "package_digest": prior_manifest["package_digest"],
                        "source_commit": prior_manifest["source_commit"],
                        "targets": [],
                        "state": state,
                        "created_at": "2026-09-02T00:00:00Z",
                        "updated_at": "2026-09-03T01:13:08Z",
                        "principals_retained_on_rollback": True,
                        "acceptance_generated": [],
                        "acceptance_ledger_prior": None,
                        "fixed_package": {
                            "path": "/var/lib/buzzci/activation-controller/package",
                            "manifest_sha256": manifest_sha256,
                        },
                        "systemd_before": {},
                        "qualification": None,
                        "capacity_one": None,
                        "persistent_authorization": None,
                        "persistent_activation": None,
                        "qualification_zero": None,
                        "last_error": None,
                    }
                    receipt_path.write_bytes(FREEZER.canonical_json(receipt))
                    receipt_path.chmod(0o600)

                def write_marker(manifest: dict[str, object], mode: int = 0o600) -> None:
                    marker = {
                        "schema": INSTALL.ROLLBACK_CLEANUP_SCHEMA,
                        "activation_id": manifest["activation_id"],
                        "package_digest": manifest["package_digest"],
                        "source_commit": manifest["source_commit"],
                        "manifest_sha256": hashlib.sha256(FREEZER.canonical_json(manifest)).hexdigest(),
                        "package_assets": ["activation-manifest.json"],
                        "manifest": manifest,
                    }
                    marker_path.write_bytes(FREEZER.canonical_json(marker))
                    marker_path.chmod(mode)

                # A live receipt of another activation refuses with or without a marker.
                for state in (
                    "preparing", "staged_zero", "qualified_closed", "activating", "active_one",
                    "preparing_zero", "qualification_uncertain", "rollback_failed", "rollback_cleanup",
                ):
                    with self.subTest(state=state):
                        write_receipt(state)
                        if marker_path.exists():
                            marker_path.unlink()
                        with self.assertRaisesRegex(ValueError, "central activation receipt binding differs"):
                            INSTALL.install(package, root, dry_run=True)
                        write_marker(prior_manifest)
                        with self.assertRaisesRegex(ValueError, "central activation receipt binding differs"):
                            INSTALL.inspect(package, root)
                        marker_path.unlink()

                # A rolled-back receipt without the controller's cleanup marker refuses.
                write_receipt("rolled_back")
                with self.assertRaisesRegex(ValueError, "lacks its rollback cleanup marker"):
                    INSTALL.install(package, root, dry_run=True)

                # A marker bound to a third activation, or to a different manifest digest, refuses.
                other_manifest = dict(prior_manifest, package_digest="8" * 64)
                write_marker(other_manifest)
                with self.assertRaisesRegex(ValueError, "differs from its rollback cleanup marker"):
                    INSTALL.install(package, root, dry_run=True)
                write_receipt("rolled_back", manifest_sha256="7" * 64)
                write_marker(prior_manifest)
                with self.assertRaisesRegex(ValueError, "differs from its rollback cleanup marker"):
                    INSTALL.install(package, root, dry_run=True)

                # A tampered or unsafe marker refuses before any binding decision.
                write_receipt("rolled_back")
                write_marker(prior_manifest, mode=0o644)
                with self.assertRaisesRegex(ValueError, "rollback cleanup marker differs"):
                    INSTALL.install(package, root, dry_run=True)
                write_marker(prior_manifest)
                tampered = json.loads(marker_path.read_bytes())
                tampered["manifest"]["entries"] = [{"role": "drift"}]
                marker_path.write_bytes(FREEZER.canonical_json(tampered))
                with self.assertRaisesRegex(ValueError, "rollback cleanup marker binding differs"):
                    INSTALL.install(package, root, dry_run=True)

                # The proven rolled-back receipt lets the next execd package install dormant.
                write_marker(prior_manifest)
                self.assertEqual(marker_path.stat().st_mode & 0o777, 0o600)
                dry_run = INSTALL.install(package, root, dry_run=True)
                self.assertEqual((dry_run["status"], dry_run["activation_receipt"]), ("dry_run", "rolled_back"))
                self.assertFalse((root / "usr/libexec/buzz-ci-execd").exists())
                installed = INSTALL.install(package, root)
                self.assertEqual((installed["status"], installed["activation_receipt"]), ("installed", "rolled_back"))
                self.assertEqual((root / "usr/libexec/buzz-ci-execd").read_bytes(), b"fixed execd binary\n")
                self.assertEqual(INSTALL.inspect(package, root)["activation_receipt"], "rolled_back")
                self.assertEqual(INSTALL.install(package, root)["status"], "unchanged")
                # The rolled-back receipt and its marker are left for the controller to retire.
                self.assertEqual(json.loads(receipt_path.read_bytes())["state"], "rolled_back")
                self.assertTrue(marker_path.exists())

    def test_installer_never_reopens_the_validated_binary_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            seccomp = b"test immutable seccomp\n"
            binary = b"validated execd binary\n"
            with mock.patch.dict(
                FREEZER.SECCOMP_CONTRACT,
                {"source_sha256": hashlib.sha256(seccomp).hexdigest()},
            ):
                package, root = _manual_install_fixture(base, binary, seccomp)
                asset = Path(os.path.abspath(package / "assets/buzz-ci-execd"))
                original_read = INSTALL.read_regular
                asset_reads = 0

                def substitute_second_read(
                    path: Path,
                    maximum: int = 128 * 1024 * 1024,
                ) -> tuple[bytes, os.stat_result]:
                    nonlocal asset_reads
                    payload, metadata = original_read(path, maximum)
                    if Path(os.path.abspath(path)) == asset:
                        asset_reads += 1
                        if asset_reads > 1:
                            return b"caller-controlled substitute\n", metadata
                    return payload, metadata

                with mock.patch.object(INSTALL, "read_regular", side_effect=substitute_second_read):
                    INSTALL.install(package, root)
                self.assertEqual(asset_reads, 1)
                self.assertEqual((root / "usr/libexec/buzz-ci-execd").read_bytes(), binary)

    def test_package_rename_and_symlink_substitution_keeps_validated_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            seccomp = b"test immutable seccomp\n"
            binary = b"validated execd binary\n"
            with mock.patch.dict(
                FREEZER.SECCOMP_CONTRACT,
                {"source_sha256": hashlib.sha256(seccomp).hexdigest()},
            ):
                package, root = _manual_install_fixture(base, binary, seccomp)
                original_parse = INSTALL.parse_package

                def swap_after_validation(path: Path) -> tuple[dict[str, object], INSTALL.Entry]:
                    parsed = original_parse(path)
                    assets = package / "assets"
                    assets.rename(package / "validated-assets")
                    hostile = package / "hostile-assets"
                    hostile.mkdir(mode=0o700)
                    substitute = hostile / "buzz-ci-execd"
                    substitute.write_bytes(b"caller-controlled substitute\n")
                    substitute.chmod(0o500)
                    assets.symlink_to(hostile, target_is_directory=True)
                    return parsed

                with mock.patch.object(INSTALL, "parse_package", side_effect=swap_after_validation):
                    INSTALL.install(package, root)
                self.assertEqual((root / "usr/libexec/buzz-ci-execd").read_bytes(), binary)

    def test_target_directory_rename_and_symlink_is_detected_and_cleaned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            seccomp = b"test immutable seccomp\n"
            with mock.patch.dict(
                FREEZER.SECCOMP_CONTRACT,
                {"source_sha256": hashlib.sha256(seccomp).hexdigest()},
            ):
                package, root = _manual_install_fixture(base, b"fixed execd binary\n", seccomp)
                original_write = INSTALL._write_temporary_at
                attacked = False

                def rename_parent(
                    directory_fd: int,
                    stem: str,
                    payload: bytes,
                    mode: int,
                    uid: int,
                    gid: int,
                ) -> str:
                    nonlocal attacked
                    if stem == "buzz-ci-execd" and not attacked:
                        attacked = True
                        target_parent = root / "usr/libexec"
                        target_parent.rename(root / "usr/libexec-held")
                        attacker = root / "attacker"
                        attacker.mkdir(mode=0o755)
                        target_parent.symlink_to(attacker, target_is_directory=True)
                    return original_write(directory_fd, stem, payload, mode, uid, gid)

                with mock.patch.object(INSTALL, "_write_temporary_at", side_effect=rename_parent):
                    with self.assertRaisesRegex(ValueError, "directory changed"):
                        INSTALL.install(package, root)
                self.assertFalse((root / "usr/libexec-held/buzz-ci-execd").exists())
                self.assertFalse((root / "attacker/buzz-ci-execd").exists())
                self.assertEqual(list((root / "usr/libexec-held").glob(".buzz-ci-execd.*")), [])
                self.assertFalse(
                    (root / "var/lib/buzzci/execd-v2/package/receipt-v1.json").exists()
                )

    def test_binary_readback_failure_removes_an_absent_prior_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            seccomp = b"test immutable seccomp\n"
            with mock.patch.dict(
                FREEZER.SECCOMP_CONTRACT,
                {"source_sha256": hashlib.sha256(seccomp).hexdigest()},
            ):
                package, root = _manual_install_fixture(base, b"fixed execd binary\n", seccomp)
                original_matches = INSTALL._binary_matches_at
                calls = 0

                def fail_first_readback(*args: object) -> bool:
                    nonlocal calls
                    calls += 1
                    if calls == 2:
                        return False
                    return original_matches(*args)

                with mock.patch.object(INSTALL, "_binary_matches_at", side_effect=fail_first_readback):
                    with self.assertRaisesRegex(ValueError, "readback differs"):
                        INSTALL.install(package, root)
                target_parent = root / "usr/libexec"
                self.assertFalse((target_parent / "buzz-ci-execd").exists())
                self.assertEqual(list(target_parent.glob(".buzz-ci-execd.*")), [])

    def test_receipt_readback_failure_restores_prior_target_and_removes_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            seccomp = b"test immutable seccomp\n"
            prior = b"prior execd binary\n"
            with mock.patch.dict(
                FREEZER.SECCOMP_CONTRACT,
                {"source_sha256": hashlib.sha256(seccomp).hexdigest()},
            ):
                package, root = _manual_install_fixture(base, b"fixed execd binary\n", seccomp)
                target = root / "usr/libexec/buzz-ci-execd"
                target.parent.mkdir(mode=0o755)
                target.parent.chmod(0o755)
                target.write_bytes(prior)
                target.chmod(0o755)
                original_verify = INSTALL._verify_receipt_at

                def fail_present_receipt(*args: object) -> None:
                    original_verify(*args)
                    raise OSError("forced receipt readback failure")

                with mock.patch.object(INSTALL, "_verify_receipt_at", side_effect=fail_present_receipt):
                    with self.assertRaisesRegex(OSError, "forced receipt readback"):
                        INSTALL.install(package, root)
                self.assertEqual(target.read_bytes(), prior)
                self.assertEqual(_mode(target), 0o755)
                self.assertEqual(list(target.parent.glob(".buzz-ci-execd.*")), [])
                self.assertFalse(
                    (root / "var/lib/buzzci/execd-v2/package/receipt-v1.json").exists()
                )

    def test_receipt_publication_failure_removes_new_binary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            seccomp = b"test immutable seccomp\n"
            with mock.patch.dict(
                FREEZER.SECCOMP_CONTRACT,
                {"source_sha256": hashlib.sha256(seccomp).hexdigest()},
            ):
                package, root = _manual_install_fixture(base, b"fixed execd binary\n", seccomp)
                with mock.patch.object(
                    INSTALL,
                    "_publish_receipt",
                    side_effect=OSError("forced receipt publication failure"),
                ):
                    with self.assertRaisesRegex(OSError, "forced receipt publication"):
                        INSTALL.install(package, root)
                target_parent = root / "usr/libexec"
                self.assertFalse((target_parent / "buzz-ci-execd").exists())
                self.assertEqual(list(target_parent.glob(".buzz-ci-execd.*")), [])
                self.assertFalse(
                    (root / "var/lib/buzzci/execd-v2/package/receipt-v1.json").exists()
                )

    def test_installer_rejects_links_drift_and_unreceipted_central_assets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            seccomp = b"test immutable seccomp\n"
            with mock.patch.dict(
                FREEZER.SECCOMP_CONTRACT,
                {"source_sha256": hashlib.sha256(seccomp).hexdigest()},
            ):
                package = base / "package"
                _manual_execd_package(package, b"fixed execd binary\n")
                root = base / "root"
                root.mkdir(mode=0o700)
                seccomp_path = root / "usr/share/containers/seccomp.json"
                seccomp_path.parent.mkdir(parents=True)
                for parent in (root / "usr", root / "usr/share", root / "usr/share/containers"):
                    parent.chmod(0o755)
                seccomp_path.write_bytes(seccomp)
                seccomp_path.chmod(0o644)
                central = root / FREEZER.ACTIVATION_OWNED_TARGETS[0].removeprefix("/")
                central.parent.mkdir(parents=True)
                central.write_bytes(b"unreceipted\n")
                with self.assertRaisesRegex(ValueError, "without a central receipt"):
                    INSTALL.install(package, root)
                central.unlink()
                asset = package / "assets/buzz-ci-execd"
                replacement = package / "assets/replacement"
                replacement.write_bytes(asset.read_bytes())
                replacement.chmod(0o500)
                asset.unlink()
                asset.symlink_to(replacement.name)
                with self.assertRaises((OSError, ValueError)):
                    INSTALL.parse_package(package)


if __name__ == "__main__":
    unittest.main()

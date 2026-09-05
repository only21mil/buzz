from __future__ import annotations

import copy
import base64
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from unittest import mock

ACTIVATION_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ACTIVATION_ROOT.parents[2]
sys.path.insert(0, str(ACTIVATION_ROOT))

import package as activation_package


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_registered_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


CONTROLLER = load_module("activation_controller", ACTIVATION_ROOT / "controller.py")
FREEZER = load_module("activation_freezer", ACTIVATION_ROOT / "freeze_package.py")
INVENTORY = load_module("activation_inventory", ACTIVATION_ROOT / "check_package_inventory.py")
RENDERER = load_module(
    "activation_test_render_inputs",
    ACTIVATION_ROOT / "render_inputs/render_inputs.py",
)
TEMPLATE_GENERATOR = load_module(
    "activation_test_checked_templates",
    ACTIVATION_ROOT / "render_inputs/generate_checked_templates.py",
)
CLEAN_HOST_GUEST = load_module(
    "activation_test_clean_host_guest",
    ACTIVATION_ROOT / "tests/clean_host_e2e/guest_entry.py",
)
ACTIVATION_SCAFFOLD = load_module(
    "activation_test_shared_scaffold",
    REPO_ROOT / "deploy/native-ci/tests/support/activation_scaffold.py",
)
ActivationFixture = ACTIVATION_SCAFFOLD.ActivationFixture
QUALIFICATION_SCRIPT = ACTIVATION_SCAFFOLD.QUALIFICATION_SCRIPT
EXECD_ROOT = REPO_ROOT / "deploy/native-ci/execd"
EXECD_FREEZER = load_registered_module(
    "activation_test_execd_freezer", EXECD_ROOT / "freeze_package.py",
)
previous_freezer = sys.modules.get("freeze_package")
sys.modules["freeze_package"] = EXECD_FREEZER
try:
    EXECD_INSTALLER = load_registered_module(
        "activation_test_execd_installer", EXECD_ROOT / "install.py",
    )
finally:
    if previous_freezer is None:
        del sys.modules["freeze_package"]
    else:
        sys.modules["freeze_package"] = previous_freezer

def write_file(path: Path, payload: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    path.chmod(mode)


def first_subordinate_id(path: Path) -> int | None:
    invoking_uid = os.getuid()
    accepted_principals = {str(invoking_uid)}
    try:
        accepted_principals.add(pwd.getpwuid(invoking_uid).pw_name)
    except KeyError:
        pass
    try:
        entries = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for entry in entries:
        try:
            owner, start, count = entry.split(":", 2)
            if owner in accepted_principals and int(count) > 0:
                return int(start)
        except ValueError:
            continue
    return None


def user_namespace_probe_unavailable(stderr: str) -> bool:
    message = stderr.strip()
    if message in {
        "unshare: unshare failed: Operation not permitted",
        "setpriv: setresuid failed: Operation not permitted",
        "setpriv: setresgid failed: Operation not permitted",
    }:
        return True
    return any(re.fullmatch(pattern, message) for pattern in (
        r"newuidmap: uid range \[\d+-\d+\) -> \[\d+-\d+\) not allowed",
        r"newgidmap: gid range \[\d+-\d+\) -> \[\d+-\d+\) not allowed",
        r"newuidmap: write to uid_map failed: Operation not permitted",
        r"newgidmap: write to gid_map failed: Operation not permitted",
    ))


def execd_package_for_activation(
    fixture: "ActivationFixture",
) -> tuple[Path, dict[str, object]]:
    source_component = next(
        item for item in fixture.components if item["name"] == "execd"
    )
    if source_component["source_commit"] != fixture.manifest["source_commit"]:
        provenance_source = source_component["provenance_source"]
        provenance = json.loads(fixture.assets[provenance_source][0])
        provenance["source_commit"] = fixture.manifest["source_commit"]
        provenance_raw = activation_package.canonical_json(provenance)
        fixture.assets[provenance_source] = (provenance_raw, 0o400)
        source_component["source_commit"] = fixture.manifest["source_commit"]
        source_component["provenance_sha256"] = activation_package.digest(provenance_raw)
        provenance_path = fixture.package / provenance_source
        provenance_path.chmod(0o600)
        write_file(provenance_path, provenance_raw, 0o400)
        fixture.manifest = fixture._manifest()
        fixture.scenario = fixture._scenario()
        fixture.binding = CONTROLLER._acceptance_binding(
            fixture.manifest, fixture.scenario,
        )
        write_file(
            fixture.package / "activation-manifest.json",
            activation_package.canonical_json(fixture.manifest),
            0o600,
        )
    component = next(
        item for item in fixture.manifest["components"] if item["name"] == "execd"
    )
    candidate = (fixture.root / CONTROLLER.EXECD_BINARY_PATH.lstrip("/")).read_bytes()
    provenance = fixture.assets[component["provenance_source"]][0]
    seccomp = b"activation execd installer fixture seccomp\n"
    seccomp_digest = activation_package.digest(seccomp)
    seccomp_contract = copy.deepcopy(EXECD_FREEZER.SECCOMP_CONTRACT)
    seccomp_contract.update({
        "source_sha256": seccomp_digest,
        "installed_path": f"/var/lib/buzzci/seccomp/v1/sha256/{seccomp_digest}.json",
    })
    write_file(
        fixture.root / str(seccomp_contract["source_path"]).lstrip("/"),
        seccomp,
        0o644,
    )
    for relative, mode in (
        ("usr/libexec", 0o755),
        ("var", 0o755),
        ("var/lib", 0o755),
        ("var/lib/buzzci", 0o711),
        ("var/lib/buzzci/activation-controller", 0o711),
    ):
        path = fixture.root / relative
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(mode)
    package = fixture.temporary / "execd-package"
    package.mkdir(mode=0o700)
    (package / "assets").mkdir(mode=0o700)
    write_file(package / "assets/buzz-ci-execd", candidate, 0o500)
    write_file(package / "binary-provenance.json", provenance, 0o600)
    with mock.patch.dict(
        EXECD_FREEZER.SECCOMP_CONTRACT, seccomp_contract, clear=True,
    ):
        binding = EXECD_FREEZER.activation_binding(
            fixture.package,
            component["source_commit"],
            component["binary_sha256"],
            component["provenance_sha256"],
            "e" * 64,
        )
        manifest: dict[str, object] = {
            "schema": EXECD_FREEZER.SCHEMA,
            "package_id": (
                f"buzz-ci-execd-{str(component['source_commit'])[:12]}-"
                f"{str(component['binary_sha256'])[:12]}"
            ),
            "source_commit": component["source_commit"],
            "binary_provenance_sha256": component["provenance_sha256"],
            "default_state": EXECD_FREEZER.DEFAULT_STATE,
            "runtime_contract": EXECD_FREEZER.RUNTIME_CONTRACT,
            "activation_owned_targets": EXECD_FREEZER.ACTIVATION_OWNED_TARGETS,
            "activation_binding": binding,
            "seccomp_contract": seccomp_contract,
            "install_receipt": EXECD_FREEZER.INSTALL_RECEIPT,
            "package_uid": 0,
            "package_gid": 0,
            "directories": EXECD_FREEZER.DIRECTORIES,
            "entries": [{
                "role": "binary",
                "source": "assets/buzz-ci-execd",
                "target": CONTROLLER.EXECD_BINARY_PATH,
                "source_mode": "0500",
                "install_mode": "0755",
                "uid": 0,
                "gid": 0,
                "sha256": component["binary_sha256"],
            }],
        }
        manifest["package_digest"] = EXECD_FREEZER.sha256(
            EXECD_FREEZER.canonical_json(manifest)
        )
        write_file(
            package / "package-manifest.json",
            EXECD_FREEZER.canonical_json(manifest),
            0o600,
        )
        EXECD_INSTALLER.parse_package(package)
    return package, seccomp_contract


def execd_install(
    package: Path, root: Path, seccomp_contract: dict[str, object],
) -> dict[str, object]:
    with mock.patch.dict(
        EXECD_FREEZER.SECCOMP_CONTRACT, seccomp_contract, clear=True,
    ):
        return EXECD_INSTALLER.install(package, root)


def execd_rollback(
    package: Path, root: Path, seccomp_contract: dict[str, object],
) -> dict[str, object]:
    with mock.patch.dict(
        EXECD_FREEZER.SECCOMP_CONTRACT, seccomp_contract, clear=True,
    ):
        return EXECD_INSTALLER.rollback(package, root)


class ActivationControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.fixture = ActivationFixture(Path(self.temporary.name))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def historical_rollback_manifest(self) -> dict[str, object]:
        raw = (ACTIVATION_ROOT / "tests/fixtures/rollback-manifest-009d2f06.json").read_bytes()
        self.assertEqual(activation_package.digest(raw), CONTROLLER._RETAINED_ROLLBACK_MANIFEST_SHA256)
        manifest = json.loads(raw)
        self.assertEqual(activation_package.canonical_json(manifest), raw)
        return manifest

    def test_historical_manifest_is_retirement_only(self) -> None:
        old = self.historical_rollback_manifest()
        before = activation_package.canonical_json(old)
        CONTROLLER._validate_rollback_manifest(old)
        self.assertEqual(activation_package.canonical_json(old), before)
        CONTROLLER._validate_rollback_manifest(self.fixture.manifest)
        with self.assertRaisesRegex(ValueError, "public acceptance template shape differs"):
            activation_package.validate_manifest(old)
        write_file(self.fixture.package / "activation-manifest.json", before, 0o600)
        with self.assertRaisesRegex(ValueError, "public acceptance template shape differs"):
            CONTROLLER.load_package(self.fixture.package, live=False)

    def test_historical_manifest_mutations_are_not_compatibility(self) -> None:
        old = self.historical_rollback_manifest()
        mutations = (
            lambda m: m.update(source_commit="f" * 40),
            lambda m: m.update(package_digest="f" * 64),
            lambda m: m.update(activation_id="buzz-ci-capacity-one-other"),
            lambda m: m["acceptance_template"]["actor"].update(public_key="f" * 64),
            lambda m: m["acceptance_template"]["actor"].update(generation=99),
            lambda m: m["identities"]["qualification"].update(uid=0),
            lambda m: m["entries"][0].update(target="/etc/other"),
            lambda m: next(e for e in m["entries"] if e["role"] == "fixture_script").update(sha256=activation_package.FIXTURE_SCRIPT_SHA256),
            lambda m: next(e for e in m["entries"] if e["role"] == "receipt_verifier_expected_stages").update(sha256=activation_package.RECEIPT_VERIFIER_EXPECTED_STAGES_SHA256),
            lambda m: m["acceptance_template"].update(export_generation=1),
            lambda m: m.update(extra=True),
        )
        for number, mutate in enumerate(mutations):
            with self.subTest(mutation=number):
                changed = copy.deepcopy(old)
                mutate(changed)
                with self.assertRaises(ValueError):
                    CONTROLLER._validate_rollback_manifest(changed)
        changed = copy.deepcopy(old)
        changed["acceptance_template"]["actor"]["generation"] += 1
        draft = {k: v for k, v in changed.items() if k not in {"package_digest", "activation_id"}}
        draft["schema"] = activation_package.DRAFT_SCHEMA
        changed["package_digest"] = activation_package.digest(activation_package.canonical_json(draft))
        changed["activation_id"] = f"buzz-ci-capacity-one-{changed['source_commit'][:12]}-{changed['package_digest'][:12]}"
        with self.assertRaises(ValueError):
            CONTROLLER._validate_rollback_manifest(changed)
        # Missing M15 fields cannot select a historical contract for a new source.
        current = copy.deepcopy(self.fixture.manifest)
        del current["acceptance_template"]["export_subject"]
        with self.assertRaisesRegex(ValueError, "public acceptance template shape differs"):
            CONTROLLER._validate_rollback_manifest(current)

    def test_historical_marker_metadata_and_retirement_bindings_stay_strict(self) -> None:
        old = self.historical_rollback_manifest()
        marker = CONTROLLER._rollback_cleanup_value(old)
        path = self.fixture.root / CONTROLLER.ROLLBACK_CLEANUP_PATH.lstrip("/")
        raw = activation_package.canonical_json(marker)
        write_file(path, raw, 0o644)
        with self.assertRaisesRegex(ValueError, "metadata is unsafe"):
            CONTROLLER._read_rollback_cleanup(self.fixture.root)
        write_file(path, raw + b"\n", 0o600)
        with self.assertRaisesRegex(ValueError, "noncanonical"):
            CONTROLLER._read_rollback_cleanup(self.fixture.root)
        changed = copy.deepcopy(marker)
        changed["manifest_sha256"] = "f" * 64
        write_file(path, activation_package.canonical_json(changed), 0o600)
        with self.assertRaisesRegex(ValueError, "binding differs"):
            CONTROLLER._read_rollback_cleanup(self.fixture.root)
        write_file(path, raw, 0o600)
        self.assertEqual(CONTROLLER._read_rollback_cleanup(self.fixture.root), marker)
        retirement = CONTROLLER._rollback_retirement_value(marker, self.fixture.manifest)
        CONTROLLER._validate_rollback_retirement(retirement)
        for field in ("archive_path", "marker_sha256"):
            with self.subTest(field=field):
                changed = copy.deepcopy(retirement)
                changed[field] = "f" * 64
                with self.assertRaises(ValueError):
                    CONTROLLER._validate_rollback_retirement(changed)
        changed = copy.deepcopy(retirement)
        changed["marker"]["manifest"]["acceptance_template"]["actor"]["generation"] += 1
        with self.assertRaises(ValueError):
            CONTROLLER._validate_rollback_retirement(changed)

    def test_historical_cleanup_mixed_dormant_state_stages_and_archives_exactly(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        CONTROLLER.rollback(manifest, self.fixture.root, driver)
        old = self.historical_rollback_manifest()
        marker = CONTROLLER._rollback_cleanup_value(old)
        receipt = CONTROLLER._read_receipt(self.fixture.root)
        for key in ("activation_id", "package_digest", "source_commit"):
            receipt[key] = old[key]
        receipt["fixed_package"]["manifest_sha256"] = activation_package.digest(activation_package.canonical_json(old))
        CONTROLLER._write_receipt(self.fixture.root, receipt, manifest["identities"]["controld"]["gid"])
        marker_path = self.fixture.root / CONTROLLER.ROLLBACK_CLEANUP_PATH.lstrip("/")
        old_raw = activation_package.canonical_json(marker)
        write_file(marker_path, old_raw, 0o600)
        # New dormant component files coexist with the old controller receipt.
        # The retained program verifier must prove the permitted next bytes.
        receipt_path = self.fixture.root / CONTROLLER.RECEIPT_PATH.lstrip("/")
        receipt_before = receipt_path.read_bytes()
        wrong_receipt = copy.deepcopy(receipt)
        wrong_receipt["package_digest"] = "f" * 64
        CONTROLLER._write_receipt(self.fixture.root, wrong_receipt, manifest["identities"]["controld"]["gid"])
        with self.assertRaisesRegex(ValueError, "receipt belongs to a different activation package"):
            CONTROLLER.check_current(manifest, self.fixture.root, driver)
        write_file(receipt_path, receipt_before, 0o600)
        checked = CONTROLLER.check_current(manifest, self.fixture.root, driver)
        self.assertEqual(checked["status"], "ready_to_stage")
        self.assertEqual(checked["retained_recovery_targets"], {
            "activation_controller": "next", "activation_package_module": "next",
        })
        self.assertEqual(marker_path.read_bytes(), old_raw)
        self.assertEqual(receipt_path.read_bytes(), receipt_before)
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        self.assertIsNone(CONTROLLER._read_rollback_cleanup(self.fixture.root))
        self.assertIsNone(CONTROLLER._read_rollback_retirement(self.fixture.root))
        archives = list((self.fixture.root / CONTROLLER.ROLLBACK_ARCHIVE_ROOT.lstrip("/")).iterdir())
        self.assertEqual(len(archives), 1)
        archive = json.loads(archives[0].read_bytes())
        self.assertEqual(activation_package.canonical_json(archive["marker"]), old_raw)
        self.assertEqual(archive["retired_by_package_digest"], manifest["package_digest"])
        self.assertEqual(CONTROLLER._read_receipt(self.fixture.root)["state"], "staged_zero")
        CONTROLLER.rollback(manifest, self.fixture.root, driver)
        self.assertEqual(CONTROLLER._read_receipt(self.fixture.root)["state"], "rolled_back")
        self.assertEqual(CONTROLLER._read_rollback_cleanup(self.fixture.root)["manifest"], manifest)

    def legacy_pre_fixed_boundaries(self, manifest: dict[str, object]) -> list[tuple[str, int]]:
        targets = [entry for entry in manifest["entries"] if entry["role"] != "execd_config"]
        return [("apply", cut) for cut in range(len(targets) + 1)] + [("provision", 0), ("tmpfiles", 0)]

    def fail_stage_at_legacy_boundary(
        self, fixture: ActivationFixture, manifest: dict[str, object], payloads: dict[str, bytes],
        driver, binding: dict[str, object], boundary: tuple[str, int],
    ) -> None:
        phase, cut = boundary
        if phase == "apply":
            def partial_apply(
                applied_manifest: dict[str, object], applied_payloads: dict[str, bytes],
                root: Path, requested_phase: str,
            ) -> None:
                self.assertEqual(requested_phase, "staged")
                targets = [entry for entry in applied_manifest["entries"] if entry["role"] != "execd_config"]
                for entry in targets[:cut]:
                    CONTROLLER._atomic_write(
                        root, entry["target"], applied_payloads[entry["source"]],
                        activation_package.parse_mode(entry["install_mode"]), entry["uid"], entry["gid"],
                    )
                raise OSError(f"injected legacy apply boundary {cut}")

            context = mock.patch.object(CONTROLLER, "_apply_phase", side_effect=partial_apply)
        else:
            original = getattr(driver, phase)

            def mutate_then_fail(*arguments) -> None:
                original(*arguments)
                raise OSError(f"injected legacy {phase} boundary")

            context = mock.patch.object(driver, phase, side_effect=mutate_then_fail)
        with context, self.assertRaisesRegex(OSError, "injected legacy"):
            CONTROLLER.stage(manifest, payloads, fixture.root, driver, binding)

    def fixed_rollback_cli(self, fixture: ActivationFixture) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [
                sys.executable, str(fixture.root / "usr/libexec/buzz-ci-activation-controller"),
                "rollback", "--package", str(fixture.root / CONTROLLER.FIXED_PACKAGE_PATH.lstrip("/")),
                "--root", str(fixture.root), "--fake-systemd-state", str(fixture.fake_state),
            ],
            check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )

    def fixed_stage_cli(
        self, fixture: ActivationFixture, executable: Path, scenario: Path,
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [
                sys.executable, str(executable), "stage",
                "--package", str(fixture.root / CONTROLLER.FIXED_PACKAGE_PATH.lstrip("/")),
                "--scenario", str(scenario),
                "--root", str(fixture.root),
                "--fake-systemd-state", str(fixture.fake_state),
            ],
            check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )

    def cut_stage_process_at(
        self, fixture: ActivationFixture, manifest: dict[str, object],
        payloads: dict[str, bytes], driver, binding: dict[str, object], boundary: str,
    ) -> None:
        pid = os.fork()
        if pid == 0:
            def cut(observed: str) -> None:
                if observed == boundary:
                    os._exit(91)

            try:
                with mock.patch.object(CONTROLLER, "_stage_restart_boundary", side_effect=cut):
                    CONTROLLER.stage(manifest, payloads, fixture.root, driver, binding)
            except BaseException:
                os._exit(92)
            os._exit(93)
        _pid, status = os.waitpid(pid, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 91, boundary)

    def advance_recovery_candidate(self, fixture: ActivationFixture) -> None:
        for role in CONTROLLER.ROLLBACK_RECOVERY_ROLES:
            entry = next(item for item in fixture.entries if item["role"] == role)
            payload, mode = fixture.assets[entry["source"]]
            if role == "activation_controller":
                marker = b'RECEIPT_PATH = "/var/lib/buzzci/activation-controller/receipt-v1.json"'
                payload = payload.replace(
                    marker,
                    b'assert activation_package.RECOVERY_TEST_GENERATION == 2\n' + marker,
                    1,
                )
            else:
                payload += b"\nRECOVERY_TEST_GENERATION = 2\n"
            fixture.assets[entry["source"]] = (payload, mode)
            entry["sha256"] = activation_package.digest(payload)
            target = fixture.package / entry["source"]
            target.chmod(0o600)
            write_file(target, payload, mode)
        fixture.acceptance_template["actor"]["generation"] += 1
        fixture.manifest = fixture._manifest()
        fixture.scenario = fixture._scenario()
        fixture.binding = CONTROLLER._acceptance_binding(
            fixture.manifest, fixture.scenario,
        )
        write_file(
            fixture.package / "activation-manifest.json",
            activation_package.canonical_json(fixture.manifest),
            0o600,
        )

    def zero_request(self, action: str, operation_digit: str = "d", **optional: object) -> tuple[dict[str, object], bytes]:
        binding = self.fixture.binding
        request: dict[str, object] = {
            "schema_version": CONTROLLER.ZERO_REQUEST_SCHEMA,
            "action": action,
            "activation_id": binding["activation_id"],
            "activation_package_digest": binding["activation_package_digest"],
            "scenario_sha256": binding["scenario_sha256"],
            "initial_controller_generation": binding["fixture"]["controller_generation"],
            "initial_runner_generation": binding["fixture"]["runner_generation"],
            "operation_id": operation_digit * 64,
        }
        for field in CONTROLLER.ZERO_OPTIONAL_FIELDS:
            if field in optional:
                request[field] = optional[field]
        return request, CONTROLLER._wire_json(request)

    def parsed_zero_request(
        self, cli_action: str, operation_digit: str = "d", **optional: object,
    ) -> tuple[dict[str, object], str]:
        _request, raw = self.zero_request(CONTROLLER.ZERO_CLI_ACTIONS[cli_action], operation_digit, **optional)
        receipt = CONTROLLER._read_receipt(self.fixture.root)
        return CONTROLLER._parse_zero_request(raw, cli_action, receipt)

    def capacity_one_request(self, operation_digit: str = "b") -> tuple[dict[str, object], bytes]:
        binding = self.fixture.binding
        request: dict[str, object] = {
            "schema_version": CONTROLLER.CAPACITY_ONE_REQUEST_SCHEMA,
            "action": CONTROLLER.CAPACITY_ONE_WIRE_ACTION,
            "activation_id": binding["activation_id"],
            "activation_package_digest": binding["activation_package_digest"],
            "scenario_sha256": binding["scenario_sha256"],
            "initial_controller_generation": binding["fixture"]["controller_generation"],
            "initial_runner_generation": binding["fixture"]["runner_generation"],
            "operation_id": operation_digit * 64,
        }
        return request, CONTROLLER._wire_json(request)

    def set_capacity_one(
        self, manifest: dict[str, object], payloads: dict[str, bytes], driver: CONTROLLER.FakeSystemd,
        operation_digit: str = "b",
    ) -> dict[str, object]:
        _request, raw = self.capacity_one_request(operation_digit)
        receipt = CONTROLLER._read_receipt(self.fixture.root)
        request, request_sha256 = CONTROLLER._parse_capacity_one_request(raw, receipt)
        return CONTROLLER._set_capacity_one(
            manifest, payloads, self.fixture.root, driver, request, request_sha256,
        )

    def activate_one(
        self, manifest: dict[str, object], payloads: dict[str, bytes], driver: CONTROLLER.FakeSystemd,
        operation_digit: str = "b",
    ) -> tuple[dict[str, object], dict[str, object]]:
        qualification = CONTROLLER.activate(manifest, payloads, self.fixture.root, driver)
        activated = self.set_capacity_one(manifest, payloads, driver, operation_digit)
        return qualification, activated

    def finalized_canary_evidence(
        self, manifest: dict[str, object], payloads: dict[str, bytes], driver: CONTROLLER.FakeSystemd,
    ) -> tuple[Path, Path]:
        self.activate_one(manifest, payloads, driver)
        prepare, prepare_sha = self.parsed_zero_request("prepare-qualification-zero", "c")
        CONTROLLER._prepare_qualification_zero(
            manifest, payloads, self.fixture.root, driver, prepare, prepare_sha,
        )
        finalize, finalize_sha = self.parsed_zero_request(
            "finalize-qualification-zero", "d", final_response_sha256="e" * 64,
            expected_controller_generation=self.fixture.binding["fixture"]["controller_generation"],
            expected_runner_generation=self.fixture.binding["fixture"]["runner_generation"],
        )
        CONTROLLER._finalize_qualification_zero(
            manifest, payloads, self.fixture.root, driver, finalize, finalize_sha,
        )
        prove, _prove_sha = self.parsed_zero_request(
            "prove-qualification-zero", "e", final_response_sha256="e" * 64,
            expected_controller_generation=self.fixture.binding["fixture"]["controller_generation"],
            expected_runner_generation=self.fixture.binding["fixture"]["runner_generation"],
        )
        proved = CONTROLLER._prove_qualification_zero(manifest, self.fixture.root, driver, prove)
        scenario_path = self.fixture.temporary / "persistent-scenario.json"
        acceptance_path = self.fixture.temporary / "persistent-acceptance.json"
        write_file(scenario_path, activation_package.canonical_json(self.fixture.scenario), 0o600)
        acceptance = {
            "schema_version": "buzz-ci-capacity-one-acceptance-receipt/v2",
            "outcome": "pass",
            "scenario_sha256": self.fixture.binding["scenario_sha256"],
            "integrated_candidate_sha": manifest["source_commit"],
            "zero_transition": {
                "phases": [{}, {"response": {"controller_receipt_sha256": proved["receipt_sha256"]}}],
            },
        }
        write_file(acceptance_path, activation_package.canonical_json(acceptance), 0o600)
        return scenario_path, acceptance_path

    @staticmethod
    def verifier_pass(*_arguments: object, **_keywords: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            [], 0, b'{"outcome":"pass","status":"verified"}\n', b"",
        )

    def enable_execd_baseline(self) -> None:
        effective = next(
            item for item in self.fixture.manifest["effective_systemd"]
            if item["unit"] == "buzz-ci-execd.socket"
        )
        entries = {entry["target"]: entry for entry in self.fixture.manifest["entries"]}
        for record in (effective["fragment"], *effective["drop_ins"]):
            source = entries[record["path"]]["source"]
            write_file(
                self.fixture.root / record["path"].lstrip("/"),
                self.fixture.assets[source][0],
                0o644,
            )
        state = json.loads(self.fixture.fake_state.read_bytes())
        state["units"]["buzz-ci-execd.socket"].update({
            "LoadState": "loaded",
            "ActiveState": "active",
            "SubState": "listening",
            "UnitFileState": "enabled",
            "FragmentPath": effective["fragment"]["path"],
            "DropInPaths": [record["path"] for record in effective["drop_ins"]],
        })
        write_file(self.fixture.fake_state, activation_package.canonical_json(state), 0o600)

    def test_full_fake_root_lifecycle_is_dormant_then_capacity_one_then_closed(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        checked = CONTROLLER.check_current(manifest, self.fixture.root, driver)
        self.assertEqual(checked["state"], "dormant")

        read_descriptor, write_descriptor = os.pipe2(os.O_NONBLOCK)
        try:
            progress = CONTROLLER.StageProgress(write_descriptor)
            for name in CONTROLLER.STAGE_PROGRESS_NAMES[:3]:
                progress.advance(name)
            staged = CONTROLLER.stage(
                manifest, payloads, self.fixture.root, driver, self.fixture.binding,
                progress,
            )
            os.close(write_descriptor)
            write_descriptor = -1
            staged_progress = os.read(
                read_descriptor, CONTROLLER.STAGE_PROGRESS_OPERATION_COUNT * 2 + 8,
            )
        finally:
            if write_descriptor >= 0:
                os.close(write_descriptor)
            os.close(read_descriptor)
        self.assertEqual((staged["state"], staged["capacity"]), ("staged_zero", 0))
        self.assertEqual(
            staged_progress,
            CONTROLLER.STAGE_PROGRESS_MAGIC + b"".join(
                bytes((ordinal, ordinal ^ 0xFF))
                for ordinal in range(1, CONTROLLER.STAGE_PROGRESS_OPERATION_COUNT + 1)
            ) + b"\x80\x7f",
        )
        effective = {item["unit"]: item for item in manifest["effective_systemd"]}
        self.assertEqual(set(staged["installed_units"]), set(effective))
        for unit, expected in effective.items():
            observed = staged["installed_units"][unit]
            self.assertEqual(observed["fragment_path"], expected["fragment"]["path"])
            self.assertEqual(observed["fragment_sha256"], expected["fragment"]["sha256"])
            self.assertEqual(observed["drop_in_paths"], [item["path"] for item in expected["drop_ins"]])
            self.assertEqual(observed["drop_in_sha256"], [item["sha256"] for item in expected["drop_ins"]])
        receipt_before_retry = (self.fixture.root / CONTROLLER.RECEIPT_PATH.lstrip("/")).read_bytes()
        read_descriptor, write_descriptor = os.pipe2(os.O_NONBLOCK)
        try:
            progress = CONTROLLER.StageProgress(write_descriptor)
            for name in CONTROLLER.STAGE_PROGRESS_NAMES[:3]:
                progress.advance(name)
            unchanged = CONTROLLER.stage(
                manifest, payloads, self.fixture.root, driver, self.fixture.binding,
                progress,
            )
            os.close(write_descriptor)
            write_descriptor = -1
            unchanged_progress = os.read(read_descriptor, CONTROLLER.STAGE_PROGRESS_OPERATION_COUNT * 2 + 8)
        finally:
            if write_descriptor >= 0:
                os.close(write_descriptor)
            os.close(read_descriptor)
        self.assertEqual(unchanged["status"], "unchanged")
        self.assertEqual(
            unchanged_progress,
            CONTROLLER.STAGE_PROGRESS_MAGIC + b"".join(
                bytes((ordinal, ordinal ^ 0xFF)) for ordinal in range(1, 7)
            ) + b"\x81\x7e",
        )
        self.assertEqual(
            (self.fixture.root / CONTROLLER.RECEIPT_PATH.lstrip("/")).read_bytes(),
            receipt_before_retry,
        )
        self.assertEqual(CONTROLLER.check_current(manifest, self.fixture.root, driver)["state"], "staged_zero")

        qualification, activated = self.activate_one(manifest, payloads, driver)
        self.assertEqual((qualification["state"], qualification["capacity"]), ("qualified_closed", 0))
        self.assertEqual(qualification["qualification"]["status"], "qualified_closed")
        self.assertEqual(activated["state"], "active_one")
        active = CONTROLLER.check_current(manifest, self.fixture.root, driver)
        self.assertEqual(active["readback"]["installed_units"]["buzz-ci-runner.service"]["drop_in_paths"], [
            "/usr/lib/systemd/system/service.d/10-timeout-abort.conf",
            "/etc/systemd/system/buzz-ci-runner.service.d/20-capacity-one.conf",
        ])
        self.assertEqual(CONTROLLER.activate(manifest, payloads, self.fixture.root, driver)["status"], "unchanged")
        self.assertEqual(CONTROLLER.qualify(manifest, payloads, self.fixture.root, driver)["status"], "qualified")

        rolled_back = CONTROLLER.rollback(manifest, self.fixture.root, driver)
        self.assertEqual((rolled_back["state"], rolled_back["capacity"]), ("rolled_back", 0))
        self.assertEqual(CONTROLLER.rollback(manifest, self.fixture.root, driver)["status"], "unchanged")
        dormant = CONTROLLER.check_current(manifest, self.fixture.root, driver)
        self.assertEqual((dormant["state"], dormant["capacity"]), ("dormant", 0))
        self.assertEqual(dormant["units"]["buzz-ci-controld-acceptance.socket"]["fragment_path"],
                         "/etc/systemd/system/buzz-ci-controld-acceptance.socket")
        self.assertEqual(
            rolled_back["retained_principals"],
            ["buzzci-controld", "buzzci-ctl", "buzzci-job", "buzzci-keyholder", "buzzci-runner"],
        )
        for entry in manifest["entries"]:
            target = self.fixture.root / entry["target"].lstrip("/")
            if entry["role"] in {"runner_config", "controld_config"}:
                self.assertEqual(target.read_bytes(), payloads[entry["source"]])
            elif entry["role"] in CONTROLLER.ROLLBACK_RECOVERY_ROLES:
                self.assertEqual(target.read_bytes(), payloads[entry["source"]])
            else:
                self.assertFalse(target.exists())

    def test_clean_host_allows_only_package_units_absent_then_reads_back_exact_install(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        report = CONTROLLER.preflight(
            manifest, self.fixture.root, driver, require_dormant=True, payloads=payloads,
        )
        for unit in activation_package.PACKAGE_UNIT_ROLES:
            self.assertEqual(report["units"][unit]["LoadState"], "not-found")
            self.assertEqual(
                {
                    key: report["units"][unit][key]
                    for key in ("LoadState", "ActiveState", "SubState", "UnitFileState")
                },
                {
                    "LoadState": "not-found",
                    "ActiveState": "inactive",
                    "SubState": "dead",
                    "UnitFileState": "",
                },
            )
        for unit in activation_package.DEPENDENCY_UNITS:
            self.assertEqual(report["units"][unit]["LoadState"], "loaded")

        state = driver._read()
        missing_dependency = activation_package.DEPENDENCY_UNITS[0]
        state["units"][missing_dependency]["LoadState"] = "not-found"
        driver._write(state)
        with self.assertRaisesRegex(ValueError, "required systemd unit is not loaded"):
            CONTROLLER.preflight(
                manifest, self.fixture.root, driver, require_dormant=True, payloads=payloads,
            )
        state = driver._read()
        state["units"][missing_dependency]["LoadState"] = "loaded"
        driver._write(state)

        staged = CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        entries = {entry["role"]: entry for entry in manifest["entries"]}
        for unit, role in activation_package.PACKAGE_UNIT_ROLES.items():
            self.assertEqual(staged["installed_units"][unit]["LoadState"], "loaded")
            self.assertEqual(staged["installed_units"][unit]["fragment_path"], entries[role]["target"])
            self.assertEqual(staged["installed_units"][unit]["sha256"], entries[role]["sha256"])

    def test_live_and_clean_host_parsers_share_exact_fedora259_absence(self) -> None:
        controller_process = subprocess.CompletedProcess(
            ["systemctl"], 0,
            b"LoadState=not-found\nActiveState=inactive\nSubState=dead\nUnitFileState=\n",
            b"",
        )
        with mock.patch.object(CONTROLLER.LiveSystemd, "_run", return_value=controller_process):
            observed = CONTROLLER.LiveSystemd(Path("/")).unit(
                "buzz-ci-acceptance-control.service",
            )
        self.assertEqual(observed, {
            "LoadState": "not-found",
            "ActiveState": "inactive",
            "SubState": "dead",
            "UnitFileState": "",
        })

        clean_host_process = subprocess.CompletedProcess(
            ["systemctl"], 0,
            b"LoadState=not-found\nActiveState=inactive\nSubState=dead\nUnitFileState=\nMainPID=0\nInvocationID=\nFragmentPath=\n",
            b"",
        )
        clean_host = CLEAN_HOST_GUEST.systemd_unit_values(
            "buzz-ci-acceptance-control.service", clean_host_process,
        )
        self.assertEqual(
            {key: clean_host[key] for key in observed},
            observed,
        )

        lines = controller_process.stdout.splitlines()
        for missing in observed:
            incomplete = subprocess.CompletedProcess(
                ["systemctl"], 0,
                b"\n".join(
                    line for line in lines
                    if not line.startswith(missing.encode() + b"=")
                ) + b"\n",
                b"",
            )
            with self.subTest(missing=missing), mock.patch.object(
                CONTROLLER.LiveSystemd, "_run", return_value=incomplete,
            ), self.assertRaisesRegex(ValueError, "incomplete systemd readback"):
                CONTROLLER.LiveSystemd(Path("/")).unit(
                    "buzz-ci-acceptance-control.service",
                )

    def test_preflight_accepts_empty_unit_file_state_only_for_exact_absence(self) -> None:
        _manifest, _payloads, driver = self.fixture.load()
        self.assertEqual(driver.unit("buzz-ci-unmodeled.service"), {
            "LoadState": "not-found",
            "ActiveState": "inactive",
            "SubState": "dead",
            "UnitFileState": "",
        })
        observed = CONTROLLER._preflight_units(driver)
        for unit in activation_package.PACKAGE_UNIT_ROLES:
            self.assertEqual(observed[unit], {
                "LoadState": "not-found",
                "ActiveState": "inactive",
                "SubState": "dead",
                "UnitFileState": "",
            })

        baseline = driver._read()
        absent_service = next(
            unit for unit in activation_package.PACKAGE_UNIT_ROLES
            if unit.endswith(".service")
        )
        absent_socket = next(
            unit for unit in activation_package.PACKAGE_UNIT_ROLES
            if unit.endswith(".socket")
        )
        cases = (
            (absent_service, {"UnitFileState": "disabled"}, "absent package-owned"),
            (absent_service, {"UnitFileState": "static"}, "absent package-owned"),
            (absent_service, {"ActiveState": "active"}, "absent package-owned"),
            (absent_service, {"SubState": "running"}, "absent package-owned"),
            (absent_service, {"LoadState": "failed"}, "required systemd unit"),
            (
                absent_socket,
                {"LoadState": "loaded", "UnitFileState": ""},
                "systemd socket is enabled before activation",
            ),
        )
        for unit, replacement, message in cases:
            with self.subTest(unit=unit, replacement=replacement):
                state = copy.deepcopy(baseline)
                state["units"][unit].update(replacement)
                driver._write(state)
                with self.assertRaisesRegex(ValueError, message):
                    CONTROLLER._preflight_units(driver)
        driver._write(baseline)

    def test_effective_systemd_rejects_missing_extra_order_relocation_digest_and_duplicate_drift(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        runner = "buzz-ci-runner.service"
        expected = next(item for item in manifest["effective_systemd"] if item["unit"] == runner)

        state = driver._read()
        state["units"][runner]["DropInPaths"] = []
        driver._write(state)
        with self.assertRaisesRegex(ValueError, "drop-in paths or order"):
            CONTROLLER.check_current(manifest, self.fixture.root, driver)

        state = driver._read()
        state["units"][runner]["DropInPaths"] = [
            expected["drop_ins"][0]["path"],
            "/etc/systemd/system/buzz-ci-runner.service.d/99-extra.conf",
        ]
        driver._write(state)
        with self.assertRaisesRegex(ValueError, "drop-in paths or order"):
            CONTROLLER.check_current(manifest, self.fixture.root, driver)

        state = driver._read()
        state["units"][runner]["DropInPaths"] = [
            "/etc/systemd/system/buzz-ci-runner.service.d/99-late.conf",
            expected["drop_ins"][0]["path"],
        ]
        driver._write(state)
        with self.assertRaisesRegex(ValueError, "drop-in paths or order"):
            CONTROLLER.check_current(manifest, self.fixture.root, driver)

        state = driver._read()
        state["units"][runner]["DropInPaths"] = [expected["drop_ins"][0]["path"]]
        state["units"][runner]["FragmentPath"] = "/usr/lib/systemd/system/buzz-ci-runner.service"
        driver._write(state)
        with self.assertRaisesRegex(ValueError, "fragment is relocated"):
            CONTROLLER.check_current(manifest, self.fixture.root, driver)

        state = driver._read()
        state["units"][runner]["FragmentPath"] = expected["fragment"]["path"]
        state["units"][runner]["DropInPaths"] = [
            expected["drop_ins"][0]["path"], expected["drop_ins"][0]["path"],
        ]
        driver._write(state)
        with self.assertRaisesRegex(ValueError, "duplicated systemd drop-in"):
            CONTROLLER.check_current(manifest, self.fixture.root, driver)

        state = driver._read()
        state["units"][runner]["DropInPaths"] = [expected["drop_ins"][0]["path"]]
        driver._write(state)
        drop_in = self.fixture.root / expected["drop_ins"][0]["path"].lstrip("/")
        drop_in.write_bytes(b"[Service]\nEnvironment=HOSTILE=1\n")
        with self.assertRaisesRegex(ValueError, "(?:file digest differs|staged readback failed)"):
            CONTROLLER.check_current(manifest, self.fixture.root, driver)

    def test_platform_global_drop_in_is_exact_for_services_only(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        global_record = activation_package.PLATFORM_SYSTEMD["service_drop_ins"][0]
        for unit in manifest["effective_systemd"]:
            paths = [record["path"] for record in unit["drop_ins"]]
            if unit["unit"].endswith(".service"):
                self.assertIn(global_record["path"], paths)
                self.assertEqual(
                    paths,
                    activation_package.systemd_drop_in_order(paths),
                )
                self.assertEqual(
                    next(record for record in unit["drop_ins"] if record["owner"] == "platform"),
                    global_record,
                )
            else:
                self.assertNotIn(global_record["path"], paths)

        changed = copy.deepcopy(manifest)
        changed["platform_systemd"]["service_drop_ins"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "platform binding differs"):
            activation_package.validate_manifest(changed)

        runner = next(
            item for item in manifest["effective_systemd"]
            if item["unit"] == "buzz-ci-runner.service"
        )

        def platform_record(drops: list[dict[str, object]]) -> dict[str, object]:
            return next(record for record in drops if record["owner"] == "platform")

        for label, mutate in (
            ("missing", lambda drops: drops.remove(platform_record(drops))),
            ("reordered", lambda drops: drops.reverse()),
            ("relocated", lambda drops: platform_record(drops).update(path="/etc/systemd/system/service.d/10-timeout-abort.conf")),
            ("drifted", lambda drops: platform_record(drops).update(sha256="1" * 64)),
        ):
            hostile = copy.deepcopy(manifest)
            drops = next(
                item["drop_ins"] for item in hostile["effective_systemd"]
                if item["unit"] == runner["unit"]
            )
            mutate(drops)
            with self.subTest(label=label), self.assertRaisesRegex(
                ValueError,
                "(?:drop-in inventory differs|drop-in owner, path, or order differs|platform effective systemd binding differs)",
            ):
                activation_package.validate_manifest(hostile)

        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        target = self.fixture.root / global_record["path"].lstrip("/")
        expected = target.read_bytes()
        target.unlink()
        with self.assertRaisesRegex(ValueError, "effective systemd file is missing"):
            CONTROLLER.check_current(manifest, self.fixture.root, driver)
        write_file(target, b"[Service]\nHostile=yes\n", 0o644)
        with self.assertRaisesRegex(ValueError, "effective systemd file digest differs"):
            CONTROLLER.check_current(manifest, self.fixture.root, driver)
        write_file(target, expected, 0o644)
        state = driver._read()
        state["units"][runner["unit"]]["DropInPaths"].insert(
            0, "/etc/systemd/system/buzz-ci-runner.service.d/10-host-adapters.conf",
        )
        driver._write(state)
        with self.assertRaisesRegex(ValueError, "drop-in paths or order"):
            CONTROLLER.check_current(manifest, self.fixture.root, driver)

    def test_systemd_drop_in_order_matches_fedora_and_rejects_collisions(self) -> None:
        global_10 = "/usr/lib/systemd/system/service.d/10-timeout-abort.conf"
        unit_20 = "/etc/systemd/system/buzz-ci-keyholder.service.d/20-acceptance-actor.conf"
        host_10 = "/etc/systemd/system/buzz-ci-execd.service.d/10-host-adapters.conf"
        self.assertEqual(
            activation_package.systemd_drop_in_order([unit_20, global_10]),
            [global_10, unit_20],
        )
        self.assertEqual(
            activation_package.systemd_drop_in_order([global_10, unit_20]),
            [global_10, unit_20],
        )
        self.assertEqual(
            activation_package.systemd_drop_in_order([global_10, host_10]),
            [host_10, global_10],
        )
        with self.assertRaisesRegex(ValueError, "basename collision"):
            activation_package.systemd_drop_in_order([
                global_10,
                "/etc/systemd/system/buzz-ci-keyholder.service.d/10-timeout-abort.conf",
            ])

        self.assertEqual(len(activation_package.SYSTEMD_UNIT_LAYOUT), 13)
        self.assertEqual(
            sum(
                record["owner"] != "platform"
                for unit in activation_package.SYSTEMD_UNIT_LAYOUT.values()
                for record in unit["drop_ins"]
            ),
            5,
        )
        for unit in ("buzz-ci-runner.service", "buzz-ci-keyholder.service"):
            paths = [
                record["path"]
                for record in activation_package.SYSTEMD_UNIT_LAYOUT[unit]["drop_ins"]
            ]
            self.assertEqual(paths, activation_package.systemd_drop_in_order(paths))

    def test_systemd_analyze_serializes_global_10_before_unit_20(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unit_root = root / "etc/systemd/system"
            unit_drop_ins = unit_root / "buzz-ci-order.service.d"
            global_drop_ins = root / "usr/lib/systemd/system/service.d"
            binary_root = root / "bin"
            unit_drop_ins.mkdir(parents=True)
            global_drop_ins.mkdir(parents=True)
            binary_root.mkdir(parents=True)
            shutil.copyfile("/bin/true", binary_root / "true")
            (binary_root / "true").chmod(0o755)
            (unit_root / "buzz-ci-order.service").write_text(
                "[Unit]\nDefaultDependencies=no\n[Service]\nExecStart=/bin/true\n",
            )
            shutil.copyfile(
                ACTIVATION_ROOT / "platform/fedora-44-systemd-259/10-timeout-abort.conf",
                global_drop_ins / "10-timeout-abort.conf",
            )
            shutil.copyfile(
                REPO_ROOT / "deploy/native-ci/keyholder/templates/20-acceptance-actor.conf",
                unit_drop_ins / "20-acceptance-actor.conf",
            )
            verified = subprocess.run(
                [
                    "systemd-analyze", "verify", f"--root={root}",
                    "buzz-ci-order.service",
                ],
                check=False,
                env={**os.environ, "SYSTEMD_LOG_LEVEL": "debug"},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)
            serialized = verified.stdout + verified.stderr
            global_marker = "DropIn Path: " + str(
                global_drop_ins / "10-timeout-abort.conf",
            )
            unit_marker = "DropIn Path: " + str(
                unit_drop_ins / "20-acceptance-actor.conf",
            )
            self.assertGreaterEqual(serialized.find(global_marker), 0, serialized)
            self.assertGreaterEqual(serialized.find(unit_marker), 0, serialized)
            self.assertLess(serialized.find(global_marker), serialized.find(unit_marker))

    def test_fedora259_serialized_drop_in_order_passes_exact_readback(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        keyholder = next(
            item for item in manifest["effective_systemd"]
            if item["unit"] == "buzz-ci-keyholder.service"
        )
        expected = [record["path"] for record in keyholder["drop_ins"]]
        self.assertEqual(expected, [
            "/usr/lib/systemd/system/service.d/10-timeout-abort.conf",
            "/etc/systemd/system/buzz-ci-keyholder.service.d/20-acceptance-actor.conf",
        ])
        serialized = subprocess.CompletedProcess(
            ["systemctl"], 0,
            (
                "FragmentPath=/etc/systemd/system/buzz-ci-keyholder.service\n"
                f"DropInPaths={' '.join(expected)}\n"
            ).encode(),
            b"",
        )
        with mock.patch.object(CONTROLLER.LiveSystemd, "_run", return_value=serialized):
            self.assertEqual(
                CONTROLLER.LiveSystemd(Path("/")).effective_paths(
                    "buzz-ci-keyholder.service",
                )["drop_in_paths"],
                expected,
            )

        CONTROLLER.preflight(
            manifest, self.fixture.root, driver, require_dormant=True, payloads=payloads,
        )
        state = driver._read()
        state["units"]["buzz-ci-keyholder.service"]["DropInPaths"] = list(reversed(expected))
        driver._write(state)
        with self.assertRaisesRegex(ValueError, "drop-in paths or order differ"):
            CONTROLLER.preflight(
                manifest, self.fixture.root, driver,
                require_dormant=True, payloads=payloads,
            )

    def test_dependency_drop_in_rejects_missing_and_stale_bytes(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        effective = next(
            item for item in manifest["effective_systemd"]
            if item["unit"] == "buzz-ci-keyholder.service"
        )
        record = next(
            item for item in effective["drop_ins"]
            if item["owner"] == "keyholder"
        )
        target = self.fixture.root / record["path"].lstrip("/")
        expected = (REPO_ROOT / FREEZER.SYSTEMD_SOURCE_PATHS[record["path"]]).read_bytes()

        target.unlink()
        with self.assertRaisesRegex(ValueError, "effective systemd file is missing"):
            CONTROLLER.check_current(manifest, self.fixture.root, driver)

        write_file(target, b"[Service]\nEnvironment=STALE=1\n", 0o644)
        with self.assertRaisesRegex(ValueError, "effective systemd file digest differs"):
            CONTROLLER.check_current(manifest, self.fixture.root, driver)

        write_file(target, expected, 0o644)
        self.assertEqual(
            CONTROLLER.check_current(manifest, self.fixture.root, driver)["state"],
            "staged_zero",
        )

    def test_effective_systemd_is_rechecked_across_every_lifecycle_state(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        unit = "buzz-ci-runner.service"
        hostile = "/etc/systemd/system/buzz-ci-runner.service.d/99-hostile.conf"

        def reject_hostile_drop_in(label: str, readback) -> None:
            state = driver._read()
            pristine = copy.deepcopy(state)
            state["units"][unit]["DropInPaths"].append(hostile)
            driver._write(state)
            with self.subTest(state=label):
                with self.assertRaisesRegex(ValueError, "drop-in paths or order"):
                    readback()
            driver._write(pristine)

        reject_hostile_drop_in(
            "dormant",
            lambda: CONTROLLER.check_current(manifest, self.fixture.root, driver),
        )
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        reject_hostile_drop_in(
            "staged_zero",
            lambda: CONTROLLER.check_current(manifest, self.fixture.root, driver),
        )
        CONTROLLER.activate(manifest, payloads, self.fixture.root, driver)
        reject_hostile_drop_in(
            "qualified_closed",
            lambda: CONTROLLER.check_current(manifest, self.fixture.root, driver),
        )
        self.set_capacity_one(manifest, payloads, driver)
        reject_hostile_drop_in(
            "active_one",
            lambda: CONTROLLER.check_current(manifest, self.fixture.root, driver),
        )

        prepare, prepare_sha = self.parsed_zero_request("prepare-qualification-zero", "c")
        CONTROLLER._prepare_qualification_zero(
            manifest, payloads, self.fixture.root, driver, prepare, prepare_sha,
        )
        reject_hostile_drop_in(
            "prepare_zero",
            lambda: CONTROLLER._prepare_qualification_zero(
                manifest, payloads, self.fixture.root, driver, prepare, prepare_sha,
            ),
        )
        finalize, finalize_sha = self.parsed_zero_request("finalize-qualification-zero", "d")
        CONTROLLER._finalize_qualification_zero(
            manifest, payloads, self.fixture.root, driver, finalize, finalize_sha,
        )
        prove, _prove_sha = self.parsed_zero_request("prove-qualification-zero", "e")
        reject_hostile_drop_in(
            "finalized_prove_zero",
            lambda: CONTROLLER._prove_qualification_zero(
                manifest, self.fixture.root, driver, prove,
            ),
        )

        CONTROLLER.rollback(manifest, self.fixture.root, driver)
        reject_hostile_drop_in(
            "rolled_back_dormant",
            lambda: CONTROLLER.check_current(manifest, self.fixture.root, driver),
        )

    def test_rollback_rejects_stale_drop_in_after_daemon_reload(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        stale = self.fixture.root / "etc/systemd/system/buzz-ci-runner.service.d/99-stale.conf"
        write_file(stale, b"[Service]\nEnvironment=STALE=1\n", 0o644)
        with self.assertRaisesRegex(ValueError, "drop-in paths or order"):
            CONTROLLER.rollback(manifest, self.fixture.root, driver)
        self.assertEqual(CONTROLLER._read_receipt(self.fixture.root)["state"], "rollback_failed")

    def test_controld_component_package_manifest_binds_effective_unit_bytes(self) -> None:
        manifest, payloads, _driver = self.fixture.load()
        component = next(item for item in manifest["components"] if item["name"] == "controld")
        raw = payloads[component["package_manifest_source"]]
        activation_package._validate_controld_package_manifest(manifest, raw)
        package = json.loads(raw)
        package["entries"][0]["sha256"] = "0" * 64
        hostile = activation_package.canonical_json(package)
        changed = copy.deepcopy(manifest)
        changed_component = next(item for item in changed["components"] if item["name"] == "controld")
        changed_component["package_manifest_sha256"] = activation_package.digest(hostile)
        with self.assertRaisesRegex(ValueError, "package manifest digest or source"):
            activation_package._validate_controld_package_manifest(changed, hostile)

        package = json.loads(raw)
        config = next(
            item
            for item in package["entries"]
            if item["target"] == activation_package.CONFIG_TARGETS["controld_config"]
        )
        config["sha256"] = "f" * 64
        unsigned = {key: value for key, value in package.items() if key != "package_digest"}
        package["package_digest"] = activation_package.digest(
            activation_package.canonical_json(unsigned)
        )
        hostile = activation_package.canonical_json(package)
        changed = copy.deepcopy(manifest)
        changed_component = next(
            item for item in changed["components"] if item["name"] == "controld"
        )
        changed_component["package_manifest_sha256"] = activation_package.digest(hostile)
        changed_component["package_digest"] = package["package_digest"]
        with self.assertRaisesRegex(ValueError, "staged config binding differs"):
            activation_package._validate_controld_package_manifest(changed, hostile)

    def test_component_package_manifests_reject_structural_and_scalar_bypasses(self) -> None:
        manifest, payloads, _driver = self.fixture.load()

        def rebound(name: str, mutate: Callable[[dict[str, object]], None]) -> tuple[dict[str, object], dict[str, bytes]]:
            changed = copy.deepcopy(manifest)
            component = next(item for item in changed["components"] if item["name"] == name)
            package = json.loads(payloads[component["package_manifest_source"]])
            mutate(package)
            unsigned = {key: value for key, value in package.items() if key != "package_digest"}
            package["package_digest"] = activation_package.digest(activation_package.canonical_json(unsigned))
            raw = activation_package.canonical_json(package)
            component["package_digest"] = package["package_digest"]
            component["package_manifest_sha256"] = activation_package.digest(raw)
            changed_payloads = dict(payloads)
            changed_payloads[component["package_manifest_source"]] = raw
            return changed, changed_payloads

        changed, changed_payloads = rebound("runner", lambda package: package.__setitem__("extra", True))
        with self.assertRaisesRegex(ValueError, "fields differ"):
            activation_package.component_tmpfiles_plan(changed, changed_payloads)

        def boolean_owner(package: dict[str, object]) -> None:
            package["package_uid"] = False

        changed, changed_payloads = rebound("runner", boolean_owner)
        with self.assertRaisesRegex(ValueError, "ownership types differ"):
            activation_package.component_tmpfiles_plan(changed, changed_payloads)

        def duplicate_role(package: dict[str, object]) -> None:
            package["entries"][0]["role"] = package["entries"][1]["role"]

        changed, changed_payloads = rebound("controld", duplicate_role)
        with self.assertRaisesRegex(ValueError, "role or target inventory differs"):
            activation_package.component_tmpfiles_plan(changed, changed_payloads)

        swapped = dict(payloads)
        runner = next(item for item in manifest["components"] if item["name"] == "runner")
        controld = next(item for item in manifest["components"] if item["name"] == "controld")
        swapped[runner["package_manifest_source"]] = payloads[controld["package_manifest_source"]]
        with self.assertRaisesRegex(ValueError, "runner package manifest bytes differ"):
            activation_package.component_tmpfiles_plan(manifest, swapped)

    def test_static_five_package_inventory_is_collision_closed(self) -> None:
        activation = copy.deepcopy(self.fixture.manifest)
        activation_entries = {entry["target"]: entry for entry in activation["entries"]}
        self.assertNotIn(
            "/etc/systemd/system/buzz-ci-controld-acceptance.socket",
            activation_entries,
        )

        def entry(role: str, target: str, payload: bytes, *, mode: str = "0644", uid: int = 0, gid: int = 0) -> dict[str, object]:
            return {
                "role": role, "target": target, "sha256": activation_package.digest(payload),
                "install_mode": mode, "uid": uid, "gid": gid,
            }

        packages: dict[str, dict[str, object]] = {"activation": activation}
        for owner, schema in INVENTORY.PACKAGE_SCHEMAS.items():
            if owner == "activation":
                continue
            owned: list[dict[str, object]] = []
            for unit in activation["effective_systemd"]:
                for record in (unit["fragment"], *unit["drop_ins"]):
                    if record["owner"] != owner:
                        continue
                    payload = (REPO_ROOT / FREEZER.SYSTEMD_SOURCE_PATHS[record["path"]]).read_bytes()
                    owned.append(entry("socket" if record["path"].endswith(".socket") else "unit", record["path"], payload))
            if owner == "controld":
                target = "/etc/buzzci/controld-v2.json"
                shared = activation_entries[target]
                owned.append({
                    "role": "config", "target": target, "sha256": shared["sha256"],
                    "install_mode": shared["install_mode"], "uid": shared["uid"], "gid": shared["gid"],
                })
            if owner == "runner":
                target = "/etc/buzzci/runner-v2.json"
                shared = activation_entries[target]
                owned.append({
                    "role": "config", "target": target, "sha256": shared["sha256"],
                    "install_mode": shared["install_mode"], "uid": shared["uid"], "gid": shared["gid"],
                })
            owned.extend([
                entry("binary", f"/usr/libexec/buzz-ci-{owner}", f"{owner}-binary\n".encode(), mode="0755"),
                entry("tmpfiles", f"/usr/lib/tmpfiles.d/buzzci-{owner}.conf", f"{owner}-tmpfiles\n".encode()),
            ])
            packages[owner] = {"schema": schema, "entries": owned}
        packages["execd"].update({
            "install_receipt": {"path": "/var/lib/buzzci/execd-v2/package/receipt-v1.json", "mode": "0600", "uid": 0, "gid": 0, "schema": "buzz-ci-execd-install-receipt-v1"},
            "seccomp_contract": {"runtime_receipt": "/var/lib/buzzci/activation/receipts/seccomp.json"},
        })

        report = INVENTORY.check_inventory(packages, source_root=REPO_ROOT)
        self.assertEqual((report["status"], report["packages"]), ("pass", sorted(INVENTORY.PACKAGE_SCHEMAS)))
        self.assertEqual(
            report["source_inventory"]["controld_acceptance_source"],
            str(INVENTORY.CONTROLD_ACCEPTANCE_SOURCE),
        )
        for category in ("binary", "config", "unit", "socket", "drop_in", "tmpfiles", "sysusers", "fixture", "receipt"):
            self.assertGreater(report["categories"].get(category, 0), 0, category)

        platform_drift = copy.deepcopy(packages)
        platform_drift["activation"]["platform_systemd"]["service_drop_ins"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "systemd platform binding differs"):
            INVENTORY.check_inventory(platform_drift)

        self.assertTrue(any(
            item["target"] == "/etc/buzzci/runner-v2.json"
            for item in packages["runner"]["entries"]
        ))
        self.assertTrue(any(
            item["target"] == "/etc/buzzci/runner-v2.json"
            for item in packages["activation"]["entries"]
        ))

        divergent = copy.deepcopy(packages)
        controld_config = next(
            item for item in divergent["controld"]["entries"]
            if item["target"] == "/etc/buzzci/controld-v2.json"
        )
        controld_config["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "divergent explicitly shared"):
            INVENTORY.check_inventory(divergent)

        collision = copy.deepcopy(packages)
        socket = next(item for item in collision["controld"]["entries"] if item["target"] == "/etc/systemd/system/buzz-ci-controld-acceptance.socket")
        collision["activation"]["entries"].append(copy.deepcopy(socket))
        with self.assertRaisesRegex(ValueError, "undeclared final package ownership collision"):
            INVENTORY.check_inventory(collision)

        missing_owner = copy.deepcopy(packages)
        missing_owner["controld"]["entries"] = [
            item for item in missing_owner["controld"]["entries"]
            if item["target"] != INVENTORY.CONTROLD_ACCEPTANCE_TARGET
        ]
        with self.assertRaisesRegex(ValueError, "controld must solely own"):
            INVENTORY.check_inventory(missing_owner)

        receipt_collision = copy.deepcopy(packages)
        receipt_collision["execd"]["install_receipt"]["path"] = INVENTORY.ACTIVATION_RECEIPT["path"]
        with self.assertRaisesRegex(ValueError, "undeclared final package ownership collision"):
            INVENTORY.check_inventory(receipt_collision)

    def test_source_inventory_rejects_a_second_controld_acceptance_template(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            canonical = root / INVENTORY.CONTROLD_ACCEPTANCE_SOURCE
            write_file(canonical, b"canonical\n", 0o644)
            platform = root / INVENTORY.PLATFORM_SYSTEMD_SOURCE
            write_file(
                platform,
                (REPO_ROOT / INVENTORY.PLATFORM_SYSTEMD_SOURCE).read_bytes(),
                0o644,
            )
            report = INVENTORY.check_source_inventory(root)
            self.assertEqual(report["controld_acceptance_source"], str(INVENTORY.CONTROLD_ACCEPTANCE_SOURCE))
            duplicate = root / "deploy/native-ci/acceptance/templates" / INVENTORY.CONTROLD_ACCEPTANCE_NAME
            write_file(duplicate, b"divergent\n", 0o644)
            with self.assertRaisesRegex(ValueError, "exactly one canonical source"):
                INVENTORY.check_source_inventory(root)

    def test_stage_persists_staged_zero_before_starting_acceptance_control(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        observed: list[tuple[str, str]] = []
        original_start = driver.start

        def receipt_bound_start(name: str) -> None:
            receipt = CONTROLLER._read_receipt(self.fixture.root)
            observed.append((name, receipt["state"]))
            if name == "buzz-ci-acceptance-control.service" and receipt["state"] != "staged_zero":
                raise ValueError("acceptance-control refused activation receipt")
            original_start(name)

        driver.start = receipt_bound_start
        staged = CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        self.assertEqual(staged["state"], "staged_zero")
        self.assertEqual([name for name, _state in observed], activation_package.STAGED_ZERO_UNITS)
        self.assertTrue(all(state == "staged_zero" for _name, state in observed))

    def test_stage_service_exit_compensates_to_exact_prior_state(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        original_start = driver.start
        original_stop = driver.stop

        def exiting_start(name: str) -> None:
            original_start(name)
            if name == "buzz-ci-acceptance-control.service":
                original_stop(name)

        driver.start = exiting_start
        with self.assertRaisesRegex(ValueError, "staged-zero readback"):
            CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        receipt = CONTROLLER._read_receipt(self.fixture.root)
        self.assertEqual(receipt["state"], "stage_failed")
        self.assertTrue((self.fixture.root / CONTROLLER.FIXED_PACKAGE_PATH.lstrip("/")).exists())
        self.assertEqual(CONTROLLER._generated_prior_readback(receipt, self.fixture.root), {
            "controld_acceptance_binding": "absent",
            "acceptance_control_config": "absent",
            "acceptance_driver_config": "absent",
            "execd_config": "absent",
        })
        self.assertEqual(CONTROLLER._systemd_prior_readback(receipt, manifest, self.fixture.root, driver)["buzz-ci-acceptance-control.service"]["ActiveState"], "inactive")
        self.assertEqual(CONTROLLER.rollback(manifest, self.fixture.root, driver)["state"], "rolled_back")
        self.assertFalse((self.fixture.root / CONTROLLER.FIXED_PACKAGE_PATH.lstrip("/")).exists())

    def assert_restart_safe_stage_boundaries(self, *, second_activation: bool) -> None:
        boundaries = [
            "fixed_package:readback",
            "recovery:activation_controller:temp",
            "recovery:activation_controller:published",
            "recovery:activation_controller:readback",
            "recovery:activation_package_module:temp",
            "recovery:activation_package_module:published",
            "recovery:activation_package_module:readback",
            "preparing_receipt:readback",
        ]
        if second_activation:
            boundaries.insert(-1, "rollback_retirement:readback")
        for boundary in boundaries:
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as temporary:
                fixture = ActivationFixture(Path(temporary))
                if second_activation:
                    first_manifest, first_payloads, driver = fixture.load()
                    CONTROLLER.stage(
                        first_manifest, first_payloads, fixture.root, driver, fixture.binding,
                    )
                    CONTROLLER.rollback(first_manifest, fixture.root, driver)
                    self.advance_recovery_candidate(fixture)
                manifest, payloads, driver = fixture.load()
                scenario = fixture.temporary / "restart-scenario.json"
                write_file(
                    scenario,
                    activation_package.canonical_json(fixture.scenario),
                    0o600,
                )
                self.cut_stage_process_at(
                    fixture, manifest, payloads, driver, fixture.binding, boundary,
                )
                fixed = fixture.root / CONTROLLER.FIXED_PACKAGE_PATH.lstrip("/")
                fixed_controller = fixed / "assets/buzz-ci-activation-controller"
                installed_controller = fixture.root / "usr/libexec/buzz-ci-activation-controller"
                self.assertEqual(
                    CONTROLLER._verify_fixed_package(manifest, fixture.root)["status"],
                    "exact",
                )
                fixture.package.rename(fixture.temporary / "original-input-removed")
                if boundary == "preparing_receipt:readback":
                    self.assertEqual(CONTROLLER._read_receipt(fixture.root)["state"], "preparing")
                else:
                    use_fixed_controller = boundary in {
                        "fixed_package:readback",
                        "recovery:activation_controller:temp",
                    }
                    executable = fixed_controller if use_fixed_controller else installed_controller
                    resumed = self.fixed_stage_cli(fixture, executable, scenario)
                    self.assertEqual(resumed.returncode, 0, resumed.stderr.decode())
                    self.assertEqual(json.loads(resumed.stdout)["state"], "staged_zero")
                controller_entry = next(
                    entry for entry in manifest["entries"]
                    if entry["role"] == "activation_controller"
                )
                self.assertEqual(
                    activation_package.digest(installed_controller.read_bytes()),
                    controller_entry["sha256"],
                )
                rolled_back = self.fixed_rollback_cli(fixture)
                self.assertEqual(rolled_back.returncode, 0, rolled_back.stderr.decode())
                self.assertEqual(json.loads(rolled_back.stdout)["state"], "rolled_back")
                exact_retry = self.fixed_rollback_cli(fixture)
                self.assertEqual(exact_retry.returncode, 0, exact_retry.stderr.decode())
                self.assertEqual(json.loads(exact_retry.stdout)["status"], "unchanged")

    def test_abrupt_restart_boundaries_are_safe_for_first_activation(self) -> None:
        self.assert_restart_safe_stage_boundaries(second_activation=False)

    def test_abrupt_restart_boundaries_are_safe_for_second_activation(self) -> None:
        self.assert_restart_safe_stage_boundaries(second_activation=True)

    def test_successor_check_accepts_only_retained_prior_or_next_recovery_targets(self) -> None:
        first_manifest, first_payloads, driver = self.fixture.load()
        CONTROLLER.stage(
            first_manifest, first_payloads, self.fixture.root, driver,
            self.fixture.binding,
        )
        CONTROLLER.rollback(first_manifest, self.fixture.root, driver)
        self.advance_recovery_candidate(self.fixture)
        manifest, payloads, driver = self.fixture.load()

        prior = CONTROLLER.check_current(manifest, self.fixture.root, driver)
        self.assertEqual(prior["status"], "ready_to_stage")
        self.assertEqual(
            prior["retained_recovery_targets"],
            {role: "prior" for role in CONTROLLER.ROLLBACK_RECOVERY_ROLES},
        )

        role = "activation_package_module"
        entry = next(item for item in manifest["entries"] if item["role"] == role)
        target = self.fixture.root / entry["target"].lstrip("/")
        write_file(
            target, payloads[entry["source"]], int(entry["install_mode"], 8),
        )
        mixed = CONTROLLER.check_current(manifest, self.fixture.root, driver)
        self.assertEqual(mixed["retained_recovery_targets"][role], "next")

        write_file(
            target, payloads[entry["source"]] + b"hostile", int(entry["install_mode"], 8),
        )
        with self.assertRaisesRegex(ValueError, "target content drift"):
            CONTROLLER.check_current(manifest, self.fixture.root, driver)

    def test_every_legacy_pre_fixed_boundary_has_restart_safe_first_activation_rollback(self) -> None:
        manifest, _payloads, _driver = self.fixture.load()
        boundaries = self.legacy_pre_fixed_boundaries(manifest)
        for boundary in boundaries:
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as temporary:
                fixture = ActivationFixture(Path(temporary))
                candidate, payloads, driver = fixture.load()
                self.fail_stage_at_legacy_boundary(
                    fixture, candidate, payloads, driver, fixture.binding, boundary,
                )
                receipt = CONTROLLER._read_receipt(fixture.root)
                self.assertEqual(receipt["state"], "stage_failed")
                self.assertEqual(
                    CONTROLLER._verify_fixed_package(candidate, fixture.root)["status"], "exact",
                )
                installed_cli = fixture.root / "usr/libexec/buzz-ci-activation-controller"
                installed_module = fixture.root / "usr/libexec/buzz_ci_activation_package.py"
                self.assertTrue(installed_cli.exists())
                self.assertTrue(installed_module.exists())
                fixture.package.rename(fixture.temporary / "input-package-missing")
                rolled_back = self.fixed_rollback_cli(fixture)
                self.assertEqual(rolled_back.returncode, 0, rolled_back.stderr.decode())
                self.assertEqual(json.loads(rolled_back.stdout)["state"], "rolled_back")
                exact_retry = self.fixed_rollback_cli(fixture)
                self.assertEqual(exact_retry.returncode, 0, exact_retry.stderr.decode())
                self.assertEqual(json.loads(exact_retry.stdout)["status"], "unchanged")

    def test_every_legacy_pre_fixed_boundary_has_restart_safe_second_activation_rollback(self) -> None:
        manifest, _payloads, _driver = self.fixture.load()
        boundaries = self.legacy_pre_fixed_boundaries(manifest)
        for boundary in boundaries:
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as temporary:
                fixture = ActivationFixture(Path(temporary))
                first_manifest, first_payloads, driver = fixture.load()
                CONTROLLER.stage(first_manifest, first_payloads, fixture.root, driver, fixture.binding)
                CONTROLLER.rollback(first_manifest, fixture.root, driver)
                first_marker = CONTROLLER._read_rollback_cleanup(fixture.root)
                fixture.acceptance_template["actor"]["generation"] += 1
                fixture.manifest = fixture._manifest()
                fixture.scenario = fixture._scenario()
                fixture.binding = CONTROLLER._acceptance_binding(fixture.manifest, fixture.scenario)
                write_file(
                    fixture.package / "activation-manifest.json",
                    activation_package.canonical_json(fixture.manifest), 0o600,
                )
                candidate, payloads, driver = fixture.load()
                self.fail_stage_at_legacy_boundary(
                    fixture, candidate, payloads, driver, fixture.binding, boundary,
                )
                self.assertEqual(CONTROLLER._read_receipt(fixture.root)["state"], "stage_failed")
                self.assertEqual(CONTROLLER._verify_fixed_package(candidate, fixture.root)["status"], "exact")
                retirement = CONTROLLER._read_rollback_retirement(fixture.root)
                self.assertEqual(retirement["marker"], first_marker)
                fixture.package.rename(fixture.temporary / "input-package-missing")
                rolled_back = self.fixed_rollback_cli(fixture)
                self.assertEqual(rolled_back.returncode, 0, rolled_back.stderr.decode())
                self.assertEqual(json.loads(rolled_back.stdout)["state"], "rolled_back")
                current = CONTROLLER._read_rollback_cleanup(fixture.root)
                self.assertEqual(current["activation_id"], candidate["activation_id"])
                self.assertIsNone(CONTROLLER._read_rollback_retirement(fixture.root))
                exact_retry = self.fixed_rollback_cli(fixture)
                self.assertEqual(exact_retry.returncode, 0, exact_retry.stderr.decode())
                self.assertEqual(json.loads(exact_retry.stdout)["status"], "unchanged")

    def test_pre_fixed_failure_package_missing_drift_and_tamper_fail_closed_then_resume(self) -> None:
        for hostile in ("missing", "asset-drift", "manifest-tamper"):
            with self.subTest(hostile=hostile), tempfile.TemporaryDirectory() as temporary:
                fixture = ActivationFixture(Path(temporary))
                manifest, payloads, driver = fixture.load()
                self.fail_stage_at_legacy_boundary(
                    fixture, manifest, payloads, driver, fixture.binding, ("apply", 0),
                )
                fixed = fixture.root / CONTROLLER.FIXED_PACKAGE_PATH.lstrip("/")
                if hostile == "missing":
                    CONTROLLER._remove_package_tree(
                        fixture.root, CONTROLLER.FIXED_PACKAGE_PATH,
                        expected_sources=set(CONTROLLER._package_references(manifest)),
                    )
                elif hostile == "asset-drift":
                    source = next(iter(CONTROLLER._package_references(manifest)))
                    asset = fixed / "assets" / Path(source).name
                    original = asset.read_bytes()
                    mode = stat.S_IMODE(asset.stat().st_mode)
                    asset.chmod(0o600)
                    write_file(asset, original + b"drift", mode)
                else:
                    package_manifest = fixed / "activation-manifest.json"
                    value = json.loads(package_manifest.read_bytes())
                    value["source_commit"] = "f" * 40
                    package_manifest.write_bytes(activation_package.canonical_json(value))
                rejected = self.fixed_rollback_cli(fixture)
                self.assertEqual(rejected.returncode, 1)
                self.assertNotEqual(CONTROLLER._read_receipt(fixture.root)["state"], "rolled_back")

                if fixed.exists():
                    CONTROLLER._remove_package_tree(
                        fixture.root, CONTROLLER.FIXED_PACKAGE_PATH, expected_sources=None,
                    )
                CONTROLLER._install_fixed_package(manifest, payloads, fixture.root)
                resumed = self.fixed_rollback_cli(fixture)
                self.assertEqual(resumed.returncode, 0, resumed.stderr.decode())
                self.assertEqual(json.loads(resumed.stdout)["state"], "rolled_back")
                exact_retry = self.fixed_rollback_cli(fixture)
                self.assertEqual(exact_retry.returncode, 0, exact_retry.stderr.decode())
                self.assertEqual(json.loads(exact_retry.stdout)["status"], "unchanged")

    def test_staged_zero_resume_restarts_only_missing_staged_unit(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        driver.stop("buzz-ci-acceptance-control.service")
        restarted: list[str] = []
        original_start = driver.start

        def record_start(name: str) -> None:
            restarted.append(name)
            original_start(name)

        driver.start = record_start
        result = CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        self.assertEqual((result["status"], result["state"]), ("unchanged", "staged_zero"))
        self.assertEqual(restarted, activation_package.STAGED_ZERO_UNITS)
        self.assertTrue(CONTROLLER._staged_zero_readback(manifest, self.fixture.root, driver)["units"])

    def test_stage_compensation_aggregates_partial_systemd_failure(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        original_start = driver.start
        original_stop = driver.stop

        def exiting_start(name: str) -> None:
            original_start(name)
            if name == "buzz-ci-acceptance-control.service":
                original_stop(name)

        def partial_stop(name: str) -> None:
            if name == "buzz-ci-runner.socket":
                raise ValueError("injected stage compensation stop failure")
            original_stop(name)

        driver.start = exiting_start
        driver.stop = partial_stop
        with self.assertRaisesRegex(ValueError, "compensation=.*injected stage compensation stop failure"):
            CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        receipt = CONTROLLER._read_receipt(self.fixture.root)
        self.assertEqual(receipt["state"], "rollback_failed")
        self.assertIn("restore active state buzz-ci-runner.socket", receipt["last_error"])

    def test_manifest_schema_mirrors_fixed_package_counts_and_systemd_abi(self) -> None:
        schema = json.loads((ACTIVATION_ROOT / "activation-manifest.schema.json").read_bytes())
        properties = schema["properties"]
        self.assertTrue(schema["$id"].endswith("capacity-one-activation-v2.json"))
        self.assertEqual(properties["schema"]["const"], activation_package.MANIFEST_SCHEMA)
        legacy = copy.deepcopy(self.fixture.manifest)
        legacy["schema"] = "buzz-ci-capacity-one-activation-package-v1"
        with self.assertRaisesRegex(ValueError, "schema is unsupported"):
            activation_package.validate_manifest(legacy)
        legacy_draft = copy.deepcopy(self.fixture.manifest)
        legacy_draft["schema"] = "buzz-ci-capacity-one-activation-draft-v1"
        legacy_draft.pop("activation_id")
        legacy_draft.pop("package_digest")
        with self.assertRaisesRegex(ValueError, "schema is unsupported"):
            activation_package.validate_manifest(legacy_draft, require_digest=False)
        self.assertEqual((properties["components"]["minItems"], properties["components"]["maxItems"]), (len(activation_package.COMPONENTS), len(activation_package.COMPONENTS)))
        expected_entries = len(activation_package.CONFIG_TARGETS) + len(activation_package.STATIC_TARGETS)
        self.assertEqual((properties["entries"]["minItems"], properties["entries"]["maxItems"]), (expected_entries, expected_entries))
        self.assertEqual(
            (properties["effective_systemd"]["minItems"], properties["effective_systemd"]["maxItems"]),
            (len(activation_package.SYSTEMD_UNIT_LAYOUT), len(activation_package.SYSTEMD_UNIT_LAYOUT)),
        )
        self.assertEqual(properties["platform_systemd"]["const"], activation_package.PLATFORM_SYSTEMD)
        self.assertEqual(INVENTORY.PLATFORM_SYSTEMD, activation_package.PLATFORM_SYSTEMD)
        self.assertIn("platform", schema["$defs"]["effectivePath"]["properties"]["owner"]["enum"])
        self.assertEqual(properties["socket_policy"]["const"], activation_package.SOCKET_POLICY)
        self.assertEqual(
            properties["systemd"]["const"],
            {
                "start_order": activation_package.START_ORDER,
                "stop_order": activation_package.STOP_ORDER,
                "persistent_unit": activation_package.PERSISTENT_UNIT,
                "stage_capacity": 0,
                "active_capacity": 1,
            },
        )
        service = (ACTIVATION_ROOT / "templates/buzz-ci-acceptance-control.service").read_text()
        self.assertIn("ReadOnlyPaths=/var/lib/buzzci/activation-controller/package\n", service)
        self.assertIn(
            "ReadWritePaths=/etc/buzzci /var/lib/buzzci/acceptance-control /var/lib/buzzci/activation-controller\n",
            service,
        )

    def test_acceptance_binding_matches_rust_field_order_and_staged_zero_contract(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        self.assertEqual(
            self.fixture.binding["scenario_sha256"],
            "b71fa0055f981301b608bb730940d29f1b3474e20302d76975f0d21fa872eb05",
        )
        staged = CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        self.assertEqual(staged["staged_zero"]["units"][activation_package.PERSISTENT_UNIT]["ActiveState"], "inactive")
        for unit in activation_package.STAGED_ZERO_UNITS:
            self.assertEqual(staged["staged_zero"]["units"][unit]["ActiveState"], "active")
        binding_path = self.fixture.root / activation_package.ACCEPTANCE_BINDING_PATH.lstrip("/")
        self.assertEqual((stat.S_IMODE(binding_path.stat().st_mode), binding_path.stat().st_gid), (0o444, os.getegid()))
        self.assertFalse(binding_path.read_bytes().endswith(b"\n"))
        self.assertEqual(json.loads(binding_path.read_bytes()), self.fixture.binding)
        self.assertEqual(self.fixture.binding["scenario_sha256"], self.fixture.binding["acceptance"]["scenario_sha256"])
        keyholder = json.loads((
            self.fixture.root / activation_package.KEYHOLDER_CONFIG_PATH.lstrip("/")
        ).read_bytes())
        controld_peer = (
            self.fixture.identities["controld"]["uid"],
            self.fixture.identities["controld"]["gid"],
        )
        qualification_peer = (
            self.fixture.identities["qualification"]["uid"],
            self.fixture.identities["qualification"]["gid"],
        )
        self.assertEqual(
            (
                self.fixture.binding["keyholder_peer_uid"],
                self.fixture.binding["keyholder_peer_gid"],
            ),
            controld_peer,
        )

        self.assertEqual(
            (
                self.fixture.binding["acceptance_peer_uid"],
                self.fixture.binding["acceptance_peer_gid"],
            ),
            qualification_peer,
        )
        self.assertEqual((keyholder["peer"]["uid"], keyholder["peer"]["gid"]), controld_peer)
        self.assertNotEqual(controld_peer, qualification_peer)
        self.assertEqual(list(self.fixture.binding), [
            "schema_version", "activation_id", "activation_package_digest", "scenario_sha256",
            "keyholder_peer_uid", "keyholder_peer_gid",
            "acceptance_peer_uid", "acceptance_peer_gid",
            "timeout_millis", "fixture", "acceptance",
        ])
        self.assertEqual(list(self.fixture.binding["acceptance"]), [
            "actor", "scenario_sha256", "run_event", "grant_event", "rerun_event", "tombstone_event", "failure_run_event",
            "export_subject", "export_generation", "export_authorization_digest",
        ])
        self.assertEqual(list(self.fixture.binding["acceptance"]["actor"]), ["public_key", "generation"])
        controld = json.loads((self.fixture.root / activation_package.CONFIG_TARGETS["controld_config"].lstrip("/")).read_bytes())
        self.assertEqual((controld["capacity"], controld["acceptance_binding"]), (0, activation_package.ACCEPTANCE_BINDING_PATH))
        for role, component_name in activation_package.INSTALLABLE_COMPONENT_ROLES.items():
            component = next(item for item in manifest["components"] if item["name"] == component_name)
            installed = self.fixture.root / activation_package.STATIC_TARGETS[role].lstrip("/")
            self.assertEqual((stat.S_IMODE(installed.stat().st_mode), activation_package.digest(installed.read_bytes())), (0o755, component["binary_sha256"]))
        controller = self.fixture.root / activation_package.ACTIVATION_CONTROLLER_PATH.lstrip("/")
        package_module = self.fixture.root / activation_package.ACTIVATION_PACKAGE_MODULE_PATH.lstrip("/")
        self.assertEqual(stat.S_IMODE(controller.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(package_module.stat().st_mode), 0o644)
        fixed = self.fixture.root / activation_package.FIXED_PACKAGE_PATH.lstrip("/")
        self.assertEqual(stat.S_IMODE(fixed.stat().st_mode), 0o700)
        fixed_manifest, _fixed_payloads = CONTROLLER.load_package(fixed, live=False)
        self.assertEqual(fixed_manifest, manifest)

    def test_frozen_rust_acceptance_validator_is_exact_and_fail_closed(self) -> None:
        manifest, payloads, _driver = self.fixture.load()
        validator_entry = next(
            item for item in manifest["entries"]
            if item["role"] == "acceptance_control_binary"
        )
        validator_source = self.fixture.package / validator_entry["source"]
        source_before = validator_source.read_bytes()
        source_metadata = validator_source.stat()
        execution_root = self.fixture.root / "usr/libexec"
        names_before = sorted(path.name for path in execution_root.iterdir())
        active_entry = next(
            item for item in manifest["entries"] if item["role"] == "controld_config"
        )
        active = json.loads(payloads[active_entry["active_source"]])
        signer = active["keyholder_selectors"]["ci_event"]["public_key"].encode() + b"\n"
        success = subprocess.CompletedProcess([], 0, signer, b"")
        invoked_descriptor = -1

        def noexec_aware_validator(argv, **_keywords):
            nonlocal invoked_descriptor
            invoked_descriptor = int(Path(argv[0]).name)
            executable = os.fstat(invoked_descriptor)
            source = validator_source.stat()
            if (executable.st_dev, executable.st_ino) == (source.st_dev, source.st_ino):
                raise PermissionError("modeled noexec package source")
            self.assertEqual(argv[1:], ["--validate-binding-stdin"])
            self.assertEqual(stat.S_IMODE(executable.st_mode), 0o500)
            self.assertEqual(executable.st_nlink, 0)
            self.assertEqual((executable.st_uid, executable.st_gid), (os.geteuid(), os.getegid()))
            self.assertEqual(
                Path(argv[0]).read_bytes(), payloads[validator_entry["source"]],
            )
            self.assertEqual(
                CONTROLLER.fcntl.fcntl(invoked_descriptor, CONTROLLER.fcntl.F_GETFL)
                & os.O_ACCMODE,
                os.O_RDONLY,
            )
            matching = []
            for candidate in Path("/proc/self/fd").iterdir():
                try:
                    metadata = os.fstat(int(candidate.name))
                except OSError:
                    continue
                if (metadata.st_dev, metadata.st_ino) == (
                    executable.st_dev, executable.st_ino,
                ):
                    matching.append(int(candidate.name))
            self.assertEqual(matching, [invoked_descriptor])
            return success

        with mock.patch.object(
            CONTROLLER.subprocess, "run", side_effect=noexec_aware_validator,
        ) as invoked:
            CONTROLLER._validate_acceptance_binding_with_frozen_rust(
                self.fixture.package, manifest, payloads, self.fixture.binding,
                live=False, root=self.fixture.root,
            )
        kwargs = invoked.call_args.kwargs
        self.assertEqual(kwargs["input"], CONTROLLER._acceptance_binding_bytes(manifest, self.fixture.binding))
        self.assertEqual(kwargs["env"], {"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        self.assertEqual(kwargs["timeout"], 5)
        self.assertEqual(kwargs["pass_fds"], (invoked_descriptor,))
        with self.assertRaises(OSError):
            os.fstat(invoked_descriptor)
        self.assertEqual(validator_source.read_bytes(), source_before)
        source_after = validator_source.stat()
        self.assertEqual(
            (source_after.st_dev, source_after.st_ino, source_after.st_mode,
             source_after.st_uid, source_after.st_gid, source_after.st_nlink,
             source_after.st_size, source_after.st_mtime_ns),
            (source_metadata.st_dev, source_metadata.st_ino, source_metadata.st_mode,
             source_metadata.st_uid, source_metadata.st_gid, source_metadata.st_nlink,
             source_metadata.st_size, source_metadata.st_mtime_ns),
        )
        self.assertEqual(sorted(path.name for path in execution_root.iterdir()), names_before)

        failures = (
            subprocess.CompletedProcess([], 4, b"", b""),
            subprocess.CompletedProcess([], 0, b"0" * 64 + b"\n", b""),
            subprocess.CompletedProcess([], 0, signer, b"sentinel-private-stderr"),
            subprocess.CompletedProcess([], 0, signer.rstrip(b"\n"), b""),
        )
        for result in failures:
            with self.subTest(result=result), mock.patch.object(
                CONTROLLER.subprocess, "run", return_value=result,
            ):
                with self.assertRaisesRegex(ValueError, "semantic validation failed"):
                    CONTROLLER._validate_acceptance_binding_with_frozen_rust(
                        self.fixture.package, manifest, payloads,
                        self.fixture.binding, live=False, root=self.fixture.root,
                    )

        real_open = CONTROLLER.os.open

        def unsupported_tmpfile(path, flags, *args, **kwargs):
            if flags & os.O_TMPFILE:
                raise OSError("O_TMPFILE unsupported")
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(
            CONTROLLER.os, "open", side_effect=unsupported_tmpfile,
        ), mock.patch.object(CONTROLLER.subprocess, "run") as not_invoked:
            with self.assertRaises(OSError):
                CONTROLLER._validate_acceptance_binding_with_frozen_rust(
                    self.fixture.package, manifest, payloads, self.fixture.binding,
                    live=False, root=self.fixture.root,
                )
        not_invoked.assert_not_called()
        self.assertEqual(sorted(path.name for path in execution_root.iterdir()), names_before)

        failed_descriptor = -1

        def exec_failure(argv, **_keywords):
            nonlocal failed_descriptor
            failed_descriptor = int(Path(argv[0]).name)
            raise OSError("modeled exec failure")

        with mock.patch.object(
            CONTROLLER.subprocess, "run", side_effect=exec_failure,
        ):
            with self.assertRaisesRegex(ValueError, "semantic validation failed"):
                CONTROLLER._validate_acceptance_binding_with_frozen_rust(
                    self.fixture.package, manifest, payloads, self.fixture.binding,
                    live=False, root=self.fixture.root,
                )
        with self.assertRaises(OSError):
            os.fstat(failed_descriptor)
        self.assertEqual(sorted(path.name for path in execution_root.iterdir()), names_before)

        drifted_descriptor = -1

        def mtime_drift(argv, **_keywords):
            nonlocal drifted_descriptor
            drifted_descriptor = int(Path(argv[0]).name)
            metadata = os.fstat(drifted_descriptor)
            os.utime(
                drifted_descriptor,
                ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000),
            )
            return success

        with mock.patch.object(
            CONTROLLER.subprocess, "run", side_effect=mtime_drift,
        ):
            with self.assertRaisesRegex(ValueError, "semantic validation failed"):
                CONTROLLER._validate_acceptance_binding_with_frozen_rust(
                    self.fixture.package, manifest, payloads, self.fixture.binding,
                    live=False, root=self.fixture.root,
                )
        with self.assertRaises(OSError):
            os.fstat(drifted_descriptor)
        self.assertEqual(sorted(path.name for path in execution_root.iterdir()), names_before)

    def test_stage_progress_fifo_is_exact_nonblocking_and_close_on_exec(self) -> None:
        read_descriptor, write_descriptor = os.pipe2(os.O_NONBLOCK)
        try:
            progress = CONTROLLER.StageProgress(write_descriptor)
            flags = CONTROLLER.fcntl.fcntl(write_descriptor, CONTROLLER.fcntl.F_GETFD)
            self.assertTrue(flags & CONTROLLER.fcntl.FD_CLOEXEC)
            for name in CONTROLLER.STAGE_PROGRESS_NAMES:
                progress.advance(name)
            progress.finish("staged")
            os.close(write_descriptor)
            write_descriptor = -1
            expected = CONTROLLER.STAGE_PROGRESS_MAGIC + b"".join(
                bytes((ordinal, ordinal ^ 0xFF))
                for ordinal in range(1, CONTROLLER.STAGE_PROGRESS_OPERATION_COUNT + 1)
            ) + b"\x80\x7f"
            self.assertEqual(os.read(read_descriptor, 128), expected)
            self.assertEqual(len(expected), 98)
            with self.assertRaisesRegex(ValueError, "operation follows terminal"):
                progress.advance("package_load")
            with self.assertRaisesRegex(ValueError, "terminal differs"):
                progress.finish("staged")
        finally:
            if write_descriptor >= 0:
                os.close(write_descriptor)
            os.close(read_descriptor)

        read_descriptor, write_descriptor = os.pipe2(os.O_NONBLOCK)
        try:
            progress = CONTROLLER.StageProgress(write_descriptor)
            for name in CONTROLLER.STAGE_PROGRESS_NAMES[:6]:
                progress.advance(name)
            with self.assertRaisesRegex(ValueError, "terminal differs"):
                progress.finish("staged")
            progress.finish("unchanged")
            os.close(write_descriptor)
            write_descriptor = -1
            expected = CONTROLLER.STAGE_PROGRESS_MAGIC + b"".join(
                bytes((ordinal, ordinal ^ 0xFF)) for ordinal in range(1, 7)
            ) + b"\x81\x7e"
            self.assertEqual(os.read(read_descriptor, 128), expected)
            self.assertEqual(len(expected), 18)
        finally:
            if write_descriptor >= 0:
                os.close(write_descriptor)
            os.close(read_descriptor)

        with tempfile.NamedTemporaryFile() as regular:
            with self.assertRaisesRegex(ValueError, "descriptor is invalid"):
                CONTROLLER.StageProgress(regular.fileno())
        read_descriptor, write_descriptor = os.pipe()
        try:
            with self.assertRaisesRegex(ValueError, "descriptor is invalid"):
                CONTROLLER.StageProgress(write_descriptor)
        finally:
            os.close(read_descriptor)
            os.close(write_descriptor)
        read_descriptor, write_descriptor = os.pipe2(os.O_NONBLOCK)
        try:
            with self.assertRaisesRegex(ValueError, "descriptor is invalid"):
                CONTROLLER.StageProgress(read_descriptor)
        finally:
            os.close(read_descriptor)
            os.close(write_descriptor)

    def test_fixed_capacity_one_action_is_bound_idempotent_and_replaces_staged_processes(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        CONTROLLER.activate(manifest, payloads, self.fixture.root, driver)
        staged_controller = driver.process("buzz-ci-controld.service")
        request, raw = self.capacity_one_request("b")
        receipt = CONTROLLER._read_receipt(self.fixture.root)
        parsed, request_sha256 = CONTROLLER._parse_capacity_one_request(raw, receipt)
        reordered = {"action": request["action"], **{key: value for key, value in request.items() if key != "action"}}
        with self.assertRaisesRegex(ValueError, "field order"):
            CONTROLLER._parse_capacity_one_request(CONTROLLER._wire_json(reordered), receipt)

        response = CONTROLLER._set_capacity_one(
            manifest, payloads, self.fixture.root, driver, parsed, request_sha256,
        )
        self.assertEqual(list(response), [
            "schema_version", "action", "activation_id", "activation_package_digest",
            "scenario_sha256", "operation_id", "state", "receipt_sha256",
        ])
        self.assertEqual((response["schema_version"], response["action"], response["state"]), (
            CONTROLLER.CAPACITY_ONE_RESPONSE_SCHEMA, "set_capacity_one", "active_one",
        ))
        receipt_path = self.fixture.root / CONTROLLER.RECEIPT_PATH.lstrip("/")
        self.assertEqual(response["receipt_sha256"], activation_package.digest(receipt_path.read_bytes()))
        final_receipt = CONTROLLER._read_receipt(self.fixture.root)
        self.assertEqual((final_receipt["state"], final_receipt["capacity_one"]["phase"]), ("active_one", "active_one"))
        self.assertEqual(
            final_receipt["capacity_one"]["processes_before"]["buzz-ci-controld.service"],
            staged_controller,
        )
        for unit in CONTROLLER.CAPACITY_ONE_PROCESS_UNITS:
            active = driver.process(unit)
            self.assertTrue(active["invocation_id"])
            self.assertGreater(active["main_pid"], 0)
        self.assertNotEqual(driver.process("buzz-ci-controld.service")["invocation_id"], staged_controller["invocation_id"])
        self.assertEqual(driver.process("buzz-ci-runner.service")["invocation_id"], final_receipt["capacity_one"]["processes_after"]["buzz-ci-runner.service"]["invocation_id"])
        for unit, path in CONTROLLER.CAPACITY_ONE_FRAGMENT_PATHS.items():
            self.assertEqual(driver.fragment_path(unit), path)
        self.assertEqual(driver.unit("buzz-ci-acceptance-control.service")["ActiveState"], "active")
        self.assertEqual(driver.unit("buzz-ci-controld-acceptance.socket")["ActiveState"], "active")
        self.assertEqual(
            CONTROLLER._set_capacity_one(manifest, payloads, self.fixture.root, driver, parsed, request_sha256),
            response,
        )
        different, different_raw = self.capacity_one_request("c")
        different_parsed, different_sha = CONTROLLER._parse_capacity_one_request(different_raw, final_receipt)
        with self.assertRaisesRegex(ValueError, "exact replay differs"):
            CONTROLLER._set_capacity_one(
                manifest, payloads, self.fixture.root, driver, different_parsed, different_sha,
            )

    def test_capacity_one_restart_failure_compensates_and_exact_retry_succeeds(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        CONTROLLER.activate(manifest, payloads, self.fixture.root, driver)
        _request, raw = self.capacity_one_request("b")
        parsed, request_sha256 = CONTROLLER._parse_capacity_one_request(raw, CONTROLLER._read_receipt(self.fixture.root))
        original_start = driver.start
        failed_once = True

        def fail_runner_start(unit: str) -> None:
            nonlocal failed_once
            if unit == "buzz-ci-runner.service" and failed_once:
                failed_once = False
                raise ValueError("injected runner restart failure")
            original_start(unit)

        driver.start = fail_runner_start
        with self.assertRaisesRegex(ValueError, "injected runner restart failure"):
            CONTROLLER._set_capacity_one(
                manifest, payloads, self.fixture.root, driver, parsed, request_sha256,
            )
        receipt = CONTROLLER._read_receipt(self.fixture.root)
        self.assertEqual((receipt["state"], receipt["capacity_one"]["phase"], receipt["capacity_one"]["attempt_count"]), (
            "qualified_closed", "compensated", 1,
        ))
        CONTROLLER._verify_phase(manifest, self.fixture.root, "staged")
        CONTROLLER._staged_zero_readback(manifest, self.fixture.root, driver)
        self.assertEqual(driver.unit("buzz-ci-acceptance-control.service")["ActiveState"], "active")
        driver.start = original_start
        response = CONTROLLER._set_capacity_one(
            manifest, payloads, self.fixture.root, driver, parsed, request_sha256,
        )
        self.assertEqual(response["state"], "active_one")
        self.assertEqual(CONTROLLER._read_receipt(self.fixture.root)["capacity_one"]["attempt_count"], 2)

    def test_capacity_one_partial_config_swap_and_fragment_drift_compensate(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        CONTROLLER.activate(manifest, payloads, self.fixture.root, driver)
        _request, raw = self.capacity_one_request("b")
        parsed, request_sha256 = CONTROLLER._parse_capacity_one_request(raw, CONTROLLER._read_receipt(self.fixture.root))
        controld = next(entry for entry in manifest["entries"] if entry["role"] == "controld_config")
        original_write = CONTROLLER._atomic_write
        failed_once = True

        def fail_partial_swap(root: Path, target: str, payload: bytes, mode: int, uid: int, gid: int) -> None:
            nonlocal failed_once
            if target == controld["target"] and payload == payloads[controld["active_source"]] and failed_once:
                failed_once = False
                raise ValueError("injected partial config swap")
            original_write(root, target, payload, mode, uid, gid)

        with mock.patch.object(CONTROLLER, "_atomic_write", side_effect=fail_partial_swap):
            with self.assertRaisesRegex(ValueError, "injected partial config swap"):
                CONTROLLER._set_capacity_one(
                    manifest, payloads, self.fixture.root, driver, parsed, request_sha256,
                )
        CONTROLLER._verify_phase(manifest, self.fixture.root, "staged")
        CONTROLLER._staged_zero_readback(manifest, self.fixture.root, driver)
        original_fragment = driver.fragment_path
        drifted_once = True

        def drift_fragment(unit: str) -> str:
            nonlocal drifted_once
            if unit == "buzz-ci-runner.socket" and drifted_once:
                drifted_once = False
                return "/etc/systemd/system/stale-runner.socket"
            return original_fragment(unit)

        driver.fragment_path = drift_fragment
        with self.assertRaisesRegex(ValueError, "systemd fragment differs"):
            CONTROLLER._set_capacity_one(
                manifest, payloads, self.fixture.root, driver, parsed, request_sha256,
            )
        CONTROLLER._verify_phase(manifest, self.fixture.root, "staged")
        CONTROLLER._staged_zero_readback(manifest, self.fixture.root, driver)

    def compensation_paths(self, manifest: dict[str, object]) -> tuple[set[Path], set[str]]:
        """Static entry parents (never written by return-to-zero) and the targets it does write."""
        static_parents: set[Path] = set()
        written: set[str] = set()
        for entry in manifest["entries"]:
            if entry["role"] == "execd_config":
                continue
            if "active_source" in entry:
                written.add(entry["target"])
            else:
                static_parents.add(self.fixture.root / Path(entry["target"]).parent.relative_to("/"))
        for record in CONTROLLER._read_receipt(self.fixture.root)["acceptance_generated"]:
            written.add(record["target"])
        return static_parents, written

    def test_return_to_zero_writes_only_inside_the_helper_sandbox_paths(self) -> None:
        # buzz-ci-acceptance-control.service runs the compensation under
        # ProtectSystem=strict with only /etc/buzzci, /var/lib/buzzci/acceptance-control,
        # and /var/lib/buzzci/activation-controller writable. On the clean host the
        # full-package restage hit EROFS on every binary and unit (H5 boot 3).
        service = (ACTIVATION_ROOT / "templates/buzz-ci-acceptance-control.service").read_text()
        writable = next(line for line in service.splitlines() if line.startswith("ReadWritePaths=")).split("=", 1)[1].split()
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        self.activate_one(manifest, payloads, driver)
        static_parents, written = self.compensation_paths(manifest)
        self.assertTrue(written)
        for target in written:
            self.assertTrue(any(target.startswith(prefix + "/") for prefix in writable), target)
        for parent in static_parents:
            self.assertFalse(any(str("/" / parent.relative_to(self.fixture.root)).startswith(prefix + "/") for prefix in writable), parent)
        self.assertNotEqual(self.fixture.root, Path("/"))
        self.assertNotEqual(os.geteuid(), 0)
        writes: list[str] = []
        original_write = CONTROLLER._atomic_write

        def record_write(root: Path, target: str, payload: bytes, mode: int, uid: int, gid: int, **kwargs: object) -> None:
            writes.append(target)
            original_write(root, target, payload, mode, uid, gid, **kwargs)

        saved_modes = {parent: parent.stat().st_mode for parent in static_parents}
        try:
            for parent in static_parents:
                parent.chmod(0o555)
            with mock.patch.object(CONTROLLER, "_atomic_write", record_write):
                result = CONTROLLER._return_to_staged_zero(
                    manifest, payloads, self.fixture.root, driver,
                    CONTROLLER._read_receipt(self.fixture.root)["acceptance_generated"],
                    keep_acceptance_control=True,
                )
        finally:
            for parent, mode in saved_modes.items():
                parent.chmod(stat.S_IMODE(mode))
        self.assertEqual(set(writes) - {CONTROLLER.RECEIPT_PATH}, written)
        self.assertEqual(result["managed_targets"]["controld_config"], "staged")
        CONTROLLER._verify_phase(manifest, self.fixture.root, "staged")
        CONTROLLER._staged_zero_readback(manifest, self.fixture.root, driver)
        self.assertEqual(driver.unit("buzz-ci-acceptance-control.service")["ActiveState"], "active")

    def test_return_to_zero_reports_a_drifted_static_target_instead_of_rewriting_it(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        self.activate_one(manifest, payloads, driver)
        entry = next(item for item in manifest["entries"] if item["role"] == "qualification_binary")
        target = self.fixture.root / entry["target"].lstrip("/")
        original = target.read_bytes()
        write_file(target, original + b"drift", stat.S_IMODE(target.stat().st_mode))
        with self.assertRaisesRegex(ValueError, "staged readback: .*" + re.escape(entry["target"])):
            CONTROLLER._return_to_staged_zero(
                manifest, payloads, self.fixture.root, driver,
                CONTROLLER._read_receipt(self.fixture.root)["acceptance_generated"],
                keep_acceptance_control=True,
            )
        self.assertEqual(target.read_bytes(), original + b"drift")

    def test_capacity_one_rejects_stale_controld_process_and_compensates(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        CONTROLLER.activate(manifest, payloads, self.fixture.root, driver)
        staged = driver.process("buzz-ci-controld.service")
        _request, raw = self.capacity_one_request("b")
        parsed, request_sha256 = CONTROLLER._parse_capacity_one_request(raw, CONTROLLER._read_receipt(self.fixture.root))
        original_start = driver.start

        def stale_controld(unit: str) -> None:
            original_start(unit)
            if unit == "buzz-ci-controld.service":
                state = json.loads(self.fixture.fake_state.read_bytes())
                state["units"][unit].update({"InvocationID": staged["invocation_id"], "MainPID": staged["main_pid"]})
                write_file(self.fixture.fake_state, activation_package.canonical_json(state), 0o600)

        driver.start = stale_controld
        with self.assertRaisesRegex(ValueError, "process generation is stale"):
            CONTROLLER._set_capacity_one(
                manifest, payloads, self.fixture.root, driver, parsed, request_sha256,
            )
        receipt = CONTROLLER._read_receipt(self.fixture.root)
        self.assertEqual((receipt["state"], receipt["capacity_one"]["phase"]), ("qualified_closed", "compensated"))
        CONTROLLER._staged_zero_readback(manifest, self.fixture.root, driver)

    def test_capacity_one_accepts_retained_invocation_ids_on_dead_units(self) -> None:
        # systemd 259 keeps the InvocationID of a stopped service until its next
        # stop job: after the closed qualification execd is inactive/dead with
        # MainPID=0 and a retained id. Capacity one must start it anyway and
        # prove a new id afterwards.
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        CONTROLLER.activate(manifest, payloads, self.fixture.root, driver)
        state = json.loads(self.fixture.fake_state.read_bytes())
        for unit in ("buzz-ci-execd.service", "buzz-ci-runner.service"):
            state["units"].setdefault(unit, {}).update({
                "LoadState": "loaded", "ActiveState": "inactive", "SubState": "dead",
                "InvocationID": "e" * 32, "MainPID": 0,
            })
        write_file(self.fixture.fake_state, activation_package.canonical_json(state), 0o600)
        self.assertEqual(driver.process("buzz-ci-execd.service"), {"invocation_id": "e" * 32, "main_pid": 0})
        _request, raw = self.capacity_one_request("b")
        parsed, request_sha256 = CONTROLLER._parse_capacity_one_request(raw, CONTROLLER._read_receipt(self.fixture.root))
        response = CONTROLLER._set_capacity_one(
            manifest, payloads, self.fixture.root, driver, parsed, request_sha256,
        )
        self.assertEqual(response["state"], "active_one")
        receipt = CONTROLLER._read_receipt(self.fixture.root)
        capacity_one = receipt["capacity_one"]
        self.assertEqual(capacity_one["processes_before"]["buzz-ci-execd.service"], {"invocation_id": "e" * 32, "main_pid": 0})
        self.assertEqual(capacity_one["processes_before"]["buzz-ci-runner.service"], {"invocation_id": "e" * 32, "main_pid": 0})
        for unit in ("buzz-ci-execd.service", "buzz-ci-runner.service"):
            after = capacity_one["processes_after"][unit]
            self.assertNotEqual(after["invocation_id"], "e" * 32)
            self.assertGreater(after["main_pid"], 0)

    def test_capacity_one_rejects_a_dead_unit_that_still_reports_a_main_pid(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        CONTROLLER.activate(manifest, payloads, self.fixture.root, driver)
        _request, raw = self.capacity_one_request("b")
        parsed, request_sha256 = CONTROLLER._parse_capacity_one_request(raw, CONTROLLER._read_receipt(self.fixture.root))
        for field, value in (("MainPID", 4242), ("SubState", "auto-restart")):
            state = json.loads(self.fixture.fake_state.read_bytes())
            state["units"].setdefault("buzz-ci-execd.service", {}).update({
                "LoadState": "loaded", "ActiveState": "inactive", "SubState": "dead",
                "InvocationID": "e" * 32, "MainPID": 0, field: value,
            })
            write_file(self.fixture.fake_state, activation_package.canonical_json(state), 0o600)
            with self.assertRaisesRegex(ValueError, "stale staged process remains active: buzz-ci-execd.service"):
                CONTROLLER._set_capacity_one(
                    manifest, payloads, self.fixture.root, driver, parsed, request_sha256,
                )
            receipt = CONTROLLER._read_receipt(self.fixture.root)
            self.assertEqual((receipt["state"], receipt["capacity_one"]), ("qualified_closed", None))

    def test_fixed_zero_actions_are_bound_idempotent_and_prove_without_writes(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        self.activate_one(manifest, payloads, driver)

        prepare, prepare_sha = self.parsed_zero_request("prepare-qualification-zero", "c")
        prepared = CONTROLLER._prepare_qualification_zero(
            manifest, payloads, self.fixture.root, driver, prepare, prepare_sha,
        )
        self.assertEqual((prepared["action"], prepared["state"]), ("prepare_qualification_zero", "staged_zero"))
        self.assertEqual(
            CONTROLLER._verify_zero_configs(manifest, self.fixture.root),
            {"runner_config": "staged", "controld_config": "staged"},
        )
        self.assertEqual(driver.unit("buzz-ci-controld.service")["ActiveState"], "active")
        self.assertEqual(
            CONTROLLER._prepare_qualification_zero(manifest, payloads, self.fixture.root, driver, prepare, prepare_sha),
            prepared,
        )

        finalize, finalize_sha = self.parsed_zero_request(
            "finalize-qualification-zero", "d", final_response_sha256="e" * 64,
            expected_controller_generation=8, expected_runner_generation=12,
        )
        finalized = CONTROLLER._finalize_qualification_zero(
            manifest, payloads, self.fixture.root, driver, finalize, finalize_sha,
        )
        self.assertEqual((finalized["action"], finalized["state"]), ("finalize_qualification_zero", "staged_zero"))
        self.assertEqual(driver.unit("buzz-ci-acceptance-control.socket")["ActiveState"], "active")
        self.assertEqual(driver.unit("buzz-ci-controld-acceptance.socket")["ActiveState"], "inactive")
        self.assertFalse(self.fixture.root.joinpath("run/buzzci/controld-acceptance.sock").exists())
        self.assertEqual(
            CONTROLLER._finalize_qualification_zero(manifest, payloads, self.fixture.root, driver, finalize, finalize_sha),
            finalized,
        )

        prove, _prove_sha = self.parsed_zero_request("prove-qualification-zero", "f")
        before = (self.fixture.root / CONTROLLER.RECEIPT_PATH.lstrip("/")).read_bytes()
        proven = CONTROLLER._prove_qualification_zero(manifest, self.fixture.root, driver, prove)
        after = (self.fixture.root / CONTROLLER.RECEIPT_PATH.lstrip("/")).read_bytes()
        self.assertEqual(before, after)
        self.assertEqual(proven["receipt_sha256"], finalized["receipt_sha256"])
        self.assertEqual(CONTROLLER.check_current(manifest, self.fixture.root, driver)["status"], "qualification_zero_finalized")

    def test_early_finalize_prepares_exact_scope_and_preserves_retry(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        self.activate_one(manifest, payloads, driver)
        self.assertIsNone(CONTROLLER._read_receipt(self.fixture.root)["qualification_zero"])
        request, digest = self.parsed_zero_request(
            "finalize-qualification-zero", "d", failed_stage="authenticated_export",
            expected_controller_generation=7, expected_runner_generation=11,
        )
        response = CONTROLLER._finalize_qualification_zero(
            manifest, payloads, self.fixture.root, driver, request, digest,
        )
        state = CONTROLLER._read_receipt(self.fixture.root)["qualification_zero"]
        self.assertEqual(state["phase"], "finalized")
        self.assertEqual(state["finalize"], {"operation_id": request["operation_id"], "request_sha256": digest})
        prepare = {**request, "action": "prepare_qualification_zero"}
        prepare["operation_id"] = activation_package.digest(
            b"buzz-ci:qualification-zero:compensation-prepare:v1\n" + digest.encode("ascii")
        )
        self.assertEqual(state["prepare"], {
            "operation_id": prepare["operation_id"],
            "request_sha256": activation_package.digest(CONTROLLER._wire_json(prepare)),
        })
        for field in ("activation_id", "activation_package_digest", "scenario_sha256",
                      "initial_controller_generation", "initial_runner_generation"):
            self.assertEqual(state[field], request[field])
        self.assertEqual(CONTROLLER._finalize_qualification_zero(
            manifest, payloads, self.fixture.root, driver, request, digest,
        ), response)
        changed, changed_sha = self.parsed_zero_request("finalize-qualification-zero", "e")
        with self.assertRaisesRegex(ValueError, "finalize replay differs"):
            CONTROLLER._finalize_qualification_zero(
                manifest, payloads, self.fixture.root, driver, changed, changed_sha,
            )
        self.assertEqual(CONTROLLER._read_receipt(self.fixture.root)["qualification_zero"], state)

    def test_early_finalize_rejects_binding_drift_before_preparation(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        self.activate_one(manifest, payloads, driver)
        before = CONTROLLER._receipt_sha256(self.fixture.root)
        request, _digest = self.parsed_zero_request("finalize-qualification-zero", "d")
        for field in ("activation_id", "activation_package_digest", "scenario_sha256",
                      "initial_controller_generation", "initial_runner_generation"):
            changed = {**request, field: request[field] + 1 if isinstance(request[field], int) else "e" * 64}
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "different activation|acceptance binding"):
                CONTROLLER._finalize_qualification_zero(
                    manifest, payloads, self.fixture.root, driver, changed,
                    activation_package.digest(CONTROLLER._wire_json(changed)),
                )
            self.assertEqual(CONTROLLER._receipt_sha256(self.fixture.root), before)

    def test_early_finalize_resumes_exact_prepare_after_interrupted_receipt_write(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        self.activate_one(manifest, payloads, driver)
        request, digest = self.parsed_zero_request("finalize-qualification-zero", "d")
        original_write = CONTROLLER._write_receipt

        def interrupted_write(*args):
            original_write(*args)
            raise ValueError("interrupted after durable preparation reservation")

        with mock.patch.object(CONTROLLER, "_write_receipt", side_effect=interrupted_write):
            with self.assertRaisesRegex(ValueError, "interrupted after durable"):
                CONTROLLER._finalize_qualification_zero(
                    manifest, payloads, self.fixture.root, driver, request, digest,
                )
        before = CONTROLLER._receipt_sha256(self.fixture.root)
        state = CONTROLLER._read_receipt(self.fixture.root)["qualification_zero"]
        self.assertEqual(state["phase"], "preparing")
        changed, changed_digest = self.parsed_zero_request("finalize-qualification-zero", "e")
        with self.assertRaisesRegex(ValueError, "compensation prepare replay differs"):
            CONTROLLER._finalize_qualification_zero(
                manifest, payloads, self.fixture.root, driver, changed, changed_digest,
            )
        self.assertEqual(CONTROLLER._receipt_sha256(self.fixture.root), before)
        CONTROLLER._finalize_qualification_zero(manifest, payloads, self.fixture.root, driver, request, digest)
        recovered = CONTROLLER._read_receipt(self.fixture.root)["qualification_zero"]
        self.assertEqual(recovered["phase"], "finalized")
        self.assertEqual(recovered["prepare"], state["prepare"])

    def test_early_prepare_failure_retains_evidence_and_finalize_retry_recovers(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        self.activate_one(manifest, payloads, driver)
        request, digest = self.parsed_zero_request("finalize-qualification-zero", "d")
        with mock.patch.object(CONTROLLER, "_apply_staged_configs", side_effect=ValueError("injected staging failure")):
            with self.assertRaisesRegex(ValueError, "injected staging failure"):
                CONTROLLER._finalize_qualification_zero(
                    manifest, payloads, self.fixture.root, driver, request, digest,
                )
        state = CONTROLLER._read_receipt(self.fixture.root)["qualification_zero"]
        self.assertEqual(state["phase"], "prepare_failed")
        prepared = state["prepare"]
        self.assertEqual(state["last_error"], "injected staging failure")
        CONTROLLER._finalize_qualification_zero(manifest, payloads, self.fixture.root, driver, request, digest)
        state = CONTROLLER._read_receipt(self.fixture.root)["qualification_zero"]
        self.assertEqual(state["prepare"], prepared)
        self.assertEqual(state["phase"], "finalized")

    def test_zero_wire_rejects_order_generation_and_replay_drift(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        self.activate_one(manifest, payloads, driver)
        request, raw = self.zero_request("prepare_qualification_zero", "c")
        receipt = CONTROLLER._read_receipt(self.fixture.root)
        reordered = {"action": request["action"], **{key: value for key, value in request.items() if key != "action"}}
        with self.assertRaisesRegex(ValueError, "field order"):
            CONTROLLER._parse_zero_request(CONTROLLER._wire_json(reordered), "prepare-qualification-zero", receipt)
        changed = dict(request)
        changed["initial_runner_generation"] = 12
        with self.assertRaisesRegex(ValueError, "acceptance binding"):
            CONTROLLER._parse_zero_request(CONTROLLER._wire_json(changed), "prepare-qualification-zero", receipt)
        parsed, request_sha = CONTROLLER._parse_zero_request(raw, "prepare-qualification-zero", receipt)
        CONTROLLER._prepare_qualification_zero(manifest, payloads, self.fixture.root, driver, parsed, request_sha)
        different, different_sha = self.parsed_zero_request("prepare-qualification-zero", "d")
        with self.assertRaisesRegex(ValueError, "replay differs"):
            CONTROLLER._prepare_qualification_zero(
                manifest, payloads, self.fixture.root, driver, different, different_sha,
            )

    def test_finalize_attempts_every_stop_and_exact_retry_recovers(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        self.activate_one(manifest, payloads, driver)
        prepare, prepare_sha = self.parsed_zero_request("prepare-qualification-zero", "c")
        CONTROLLER._prepare_qualification_zero(manifest, payloads, self.fixture.root, driver, prepare, prepare_sha)
        finalize, finalize_sha = self.parsed_zero_request("finalize-qualification-zero", "d")
        attempts: list[str] = []
        original_stop = driver.stop
        failed_once = True

        def partial_stop(name: str) -> None:
            nonlocal failed_once
            attempts.append(name)
            if name == "buzz-ci-runner.socket" and failed_once:
                failed_once = False
                raise ValueError("injected finalize stop failure")
            original_stop(name)

        driver.stop = partial_stop
        with self.assertRaisesRegex(ValueError, "qualification-zero finalize failures"):
            CONTROLLER._finalize_qualification_zero(manifest, payloads, self.fixture.root, driver, finalize, finalize_sha)
        self.assertEqual(attempts[:2], ["buzz-ci-controld-acceptance.socket", "buzz-ci-controld.service"])
        self.assertIn("buzz-ci-keyholder.socket", attempts)
        receipt = CONTROLLER._read_receipt(self.fixture.root)
        self.assertEqual((receipt["state"], receipt["qualification_zero"]["phase"]), ("rollback_failed", "finalize_failed"))
        driver.stop = original_stop
        recovered = CONTROLLER._finalize_qualification_zero(
            manifest, payloads, self.fixture.root, driver, finalize, finalize_sha,
        )
        self.assertEqual(recovered["state"], "staged_zero")

    def test_zero_proof_fails_closed_on_socket_path_readback(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        self.activate_one(manifest, payloads, driver)
        prepare, prepare_sha = self.parsed_zero_request("prepare-qualification-zero", "c")
        CONTROLLER._prepare_qualification_zero(manifest, payloads, self.fixture.root, driver, prepare, prepare_sha)
        finalize, finalize_sha = self.parsed_zero_request("finalize-qualification-zero", "d")
        CONTROLLER._finalize_qualification_zero(manifest, payloads, self.fixture.root, driver, finalize, finalize_sha)
        prove, _prove_sha = self.parsed_zero_request("prove-qualification-zero", "e")
        state = json.loads(self.fixture.fake_state.read_bytes())
        policy = manifest["socket_policy"]["controld_acceptance"]
        state["sockets"][policy["path"]] = {
            "path": policy["path"], "mode": policy["mode"], "uid": 0,
            "gid": manifest["identities"]["qualification"]["gid"],
        }
        write_file(self.fixture.fake_state, activation_package.canonical_json(state), 0o600)
        before = (self.fixture.root / CONTROLLER.RECEIPT_PATH.lstrip("/")).read_bytes()
        with self.assertRaisesRegex(ValueError, "endpoint remains present"):
            CONTROLLER._prove_qualification_zero(manifest, self.fixture.root, driver, prove)
        self.assertEqual((self.fixture.root / CONTROLLER.RECEIPT_PATH.lstrip("/")).read_bytes(), before)

    def test_persistent_activation_is_bound_idempotent_and_rolls_back_to_zero(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        scenario, acceptance = self.finalized_canary_evidence(manifest, payloads, driver)
        with mock.patch.object(CONTROLLER.subprocess, "run", side_effect=self.verifier_pass):
            first = CONTROLLER.persist_capacity_one(
                manifest, payloads, self.fixture.root, driver, scenario, acceptance,
            )
            receipt_before = (self.fixture.root / CONTROLLER.RECEIPT_PATH.lstrip("/")).read_bytes()
            second = CONTROLLER.persist_capacity_one(
                manifest, payloads, self.fixture.root, driver, scenario, acceptance,
            )
        self.assertEqual((first["status"], first["state"], first["capacity"]), ("persistent_active", "active_one", 1))
        self.assertEqual(first, second)
        self.assertEqual(
            (self.fixture.root / CONTROLLER.RECEIPT_PATH.lstrip("/")).read_bytes(), receipt_before,
        )
        receipt = CONTROLLER._read_receipt(self.fixture.root)
        self.assertEqual(receipt["persistent_activation"]["phase"], "active_one")
        self.assertEqual(
            receipt["persistent_activation"]["operation_id"],
            receipt["persistent_authorization"]["operation_id"],
        )
        rolled_back = CONTROLLER.rollback(manifest, self.fixture.root, driver)
        self.assertEqual((rolled_back["state"], rolled_back["capacity"]), ("rolled_back", 0))
        self.assertEqual(CONTROLLER.rollback(manifest, self.fixture.root, driver)["status"], "unchanged")

    def test_persistent_activation_rejects_stale_mismatch_and_changed_replay(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        scenario, acceptance = self.finalized_canary_evidence(manifest, payloads, driver)
        original = json.loads(acceptance.read_bytes())
        lock_fd = CONTROLLER._acquire_operator_lock(
            self.fixture.root, manifest["identities"]["controld"]["gid"],
        )
        try:
            with self.assertRaisesRegex(ValueError, "another activation operator operation"):
                CONTROLLER.persist_capacity_one(
                    manifest, payloads, self.fixture.root, driver, scenario, acceptance,
                )
        finally:
            CONTROLLER.fcntl.flock(lock_fd, CONTROLLER.fcntl.LOCK_UN)
            os.close(lock_fd)
        rejected = subprocess.CompletedProcess([], 1, b"", b"receipt rejected\n")
        before = (self.fixture.root / CONTROLLER.RECEIPT_PATH.lstrip("/")).read_bytes()
        with mock.patch.object(CONTROLLER.subprocess, "run", return_value=rejected), self.assertRaisesRegex(
            ValueError, "verifier did not return",
        ):
            CONTROLLER.persist_capacity_one(
                manifest, payloads, self.fixture.root, driver, scenario, acceptance,
            )
        self.assertEqual((self.fixture.root / CONTROLLER.RECEIPT_PATH.lstrip("/")).read_bytes(), before)

        stale = copy.deepcopy(original)
        stale["zero_transition"]["phases"][1]["response"]["controller_receipt_sha256"] = "f" * 64
        write_file(acceptance, activation_package.canonical_json(stale), 0o600)
        before = (self.fixture.root / CONTROLLER.RECEIPT_PATH.lstrip("/")).read_bytes()
        with mock.patch.object(CONTROLLER.subprocess, "run", side_effect=self.verifier_pass), self.assertRaisesRegex(
            ValueError, "stale",
        ):
            CONTROLLER.persist_capacity_one(
                manifest, payloads, self.fixture.root, driver, scenario, acceptance,
            )
        self.assertEqual((self.fixture.root / CONTROLLER.RECEIPT_PATH.lstrip("/")).read_bytes(), before)

        mismatched = copy.deepcopy(original)
        mismatched["integrated_candidate_sha"] = "f" * 40
        write_file(acceptance, activation_package.canonical_json(mismatched), 0o600)
        with mock.patch.object(CONTROLLER.subprocess, "run", side_effect=self.verifier_pass), self.assertRaisesRegex(
            ValueError, "does not authorize",
        ):
            CONTROLLER.persist_capacity_one(
                manifest, payloads, self.fixture.root, driver, scenario, acceptance,
            )

        write_file(acceptance, activation_package.canonical_json(original), 0o600)
        CONTROLLER._return_to_staged_zero(
            manifest, payloads, self.fixture.root, driver,
            CONTROLLER._read_receipt(self.fixture.root)["acceptance_generated"],
            keep_acceptance_control=True,
        )
        with mock.patch.object(CONTROLLER.subprocess, "run", side_effect=self.verifier_pass):
            CONTROLLER.persist_capacity_one(
                manifest, payloads, self.fixture.root, driver, scenario, acceptance,
            )
        acceptance.write_bytes(acceptance.read_bytes() + b" ")
        acceptance.chmod(0o600)
        with mock.patch.object(CONTROLLER.subprocess, "run", side_effect=self.verifier_pass), self.assertRaisesRegex(
            ValueError, "authorization replay differs",
        ):
            CONTROLLER.persist_capacity_one(
                manifest, payloads, self.fixture.root, driver, scenario, acceptance,
            )

    def test_global_operator_lock_rejects_every_mutating_controller_path(self) -> None:
        manifest, payloads, driver = self.fixture.load()

        def assert_locked(label: str, operation) -> None:
            receipt_path = self.fixture.root / CONTROLLER.RECEIPT_PATH.lstrip("/")
            receipt_before = receipt_path.read_bytes() if receipt_path.exists() else None
            systemd_before = self.fixture.fake_state.read_bytes()
            lock_fd = CONTROLLER._acquire_operator_lock(
                self.fixture.root, manifest["identities"]["controld"]["gid"],
            )
            try:
                with self.subTest(action=label), self.assertRaisesRegex(
                    ValueError, "another activation operator operation",
                ):
                    operation()
            finally:
                CONTROLLER.fcntl.flock(lock_fd, CONTROLLER.fcntl.LOCK_UN)
                os.close(lock_fd)
            self.assertEqual(self.fixture.fake_state.read_bytes(), systemd_before)
            self.assertEqual(receipt_path.read_bytes() if receipt_path.exists() else None, receipt_before)

        assert_locked(
            "stage",
            lambda: CONTROLLER.stage(
                manifest, payloads, self.fixture.root, driver, self.fixture.binding,
            ),
        )
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        assert_locked(
            "activate",
            lambda: CONTROLLER.activate(manifest, payloads, self.fixture.root, driver),
        )
        CONTROLLER.activate(manifest, payloads, self.fixture.root, driver)
        _request, raw = self.capacity_one_request("b")
        receipt = CONTROLLER._read_receipt(self.fixture.root)
        parsed, request_sha256 = CONTROLLER._parse_capacity_one_request(raw, receipt)
        assert_locked(
            "set-capacity-one",
            lambda: CONTROLLER._set_capacity_one(
                manifest, payloads, self.fixture.root, driver, parsed, request_sha256,
            ),
        )
        CONTROLLER._set_capacity_one(
            manifest, payloads, self.fixture.root, driver, parsed, request_sha256,
        )
        assert_locked(
            "qualify",
            lambda: CONTROLLER.qualify(manifest, payloads, self.fixture.root, driver),
        )
        prepare, prepare_sha = self.parsed_zero_request("prepare-qualification-zero", "c")
        assert_locked(
            "prepare-qualification-zero",
            lambda: CONTROLLER._prepare_qualification_zero(
                manifest, payloads, self.fixture.root, driver, prepare, prepare_sha,
            ),
        )
        CONTROLLER._prepare_qualification_zero(
            manifest, payloads, self.fixture.root, driver, prepare, prepare_sha,
        )
        finalize, finalize_sha = self.parsed_zero_request("finalize-qualification-zero", "d")
        assert_locked(
            "finalize-qualification-zero",
            lambda: CONTROLLER._finalize_qualification_zero(
                manifest, payloads, self.fixture.root, driver, finalize, finalize_sha,
            ),
        )
        CONTROLLER._finalize_qualification_zero(
            manifest, payloads, self.fixture.root, driver, finalize, finalize_sha,
        )
        missing = self.fixture.temporary / "must-not-be-read-under-lock.json"
        assert_locked(
            "persist-capacity-one",
            lambda: CONTROLLER.persist_capacity_one(
                manifest, payloads, self.fixture.root, driver, missing, missing,
            ),
        )
        assert_locked(
            "rollback",
            lambda: CONTROLLER.rollback(manifest, self.fixture.root, driver),
        )

    def test_persistent_activation_compensates_partial_failure_and_exact_retry_succeeds(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        scenario, acceptance = self.finalized_canary_evidence(manifest, payloads, driver)
        original_start = driver.start
        injected = False

        def fail_once(unit: str) -> None:
            nonlocal injected
            if unit == "buzz-ci-runner.service" and not injected:
                injected = True
                raise ValueError("injected persistent start failure")
            original_start(unit)

        driver.start = fail_once
        with mock.patch.object(CONTROLLER.subprocess, "run", side_effect=self.verifier_pass), self.assertRaisesRegex(
            ValueError, "injected persistent start failure",
        ):
            CONTROLLER.persist_capacity_one(
                manifest, payloads, self.fixture.root, driver, scenario, acceptance,
            )
        receipt = CONTROLLER._read_receipt(self.fixture.root)
        self.assertEqual(
            (receipt["state"], receipt["persistent_activation"]["phase"]),
            ("qualified_closed", "compensated"),
        )
        CONTROLLER._staged_zero_readback(manifest, self.fixture.root, driver)
        driver.start = original_start
        with mock.patch.object(CONTROLLER.subprocess, "run", side_effect=self.verifier_pass):
            result = CONTROLLER.persist_capacity_one(
                manifest, payloads, self.fixture.root, driver, scenario, acceptance,
            )
        self.assertEqual((result["state"], result["capacity"]), ("active_one", 1))
        self.assertEqual(CONTROLLER._read_receipt(self.fixture.root)["persistent_activation"]["attempt_count"], 2)

    def test_persistent_activation_readback_mismatch_compensates_to_zero(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        scenario, acceptance = self.finalized_canary_evidence(manifest, payloads, driver)
        original_fragment = driver.fragment_path
        injected = False

        def mismatch_once(unit: str) -> str:
            nonlocal injected
            if unit == "buzz-ci-runner.socket" and not injected:
                injected = True
                return "/wrong/persistent.fragment"
            return original_fragment(unit)

        driver.fragment_path = mismatch_once
        with mock.patch.object(CONTROLLER.subprocess, "run", side_effect=self.verifier_pass), self.assertRaisesRegex(
            ValueError, "fragment differs",
        ):
            CONTROLLER.persist_capacity_one(
                manifest, payloads, self.fixture.root, driver, scenario, acceptance,
            )
        receipt = CONTROLLER._read_receipt(self.fixture.root)
        self.assertEqual((receipt["state"], receipt["persistent_activation"]["phase"]), ("qualified_closed", "compensated"))
        CONTROLLER._staged_zero_readback(manifest, self.fixture.root, driver)

    def test_acceptance_scenario_package_and_peer_binding_are_fail_closed(self) -> None:
        changed = copy.deepcopy(self.fixture.scenario)
        changed["fixture"]["activation_package_digest"] = "c" * 64
        with self.assertRaisesRegex(ValueError, "different activation package"):
            CONTROLLER._acceptance_binding(self.fixture.manifest, changed)
        changed = copy.deepcopy(self.fixture.scenario)
        changed["fixture"]["expected_artifacts"].append(copy.deepcopy(changed["fixture"]["expected_artifacts"][0]))
        with self.assertRaisesRegex(ValueError, "exactly one"):
            CONTROLLER._acceptance_binding(self.fixture.manifest, changed)
        self.assertEqual(
            (
                self.fixture.binding["keyholder_peer_uid"],
                self.fixture.binding["keyholder_peer_gid"],
            ),
            (self.fixture.identities["controld"]["uid"], self.fixture.identities["controld"]["gid"]),
        )
        self.assertEqual(
            (
                self.fixture.binding["acceptance_peer_uid"],
                self.fixture.binding["acceptance_peer_gid"],
            ),
            (
                self.fixture.identities["qualification"]["uid"],
                self.fixture.identities["qualification"]["gid"],
            ),
        )
        different_peer = copy.deepcopy(self.fixture.binding)
        different_peer["acceptance_peer_uid"] = self.fixture.identities["controld"]["uid"]
        different_peer["acceptance_peer_gid"] = self.fixture.identities["controld"]["gid"]
        with self.assertRaisesRegex(ValueError, "peer identities differ"):
            CONTROLLER._acceptance_binding_bytes(self.fixture.manifest, different_peer)
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        different = copy.deepcopy(self.fixture.binding)
        different["scenario_sha256"] = "c" * 64
        different["acceptance"]["scenario_sha256"] = "c" * 64
        with self.assertRaisesRegex(ValueError, "scenario differs"):
            CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, different)

    def test_rollback_restores_enabled_listening_execd_baseline(self) -> None:
        prior_binary = b"prior execd binary\n"
        execd_package, seccomp_contract = execd_package_for_activation(self.fixture)
        execd_target = self.fixture.root / CONTROLLER.EXECD_BINARY_PATH.lstrip("/")
        write_file(execd_target, prior_binary, 0o755)
        installed = execd_install(execd_package, self.fixture.root, seccomp_contract)
        self.assertEqual(installed["status"], "installed")
        install_receipt_path = (
            self.fixture.root / CONTROLLER.EXECD_PACKAGE_RECEIPT_PATH.lstrip("/")
        )
        self.assertEqual(json.loads(install_receipt_path.read_bytes())["prior"]["state"], "present")
        self.enable_execd_baseline()
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        scenario, acceptance = self.finalized_canary_evidence(manifest, payloads, driver)
        with mock.patch.object(CONTROLLER.subprocess, "run", side_effect=self.verifier_pass):
            persistent = CONTROLLER.persist_capacity_one(
                manifest, payloads, self.fixture.root, driver, scenario, acceptance,
            )
        self.assertEqual(
            (persistent["status"], persistent["state"], persistent["capacity"]),
            ("persistent_active", "active_one", 1),
        )
        fixed_package = self.fixture.root / CONTROLLER.FIXED_PACKAGE_PATH.lstrip("/")
        installed_cli = self.fixture.root / "usr/libexec/buzz-ci-activation-controller"
        first = subprocess.run(
            [
                sys.executable, str(installed_cli), "rollback", "--package", str(fixed_package),
                "--root", str(self.fixture.root), "--fake-systemd-state", str(self.fixture.fake_state),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        self.assertEqual(first.returncode, 1)
        self.assertIn("execd package rollback is required", json.loads(first.stderr)["error"])
        self.assertTrue(fixed_package.exists())
        fixed_cli = fixed_package / "assets/buzz-ci-activation-controller"
        self.assertTrue(fixed_cli.exists())
        self.assertTrue(installed_cli.exists())
        self.assertEqual(driver.unit("buzz-ci-execd.socket")["ActiveState"], "inactive")

        def retry_from_installed_controller() -> subprocess.CompletedProcess[bytes]:
            return subprocess.run(
                [
                    sys.executable, str(installed_cli), "rollback", "--package", str(fixed_package),
                    "--root", str(self.fixture.root), "--fake-systemd-state", str(self.fixture.fake_state),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            )

        exact_hold_retry = retry_from_installed_controller()
        self.assertEqual(exact_hold_retry.returncode, 1)
        self.assertIn("execd package rollback is required", json.loads(exact_hold_retry.stderr)["error"])
        self.assertTrue(fixed_package.exists())

        terminal_path = self.fixture.root / CONTROLLER.EXECD_PACKAGE_ROLLBACK_PATH.lstrip("/")
        held_baseline = execd_target.with_name("buzz-ci-execd.test-held-baseline")
        injected = False

        def replace_terminal_target(phase: str) -> None:
            nonlocal injected
            if phase == "after_publish" and not injected:
                os.replace(execd_target, held_baseline)
                write_file(execd_target, b"hostile replacement\n", 0o755)
                injected = True

        with mock.patch.object(
            EXECD_INSTALLER, "_rollback_terminal_race", side_effect=replace_terminal_target,
        ), self.assertRaisesRegex(ValueError, "recoverable hold"):
            execd_rollback(execd_package, self.fixture.root, seccomp_contract)
        self.assertTrue(injected)
        holding = json.loads(terminal_path.read_bytes())
        self.assertEqual((holding["state"], holding["live_target"]["state"]), ("holding", "present"))
        held = retry_from_installed_controller()
        self.assertEqual(held.returncode, 1)
        self.assertIn("execd package rollback receipt differs", json.loads(held.stderr)["error"])
        self.assertTrue(fixed_package.exists())

        os.replace(held_baseline, execd_target)
        completed = execd_rollback(execd_package, self.fixture.root, seccomp_contract)
        self.assertEqual((completed["state"], completed["prior_state"]), ("rolled_back", "present"))
        terminal = json.loads(terminal_path.read_bytes())
        self.assertEqual(set(terminal), {"schema", "state", "install_receipt", "live_target"})
        terminal_raw = terminal_path.read_bytes()

        invalid_receipts: list[tuple[str, dict[str, object], str]] = []
        old_shape = copy.deepcopy(terminal)
        old_shape.pop("live_target")
        invalid_receipts.append(("old shape", old_shape, "rollback receipt differs"))
        extra = copy.deepcopy(terminal)
        extra["unexpected"] = True
        invalid_receipts.append(("extra field", extra, "rollback receipt differs"))
        stale = copy.deepcopy(terminal)
        stale["install_receipt"]["activation_package_digest"] = "f" * 64
        invalid_receipts.append(("wrong candidate", stale, "different candidate"))
        tampered = copy.deepcopy(terminal)
        tampered["live_target"]["sha256"] = "f" * 64
        invalid_receipts.append(("tampered binding", tampered, "live binding differs"))
        wrong_baseline = copy.deepcopy(terminal)
        wrong_baseline["install_receipt"]["prior"]["binary"]["sha256"] = "f" * 64
        wrong_baseline["install_receipt"]["prior"]["preimage"]["sha256"] = "f" * 64
        wrong_baseline["live_target"]["sha256"] = "f" * 64
        invalid_receipts.append(("wrong baseline", wrong_baseline, "rolled-back execd baseline differs"))
        wrong_absence = copy.deepcopy(terminal)
        wrong_absence["install_receipt"]["prior"] = {
            "state": "absent", "binary": None, "preimage": None,
        }
        wrong_absence["live_target"] = {"state": "absent"}
        invalid_receipts.append(("wrong absence", wrong_absence, "absent execd baseline differs"))
        wrong_identity = copy.deepcopy(terminal)
        wrong_identity["live_target"]["inode"] += 1
        invalid_receipts.append(("wrong identity", wrong_identity, "rolled-back execd baseline differs"))
        for label, invalid, message in invalid_receipts:
            with self.subTest(receipt=label):
                write_file(terminal_path, activation_package.canonical_json(invalid), 0o600)
                rejected = retry_from_installed_controller()
                self.assertEqual(rejected.returncode, 1)
                self.assertIn(message, json.loads(rejected.stderr)["error"])
                self.assertTrue(fixed_package.exists())
        write_file(terminal_path, terminal_raw, 0o600)

        write_file(execd_target, b"rolled-back baseline drift\n", 0o755)
        drifted = retry_from_installed_controller()
        self.assertEqual(drifted.returncode, 1)
        self.assertIn("rolled-back execd baseline differs", json.loads(drifted.stderr)["error"])
        self.assertTrue(fixed_package.exists())
        write_file(execd_target, prior_binary, 0o755)
        resumed = retry_from_installed_controller()
        self.assertEqual(resumed.returncode, 0, resumed.stderr.decode())
        rolled_back = json.loads(resumed.stdout)
        self.assertEqual(
            (rolled_back["units"]["buzz-ci-execd.socket"]["ActiveState"], rolled_back["units"]["buzz-ci-execd.socket"]["UnitFileState"]),
            ("active", "enabled"),
        )
        self.assertEqual(driver.socket(manifest["socket_policy"]["execd"])["path"], "/run/buzzci/execd.sock")
        self.assertFalse(fixed_package.exists())
        self.assertTrue(installed_cli.exists())

    def test_rollback_accepts_real_execd_absent_baseline_receipt(self) -> None:
        execd_package, seccomp_contract = execd_package_for_activation(self.fixture)
        execd_target = self.fixture.root / CONTROLLER.EXECD_BINARY_PATH.lstrip("/")
        execd_target.unlink()
        installed = execd_install(execd_package, self.fixture.root, seccomp_contract)
        self.assertEqual(installed["status"], "installed")
        install_receipt_path = (
            self.fixture.root / CONTROLLER.EXECD_PACKAGE_RECEIPT_PATH.lstrip("/")
        )
        self.assertEqual(json.loads(install_receipt_path.read_bytes())["prior"]["state"], "absent")
        self.enable_execd_baseline()
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        scenario, acceptance = self.finalized_canary_evidence(manifest, payloads, driver)
        with mock.patch.object(CONTROLLER.subprocess, "run", side_effect=self.verifier_pass):
            CONTROLLER.persist_capacity_one(
                manifest, payloads, self.fixture.root, driver, scenario, acceptance,
            )
        fixed_package = self.fixture.root / CONTROLLER.FIXED_PACKAGE_PATH.lstrip("/")
        installed_cli = self.fixture.root / "usr/libexec/buzz-ci-activation-controller"
        first = subprocess.run(
            [
                sys.executable, str(installed_cli), "rollback", "--package", str(fixed_package),
                "--root", str(self.fixture.root), "--fake-systemd-state", str(self.fixture.fake_state),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        self.assertEqual(first.returncode, 1)
        self.assertIn("execd package rollback is required", json.loads(first.stderr)["error"])
        completed = execd_rollback(execd_package, self.fixture.root, seccomp_contract)
        self.assertEqual((completed["state"], completed["prior_state"]), ("rolled_back", "absent"))
        terminal = json.loads(
            (self.fixture.root / CONTROLLER.EXECD_PACKAGE_ROLLBACK_PATH.lstrip("/")).read_bytes()
        )
        self.assertEqual(terminal["live_target"], {"state": "absent"})
        self.assertFalse(execd_target.exists())
        resumed = subprocess.run(
            [
                sys.executable, str(installed_cli), "rollback", "--package", str(fixed_package),
                "--root", str(self.fixture.root), "--fake-systemd-state", str(self.fixture.fake_state),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        self.assertEqual(resumed.returncode, 0, resumed.stderr.decode())
        self.assertEqual(json.loads(resumed.stdout)["state"], "rolled_back")
        self.assertFalse(fixed_package.exists())

    def test_terminal_package_cleanup_resumes_after_every_unlink_and_rmdir(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        fixed_package = self.fixture.root / CONTROLLER.FIXED_PACKAGE_PATH.lstrip("/")
        installed_cli = self.fixture.root / "usr/libexec/buzz-ci-activation-controller"
        mutation_count = len(list((fixed_package / "assets").iterdir())) + 3
        with mock.patch.object(
            CONTROLLER, "_remove_fixed_package_resumable",
            side_effect=OSError("injected cleanup pause"),
        ), self.assertRaisesRegex(OSError, "injected cleanup pause"):
            CONTROLLER.rollback(manifest, self.fixture.root, driver)
        self.assertEqual(CONTROLLER._read_receipt(self.fixture.root)["state"], "rollback_cleanup")
        self.assertTrue(installed_cli.exists())

        original_unlink = CONTROLLER.os.unlink
        original_rmdir = CONTROLLER.os.rmdir
        mutations: list[str] = []
        for _index in range(mutation_count):
            fired = False

            def unlink_then_interrupt(*args, **kwargs) -> None:
                nonlocal fired
                original_unlink(*args, **kwargs)
                fired = True
                mutations.append("unlink")
                raise OSError("injected unlink acknowledgement loss")

            def rmdir_then_interrupt(*args, **kwargs) -> None:
                nonlocal fired
                original_rmdir(*args, **kwargs)
                fired = True
                mutations.append("rmdir")
                raise OSError("injected rmdir acknowledgement loss")

            with mock.patch.object(CONTROLLER.os, "unlink", side_effect=unlink_then_interrupt), mock.patch.object(
                CONTROLLER.os, "rmdir", side_effect=rmdir_then_interrupt,
            ), self.assertRaisesRegex(OSError, "acknowledgement loss"):
                CONTROLLER.rollback(manifest, self.fixture.root, driver)
            self.assertTrue(fired)
            self.assertEqual(CONTROLLER._read_receipt(self.fixture.root)["state"], "rollback_cleanup")
            self.assertTrue(installed_cli.exists())
            self.assertIsNotNone(CONTROLLER._read_rollback_cleanup(self.fixture.root))
            reloaded, reloaded_payloads = CONTROLLER._load_rollback_package_for_cli(
                fixed_package, self.fixture.root, live=False,
            )
            self.assertEqual((reloaded, reloaded_payloads), (manifest, {}))

        self.assertEqual((mutations.count("unlink"), mutations.count("rmdir")), (mutation_count - 2, 2))
        self.assertFalse(fixed_package.exists())
        completed = CONTROLLER.rollback(manifest, self.fixture.root, driver)
        self.assertEqual((completed["status"], completed["state"]), ("rolled_back", "rolled_back"))
        unchanged = CONTROLLER.rollback(manifest, self.fixture.root, driver)
        self.assertEqual((unchanged["status"], unchanged["state"]), ("unchanged", "rolled_back"))

    def test_final_receipt_failure_resumes_from_installed_cli_and_exact_retry_is_unchanged(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        fixed_package = self.fixture.root / CONTROLLER.FIXED_PACKAGE_PATH.lstrip("/")
        installed_cli = self.fixture.root / "usr/libexec/buzz-ci-activation-controller"
        original_write_receipt = CONTROLLER._write_receipt

        def fail_terminal_receipt(root: Path, receipt: dict[str, object], controld_gid: int) -> None:
            if receipt["state"] == "rolled_back":
                raise OSError("injected terminal receipt failure")
            original_write_receipt(root, receipt, controld_gid)

        with mock.patch.object(
            CONTROLLER, "_write_receipt", side_effect=fail_terminal_receipt,
        ), self.assertRaisesRegex(OSError, "injected terminal receipt failure"):
            CONTROLLER.rollback(manifest, self.fixture.root, driver)
        self.assertFalse(fixed_package.exists())
        self.assertTrue(installed_cli.exists())
        self.assertEqual(CONTROLLER._read_receipt(self.fixture.root)["state"], "rollback_cleanup")

        def retry_cli() -> subprocess.CompletedProcess[bytes]:
            return subprocess.run(
                [
                    sys.executable, str(installed_cli), "rollback", "--package", str(fixed_package),
                    "--root", str(self.fixture.root), "--fake-systemd-state", str(self.fixture.fake_state),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            )

        resumed = retry_cli()
        self.assertEqual(resumed.returncode, 0, resumed.stderr.decode())
        self.assertEqual(json.loads(resumed.stdout)["status"], "rolled_back")
        lost_ack_retry = retry_cli()
        self.assertEqual(lost_ack_retry.returncode, 0, lost_ack_retry.stderr.decode())
        self.assertEqual(json.loads(lost_ack_retry.stdout)["status"], "unchanged")

    def test_lost_terminal_receipt_acknowledgement_retries_unchanged(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        fixed_package = self.fixture.root / CONTROLLER.FIXED_PACKAGE_PATH.lstrip("/")
        installed_cli = self.fixture.root / "usr/libexec/buzz-ci-activation-controller"
        original_write_receipt = CONTROLLER._write_receipt

        def write_terminal_then_lose_ack(root: Path, receipt: dict[str, object], controld_gid: int) -> None:
            original_write_receipt(root, receipt, controld_gid)
            if receipt["state"] == "rolled_back":
                raise OSError("injected terminal acknowledgement loss")

        with mock.patch.object(
            CONTROLLER, "_write_receipt", side_effect=write_terminal_then_lose_ack,
        ), self.assertRaisesRegex(OSError, "injected terminal acknowledgement loss"):
            CONTROLLER.rollback(manifest, self.fixture.root, driver)
        self.assertFalse(fixed_package.exists())
        self.assertTrue(installed_cli.exists())
        self.assertEqual(CONTROLLER._read_receipt(self.fixture.root)["state"], "rolled_back")
        retried = subprocess.run(
            [
                sys.executable, str(installed_cli), "rollback", "--package", str(fixed_package),
                "--root", str(self.fixture.root), "--fake-systemd-state", str(self.fixture.fake_state),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        self.assertEqual(retried.returncode, 0, retried.stderr.decode())
        self.assertEqual(json.loads(retried.stdout)["status"], "unchanged")

    def test_rollback_rejects_fixed_package_missing_before_first_cleanup_marker(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        CONTROLLER._remove_package_tree(
            self.fixture.root, CONTROLLER.FIXED_PACKAGE_PATH,
            expected_sources=set(CONTROLLER._package_references(manifest)),
        )
        with self.assertRaises(FileNotFoundError):
            CONTROLLER.rollback(manifest, self.fixture.root, driver)
        self.assertEqual(CONTROLLER._read_receipt(self.fixture.root)["state"], "rollback_failed")
        self.assertIsNone(CONTROLLER._read_rollback_cleanup(self.fixture.root))

    def test_rollback_and_terminal_retry_reject_broken_fixed_package_symlink(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        CONTROLLER._remove_package_tree(
            self.fixture.root, CONTROLLER.FIXED_PACKAGE_PATH,
            expected_sources=set(CONTROLLER._package_references(manifest)),
        )
        fixed_package = self.fixture.root / CONTROLLER.FIXED_PACKAGE_PATH.lstrip("/")
        fixed_package.symlink_to("missing-package", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "root must be real|not a directory"):
            CONTROLLER.rollback(manifest, self.fixture.root, driver)
        self.assertIsNone(CONTROLLER._read_rollback_cleanup(self.fixture.root))
        fixed_package.unlink()

        CONTROLLER._install_fixed_package(manifest, payloads, self.fixture.root)
        self.assertEqual(CONTROLLER.rollback(manifest, self.fixture.root, driver)["state"], "rolled_back")
        fixed_package.symlink_to("missing-package", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "not a directory"):
            CONTROLLER.rollback(manifest, self.fixture.root, driver)

    def test_two_activation_rollback_cycles_archive_and_replace_current_marker(self) -> None:
        first_manifest, first_payloads, driver = self.fixture.load()
        CONTROLLER.stage(first_manifest, first_payloads, self.fixture.root, driver, self.fixture.binding)
        CONTROLLER.rollback(first_manifest, self.fixture.root, driver)
        first_marker = CONTROLLER._read_rollback_cleanup(self.fixture.root)
        self.assertIsNotNone(first_marker)

        self.fixture.acceptance_template["actor"]["generation"] += 1
        self.fixture.manifest = self.fixture._manifest()
        self.fixture.scenario = self.fixture._scenario()
        self.fixture.binding = CONTROLLER._acceptance_binding(self.fixture.manifest, self.fixture.scenario)
        write_file(
            self.fixture.package / "activation-manifest.json",
            activation_package.canonical_json(self.fixture.manifest), 0o600,
        )
        second_manifest, second_payloads, driver = self.fixture.load()
        self.assertNotEqual(second_manifest["activation_id"], first_manifest["activation_id"])
        CONTROLLER.stage(second_manifest, second_payloads, self.fixture.root, driver, self.fixture.binding)
        self.assertIsNone(CONTROLLER._read_rollback_cleanup(self.fixture.root))
        self.assertIsNone(CONTROLLER._read_rollback_retirement(self.fixture.root))
        archives = list((self.fixture.root / CONTROLLER.ROLLBACK_ARCHIVE_ROOT.lstrip("/")).iterdir())
        self.assertEqual(len(archives), 1)
        self.assertEqual(json.loads(archives[0].read_bytes())["marker"], first_marker)

        CONTROLLER.rollback(second_manifest, self.fixture.root, driver)
        second_marker = CONTROLLER._read_rollback_cleanup(self.fixture.root)
        self.assertEqual(second_marker["activation_id"], second_manifest["activation_id"])
        self.assertEqual(CONTROLLER.rollback(second_manifest, self.fixture.root, driver)["status"], "unchanged")

    def test_retirement_archive_write_lost_ack_tamper_and_exact_retry(self) -> None:
        first_manifest, first_payloads, driver = self.fixture.load()
        CONTROLLER.stage(first_manifest, first_payloads, self.fixture.root, driver, self.fixture.binding)
        CONTROLLER.rollback(first_manifest, self.fixture.root, driver)
        self.fixture.acceptance_template["actor"]["generation"] += 1
        self.fixture.manifest = self.fixture._manifest()
        self.fixture.scenario = self.fixture._scenario()
        self.fixture.binding = CONTROLLER._acceptance_binding(self.fixture.manifest, self.fixture.scenario)
        write_file(
            self.fixture.package / "activation-manifest.json",
            activation_package.canonical_json(self.fixture.manifest), 0o600,
        )
        manifest, payloads, driver = self.fixture.load()
        original_write = CONTROLLER._atomic_write

        def write_archive_then_lose_ack(root: Path, target: str, *arguments) -> None:
            original_write(root, target, *arguments)
            if target.startswith(CONTROLLER.ROLLBACK_ARCHIVE_ROOT + "/"):
                raise OSError("injected archive acknowledgement loss")

        with mock.patch.object(CONTROLLER, "_atomic_write", side_effect=write_archive_then_lose_ack), self.assertRaisesRegex(
            OSError, "archive acknowledgement loss",
        ):
            CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        retirement = CONTROLLER._read_rollback_retirement(self.fixture.root)
        archive_path = self.fixture.root / retirement["archive_path"].lstrip("/")
        archive = json.loads(archive_path.read_bytes())
        archive["retired_by_source_commit"] = "f" * 40
        write_file(archive_path, activation_package.canonical_json(archive), 0o600)
        with self.assertRaisesRegex(ValueError, "archive binding differs"):
            CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        write_file(
            archive_path,
            activation_package.canonical_json(CONTROLLER._rollback_archive_value(retirement)),
            0o600,
        )
        resumed = CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        self.assertEqual(resumed["status"], "unchanged")
        exact_retry = CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        self.assertEqual(exact_retry["status"], "unchanged")

    def test_retirement_unlink_interruptions_resume_deterministically(self) -> None:
        first_manifest, first_payloads, driver = self.fixture.load()
        CONTROLLER.stage(first_manifest, first_payloads, self.fixture.root, driver, self.fixture.binding)
        CONTROLLER.rollback(first_manifest, self.fixture.root, driver)
        self.fixture.acceptance_template["actor"]["generation"] += 1
        self.fixture.manifest = self.fixture._manifest()
        self.fixture.scenario = self.fixture._scenario()
        self.fixture.binding = CONTROLLER._acceptance_binding(self.fixture.manifest, self.fixture.scenario)
        write_file(
            self.fixture.package / "activation-manifest.json",
            activation_package.canonical_json(self.fixture.manifest), 0o600,
        )
        manifest, payloads, driver = self.fixture.load()
        original_write = CONTROLLER._atomic_write

        def write_retirement_then_lose_ack(root: Path, target: str, *arguments) -> None:
            original_write(root, target, *arguments)
            if target == CONTROLLER.ROLLBACK_RETIREMENT_PATH:
                raise OSError("injected retirement marker acknowledgement loss")

        with mock.patch.object(
            CONTROLLER, "_atomic_write", side_effect=write_retirement_then_lose_ack,
        ), self.assertRaisesRegex(OSError, "retirement marker acknowledgement loss"):
            CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        self.assertEqual(CONTROLLER._read_receipt(self.fixture.root)["state"], "rolled_back")
        self.assertIsNotNone(CONTROLLER._read_rollback_retirement(self.fixture.root))
        original_unlink = CONTROLLER._unlink_target
        interrupted: set[str] = set()

        def unlink_then_lose_ack(root: Path, target: str) -> None:
            original_unlink(root, target)
            if target not in interrupted:
                interrupted.add(target)
                raise OSError(f"injected retirement unlink acknowledgement loss: {target}")

        with mock.patch.object(CONTROLLER, "_unlink_target", side_effect=unlink_then_lose_ack), self.assertRaisesRegex(
            OSError, "rollback-cleanup-v1",
        ):
            CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        with mock.patch.object(CONTROLLER, "_unlink_target", side_effect=unlink_then_lose_ack), self.assertRaisesRegex(
            OSError, "rollback-retirement-v1",
        ):
            CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        resumed = CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        self.assertEqual(resumed["status"], "unchanged")
        self.assertEqual(interrupted, {CONTROLLER.ROLLBACK_CLEANUP_PATH, CONTROLLER.ROLLBACK_RETIREMENT_PATH})
        self.assertIsNone(CONTROLLER._read_rollback_cleanup(self.fixture.root))
        self.assertIsNone(CONTROLLER._read_rollback_retirement(self.fixture.root))

    def test_retirement_marker_tamper_fails_closed(self) -> None:
        first_manifest, first_payloads, driver = self.fixture.load()
        CONTROLLER.stage(first_manifest, first_payloads, self.fixture.root, driver, self.fixture.binding)
        CONTROLLER.rollback(first_manifest, self.fixture.root, driver)
        self.fixture.acceptance_template["actor"]["generation"] += 1
        self.fixture.manifest = self.fixture._manifest()
        self.fixture.scenario = self.fixture._scenario()
        self.fixture.binding = CONTROLLER._acceptance_binding(self.fixture.manifest, self.fixture.scenario)
        write_file(
            self.fixture.package / "activation-manifest.json",
            activation_package.canonical_json(self.fixture.manifest), 0o600,
        )
        manifest, payloads, driver = self.fixture.load()
        receipt = CONTROLLER._read_receipt(self.fixture.root)
        retirement = CONTROLLER._prepare_rollback_retirement(receipt, manifest, self.fixture.root)
        retirement["next_source_commit"] = "f" * 40
        write_file(
            self.fixture.root / CONTROLLER.ROLLBACK_RETIREMENT_PATH.lstrip("/"),
            activation_package.canonical_json(retirement), 0o600,
        )
        with self.assertRaisesRegex(ValueError, "different staged activation"):
            CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)

    def test_new_activation_replaces_and_rollback_restores_prior_controld_ledger(self) -> None:
        ledger = self.fixture.root / CONTROLLER.CONTROLD_ACCEPTANCE_LEDGER_PATH.lstrip("/")
        prior = b'{"prior":"activation"}\n'
        write_file(ledger, prior, 0o600)
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        self.assertFalse(ledger.exists())
        write_file(ledger, b'{"current":"activation"}\n', 0o600)
        rolled_back = CONTROLLER.rollback(manifest, self.fixture.root, driver)
        self.assertEqual((rolled_back["acceptance_ledger"], ledger.read_bytes()), ("restored", prior))

    def test_failed_qualification_returns_to_staged_capacity_zero(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        original = CONTROLLER._run_qualification
        CONTROLLER._run_qualification = lambda *_arguments: (_ for _ in ()).throw(ValueError("injected qualification failure"))
        try:
            with self.assertRaisesRegex(ValueError, "injected qualification failure"):
                CONTROLLER.activate(manifest, payloads, self.fixture.root, driver)
        finally:
            CONTROLLER._run_qualification = original
        receipt = CONTROLLER._read_receipt(self.fixture.root)
        self.assertEqual(receipt["state"], "staged_zero")
        self.assertEqual(
            CONTROLLER._staged_zero_readback(manifest, self.fixture.root, driver)["units"][activation_package.PERSISTENT_UNIT]["ActiveState"],
            "inactive",
        )
        CONTROLLER._verify_phase(manifest, self.fixture.root, "staged")

    def test_fake_systemd_starts_units_required_by_packaged_unit_files(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        explicit: list[str] = []
        original_start = driver.start

        def record_start(name: str) -> None:
            explicit.append(name)
            original_start(name)

        driver.start = record_start
        for unit in ("buzz-ci-execd.socket", "buzz-ci-executor.socket"):
            self.assertEqual(driver.unit(unit)["ActiveState"], "inactive")
        driver.start("buzz-ci-execd.service")
        self.assertEqual(explicit, ["buzz-ci-execd.service"])
        for unit in ("buzz-ci-execd.service", "buzz-ci-execd.socket", "buzz-ci-executor.socket"):
            self.assertEqual(driver.unit(unit)["ActiveState"], "active", unit)
        self.assertEqual(driver.unit("buzz-ci-executor.service")["ActiveState"], "inactive")
        self.assertEqual(
            driver.socket(manifest["socket_policy"]["executor"]),
            {"path": "/run/buzzci/executor.sock", "mode": "0600", "uid": 0, "gid": 0},
        )
        self.assertEqual(
            driver._pulled_in("buzz-ci-execd.service"),
            ["buzz-ci-execd.socket", "buzz-ci-executor.socket"],
        )
        self.assertEqual(driver._pulled_in("buzz-ci-executor.socket"), [])

    def test_stopping_only_the_execd_units_after_qualification_leaves_the_required_executor_socket_active(self) -> None:
        # The stop sequence the controller used before this fix, replayed against the
        # fake that models Requires=, reproduces the recorded clean-host failure.
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        driver.start("buzz-ci-execd.socket")
        driver.start("buzz-ci-execd.service")
        driver.stop("buzz-ci-execd.service")
        driver.stop("buzz-ci-execd.socket")
        with self.assertRaisesRegex(
            ValueError,
            r"^staged-zero readback found unit buzz-ci-executor\.socket active, expected inactive$",
        ):
            CONTROLLER._staged_zero_readback(manifest, self.fixture.root, driver)
        CONTROLLER._stop_qualification_units(driver)
        CONTROLLER._staged_zero_readback(manifest, self.fixture.root, driver)

    def test_activate_stops_every_unit_the_closed_qualification_started(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        stops: list[str] = []
        original_stop = driver.stop

        def record_stop(name: str) -> None:
            stops.append(name)
            original_stop(name)

        driver.stop = record_stop
        qualified = CONTROLLER.activate(manifest, payloads, self.fixture.root, driver)
        driver.stop = original_stop
        self.assertEqual((qualified["state"], qualified["capacity"]), ("qualified_closed", 0))
        expected = [
            unit for unit in activation_package.STOP_ORDER
            if unit not in activation_package.STAGED_ZERO_UNITS
        ]
        self.assertEqual(stops, expected)
        self.assertIn("buzz-ci-executor.socket", stops)
        for unit in expected:
            if unit.endswith(".service"):
                socket = unit[: -len(".service")] + ".socket"
                self.assertLess(stops.index(unit), stops.index(socket), unit)
        readback = qualified["staged_zero"]["units"]
        for unit in expected:
            self.assertEqual(readback[unit]["ActiveState"], "inactive", unit)
        for unit in activation_package.STAGED_ZERO_UNITS:
            self.assertEqual(readback[unit]["ActiveState"], "active", unit)
        self.assertEqual(CONTROLLER._read_receipt(self.fixture.root)["state"], "qualified_closed")

    def test_rollback_refuses_drift_before_systemd_mutation(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        CONTROLLER.activate(manifest, payloads, self.fixture.root, driver)
        target = self.fixture.root / activation_package.CONFIG_TARGETS["controld_config"].lstrip("/")
        target.write_bytes(b'{"drift":true}\n')
        target.chmod(0o600)
        before = self.fixture.fake_state.read_bytes()
        with self.assertRaisesRegex(ValueError, "drift blocks rollback"):
            CONTROLLER.rollback(manifest, self.fixture.root, driver)
        self.assertEqual(self.fixture.fake_state.read_bytes(), before)

    def test_linked_package_asset_is_rejected(self) -> None:
        source = self.fixture.package / "assets/runner-staged.json"
        target = self.fixture.temporary / "runner-staged-target.json"
        source.rename(target)
        source.symlink_to(target)
        with self.assertRaises((OSError, ValueError)):
            CONTROLLER.load_package(self.fixture.package, live=False)

    def test_numeric_principal_collision_blocks_staging(self) -> None:
        manifest, _payloads, driver = self.fixture.load()
        state = json.loads(self.fixture.fake_state.read_bytes())
        state["identities"]["occupied-runner-id"] = {
            "user": "occupied-runner-id",
            "group": "occupied-runner-id",
            "uid": 62001,
            "gid": 62001,
            "primary_gid": 62001,
            "home": "/nonexistent",
            "shell": "/usr/sbin/nologin",
        }
        write_file(self.fixture.fake_state, activation_package.canonical_json(state), 0o600)
        with self.assertRaisesRegex(ValueError, "numeric principal is already occupied"):
            CONTROLLER.preflight(manifest, self.fixture.root, driver, require_dormant=True)

    def test_installed_buzzci_ctl_identity_converges_access_group_membership(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        state = json.loads(self.fixture.fake_state.read_bytes())
        planned = manifest["identities"]["qualification"]
        state["identities"]["buzzci-ctl"] = {
            "user": "buzzci-ctl",
            "group": "buzzci-ctl",
            "uid": 961,
            "gid": 961,
            "primary_gid": 961,
            "home": "/var/lib/buzzci/principals/ctl",
            "shell": "/usr/sbin/nologin",
            "supplementary_groups": [],
        }
        write_file(self.fixture.fake_state, activation_package.canonical_json(state), 0o600)
        report = CONTROLLER.preflight(
            manifest, self.fixture.root, driver, require_dormant=True, payloads=payloads,
        )
        self.assertEqual(report["principals"]["qualification"]["status"], "convergent_legacy")
        staged = CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        expected = {
            "user": planned["user"], "group": planned["group"], "uid": planned["uid"],
            "gid": planned["gid"], "primary_gid": planned["gid"], "home": planned["home"],
            "shell": planned["shell"], "supplementary_groups": planned["supplementary_groups"],
        }
        self.assertEqual(staged["principals"]["qualification"], {"status": "exact", **expected})

    def test_cli_check_uses_only_the_explicit_fake_driver(self) -> None:
        completed = subprocess.run(
            [
                str(ACTIVATION_ROOT / "controller.py"),
                "check",
                "--package",
                str(self.fixture.package),
                "--root",
                str(self.fixture.root),
                "--fake-systemd-state",
                str(self.fixture.fake_state),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        self.assertEqual(json.loads(completed.stdout)["status"], "ready_to_stage")

    def test_keyholder_config_is_external_and_controld_has_only_the_shared_receipt_path(self) -> None:
        manifest, payloads, _driver = self.fixture.load()
        entries = {entry["role"]: entry for entry in manifest["entries"]}
        controld = json.loads(payloads[entries["controld_config"]["active_source"]])
        self.assertNotIn("keyholder_config", entries)
        self.assertFalse(any(entry["target"] == activation_package.KEYHOLDER_CONFIG_PATH for entry in manifest["entries"]))
        self.assertEqual((controld["keyholder_uid"], controld["keyholder_gid"]), (62003, 62003))
        self.assertEqual(controld["acceptance_binding"], activation_package.ACCEPTANCE_BINDING_PATH)
        self.assertNotIn("acceptance", controld)
        self.assertNotIn("private", activation_package.canonical_json(controld).decode())

    def test_external_keyholder_config_is_read_back_and_never_overwritten(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        target = self.fixture.root / activation_package.KEYHOLDER_CONFIG_PATH.lstrip("/")
        before = target.read_bytes()
        report = CONTROLLER.preflight(manifest, self.fixture.root, driver, require_dormant=True, payloads=payloads)
        self.assertEqual(report["keyholder_config"]["status"], "exact")
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        CONTROLLER.activate(manifest, payloads, self.fixture.root, driver)
        CONTROLLER.rollback(manifest, self.fixture.root, driver)
        self.assertEqual((target.read_bytes(), stat.S_IMODE(target.stat().st_mode)), (before, 0o600))

    def test_external_keyholder_config_drift_blocks_activation(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        target = self.fixture.root / activation_package.KEYHOLDER_CONFIG_PATH.lstrip("/")
        original = target.read_bytes()
        value = json.loads(original)
        value["selectors"]["ci_event"]["generation"] += 1
        write_file(target, activation_package.canonical_json(value), 0o600)
        with self.assertRaisesRegex(ValueError, "selectors differ from active controld"):
            CONTROLLER.preflight(manifest, self.fixture.root, driver, require_dormant=True, payloads=payloads)
        write_file(target, activation_package.canonical_json(value), 0o640)
        with self.assertRaisesRegex(ValueError, "metadata differs"):
            CONTROLLER.preflight(manifest, self.fixture.root, driver, require_dormant=True, payloads=payloads)
        value = json.loads(original)
        value["peer"] = {
            "uid": manifest["identities"]["qualification"]["uid"],
            "gid": manifest["identities"]["qualification"]["gid"],
            "allowed_operations": value["peer"]["allowed_operations"],
        }
        write_file(target, activation_package.canonical_json(value), 0o600)
        with self.assertRaisesRegex(ValueError, "peer contract differs"):
            CONTROLLER.preflight(
                manifest, self.fixture.root, driver, require_dormant=True, payloads=payloads,
            )

    def test_public_acceptance_template_omits_scenario_and_binds_event_ids(self) -> None:
        manifest, _payloads, _driver = self.fixture.load()
        template = manifest["acceptance_template"]
        self.assertNotIn("scenario_sha256", template)
        for field in (
            "run_event", "grant_event", "rerun_event", "tombstone_event", "failure_run_event",
        ):
            event_id = activation_package.digest(json.dumps(
                template[field], ensure_ascii=False, separators=(",", ":"),
            ).encode())
            self.assertRegex(event_id, r"^[0-9a-f]{64}$")
        self.assertEqual(
            self.fixture.scenario["fixture"]["grant_event_id"],
            activation_package.digest(json.dumps(
                template["grant_event"], ensure_ascii=False, separators=(",", ":"),
            ).encode()),
        )

    def test_frozen_grant_event_flows_through_checked_render_and_controller(self) -> None:
        manifest, payloads, _driver = self.fixture.load()
        source = json.loads(
            (REPO_ROOT / "deploy/native-ci/acceptance/scenario.template.json").read_bytes(),
        )
        checked = TEMPLATE_GENERATOR.checked_scenario_template(source)
        grant_event_id = RENDERER.activation_grant_event_id(manifest)
        request_digest = RENDERER.activation_request_digest(manifest)
        failure_request_digest = RENDERER.activation_failure_request_digest(manifest)
        approved_by = RENDERER.activation_approved_by(manifest)
        bindings = {
            "candidate_sha": manifest["source_commit"],
            "packages": {"activation": manifest},
            "activation_grant_event_id": grant_event_id,
            "activation_request_digest": request_digest,
            "activation_failure_request_digest": failure_request_digest,
            "activation_run_id": RENDERER.activation_run_id(manifest),
            "activation_failure_run_id": RENDERER.activation_failure_run_id(manifest),
            "activation_failure_selector": RENDERER.activation_failure_selector(manifest),
            "activation_approved_by": approved_by,
            "activation_export_subject": RENDERER.activation_export_subject(manifest),
            "activation_export_generation": RENDERER.activation_export_generation(manifest),
            "activation_export_authorization_digest": RENDERER.activation_export_authorization_digest(manifest),
            "activation_fixture_manifest_sha256": RENDERER.activation_fixture_manifest_sha256(
                manifest,
            ),
        }
        rendered = RENDERER.resolve_template(
            checked, "capacity-one-scenario", bindings,
        )
        rendered = RENDERER.validate_scenario(rendered, bindings)
        self.assertEqual(rendered["fixture"]["grant_event_id"], grant_event_id)
        self.assertEqual(rendered["fixture"]["request_digest"], request_digest)
        self.assertEqual(
            rendered["fixture"]["failure_request_digest"], failure_request_digest,
        )
        self.assertEqual(
            rendered["fixture"]["failure_run_id"],
            RENDERER.activation_failure_run_id(manifest),
        )
        self.assertEqual(rendered["fixture"]["approved_by"], approved_by)
        self.assertEqual(
            rendered["fixture"]["manifest_digest"],
            activation_package.FIXTURE_MANIFEST_SHA256,
        )

        scenario_path = self.fixture.temporary / "renderer-scenario.json"
        write_file(scenario_path, RENDERER.canonical_scenario(rendered), 0o400)
        controller_binding = CONTROLLER.load_acceptance_scenario(
            scenario_path, manifest, live=False,
        )
        self.assertEqual(
            controller_binding["fixture"]["grant_event_id"], grant_event_id,
        )
        generated = CONTROLLER._generated_acceptance_files(
            manifest, payloads, controller_binding,
        )
        execd_config = json.loads(next(
            item["payload"] for item in generated if item["role"] == "execd_config"
        ))
        self.assertEqual(
            controller_binding["fixture"]["manifest_digest"],
            execd_config["execution"]["fixture_manifest_sha256"],
        )
        self.assertEqual(
            execd_config["lane_manifest_digest"],
            activation_package.lane_manifest_digest(execd_config["lane_manifest"]),
        )
        self.assertNotEqual(
            execd_config["lane_manifest_digest"],
            controller_binding["fixture"]["manifest_digest"],
        )

        stale = copy.deepcopy(rendered)
        stale["fixture"]["grant_event_id"] = "8" * 64
        with self.assertRaisesRegex(RENDERER.RenderError, "cross-binding differs"):
            RENDERER.validate_scenario(stale, bindings)
        stale_request = copy.deepcopy(rendered)
        stale_request["fixture"]["request_digest"] = "8" * 64
        with self.assertRaisesRegex(RENDERER.RenderError, "cross-binding differs"):
            RENDERER.validate_scenario(stale_request, bindings)
        stale_failure_request = copy.deepcopy(rendered)
        stale_failure_request["fixture"]["failure_request_digest"] = "8" * 64
        with self.assertRaisesRegex(RENDERER.RenderError, "cross-binding differs"):
            RENDERER.validate_scenario(stale_failure_request, bindings)
        stale_approver = copy.deepcopy(rendered)
        stale_approver["fixture"]["approved_by"] = "8" * 64
        with self.assertRaisesRegex(RENDERER.RenderError, "cross-binding differs"):
            RENDERER.validate_scenario(stale_approver, bindings)
        stale_path = self.fixture.temporary / "stale-renderer-scenario.json"
        write_file(stale_path, RENDERER.canonical_scenario(stale), 0o400)
        with self.assertRaisesRegex(
            ValueError, "grant event id differs from the frozen public template",
        ):
            CONTROLLER.load_acceptance_scenario(stale_path, manifest, live=False)

        wrong_fixture = copy.deepcopy(rendered)
        wrong_fixture["fixture"]["manifest_digest"] = self.fixture.lane_manifest_digest
        with self.assertRaisesRegex(RENDERER.RenderError, "cross-binding differs"):
            RENDERER.validate_scenario(wrong_fixture, bindings)
        wrong_fixture_path = self.fixture.temporary / "wrong-fixture-renderer-scenario.json"
        write_file(
            wrong_fixture_path, RENDERER.canonical_scenario(wrong_fixture), 0o400,
        )
        with self.assertRaisesRegex(
            ValueError, "fixture manifest digest differs from the activation package",
        ):
            CONTROLLER.load_acceptance_scenario(
                wrong_fixture_path, manifest, live=False,
            )

        changed_manifest = copy.deepcopy(manifest)
        changed_manifest["acceptance_template"]["grant_event"][5] = "{\"type\":\"different-grant\"}"
        changed_bindings = {**bindings, "packages": {"activation": changed_manifest}}
        with self.assertRaisesRegex(RENDERER.RenderError, "renderer binding differs"):
            RENDERER.validate_scenario(rendered, changed_bindings)

        extra = copy.deepcopy(rendered)
        extra["fixture"]["caller_grant_event_id"] = grant_event_id
        with self.assertRaisesRegex(RENDERER.RenderError, "shape differs"):
            RENDERER.validate_scenario(extra, bindings)

    def test_stage_executes_all_installed_tmpfiles_declarations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "usr/lib/tmpfiles.d").mkdir(parents=True)
            manifest, payloads, _fake = self.fixture.load()
            plan = activation_package.tmpfiles_plan(manifest, payloads)
            source_payloads = {
                activation_package.STATIC_TARGETS["tmpfiles"]: (ACTIVATION_ROOT / "templates/buzzci-activation.tmpfiles").read_bytes(),
                activation_package.STATIC_TARGETS["acceptance_tmpfiles"]: (ACTIVATION_ROOT / "templates/buzzci-acceptance.tmpfiles").read_bytes(),
                activation_package.COMPONENT_TMPFILES_TARGETS["runner"]: (REPO_ROOT / "deploy/native-ci/runner/templates/buzzci-runner.tmpfiles").read_bytes(),
                activation_package.COMPONENT_TMPFILES_TARGETS["controld"]: (REPO_ROOT / "deploy/native-ci/controld/templates/buzzci-controld.tmpfiles").read_bytes(),
            }
            self.assertEqual({item["target"] for item in plan}, set(source_payloads))
            for item in plan:
                payload = source_payloads[item["target"]]
                self.assertEqual(activation_package.digest(payload), item["sha256"])
                write_file(root / str(item["target"]).lstrip("/"), payload, 0o644)

            calls: list[tuple[str, list[str], bool]] = []
            driver = object.__new__(CONTROLLER.LiveSystemd)
            driver.root = root
            directories = {
                "run/buzzci": 0o711,
                "var/lib/buzzci": 0o711,
                "var/lib/buzzci/activation-controller": 0o711,
                "var/lib/buzzci/acceptance-control": 0o700,
                "var/lib/buzzci/seccomp": 0o711,
                "var/lib/buzzci/seccomp/v1": 0o711,
                "var/lib/buzzci/seccomp/v1/sha256": 0o711,
                "var/lib/buzzci/activation": 0o700,
                "var/lib/buzzci/activation/receipts": 0o700,
                "var/lib/buzzci/execd-v2": 0o711,
                "var/lib/buzzci/execd-v2/intents": 0o700,
                "var/lib/buzzci/execd-v2/bindings": 0o700,
                "var/lib/buzzci/execd-v2/evidence": 0o700,
                "var/lib/buzzci/execd-v2/teardown": 0o700,
                "var/lib/buzzci/execd-v2/attempts": 0o711,
                "var/lib/buzzci/execd-v2/qualification": 0o700,
                "var/lib/buzzci/controld": 0o700,
                "var/lib/buzzci/runner": 0o700,
            }

            def record(program: str, args: list[str], *, mutation: bool = False) -> subprocess.CompletedProcess[bytes]:
                calls.append((program, args, mutation))
                for target, mode in directories.items():
                    directory = root / target
                    directory.mkdir(parents=True, exist_ok=True)
                    directory.chmod(mode)
                return subprocess.CompletedProcess([program, *args], 0, b"", b"")

            driver._run = record
            driver.tmpfiles(self.fixture.identities, plan)
            driver.tmpfiles(self.fixture.identities, plan)
            expected_args = ["--create", *(item["target"] for item in plan)]
            self.assertEqual(calls, [
                (CONTROLLER.TMPFILES, expected_args, True),
                (CONTROLLER.TMPFILES, expected_args, True),
            ])

            declaration = root / str(plan[-1]["target"]).lstrip("/")
            original = declaration.read_bytes()
            declaration.write_bytes(b"d /tmp/hostile 0777 root root -\n")
            with self.assertRaisesRegex(ValueError, "content drift"):
                driver.tmpfiles(self.fixture.identities, plan)
            self.assertEqual(len(calls), 2)
            declaration.write_bytes(original)
            declaration.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "metadata drift"):
                driver.tmpfiles(self.fixture.identities, plan)
            self.assertEqual(len(calls), 2)
            declaration.chmod(0o644)
            declaration.unlink()
            with self.assertRaisesRegex(ValueError, "required target is absent"):
                driver.tmpfiles(self.fixture.identities, plan)
            self.assertEqual(len(calls), 2)
            declaration.mkdir()
            with self.assertRaisesRegex(ValueError, "metadata drift"):
                driver.tmpfiles(self.fixture.identities, plan)
            self.assertEqual(len(calls), 2)
            declaration.rmdir()
            write_file(declaration, original, 0o644)
            with mock.patch.object(
                CONTROLLER, "_physical_ids",
                return_value=(os.geteuid() + 1, os.getegid() + 1),
            ):
                with self.assertRaisesRegex(ValueError, "parent chain is unsafe"):
                    driver.tmpfiles(self.fixture.identities, plan)
            self.assertEqual(len(calls), 2)
            with (
                mock.patch.object(CONTROLLER, "_verify_tmpfiles_parent_chain"),
                mock.patch.object(
                    CONTROLLER, "_physical_ids",
                    return_value=(os.geteuid() + 1, os.getegid() + 1),
                ),
            ):
                with self.assertRaisesRegex(ValueError, "metadata drift"):
                    driver.tmpfiles(self.fixture.identities, plan)
            self.assertEqual(len(calls), 2)
            hardlink = declaration.with_name("hardlink.conf")
            os.link(declaration, hardlink)
            with self.assertRaisesRegex(ValueError, "metadata drift"):
                driver.tmpfiles(self.fixture.identities, plan)
            self.assertEqual(len(calls), 2)
            hardlink.unlink()
            declaration.unlink()
            declaration.symlink_to("missing.conf")
            with self.assertRaises(OSError):
                driver.tmpfiles(self.fixture.identities, plan)
            self.assertEqual(len(calls), 2)
            declaration.unlink()
            write_file(declaration, original, 0o644)
            tmpfiles_parent = declaration.parent
            tmpfiles_parent.chmod(0o777)
            with self.assertRaisesRegex(ValueError, "parent chain is unsafe"):
                driver.tmpfiles(self.fixture.identities, plan)
            self.assertEqual(len(calls), 2)
            tmpfiles_parent.chmod(0o755)
            real_parent = tmpfiles_parent.with_name("tmpfiles.real")
            tmpfiles_parent.rename(real_parent)
            tmpfiles_parent.symlink_to(real_parent.name)
            with self.assertRaises(OSError):
                driver.tmpfiles(self.fixture.identities, plan)
            self.assertEqual(len(calls), 2)
            tmpfiles_parent.unlink()
            real_parent.rename(tmpfiles_parent)
            (root / "var/lib/buzzci/runner").chmod(0o755)
            with self.assertRaisesRegex(ValueError, "directory differs"):
                driver.tmpfiles(self.fixture.identities, plan)
            self.assertEqual(len(calls), 2)
            (root / "var/lib/buzzci/runner").chmod(0o700)

            def wrong_post(program: str, args: list[str], *, mutation: bool = False) -> subprocess.CompletedProcess[bytes]:
                result = record(program, args, mutation=mutation)
                declaration.write_bytes(b"post-command swap\n")
                (root / "var/lib/buzzci/controld").chmod(0o755)
                return result

            driver._run = wrong_post
            with self.assertRaisesRegex(ValueError, "content drift"):
                driver.tmpfiles(self.fixture.identities, plan)
            self.assertEqual(len(calls), 3)
            declaration.write_bytes(original)
            (root / "var/lib/buzzci/controld").chmod(0o700)

            def wrong_directory_post(program: str, args: list[str], *, mutation: bool = False) -> subprocess.CompletedProcess[bytes]:
                result = record(program, args, mutation=mutation)
                (root / "var/lib/buzzci/controld").chmod(0o755)
                return result

            driver._run = wrong_directory_post
            with self.assertRaisesRegex(ValueError, "directory differs"):
                driver.tmpfiles(self.fixture.identities, plan)
            self.assertEqual(len(calls), 4)

    def test_live_systemd_constructor_drives_tmpfiles_pre_and_post_readback(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            "live systemd driver requires root /",
        ):
            CONTROLLER.LiveSystemd(Path("/tmp"))

        driver = CONTROLLER.LiveSystemd(Path("/"))
        self.assertEqual(driver.root, Path("/"))
        plan = ({
            "component": "runner",
            "target": "/usr/lib/tmpfiles.d/buzzci-runner.conf",
            "sha256": "1" * 64,
            "mode": "0644",
            "uid": 0,
            "gid": 0,
        },)
        calls: list[tuple[str, list[str], bool]] = []

        def record(
            program: str, arguments: list[str], *, mutation: bool = False,
        ) -> subprocess.CompletedProcess[bytes]:
            calls.append((program, arguments, mutation))
            return subprocess.CompletedProcess([program, *arguments], 0, b"", b"")

        driver._run = record
        with (
            mock.patch.object(CONTROLLER, "_tmpfiles_config_readback") as config_readback,
            mock.patch.object(
                CONTROLLER, "_tmpfiles_directory_readback",
                side_effect=({"pre": "exact"}, {"post": "exact"}),
            ) as directory_readback,
        ):
            driver.tmpfiles(self.fixture.identities, plan)
        self.assertEqual(
            config_readback.call_args_list,
            [mock.call(Path("/"), plan), mock.call(Path("/"), plan)],
        )
        self.assertEqual(
            directory_readback.call_args_list,
            [
                mock.call(Path("/"), self.fixture.identities, allow_absent=True),
                mock.call(Path("/"), self.fixture.identities, allow_absent=False),
            ],
        )
        self.assertEqual(calls, [(
            CONTROLLER.TMPFILES,
            ["--create", "/usr/lib/tmpfiles.d/buzzci-runner.conf"],
            True,
        )])

    def test_staged_zero_controld_does_not_activate_operational_sockets(self) -> None:
        drop_in = (ACTIVATION_ROOT / "templates/20-controld-capacity-one.conf").read_text()
        self.assertIn("Requires=buzz-ci-controld-acceptance.socket\n", drop_in)
        requires = next(line for line in drop_in.splitlines() if line.startswith("Requires="))
        self.assertNotIn("buzz-ci-keyholder.socket", requires)
        self.assertNotIn("buzz-ci-runner.socket", requires)
        read_only = next(line for line in drop_in.splitlines() if line.startswith("ReadOnlyPaths="))
        base = (REPO_ROOT / "deploy/native-ci/controld/templates/buzz-ci-controld.service").read_text()
        base_read_only = next(line for line in base.splitlines() if line.startswith("ReadOnlyPaths="))
        # The sockets are reached through the read-only /run/buzzci directory.
        # A socket inode must never be a ReadOnlyPaths entry: SELinux denies
        # init_t mounton on a sock_file, which failed controld at NAMESPACE at
        # capacity one on the clean host (systemd 259.5, Fedora 44).
        for line in (read_only, base_read_only):
            entries = line.split("=", 1)[1].split()
            self.assertIn("/run/buzzci", entries)
            self.assertFalse([entry for entry in entries if entry.endswith(".sock")], entries)
        self.assertIn("/var/lib/buzzci/activation-controller/controld-acceptance-v2.json", read_only)

        manifest, payloads, driver = self.fixture.load()
        staged = CONTROLLER.stage(
            manifest, payloads, self.fixture.root, driver, self.fixture.binding,
        )
        units = staged["staged_zero"]["units"]
        self.assertEqual(units["buzz-ci-controld.service"]["ActiveState"], "active")
        self.assertEqual(units["buzz-ci-keyholder.socket"]["ActiveState"], "inactive")
        self.assertEqual(units["buzz-ci-keyholder.service"]["ActiveState"], "inactive")
        self.assertEqual(units["buzz-ci-runner.socket"]["ActiveState"], "inactive")
        self.assertEqual(units["buzz-ci-runner.service"]["ActiveState"], "inactive")
        self.assertTrue(driver.socket_absent(manifest["socket_policy"]["keyholder"]))
        self.assertTrue(driver.socket_absent(manifest["socket_policy"]["runner"]))
        for relative in ("var/lib/buzzci/controld", "var/lib/buzzci/runner"):
            target = self.fixture.root / relative
            self.assertTrue(target.is_dir())
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)

    def test_keyholder_fd_name_and_execd_access_group_are_exact(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        self.assertEqual(manifest["socket_policy"]["keyholder"]["descriptor_name"], "buzz-ci-keyholder-control")
        template = (ACTIVATION_ROOT / "templates/20-keyholder-capacity-one.conf").read_text()
        self.assertNotIn("FileDescriptorName", template)
        sysusers = FREEZER._render_sysusers(
            (ACTIVATION_ROOT / "templates/buzzci-activation.sysusers.in").read_bytes(),
            manifest["identities"],
            manifest["access_group"],
        ).decode()
        self.assertIn("g buzzci-execd 62005\n", sysusers)
        self.assertIn("m buzzci-runner buzzci-execd\n", sysusers)
        self.assertIn("m buzzci-ctl buzzci-execd\n", sysusers)
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        state = json.loads(self.fixture.fake_state.read_bytes())
        self.assertEqual(
            state["groups"],
            {"buzzci-execd": {"group": "buzzci-execd", "gid": 62005, "members": ["buzzci-ctl", "buzzci-runner"]}},
        )
        self.assertEqual(state["identities"]["buzzci-runner"]["supplementary_groups"], ["buzzci-execd"])
        self.assertEqual(state["identities"]["buzzci-ctl"]["supplementary_groups"], ["buzzci-execd"])
        self.assertEqual(state["identities"]["buzzci-controld"]["supplementary_groups"], [])
        self.activate_one(manifest, payloads, driver)
        self.assertEqual(driver.socket(manifest["socket_policy"]["execd"])["gid"], 62005)

    def test_runner_and_execd_reject_legacy_or_unbound_executor_programs(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        entries = {entry["role"]: entry for entry in manifest["entries"]}
        active = json.loads(payloads[entries["runner_config"]["active_source"]])
        active["host"] = {"executor_program": "/usr/bin/env"}
        payloads[entries["runner_config"]["active_source"]] = activation_package.canonical_json(active)
        with self.assertRaisesRegex(ValueError, "complete v2 proxy contract"):
            CONTROLLER._validate_phase_configs(manifest, payloads)

        manifest, payloads, _driver = self.fixture.load()
        entries = {entry["role"]: entry for entry in manifest["entries"]}
        execd = json.loads(payloads[entries["execd_config"]["source"]])
        execd["executor"]["path"] = "/usr/bin/env"
        payloads[entries["execd_config"]["source"]] = activation_package.canonical_json(execd)
        active_execd = json.loads(payloads[entries["execd_config"]["active_source"]])
        active_execd["executor"]["path"] = "/usr/bin/env"
        payloads[entries["execd_config"]["active_source"]] = activation_package.canonical_json(active_execd)
        with self.assertRaisesRegex(ValueError, "executor provenance"):
            CONTROLLER._validate_phase_configs(manifest, payloads)

        manifest, _payloads, driver = self.fixture.load()
        executor = next(item for item in manifest["components"] if item["name"] == "executor")
        program = self.fixture.root / executor["binary_path"].lstrip("/")
        program.write_bytes(b"drifted-executor\n")
        program.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "target content drift"):
            CONTROLLER.preflight(manifest, self.fixture.root, driver, require_dormant=True)

    def test_runner_v2_and_execd_v2_are_exact_and_cross_bound(self) -> None:
        manifest, payloads, _driver = self.fixture.load()
        entries = {entry["role"]: entry for entry in manifest["entries"]}
        runner = entries["runner_config"]
        execd = entries["execd_config"]
        staged = json.loads(payloads[runner["source"]])
        active = json.loads(payloads[runner["active_source"]])
        broker = json.loads(payloads[execd["source"]])
        active_broker = json.loads(payloads[execd["active_source"]])

        self.assertEqual((runner["target"], runner["install_mode"]), ("/etc/buzzci/runner-v2.json", "0600"))
        self.assertEqual((execd["target"], execd["install_mode"], execd["uid"], execd["gid"]), ("/etc/buzzci/execd-v2.json", "0600", 0, 0))
        self.assertEqual(staged, {"schema_version": 2, "controld_uid": 62002, "controld_gid": 62002, "mode": "dormant"})
        self.assertEqual((active["mode"], active["execd_socket"], active["execd_uid"], active["execd_gid"]), ("v2_proxy", "/run/buzzci/execd.sock", 0, 0))
        self.assertEqual((broker["enabled_protocol"], broker["capacity"], active_broker["capacity"], activation_package.REGISTER_JOB_INTENT_OPERATION), (2, 0, 1, 9))
        self.assertEqual(broker["identities"]["access_group_members"], ["buzzci-ctl", "buzzci-runner"])
        self.assertEqual((broker["identities"]["control_uid"], broker["identities"]["job_uid"]), (961, 62006))
        self.assertEqual(
            {key: broker["identities"][key] for key in (
                "control_user", "control_group", "control_home", "control_shell", "control_supplementary_groups",
            )},
            {
                "control_user": "buzzci-ctl", "control_group": "buzzci-ctl",
                "control_home": "/var/lib/buzzci/principals/ctl", "control_shell": "/usr/sbin/nologin",
                "control_supplementary_groups": ["buzzci-execd"],
            },
        )
        self.assertEqual(broker["paths"]["intent_root"], activation_package.EXECD_INTENT_ROOT)
        self.assertEqual(broker["paths"]["executor_socket"], activation_package.EXECUTOR_SOCKET_PATH)
        self.assertEqual(active["lane_manifest_digest"], broker["lane_manifest_digest"])
        self.assertEqual(
            activation_package.lane_manifest_digest(broker["lane_manifest"]),
            "5d016bf76974d69c05899940b899c329c8f25302a39bd7864ec10ec03d6a0bef",
        )
        selectors = json.loads(payloads[entries["controld_config"]["active_source"]])["keyholder_selectors"]
        self.assertEqual(
            (broker["lane_manifest"]["admission_verifying_key"], broker["lane_manifest"]["admission_key_generation"]),
            (selectors["manifest"]["public_key"], selectors["manifest"]["generation"]),
        )
        qualification = next(item for item in manifest["components"] if item["name"] == "qualification")
        qualification_entry = entries["qualification_binary"]
        self.assertEqual(
            (qualification["binary_path"], qualification["source_commit"], qualification_entry["target"], qualification_entry["install_mode"]),
            (
                "/usr/libexec/buzz-ci-production-qualification",
                activation_package.QUALIFICATION_SOURCE_COMMIT,
                "/usr/libexec/buzz-ci-production-qualification",
                "0755",
            ),
        )
        self.assertEqual(
            (activation_package.SECCOMP_PROFILE_PATH, activation_package.SECCOMP_PROFILE_DIGEST),
            (
                "/var/lib/buzzci/seccomp/v1/sha256/2598b3b98e6970f37f917e210202fa8976aefcd99abf8955803a6e35bba17eb4.json",
                "2598b3b98e6970f37f917e210202fa8976aefcd99abf8955803a6e35bba17eb4",
            ),
        )
        self.assertFalse(any(entry["target"] == activation_package.SECCOMP_PROFILE_PATH for entry in manifest["entries"]))
        self.assertFalse(any(str(entry["target"]).startswith(activation_package.EXECD_INTENT_ROOT + "/") for entry in manifest["entries"]))
        verifier = next(item for item in manifest["components"] if item["name"] == "receipt_verifier")
        verifier_entry = entries["receipt_verifier_binary"]
        self.assertEqual(
            (verifier["binary_path"], verifier_entry["target"], verifier_entry["source_mode"], verifier_entry["install_mode"]),
            (
                "/usr/libexec/buzz-ci-verify-acceptance-receipt",
                "/usr/libexec/buzz-ci-verify-acceptance-receipt",
                "0500",
                "0755",
            ),
        )

    def test_production_v2_request_is_post_freeze_persisted_and_closed(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        result = CONTROLLER.activate(manifest, payloads, self.fixture.root, driver)["qualification"]
        self.set_capacity_one(manifest, payloads, driver)
        receipt = CONTROLLER._read_receipt(self.fixture.root)
        state = receipt["qualification"]
        request_raw = base64.b64decode(state["request_base64"], validate=True)
        request = json.loads(request_raw, object_pairs_hook=activation_package.reject_duplicates)
        self.assertEqual(list(request), [
            "schema_version", "request_id", "integrated_candidate_sha", "activation_package_digest",
            "fixture_digest", "principal_digest", "lane_manifest_digest", "broker_build_identity_digest",
            "host_profile_digest", "suite_digest", "isolation_profile_digest", "seccomp_profile_digest",
            "executor_program_digest", "executor_provenance_digest", "nonce", "controller_generation",
            "runner_generation", "lane_epoch", "admission_key_generation", "issued_at", "expires_at",
        ])
        self.assertEqual(request["schema_version"], CONTROLLER.QUALIFICATION_REQUEST_SCHEMA)
        self.assertEqual((request["activation_package_digest"], request["fixture_digest"]), (manifest["package_digest"], self.fixture.binding["scenario_sha256"]))
        self.assertEqual(request["expires_at"] - request["issued_at"], 60)
        self.assertEqual(request["principal_digest"], CONTROLLER._qualification_principal_digest(manifest))
        execd_record = next(item for item in receipt["acceptance_generated"] if item["role"] == "execd_config")
        execd_config = json.loads(base64.b64decode(execd_record["payload_base64"], validate=True))
        self.assertEqual(request["executor_provenance_digest"], CONTROLLER._executor_provenance_digest(execd_config["executor"]))
        self.assertTrue(set(request).isdisjoint({"action", "program", "path", "argv", "environment"}))
        self.assertEqual((state["status"], result["status"]), ("passed", "qualified_closed"))
        before = request_raw
        CONTROLLER.qualify(manifest, payloads, self.fixture.root, driver)
        after = base64.b64decode(CONTROLLER._read_receipt(self.fixture.root)["qualification"]["request_base64"], validate=True)
        self.assertEqual(after, before)

    def test_executor_provenance_digest_uses_protocol_git_oid_wire_form(self) -> None:
        # Executor record recorded from /etc/buzzci/execd-v2.json on a clean
        # host at candidate cbca8b13. execd (buzz-ci-broker-protocol
        # production_qualification_executor_provenance_digest) hashes the
        # source commit as the 33-byte GitOid wire form; the expected value is
        # the digest execd computed for this record.
        executor = {
            "gid": 0,
            "mode": 493,
            "path": "/usr/libexec/buzz-ci-executor",
            "sha256": "ac9ef9987b627eded1d40e30726ec02b24fa6591b394513007218ef91a22ba7b",
            "source_commit": "cbca8b1371206688fde40d6f370ee65b97bb145a",
            "uid": 0,
        }
        self.assertEqual(
            CONTROLLER._executor_provenance_digest(executor),
            "fe38da0b58ca8073b45ab76a716bf98577016d9d6cbed67227f405a79705a9bc",
        )
        # The previous encoding (length byte 20 plus the raw SHA-1) produced
        # the digest execd refused with policy_denied.
        self.assertNotEqual(
            CONTROLLER._executor_provenance_digest(executor),
            "112e3fda1d0f1c4409fd8bacd198d9a96d41db885ac544d9f1353a7c2753f0c0",
        )
        self.assertEqual(
            CONTROLLER._protocol_git_oid(executor["source_commit"]),
            b"\x01" + bytes.fromhex(executor["source_commit"]) + bytes(12),
        )
        self.assertEqual(CONTROLLER._protocol_git_oid("ab" * 32), b"\x02" + bytes([0xAB] * 32))
        with self.assertRaisesRegex(ValueError, "neither SHA-1 nor SHA-256"):
            CONTROLLER._protocol_git_oid("ab" * 24)

    def test_production_v2_nonzero_exit_keeps_exact_pending_request(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        component = next(item for item in manifest["components"] if item["name"] == "qualification")
        program = self.fixture.root / component["binary_path"].lstrip("/")
        failure = b"#!/usr/bin/python3\nraise SystemExit(3)\n"
        write_file(program, failure, 0o755)
        component["binary_sha256"] = activation_package.digest(failure)
        receipt = CONTROLLER._read_receipt(self.fixture.root)
        with self.assertRaisesRegex(ValueError, "failed with status 3"):
            CONTROLLER._run_qualification(manifest, self.fixture.root, receipt)
        persisted = CONTROLLER._read_receipt(self.fixture.root)["qualification"]
        self.assertEqual(persisted["status"], "pending")
        request = base64.b64decode(persisted["request_base64"], validate=True)
        self.assertEqual(activation_package.digest(request), persisted["request_sha256"])
        self.assertEqual(persisted["attempt_count"], 1)
        self.assertIn("failed with status 3", persisted["last_error"])

    def test_qualification_clock_is_the_named_live_bound_only(self) -> None:
        # Sol focus read of head Q, finding 1: the qualification request's
        # issue and expiry read the host clock. That request is minted live
        # (fresh ID and nonce, 60 s delivery validity) and execd judges it on
        # the same host clock; it is not package material. The rule is named
        # once so a reviewer verifies it by grep.
        source = (ACTIVATION_ROOT / "controller.py").read_text()
        needle = "time." + "time()"
        self.assertEqual(source.count(needle), 1)
        helper_start = source.index("def live_unix_now()")
        helper_end = source.index("\n\n\n", helper_start)
        self.assertIn(needle, source[helper_start:helper_end])
        self.assertEqual(source.count("live_unix_now()"), 4)
        with mock.patch.object(CONTROLLER.time, "time", return_value=1_234.9):
            self.assertEqual(CONTROLLER.live_unix_now(), 1_234)

    def test_production_v2_retries_only_the_exact_valid_request_with_a_fixed_budget(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        component = next(item for item in manifest["components"] if item["name"] == "qualification")
        program = self.fixture.root / component["binary_path"].lstrip("/")
        failure = b"#!/usr/bin/python3\nraise SystemExit(3)\n"
        write_file(program, failure, 0o755)
        component["binary_sha256"] = activation_package.digest(failure)
        with mock.patch.object(CONTROLLER.time, "time", return_value=1_000):
            for attempt in range(1, CONTROLLER.QUALIFICATION_MAX_ATTEMPTS + 1):
                receipt = CONTROLLER._read_receipt(self.fixture.root)
                with self.assertRaisesRegex(ValueError, "failed with status 3"):
                    CONTROLLER._run_qualification(manifest, self.fixture.root, receipt)
                state = CONTROLLER._read_receipt(self.fixture.root)["qualification"]
                self.assertEqual(state["attempt_count"], attempt)
                request = base64.b64decode(state["request_base64"], validate=True)
                if attempt == 1:
                    exact_request = request
                else:
                    self.assertEqual(request, exact_request)
            receipt = CONTROLLER._read_receipt(self.fixture.root)
            with self.assertRaisesRegex(ValueError, "retry budget is exhausted"):
                CONTROLLER._run_qualification(manifest, self.fixture.root, receipt)
        state = CONTROLLER._read_receipt(self.fixture.root)["qualification"]
        self.assertEqual(state["attempt_count"], CONTROLLER.QUALIFICATION_MAX_ATTEMPTS)
        self.assertEqual(base64.b64decode(state["request_base64"], validate=True), exact_request)

    def test_valid_uncertain_request_retries_exactly_and_resolves(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        component = next(item for item in manifest["components"] if item["name"] == "qualification")
        program = self.fixture.root / component["binary_path"].lstrip("/")
        failure = b"#!/usr/bin/python3\nraise SystemExit(3)\n"
        write_file(program, failure, 0o755)
        component["binary_sha256"] = activation_package.digest(failure)
        with mock.patch.object(CONTROLLER.time, "time", return_value=1_000):
            receipt = CONTROLLER._read_receipt(self.fixture.root)
            with self.assertRaisesRegex(ValueError, "failed with status 3"):
                CONTROLLER._run_qualification(manifest, self.fixture.root, receipt)
        before = base64.b64decode(
            CONTROLLER._read_receipt(self.fixture.root)["qualification"]["request_base64"], validate=True,
        )
        write_file(program, QUALIFICATION_SCRIPT, 0o755)
        component["binary_sha256"] = activation_package.digest(QUALIFICATION_SCRIPT)
        with mock.patch.object(CONTROLLER.time, "time", return_value=1_001):
            result = CONTROLLER.activate(manifest, payloads, self.fixture.root, driver)
        self.set_capacity_one(manifest, payloads, driver)
        state = CONTROLLER._read_receipt(self.fixture.root)["qualification"]
        self.assertEqual((result["state"], state["status"], state["attempt_count"]), ("qualified_closed", "passed", 2))
        self.assertEqual(base64.b64decode(state["request_base64"], validate=True), before)

    def test_expired_uncertain_qualification_requires_rollback_and_new_replay_binding(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        component = next(item for item in manifest["components"] if item["name"] == "qualification")
        program = self.fixture.root / component["binary_path"].lstrip("/")
        failure = b"#!/usr/bin/python3\nraise SystemExit(3)\n"
        write_file(program, failure, 0o755)
        component["binary_sha256"] = activation_package.digest(failure)
        with mock.patch.object(CONTROLLER.time, "time", return_value=1_000):
            receipt = CONTROLLER._read_receipt(self.fixture.root)
            with self.assertRaisesRegex(ValueError, "failed with status 3"):
                CONTROLLER._run_qualification(manifest, self.fixture.root, receipt)
        write_file(program, QUALIFICATION_SCRIPT, 0o755)
        component["binary_sha256"] = activation_package.digest(QUALIFICATION_SCRIPT)
        pending_receipt = CONTROLLER._read_receipt(self.fixture.root)
        self.assertEqual(pending_receipt["state"], "staged_zero")
        pending = pending_receipt["qualification"]
        exact_request = base64.b64decode(pending["request_base64"], validate=True)
        self.assertIn("failed with status 3", pending["last_error"])

        with mock.patch.object(CONTROLLER.time, "time", return_value=1_060):
            with self.assertRaisesRegex(ValueError, "request expired"):
                CONTROLLER.activate(manifest, payloads, self.fixture.root, driver)
        uncertain_receipt = CONTROLLER._read_receipt(self.fixture.root)
        uncertain = uncertain_receipt["qualification"]
        self.assertEqual((uncertain_receipt["state"], uncertain["status"]), ("qualification_uncertain", "expired_uncertain"))
        self.assertEqual(base64.b64decode(uncertain["request_base64"], validate=True), exact_request)
        self.assertIn("failed with status 3", uncertain["last_error"])
        self.assertIsNotNone(uncertain["expired_at"])
        current = CONTROLLER.check_current(manifest, self.fixture.root, driver)
        self.assertEqual((current["status"], current["capacity"]), ("rollback_and_restage_required", 0))

        CONTROLLER.rollback(manifest, self.fixture.root, driver)
        with self.assertRaisesRegex(ValueError, "forbids request rotation under the same"):
            CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)

        scenario = copy.deepcopy(self.fixture.scenario)
        scenario["fixture"]["controller_generation"] += 1
        binding = CONTROLLER._acceptance_binding(manifest, scenario)
        restaged = CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, binding)
        self.assertEqual((restaged["state"], CONTROLLER._read_receipt(self.fixture.root)["qualification"]), ("staged_zero", None))

    def test_receipt_verifier_stage_table_is_frozen_installed_and_rolled_back(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        entry = next(item for item in manifest["entries"] if item["role"] == "receipt_verifier_expected_stages")
        self.assertEqual(
            (entry["source_mode"], entry["install_mode"], entry["target"], entry["sha256"]),
            (
                "0400", "0644", "/usr/libexec/buzz-ci-acceptance-expected-stages.json",
                activation_package.RECEIPT_VERIFIER_EXPECTED_STAGES_SHA256,
            ),
        )
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        target = self.fixture.root / entry["target"].lstrip("/")
        self.assertEqual((target.read_bytes(), stat.S_IMODE(target.stat().st_mode)), (payloads[entry["source"]], 0o644))
        CONTROLLER.rollback(manifest, self.fixture.root, driver)
        self.assertFalse(target.exists())
    def test_execd_contract_drift_is_rejected(self) -> None:
        mutations = (
            ("peer", lambda value: value["identities"].__setitem__("runner_uid", 62004), "peer and job identities"),
            ("intent", lambda value: value["paths"].__setitem__("intent_root", "/tmp/intents"), "intent, evidence, teardown"),
            ("lane", lambda value: value.__setitem__("lane_manifest_digest", "f" * 64), "Rust contract"),
            ("execution", lambda value: value["execution"].__setitem__("workflow_id", "different"), "execution declaration differs"),
        )
        for label, mutate, message in mutations:
            with self.subTest(label=label):
                manifest, payloads, _driver = self.fixture.load()
                entry = next(item for item in manifest["entries"] if item["role"] == "execd_config")
                value = json.loads(payloads[entry["source"]])
                active_value = json.loads(payloads[entry["active_source"]])
                mutate(value)
                mutate(active_value)
                payloads[entry["source"]] = activation_package.canonical_json(value)
                payloads[entry["active_source"]] = activation_package.canonical_json(active_value)
                with self.assertRaisesRegex(ValueError, message):
                    CONTROLLER._validate_phase_configs(manifest, payloads)

    def test_execd_config_and_retained_directories_install_and_rollback(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        entry = next(item for item in manifest["entries"] if item["role"] == "execd_config")
        target = self.fixture.root / entry["target"].lstrip("/")
        installed = json.loads(target.read_bytes())
        self.assertEqual((installed["capacity"], installed["qualification"]["activation_package_digest"]), (0, manifest["package_digest"]))
        self.assertEqual(installed["qualification"]["fixture_digest"], self.fixture.binding["scenario_sha256"])
        self.assertEqual(
            installed["execution"]["declaration_digest"],
            activation_package.execution_declaration_digest(
                manifest["source_commit"], manifest["package_digest"], installed["lane_manifest"], installed["execution"],
            ),
        )
        self.assertNotEqual(installed["execution"]["declaration_digest"], "0" * 64)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.fixture.root / "var/lib/buzzci").stat().st_mode), 0o711)
        for path, mode in (
            ("/var/lib/buzzci/execd-v2", 0o711),
            (activation_package.EXECD_INTENT_ROOT, 0o700),
            (activation_package.EXECD_BINDING_ROOT, 0o700),
            (activation_package.EXECD_EVIDENCE_ROOT, 0o700),
            (activation_package.EXECD_TEARDOWN_ROOT, 0o700),
            (activation_package.EXECD_ATTEMPT_ROOT, 0o711),
            (activation_package.EXECD_QUALIFICATION_ROOT, 0o700),
            ("/var/lib/buzzci/seccomp", 0o711),
            ("/var/lib/buzzci/seccomp/v1", 0o711),
            ("/var/lib/buzzci/seccomp/v1/sha256", 0o711),
        ):
            directory = self.fixture.root / path.lstrip("/")
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), mode)
        self.assertFalse((self.fixture.root / activation_package.SECCOMP_PROFILE_PATH.lstrip("/")).exists())
        self.assertFalse((self.fixture.root / "var/lib/buzzci/activation/receipts/seccomp.json").exists())
        CONTROLLER.rollback(manifest, self.fixture.root, driver)
        self.assertFalse(target.exists())
        self.assertTrue((self.fixture.root / activation_package.EXECD_INTENT_ROOT.lstrip("/")).is_dir())

    def test_execution_declaration_is_closed_bound_and_matches_controld(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        entry = next(item for item in manifest["entries"] if item["role"] == "execd_config")
        template = json.loads(payloads[entry["source"]])
        self.assertEqual(template["execution"]["declaration_digest"], "0" * 64)
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        staged = json.loads((self.fixture.root / entry["target"].lstrip("/")).read_bytes())
        execution = staged["execution"]
        controld_entry = next(item for item in manifest["entries"] if item["role"] == "controld_config")
        controld = json.loads(payloads[controld_entry["active_source"]])
        self.assertEqual(
            (execution["workflow_id"], execution["workflow_digest"], execution["job_id"], execution["artifact"]),
            (controld["workflow_id"], controld["workflow_digest"], controld["jobs"][0]["job_id"], controld["jobs"][0]["artifacts"][0]),
        )
        active = CONTROLLER._render_execd_config(
            manifest, payloads, entry, self.fixture.binding, capacity=1,
        )
        self.assertEqual(json.loads(active)["execution"], execution)
        for field, changed in (
            ("workflow_id", "x" * 65),
            ("job_id", "other"),
            ("fixture_input_sha256", "f" * 64),
            ("max_processes", 17),
        ):
            with self.subTest(field=field):
                mutated = copy.deepcopy(template["execution"])
                mutated[field] = changed
                with self.assertRaises(ValueError):
                    activation_package.validate_execution_declaration(mutated, allow_placeholder=True)

    def test_execd_config_bytes_follow_the_sorted_canonical_contract(self) -> None:
        # execd `canonical_sorted_parse` accepts exactly these bytes: compact JSON,
        # every object key sorted bytewise, one trailing LF, nothing else.
        manifest, payloads, driver = self.fixture.load()
        entry = next(item for item in manifest["entries"] if item["role"] == "execd_config")

        def assert_sorted(value: object) -> None:
            if isinstance(value, dict):
                self.assertEqual(list(value), sorted(value))
                for child in value.values():
                    assert_sorted(child)
            elif isinstance(value, list):
                for child in value:
                    assert_sorted(child)

        for capacity in (0, 1):
            with self.subTest(capacity=capacity):
                rendered = CONTROLLER._render_execd_config(
                    manifest, payloads, entry, self.fixture.binding, capacity=capacity,
                )
                self.assertTrue(rendered.endswith(b"\n"))
                self.assertNotIn(b"\n", rendered[:-1])
                self.assertEqual(rendered.decode("ascii").encode("ascii"), rendered)
                value = json.loads(rendered, object_pairs_hook=activation_package.reject_duplicates)
                self.assertEqual(value["capacity"], capacity)
                assert_sorted(value)
                self.assertEqual(activation_package.canonical_json(value), rendered)
                self.assertEqual(
                    json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n", rendered,
                )
                self.assertNotEqual(json.dumps(value, sort_keys=True).encode() + b"\n", rendered)
                self.assertNotEqual(rendered[:-1], activation_package.canonical_json(value))
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        staged = (self.fixture.root / entry["target"].lstrip("/")).read_bytes()
        self.assertEqual(
            staged,
            CONTROLLER._render_execd_config(manifest, payloads, entry, self.fixture.binding, capacity=0),
        )

    def test_execution_digest_matches_frozen_rust_vector(self) -> None:
        manifest, payloads, _driver = self.fixture.load()
        entry = next(item for item in manifest["entries"] if item["role"] == "execd_config")
        config = json.loads(payloads[entry["source"]])
        # The Rust vector (crates/buzz-ci-execd/src/production_v2.rs) freezes a
        # lane manifest with the placeholder admission key; the scaffold now
        # carries the keyholder manifest selector, so the vector is rebuilt here.
        frozen_lane_manifest = dict(
            config["lane_manifest"], admission_verifying_key="20" * 32, admission_key_generation=9,
        )
        config["execution"]["failure_selector"] = manifest["acceptance_template"]["failure_selector"]
        self.assertEqual(
            activation_package.lane_manifest_digest(frozen_lane_manifest),
            "12ede37672233a144707bc49efa5d8f86ec5803e6b9d623347472702b2c98f04",
        )
        self.assertEqual(
            activation_package.execution_declaration_digest(
                "aa" * 20, "70" * 32, frozen_lane_manifest, config["execution"],
            ),
            "8503abd897bbab6a86c42ea966de80c57752592d7f4d84ae84a68306a7df5452",
        )

    def test_lane_manifest_admission_key_must_be_the_keyholder_manifest_selector(self) -> None:
        """H6 clean host, canary stage 5: runner-active carried
        admission_key_generation 9 from a placeholder lane manifest while
        controld derived 1 from the keyholder manifest selector, so the runner
        rejected controld's first dispatch ("does not match static activation
        coordinates"). The freezer now binds the lane manifest to the selector."""
        manifest, payloads, _driver = self.fixture.load()
        entries = {entry["role"]: entry for entry in manifest["entries"]}
        controld_active = json.loads(payloads[entries["controld_config"]["active_source"]])
        selector = controld_active["keyholder_selectors"]["manifest"]
        for field, value in (
            ("admission_key_generation", 9),
            ("admission_key_generation", selector["generation"] + 1),
            ("admission_verifying_key", "20" * 32),
        ):
            manifest, payloads, _driver = self.fixture.load()
            entries = {entry["role"]: entry for entry in manifest["entries"]}
            for source in (entries["execd_config"]["source"], entries["execd_config"]["active_source"]):
                execd = json.loads(payloads[source])
                execd["lane_manifest"][field] = value
                execd["lane_manifest_digest"] = activation_package.lane_manifest_digest(execd["lane_manifest"])
                payloads[source] = activation_package.canonical_json(execd)
            runner_active = json.loads(payloads[entries["runner_config"]["active_source"]])
            runner_active["lane_manifest_digest"] = execd["lane_manifest_digest"]
            if field == "admission_key_generation":
                runner_active["admission_key_generation"] = value
            payloads[entries["runner_config"]["active_source"]] = activation_package.canonical_json(runner_active)
            controld_active = json.loads(payloads[entries["controld_config"]["active_source"]])
            controld_active["lane_manifest_digest"] = execd["lane_manifest_digest"]
            payloads[entries["controld_config"]["active_source"]] = activation_package.canonical_json(controld_active)
            with self.assertRaisesRegex(ValueError, "admission key differs from the keyholder manifest selector"):
                CONTROLLER._validate_phase_configs(manifest, payloads)
        manifest, payloads, _driver = self.fixture.load()
        CONTROLLER._validate_phase_configs(manifest, payloads)

    def test_every_frozen_request_is_admissible_at_the_package_time_reference(self) -> None:
        """H9 clean host, canary stage 8 (rerun_separation): the runner refused the
        frozen rerun with "issued after the package time reference: issued_at
        reference + 10 > time_reference". The runner and execd judge every request
        window as issued_at <= reference < expires_at, so the template issues the
        run and the rerun at the reference and the validator holds both there."""
        manifest, _payloads, _driver = self.fixture.load()
        template = manifest["acceptance_template"]
        reference = template["time_reference"]
        for name in ("run_event", "rerun_event"):
            event = template[name]
            envelope = json.loads(event[5])
            self.assertEqual(event[2], reference, name)
            self.assertLessEqual(envelope["issued_at"], reference, name)
            self.assertLess(reference, envelope["expires_at"], name)
        rerun = json.loads(template["rerun_event"][5])
        self.assertEqual((rerun["request_type"], rerun["attempt"], rerun["parent_attempt"]), ("rerun", 2, 1))
        self.assertEqual(rerun["expires_at"], reference + 310)
        for shift in (1, 10):
            drifted = copy.deepcopy(template)
            envelope = json.loads(drifted["rerun_event"][5])
            envelope["issued_at"] = reference + shift
            drifted["rerun_event"][2] = reference + shift
            drifted["rerun_event"][5] = json.dumps(envelope, ensure_ascii=False, separators=(",", ":"))
            with self.assertRaisesRegex(ValueError, "rerun template is not issued at the time reference"):
                activation_package.validate_acceptance_template(drifted)
        drifted = copy.deepcopy(template)
        drifted["rerun_event"][5] = "{"
        with self.assertRaisesRegex(ValueError, "rerun template envelope is invalid"):
            activation_package.validate_acceptance_template(drifted)

    def test_runner_time_reference_must_be_the_frozen_acceptance_template_reference(self) -> None:
        """H7 clean host, canary stage 5: the fixture hard-coded issued_at
        1800000000 (2027-01-15T08:00:00Z) with a 300 s window while the runner
        judged the window by wall clock, so it refused controld's dispatch as
        "does not match static activation coordinates". The template now
        records its bound time reference, the runner copies it as the static
        coordinate acceptance_time_reference, and the freezer binds the two."""
        manifest, payloads, _driver = self.fixture.load()
        template = manifest["acceptance_template"]
        reference = template["time_reference"]
        run = json.loads(template["run_event"][5])
        self.assertEqual(template["run_event"][2], reference)
        self.assertEqual(run["issued_at"], reference)
        self.assertEqual(run["expires_at"], reference + 300)
        entries = {entry["role"]: entry for entry in manifest["entries"]}
        runner_active = json.loads(payloads[entries["runner_config"]["active_source"]])
        self.assertEqual(runner_active["acceptance_time_reference"], reference)
        for value in (reference + 1, reference - 1, 1_800_000_300):
            manifest, payloads, _driver = self.fixture.load()
            entries = {entry["role"]: entry for entry in manifest["entries"]}
            runner_active = json.loads(payloads[entries["runner_config"]["active_source"]])
            runner_active["acceptance_time_reference"] = value
            payloads[entries["runner_config"]["active_source"]] = activation_package.canonical_json(runner_active)
            with self.assertRaisesRegex(ValueError, "time reference differs from the frozen acceptance template"):
                CONTROLLER._validate_phase_configs(manifest, payloads)
        manifest, payloads, _driver = self.fixture.load()
        entries = {entry["role"]: entry for entry in manifest["entries"]}
        runner_active = json.loads(payloads[entries["runner_config"]["active_source"]])
        del runner_active["acceptance_time_reference"]
        payloads[entries["runner_config"]["active_source"]] = activation_package.canonical_json(runner_active)
        with self.assertRaisesRegex(ValueError, "complete v2 proxy contract"):
            CONTROLLER._validate_phase_configs(manifest, payloads)
        drifted = copy.deepcopy(template)
        drifted["time_reference"] = reference + 1
        with self.assertRaisesRegex(ValueError, "not issued at the time reference"):
            activation_package.validate_acceptance_template(drifted)
        drifted = copy.deepcopy(template)
        del drifted["time_reference"]
        with self.assertRaisesRegex(ValueError, "template shape differs"):
            activation_package.validate_acceptance_template(drifted)
        rebuilt = activation_package.production_acceptance_template(
            actor_public_key=template["actor"]["public_key"],
            actor_generation=template["actor"]["generation"],
            ci_signer_public_key=json.loads(template["grant_event"][5])["signer_pubkey"],
            candidate_sha=manifest["source_commit"],
            workflow_id=run["workflow_id"],
            workflow_digest=run["workflow_digest"],
            job_id=run["job_ids"][0],
            channel_id=activation_package.acceptance_template_channel(template),
            repository_owner_public_key=run["target_repo_a"].split(":")[1],
            repository_id=run["target_repo_a"].split(":")[2],
            source_clone_url=run["source_clone_url"],
            relay_http_origin=ACTIVATION_SCAFFOLD.TEST_RELAY_HTTP_ORIGIN,
            export_subject=template["export_subject"],
            export_generation=template["export_generation"],
            time_reference=reference + 7,
        )
        self.assertEqual(rebuilt["time_reference"], reference + 7)
        self.assertEqual(json.loads(rebuilt["run_event"][5])["issued_at"], reference + 7)
        self.assertEqual(json.loads(rebuilt["rerun_event"][5])["issued_at"], reference + 7)
        self.assertEqual(rebuilt["rerun_event"][2], reference + 7)
        self.assertNotEqual(rebuilt["run_event"], template["run_event"])
        # H8 clean host, diagnostic boots 3 and 4: execd judged the same window
        # by wall clock. Its config now carries the reference as well, bound to
        # the template in both phases.
        for source_field, value in (("source", reference + 1), ("active_source", reference - 1)):
            manifest, payloads, _driver = self.fixture.load()
            entries = {entry["role"]: entry for entry in manifest["entries"]}
            execd = json.loads(payloads[entries["execd_config"][source_field]])
            self.assertEqual(execd["acceptance_time_reference"], reference)
            execd["acceptance_time_reference"] = value
            payloads[entries["execd_config"][source_field]] = activation_package.canonical_json(execd)
            with self.assertRaisesRegex(ValueError, "execd v2 time reference differs"):
                CONTROLLER._validate_phase_configs(manifest, payloads)
        manifest, payloads, _driver = self.fixture.load()
        entries = {entry["role"]: entry for entry in manifest["entries"]}
        execd = json.loads(payloads[entries["execd_config"]["source"]])
        del execd["acceptance_time_reference"]
        payloads[entries["execd_config"]["source"]] = activation_package.canonical_json(execd)
        with self.assertRaisesRegex(ValueError, "shape differs from production"):
            CONTROLLER._validate_phase_configs(manifest, payloads)

    def _bound_template_inputs(self, manifest: dict[str, object]) -> dict[str, object]:
        template = manifest["acceptance_template"]
        run = json.loads(template["run_event"][5])
        return {
            "actor_public_key": template["actor"]["public_key"],
            "actor_generation": template["actor"]["generation"],
            "ci_signer_public_key": json.loads(template["grant_event"][5])["signer_pubkey"],
            "candidate_sha": manifest["source_commit"],
            "workflow_id": run["workflow_id"],
            "workflow_digest": run["workflow_digest"],
            "job_id": run["job_ids"][0],
            "channel_id": activation_package.acceptance_template_channel(template),
            "repository_owner_public_key": run["target_repo_a"].split(":")[1],
            "repository_id": run["target_repo_a"].split(":")[2],
            "source_clone_url": run["source_clone_url"],
            "relay_http_origin": ACTIVATION_SCAFFOLD.TEST_RELAY_HTTP_ORIGIN,
            "export_subject": template["export_subject"],
            "export_generation": template["export_generation"],
            "time_reference": template["time_reference"],
        }

    def test_acceptance_template_renders_the_bound_channel_and_repository(self) -> None:
        """M4 canary, stage 3 (manifest_identity): controld signed the frozen Run
        event and published it to the production relay, which refused it because
        the fixture hard-coded a channel, repository coordinate, and clone URL
        that exist on no relay. The relay indexes a kind-46100 request by its h
        tag channel and a tag repository and requires both to be well formed, so
        the builder takes them as inputs and the freezer binds the controld
        channel to the frozen events."""
        manifest, payloads, _driver = self.fixture.load()
        template = manifest["acceptance_template"]
        channel = "1ad360e2-da4d-42c4-9702-2e4ad7cd90df"
        owner = "73c705675d848ad38a919a5fa07687f55b4f0863c21969941c216b44f9e7a812"
        clone_url = f"https://framework-desktop.tail69757d.ts.net:38443/git/{owner}/buzz"
        coordinate = f"30617:{owner}:buzz"
        inputs = self._bound_template_inputs(manifest)
        inputs.update({
            "channel_id": channel, "repository_owner_public_key": owner,
            "repository_id": "buzz", "source_clone_url": clone_url,
        })
        bound = activation_package.production_acceptance_template(**inputs)
        self.assertEqual(activation_package.acceptance_template_channel(bound), channel)
        self.assertEqual(activation_package.acceptance_template_repository(bound), coordinate)
        for name in ("run_event", "grant_event", "rerun_event"):
            self.assertEqual([tag for tag in bound[name][4] if tag[0] == "h"], [["h", channel]], name)
        for name in ("run_event", "rerun_event"):
            envelope = json.loads(bound[name][5])
            self.assertEqual(envelope["target_repo_a"], coordinate, name)
            self.assertEqual(envelope["source_clone_url"], clone_url, name)
            self.assertEqual([tag for tag in bound[name][4] if tag[0] == "a"], [["a", coordinate]], name)
        self.assertEqual(json.loads(bound["grant_event"][5])["target_repo_a"], coordinate)
        rendered = activation_package.canonical_json(bound).decode()
        for placeholder in (
            ACTIVATION_SCAFFOLD.TEST_CHANNEL_ID, ACTIVATION_SCAFFOLD.TEST_REPOSITORY_OWNER,
            "relay.example.invalid",
        ):
            self.assertNotIn(placeholder, rendered)
        # The fixture's other invariants hold: event ids are digests of the
        # exact bytes, the tombstone names the rerun, both requests issue at
        # the reference, and the run identity rotates with the bound authority.
        rerun_id = activation_package.digest(json.dumps(
            bound["rerun_event"], ensure_ascii=False, separators=(",", ":"),
        ).encode())
        self.assertEqual(bound["tombstone_event"][4], [["e", rerun_id]])
        self.assertEqual(bound["time_reference"], template["time_reference"])
        self.assertNotEqual(
            json.loads(bound["run_event"][5])["run_id"], json.loads(template["run_event"][5])["run_id"],
        )
        self.assertIs(activation_package.validate_acceptance_template(bound), bound)
        # Frozen into a manifest, the template must agree with the controld
        # channel: the acceptance path publishes on the event's own h tag while
        # controld polls the configured channel.
        bound_manifest = copy.deepcopy(manifest)
        bound_manifest["acceptance_template"] = bound
        with self.assertRaisesRegex(ValueError, "controld channel differs from the frozen acceptance template channel"):
            CONTROLLER._validate_phase_configs(bound_manifest, payloads)
        entries = {entry["role"]: entry for entry in manifest["entries"]}
        controld_active = json.loads(payloads[entries["controld_config"]["active_source"]])
        controld_active["channel_id"] = channel
        payloads[entries["controld_config"]["active_source"]] = activation_package.canonical_json(controld_active)
        CONTROLLER._validate_phase_configs(bound_manifest, payloads)
        with tempfile.NamedTemporaryFile("wb", suffix=".json", dir=os.environ.get("TMPDIR")) as handle:
            handle.write(activation_package.canonical_json(bound_manifest))
            handle.flush()
            output = subprocess.run(
                [
                    "check-jsonschema", "--schemafile",
                    str(ACTIVATION_ROOT / "activation-manifest.schema.json"), handle.name,
                ],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
        self.assertEqual(output.returncode, 0, output.stdout + output.stderr)

    def test_acceptance_template_request_identities_rotate_per_frozen_package(self) -> None:
        manifest, _payloads, _driver = self.fixture.load()
        inputs = self._bound_template_inputs(manifest)
        first = activation_package.production_acceptance_template(**inputs)
        repeated = activation_package.production_acceptance_template(**inputs)
        later = activation_package.production_acceptance_template(
            **{**inputs, "time_reference": inputs["time_reference"] + 1},
        )

        self.assertEqual(first, repeated)
        first_run = json.loads(first["run_event"][5])
        first_rerun = json.loads(first["rerun_event"][5])
        first_failure = json.loads(first["failure_run_event"][5])
        later_run = json.loads(later["run_event"][5])
        later_rerun = json.loads(later["rerun_event"][5])
        self.assertNotEqual(first_run["run_id"], first_failure["run_id"])
        self.assertEqual(first_failure["run_id"], first_rerun["run_id"])
        self.assertEqual(first_rerun["parent_run_id"], first_failure["run_id"])
        self.assertNotEqual(first_run["run_id"], later_run["run_id"])
        self.assertNotEqual(first_run["idempotency_key"], later_run["idempotency_key"])
        self.assertNotEqual(first_rerun["idempotency_key"], later_rerun["idempotency_key"])
        values = (
            first_run["run_id"], first_run["idempotency_key"],
            first_failure["run_id"], first_failure["idempotency_key"],
            first_rerun["idempotency_key"], later_run["run_id"],
            later_run["idempotency_key"], later_rerun["idempotency_key"],
        )
        self.assertEqual(len(set(values)), len(values))
        for value in values:
            parsed = uuid.UUID(value)
            self.assertEqual(str(parsed), value)
            self.assertEqual(parsed.version, 5)
            self.assertEqual(parsed.variant, uuid.RFC_4122)
        self.assertEqual(first["failure_selector"]["run_id"], first_failure["run_id"])
        self.assertEqual(first["failure_selector"]["attempt"], 1)
        self.assertEqual(first["failure_selector"]["job_id"], first_failure["job_ids"][0])

        for field, replacement in (
            ("run_id", first_run["run_id"]),
            ("attempt", 2),
            ("job_id", "other-job"),
            ("sha256", "0" * 64),
        ):
            tampered = copy.deepcopy(first)
            tampered["failure_selector"][field] = replacement
            with self.subTest(selector_field=field), self.assertRaises(ValueError):
                activation_package.validate_acceptance_template(tampered)

    def test_export_authority_digest_binds_the_exact_stable_get_plan(self) -> None:
        arguments = {
            "relay_http_origin": "https://relay.example.invalid",
            "subject": ACTIVATION_SCAFFOLD.TEST_NIP98_PUBLIC_KEY,
            "generation": ACTIVATION_SCAFFOLD.TEST_NIP98_GENERATION,
            "request_event_id": "2" * 64,
            "run_id": "11111111-1111-5111-9111-111111111111",
            "job_id": "capacity-one-fixture",
            "attempt": 1,
        }
        expected = activation_package._export_transcript_digest(**arguments)
        self.assertEqual(
            expected,
            "304a38e4780ecf0f6e4bc9b4fa9e5babd57c2a8a47e473c683b330ec5027a3cf",
        )
        mutations = (
            {"request_event_id": "3" * 64},
            {"run_id": "11111111-1111-5111-9111-111111111113"},
            {"job_id": "other-job"},
            {"subject": "4" * 64},
            {"generation": 3},
            {"relay_http_origin": "https://other.example.invalid"},
            {"artifacts": (("result", "result.json", "5" * 64, 107),)},
            {"artifacts": (("result", "result.json", activation_package.EXPORT_ARTIFACTS[0][2], 108),)},
            {"artifacts": (("result.json", "result", activation_package.EXPORT_ARTIFACTS[0][2], 107),)},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assertNotEqual(
                    activation_package._export_transcript_digest(**{**arguments, **mutation}),
                    expected,
                )
        for artifacts in ((), activation_package.EXPORT_ARTIFACTS * 2):
            with self.subTest(cardinality=len(artifacts)), self.assertRaisesRegex(
                ValueError, "exactly one artifact",
            ):
                activation_package._export_transcript_digest(
                    **arguments, artifacts=artifacts,
                )
        boundary_artifact = (
            "a" * 128,
            "result.json",
            activation_package.EXPORT_ARTIFACTS[0][2],
            107,
        )
        self.assertRegex(
            activation_package._export_transcript_digest(
                **arguments, artifacts=(boundary_artifact,),
            ),
            r"^[0-9a-f]{64}$",
        )
        for artifact_id in ("a" * 129, ".", ".."):
            with self.subTest(artifact_id=artifact_id), self.assertRaisesRegex(
                ValueError, "artifact plan entry is invalid",
            ):
                activation_package._export_transcript_digest(
                    **arguments,
                    artifacts=((
                        artifact_id,
                        "result.json",
                        activation_package.EXPORT_ARTIFACTS[0][2],
                        107,
                    ),),
                )

    def test_phase_validation_rederives_export_authority_from_nip98_selector(self) -> None:
        manifest, payloads, _driver = self.fixture.load()
        entries = {entry["role"]: entry for entry in manifest["entries"]}
        active_source = entries["controld_config"]["active_source"]
        for field, replacement in (
            ("export_subject", "4" * 64),
            ("export_generation", manifest["acceptance_template"]["export_generation"] + 1),
            ("export_authorization_digest", "5" * 64),
        ):
            changed = copy.deepcopy(manifest)
            changed["acceptance_template"][field] = replacement
            with self.subTest(template_field=field), self.assertRaisesRegex(
                ValueError, "export authority differs",
            ):
                CONTROLLER._validate_phase_configs(changed, payloads)
        for mutate in ("subject", "generation", "origin"):
            changed_payloads = dict(payloads)
            active = json.loads(changed_payloads[active_source])
            if mutate == "subject":
                active["keyholder_selectors"]["nip98"]["public_key"] = "4" * 64
            elif mutate == "generation":
                active["keyholder_selectors"]["nip98"]["generation"] += 1
            else:
                active["relay_http_origin"] = "https://other.example.invalid"
                active["relay_url"] = "wss://other.example.invalid"
            changed_payloads[active_source] = activation_package.canonical_json(active)
            with self.subTest(active_field=mutate), self.assertRaisesRegex(
                ValueError, "export authority differs",
            ):
                CONTROLLER._validate_phase_configs(manifest, changed_payloads)

    def test_clean_host_scaffold_binds_its_own_test_channel_and_repository(self) -> None:
        manifest, payloads, _driver = self.fixture.load()
        template = manifest["acceptance_template"]
        self.assertEqual(
            activation_package.acceptance_template_channel(template), ACTIVATION_SCAFFOLD.TEST_CHANNEL_ID,
        )
        self.assertEqual(
            activation_package.acceptance_template_repository(template),
            f"30617:{ACTIVATION_SCAFFOLD.TEST_REPOSITORY_OWNER}:{ACTIVATION_SCAFFOLD.TEST_REPOSITORY_ID}",
        )
        for name in ("run_event", "rerun_event"):
            self.assertEqual(
                json.loads(template[name][5])["source_clone_url"], ACTIVATION_SCAFFOLD.TEST_SOURCE_CLONE_URL,
            )
        entries = {entry["role"]: entry for entry in manifest["entries"]}
        controld_active = json.loads(payloads[entries["controld_config"]["active_source"]])
        self.assertEqual(controld_active["channel_id"], ACTIVATION_SCAFFOLD.TEST_CHANNEL_ID)
        CONTROLLER._validate_phase_configs(manifest, payloads)
        controld_active["channel_id"] = "1ad360e2-da4d-42c4-9702-2e4ad7cd90df"
        payloads[entries["controld_config"]["active_source"]] = activation_package.canonical_json(controld_active)
        with self.assertRaisesRegex(ValueError, "controld channel differs from the frozen acceptance template channel"):
            CONTROLLER._validate_phase_configs(manifest, payloads)

    def test_acceptance_template_rejects_malformed_channel_repository_and_clone_url(self) -> None:
        manifest, _payloads, _driver = self.fixture.load()
        inputs = self._bound_template_inputs(manifest)
        activation_package.production_acceptance_template(**inputs)
        cases = [
            ({"channel_id": "12345678-1234-4ABC-8DEF-123456789ABC"}, "not a canonical UUID"),
            ({"channel_id": "123456781234 4abc8def123456789abc"}, "not a canonical UUID"),
            ({"channel_id": "not-a-uuid"}, "not a canonical UUID"),
            ({"channel_id": 5}, "not a canonical UUID"),
            ({"repository_owner_public_key": "0" * 64}, "repository owner public key"),
            ({"repository_owner_public_key": "22" * 31}, "repository owner public key"),
            ({"repository_owner_public_key": "2G" * 32}, "repository owner public key"),
            ({"repository_id": ""}, "plain NIP-34 d tag"),
            ({"repository_id": "buzz:main"}, "plain NIP-34 d tag"),
            ({"repository_id": "/buzz"}, "plain NIP-34 d tag"),
            ({"repository_id": "a" * 65}, "plain NIP-34 d tag"),
            ({"repository_id": None}, "plain NIP-34 d tag"),
            ({"source_clone_url": "http://relay.example.invalid/git/buzz"}, "credential-free https"),
            ({"source_clone_url": "https://user@relay.example.invalid/git/buzz"}, "credential-free https"),
            ({"source_clone_url": "https://:pw@relay.example.invalid/git/buzz"}, "credential-free https"),
            ({"source_clone_url": "https://relay.example.invalid/git/buzz?token=1"}, "credential-free https"),
            ({"source_clone_url": "https://relay.example.invalid/git/buzz#main"}, "credential-free https"),
            ({"source_clone_url": "https://relay.example.invalid/"}, "credential-free https"),
            ({"source_clone_url": "https://relay.example.invalid"}, "credential-free https"),
            ({"source_clone_url": "https:///git/buzz"}, "credential-free https"),
            ({"source_clone_url": None}, "credential-free https"),
        ]
        for overrides, message in cases:
            with self.subTest(**{key: str(value) for key, value in overrides.items()}):
                with self.assertRaisesRegex(ValueError, message):
                    activation_package.production_acceptance_template(**{**inputs, **overrides})
        template = manifest["acceptance_template"]
        drifted = copy.deepcopy(template)
        drifted["grant_event"][4] = [["h", "1ad360e2-da4d-42c4-9702-2e4ad7cd90df"]]
        with self.assertRaisesRegex(ValueError, "more than one channel"):
            activation_package.validate_acceptance_template(drifted)
        drifted = copy.deepcopy(template)
        drifted["rerun_event"][4][0] = ["h", "1ad360e2-da4d-42c4-9702-2e4ad7cd90df"]
        with self.assertRaisesRegex(ValueError, "more than one channel"):
            activation_package.validate_acceptance_template(drifted)
        drifted = copy.deepcopy(template)
        drifted["run_event"][4].append(["h", "1ad360e2-da4d-42c4-9702-2e4ad7cd90df"])
        with self.assertRaisesRegex(ValueError, "exactly one h tag"):
            activation_package.validate_acceptance_template(drifted)
        drifted = copy.deepcopy(template)
        drifted["run_event"][4] = [tag for tag in drifted["run_event"][4] if tag[0] != "h"]
        with self.assertRaisesRegex(ValueError, "exactly one h tag"):
            activation_package.validate_acceptance_template(drifted)
        drifted = copy.deepcopy(template)
        drifted["run_event"][4][0] = ["h", "12345678-1234-4ABC-8DEF-123456789ABC"]
        with self.assertRaisesRegex(ValueError, "not a canonical UUID"):
            activation_package.validate_acceptance_template(drifted)
        drifted = copy.deepcopy(template)
        drifted["run_event"][4][1] = ["a", f"30617:{'24' * 32}:buzz"]
        with self.assertRaisesRegex(ValueError, "more than one repository"):
            activation_package.validate_acceptance_template(drifted)
        drifted = copy.deepcopy(template)
        envelope = json.loads(drifted["rerun_event"][5])
        envelope["target_repo_a"] = f"30617:{'24' * 32}:buzz"
        drifted["rerun_event"][5] = json.dumps(envelope, ensure_ascii=False, separators=(",", ":"))
        with self.assertRaisesRegex(ValueError, "more than one repository"):
            activation_package.validate_acceptance_template(drifted)

    def test_every_execution_declaration_field_drift_is_rejected(self) -> None:
        mutations = {
            "schema_version": lambda value: value.__setitem__("schema_version", 2),
            "declaration_digest": lambda value: value.__setitem__("declaration_digest", "1" * 64),
            "workflow_id": lambda value: value.__setitem__("workflow_id", "different"),
            "workflow_digest": lambda value: value.__setitem__("workflow_digest", "1" * 64),
            "job_id": lambda value: value.__setitem__("job_id", "different"),
            "artifact_id": lambda value: value["artifact"].__setitem__("artifact_id", "other"),
            "artifact_name": lambda value: value["artifact"].__setitem__("name", "other.json"),
            "artifact_media": lambda value: value["artifact"].__setitem__("media_type", "text/plain"),
            "artifact_relative": lambda value: value["artifact"].__setitem__("relative_name", "other.json"),
            "artifact_max": lambda value: value["artifact"].__setitem__("max_bytes", 32767),
            "fixture_manifest": lambda value: value.__setitem__("fixture_manifest_sha256", "1" * 64),
            "fixture_input": lambda value: value.__setitem__("fixture_input_sha256", "1" * 64),
            "fixture_script": lambda value: value.__setitem__("fixture_script_sha256", "1" * 64),
            "stdout": lambda value: value.__setitem__("max_stdout_bytes", 32767),
            "stderr": lambda value: value.__setitem__("max_stderr_bytes", 32767),
            "memory": lambda value: value.__setitem__("max_memory_bytes", 134217727),
            "processes": lambda value: value.__setitem__("max_processes", 15),
            "wall": lambda value: value.__setitem__("max_wall_seconds", 119),
        }
        for name, mutate in mutations.items():
            with self.subTest(field=name):
                manifest, payloads, _driver = self.fixture.load()
                entry = next(item for item in manifest["entries"] if item["role"] == "execd_config")
                for source in (entry["source"], entry["active_source"]):
                    config = json.loads(payloads[source])
                    mutate(config["execution"])
                    payloads[source] = activation_package.canonical_json(config)
                with self.assertRaises(ValueError):
                    CONTROLLER._validate_phase_configs(manifest, payloads)

    def test_fixture_executor_and_units_are_installed_exact_and_rollback_owned(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        staged = CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        expected = {
            "fixture_manifest": (0o444, activation_package.FIXTURE_MANIFEST_SHA256),
            "fixture_input": (0o444, activation_package.FIXTURE_INPUT_SHA256),
            "fixture_script": (0o555, activation_package.FIXTURE_SCRIPT_SHA256),
            "executor_binary": (0o755, next(item for item in manifest["components"] if item["name"] == "executor")["binary_sha256"]),
            "execd_service": (0o644, None), "execd_socket": (0o644, None),
            "executor_service": (0o644, None), "executor_socket": (0o644, None),
        }
        entries = {item["role"]: item for item in manifest["entries"]}
        for role, (mode, fixed_digest) in expected.items():
            target = self.fixture.root / entries[role]["target"].lstrip("/")
            self.assertEqual((stat.S_IMODE(target.stat().st_mode), activation_package.digest(target.read_bytes())), (mode, fixed_digest or entries[role]["sha256"]))
        for unit in ("buzz-ci-execd.service", "buzz-ci-execd.socket", "buzz-ci-executor.service", "buzz-ci-executor.socket"):
            self.assertEqual(staged["installed_units"][unit]["fragment_path"], entries[activation_package.PACKAGE_UNIT_ROLES[unit]]["target"])
        drift = self.fixture.root / entries["fixture_input"]["target"].lstrip("/")
        drift.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "readback failed"):
            CONTROLLER._verify_phase(manifest, self.fixture.root, "staged")
        drift.chmod(0o444)
        CONTROLLER.rollback(manifest, self.fixture.root, driver)
        for role in expected:
            self.assertFalse((self.fixture.root / entries[role]["target"].lstrip("/")).exists())

    def test_manifest_schema_inventory_matches_every_closed_role_and_target(self) -> None:
        schema = json.loads((ACTIVATION_ROOT / "activation-manifest.schema.json").read_bytes())
        entry = schema["$defs"]["entry"]["properties"]
        self.assertEqual(
            set(entry["role"]["enum"]),
            set(activation_package.CONFIG_TARGETS) | set(activation_package.STATIC_TARGETS),
        )
        self.assertEqual(
            set(entry["target"]["enum"]),
            set(activation_package.CONFIG_TARGETS.values()) | set(activation_package.STATIC_TARGETS.values()),
        )
        self.assertEqual(
            schema["properties"]["entries"]["minItems"],
            len(activation_package.CONFIG_TARGETS) + len(activation_package.STATIC_TARGETS),
        )
        self.assertEqual(schema["properties"]["entries"]["minItems"], schema["properties"]["entries"]["maxItems"])

    def test_executor_socket_is_required_for_capacity_one_readiness(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        _qualification, active = self.activate_one(manifest, payloads, driver)
        self.assertEqual(active["state"], "active_one")
        self.assertEqual(
            driver.socket(manifest["socket_policy"]["executor"]),
            {"path": "/run/buzzci/executor.sock", "mode": "0600", "uid": 0, "gid": 0},
        )
        driver.stop("buzz-ci-executor.socket")
        receipt = CONTROLLER._read_receipt(self.fixture.root)
        with self.assertRaisesRegex(ValueError, "unit is not active"):
            CONTROLLER._active_capacity_one_readback(
                manifest, self.fixture.root, driver, receipt["capacity_one"]["processes_before"],
            )

    def test_job_principal_can_traverse_only_fixed_attempt_and_seccomp_paths(self) -> None:
        unshare = shutil.which("unshare")
        setpriv = shutil.which("setpriv")
        if unshare is None or setpriv is None:
            self.skipTest("user namespace DAC test requires unshare and setpriv")
        subordinate_uid = first_subordinate_id(Path("/etc/subuid"))
        subordinate_gid = first_subordinate_id(Path("/etc/subgid"))
        if subordinate_uid is None or subordinate_gid is None:
            self.skipTest("user namespace DAC test requires subordinate uid and gid mappings")
        mappings = [
            f"--map-users=0:{os.getuid()}:1",
            f"--map-users=1:{subordinate_uid}:1",
            f"--map-groups=0:{os.getgid()}:1",
            f"--map-groups=1:{subordinate_gid}:1",
        ]
        probe = subprocess.run(
            [
                unshare, "--user", *mappings, setpriv,
                "--reuid=1", "--regid=1", "--clear-groups", "true",
            ],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        if probe.returncode != 0:
            if user_namespace_probe_unavailable(probe.stderr):
                self.skipTest(f"user namespace DAC test mapping unavailable: {probe.stderr.strip()}")
            self.fail(f"user namespace DAC test probe failed: {probe.stderr.strip()}")
        script = r'''
set -eu
root=$1
trap 'chmod -R a+rwx "$root/var/lib/buzzci/execd-v2/attempts/a" 2>/dev/null || :' EXIT
mkdir -p "$root/var/lib/buzzci/execd-v2/attempts/a/source" "$root/var/lib/buzzci/execd-v2/intents" "$root/var/lib/buzzci/seccomp/v1/sha256"
chmod 0755 "$root" "$root/var" "$root/var/lib"
chmod 0711 "$root/var/lib/buzzci" "$root/var/lib/buzzci/execd-v2" "$root/var/lib/buzzci/execd-v2/attempts" "$root/var/lib/buzzci/seccomp" "$root/var/lib/buzzci/seccomp/v1" "$root/var/lib/buzzci/seccomp/v1/sha256"
chmod 0700 "$root/var/lib/buzzci/execd-v2/intents"
chown 1:1 "$root/var/lib/buzzci/execd-v2/attempts/a" "$root/var/lib/buzzci/execd-v2/attempts/a/source"
chmod 0500 "$root/var/lib/buzzci/execd-v2/attempts/a" "$root/var/lib/buzzci/execd-v2/attempts/a/source"
printf input > "$root/var/lib/buzzci/execd-v2/attempts/a/source/input.txt"
chown 1:1 "$root/var/lib/buzzci/execd-v2/attempts/a/source/input.txt"
chmod 0400 "$root/var/lib/buzzci/execd-v2/attempts/a/source/input.txt"
printf profile > "$root/var/lib/buzzci/seccomp/v1/sha256/profile.json"
chmod 0444 "$root/var/lib/buzzci/seccomp/v1/sha256/profile.json"
setpriv --reuid=1 --regid=1 --clear-groups sh -eu -c 'test "$(cat "$1/var/lib/buzzci/execd-v2/attempts/a/source/input.txt")" = input; test "$(cat "$1/var/lib/buzzci/seccomp/v1/sha256/profile.json")" = profile; ! test -r "$1/var/lib/buzzci/execd-v2/intents"' sh "$root"
'''
        with tempfile.TemporaryDirectory(prefix="buzz-activation-job-dac-", dir="/tmp") as temporary:
            namespace_root = Path(temporary)
            result = subprocess.run(
                [
                    unshare, "--user", *mappings,
                    "sh", "-eu", "-c", script, "sh", str(namespace_root),
                ],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_user_namespace_probe_classification_is_narrow(self) -> None:
        for unavailable in (
            "unshare: unshare failed: Operation not permitted",
            "setpriv: setresuid failed: Operation not permitted",
            "setpriv: setresgid failed: Operation not permitted",
            "newuidmap: uid range [1-2) -> [100000-100001) not allowed",
            "newgidmap: write to gid_map failed: Operation not permitted",
        ):
            with self.subTest(unavailable=unavailable):
                self.assertTrue(user_namespace_probe_unavailable(unavailable))
        for defect in (
            "unshare: unrecognized option '--map-users=0:1000:1'",
            "setpriv: setresuid failed: Invalid argument",
            "newuidmap: uid range malformed",
        ):
            with self.subTest(defect=defect):
                self.assertFalse(user_namespace_probe_unavailable(defect))
        with mock.patch.object(Path, "read_text", side_effect=PermissionError):
            self.assertIsNone(first_subordinate_id(Path("/etc/subuid")))
        with (
            mock.patch.object(pwd, "getpwuid", side_effect=KeyError),
            mock.patch.object(
                Path, "read_text", return_value=f"{os.getuid()}:700000:1\n",
            ),
        ):
            self.assertEqual(first_subordinate_id(Path("/etc/subuid")), 700000)

    def test_rollback_restores_preexisting_exact_execd_v2_config(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        entry = next(item for item in manifest["entries"] if item["role"] == "execd_config")
        target = self.fixture.root / entry["target"].lstrip("/")
        write_file(target, payloads[entry["source"]], 0o600)
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        CONTROLLER.rollback(manifest, self.fixture.root, driver)
        self.assertEqual((target.read_bytes(), stat.S_IMODE(target.stat().st_mode)), (payloads[entry["source"]], 0o600))

    def test_qualification_process_is_hardened_and_manifest_principal_is_exact(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        os.environ["ACTIVATION_TEST_LEAK"] = "must-not-cross-exec"
        try:
            result = CONTROLLER.activate(manifest, payloads, self.fixture.root, driver)["qualification"]
            self.assertEqual(result["status"], "qualified_closed")
        finally:
            del os.environ["ACTIVATION_TEST_LEAK"]
        self.assertEqual(
            CONTROLLER._qualification_credentials(manifest, Path("/")),
            {"user": 961, "group": 961, "extra_groups": [62005]},
        )

    def test_qualification_timeout_kills_descendant_process_group(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        component = next(item for item in manifest["components"] if item["name"] == "qualification")
        program = self.fixture.root / component["binary_path"].lstrip("/")
        marker = self.fixture.temporary / "descendant.pid"
        script = f"""#!/usr/bin/python3
import os
import signal
import time
pid = os.fork()
if pid == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    with open({str(marker)!r}, 'w', encoding='ascii') as stream:
        stream.write(str(os.getpid()))
        stream.flush()
    while True:
        time.sleep(1)
while True:
    time.sleep(1)
""".encode()
        write_file(program, script, 0o755)
        component["binary_sha256"] = activation_package.digest(script)
        manifest["qualification"]["timeout_seconds"] = 1
        receipt = CONTROLLER._read_receipt(self.fixture.root)
        with self.assertRaisesRegex(ValueError, "timed out"):
            CONTROLLER._run_qualification(manifest, self.fixture.root, receipt)
        descendant = int(marker.read_text())
        for _ in range(20):
            try:
                state = Path(f"/proc/{descendant}/stat").read_text().split()[2]
            except FileNotFoundError:
                break
            if state == "Z":
                break
            time.sleep(0.05)
        else:
            self.fail("qualification descendant survived process-group timeout cleanup")

    def test_failed_return_to_zero_attempts_all_steps_and_persists_truth(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        original_qualification = CONTROLLER._run_qualification
        CONTROLLER._run_qualification = lambda *_arguments: (_ for _ in ()).throw(ValueError("injected qualification failure"))
        stop_attempts: list[str] = []
        original_stop = driver.stop
        original_disable = driver.disable

        def partial_stop(name: str) -> None:
            stop_attempts.append(name)
            if name == "buzz-ci-execd.socket":
                raise ValueError("injected stop failure")
            original_stop(name)

        def partial_disable(name: str) -> None:
            if name == activation_package.PERSISTENT_UNIT:
                raise ValueError("injected disable failure")
            original_disable(name)

        driver.stop = partial_stop
        driver.disable = partial_disable
        try:
            with self.assertRaisesRegex(ValueError, "injected qualification failure"):
                CONTROLLER.activate(manifest, payloads, self.fixture.root, driver)
        finally:
            CONTROLLER._run_qualification = original_qualification
        self.assertEqual(
            stop_attempts,
            [*activation_package.STOP_ORDER, activation_package.PERSISTENT_UNIT],
        )
        self.assertEqual(CONTROLLER._verify_phase(manifest, self.fixture.root, "staged")["controld_config"], "staged")
        receipt = CONTROLLER._read_receipt(self.fixture.root)
        self.assertEqual(receipt["state"], "rollback_failed")
        self.assertIn("capacity-zero readback", receipt["last_error"])

    def test_partial_explicit_rollback_attempts_all_stops_and_persists_failure(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        self.activate_one(manifest, payloads, driver)
        stop_attempts: list[str] = []
        original_stop = driver.stop

        def partial_stop(name: str) -> None:
            stop_attempts.append(name)
            if name == "buzz-ci-runner.socket":
                raise ValueError("injected explicit rollback failure")
            original_stop(name)

        driver.stop = partial_stop
        with self.assertRaisesRegex(ValueError, "rollback failures"):
            CONTROLLER.rollback(manifest, self.fixture.root, driver)
        self.assertEqual(
            stop_attempts[:len(activation_package.STOP_ORDER) + 1],
            activation_package.STOP_ORDER + [activation_package.PERSISTENT_UNIT],
        )
        receipt = CONTROLLER._read_receipt(self.fixture.root)
        self.assertEqual(receipt["state"], "rollback_failed")
        self.assertIn("systemd prior readback", receipt["last_error"])

    def test_qualification_executable_mode_drift_is_rejected(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        qualification = next(item for item in manifest["components"] if item["name"] == "qualification")
        program = self.fixture.root / qualification["binary_path"].lstrip("/")
        program.chmod(0o700)
        receipt = CONTROLLER._read_receipt(self.fixture.root)
        with self.assertRaisesRegex(ValueError, "executable metadata differs"):
            CONTROLLER._run_qualification(manifest, self.fixture.root, receipt)


class ActivationFreezerModeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _metadata(self, name: str, mode: int) -> os.stat_result:
        path = self.root / name
        write_file(path, b"payload\n", mode)
        return path.stat()

    def _shared_worktree(self) -> tuple[Path, Path]:
        repository = self.root / "shared-repository"
        worktree = self.root / "shared-worktree"
        relative = Path("deploy/native-ci/activation/templates/static.conf")
        subprocess.run(["git", "init", "-q", str(repository)], check=True)
        subprocess.run(["git", "-C", str(repository), "config", "user.name", "Activation Test"], check=True)
        subprocess.run(["git", "-C", str(repository), "config", "user.email", "activation@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(repository), "config", "core.sharedRepository", "all"], check=True)
        write_file(repository / relative, b"shared payload\n", 0o600)
        subprocess.run(["git", "-C", str(repository), "add", str(relative)], check=True)
        subprocess.run(["git", "-C", str(repository), "commit", "-qm", "seed"], check=True)
        original_umask = os.umask(0o077)
        try:
            subprocess.run(
                ["git", "-C", str(repository), "worktree", "add", "-q", "-b", "shared-test", str(worktree), "HEAD"],
                check=True,
            )
        finally:
            os.umask(original_umask)
        worktree.chmod(0o2775)
        return worktree, relative

    def test_private_checkout_modes_preserve_git_executable_intent(self) -> None:
        FREEZER._validate_checkout_metadata(
            self._metadata("nonexecuted", 0o600), 0o100644, os.geteuid(), "nonexecuted",
        )
        FREEZER._validate_checkout_metadata(
            self._metadata("executed", 0o700), 0o100755, os.geteuid(), "executed",
        )

    def test_receipt_verifier_accepts_private_checkout_and_installs_public_executable(self) -> None:
        relative, asset_name, git_mode, source_mode = FREEZER.TRACKED_REPO_SOURCES["receipt_verifier_binary"]
        source = self.root / relative
        write_file(source, b"#!/usr/bin/python3\nraise SystemExit(0)\n", 0o700)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "core.sharedRepository", "true"], check=True)
        subprocess.run(["git", "-C", str(self.root), "add", str(relative)], check=True)
        self.assertEqual((git_mode, source_mode, asset_name), (0o100755, 0o500, "assets/buzz-ci-verify-acceptance-receipt"))
        payload, actual_name = FREEZER._static_payload(
            self.root, "receipt_verifier_binary", {}, {},
        )
        self.assertEqual((payload, actual_name), (source.read_bytes(), asset_name))

    def test_receipt_verifier_expected_stages_accepts_private_nonexecutable_checkout(self) -> None:
        role = "receipt_verifier_expected_stages"
        relative, asset_name, git_mode, source_mode = FREEZER.TRACKED_REPO_SOURCES[role]
        source = self.root / relative
        payload = b'["capacity_zero_closed","prepare_capacity_zero"]\n'
        write_file(source, payload, 0o600)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "core.sharedRepository", "true"], check=True)
        subprocess.run(["git", "-C", str(self.root), "add", str(relative)], check=True)
        self.assertEqual(
            (git_mode, source_mode, asset_name),
            (0o100644, 0o400, "assets/buzz-ci-acceptance-expected-stages.json"),
        )
        observed, actual_name = FREEZER._static_payload(self.root, role, {}, {})
        self.assertEqual((observed, actual_name), (payload, asset_name))
        installed = self.root / "installed-verifier"
        FREEZER._write_asset(installed, payload, 0o755)
        self.assertEqual(stat.S_IMODE(installed.stat().st_mode), 0o755)

    def test_checkout_executable_class_and_unexpected_writes_are_rejected(self) -> None:
        cases = (
            ("nonexecuted-is-executable", 0o700, 0o100644, "executable class differs"),
            ("executed-is-nonexecutable", 0o600, 0o100755, "executable class differs"),
            ("nonexecuted-group-writable", 0o620, 0o100644, "unsafe permissions"),
            ("executed-world-writable", 0o702, 0o100755, "unsafe permissions"),
        )
        for name, materialized_mode, git_mode, message in cases:
            with self.subTest(name=name):
                metadata = self._metadata(name, materialized_mode)
                with self.assertRaisesRegex(ValueError, message):
                    FREEZER._validate_checkout_metadata(metadata, git_mode, os.geteuid(), name)

    def test_checkout_owner_read_access_is_required(self) -> None:
        with self.assertRaisesRegex(ValueError, "owner access differs"):
            FREEZER._validate_checkout_metadata(
                self._metadata("write-only", 0o200), 0o100644, os.geteuid(), "write-only",
            )
        with self.assertRaisesRegex(ValueError, "owner access differs"):
            FREEZER._validate_checkout_metadata(
                self._metadata("wrong-owner", 0o600), 0o100644, os.geteuid() + 1, "wrong-owner",
            )

    def test_tracked_payload_rejects_symbolic_link_shape(self) -> None:
        relative = Path("deploy/native-ci/activation/templates/static.conf")
        source = self.root / relative
        write_file(source, b"static\n", 0o600)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "core.sharedRepository", "true"], check=True)
        subprocess.run(["git", "-C", str(self.root), "add", str(relative)], check=True)
        self.assertEqual(FREEZER._tracked_payload(self.root, relative, 0o100644), b"static\n")
        target = self.root / "target.conf"
        write_file(target, b"static\n", 0o600)
        source.unlink()
        source.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "symbolic links"):
            FREEZER._tracked_payload(self.root, relative, 0o100644)

    def test_real_shared_repository_worktree_accepts_private_checkout_modes(self) -> None:
        worktree, relative = self._shared_worktree()
        source = worktree / relative
        self.assertEqual(stat.S_IMODE(worktree.stat().st_mode), 0o2775)
        self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o600)
        self.assertEqual(
            FREEZER._safe_input_directory(worktree, "source root", allow_shared_repository=True),
            worktree,
        )
        self.assertEqual(FREEZER._tracked_payload(worktree, relative, 0o100644), b"shared payload\n")

    def test_shared_repository_exception_rejects_malicious_write_and_shape_drift(self) -> None:
        worktree, relative = self._shared_worktree()
        source = worktree / relative
        source.chmod(0o620)
        with self.assertRaisesRegex(ValueError, "unsafe permissions"):
            FREEZER._tracked_payload(worktree, relative, 0o100644)
        source.chmod(0o600)

        deploy = worktree / "deploy"
        deploy.chmod(0o775)
        with self.assertRaisesRegex(ValueError, "parent shared access differs"):
            FREEZER._tracked_payload(worktree, relative, 0o100644)
        deploy.chmod(0o755)

        hardlink = worktree / "hardlink"
        os.link(source, hardlink)
        with self.assertRaisesRegex(ValueError, "unsafe regular file"):
            FREEZER._tracked_payload(worktree, relative, 0o100644)
        hardlink.unlink()

        for mode, message in ((0o775, "mode must be 2775"), (0o3775, "mode must be 2775"), (0o2777, "must not be group or world writable")):
            with self.subTest(mode=oct(mode)):
                worktree.chmod(mode)
                with self.assertRaisesRegex(ValueError, message):
                    FREEZER._safe_input_directory(worktree, "source root", allow_shared_repository=True)
        worktree.chmod(0o2775)
        subprocess.run(["git", "-C", str(worktree), "config", "core.sharedRepository", "group"], check=True)
        with self.assertRaisesRegex(ValueError, "core.sharedRepository=all"):
            FREEZER._safe_input_directory(worktree, "source root", allow_shared_repository=True)

        output_parent = self.root / "shared-output"
        output_parent.mkdir(mode=0o700)
        output_parent.chmod(0o2775)
        with self.assertRaisesRegex(ValueError, "must not be group or world writable"):
            FREEZER._safe_input_directory(output_parent, "output parent")

    def test_asset_writer_materializes_declared_modes_under_private_umask(self) -> None:
        original_umask = os.umask(0o077)
        try:
            for name, mode in (("private-source", 0o400), ("manifest", 0o600), ("executable", 0o500)):
                with self.subTest(name=name):
                    path = self.root / name
                    FREEZER._write_asset(path, b"payload\n", mode)
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)
        finally:
            os.umask(original_umask)


if __name__ == "__main__":
    unittest.main()

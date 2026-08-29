from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest

ACTIVATION_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ACTIVATION_ROOT))

import package as activation_package


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CONTROLLER = load_module("activation_controller", ACTIVATION_ROOT / "controller.py")
FREEZER = load_module("activation_freezer", ACTIVATION_ROOT / "freeze_package.py")

RESPONSE = b'{"status":"qualification_passed"}\n'


def write_file(path: Path, payload: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    path.chmod(mode)


class ActivationFixture:
    def __init__(self, temporary: Path) -> None:
        self.temporary = temporary
        self.root = temporary / "root"
        self.package = temporary / "package"
        self.package.mkdir(mode=0o700)
        (self.package / "assets").mkdir(mode=0o700)
        self.identity_base = 62000
        self.identities = {
            "runner": {
                "user": "buzzci-runner", "group": "buzzci-runner", "uid": 62001, "gid": 62001,
                "home": "/var/lib/buzzci/runner", "shell": "/usr/sbin/nologin",
                "supplementary_groups": ["buzzci-execd"],
            },
            "controld": {
                "user": "buzzci-controld", "group": "buzzci-controld", "uid": 62002, "gid": 62002,
                "home": "/var/lib/buzzci/controld", "shell": "/usr/sbin/nologin", "supplementary_groups": [],
            },
            "keyholder": {
                "user": "buzzci-keyholder", "group": "buzzci-keyholder", "uid": 62003, "gid": 62003,
                "home": "/var/lib/buzzci/keyholder", "shell": "/usr/sbin/nologin", "supplementary_groups": [],
            },
            "qualification": {
                "user": "buzzci-ctl", "group": "buzzci-ctl", "uid": 62004, "gid": 62004,
                "home": "/var/lib/buzzci/ctl", "shell": "/usr/sbin/nologin",
                "supplementary_groups": ["buzzci-execd"],
            },
        }
        self.access_group = {"group": "buzzci-execd", "gid": 62005, "members": ["buzzci-ctl", "buzzci-runner"]}
        self.assets: dict[str, tuple[bytes, int]] = {}
        self.entries: list[dict[str, object]] = []
        self._add_configs()
        self._add_static_assets()
        self.components = self._add_components()
        request = b'{"version":"qualification_v1"}\n'
        self.assets["assets/qualification-request.json"] = (request, 0o400)
        self.qualification = {
            "program": "/usr/libexec/buzz-ci-acceptance-ctl",
            "request_source": "assets/qualification-request.json",
            "request_sha256": activation_package.digest(request),
            "expected_response_sha256": activation_package.digest(RESPONSE),
            "timeout_seconds": 5,
            "terminate_grace_seconds": 2,
            "principal": "qualification",
        }
        self.manifest = self._manifest()
        self._write_package()
        self._write_installed_closed_configs()
        self._write_fake_systemd()

    def _asset_entry(
        self,
        role: str,
        target: str,
        staged_name: str,
        staged: bytes,
        install_mode: int,
        uid: int,
        gid: int,
        active_name: str | None = None,
        active: bytes | None = None,
    ) -> None:
        source = f"assets/{staged_name}"
        self.assets[source] = (staged, 0o400)
        entry: dict[str, object] = {
            "role": role,
            "source": source,
            "source_mode": "0400",
            "sha256": activation_package.digest(staged),
            "target": target,
            "install_mode": f"{install_mode:04o}",
            "uid": uid,
            "gid": gid,
        }
        if active_name is not None and active is not None:
            active_source = f"assets/{active_name}"
            self.assets[active_source] = (active, 0o400)
            entry.update({
                "active_source": active_source,
                "active_source_mode": "0400",
                "active_sha256": activation_package.digest(active),
            })
        self.entries.append(entry)

    def _add_configs(self) -> None:
        runner_staged = activation_package.canonical_json({"schema_version": 1, "controld_uid": 62002})
        runner_active = activation_package.canonical_json({
            "schema_version": 1,
            "controld_uid": 62002,
            "host": {
                "owner_pubkey": "11" * 32,
                "manifest_verification_key": "22" * 32,
                "relay_signer": "33" * 32,
                "broker_socket": "/run/buzzci/execd.sock",
                "broker_uid": 0,
                "executor_program": "/usr/libexec/buzz-ci-executor",
                "evidence_directory": "/var/lib/buzzci/runner/evidence",
                "journal_directory": "/var/lib/buzzci/runner/journal",
                "max_argv_items": 32,
                "max_argv_bytes": 8192,
                "max_environment_items": 32,
                "max_environment_bytes": 8192,
                "max_output_bytes": 1048576,
            },
        })
        self._asset_entry(
            "runner_config", activation_package.CONFIG_TARGETS["runner_config"], "runner-staged.json", runner_staged,
            0o600, 62001, 62001, "runner-active.json", runner_active,
        )
        controld_staged = activation_package.canonical_json({
            "schema_version": 1, "capacity": 0, "store_root": "/var/lib/buzzci/controld",
        })
        controld_active = activation_package.canonical_json({
            "schema_version": 1, "capacity": 1, "store_root": "/var/lib/buzzci/controld",
            "relay_url": "wss://relay.example.invalid", "runner_socket": "/run/buzzci/runner-control.sock",
            "keyholder_socket": "/run/buzzci/keyholder.sock",
            "keyholder_uid": 62003, "keyholder_gid": 62003,
            "keyholder_selectors": {
                "ci_event": {"public_key": "44" * 32, "generation": 1},
                "nip98": {"public_key": "55" * 32, "generation": 2},
                "manifest": {"public_key": "66" * 32, "generation": 3},
            },
            "keyholder_timeout_millis": 5000, "keyholder_transport_attempts": 2,
        })
        self._asset_entry(
            "controld_config", activation_package.CONFIG_TARGETS["controld_config"], "controld-staged.json", controld_staged,
            0o600, 62002, 62002, "controld-active.json", controld_active,
        )
        keyholder = activation_package.canonical_json({
            "schema_version": 1,
            "peer": {"uid": 62002, "gid": 62002},
            "selectors": {
                "ci_event": {"public_key": "44" * 32, "generation": 1},
                "nip98": {"public_key": "55" * 32, "generation": 2},
                "manifest": {"public_key": "66" * 32, "generation": 3},
            },
            "nip98_origin": "https://relay.example.invalid",
        })
        self._asset_entry(
            "keyholder_config", activation_package.CONFIG_TARGETS["keyholder_config"], "keyholder.json", keyholder,
            0o600, 62003, 62003,
        )

    def _render_sysusers(self) -> bytes:
        return FREEZER._render_sysusers(
            (ACTIVATION_ROOT / "templates/buzzci-activation.sysusers.in").read_bytes(),
            self.identities,
            self.access_group,
        )

    def _add_static_assets(self) -> None:
        source_map = {
            "sysusers": ("buzzci-activation.conf", self._render_sysusers()),
            "tmpfiles": ("buzzci-activation.tmpfiles", (ACTIVATION_ROOT / "templates/buzzci-activation.tmpfiles").read_bytes()),
            "capacity_target": ("buzz-ci-capacity-one.target", (ACTIVATION_ROOT / "templates/buzz-ci-capacity-one.target").read_bytes()),
            "execd_socket_dropin": ("20-execd-capacity-one.conf", (ACTIVATION_ROOT / "templates/20-execd-capacity-one.conf").read_bytes()),
            "runner_service_dropin": ("20-runner-capacity-one.conf", (ACTIVATION_ROOT / "templates/20-runner-capacity-one.conf").read_bytes()),
            "controld_service_dropin": ("20-controld-capacity-one.conf", (ACTIVATION_ROOT / "templates/20-controld-capacity-one.conf").read_bytes()),
            "keyholder_socket_dropin": ("20-keyholder-capacity-one.conf", (ACTIVATION_ROOT / "templates/20-keyholder-capacity-one.conf").read_bytes()),
        }
        for role, (name, payload) in source_map.items():
            self._asset_entry(role, activation_package.STATIC_TARGETS[role], name, payload, 0o644, 0, 0)

    def _add_components(self) -> list[dict[str, object]]:
        components: list[dict[str, object]] = []
        for index, (name, (binary_path, unit)) in enumerate(activation_package.COMPONENTS.items(), start=1):
            if name == "qualification":
                binary = b"#!/usr/bin/python3\nimport sys\nsys.stdin.buffer.read()\nsys.stdout.buffer.write(" + repr(RESPONSE).encode() + b")\n"
            else:
                binary = f"{name}-binary\n".encode()
            write_file(self.root / binary_path.lstrip("/"), binary, 0o755)
            source_commit = f"{index:x}" * 40
            provenance = activation_package.canonical_json({
                "binary": Path(binary_path).name,
                "profile": "release",
                "schema": activation_package.PROVENANCE_SCHEMA,
                "sha256": activation_package.digest(binary),
                "source_commit": source_commit,
            })
            provenance_source = f"assets/{name}-provenance.json"
            self.assets[provenance_source] = (provenance, 0o400)
            components.append({
                "name": name,
                "binary_path": binary_path,
                "binary_sha256": activation_package.digest(binary),
                "source_commit": source_commit,
                "provenance_source": provenance_source,
                "provenance_sha256": activation_package.digest(provenance),
                "uid": 0,
                "gid": 0,
                "mode": "0755",
                "unit": unit,
            })
        return components

    def _manifest(self) -> dict[str, object]:
        draft: dict[str, object] = {
            "schema": activation_package.DRAFT_SCHEMA,
            "source_commit": "a" * 40,
            "default_state": {"capacity": 0, "enabled": False, "active": False, "provisioned": False},
            "identities": self.identities,
            "access_group": self.access_group,
            "components": self.components,
            "entries": self.entries,
            "systemd": {
                "start_order": activation_package.START_ORDER,
                "stop_order": activation_package.STOP_ORDER,
                "persistent_unit": activation_package.PERSISTENT_UNIT,
                "stage_capacity": 0,
                "active_capacity": 1,
            },
            "socket_policy": activation_package.SOCKET_POLICY,
            "qualification": self.qualification,
            "package_uid": 0,
            "package_gid": 0,
        }
        package_digest = activation_package.digest(activation_package.canonical_json(draft))
        manifest = copy.deepcopy(draft)
        manifest["schema"] = activation_package.MANIFEST_SCHEMA
        manifest["package_digest"] = package_digest
        manifest["activation_id"] = f"buzz-ci-capacity-one-{'a' * 12}-{package_digest[:12]}"
        activation_package.validate_manifest(manifest)
        return manifest

    def _write_package(self) -> None:
        for source, (payload, mode) in self.assets.items():
            write_file(self.package / source, payload, mode)
        write_file(
            self.package / "activation-manifest.json",
            activation_package.canonical_json(self.manifest),
            0o600,
        )

    def _write_installed_closed_configs(self) -> None:
        for entry in self.manifest["entries"]:
            if entry["role"] not in {"runner_config", "controld_config"}:
                continue
            write_file(
                self.root / entry["target"].lstrip("/"),
                self.assets[entry["source"]][0],
                0o600,
            )

    def _write_fake_systemd(self) -> None:
        units: dict[str, object] = {}
        for name in sorted(set(activation_package.START_ORDER + activation_package.STOP_ORDER)):
            units[name] = {
                "LoadState": "loaded",
                "ActiveState": "inactive",
                "SubState": "dead",
                "UnitFileState": "disabled" if name.endswith(".socket") else "static",
            }
        state = {"schema": "buzz-ci-fake-systemd-v1", "units": units, "identities": {}, "groups": {}, "sockets": {}}
        self.fake_state = self.root / "var/lib/buzzci/activation-controller/fake-systemd-v1.json"
        write_file(self.fake_state, activation_package.canonical_json(state), 0o600)
        self.fake_state.parent.chmod(0o700)

    def load(self):
        manifest, payloads = CONTROLLER.load_package(self.package, live=False)
        driver = CONTROLLER.FakeSystemd(
            self.root, self.fake_state, manifest["identities"], manifest["access_group"], manifest["socket_policy"],
        )
        return manifest, payloads, driver


class ActivationControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.fixture = ActivationFixture(Path(self.temporary.name))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_full_fake_root_lifecycle_is_dormant_then_capacity_one_then_closed(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        checked = CONTROLLER.check_current(manifest, self.fixture.root, driver)
        self.assertEqual(checked["state"], "dormant")

        staged = CONTROLLER.stage(manifest, payloads, self.fixture.root, driver)
        self.assertEqual((staged["state"], staged["capacity"]), ("staged_zero", 0))
        self.assertEqual(CONTROLLER.stage(manifest, payloads, self.fixture.root, driver)["status"], "unchanged")
        self.assertEqual(CONTROLLER.check_current(manifest, self.fixture.root, driver)["state"], "staged_zero")

        activated = CONTROLLER.activate(manifest, payloads, self.fixture.root, driver)
        self.assertEqual((activated["state"], activated["capacity"]), ("active_one", 1))
        self.assertEqual(activated["qualification"]["status"], "passed")
        self.assertEqual(CONTROLLER.activate(manifest, payloads, self.fixture.root, driver)["status"], "unchanged")
        self.assertEqual(CONTROLLER.qualify(manifest, payloads, self.fixture.root, driver)["status"], "qualified")

        rolled_back = CONTROLLER.rollback(manifest, self.fixture.root, driver)
        self.assertEqual((rolled_back["state"], rolled_back["capacity"]), ("rolled_back", 0))
        self.assertEqual(CONTROLLER.rollback(manifest, self.fixture.root, driver)["status"], "unchanged")
        self.assertEqual(
            rolled_back["retained_principals"],
            ["buzzci-controld", "buzzci-ctl", "buzzci-keyholder", "buzzci-runner"],
        )
        for entry in manifest["entries"]:
            target = self.fixture.root / entry["target"].lstrip("/")
            if entry["role"] in {"runner_config", "controld_config"}:
                self.assertEqual(target.read_bytes(), payloads[entry["source"]])
            else:
                self.assertFalse(target.exists())

    def test_failed_qualification_returns_to_staged_capacity_zero(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver)
        manifest["qualification"]["expected_response_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "qualification response digest differs"):
            CONTROLLER.activate(manifest, payloads, self.fixture.root, driver)
        receipt = CONTROLLER._read_receipt(self.fixture.root)
        self.assertEqual(receipt["state"], "staged_zero")
        self.assertEqual(CONTROLLER._zero_readback(driver)[activation_package.PERSISTENT_UNIT]["ActiveState"], "inactive")
        CONTROLLER._verify_phase(manifest, self.fixture.root, "staged")

    def test_rollback_refuses_drift_before_systemd_mutation(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver)
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

    def test_keyholder_private_fields_are_rejected(self) -> None:
        manifest, payloads, _driver = self.fixture.load()
        entry = next(item for item in manifest["entries"] if item["role"] == "keyholder_config")
        payloads[entry["source"]] = activation_package.canonical_json({
            "schema_version": 1, "socket": "/run/buzzci/keyholder.sock", "private_key": "forbidden",
        })
        with self.assertRaisesRegex(ValueError, "cannot contain"):
            CONTROLLER._validate_phase_configs(manifest, payloads)

    def test_keyholder_and_controld_configs_compose_without_local_secret_descriptors(self) -> None:
        manifest, payloads, _driver = self.fixture.load()
        entries = {entry["role"]: entry for entry in manifest["entries"]}
        keyholder = json.loads(payloads[entries["keyholder_config"]["source"]])
        controld = json.loads(payloads[entries["controld_config"]["active_source"]])
        self.assertEqual(set(keyholder), {"schema_version", "peer", "selectors", "nip98_origin"})
        self.assertEqual(keyholder["peer"], {"uid": 62002, "gid": 62002})
        self.assertEqual(controld["keyholder_selectors"], keyholder["selectors"])
        self.assertEqual((controld["keyholder_uid"], controld["keyholder_gid"]), (62003, 62003))
        self.assertNotIn("key_descriptor", activation_package.canonical_json(keyholder).decode())
        self.assertNotIn("private", activation_package.canonical_json(controld).decode())

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
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver)
        state = json.loads(self.fixture.fake_state.read_bytes())
        self.assertEqual(
            state["groups"],
            {"buzzci-execd": {"group": "buzzci-execd", "gid": 62005, "members": ["buzzci-ctl", "buzzci-runner"]}},
        )
        self.assertEqual(state["identities"]["buzzci-runner"]["supplementary_groups"], ["buzzci-execd"])
        self.assertEqual(state["identities"]["buzzci-ctl"]["supplementary_groups"], ["buzzci-execd"])
        self.assertEqual(state["identities"]["buzzci-controld"]["supplementary_groups"], [])
        CONTROLLER.activate(manifest, payloads, self.fixture.root, driver)
        self.assertEqual(driver.socket(manifest["socket_policy"]["execd"])["gid"], 62005)

    def test_executor_program_and_installed_binary_are_manifest_bound(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        runner = next(entry for entry in manifest["entries"] if entry["role"] == "runner_config")
        active = json.loads(payloads[runner["active_source"]])
        active["host"]["executor_program"] = "/usr/bin/env"
        payloads[runner["active_source"]] = activation_package.canonical_json(active)
        with self.assertRaisesRegex(ValueError, "packaged executor component"):
            CONTROLLER._validate_phase_configs(manifest, payloads)

        manifest, _payloads, driver = self.fixture.load()
        executor = next(item for item in manifest["components"] if item["name"] == "executor")
        program = self.fixture.root / executor["binary_path"].lstrip("/")
        program.write_bytes(b"drifted-executor\n")
        program.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "target content drift"):
            CONTROLLER.preflight(manifest, self.fixture.root, driver, require_dormant=True)

    def test_qualification_process_is_hardened_and_manifest_principal_is_exact(self) -> None:
        manifest, payloads, _driver = self.fixture.load()
        component = next(item for item in manifest["components"] if item["name"] == "qualification")
        program = self.fixture.root / component["binary_path"].lstrip("/")
        script = b"""#!/usr/bin/python3
import json
import os
status = open('/proc/self/status', encoding='utf-8').read().splitlines()
no_new_privs = int(next(line.split()[1] for line in status if line.startswith('NoNewPrivs:')))
print(json.dumps({'egid': os.getegid(), 'euid': os.geteuid(), 'leaked': os.getenv('ACTIVATION_TEST_LEAK'), 'no_new_privs': no_new_privs}, sort_keys=True, separators=(',', ':')))
"""
        write_file(program, script, 0o755)
        component["binary_sha256"] = activation_package.digest(script)
        expected = activation_package.canonical_json({
            "egid": os.getegid(), "euid": os.geteuid(), "leaked": None, "no_new_privs": 1,
        })
        manifest["qualification"]["expected_response_sha256"] = activation_package.digest(expected)
        os.environ["ACTIVATION_TEST_LEAK"] = "must-not-cross-exec"
        try:
            self.assertEqual(CONTROLLER._run_qualification(manifest, payloads, self.fixture.root)["status"], "passed")
        finally:
            del os.environ["ACTIVATION_TEST_LEAK"]
        self.assertEqual(
            CONTROLLER._qualification_credentials(manifest, Path("/")),
            {"user": 62004, "group": 62004, "extra_groups": [62005]},
        )

    def test_qualification_timeout_kills_descendant_process_group(self) -> None:
        manifest, payloads, _driver = self.fixture.load()
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
        with self.assertRaisesRegex(ValueError, "timed out"):
            CONTROLLER._run_qualification(manifest, payloads, self.fixture.root)
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
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver)
        manifest["qualification"]["expected_response_sha256"] = "0" * 64
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
        with self.assertRaisesRegex(ValueError, "qualification response digest differs"):
            CONTROLLER.activate(manifest, payloads, self.fixture.root, driver)
        self.assertEqual(stop_attempts, activation_package.STOP_ORDER + [activation_package.PERSISTENT_UNIT])
        self.assertEqual(CONTROLLER._verify_phase(manifest, self.fixture.root, "staged")["controld_config"], "staged")
        receipt = CONTROLLER._read_receipt(self.fixture.root)
        self.assertEqual(receipt["state"], "rollback_failed")
        self.assertIn("capacity-zero readback", receipt["last_error"])

    def test_partial_explicit_rollback_attempts_all_stops_and_persists_failure(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver)
        CONTROLLER.activate(manifest, payloads, self.fixture.root, driver)
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
        self.assertEqual(stop_attempts, activation_package.STOP_ORDER + [activation_package.PERSISTENT_UNIT])
        receipt = CONTROLLER._read_receipt(self.fixture.root)
        self.assertEqual(receipt["state"], "rollback_failed")
        self.assertIn("capacity-zero readback", receipt["last_error"])

    def test_qualification_executable_mode_drift_is_rejected(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        qualification = next(item for item in manifest["components"] if item["name"] == "qualification")
        program = self.fixture.root / qualification["binary_path"].lstrip("/")
        program.chmod(0o700)
        with self.assertRaisesRegex(ValueError, "target metadata drift"):
            CONTROLLER.preflight(manifest, self.fixture.root, driver, require_dormant=True)


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

    def test_private_checkout_modes_preserve_git_executable_intent(self) -> None:
        FREEZER._validate_checkout_metadata(
            self._metadata("nonexecuted", 0o600), 0o100644, os.geteuid(), "nonexecuted",
        )
        FREEZER._validate_checkout_metadata(
            self._metadata("executed", 0o700), 0o100755, os.geteuid(), "executed",
        )

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

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
            "job": {
                "user": "buzzci-job", "group": "buzzci-job", "uid": 62006, "gid": 62006,
                "home": "/var/empty", "shell": "/usr/sbin/nologin", "supplementary_groups": [],
            },
        }
        self.access_group = {"group": "buzzci-execd", "gid": 62005, "members": ["buzzci-ctl", "buzzci-runner"]}
        self.assets: dict[str, tuple[bytes, int]] = {}
        self.entries: list[dict[str, object]] = []
        self.components = self._add_components()
        self._add_configs()
        self._add_static_assets()
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
        actor = "90" * 32
        self.acceptance_template = {
            "actor": {"public_key": actor, "generation": 10},
            "run_event": [0, actor, 1_800_000_000, 46_100, [["h", "capacity-one"]], "{\"type\":\"run\"}"],
            "grant_event": [0, actor, 1_800_000_001, 46_107, [["h", "capacity-one"]], "{\"type\":\"grant\"}"],
            "rerun_event": [0, actor, 1_800_000_010, 46_100, [["h", "capacity-one"]], "{\"type\":\"rerun\"}"],
            "tombstone_event": [0, actor, 1_800_000_020, 5, [["e", "08" * 32]], ""],
        }
        self.manifest = self._manifest()
        self.scenario = self._scenario()
        self.binding = CONTROLLER._acceptance_binding(self.manifest, self.scenario)
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
        lane_manifest = {
            "schema_version": 1,
            "lane_id": "10" * 32,
            "lane_epoch": 4,
            "admission_verifying_key": "20" * 32,
            "admission_key_generation": 9,
            "broker_build_identity": "30" * 32,
            "host_profile_digest": "40" * 32,
            "suite_identity": "50" * 32,
            "isolation_profile_digest": "60" * 32,
            "not_before": 1,
            "expires_at": 4_102_444_800,
            "max_wall_timeout_seconds": 300,
        }
        lane_manifest_digest = activation_package.lane_manifest_digest(lane_manifest)
        runner_staged = activation_package.canonical_json({
            "schema_version": 2, "controld_uid": 62002, "controld_gid": 62002, "mode": "dormant",
        })
        runner_active = activation_package.canonical_json({
            "schema_version": 2,
            "controld_uid": 62002,
            "controld_gid": 62002,
            "mode": "v2_proxy",
            "execd_socket": "/run/buzzci/execd.sock",
            "execd_uid": 0,
            "execd_gid": 0,
            "replay_journal": "/var/lib/buzzci/runner/v2-replay.json",
            "connect_timeout_millis": 1000,
            "io_timeout_millis": 5000,
            "transport_attempts": 3,
            "retry_delay_millis": 100,
            "lane_manifest_digest": lane_manifest_digest,
            "lane_epoch": lane_manifest["lane_epoch"],
            "admission_key_generation": lane_manifest["admission_key_generation"],
            "isolation_profile_digest": lane_manifest["isolation_profile_digest"],
            "audience_digest": "70" * 32,
        })
        self._asset_entry(
            "runner_config", activation_package.CONFIG_TARGETS["runner_config"], "runner-staged.json", runner_staged,
            0o600, 62001, 62001, "runner-active.json", runner_active,
        )
        executor = next(item for item in self.components if item["name"] == "executor")
        execd_config = activation_package.canonical_json({
            "schema_version": 2,
            "enabled_protocol": 2,
            "capacity": 1,
            "identities": {
                "execd_uid": 0, "execd_gid": 0,
                "runner_uid": 62001, "runner_gid": 62001,
                "control_uid": 62004, "control_gid": 62004,
                "job_uid": 62006, "job_gid": 62006,
                "access_group": "buzzci-execd", "access_group_gid": 62005,
                "access_group_members": ["buzzci-ctl", "buzzci-runner"],
            },
            "paths": {
                "intent_root": "/var/lib/buzzci/execd-v2/intents",
                "binding_root": "/var/lib/buzzci/execd-v2/bindings",
                "evidence_root": "/var/lib/buzzci/execd-v2/evidence",
                "teardown_root": "/var/lib/buzzci/execd-v2/teardown",
                "attempt_root": "/var/lib/buzzci/execd-v2/attempts",
                "executor_socket": "/run/buzzci/executor.sock",
            },
            "lane_manifest": lane_manifest,
            "lane_manifest_digest": lane_manifest_digest,
            "executor": {
                "path": "/usr/libexec/buzz-ci-executor",
                "sha256": executor["binary_sha256"],
                "source_commit": executor["source_commit"],
                "uid": 0, "gid": 0, "mode": 0o755,
            },
        })
        self._asset_entry(
            "execd_config", activation_package.CONFIG_TARGETS["execd_config"], "execd-v2.json",
            execd_config, 0o600, 0, 0,
        )
        controld_staged = activation_package.canonical_json({
            "schema_version": 1, "capacity": 0, "store_root": "/var/lib/buzzci/controld",
            "acceptance_binding": activation_package.ACCEPTANCE_BINDING_PATH,
        })
        controld_active = activation_package.canonical_json({
            "schema_version": 1, "capacity": 1, "store_root": "/var/lib/buzzci/controld",
            "acceptance_binding": activation_package.ACCEPTANCE_BINDING_PATH,
            "relay_url": "wss://relay.example.invalid", "relay_http_origin": "https://relay.example.invalid",
            "channel_id": "12345678-1234-4abc-8def-123456789abc", "poll_interval_millis": 1000,
            "runner_socket": "/run/buzzci/runner-control.sock", "runner_uid": 62001, "runner_gid": 62001,
            "runner_connect_timeout_millis": 1000, "runner_io_timeout_millis": 5000,
            "runner_transport_attempts": 3, "lane_manifest_digest": lane_manifest_digest,
            "lane_epoch": lane_manifest["lane_epoch"], "audience_digest": "70" * 32,
            "isolation_profile_digest": lane_manifest["isolation_profile_digest"],
            "workflow_id": "capacity-one", "workflow_digest": "80" * 32,
            "jobs": [{
                "job_id": "capacity-one-fixture", "name": "capacity-one-fixture", "required": True,
                "skip_policy": "forbid", "selected_job_instance": "capacity-one-fixture",
                "also_reruns": [],
                "artifacts": [{
                    "artifact_id": "result", "name": "result.json", "media_type": "application/json",
                    "relative_name": "result.json", "max_bytes": 32768,
                }],
            }],
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
            "controld_acceptance_socket": ("buzz-ci-controld-acceptance.socket", (ACTIVATION_ROOT / "templates/buzz-ci-controld-acceptance.socket").read_bytes()),
            "acceptance_control_socket": ("buzz-ci-acceptance-control.socket", (ACTIVATION_ROOT / "templates/buzz-ci-acceptance-control.socket").read_bytes()),
            "acceptance_control_service": ("buzz-ci-acceptance-control.service", (ACTIVATION_ROOT / "templates/buzz-ci-acceptance-control.service").read_bytes()),
            "acceptance_tmpfiles": ("buzzci-acceptance.tmpfiles", (ACTIVATION_ROOT / "templates/buzzci-acceptance.tmpfiles").read_bytes()),
            "execd_socket_dropin": ("20-execd-capacity-one.conf", (ACTIVATION_ROOT / "templates/20-execd-capacity-one.conf").read_bytes()),
            "runner_service_dropin": ("20-runner-capacity-one.conf", (ACTIVATION_ROOT / "templates/20-runner-capacity-one.conf").read_bytes()),
            "controld_service_dropin": ("20-controld-capacity-one.conf", (ACTIVATION_ROOT / "templates/20-controld-capacity-one.conf").read_bytes()),
            "keyholder_socket_dropin": ("20-keyholder-capacity-one.conf", (ACTIVATION_ROOT / "templates/20-keyholder-capacity-one.conf").read_bytes()),
        }
        for role, (name, payload) in source_map.items():
            self._asset_entry(role, activation_package.STATIC_TARGETS[role], name, payload, 0o644, 0, 0)
        for role, name, path, install_mode in (
            ("activation_controller", "buzz-ci-activation-controller", ACTIVATION_ROOT / "controller.py", 0o755),
            ("activation_package_module", "buzz_ci_activation_package.py", ACTIVATION_ROOT / "package.py", 0o644),
        ):
            payload = path.read_bytes()
            self._asset_entry(role, activation_package.STATIC_TARGETS[role], name, payload, install_mode, 0, 0)
            self.entries[-1]["source_mode"] = "0500"
            self.assets[self.entries[-1]["source"]] = (payload, 0o500)

    def _add_components(self) -> list[dict[str, object]]:
        components: list[dict[str, object]] = []
        for index, (name, (binary_path, unit)) in enumerate(activation_package.COMPONENTS.items(), start=1):
            if name == "qualification":
                binary = b"#!/usr/bin/python3\nimport sys\nsys.stdin.buffer.read()\nsys.stdout.buffer.write(" + repr(RESPONSE).encode() + b")\n"
            elif name == "receipt_verifier":
                binary = b"#!/usr/bin/python3\nraise SystemExit(0)\n"
            else:
                binary = f"{name}-binary\n".encode()
            if name not in set(activation_package.INSTALLABLE_COMPONENT_ROLES.values()):
                write_file(self.root / binary_path.lstrip("/"), binary, 0o755)
            source_commit = "a" * 40 if name == "receipt_verifier" else f"{index:x}" * 40
            provenance = activation_package.canonical_json({
                "binary": Path(binary_path).name,
                "profile": "release",
                "schema": activation_package.PROVENANCE_SCHEMA,
                "sha256": activation_package.digest(binary),
                "source_commit": source_commit,
            })
            provenance_source = (
                FREEZER.TRACKED_COMPONENT_PROVENANCE[name]
                if name in FREEZER.TRACKED_COMPONENT_PROVENANCE
                else f"assets/{name}-provenance.json"
            )
            self.assets[provenance_source] = (provenance, 0o400)
            install_role = next((role for role, component_name in activation_package.INSTALLABLE_COMPONENT_ROLES.items() if component_name == name), None)
            if install_role is not None:
                self._asset_entry(
                    install_role, binary_path, f"{name}.bin", binary, 0o755, 0, 0,
                )
                self.entries[-1]["source_mode"] = "0500"
                self.assets[self.entries[-1]["source"]] = (binary, 0o500)
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

    def _scenario(self) -> dict[str, object]:
        endpoint = {"program": "/usr/libexec/buzz-ci-capacity-one-driver", "args": []}
        grant_event_id = activation_package.digest(json.dumps(
            self.acceptance_template["grant_event"], ensure_ascii=False, separators=(",", ":"),
        ).encode())
        return {
            "schema_version": "buzz-ci-capacity-one-scenario/v1",
            "fixture": {
                "integrated_candidate_sha": self.manifest["source_commit"],
                "activation_id": self.manifest["activation_id"],
                "activation_package_digest": self.manifest["package_digest"],
                "run_id": "1" * 32,
                "job_id": "capacity-one-fixture",
                "request_digest": "2" * 64,
                "manifest_digest": "3" * 64,
                "source_oid": "a" * 40,
                "approval_id": "4" * 32,
                "grant_event_id": grant_event_id,
                "grant_digest": "6" * 64,
                "approved_by": "7" * 64,
                "export_subject": "8" * 64,
                "export_authorization_digest": "9" * 64,
                "controller_generation": 7,
                "runner_generation": 11,
                "expected_log": {"name": "job.log", "sha256": "a" * 64, "bytes": 10},
                "expected_artifacts": [{"name": "result.json", "sha256": "b" * 64, "bytes": 20}],
            },
            "driver": {
                "control": endpoint, "observe": endpoint, "export": endpoint,
                "controller_process": endpoint, "runner_process": endpoint, "timeout_seconds": 120,
            },
        }

    def _manifest(self) -> dict[str, object]:
        draft: dict[str, object] = {
            "schema": activation_package.DRAFT_SCHEMA,
            "source_commit": "a" * 40,
            "default_state": {"capacity": 0, "enabled": False, "active": False, "provisioned": False},
            "identities": self.identities,
            "access_group": self.access_group,
            "acceptance_template": self.acceptance_template,
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
        keyholder = {
            "schema_version": 1,
            "peer": {
                "uid": 62002, "gid": 62002,
                "allowed_operations": activation_package.KEYHOLDER_ALLOWED_OPERATIONS,
            },
            "selectors": {
                "ci_event": {"public_key": "44" * 32, "generation": 1},
                "nip98": {"public_key": "55" * 32, "generation": 2},
                "manifest": {"public_key": "66" * 32, "generation": 3},
            },
            "nip98_origin": "https://relay.example.invalid",
            "acceptance": {
                "binding_receipt_path": activation_package.ACCEPTANCE_BINDING_PATH,
                "credential_selector": "acceptance-actor.key",
            },
        }
        write_file(
            self.root / activation_package.KEYHOLDER_CONFIG_PATH.lstrip("/"),
            activation_package.canonical_json(keyholder),
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

    def test_full_fake_root_lifecycle_is_dormant_then_capacity_one_then_closed(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        checked = CONTROLLER.check_current(manifest, self.fixture.root, driver)
        self.assertEqual(checked["state"], "dormant")

        staged = CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        self.assertEqual((staged["state"], staged["capacity"]), ("staged_zero", 0))
        self.assertEqual(CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)["status"], "unchanged")
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
            ["buzzci-controld", "buzzci-ctl", "buzzci-job", "buzzci-keyholder", "buzzci-runner"],
        )
        for entry in manifest["entries"]:
            target = self.fixture.root / entry["target"].lstrip("/")
            if entry["role"] in {"runner_config", "controld_config"}:
                self.assertEqual(target.read_bytes(), payloads[entry["source"]])
            else:
                self.assertFalse(target.exists())

    def test_manifest_schema_mirrors_fixed_package_counts_and_systemd_abi(self) -> None:
        schema = json.loads((ACTIVATION_ROOT / "activation-manifest.schema.json").read_bytes())
        properties = schema["properties"]
        self.assertEqual((properties["components"]["minItems"], properties["components"]["maxItems"]), (len(activation_package.COMPONENTS), len(activation_package.COMPONENTS)))
        expected_entries = len(activation_package.CONFIG_TARGETS) + len(activation_package.STATIC_TARGETS)
        self.assertEqual((properties["entries"]["minItems"], properties["entries"]["maxItems"]), (expected_entries, expected_entries))
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
            "7818b9104369a86274a3f1f5a20f9929d697de11f1427a3b93081fb4fd73d7a8",
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
        self.assertEqual(list(self.fixture.binding), [
            "schema_version", "activation_id", "activation_package_digest", "scenario_sha256",
            "peer_uid", "peer_gid", "timeout_millis", "fixture", "acceptance",
        ])
        self.assertEqual(list(self.fixture.binding["acceptance"]), [
            "actor", "scenario_sha256", "run_event", "grant_event", "rerun_event", "tombstone_event",
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

    def test_fixed_zero_actions_are_bound_idempotent_and_prove_without_writes(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        CONTROLLER.activate(manifest, payloads, self.fixture.root, driver)

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

    def test_zero_wire_rejects_order_generation_and_replay_drift(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        CONTROLLER.activate(manifest, payloads, self.fixture.root, driver)
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
        CONTROLLER.activate(manifest, payloads, self.fixture.root, driver)
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
        CONTROLLER.activate(manifest, payloads, self.fixture.root, driver)
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
            (self.fixture.binding["peer_uid"], self.fixture.binding["peer_gid"]),
            (self.fixture.identities["qualification"]["uid"], self.fixture.identities["qualification"]["gid"]),
        )
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        different = copy.deepcopy(self.fixture.binding)
        different["scenario_sha256"] = "c" * 64
        different["acceptance"]["scenario_sha256"] = "c" * 64
        with self.assertRaisesRegex(ValueError, "scenario differs"):
            CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, different)

    def test_rollback_restores_enabled_listening_execd_baseline(self) -> None:
        state = json.loads(self.fixture.fake_state.read_bytes())
        state["units"]["buzz-ci-execd.socket"].update({
            "ActiveState": "active", "SubState": "listening", "UnitFileState": "enabled",
        })
        write_file(self.fixture.fake_state, activation_package.canonical_json(state), 0o600)
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        CONTROLLER.activate(manifest, payloads, self.fixture.root, driver)
        prepare, prepare_sha = self.parsed_zero_request("prepare-qualification-zero", "c")
        CONTROLLER._prepare_qualification_zero(manifest, payloads, self.fixture.root, driver, prepare, prepare_sha)
        finalize, finalize_sha = self.parsed_zero_request("finalize-qualification-zero", "d")
        CONTROLLER._finalize_qualification_zero(manifest, payloads, self.fixture.root, driver, finalize, finalize_sha)
        rolled_back = CONTROLLER.rollback(manifest, self.fixture.root, driver)
        self.assertEqual(
            (rolled_back["units"]["buzz-ci-execd.socket"]["ActiveState"], rolled_back["units"]["buzz-ci-execd.socket"]["UnitFileState"]),
            ("active", "enabled"),
        )
        self.assertEqual(driver.socket(manifest["socket_policy"]["execd"])["path"], "/run/buzzci/execd.sock")

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
            CONTROLLER._staged_zero_readback(manifest, driver)["units"][activation_package.PERSISTENT_UNIT]["ActiveState"],
            "inactive",
        )
        CONTROLLER._verify_phase(manifest, self.fixture.root, "staged")

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
        value = json.loads(target.read_bytes())
        value["selectors"]["ci_event"]["generation"] += 1
        write_file(target, activation_package.canonical_json(value), 0o600)
        with self.assertRaisesRegex(ValueError, "selectors differ from active controld"):
            CONTROLLER.preflight(manifest, self.fixture.root, driver, require_dormant=True, payloads=payloads)
        write_file(target, activation_package.canonical_json(value), 0o640)
        with self.assertRaisesRegex(ValueError, "metadata differs"):
            CONTROLLER.preflight(manifest, self.fixture.root, driver, require_dormant=True, payloads=payloads)

    def test_public_acceptance_template_omits_scenario_and_binds_event_ids(self) -> None:
        manifest, _payloads, _driver = self.fixture.load()
        template = manifest["acceptance_template"]
        self.assertNotIn("scenario_sha256", template)
        for field in ("run_event", "grant_event", "rerun_event", "tombstone_event"):
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
        CONTROLLER.activate(manifest, payloads, self.fixture.root, driver)
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

        self.assertEqual((runner["target"], runner["install_mode"]), ("/etc/buzzci/runner-v2.json", "0600"))
        self.assertEqual((execd["target"], execd["install_mode"], execd["uid"], execd["gid"]), ("/etc/buzzci/execd-v2.json", "0600", 0, 0))
        self.assertEqual(staged, {"schema_version": 2, "controld_uid": 62002, "controld_gid": 62002, "mode": "dormant"})
        self.assertEqual((active["mode"], active["execd_socket"], active["execd_uid"], active["execd_gid"]), ("v2_proxy", "/run/buzzci/execd.sock", 0, 0))
        self.assertEqual((broker["enabled_protocol"], broker["capacity"], activation_package.REGISTER_JOB_INTENT_OPERATION), (2, 1, 9))
        self.assertEqual(broker["identities"]["access_group_members"], ["buzzci-ctl", "buzzci-runner"])
        self.assertEqual((broker["identities"]["control_uid"], broker["identities"]["job_uid"]), (62004, 62006))
        self.assertEqual(broker["paths"]["intent_root"], activation_package.EXECD_INTENT_ROOT)
        self.assertEqual(broker["paths"]["executor_socket"], activation_package.EXECUTOR_SOCKET_PATH)
        self.assertEqual(active["lane_manifest_digest"], broker["lane_manifest_digest"])
        self.assertEqual(
            activation_package.lane_manifest_digest(broker["lane_manifest"]),
            "12ede37672233a144707bc49efa5d8f86ec5803e6b9d623347472702b2c98f04",
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

    def test_execd_contract_drift_is_rejected(self) -> None:
        mutations = (
            ("peer", lambda value: value["identities"].__setitem__("runner_uid", 62004), "peer and job identities"),
            ("intent", lambda value: value["paths"].__setitem__("intent_root", "/tmp/intents"), "intent, evidence, teardown"),
            ("lane", lambda value: value.__setitem__("lane_manifest_digest", "f" * 64), "Rust contract"),
        )
        for label, mutate, message in mutations:
            with self.subTest(label=label):
                manifest, payloads, _driver = self.fixture.load()
                entry = next(item for item in manifest["entries"] if item["role"] == "execd_config")
                value = json.loads(payloads[entry["source"]])
                mutate(value)
                payloads[entry["source"]] = activation_package.canonical_json(value)
                with self.assertRaisesRegex(ValueError, message):
                    CONTROLLER._validate_phase_configs(manifest, payloads)

    def test_execd_config_and_retained_directories_install_and_rollback(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        entry = next(item for item in manifest["entries"] if item["role"] == "execd_config")
        target = self.fixture.root / entry["target"].lstrip("/")
        self.assertEqual((target.read_bytes(), stat.S_IMODE(target.stat().st_mode)), (payloads[entry["source"]], 0o600))
        self.assertEqual(stat.S_IMODE((self.fixture.root / "var/lib/buzzci").stat().st_mode), 0o711)
        for path, mode in (
            (activation_package.EXECD_INTENT_ROOT, 0o700),
            (activation_package.EXECD_BINDING_ROOT, 0o700),
            (activation_package.EXECD_EVIDENCE_ROOT, 0o700),
            (activation_package.EXECD_TEARDOWN_ROOT, 0o700),
            (activation_package.EXECD_ATTEMPT_ROOT, 0o711),
        ):
            directory = self.fixture.root / path.lstrip("/")
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), mode)
        self.assertFalse((self.fixture.root / activation_package.SECCOMP_PROFILE_PATH.lstrip("/")).exists())
        self.assertFalse((self.fixture.root / "var/lib/buzzci/activation/receipts/seccomp.json").exists())
        CONTROLLER.rollback(manifest, self.fixture.root, driver)
        self.assertFalse(target.exists())
        self.assertTrue((self.fixture.root / activation_package.EXECD_INTENT_ROOT.lstrip("/")).is_dir())

    def test_rollback_restores_preexisting_exact_execd_v2_config(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        entry = next(item for item in manifest["entries"] if item["role"] == "execd_config")
        target = self.fixture.root / entry["target"].lstrip("/")
        write_file(target, payloads[entry["source"]], 0o600)
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        CONTROLLER.rollback(manifest, self.fixture.root, driver)
        self.assertEqual((target.read_bytes(), stat.S_IMODE(target.stat().st_mode)), (payloads[entry["source"]], 0o600))

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
            ["buzz-ci-controld.service", *activation_package.STOP_ORDER, activation_package.PERSISTENT_UNIT],
        )
        self.assertEqual(CONTROLLER._verify_phase(manifest, self.fixture.root, "staged")["controld_config"], "staged")
        receipt = CONTROLLER._read_receipt(self.fixture.root)
        self.assertEqual(receipt["state"], "rollback_failed")
        self.assertIn("capacity-zero readback", receipt["last_error"])

    def test_partial_explicit_rollback_attempts_all_stops_and_persists_failure(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
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
        self.assertEqual(
            stop_attempts[:len(activation_package.STOP_ORDER) + 1],
            activation_package.STOP_ORDER + [activation_package.PERSISTENT_UNIT],
        )
        receipt = CONTROLLER._read_receipt(self.fixture.root)
        self.assertEqual(receipt["state"], "rollback_failed")
        self.assertIn("systemd prior readback", receipt["last_error"])

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

from __future__ import annotations

import copy
import base64
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
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


CONTROLLER = load_module("activation_controller", ACTIVATION_ROOT / "controller.py")
FREEZER = load_module("activation_freezer", ACTIVATION_ROOT / "freeze_package.py")
INVENTORY = load_module("activation_inventory", ACTIVATION_ROOT / "check_package_inventory.py")

QUALIFICATION_SCRIPT = b'''#!/usr/bin/python3
import json, os, sys
status=open('/proc/self/status',encoding='utf-8').read().splitlines()
if os.getenv('ACTIVATION_TEST_LEAK') is not None or int(next(line.split()[1] for line in status if line.startswith('NoNewPrivs:'))) != 1:
    raise SystemExit(3)
r=json.load(sys.stdin)
o={"schema_version":"buzz-ci-production-qualification-response/v2","status":"qualified_closed","disposition":"created","request_id":r["request_id"],"request_frame_digest":"71"*32,"qualification_receipt_digest":"72"*32,"integrated_candidate_sha":r["integrated_candidate_sha"],"activation_package_digest":r["activation_package_digest"],"fixture_digest":r["fixture_digest"],"principal_digest":r["principal_digest"],"lane_manifest_digest":r["lane_manifest_digest"],"broker_build_identity_digest":r["broker_build_identity_digest"],"host_profile_digest":r["host_profile_digest"],"suite_digest":r["suite_digest"],"isolation_profile_digest":r["isolation_profile_digest"],"seccomp_profile_digest":r["seccomp_profile_digest"],"seccomp_install_receipt_digest":"73"*32,"executor_program_digest":r["executor_program_digest"],"executor_provenance_digest":r["executor_provenance_digest"],"controller_generation":r["controller_generation"],"runner_generation":r["runner_generation"],"lane_epoch":r["lane_epoch"],"admission_key_generation":r["admission_key_generation"],"qualified_at":r["issued_at"],"request_expires_at":r["expires_at"]}
sys.stdout.write(json.dumps(o,separators=(",",":"))+"\\n")
'''


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
        self.qualification = {
            "program": "/usr/libexec/buzz-ci-production-qualification",
            "request_validity_seconds": 60,
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
        self.lane_manifest_digest = lane_manifest_digest
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
        execd_template = {
            "schema_version": 2,
            "enabled_protocol": 2,
            "capacity": 0,
            "identities": {
                "execd_uid": 0, "execd_gid": 0,
                "runner_uid": 62001, "runner_gid": 62001,
                "control_uid": 62004, "control_gid": 62004,
                "control_user": "buzzci-ctl", "control_group": "buzzci-ctl",
                "control_home": "/var/lib/buzzci/ctl", "control_shell": "/usr/sbin/nologin",
                "control_supplementary_groups": ["buzzci-execd"],
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
                "qualification_root": "/var/lib/buzzci/execd-v2/qualification",
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
            "qualification": {
                "integrated_candidate_sha": "0" * 40,
                "activation_package_digest": "0" * 64,
                "fixture_digest": "0" * 64,
                "controller_generation": 1,
                "runner_generation": 1,
            },
            "execution": {
                "schema_version": 1,
                "declaration_digest": "0" * 64,
                "workflow_id": "capacity-one",
                "workflow_digest": "80" * 32,
                "job_id": "capacity-one-fixture",
                "artifact": {
                    "artifact_id": "result", "name": "result.json", "media_type": "application/json",
                    "relative_name": "result.json", "max_bytes": 32768,
                },
                "fixture_manifest_sha256": activation_package.FIXTURE_MANIFEST_SHA256,
                "fixture_input_sha256": activation_package.FIXTURE_INPUT_SHA256,
                "fixture_script_sha256": activation_package.FIXTURE_SCRIPT_SHA256,
                "max_stdout_bytes": 32768,
                "max_stderr_bytes": 32768,
                "max_memory_bytes": 134217728,
                "max_processes": 16,
                "max_wall_seconds": 120,
            },
        }
        execd_template["qualification"]["integrated_candidate_sha"] = "a" * 40
        execd_staged = activation_package.canonical_json(execd_template)
        execd_active_template = copy.deepcopy(execd_template)
        execd_active_template["capacity"] = 1
        execd_active = activation_package.canonical_json(execd_active_template)
        self._asset_entry(
            "execd_config", activation_package.CONFIG_TARGETS["execd_config"], "execd-staged-template.json",
            execd_staged, 0o600, 0, 0, "execd-active-template.json", execd_active,
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
            "acceptance_control_socket": ("buzz-ci-acceptance-control.socket", (ACTIVATION_ROOT / "templates/buzz-ci-acceptance-control.socket").read_bytes()),
            "acceptance_control_service": ("buzz-ci-acceptance-control.service", (ACTIVATION_ROOT / "templates/buzz-ci-acceptance-control.service").read_bytes()),
            "acceptance_tmpfiles": ("buzzci-acceptance.tmpfiles", (ACTIVATION_ROOT / "templates/buzzci-acceptance.tmpfiles").read_bytes()),
            "execd_socket_dropin": ("20-execd-capacity-one.conf", (ACTIVATION_ROOT / "templates/20-execd-capacity-one.conf").read_bytes()),
            "runner_service_dropin": ("20-runner-capacity-one.conf", (ACTIVATION_ROOT / "templates/20-runner-capacity-one.conf").read_bytes()),
            "controld_service_dropin": ("20-controld-capacity-one.conf", (ACTIVATION_ROOT / "templates/20-controld-capacity-one.conf").read_bytes()),
            "keyholder_socket_dropin": ("20-keyholder-capacity-one.conf", (ACTIVATION_ROOT / "templates/20-keyholder-capacity-one.conf").read_bytes()),
            "receipt_verifier_expected_stages": (
                "buzz-ci-acceptance-expected-stages.json",
                (ACTIVATION_ROOT.parent / "acceptance/expected-stages.json").read_bytes(),
            ),
        }
        for role, (name, payload) in source_map.items():
            self._asset_entry(role, activation_package.STATIC_TARGETS[role], name, payload, 0o644, 0, 0)
        for role, relative, name, source_mode, install_mode in (
            ("fixture_manifest", "deploy/native-ci/acceptance/fixtures/fixture-manifest.json", "buzz-ci-capacity-one-fixture-manifest.json", 0o400, 0o444),
            ("fixture_input", "deploy/native-ci/acceptance/fixtures/input.txt", "buzz-ci-capacity-one-fixture-input.txt", 0o400, 0o444),
            ("fixture_script", "deploy/native-ci/acceptance/fixtures/run-fixture.sh", "buzz-ci-capacity-one-fixture", 0o500, 0o555),
            ("execd_service", "deploy/native-ci/execd/templates/buzz-ci-execd.service", "buzz-ci-execd.service", 0o400, 0o644),
            ("execd_socket", "deploy/native-ci/execd/templates/buzz-ci-execd.socket", "buzz-ci-execd.socket", 0o400, 0o644),
            ("executor_service", "deploy/native-ci/execd/templates/buzz-ci-executor.service", "buzz-ci-executor.service", 0o400, 0o644),
            ("executor_socket", "deploy/native-ci/execd/templates/buzz-ci-executor.socket", "buzz-ci-executor.socket", 0o400, 0o644),
        ):
            payload = (REPO_ROOT / relative).read_bytes()
            self._asset_entry(role, activation_package.STATIC_TARGETS[role], name, payload, install_mode, 0, 0)
            self.entries[-1]["source_mode"] = f"{source_mode:04o}"
            self.assets[self.entries[-1]["source"]] = (payload, source_mode)
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
                binary = QUALIFICATION_SCRIPT
            elif name == "receipt_verifier":
                binary = b"#!/usr/bin/python3\nraise SystemExit(0)\n"
            else:
                binary = f"{name}-binary\n".encode()
            if name not in set(activation_package.INSTALLABLE_COMPONENT_ROLES.values()):
                write_file(self.root / binary_path.lstrip("/"), binary, 0o755)
            source_commit = (
                "a" * 40 if name == "receipt_verifier"
                else activation_package.QUALIFICATION_SOURCE_COMMIT if name == "qualification"
                else "a" * 40 if name == "executor"
                else f"{index:x}" * 40
            )
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
            component: dict[str, object] = {
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
            }
            if name == "controld":
                package: dict[str, object] = {
                    "schema": "buzz-ci-controld-install-package-v1",
                    "source_commit": source_commit,
                    "entries": [],
                }
                for role, relative, target in (
                    ("service", "deploy/native-ci/controld/templates/buzz-ci-controld.service", "/etc/systemd/system/buzz-ci-controld.service"),
                    ("acceptance_socket", "deploy/native-ci/controld/templates/buzz-ci-controld-acceptance.socket", "/etc/systemd/system/buzz-ci-controld-acceptance.socket"),
                ):
                    payload = (REPO_ROOT / relative).read_bytes()
                    package["entries"].append({
                        "role": role, "target": target, "sha256": activation_package.digest(payload),
                        "install_mode": "0644", "uid": 0, "gid": 0,
                    })
                package["package_digest"] = activation_package.digest(activation_package.canonical_json(package))
                package_raw = activation_package.canonical_json(package)
                source = "assets/controld-package-manifest.json"
                self.assets[source] = (package_raw, 0o400)
                component.update({
                    "package_manifest_source": source,
                    "package_manifest_sha256": activation_package.digest(package_raw),
                    "package_digest": package["package_digest"],
                })
            components.append(component)
        return components

    def _effective_systemd(self) -> list[dict[str, object]]:
        entries = {entry["target"]: entry for entry in self.entries}
        result: list[dict[str, object]] = []
        for unit, layout in sorted(activation_package.SYSTEMD_UNIT_LAYOUT.items()):
            def record(value: dict[str, str]) -> dict[str, str]:
                entry = entries.get(value["path"])
                payload = (
                    self.assets[entry["source"]][0]
                    if entry is not None
                    else (REPO_ROOT / FREEZER.SYSTEMD_SOURCE_PATHS[value["path"]]).read_bytes()
                )
                return {**value, "sha256": activation_package.digest(payload)}

            result.append({
                "unit": unit,
                "fragment": record(layout["fragment"]),
                "drop_ins": [record(item) for item in layout["drop_ins"]],
            })
        return result

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
                "manifest_digest": self.lane_manifest_digest,
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
            "effective_systemd": self._effective_systemd(),
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
        for unit in self.manifest["effective_systemd"]:
            for record in (unit["fragment"], *unit["drop_ins"]):
                if record["owner"] == "activation":
                    continue
                write_file(
                    self.root / record["path"].lstrip("/"),
                    (REPO_ROOT / FREEZER.SYSTEMD_SOURCE_PATHS[record["path"]]).read_bytes(),
                    0o644,
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
        effective = {item["unit"]: item for item in self.manifest["effective_systemd"]}
        for name in sorted(set(activation_package.START_ORDER + activation_package.STOP_ORDER)):
            item = effective[name]
            load_state = "not-found" if item["fragment"]["owner"] == "activation" else "loaded"
            units[name] = {
                "LoadState": load_state,
                "ActiveState": "inactive",
                "SubState": "dead",
                "UnitFileState": "disabled" if load_state == "not-found" or name.endswith(".socket") else "static",
                "FragmentPath": "" if load_state == "not-found" else item["fragment"]["path"],
                "DropInPaths": [
                    record["path"] for record in item["drop_ins"]
                    if record["owner"] != "activation"
                ],
            }
        state = {"schema": "buzz-ci-fake-systemd-v1", "units": units, "identities": {}, "groups": {}, "sockets": {}}
        self.fake_state = self.root / "var/lib/buzzci/activation-controller/fake-systemd-v1.json"
        write_file(self.fake_state, activation_package.canonical_json(state), 0o600)
        self.fake_state.parent.chmod(0o700)

    def load(self):
        manifest, payloads = CONTROLLER.load_package(self.package, live=False)
        driver = CONTROLLER.FakeSystemd(
            self.root, self.fake_state, manifest["identities"], manifest["access_group"],
            manifest["socket_policy"], manifest["effective_systemd"],
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

    def test_full_fake_root_lifecycle_is_dormant_then_capacity_one_then_closed(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        checked = CONTROLLER.check_current(manifest, self.fixture.root, driver)
        self.assertEqual(checked["state"], "dormant")

        staged = CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        self.assertEqual((staged["state"], staged["capacity"]), ("staged_zero", 0))
        effective = {item["unit"]: item for item in manifest["effective_systemd"]}
        self.assertEqual(set(staged["installed_units"]), set(effective))
        for unit, expected in effective.items():
            observed = staged["installed_units"][unit]
            self.assertEqual(observed["fragment_path"], expected["fragment"]["path"])
            self.assertEqual(observed["fragment_sha256"], expected["fragment"]["sha256"])
            self.assertEqual(observed["drop_in_paths"], [item["path"] for item in expected["drop_ins"]])
            self.assertEqual(observed["drop_in_sha256"], [item["sha256"] for item in expected["drop_ins"]])
        self.assertEqual(CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)["status"], "unchanged")
        self.assertEqual(CONTROLLER.check_current(manifest, self.fixture.root, driver)["state"], "staged_zero")

        qualification, activated = self.activate_one(manifest, payloads, driver)
        self.assertEqual((qualification["state"], qualification["capacity"]), ("qualified_closed", 0))
        self.assertEqual(qualification["qualification"]["status"], "qualified_closed")
        self.assertEqual(activated["state"], "active_one")
        active = CONTROLLER.check_current(manifest, self.fixture.root, driver)
        self.assertEqual(active["readback"]["installed_units"]["buzz-ci-runner.service"]["drop_in_paths"], [
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
            else:
                self.assertFalse(target.exists())

    def test_clean_host_allows_only_package_units_absent_then_reads_back_exact_install(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        report = CONTROLLER.preflight(
            manifest, self.fixture.root, driver, require_dormant=True, payloads=payloads,
        )
        for unit in activation_package.PACKAGE_UNIT_ROLES:
            self.assertEqual(report["units"][unit]["LoadState"], "not-found")
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

    def test_dependency_drop_in_rejects_missing_and_stale_bytes(self) -> None:
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        effective = next(
            item for item in manifest["effective_systemd"]
            if item["unit"] == "buzz-ci-keyholder.service"
        )
        record = effective["drop_ins"][0]
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
            if owner in {"runner", "controld"}:
                target = f"/etc/buzzci/{'runner-v2' if owner == 'runner' else 'controld-v1'}.json"
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

        report = INVENTORY.check_inventory(packages)
        self.assertEqual((report["status"], report["packages"]), ("pass", sorted(INVENTORY.PACKAGE_SCHEMAS)))
        for category in ("binary", "config", "unit", "socket", "drop_in", "tmpfiles", "sysusers", "fixture", "receipt"):
            self.assertGreater(report["categories"].get(category, 0), 0, category)

        divergent = copy.deepcopy(packages)
        runner_config = next(item for item in divergent["runner"]["entries"] if item["target"] == "/etc/buzzci/runner-v2.json")
        runner_config["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "divergent explicitly shared"):
            INVENTORY.check_inventory(divergent)

        collision = copy.deepcopy(packages)
        socket = next(item for item in collision["controld"]["entries"] if item["target"] == "/etc/systemd/system/buzz-ci-controld-acceptance.socket")
        collision["activation"]["entries"].append(copy.deepcopy(socket))
        with self.assertRaisesRegex(ValueError, "undeclared final package ownership collision"):
            INVENTORY.check_inventory(collision)

        receipt_collision = copy.deepcopy(packages)
        receipt_collision["execd"]["install_receipt"]["path"] = INVENTORY.ACTIVATION_RECEIPT["path"]
        with self.assertRaisesRegex(ValueError, "undeclared final package ownership collision"):
            INVENTORY.check_inventory(receipt_collision)

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
        self.assertFalse((self.fixture.root / CONTROLLER.FIXED_PACKAGE_PATH.lstrip("/")).exists())
        self.assertEqual(CONTROLLER._generated_prior_readback(receipt, self.fixture.root), {
            "controld_acceptance_binding": "absent",
            "acceptance_control_config": "absent",
            "acceptance_driver_config": "absent",
            "execd_config": "absent",
        })
        self.assertEqual(CONTROLLER._systemd_prior_readback(receipt, manifest, self.fixture.root, driver)["buzz-ci-acceptance-control.service"]["ActiveState"], "inactive")
        self.assertEqual(CONTROLLER.rollback(manifest, self.fixture.root, driver)["state"], "rolled_back")

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
        self.assertEqual((properties["components"]["minItems"], properties["components"]["maxItems"]), (len(activation_package.COMPONENTS), len(activation_package.COMPONENTS)))
        expected_entries = len(activation_package.CONFIG_TARGETS) + len(activation_package.STATIC_TARGETS)
        self.assertEqual((properties["entries"]["minItems"], properties["entries"]["maxItems"]), (expected_entries, expected_entries))
        self.assertEqual(
            (properties["effective_systemd"]["minItems"], properties["effective_systemd"]["maxItems"]),
            (len(activation_package.SYSTEMD_UNIT_LAYOUT), len(activation_package.SYSTEMD_UNIT_LAYOUT)),
        )
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
            "d2a6ce74f1a7a2532e3e7f5e1f353ba1e9bc989a32db87ede368bd3dc716f2c5",
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
            "LoadState": "loaded", "ActiveState": "active", "SubState": "listening", "UnitFileState": "enabled",
            "FragmentPath": effective["fragment"]["path"],
            "DropInPaths": [record["path"] for record in effective["drop_ins"]],
        })
        write_file(self.fixture.fake_state, activation_package.canonical_json(state), 0o600)
        manifest, payloads, driver = self.fixture.load()
        CONTROLLER.stage(manifest, payloads, self.fixture.root, driver, self.fixture.binding)
        self.activate_one(manifest, payloads, driver)
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
            CONTROLLER._staged_zero_readback(manifest, self.fixture.root, driver)["units"][activation_package.PERSISTENT_UNIT]["ActiveState"],
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
        self.assertEqual((broker["identities"]["control_uid"], broker["identities"]["job_uid"]), (62004, 62006))
        self.assertEqual(
            {key: broker["identities"][key] for key in (
                "control_user", "control_group", "control_home", "control_shell", "control_supplementary_groups",
            )},
            {
                "control_user": "buzzci-ctl", "control_group": "buzzci-ctl",
                "control_home": "/var/lib/buzzci/ctl", "control_shell": "/usr/sbin/nologin",
                "control_supplementary_groups": ["buzzci-execd"],
            },
        )
        self.assertEqual(broker["paths"]["intent_root"], activation_package.EXECD_INTENT_ROOT)
        self.assertEqual(broker["paths"]["executor_socket"], activation_package.EXECUTOR_SOCKET_PATH)
        self.assertEqual(active["lane_manifest_digest"], broker["lane_manifest_digest"])
        self.assertEqual(
            activation_package.lane_manifest_digest(broker["lane_manifest"]),
            "12ede37672233a144707bc49efa5d8f86ec5803e6b9d623347472702b2c98f04",
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
        self.assertTrue(set(request).isdisjoint({"action", "program", "path", "argv", "environment"}))
        self.assertEqual((state["status"], result["status"]), ("passed", "qualified_closed"))
        before = request_raw
        CONTROLLER.qualify(manifest, payloads, self.fixture.root, driver)
        after = base64.b64decode(CONTROLLER._read_receipt(self.fixture.root)["qualification"]["request_base64"], validate=True)
        self.assertEqual(after, before)

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

    def test_execution_digest_matches_frozen_rust_vector(self) -> None:
        manifest, payloads, _driver = self.fixture.load()
        entry = next(item for item in manifest["entries"] if item["role"] == "execd_config")
        config = json.loads(payloads[entry["source"]])
        self.assertEqual(
            activation_package.lane_manifest_digest(config["lane_manifest"]),
            "12ede37672233a144707bc49efa5d8f86ec5803e6b9d623347472702b2c98f04",
        )
        self.assertEqual(
            activation_package.execution_declaration_digest(
                "aa" * 20, "70" * 32, config["lane_manifest"], config["execution"],
            ),
            "a0c535305d1e1f370c39aaaa077f0a01f88993d76fb743892d5d161e8411f438",
        )

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
        script = r'''
set -eu
root=$1
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
setpriv --reuid=1 --regid=1 --clear-groups sh -eu -c 'trap '\''chmod -R a+rwx "$1/var/lib/buzzci/execd-v2/attempts/a"'\'' EXIT; test "$(cat "$1/var/lib/buzzci/execd-v2/attempts/a/source/input.txt")" = input; test "$(cat "$1/var/lib/buzzci/seccomp/v1/sha256/profile.json")" = profile; ! test -r "$1/var/lib/buzzci/execd-v2/intents"' sh "$root"
'''
        with tempfile.TemporaryDirectory(prefix="buzz-activation-job-dac-", dir="/tmp") as temporary:
            namespace_root = Path(temporary)
            result = subprocess.run(
                [
                    unshare, "--user", "--map-users=0:1000:1", "--map-users=1:524288:65536",
                    "--map-groups=0:1000:1", "--map-groups=1:524288:65536", "sh", "-eu", "-c", script, "sh", str(namespace_root),
                ],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

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
            {"user": 62004, "group": 62004, "extra_groups": [62005]},
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

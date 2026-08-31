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
                "user": "buzzci-ctl", "group": "buzzci-ctl", "uid": 961, "gid": 961,
                "home": "/var/lib/buzzci/principals/ctl", "shell": "/usr/sbin/nologin",
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
        self._bind_controld_package_config()
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
                "control_uid": 961, "control_gid": 961,
                "control_user": "buzzci-ctl", "control_group": "buzzci-ctl",
                "control_home": "/var/lib/buzzci/principals/ctl", "control_shell": "/usr/sbin/nologin",
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
                    "daemon_contract": {
                        "acceptance_binding": activation_package.ACCEPTANCE_BINDING_PATH,
                    },
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

    def _bind_controld_package_config(self) -> None:
        component = next(item for item in self.components if item["name"] == "controld")
        source = component["package_manifest_source"]
        package = json.loads(self.assets[source][0])
        config = next(item for item in self.entries if item["role"] == "controld_config")
        package["entries"].append({
            "role": "config",
            "target": config["target"],
            "sha256": config["sha256"],
            "install_mode": config["install_mode"],
            "uid": config["uid"],
            "gid": config["gid"],
        })
        package["package_digest"] = activation_package.digest(
            activation_package.canonical_json({
                key: value for key, value in package.items() if key != "package_digest"
            })
        )
        raw = activation_package.canonical_json(package)
        self.assets[source] = (raw, 0o400)
        component["package_manifest_sha256"] = activation_package.digest(raw)
        component["package_digest"] = package["package_digest"]

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

        report = INVENTORY.check_inventory(packages, source_root=REPO_ROOT)
        self.assertEqual((report["status"], report["packages"]), ("pass", sorted(INVENTORY.PACKAGE_SCHEMAS)))
        self.assertEqual(
            report["source_inventory"]["controld_acceptance_source"],
            str(INVENTORY.CONTROLD_ACCEPTANCE_SOURCE),
        )
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
            "d2fb3dc4888112437a81904ce4fa303a9557de7b631f0b3e769b1d743ab0cdda",
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

from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[4]
ACTIVATION_ROOT = REPO_ROOT / "deploy/native-ci/activation"
sys.path.insert(0, str(ACTIVATION_ROOT))

import package as activation_package


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CONTROLLER = load_module("activation_scaffold_controller", ACTIVATION_ROOT / "controller.py")
# Test-only relay identities: the disposable clean-host relay accepts any
# channel and repository, so the scaffold binds these explicitly instead of
# inheriting production values.
TEST_CHANNEL_ID = "12345678-1234-4abc-8def-123456789abc"
TEST_REPOSITORY_OWNER = "22" * 32
TEST_REPOSITORY_ID = "buzz"
TEST_SOURCE_CLONE_URL = "https://relay.example.invalid/git/buzz"
FREEZER = load_module("activation_scaffold_freezer", ACTIVATION_ROOT / "freeze_package.py")

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
        self._bind_component_package_configs()
        self._add_static_assets()
        self.qualification = {
            "program": "/usr/libexec/buzz-ci-production-qualification",
            "request_validity_seconds": 60,
            "timeout_seconds": 5,
            "terminate_grace_seconds": 2,
            "principal": "qualification",
        }
        actor = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        self.acceptance_template = activation_package.production_acceptance_template(
            actor_public_key=actor,
            actor_generation=10,
            ci_signer_public_key="c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            candidate_sha="a" * 40,
            workflow_id="capacity-one",
            workflow_digest="80" * 32,
            job_id="capacity-one-fixture",
            channel_id=TEST_CHANNEL_ID,
            repository_owner_public_key=TEST_REPOSITORY_OWNER,
            repository_id=TEST_REPOSITORY_ID,
            source_clone_url=TEST_SOURCE_CLONE_URL,
            time_reference=1_800_000_000,
        )
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
        # The admission key is the keyholder's manifest selector (see
        # package.validate_phase_configs); the lane manifest copies it.
        keyholder_selectors = {
            "ci_event": {"public_key": "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5", "generation": 1},
            "nip98": {"public_key": "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9", "generation": 2},
            "manifest": {"public_key": "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13", "generation": 3},
        }
        lane_manifest = {
            "schema_version": 1,
            "lane_id": "10" * 32,
            "lane_epoch": 4,
            "admission_verifying_key": keyholder_selectors["manifest"]["public_key"],
            "admission_key_generation": keyholder_selectors["manifest"]["generation"],
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
            "acceptance_time_reference": 1_800_000_000,
        })
        self._asset_entry(
            "runner_config", activation_package.CONFIG_TARGETS["runner_config"], "runner-staged.json", runner_staged,
            0o600, 62001, 62001, "runner-active.json", runner_active,
        )
        executor = next(item for item in self.components if item["name"] == "executor")
        execd_template = {
            "schema_version": 2,
            "enabled_protocol": 2,
            "acceptance_time_reference": 1_800_000_000,
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
            "schema_version": 2, "capacity": 0, "store_root": "/var/lib/buzzci/controld",
            "acceptance_binding": activation_package.ACCEPTANCE_BINDING_PATH,
        })
        controld_active = activation_package.canonical_json({
            "schema_version": 2, "capacity": 1, "store_root": "/var/lib/buzzci/controld",
            "acceptance_binding": activation_package.ACCEPTANCE_BINDING_PATH,
            "relay_url": "wss://relay.example.invalid", "relay_http_origin": "https://relay.example.invalid",
            "channel_id": TEST_CHANNEL_ID, "poll_interval_millis": 1000,
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
            "keyholder_selectors": keyholder_selectors,
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
            if name in activation_package.COMPONENT_PACKAGE_NAMES:
                socket_role = "socket" if name == "runner" else "acceptance_socket"
                socket_name = (
                    "buzz-ci-runner.socket"
                    if name == "runner"
                    else "buzz-ci-controld-acceptance.socket"
                )
                package_id = f"buzz-ci-{name}-{source_commit[:12]}-{activation_package.digest(binary)[:12]}"
                package: dict[str, object] = {
                    "schema": f"buzz-ci-{name}-install-package-v2",
                    "package_id": package_id,
                    "source_commit": source_commit,
                    "binary_provenance_sha256": activation_package.digest(provenance),
                    "default_state": (
                        {"enabled": False, "active": False, "provisioned": False, "capacity": 0, "host_block": False}
                        if name == "runner"
                        else {"enabled": False, "active": False, "provisioned": False, "capacity": 0, "providers_wired": False}
                    ),
                    "package_uid": 0,
                    "package_gid": 0,
                    "directories": [
                        {"target": "/etc/buzzci", "mode": "0755", "uid": 0, "gid": 0},
                        {"target": f"/usr/share/doc/buzz-ci-{name}", "mode": "0755", "uid": 0, "gid": 0},
                    ],
                    "entries": [],
                }
                if name == "runner":
                    package["peer_policy"] = {
                        "runner_control_socket": {
                            "path": "/run/buzzci/runner-control.sock", "descriptor_name": "buzz-ci-runner-control",
                            "user": "buzzci-runner", "group": "buzzci-controld", "mode": "0620", "directory_mode": "0711",
                        },
                        "broker_socket": {
                            "path": "/run/buzzci/execd.sock", "expected_uid": 0, "owner": "root",
                            "group": "buzzci-execd", "mode": "0620",
                            "supplementary_members": ["buzzci-runner", "buzzci-ctl"], "managed_by_package": False,
                        },
                    }
                    package["identities"] = {
                        role: {
                            "user": self.identities[role]["user"], "group": self.identities[role]["group"],
                            "uid": self.identities[role]["uid"], "gid": self.identities[role]["gid"],
                        }
                        for role in ("runner", "controld")
                    }
                else:
                    package["daemon_contract"] = {
                        "service_user": "buzzci-controld", "config_path": "/etc/buzzci/controld-v2.json",
                        "acceptance_binding": activation_package.ACCEPTANCE_BINDING_PATH,
                        "store_root": "/var/lib/buzzci/controld", "default_capacity": 0,
                        "maximum_capacity": 1, "providers_fail_closed": True, "runner_protocol": 2,
                        "acceptance_socket": "/run/buzzci/controld-acceptance.sock",
                    }
                    package["identity"] = {
                        "user": self.identities["controld"]["user"], "group": self.identities["controld"]["group"],
                        "uid": self.identities["controld"]["uid"], "gid": self.identities["controld"]["gid"],
                    }
                package["entries"].append({
                    "role": "binary", "source": f"assets/buzz-ci-{name}", "target": binary_path,
                    "source_mode": "0500", "install_mode": "0755", "uid": 0, "gid": 0,
                    "sha256": activation_package.digest(binary),
                })
                for role, relative, target in (
                    ("service", f"deploy/native-ci/{name}/templates/buzz-ci-{name}.service", f"/etc/systemd/system/buzz-ci-{name}.service"),
                    (socket_role, f"deploy/native-ci/{name}/templates/{socket_name}", f"/etc/systemd/system/{socket_name}"),
                    ("tmpfiles", f"deploy/native-ci/{name}/templates/buzzci-{name}.tmpfiles", activation_package.COMPONENT_TMPFILES_TARGETS[name]),
                    ("documentation", f"deploy/native-ci/{name}/README.md", f"/usr/share/doc/buzz-ci-{name}/README.md"),
                ):
                    payload = (REPO_ROOT / relative).read_bytes()
                    package["entries"].append({
                        "role": role,
                        "source": "assets/README.md" if role == "documentation" else f"assets/{Path(target).name}",
                        "target": target, "source_mode": "0400",
                        "sha256": activation_package.digest(payload), "install_mode": "0644", "uid": 0, "gid": 0,
                    })
                package["entries"].sort(key=lambda item: item["target"].encode())
                package_raw = activation_package.canonical_json(package)
                source = f"assets/{name}-package-manifest.json"
                self.assets[source] = (package_raw, 0o400)
                component.update({
                    "package_manifest_source": source,
                    "package_manifest_sha256": "0" * 64,
                    "package_digest": "0" * 64,
                })
            components.append(component)
        return components

    def _bind_component_package_configs(self) -> None:
        for name in activation_package.COMPONENT_PACKAGE_NAMES:
            component = next(item for item in self.components if item["name"] == name)
            source = component["package_manifest_source"]
            package = json.loads(self.assets[source][0])
            config = next(item for item in self.entries if item["role"] == f"{name}_config")
            package["entries"].append({
                "role": "config", "source": f"assets/{name}-v2.json",
                "target": config["target"], "source_mode": "0400",
                "sha256": config["sha256"], "install_mode": config["install_mode"],
                "uid": config["uid"], "gid": config["gid"],
            })
            package["entries"].sort(key=lambda item: item["target"].encode())
            package["package_digest"] = activation_package.digest(
                activation_package.canonical_json(package)
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
        request_digest = activation_package.digest(json.dumps(
            self.acceptance_template["run_event"], ensure_ascii=False, separators=(",", ":"),
        ).encode())
        grant_event_id = activation_package.digest(json.dumps(
            self.acceptance_template["grant_event"], ensure_ascii=False, separators=(",", ":"),
        ).encode())
        return {
            "schema_version": "buzz-ci-capacity-one-scenario/v2",
            "fixture": {
                "integrated_candidate_sha": self.manifest["source_commit"],
                "activation_id": self.manifest["activation_id"],
                "activation_package_digest": self.manifest["package_digest"],
                "run_id": "1" * 32,
                "job_id": "capacity-one-fixture",
                "request_digest": request_digest,
                "manifest_digest": activation_package.FIXTURE_MANIFEST_SHA256,
                "source_oid": "a" * 40,
                "approval_id": "4" * 32,
                "grant_event_id": grant_event_id,
                "grant_digest": "6" * 64,
                "approved_by": self.acceptance_template["actor"]["public_key"],
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
            "platform_systemd": activation_package.PLATFORM_SYSTEMD,
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
            "schema_version": 2,
            "peer": {
                "uid": 62002, "gid": 62002,
                "allowed_operations": activation_package.KEYHOLDER_ALLOWED_OPERATIONS,
            },
            "selectors": {
                "ci_event": {"public_key": "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5", "generation": 1},
                "nip98": {"public_key": "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9", "generation": 2},
                "manifest": {"public_key": "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13", "generation": 3},
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
                "UnitFileState": "" if load_state == "not-found" else "disabled" if name.endswith(".socket") else "static",
                "FragmentPath": "" if load_state == "not-found" else item["fragment"]["path"],
                "DropInPaths": activation_package.systemd_drop_in_order([
                    record["path"] for record in item["drop_ins"]
                    if record["owner"] != "activation"
                ]),
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

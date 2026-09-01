from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[3]
ACTIVATION_ROOT = REPO_ROOT / "deploy/native-ci/activation"
RUNNER_ROOT = REPO_ROOT / "deploy/native-ci/runner"
CONTROLD_ROOT = REPO_ROOT / "deploy/native-ci/controld"
EXECD_ROOT = REPO_ROOT / "deploy/native-ci/execd"
KEYHOLDER_ROOT = REPO_ROOT / "deploy/native-ci/keyholder"
sys.path.insert(0, str(ACTIVATION_ROOT))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ACTIVATION_PACKAGE = load_module("bootstrap_activation_package", ACTIVATION_ROOT / "package.py")
ACTIVATION_FREEZER = load_module("bootstrap_activation_freezer", ACTIVATION_ROOT / "freeze_package.py")
INVENTORY = load_module("bootstrap_inventory", ACTIVATION_ROOT / "check_package_inventory.py")
RENDER = load_module("bootstrap_renderer", ACTIVATION_ROOT / "render_inputs/render_inputs.py")
TEMPLATE_GENERATOR = load_module(
    "bootstrap_template_generator",
    ACTIVATION_ROOT / "render_inputs/generate_checked_templates.py",
)
EXECD_FREEZER = load_module("bootstrap_execd_freezer", EXECD_ROOT / "freeze_package.py")
ACTIVATION_TESTS = load_module(
    "bootstrap_activation_test_fixture", ACTIVATION_ROOT / "tests/test_activation_controller.py",
)
load_module("render_runner_config", RUNNER_ROOT / "render_runner_config.py")
RUNNER_FREEZER = load_module("bootstrap_runner_freezer", RUNNER_ROOT / "freeze_package.py")
load_module("render_controld_config", CONTROLD_ROOT / "render_controld_config.py")
CONTROLD_FREEZER = load_module("bootstrap_controld_freezer", CONTROLD_ROOT / "freeze_package.py")
load_module("render_keyholder_config", KEYHOLDER_ROOT / "render_keyholder_config.py")
KEYHOLDER_FREEZER = load_module(
    "bootstrap_keyholder_freezer", KEYHOLDER_ROOT / "freeze_package.py",
)
CLEAN_HOST_HARNESS = load_module(
    "bootstrap_clean_host_harness",
    ACTIVATION_ROOT / "tests/clean_host_e2e/harness.py",
)
CLEAN_HOST_GUEST = load_module(
    "bootstrap_clean_host_guest",
    ACTIVATION_ROOT / "tests/clean_host_e2e/guest_entry.py",
)


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def write_file(path: Path, payload: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.chmod(0o600)
    path.write_bytes(payload)
    path.chmod(mode)


def file_ref(base: Path, path: Path) -> dict[str, object]:
    payload = path.read_bytes()
    return {
        "path": path.relative_to(base).as_posix(),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
        "mode": f"{stat.S_IMODE(path.stat().st_mode):04o}",
    }


class BootstrapCompositionTests(unittest.TestCase):
    def test_activation_template_generator_rejects_unsafe_input_and_never_clobbers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture_root = root / "fixture"
            fixture_root.mkdir(mode=0o700)
            fixture = ACTIVATION_TESTS.ActivationFixture(fixture_root)
            draft = self._retarget_draft(fixture, "c" * 40)
            source = root / "draft.json"
            output = root / "template.json"
            write_file(source, canonical(draft), 0o600)
            command = [
                "python3",
                str(ACTIVATION_ROOT / "render_inputs/generate_checked_templates.py"),
                "activation-draft",
                "--input",
                str(source),
                "--output",
                str(output),
            ]
            first = subprocess.run(
                command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            expected = output.read_bytes()
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

            repeated = subprocess.run(
                command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(repeated.returncode, 64)
            self.assertEqual(output.read_bytes(), expected)

            for name, payload, mode in (
                ("public-mode", canonical(draft), 0o644),
                ("noncanonical", json.dumps(draft, indent=2).encode() + b"\n", 0o600),
            ):
                rejected_source = root / f"{name}.json"
                rejected_output = root / f"{name}.template.json"
                write_file(rejected_source, payload, mode)
                rejected = subprocess.run(
                    [
                        *command[:3],
                        "--input",
                        str(rejected_source),
                        "--output",
                        str(rejected_output),
                    ],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(rejected.returncode, 64)
                self.assertFalse(rejected_output.exists())

    def _source_checkout(self, root: Path) -> tuple[Path, str]:
        source = root / "candidate"
        shutil.copytree(REPO_ROOT / "deploy/native-ci", source / "deploy/native-ci")
        for cached in source.rglob("__pycache__"):
            shutil.rmtree(cached)
        subprocess.run(["git", "init", "-q", source], check=True)
        subprocess.run(["git", "-C", source, "config", "user.name", "Test"], check=True)
        subprocess.run(
            ["git", "-C", source, "config", "user.email", "test@example.invalid"], check=True,
        )
        subprocess.run(["git", "-C", source, "add", "."], check=True)
        subprocess.run(["git", "-C", source, "commit", "-q", "-m", "candidate"], check=True)
        candidate = subprocess.check_output(
            ["git", "-C", source, "rev-parse", "HEAD"], text=True,
        ).strip()
        return source, candidate

    def _public_binding(self, actor: dict[str, object]) -> dict[str, object]:
        return {
            "schema_version": "buzz-ci-clean-host-e2e-public-binding/v3",
            "relay_url": "wss://relay.example.invalid",
            "relay_http_origin": "https://relay.example.invalid",
            "acceptance_actor": actor,
            "keyholder_public_spec": {
                "schema_version": 2,
                "peer": {
                    "uid": 62002,
                    "gid": 62002,
                    "allowed_operations": [
                        "describe", "sign_ci_event", "nip98_authorize", "sign_manifest",
                        "describe_acceptance", "sign_acceptance_mutation",
                    ],
                },
                "selectors": {
                    "ci_event": {"public_key": "44" * 32, "generation": 1},
                    "nip98": {"public_key": "55" * 32, "generation": 1},
                    "manifest": {"public_key": "66" * 32, "generation": 1},
                },
                "nip98_origin": "https://relay.example.invalid",
                "acceptance": {
                    "binding_receipt_path": "/var/lib/buzzci/activation-controller/controld-acceptance-v2.json",
                    "credential_selector": "acceptance-actor.key",
                },
            },
        }

    def _retarget_draft(
        self,
        fixture: object,
        candidate: str,
    ) -> dict[str, object]:
        draft = copy.deepcopy(fixture.manifest)
        draft.pop("activation_id")
        draft.pop("package_digest")
        draft["schema"] = ACTIVATION_PACKAGE.DRAFT_SCHEMA
        draft["source_commit"] = candidate
        draft["acceptance_template"]["actor"]["generation"] = 1

        entries = {item["role"]: item for item in draft["entries"]}
        components = {item["name"]: item for item in draft["components"]}
        verifier_payload = (REPO_ROOT / "deploy/native-ci/acceptance/verify-receipt.py").read_bytes()
        components["receipt_verifier"]["binary_sha256"] = hashlib.sha256(verifier_payload).hexdigest()
        entries["receipt_verifier_binary"]["sha256"] = hashlib.sha256(verifier_payload).hexdigest()
        entries["receipt_verifier_binary"]["source"] = (
            ACTIVATION_FREEZER.TRACKED_REPO_SOURCES["receipt_verifier_binary"][1]
        )

        for name, component in components.items():
            if name != "qualification":
                component["source_commit"] = candidate
            provenance = canonical({
                "binary": Path(component["binary_path"]).name,
                "profile": "release",
                "schema": ACTIVATION_PACKAGE.PROVENANCE_SCHEMA,
                "sha256": component["binary_sha256"],
                "source_commit": component["source_commit"],
            })
            component["provenance_sha256"] = hashlib.sha256(provenance).hexdigest()
            fixture.assets[component["provenance_source"]] = (provenance, 0o400)

        execd_entry = entries["execd_config"]
        for source_key, digest_key in (
            ("source", "sha256"), ("active_source", "active_sha256"),
        ):
            source = execd_entry[source_key]
            value = json.loads(fixture.assets[source][0])
            value["executor"]["source_commit"] = candidate
            value["qualification"]["integrated_candidate_sha"] = candidate
            payload = canonical(value)
            fixture.assets[source] = (payload, 0o400)
            execd_entry[digest_key] = hashlib.sha256(payload).hexdigest()

        return draft

    def _ready_packages(
        self,
        ceremony: Path,
        source: Path,
        draft: dict[str, object],
        fixture: object,
        candidate: str,
        public_path: Path,
    ) -> dict[str, dict[str, object]]:
        results: dict[str, dict[str, object]] = {}
        identities = draft["identities"]
        packages_root = ceremony / "packages"
        packages_root.mkdir(mode=0o700)
        packages_root.chmod(0o700)
        inputs = ceremony / "component-inputs"
        inputs.mkdir(mode=0o700)

        for name, freezer in (("runner", RUNNER_FREEZER), ("controld", CONTROLD_FREEZER)):
            component = next(item for item in draft["components"] if item["name"] == name)
            binary = inputs / f"buzz-ci-{name}"
            binary_payload = f"{name}-binary\n".encode()
            write_file(binary, binary_payload, 0o755)
            self.assertEqual(
                hashlib.sha256(binary_payload).hexdigest(),
                component["binary_sha256"],
            )
            provenance = inputs / f"buzz-ci-{name}.provenance.json"
            write_file(
                provenance,
                canonical({
                    "binary": f"buzz-ci-{name}",
                    "profile": "release",
                    "schema": "buzz-ci-binary-provenance-v1",
                    "sha256": component["binary_sha256"],
                    "source_commit": candidate,
                }),
                0o600,
            )
            output = packages_root / name
            if name == "runner":
                manifest = freezer.freeze_package(
                    source,
                    candidate,
                    binary,
                    provenance,
                    output,
                    identities["runner"]["uid"],
                    identities["runner"]["gid"],
                    identities["controld"]["uid"],
                    identities["controld"]["gid"],
                )
            else:
                manifest = freezer.freeze_package(
                    source,
                    candidate,
                    binary,
                    provenance,
                    output,
                    identities["controld"]["uid"],
                    identities["controld"]["gid"],
                )
                raw = (output / "package-manifest.json").read_bytes()
                component["package_manifest_sha256"] = hashlib.sha256(raw).hexdigest()
                component["package_digest"] = manifest["package_digest"]
                fixture.assets[component["package_manifest_source"]] = (raw, 0o400)
            results[name] = manifest

        keyholder_component = next(
            item for item in draft["components"] if item["name"] == "keyholder"
        )
        keyholder_binary = inputs / "buzz-ci-keyholder"
        keyholder_payload = b"keyholder-binary\n"
        write_file(keyholder_binary, keyholder_payload, 0o755)
        self.assertEqual(
            hashlib.sha256(keyholder_payload).hexdigest(),
            keyholder_component["binary_sha256"],
        )
        keyholder_provenance = inputs / "buzz-ci-keyholder.provenance.json"
        write_file(
            keyholder_provenance,
            canonical({
                "binary": "buzz-ci-keyholder",
                "profile": "release",
                "schema": KEYHOLDER_FREEZER.PROVENANCE_SCHEMA,
                "sha256": keyholder_component["binary_sha256"],
                "source_commit": candidate,
            }),
            0o600,
        )
        results["keyholder"] = KEYHOLDER_FREEZER.freeze_package(
            source,
            candidate,
            keyholder_binary,
            keyholder_provenance,
            None,
            packages_root / "keyholder",
            draft["identities"]["keyholder"]["uid"],
            draft["identities"]["keyholder"]["gid"],
            draft["identities"]["controld"]["uid"],
            draft["identities"]["controld"]["gid"],
            public_binding=public_path,
        )
        return results

    def _write_descriptor(self, ceremony: Path, name: str, value: object) -> Path:
        path = ceremony / name
        write_file(path, canonical(value), 0o600)
        return path

    def _render(self, action: str, descriptor_path: Path, output: str) -> dict[str, object]:
        root = RENDER.DescriptorRoot(descriptor_path)
        try:
            value = RENDER.render(action, root)
            RENDER.write_output(root, output, RENDER.render_output(action, value))
            return value
        finally:
            root.close()

    def test_five_package_bootstrap_composes_without_a_vm(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ceremony = Path(directory)
            source, candidate = self._source_checkout(ceremony)
            fixture_root = ceremony / "fixture"
            fixture_root.mkdir(mode=0o700)
            fixture = ACTIVATION_TESTS.ActivationFixture(fixture_root)
            draft = self._retarget_draft(fixture, candidate)
            public = self._public_binding(draft["acceptance_template"]["actor"])
            controld_entry = next(
                item for item in draft["entries"] if item["role"] == "controld_config"
            )
            controld_active_source = controld_entry["active_source"]
            controld_active = json.loads(fixture.assets[controld_active_source][0])
            controld_active["keyholder_selectors"] = copy.deepcopy(
                public["keyholder_public_spec"]["selectors"]
            )
            controld_active_raw = canonical(controld_active)
            fixture.assets[controld_active_source] = (controld_active_raw, 0o400)
            controld_entry["active_sha256"] = hashlib.sha256(
                controld_active_raw
            ).hexdigest()
            state = ceremony / "state"
            state.mkdir(mode=0o700)
            public_path = state / "public-binding.json"
            write_file(
                public_path,
                KEYHOLDER_FREEZER.canonical_public_binding(public),
                0o444,
            )
            self.assertNotEqual(public_path.read_bytes(), canonical(public))
            ready = self._ready_packages(
                ceremony, source, draft, fixture, candidate, public_path,
            )
            self.assertEqual(
                (ceremony / "packages/keyholder/public-binding.json").read_bytes(),
                public_path.read_bytes(),
            )
            runner_targets = {item["target"] for item in ready["runner"]["entries"]}
            self.assertIn("/etc/buzzci/runner-v2.json", runner_targets)
            self.assertNotIn("/etc/buzzci/runner-v1.json", runner_targets)
            controld_targets = {item["target"] for item in ready["controld"]["entries"]}
            self.assertIn("/etc/buzzci/controld-v2.json", controld_targets)
            self.assertIn(INVENTORY.CONTROLD_ACCEPTANCE_TARGET, controld_targets)
            for name, schema in (
                ("runner", RUNNER_ROOT / "package-manifest.schema.json"),
                ("controld", CONTROLD_ROOT / "package-manifest.schema.json"),
                ("keyholder", KEYHOLDER_ROOT / "package-manifest.schema.json"),
            ):
                subprocess.run(
                    [
                        "check-jsonschema",
                        "--schemafile",
                        str(schema),
                        str(ceremony / f"packages/{name}/package-manifest.json"),
                    ],
                    check=True,
                )

            asset_root = ceremony / "activation-inputs"
            asset_root.mkdir(mode=0o700)
            for source_name, (payload, mode) in fixture.assets.items():
                write_file(asset_root / Path(source_name).name, payload, mode)

            execd_binary = ceremony / "buzz-ci-execd"
            execd_component = next(item for item in draft["components"] if item["name"] == "execd")
            write_file(execd_binary, b"execd-binary\n", 0o755)
            self.assertEqual(hashlib.sha256(execd_binary.read_bytes()).hexdigest(), execd_component["binary_sha256"])
            execd_provenance = ceremony / "execd-provenance.json"
            write_file(
                execd_provenance,
                canonical({
                    "binary": "buzz-ci-execd", "profile": "release",
                    "schema": EXECD_FREEZER.PROVENANCE_SCHEMA,
                    "sha256": execd_component["binary_sha256"], "source_commit": candidate,
                }),
                0o600,
            )
            preactivation_path = ceremony / "execd-preactivation.json"
            preactivation = EXECD_FREEZER.prepare_preactivation_input(
                source, candidate, execd_binary, execd_provenance, preactivation_path,
            )

            RENDER.validate_acceptance_client_binding(public, {"keyholder": ready["keyholder"]})
            qualification_public = copy.deepcopy(public)
            qualification_public["keyholder_public_spec"]["peer"].update({"uid": 961, "gid": 961})
            with self.assertRaisesRegex(RENDER.RenderError, "differs from controld"):
                RENDER.validate_acceptance_client_binding(
                    qualification_public, {"keyholder": ready["keyholder"]},
                )
            template_path = ceremony / "activation-template.json"
            draft_seed = ceremony / "activation-draft.seed.json"
            write_file(draft_seed, canonical(draft), 0o600)
            generated = subprocess.run(
                [
                    "python3", str(ACTIVATION_ROOT / "render_inputs/generate_checked_templates.py"),
                    "activation-draft", "--input", str(draft_seed),
                    "--output", str(template_path),
                ],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            self.assertEqual(generated.returncode, 0, generated.stderr)
            self.assertEqual(
                json.loads(template_path.read_bytes()),
                TEMPLATE_GENERATOR.checked_activation_template(draft),
            )
            template_document = json.loads(template_path.read_bytes())["document"]
            original_components = {item["name"]: item for item in draft["components"]}
            template_components = {
                item["name"]: item for item in template_document["components"]
            }
            non_package_candidate_components = {
                "executor", "acceptance_canary", "acceptance_driver",
                "acceptance_control", "receipt_verifier",
            }
            for name in non_package_candidate_components:
                self.assertEqual(
                    template_components[name]["source_commit"],
                    {"$copy": "candidate_sha"},
                )
                self.assertEqual(
                    template_components[name]["binary_sha256"],
                    original_components[name]["binary_sha256"],
                )
                self.assertEqual(
                    template_components[name]["provenance_sha256"],
                    original_components[name]["provenance_sha256"],
                )
            self.assertEqual(
                template_components["qualification"],
                original_components["qualification"],
            )
            draft_descriptor = self._write_descriptor(ceremony, "draft-descriptor.json", {
                "schema_version": "buzz-ci-activation-draft-render-input/v1",
                "candidate_sha": candidate,
                "public_binding": file_ref(ceremony, public_path),
                "package_manifests": {
                    name: file_ref(ceremony, ceremony / f"packages/{name}/package-manifest.json")
                    for name in ("runner", "controld", "keyholder")
                },
                "execd_preactivation": file_ref(ceremony, preactivation_path),
                "template": file_ref(ceremony, template_path),
            })
            rendered_draft = self._render("render-draft", draft_descriptor, "activation-draft.json")
            self.assertEqual(rendered_draft["source_commit"], candidate)
            rendered_execd = next(item for item in rendered_draft["components"] if item["name"] == "execd")
            self.assertEqual(
                (rendered_execd["binary_sha256"], rendered_execd["provenance_sha256"]),
                (preactivation["binary_sha256"], preactivation["provenance_sha256"]),
            )

            activation_path = ceremony / "packages/activation"
            activation_manifest = ACTIVATION_FREEZER.freeze_package(
                source, candidate, ceremony / "activation-draft.json", asset_root, activation_path,
            )
            loaded_manifest, _loaded_payloads = ACTIVATION_TESTS.CONTROLLER.load_package(
                activation_path, live=False,
            )
            self.assertEqual(loaded_manifest, activation_manifest)
            execd_path = ceremony / "packages/execd"
            execd_manifest = EXECD_FREEZER.freeze_package(
                source, candidate, execd_binary, execd_provenance, preactivation_path,
                activation_path, execd_path,
            )
            self.assertEqual(
                execd_manifest["activation_binding"]["preactivation_input_sha256"],
                hashlib.sha256(preactivation_path.read_bytes()).hexdigest(),
            )

            manifests = {**ready, "execd": execd_manifest, "activation": activation_manifest}
            RENDER.validate_acceptance_client_binding(public, manifests)
            wrong_keyholder = copy.deepcopy(manifests)
            wrong_keyholder["keyholder"]["identities"]["controld_uid"] = 961
            with self.assertRaisesRegex(RENDER.RenderError, "differs from controld"):
                RENDER.validate_acceptance_client_binding(public, wrong_keyholder)
            scenario = json.loads(
                (REPO_ROOT / "deploy/native-ci/acceptance/scenario.template.json").read_bytes()
            )
            scenario["fixture"].update({
                "integrated_candidate_sha": candidate,
                "source_oid": candidate,
                "activation_id": activation_manifest["activation_id"],
                "activation_package_digest": activation_manifest["package_digest"],
                "grant_event_id": ACTIVATION_PACKAGE.digest(
                    json.dumps(
                        activation_manifest["acceptance_template"]["grant_event"],
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ).encode()
                ),
            })
            scenario_template_path = ceremony / "scenario-template.json"
            scenario_source_path = ceremony / "scenario-source.json"
            write_file(scenario_source_path, RENDER.canonical_scenario(scenario), 0o600)
            generated = subprocess.run(
                [
                    "python3", str(ACTIVATION_ROOT / "render_inputs/generate_checked_templates.py"),
                    "capacity-one-scenario", "--input", str(scenario_source_path),
                    "--output", str(scenario_template_path),
                ],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            self.assertEqual(generated.returncode, 0, generated.stderr)
            self.assertEqual(
                json.loads(scenario_template_path.read_bytes()),
                TEMPLATE_GENERATOR.checked_scenario_template(scenario),
            )
            scenario_descriptor = self._write_descriptor(ceremony, "scenario-descriptor.json", {
                "schema_version": "buzz-ci-capacity-one-scenario-render-input/v1",
                "candidate_sha": candidate,
                "public_binding": file_ref(ceremony, public_path),
                "package_manifests": {
                    name: file_ref(
                        ceremony,
                        ceremony / f"packages/{name}/{'activation-manifest.json' if name == 'activation' else 'package-manifest.json'}",
                    )
                    for name in RENDER.PACKAGE_NAMES
                },
                "template": file_ref(ceremony, scenario_template_path),
            })
            rendered_scenario = self._render(
                "render-scenario", scenario_descriptor, "capacity-one-scenario.json",
            )
            self.assertEqual(rendered_scenario, scenario)
            scenario_path = ceremony / "capacity-one-scenario.json"
            scenario_raw = scenario_path.read_bytes()
            scenario_sha256 = hashlib.sha256(scenario_raw).hexdigest()
            verifier = RENDER.receipt_verifier_module()
            self.assertEqual(scenario_raw, RENDER.canonical_scenario(scenario))
            self.assertFalse(scenario_raw.endswith(b"\n"))
            self.assertEqual(verifier._digest(verifier._ordered_scenario(scenario)), scenario_sha256)
            self.assertEqual(
                ACTIVATION_TESTS.CONTROLLER._acceptance_binding(
                    activation_manifest, json.loads(scenario_raw),
                )["scenario_sha256"],
                scenario_sha256,
            )

            seccomp_path = ceremony / "seccomp.json"
            seccomp = b'{"defaultAction":"SCMP_ACT_ERRNO"}\n'
            write_file(seccomp_path, seccomp, 0o644)
            seccomp_sha256 = hashlib.sha256(seccomp).hexdigest()
            self.assertEqual(file_ref(ceremony, seccomp_path)["sha256"], seccomp_sha256)
            clean_descriptor = self._write_descriptor(ceremony, "clean-descriptor.json", {
                "schema_version": "buzz-ci-clean-host-contract-render-input/v1",
                "candidate_sha": candidate,
                "state": "state",
                "candidate_root": "candidate",
                "public_binding": file_ref(ceremony, public_path),
                "scenario": file_ref(ceremony, ceremony / "capacity-one-scenario.json"),
                "seccomp_source": file_ref(ceremony, seccomp_path),
                "packages": {
                    name: {
                        "path": f"packages/{name}",
                        "manifest_sha256": file_ref(
                            ceremony,
                            ceremony / f"packages/{name}/{'activation-manifest.json' if name == 'activation' else 'package-manifest.json'}",
                        )["sha256"],
                        "manifest_bytes": file_ref(
                            ceremony,
                            ceremony / f"packages/{name}/{'activation-manifest.json' if name == 'activation' else 'package-manifest.json'}",
                        )["bytes"],
                        "manifest_mode": file_ref(
                            ceremony,
                            ceremony / f"packages/{name}/{'activation-manifest.json' if name == 'activation' else 'package-manifest.json'}",
                        )["mode"],
                    }
                    for name in RENDER.PACKAGE_NAMES
                },
            })
            with mock.patch.object(RENDER, "SECCOMP_SHA256", seccomp_sha256):
                clean_contract = self._render(
                    "render-clean-host", clean_descriptor, "clean-host-contract.json",
                )
            self.assertEqual(set(clean_contract["packages"]), set(RENDER.PACKAGE_NAMES))
            self.assertEqual(clean_contract["seccomp_source"]["sha256"], seccomp_sha256)
            self.assertEqual(clean_contract["scenario"]["sha256"], scenario_sha256)
            previous_directory = Path.cwd()
            try:
                os.chdir(ceremony)
                prepared_state = {
                    "harness_sha256": clean_contract["harness_sha256"],
                    "timing_asset_sha256": clean_contract["timing_asset_sha256"],
                    "timing_sha256": clean_contract["timing_sha256"],
                }
                with (
                    mock.patch.object(CLEAN_HOST_HARNESS, "SECCOMP_SHA256", seccomp_sha256),
                    mock.patch.object(
                        CLEAN_HOST_HARNESS,
                        "validate_prepared_state",
                        return_value=prepared_state,
                    ),
                ):
                    (
                        harness_contract,
                        _harness_state,
                        _harness_records,
                        harness_scenario_raw,
                        _harness_seccomp_raw,
                    ) = CLEAN_HOST_HARNESS.validate_contract(
                        ceremony / "clean-host-contract.json",
                    )
            finally:
                os.chdir(previous_directory)
            self.assertEqual(harness_contract["scenario"]["sha256"], scenario_sha256)
            self.assertEqual(harness_scenario_raw, scenario_raw)

            guest_stage = ceremony / "guest-stage"
            guest_inputs = guest_stage / "inputs"
            guest_inputs.mkdir(parents=True)
            for name in RENDER.PACKAGE_NAMES:
                shutil.copytree(ceremony / f"packages/{name}", guest_inputs / name)
            shutil.copyfile(scenario_path, guest_inputs / "scenario.json")
            shutil.copyfile(seccomp_path, guest_inputs / "seccomp.json")
            shutil.copyfile(public_path, guest_inputs / "public-binding.json")
            subprocess.run(
                [
                    "tar", "-cf", str(guest_stage / "candidate.tar"), "-C", str(source),
                    "deploy/native-ci/activation/tests/clean_host_e2e/harness.py",
                    "deploy/native-ci/activation/tests/clean_host_e2e/timing-contract.json",
                ],
                check=True,
            )
            candidate_tar_raw = (guest_stage / "candidate.tar").read_bytes()
            guest_state = ceremony / "guest-state"
            guest_state.mkdir()
            shutil.copyfile(public_path, guest_state / "public-binding.json")
            guest_descriptor = {
                "candidate_sha": candidate,
                "candidate_tar_sha256": hashlib.sha256(candidate_tar_raw).hexdigest(),
                "harness_sha256": clean_contract["harness_sha256"],
                "package_tree_sha256": {
                    name: clean_contract["packages"][name]["tree_sha256"]
                    for name in RENDER.PACKAGE_NAMES
                },
                "public_binding_sha256": hashlib.sha256(public_path.read_bytes()).hexdigest(),
                "scenario_sha256": scenario_sha256,
                "seccomp_source_sha256": seccomp_sha256,
                "timing_asset_sha256": clean_contract["timing_asset_sha256"],
            }
            with (
                mock.patch.object(CLEAN_HOST_GUEST, "STATE_ROOT", guest_state),
                mock.patch.object(
                    CLEAN_HOST_GUEST,
                    "TIMING_PATH",
                    source / "deploy/native-ci/activation/tests/clean_host_e2e/timing-contract.json",
                ),
                mock.patch.object(CLEAN_HOST_GUEST, "SECCOMP_SHA256", seccomp_sha256),
            ):
                _candidate_path, guest_scenario, _guest_public = CLEAN_HOST_GUEST.cross_bind(
                    guest_stage, guest_descriptor,
                )
            self.assertEqual(RENDER.canonical_scenario(guest_scenario), scenario_raw)

            drifted_seccomp = b'{"defaultAction":"SCMP_ACT_ALLOW"}\n'
            write_file(seccomp_path, drifted_seccomp, 0o644)
            drifted_descriptor = json.loads(clean_descriptor.read_bytes())
            drifted_descriptor["seccomp_source"] = file_ref(ceremony, seccomp_path)
            drifted_descriptor_path = self._write_descriptor(
                ceremony, "drifted-clean-descriptor.json", drifted_descriptor,
            )
            with mock.patch.object(RENDER, "SECCOMP_SHA256", seccomp_sha256):
                with self.assertRaisesRegex(RENDER.RenderError, "seccomp source differs"):
                    self._render(
                        "render-clean-host",
                        drifted_descriptor_path,
                        "drifted-clean-host-contract.json",
                    )
            self.assertEqual(INVENTORY.check_inventory(manifests)["status"], "pass")

            rejected_inputs = {
                "mismatched": {**preactivation, "binary_sha256": "d" * 64},
                "replayed": {**preactivation, "source_commit": "f" * 40},
            }
            for label, value in rejected_inputs.items():
                path = ceremony / f"{label}-preactivation.json"
                write_file(path, canonical(value), 0o600)
                with self.subTest(label=label), self.assertRaisesRegex(ValueError, "tuple differs"):
                    EXECD_FREEZER.freeze_package(
                        source, candidate, execd_binary, execd_provenance, path,
                        activation_path, ceremony / f"packages/rejected-{label}",
                    )
            tampered = ceremony / "tampered-preactivation.json"
            write_file(tampered, preactivation_path.read_bytes()[:-1] + b" \n", 0o600)
            with self.assertRaisesRegex(ValueError, "canonical"):
                EXECD_FREEZER.freeze_package(
                    source, candidate, execd_binary, execd_provenance, tampered,
                    activation_path, ceremony / "packages/rejected-tampered",
                )


if __name__ == "__main__":
    unittest.main()

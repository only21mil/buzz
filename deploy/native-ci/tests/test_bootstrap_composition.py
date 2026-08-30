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


REPO_ROOT = Path(__file__).resolve().parents[3]
ACTIVATION_ROOT = REPO_ROOT / "deploy/native-ci/activation"
CONTROLD_ROOT = REPO_ROOT / "deploy/native-ci/controld"
EXECD_ROOT = REPO_ROOT / "deploy/native-ci/execd"
KEYHOLDER_ROOT = REPO_ROOT / "deploy/native-ci/keyholder"
RUNNER_ROOT = REPO_ROOT / "deploy/native-ci/runner"
sys.path.insert(0, str(ACTIVATION_ROOT))
sys.path.insert(0, str(CONTROLD_ROOT))
sys.path.insert(0, str(KEYHOLDER_ROOT))
sys.path.insert(0, str(RUNNER_ROOT))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


ACTIVATION_PACKAGE = load_module("bootstrap_activation_package", ACTIVATION_ROOT / "package.py")
ACTIVATION_FREEZER = load_module("bootstrap_activation_freezer", ACTIVATION_ROOT / "freeze_package.py")
CONTROLD_FREEZER = load_module("bootstrap_controld_freezer", CONTROLD_ROOT / "freeze_package.py")
INVENTORY = load_module("bootstrap_inventory", ACTIVATION_ROOT / "check_package_inventory.py")
RENDER = load_module("bootstrap_renderer", ACTIVATION_ROOT / "render_inputs/render_inputs.py")
HARNESS = load_module(
    "bootstrap_clean_host_harness", ACTIVATION_ROOT / "tests/clean_host_e2e/harness.py",
)
EXECD_FREEZER = load_module("bootstrap_execd_freezer", EXECD_ROOT / "freeze_package.py")
KEYHOLDER_FREEZER = load_module(
    "bootstrap_keyholder_freezer", KEYHOLDER_ROOT / "freeze_package.py",
)
RUNNER_FREEZER = load_module("bootstrap_runner_freezer", RUNNER_ROOT / "freeze_package.py")
ACTIVATION_TESTS = load_module(
    "bootstrap_activation_test_fixture", ACTIVATION_ROOT / "tests/test_activation_controller.py",
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
            "schema_version": "buzz-ci-clean-host-e2e-public-binding/v2",
            "relay_url": "wss://relay.example.invalid",
            "relay_http_origin": "https://relay.example.invalid",
            "acceptance_actor": actor,
            "keyholder_public_spec": {
                "schema_version": 1,
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
                    "binding_receipt_path": "/var/lib/buzzci/activation-controller/controld-acceptance-v1.json",
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
        source_root: Path,
        draft: dict[str, object],
        fixture: object,
        candidate: str,
        public_binding: Path,
    ) -> dict[str, dict[str, object]]:
        results: dict[str, dict[str, object]] = {}
        draft_entries = {item["role"]: item for item in draft["entries"]}
        identities = draft["identities"]
        (ceremony / "packages").mkdir(mode=0o700)
        frozen: dict[str, tuple[object, tuple[int, ...]]] = {
            "runner": (
                RUNNER_FREEZER,
                (
                    identities["runner"]["uid"], identities["runner"]["gid"],
                    identities["controld"]["uid"], identities["controld"]["gid"],
                ),
            ),
            "controld": (
                CONTROLD_FREEZER,
                (identities["controld"]["uid"], identities["controld"]["gid"]),
            ),
        }
        for name, (freezer, identity_args) in frozen.items():
            binary_payload = f"{name}-binary\n".encode()
            binary = ceremony / f"buzz-ci-{name}"
            write_file(binary, binary_payload, 0o755)
            provenance = ceremony / f"{name}-provenance.json"
            write_file(provenance, canonical({
                "binary": f"buzz-ci-{name}",
                "profile": "release",
                "schema": freezer.PROVENANCE_SCHEMA,
                "sha256": hashlib.sha256(binary_payload).hexdigest(),
                "source_commit": candidate,
            }), 0o600)
            package = ceremony / "packages" / name
            manifest = freezer.freeze_package(
                source_root, candidate, binary, provenance, package, *identity_args,
            )
            repeated = freezer.freeze_package(
                source_root, candidate, binary, provenance,
                ceremony / "packages" / f"{name}-repeat", *identity_args,
            )
            self.assertEqual(repeated["package_digest"], manifest["package_digest"])
            config_entry = next(item for item in manifest["entries"] if item["role"] == "config")
            activation_entry = draft_entries[f"{name}_config"]
            self.assertEqual(config_entry["target"], activation_entry["target"])
            self.assertEqual(config_entry["sha256"], activation_entry["sha256"])
            self.assertEqual(
                (package / config_entry["source"]).read_bytes(),
                fixture.assets[activation_entry["source"]][0],
            )
            results[name] = manifest

        component = next(item for item in draft["components"] if item["name"] == "controld")
        controld_raw = (ceremony / "packages/controld/package-manifest.json").read_bytes()
        component["source_commit"] = candidate
        component["package_manifest_sha256"] = hashlib.sha256(controld_raw).hexdigest()
        component["package_digest"] = results["controld"]["package_digest"]
        fixture.assets[component["package_manifest_source"]] = (controld_raw, 0o400)

        keyholder_binary = ceremony / "buzz-ci-keyholder"
        write_file(keyholder_binary, b"keyholder-binary\n", 0o755)
        keyholder_provenance = ceremony / "keyholder-provenance.json"
        write_file(keyholder_provenance, canonical({
            "binary": "buzz-ci-keyholder", "profile": "release",
            "schema": KEYHOLDER_FREEZER.PROVENANCE_SCHEMA,
            "sha256": hashlib.sha256(keyholder_binary.read_bytes()).hexdigest(),
            "source_commit": candidate,
        }), 0o600)
        identities = draft["identities"]
        keyholder = identities["keyholder"]
        controld = identities["controld"]
        results["keyholder"] = KEYHOLDER_FREEZER.freeze_package(
            source_root,
            candidate,
            keyholder_binary,
            keyholder_provenance,
            None,
            ceremony / "packages/keyholder",
            keyholder_uid=keyholder["uid"],
            keyholder_gid=keyholder["gid"],
            controld_uid=controld["uid"],
            controld_gid=controld["gid"],
            public_binding=public_binding,
        )
        repeated_keyholder = KEYHOLDER_FREEZER.freeze_package(
            source_root,
            candidate,
            keyholder_binary,
            keyholder_provenance,
            None,
            ceremony / "packages/keyholder-repeat",
            keyholder_uid=keyholder["uid"],
            keyholder_gid=keyholder["gid"],
            controld_uid=controld["uid"],
            controld_gid=controld["gid"],
            public_binding=public_binding,
        )
        self.assertEqual(
            repeated_keyholder["package_digest"], results["keyholder"]["package_digest"],
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
            RENDER.write_output(root, output, canonical(value))
            return value
        finally:
            root.close()

    def _complete_prepared_state(self, ceremony: Path) -> dict[str, object]:
        state = ceremony / "state"
        state.chmod(0o700)
        frozen = state / "frozen-assets"
        frozen.mkdir(mode=0o700)
        asset_digests: dict[str, str] = {}
        harness_root = Path(HARNESS.__file__).resolve().parent
        for name in HARNESS.FROZEN_ASSETS:
            source = HARNESS.asset_source(harness_root, name)
            payload = source.read_bytes()
            write_file(frozen / name, payload, 0o400)
            asset_digests[name] = hashlib.sha256(payload).hexdigest()
        trusted = state / "trusted.qcow2"
        subprocess.run(
            [HARNESS.TOOLS["qemu_img"], "create", "-q", "-f", "qcow2", str(trusted), "1M"],
            check=True,
        )
        trusted.chmod(0o400)
        tool_digests = {
            name: hashlib.sha256(Path(path).read_bytes()).hexdigest()
            for name, path in HARNESS.TOOLS.items()
        }
        record = {
            "schema_version": HARNESS.STATE_SCHEMA,
            "challenge": "1" * 64,
            "image_sha256": "2" * 64,
            "qemu_sha256": tool_digests["qemu"],
            "qemu_img_sha256": tool_digests["qemu_img"],
            "qemu_version": "composition-test",
            "tool_sha256": tool_digests,
            "harness_sha256": asset_digests["harness.py"],
            "harness_asset_sha256": asset_digests,
            "timing_asset_sha256": asset_digests["timing-contract.json"],
            "timing": HARNESS.TIMING_CONTRACT,
            "timing_sha256": HARNESS.timing_sha256(),
            "trusted_image_sha256": hashlib.sha256(trusted.read_bytes()).hexdigest(),
        }
        write_file(state / "state.json", HARNESS.canonical(record), 0o400)
        return record

    def _harness_preflight(self, ceremony: Path, contract_name: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable, str(Path(HARNESS.__file__).resolve()), "preflight",
                "--contract", contract_name,
            ],
            cwd=ceremony, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False,
        )

    def test_five_package_bootstrap_composes_without_a_vm(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as directory:
            ceremony = Path(directory)
            source, candidate = self._source_checkout(ceremony)
            fixture_root = ceremony / "fixture"
            fixture_root.mkdir(mode=0o700)
            fixture = ACTIVATION_TESTS.ActivationFixture(fixture_root)
            draft = self._retarget_draft(fixture, candidate)
            public_path = ceremony / "state/public-binding.json"
            write_file(
                public_path,
                KEYHOLDER_FREEZER.canonical_public_binding(
                    self._public_binding(draft["acceptance_template"]["actor"]),
                ),
                0o444,
            )
            ready = self._ready_packages(
                ceremony, source, draft, fixture, candidate, public_path,
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

            template_document = copy.deepcopy(draft)
            template_document["source_commit"] = {"$copy": "candidate_sha"}
            template_execd = next(
                item for item in template_document["components"] if item["name"] == "execd"
            )
            template_execd["binary_sha256"] = {"$copy": "execd_preactivation.binary_sha256"}
            template_execd["provenance_sha256"] = {"$copy": "execd_preactivation.provenance_sha256"}
            template_execd["source_commit"] = {"$copy": "execd_preactivation.source_commit"}
            template_controld = next(
                item for item in template_document["components"] if item["name"] == "controld"
            )
            template_controld["package_manifest_sha256"] = {"$copy": "package_manifest_sha256.controld"}
            template_controld["package_digest"] = {"$copy": "packages.controld.package_digest"}
            template_path = ceremony / "activation-template.json"
            write_file(template_path, canonical({
                "schema_version": "buzz-ci-checked-render-template/v1",
                "kind": "activation-draft", "definitions": {}, "document": template_document,
            }), 0o600)
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
            self.assertEqual(
                (ceremony / "packages/keyholder/public-binding.json").read_bytes(),
                public_path.read_bytes(),
            )
            tampered_keyholder = copy.deepcopy(ready["keyholder"])
            tampered_keyholder["public_binding_sha256"] = "a" * 64
            del tampered_keyholder["package_digest"]
            tampered_keyholder["package_digest"] = hashlib.sha256(
                canonical(tampered_keyholder),
            ).hexdigest()
            tampered_keyholder_path = ceremony / "tampered-keyholder-manifest.json"
            write_file(tampered_keyholder_path, canonical(tampered_keyholder), 0o600)
            tampered_descriptor = copy.deepcopy(json.loads(draft_descriptor.read_bytes()))
            tampered_descriptor["package_manifests"]["keyholder"] = file_ref(
                ceremony, tampered_keyholder_path,
            )
            tampered_descriptor_path = self._write_descriptor(
                ceremony, "tampered-draft-descriptor.json", tampered_descriptor,
            )
            with self.assertRaisesRegex(RENDER.RenderError, "public binding digest differs"):
                self._render(
                    "render-draft", tampered_descriptor_path, "tampered-activation-draft.json",
                )
            rendered_execd = next(item for item in rendered_draft["components"] if item["name"] == "execd")
            self.assertEqual(
                (rendered_execd["binary_sha256"], rendered_execd["provenance_sha256"]),
                (preactivation["binary_sha256"], preactivation["provenance_sha256"]),
            )

            activation_path = ceremony / "packages/activation"
            activation_manifest = ACTIVATION_FREEZER.freeze_package(
                source, candidate, ceremony / "activation-draft.json", asset_root, activation_path,
            )
            repeated_activation = ACTIVATION_FREEZER.freeze_package(
                source,
                candidate,
                ceremony / "activation-draft.json",
                asset_root,
                ceremony / "packages/activation-repeat",
            )
            self.assertEqual(
                repeated_activation["package_digest"], activation_manifest["package_digest"],
            )
            execd_path = ceremony / "packages/execd"
            execd_manifest = EXECD_FREEZER.freeze_package(
                source, candidate, execd_binary, execd_provenance, preactivation_path,
                activation_path, execd_path,
            )
            repeated_execd = EXECD_FREEZER.freeze_package(
                source,
                candidate,
                execd_binary,
                execd_provenance,
                preactivation_path,
                activation_path,
                ceremony / "packages/execd-repeat",
            )
            self.assertEqual(repeated_execd["package_digest"], execd_manifest["package_digest"])
            self.assertEqual(
                execd_manifest["activation_binding"]["preactivation_input_sha256"],
                hashlib.sha256(preactivation_path.read_bytes()).hexdigest(),
            )

            manifests = {**ready, "execd": execd_manifest, "activation": activation_manifest}
            scenario = copy.deepcopy(fixture.scenario)
            scenario["fixture"].update({
                "integrated_candidate_sha": candidate,
                "source_oid": candidate,
                "activation_id": activation_manifest["activation_id"],
                "activation_package_digest": activation_manifest["package_digest"],
            })
            scenario_template = copy.deepcopy(scenario)
            for field, binding in (
                ("integrated_candidate_sha", "candidate_sha"),
                ("source_oid", "candidate_sha"),
                ("activation_id", "packages.activation.activation_id"),
                ("activation_package_digest", "packages.activation.package_digest"),
            ):
                scenario_template["fixture"][field] = {"$copy": binding}
            scenario_template_path = ceremony / "scenario-template.json"
            write_file(scenario_template_path, canonical({
                "schema_version": "buzz-ci-checked-render-template/v1",
                "kind": "capacity-one-scenario", "definitions": {}, "document": scenario_template,
            }), 0o600)
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

            seccomp_path = ceremony / "seccomp.json"
            write_file(seccomp_path, Path("/usr/share/containers/seccomp.json").read_bytes(), 0o644)
            state_record = self._complete_prepared_state(ceremony)
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
            clean_contract = self._render(
                "render-clean-host", clean_descriptor, "clean-host-contract.json",
            )
            expected_contract_keys = {
                "schema_version", "state", "candidate_root", "candidate_sha",
                "harness_sha256", "timing_asset_sha256", "timing", "timing_sha256",
                "scenario", "seccomp_source", "packages",
            }
            self.assertEqual(set(clean_contract), expected_contract_keys)
            self.assertEqual(clean_contract["schema_version"], HARNESS.SCHEMA)
            candidate_bindings = RENDER.candidate_clean_host_bindings(source, candidate)
            self.assertEqual(
                {
                    key: clean_contract[key]
                    for key in ("harness_sha256", "timing_asset_sha256", "timing", "timing_sha256")
                },
                {
                    key: candidate_bindings[key]
                    for key in ("harness_sha256", "timing_asset_sha256", "timing", "timing_sha256")
                },
            )
            candidate_guest = subprocess.check_output([
                "/usr/bin/git", "-C", str(source), "show",
                f"{candidate}:deploy/native-ci/activation/tests/clean_host_e2e/guest_entry.py",
            ])
            self.assertEqual(
                candidate_bindings["guest_entry_sha256"],
                hashlib.sha256(candidate_guest).hexdigest(),
            )
            self.assertEqual(set(clean_contract["packages"]), set(RENDER.PACKAGE_NAMES))
            self.assertEqual(INVENTORY.check_inventory(manifests)["status"], "pass")

            drifted_state = copy.deepcopy(state_record)
            drifted_state["harness_asset_sha256"]["guest_entry.py"] = "f" * 64
            write_file(ceremony / "state/state.json", HARNESS.canonical(drifted_state), 0o400)
            with self.assertRaisesRegex(
                RENDER.RenderError, "prepared state differs from candidate clean-host assets",
            ):
                self._render(
                    "render-clean-host", clean_descriptor, "rejected-state-contract.json",
                )
            self.assertFalse((ceremony / "rejected-state-contract.json").exists())
            write_file(ceremony / "state/state.json", HARNESS.canonical(state_record), 0o400)

            self.assertEqual(clean_contract["harness_sha256"], state_record["harness_sha256"])
            self.assertEqual(
                clean_contract["timing_asset_sha256"], state_record["timing_asset_sha256"],
            )
            preflight = self._harness_preflight(ceremony, "clean-host-contract.json")
            self.assertEqual(preflight.returncode, 0, preflight.stderr)
            self.assertEqual(json.loads(preflight.stdout)["status"], "ready")

            rejected_contracts = {
                "stale-v2": {**clean_contract, "schema_version": "buzz-ci-clean-host-e2e-vm-contract/v2"},
                "missing": {key: value for key, value in clean_contract.items() if key != "timing_sha256"},
                "extra": {**clean_contract, "unexpected": True},
                "timing-only": {
                    **clean_contract,
                    "timing": {**clean_contract["timing"], "schema_version": "stale"},
                },
                "harness-only": {**clean_contract, "harness_sha256": "f" * 64},
            }
            for label, rejected in rejected_contracts.items():
                contract_path = ceremony / f"rejected-{label}.json"
                write_file(contract_path, HARNESS.canonical(rejected), 0o600)
                process = self._harness_preflight(ceremony, contract_path.name)
                with self.subTest(contract=label):
                    self.assertNotEqual(process.returncode, 0)
                    self.assertIn("run contract", json.loads(process.stderr)["error"])

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

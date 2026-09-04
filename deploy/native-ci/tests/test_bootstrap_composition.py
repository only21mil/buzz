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
ACTIVATION_CONTROLLER = load_module(
    "bootstrap_activation_controller", ACTIVATION_ROOT / "controller.py",
)
INVENTORY = load_module("bootstrap_inventory", ACTIVATION_ROOT / "check_package_inventory.py")
RENDER = load_module("bootstrap_renderer", ACTIVATION_ROOT / "render_inputs/render_inputs.py")
TEMPLATE_GENERATOR = load_module(
    "bootstrap_template_generator",
    ACTIVATION_ROOT / "render_inputs/generate_checked_templates.py",
)
EXECD_FREEZER = load_module("bootstrap_execd_freezer", EXECD_ROOT / "freeze_package.py")
ACTIVATION_SCAFFOLD = load_module(
    "bootstrap_activation_scaffold",
    REPO_ROOT / "deploy/native-ci/tests/support/activation_scaffold.py",
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
    def test_production_bootstrap_has_one_event_owner_and_no_test_or_prior_seed(self) -> None:
        tracked = subprocess.run(
            ["git", "ls-files", "-z", "--", "."],
            cwd=REPO_ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        ).stdout.split(b"\0")
        serialized_placeholders = (
            b'{"type":"' + b'run"}',
            b'{"type":"' + b'grant"}',
            b'{"type":"' + b'rerun"}',
        )
        banned = (
            b"tests/test_activation_" + b"controller.py",
            b"bootstrap_activation_" + b"test_fixture",
            b"validated-activation-" + b"draft",
            *serialized_placeholders,
            *(value.replace(b'"', b'\\"') for value in serialized_placeholders),
        )
        event_owners = 0
        for raw_relative in tracked:
            if not raw_relative:
                continue
            relative = raw_relative.decode()
            if "/archive/" in relative or "/evidence/" in relative:
                continue
            path = REPO_ROOT / relative
            try:
                payload = path.read_bytes()
            except OSError:
                continue
            for marker in banned:
                self.assertNotIn(marker, payload, relative)
            event_owners += payload.count(
                b"def production_acceptance_" + b"template(",
            )
        self.assertEqual(event_owners, 1)

    def test_activation_template_generator_rejects_unsafe_input_and_never_clobbers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture_root = root / "fixture"
            fixture_root.mkdir(mode=0o700)
            fixture = ACTIVATION_SCAFFOLD.ActivationFixture(fixture_root)
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
                    "ci_event": {"public_key": "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5", "generation": 1},
                    "nip98": {"public_key": "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9", "generation": 1},
                    "manifest": {"public_key": "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13", "generation": 1},
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

        controld_entry = next(
            item for item in draft["entries"] if item["role"] == "controld_config"
        )
        controld_active = json.loads(fixture.assets[controld_entry["active_source"]][0])
        public = self._public_binding(draft["acceptance_template"]["actor"])
        draft["acceptance_template"] = ACTIVATION_PACKAGE.production_acceptance_template(
            actor_public_key=draft["acceptance_template"]["actor"]["public_key"],
            actor_generation=1,
            ci_signer_public_key=controld_active["keyholder_selectors"]["ci_event"]["public_key"],
            candidate_sha=candidate,
            workflow_id=controld_active["workflow_id"],
            workflow_digest=controld_active["workflow_digest"],
            job_id=controld_active["jobs"][0]["job_id"],
            channel_id=controld_active["channel_id"],
            repository_owner_public_key=ACTIVATION_SCAFFOLD.TEST_REPOSITORY_OWNER,
            repository_id=ACTIVATION_SCAFFOLD.TEST_REPOSITORY_ID,
            source_clone_url=ACTIVATION_SCAFFOLD.TEST_SOURCE_CLONE_URL,
            relay_http_origin=public["relay_http_origin"],
            export_subject=public["keyholder_public_spec"]["selectors"]["nip98"]["public_key"],
            export_generation=public["keyholder_public_spec"]["selectors"]["nip98"]["generation"],
            time_reference=draft["acceptance_template"]["time_reference"],
        )

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

    def _bind_admission_key(
        self,
        draft: dict[str, object],
        fixture: object,
        public: dict[str, object],
    ) -> dict[str, object]:
        """Retarget the draft to the ceremony's keyholder selectors.

        The manifest selector is the one source of the admission key: the execd
        lane manifest copies its public key and generation, the runner's static
        coordinates and every lane_manifest_digest follow, and controld carries
        the selectors themselves (package.validate_phase_configs binds them).
        """
        selectors = copy.deepcopy(public["keyholder_public_spec"]["selectors"])
        entries = {item["role"]: item for item in draft["entries"]}
        execd_entry = entries["execd_config"]
        lane_digest = ""
        for source_key, digest_key in (
            ("source", "sha256"), ("active_source", "active_sha256"),
        ):
            source = execd_entry[source_key]
            value = json.loads(fixture.assets[source][0])
            value["lane_manifest"]["admission_verifying_key"] = selectors["manifest"]["public_key"]
            value["lane_manifest"]["admission_key_generation"] = selectors["manifest"]["generation"]
            lane_digest = ACTIVATION_PACKAGE.lane_manifest_digest(value["lane_manifest"])
            value["lane_manifest_digest"] = lane_digest
            payload = canonical(value)
            fixture.assets[source] = (payload, 0o400)
            execd_entry[digest_key] = hashlib.sha256(payload).hexdigest()
        runner_entry = entries["runner_config"]
        runner_active = json.loads(fixture.assets[runner_entry["active_source"]][0])
        runner_active["lane_manifest_digest"] = lane_digest
        runner_active["admission_key_generation"] = selectors["manifest"]["generation"]
        payload = canonical(runner_active)
        fixture.assets[runner_entry["active_source"]] = (payload, 0o400)
        runner_entry["active_sha256"] = hashlib.sha256(payload).hexdigest()
        controld_entry = entries["controld_config"]
        controld_active = json.loads(fixture.assets[controld_entry["active_source"]][0])
        controld_active["keyholder_selectors"] = selectors
        controld_active["lane_manifest_digest"] = lane_digest
        payload = canonical(controld_active)
        fixture.assets[controld_entry["active_source"]] = (payload, 0o400)
        controld_entry["active_sha256"] = hashlib.sha256(payload).hexdigest()
        return controld_active

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
            fixture = ACTIVATION_SCAFFOLD.ActivationFixture(fixture_root)
            draft = self._retarget_draft(fixture, candidate)
            public = self._public_binding(draft["acceptance_template"]["actor"])
            controld_active = self._bind_admission_key(draft, fixture, public)
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
            draft = ACTIVATION_PACKAGE.production_activation_draft(
                source_commit=candidate,
                identities=draft["identities"],
                access_group=draft["access_group"],
                components=draft["components"],
                entries=draft["entries"],
                effective_systemd=draft["effective_systemd"],
                actor_public_key=public["acceptance_actor"]["public_key"],
                actor_generation=public["acceptance_actor"]["generation"],
                ci_signer_public_key=public["keyholder_public_spec"]["selectors"]["ci_event"]["public_key"],
                workflow_id=controld_active["workflow_id"],
                workflow_digest=controld_active["workflow_digest"],
                job_id=controld_active["jobs"][0]["job_id"],
                channel_id=controld_active["channel_id"],
                repository_owner_public_key=ACTIVATION_SCAFFOLD.TEST_REPOSITORY_OWNER,
                repository_id=ACTIVATION_SCAFFOLD.TEST_REPOSITORY_ID,
                source_clone_url=ACTIVATION_SCAFFOLD.TEST_SOURCE_CLONE_URL,
                relay_http_origin=public["relay_http_origin"],
                export_subject=public["keyholder_public_spec"]["selectors"]["nip98"]["public_key"],
                export_generation=public["keyholder_public_spec"]["selectors"]["nip98"]["generation"],
                time_reference=draft["acceptance_template"]["time_reference"],
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
            loaded_manifest, _loaded_payloads = ACTIVATION_CONTROLLER.load_package(
                activation_path, live=False,
            )
            self.assertEqual(loaded_manifest, activation_manifest)
            hostile_draft = copy.deepcopy(rendered_draft)
            hostile_runner = next(
                item for item in hostile_draft["components"] if item["name"] == "runner"
            )
            runner_asset = asset_root / Path(hostile_runner["package_manifest_source"]).name
            original_runner_raw = runner_asset.read_bytes()
            hostile_package = json.loads(original_runner_raw)
            hostile_tmpfiles = next(
                item for item in hostile_package["entries"] if item["role"] == "tmpfiles"
            )
            hostile_tmpfiles["sha256"] = "f" * 64
            hostile_unsigned = {
                key: value for key, value in hostile_package.items() if key != "package_digest"
            }
            hostile_package["package_digest"] = hashlib.sha256(canonical(hostile_unsigned)).hexdigest()
            hostile_raw = canonical(hostile_package)
            hostile_runner["package_manifest_sha256"] = hashlib.sha256(hostile_raw).hexdigest()
            hostile_runner["package_digest"] = hostile_package["package_digest"]
            hostile_draft_path = ceremony / "hostile-activation-draft.json"
            write_file(hostile_draft_path, canonical(hostile_draft), 0o600)
            write_file(runner_asset, hostile_raw, 0o400)
            with self.assertRaisesRegex(ValueError, "runner package tmpfiles source binding differs"):
                ACTIVATION_FREEZER.freeze_package(
                    source, candidate, hostile_draft_path, asset_root,
                    ceremony / "packages/hostile-activation",
                )
            write_file(runner_asset, original_runner_raw, 0o400)
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
            checked_scenario = json.loads(scenario_template_path.read_bytes())
            self.assertEqual(
                checked_scenario["document"]["fixture"]["grant_event_id"],
                {"$copy": "activation_grant_event_id"},
            )
            scenario["fixture"]["request_digest"] = ACTIVATION_PACKAGE.digest(
                json.dumps(
                    activation_manifest["acceptance_template"]["run_event"],
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode()
            )
            scenario["fixture"]["grant_event_id"] = ACTIVATION_PACKAGE.digest(
                json.dumps(
                    activation_manifest["acceptance_template"]["grant_event"],
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode()
            )
            scenario["fixture"]["approved_by"] = (
                activation_manifest["acceptance_template"]["actor"]["public_key"]
            )
            scenario["fixture"].update({
                "run_id": RENDER.activation_run_id(activation_manifest),
                "failure_run_id": RENDER.activation_failure_run_id(activation_manifest),
                "failure_selector": RENDER.activation_failure_selector(activation_manifest),
                "failure_request_digest": RENDER.activation_failure_request_digest(activation_manifest),
                "manifest_digest": RENDER.activation_fixture_manifest_sha256(activation_manifest),
                "export_subject": RENDER.activation_export_subject(activation_manifest),
                "export_generation": RENDER.activation_export_generation(activation_manifest),
                "export_authorization_digest": RENDER.activation_export_authorization_digest(activation_manifest),
            })
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
                ACTIVATION_CONTROLLER._acceptance_binding(
                    activation_manifest, json.loads(scenario_raw),
                )["scenario_sha256"],
                scenario_sha256,
            )

            # The prior activation the guest activates and rolls back before the candidate
            # activation: a distinct package frozen from the same candidate, here with another
            # repository binding, sharing every component package and principal.
            prior_draft = ACTIVATION_PACKAGE.production_activation_draft(
                source_commit=candidate,
                identities=draft["identities"],
                access_group=draft["access_group"],
                components=draft["components"],
                entries=draft["entries"],
                effective_systemd=draft["effective_systemd"],
                actor_public_key=public["acceptance_actor"]["public_key"],
                actor_generation=public["acceptance_actor"]["generation"],
                ci_signer_public_key=public["keyholder_public_spec"]["selectors"]["ci_event"]["public_key"],
                workflow_id=controld_active["workflow_id"],
                workflow_digest=controld_active["workflow_digest"],
                job_id=controld_active["jobs"][0]["job_id"],
                channel_id=controld_active["channel_id"],
                repository_owner_public_key=ACTIVATION_SCAFFOLD.TEST_REPOSITORY_OWNER,
                repository_id=ACTIVATION_SCAFFOLD.TEST_REPOSITORY_ID + "-prior",
                source_clone_url=ACTIVATION_SCAFFOLD.TEST_SOURCE_CLONE_URL,
                relay_http_origin=public["relay_http_origin"],
                export_subject=public["keyholder_public_spec"]["selectors"]["nip98"]["public_key"],
                export_generation=public["keyholder_public_spec"]["selectors"]["nip98"]["generation"],
                time_reference=draft["acceptance_template"]["time_reference"],
            )
            prior_root = ceremony / "prior"
            (prior_root / "packages").mkdir(parents=True, mode=0o700)
            prior_draft_path = prior_root / "activation-draft.json"
            write_file(prior_draft_path, ACTIVATION_PACKAGE.canonical_json(prior_draft), 0o600)
            prior_activation_path = prior_root / "packages/activation"
            prior_activation_manifest = ACTIVATION_FREEZER.freeze_package(
                source, candidate, prior_draft_path, asset_root, prior_activation_path,
            )
            self.assertNotEqual(prior_activation_manifest["activation_id"], activation_manifest["activation_id"])
            self.assertNotEqual(prior_activation_manifest["package_digest"], activation_manifest["package_digest"])
            self.assertEqual(prior_activation_manifest["components"], activation_manifest["components"])
            prior_execd_path = prior_root / "packages/execd"
            prior_execd_manifest = EXECD_FREEZER.freeze_package(
                source, candidate, execd_binary, execd_provenance, preactivation_path,
                prior_activation_path, prior_execd_path,
            )
            self.assertEqual(
                prior_execd_manifest["activation_binding"]["activation_id"],
                prior_activation_manifest["activation_id"],
            )
            self.assertNotEqual(prior_execd_manifest["package_digest"], execd_manifest["package_digest"])
            self.assertEqual(
                prior_execd_manifest["activation_binding"]["execd_binary_sha256"],
                execd_manifest["activation_binding"]["execd_binary_sha256"],
            )
            prior_scenario = copy.deepcopy(scenario)
            prior_scenario["fixture"].update({
                "activation_id": prior_activation_manifest["activation_id"],
                "activation_package_digest": prior_activation_manifest["package_digest"],
                "run_id": RENDER.activation_run_id(prior_activation_manifest),
                "failure_run_id": RENDER.activation_failure_run_id(prior_activation_manifest),
                "failure_selector": RENDER.activation_failure_selector(prior_activation_manifest),
                "failure_request_digest": RENDER.activation_failure_request_digest(prior_activation_manifest),
                "manifest_digest": RENDER.activation_fixture_manifest_sha256(prior_activation_manifest),
                "export_subject": RENDER.activation_export_subject(prior_activation_manifest),
                "export_generation": RENDER.activation_export_generation(prior_activation_manifest),
                "export_authorization_digest": RENDER.activation_export_authorization_digest(prior_activation_manifest),
                "request_digest": ACTIVATION_PACKAGE.digest(
                    json.dumps(
                        prior_activation_manifest["acceptance_template"]["run_event"],
                        ensure_ascii=False, separators=(",", ":"),
                    ).encode()
                ),
                "grant_event_id": ACTIVATION_PACKAGE.digest(
                    json.dumps(
                        prior_activation_manifest["acceptance_template"]["grant_event"],
                        ensure_ascii=False, separators=(",", ":"),
                    ).encode()
                ),
            })
            prior_scenario_path = prior_root / "capacity-one-scenario.json"
            write_file(prior_scenario_path, RENDER.canonical_scenario(prior_scenario), 0o600)
            prior_scenario_raw = prior_scenario_path.read_bytes()
            prior_scenario_sha256 = hashlib.sha256(prior_scenario_raw).hexdigest()
            self.assertNotEqual(prior_scenario_sha256, scenario_sha256)

            seccomp_path = ceremony / "seccomp.json"
            seccomp = b'{"defaultAction":"SCMP_ACT_ERRNO"}\n'
            write_file(seccomp_path, seccomp, 0o644)
            seccomp_sha256 = hashlib.sha256(seccomp).hexdigest()
            self.assertEqual(file_ref(ceremony, seccomp_path)["sha256"], seccomp_sha256)

            def package_tree(prefix: str, name: str) -> dict[str, object]:
                manifest_name = "activation-manifest.json" if name == "activation" else "package-manifest.json"
                reference = file_ref(ceremony, ceremony / f"{prefix}packages/{name}/{manifest_name}")
                return {
                    "path": f"{prefix}packages/{name}",
                    "manifest_sha256": reference["sha256"],
                    "manifest_bytes": reference["bytes"],
                    "manifest_mode": reference["mode"],
                }

            clean_descriptor = self._write_descriptor(ceremony, "clean-descriptor.json", {
                "schema_version": "buzz-ci-clean-host-contract-render-input/v1",
                "candidate_sha": candidate,
                "state": "state",
                "candidate_root": "candidate",
                "public_binding": file_ref(ceremony, public_path),
                "scenario": file_ref(ceremony, ceremony / "capacity-one-scenario.json"),
                "seccomp_source": file_ref(ceremony, seccomp_path),
                "packages": {name: package_tree("", name) for name in RENDER.PACKAGE_NAMES},
                "prior_packages": {name: package_tree("prior/", name) for name in RENDER.PRIOR_PACKAGE_NAMES},
                "prior_scenario": file_ref(ceremony, prior_scenario_path),
            })
            with mock.patch.object(RENDER, "SECCOMP_SHA256", seccomp_sha256):
                clean_contract = self._render(
                    "render-clean-host", clean_descriptor, "clean-host-contract.json",
                )
            self.assertEqual(set(clean_contract["packages"]), set(RENDER.PACKAGE_NAMES))
            self.assertEqual(set(clean_contract["prior_packages"]), set(RENDER.PRIOR_PACKAGE_NAMES))
            self.assertEqual(clean_contract["seccomp_source"]["sha256"], seccomp_sha256)
            self.assertEqual(clean_contract["scenario"]["sha256"], scenario_sha256)
            self.assertEqual(clean_contract["prior_scenario"]["sha256"], prior_scenario_sha256)
            self.assertEqual(clean_contract["platform_systemd"], RENDER.PLATFORM_SYSTEMD)
            for name in RENDER.PRIOR_PACKAGE_NAMES:
                self.assertNotEqual(
                    clean_contract["prior_packages"][name]["tree_sha256"],
                    clean_contract["packages"][name]["tree_sha256"],
                )
            same_prior_descriptor = json.loads(clean_descriptor.read_bytes())
            same_prior_descriptor["prior_packages"] = {
                name: package_tree("", name) for name in RENDER.PRIOR_PACKAGE_NAMES
            }
            same_prior_descriptor["prior_scenario"] = file_ref(ceremony, scenario_path)
            same_prior_descriptor_path = self._write_descriptor(
                ceremony, "same-prior-clean-descriptor.json", same_prior_descriptor,
            )
            with mock.patch.object(
                RENDER, "SECCOMP_SHA256", seccomp_sha256,
            ), self.assertRaisesRegex(RENDER.RenderError, "prior activation does not differ"):
                self._render(
                    "render-clean-host", same_prior_descriptor_path, "same-prior-clean-host-contract.json",
                )

            stale_scenario = copy.deepcopy(scenario)
            stale_scenario["fixture"]["grant_event_id"] = "8" * 64
            write_file(scenario_path, RENDER.canonical_scenario(stale_scenario), 0o600)
            stale_clean_descriptor = json.loads(clean_descriptor.read_bytes())
            stale_clean_descriptor["scenario"] = file_ref(ceremony, scenario_path)
            stale_clean_descriptor_path = self._write_descriptor(
                ceremony, "stale-grant-clean-descriptor.json", stale_clean_descriptor,
            )
            with mock.patch.object(
                RENDER, "SECCOMP_SHA256", seccomp_sha256,
            ), self.assertRaisesRegex(RENDER.RenderError, "cross-binding differs"):
                self._render(
                    "render-clean-host",
                    stale_clean_descriptor_path,
                    "stale-grant-clean-host-contract.json",
                )
            write_file(scenario_path, scenario_raw, 0o600)
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
                        harness_records,
                        harness_scenario_raw,
                        _harness_seccomp_raw,
                        harness_prior_scenario_raw,
                    ) = CLEAN_HOST_HARNESS.validate_contract(
                        ceremony / "clean-host-contract.json",
                    )
            finally:
                os.chdir(previous_directory)
            self.assertEqual(harness_contract["scenario"]["sha256"], scenario_sha256)
            self.assertEqual(harness_scenario_raw, scenario_raw)
            self.assertEqual(harness_prior_scenario_raw, prior_scenario_raw)
            self.assertEqual(
                CLEAN_HOST_HARNESS.prior_activation_binding(harness_records),
                {
                    "activation_id": prior_activation_manifest["activation_id"],
                    "package_digest": prior_activation_manifest["package_digest"],
                },
            )

            guest_stage = ceremony / "guest-stage"
            guest_inputs = guest_stage / "inputs"
            guest_inputs.mkdir(parents=True)
            for name in RENDER.PACKAGE_NAMES:
                shutil.copytree(ceremony / f"packages/{name}", guest_inputs / name)
            (guest_inputs / "prior").mkdir()
            for name in RENDER.PRIOR_PACKAGE_NAMES:
                shutil.copytree(ceremony / f"prior/packages/{name}", guest_inputs / "prior" / name)
            shutil.copyfile(prior_scenario_path, guest_inputs / "prior/scenario.json")
            shutil.copyfile(scenario_path, guest_inputs / "scenario.json")
            shutil.copyfile(seccomp_path, guest_inputs / "seccomp.json")
            shutil.copyfile(public_path, guest_inputs / "public-binding.json")
            subprocess.run(
                [
                    "tar", "-cf", str(guest_stage / "candidate.tar"), "-C", str(source),
                    "deploy/native-ci/activation/tests/clean_host_e2e/harness.py",
                    "deploy/native-ci/activation/tests/clean_host_e2e/timing-contract.json",
                    "deploy/native-ci/activation/platform/fedora-44-systemd-259/10-timeout-abort.conf",
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
                "platform_systemd": clean_contract["platform_systemd"],
                "prior_package_tree_sha256": {
                    name: clean_contract["prior_packages"][name]["tree_sha256"]
                    for name in RENDER.PRIOR_PACKAGE_NAMES
                },
                "prior_scenario_sha256": prior_scenario_sha256,
            }
            with (
                mock.patch.object(CLEAN_HOST_GUEST, "STATE_ROOT", guest_state),
                mock.patch.object(
                    CLEAN_HOST_GUEST,
                    "TIMING_PATH",
                    source / "deploy/native-ci/activation/tests/clean_host_e2e/timing-contract.json",
                ),
                mock.patch.object(CLEAN_HOST_GUEST, "SECCOMP_SHA256", seccomp_sha256),
                mock.patch.object(CLEAN_HOST_GUEST, "verify_platform_systemd") as platform_check,
            ):
                _candidate_path, guest_scenario, _guest_public, guest_channel = CLEAN_HOST_GUEST.cross_bind(
                    guest_stage, guest_descriptor,
                )
            platform_check.assert_called_once_with(clean_contract["platform_systemd"])
            self.assertEqual(RENDER.canonical_scenario(guest_scenario), scenario_raw)
            self.assertEqual(guest_channel, "12345678-1234-4abc-8def-123456789abc")

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

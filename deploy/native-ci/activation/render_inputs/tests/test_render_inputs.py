#!/usr/bin/env python3
"""Focused tests for descriptor-bound activation input rendering."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "render_inputs.py"
SPEC = importlib.util.spec_from_file_location("render_inputs", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
RENDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RENDER)

CANDIDATE = "c" * 40
HEX = {
    "scenario": "1" * 64,
    "config": "2" * 64,
    "units": "3" * 64,
}


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def write_json(root: Path, relative: str, value: object, mode: int = 0o600) -> dict[str, object]:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = canonical(value)
    path.write_bytes(raw)
    path.chmod(mode)
    return {"path": relative, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw), "mode": f"{mode:04o}"}


def file_ref(root: Path, relative: str) -> dict[str, object]:
    path = root / relative
    raw = path.read_bytes()
    return {
        "path": relative,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "mode": f"{path.stat().st_mode & 0o7777:04o}",
    }


def public_binding() -> dict[str, object]:
    keys = ["4" * 64, "5" * 64, "6" * 64, "7" * 64]
    return {
        "schema_version": "buzz-ci-clean-host-e2e-public-binding/v2",
        "relay_url": "wss://relay.test.invalid:3443",
        "relay_http_origin": "https://relay.test.invalid:3443",
        "acceptance_actor": {"public_key": keys[0], "generation": 1},
        "keyholder_public_spec": {
            "schema_version": 1,
            "peer": {"uid": 1201, "gid": 1201, "allowed_operations": [
                "describe", "sign_ci_event", "nip98_authorize", "sign_manifest",
                "describe_acceptance", "sign_acceptance_mutation",
            ]},
            "selectors": {
                "ci_event": {"public_key": keys[1], "generation": 1},
                "nip98": {"public_key": keys[2], "generation": 1},
                "manifest": {"public_key": keys[3], "generation": 1},
            },
            "nip98_origin": "https://relay.test.invalid:3443",
            "acceptance": {
                "binding_receipt_path": "/var/lib/buzzci/activation-controller/controld-acceptance-v1.json",
                "credential_selector": "acceptance-actor.key",
            },
        },
    }


def minimal_manifest(name: str, source: str, raw: bytes, mode: int = 0o400) -> dict[str, object]:
    unsigned: dict[str, object] = {
        "schema": f"test-{name}-package-v1",
        "source_commit": CANDIDATE,
        "entries": [{
            "role": "payload", "source": source, "source_mode": f"{mode:04o}",
            "sha256": hashlib.sha256(raw).hexdigest(),
        }],
    }
    return {**unsigned, "package_digest": hashlib.sha256(canonical(unsigned)).hexdigest()}


class RendererTests(unittest.TestCase):
    def test_schema_documents_and_relative_references_are_valid(self) -> None:
        acceptance = ROOT.parents[1] / "acceptance"
        schema_paths = (
            ROOT / "descriptor.schema.json",
            ROOT / "output.schema.json",
            acceptance / "scenario.schema.json",
            acceptance / "receipt.schema.json",
        )
        for schema_path in schema_paths:
            schema = json.loads(schema_path.read_bytes())
            stack: list[object] = [schema]
            while stack:
                value = stack.pop()
                if isinstance(value, dict):
                    pattern = value.get("pattern")
                    if isinstance(pattern, str):
                        re.compile(pattern)
                    stack.extend(value.values())
                elif isinstance(value, list):
                    stack.extend(value)
        metaschema = subprocess.run(
            ["check-jsonschema", "--check-metaschema", *map(str, schema_paths)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(metaschema.returncode, 0, metaschema.stderr)
        output = subprocess.run(
            [
                "check-jsonschema",
                "--schemafile",
                str(ROOT / "output.schema.json"),
                str(acceptance / "scenario.template.json"),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(output.returncode, 0, output.stderr)

    def test_scenario_render_matches_current_schema_and_closed_zero_package(self) -> None:
        acceptance = ROOT.parents[1] / "acceptance"
        scenario = json.loads((acceptance / "scenario.template.json").read_bytes())
        fixture = scenario["fixture"]
        activation = {
            "activation_id": fixture["activation_id"],
            "package_digest": fixture["activation_package_digest"],
            "default_state": {
                "capacity": 0,
                "enabled": False,
                "active": False,
                "provisioned": False,
            },
        }
        bindings = {
            "candidate_sha": fixture["integrated_candidate_sha"],
            "packages": {"activation": activation},
        }
        template = {
            "schema_version": "buzz-ci-checked-render-template/v1",
            "kind": "capacity-one-scenario",
            "definitions": {},
            "document": scenario,
        }
        descriptor = {
            "schema_version": "buzz-ci-capacity-one-scenario-render-input/v1",
            "candidate_sha": fixture["integrated_candidate_sha"],
            "public_binding": {
                "path": "public.json",
                "sha256": "1" * 64,
                "bytes": 1,
                "mode": "0400",
            },
            "package_manifests": {
                name: {
                    "path": f"{name}.json",
                    "sha256": character * 64,
                    "bytes": 1,
                    "mode": "0400",
                }
                for name, character in zip(RENDER.PACKAGE_NAMES, "23456", strict=True)
            },
            "template": {
                "path": "template.json",
                "sha256": "7" * 64,
                "bytes": 1,
                "mode": "0400",
            },
        }
        with mock.patch.object(RENDER, "load_template_bindings", return_value=(template, bindings)):
            rendered = RENDER.render_scenario(mock.Mock(), descriptor)
        self.assertEqual(rendered, scenario)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            descriptor_path = root / "descriptor.json"
            output_path = root / "scenario.json"
            descriptor_path.write_bytes(canonical(descriptor))
            output_path.write_bytes(canonical(rendered))
            for schema, instance in (
                (ROOT / "descriptor.schema.json", descriptor_path),
                (ROOT / "output.schema.json", output_path),
            ):
                result = subprocess.run(
                    ["check-jsonschema", "--schemafile", str(schema), str(instance)],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

        open_activation = {
            **activation,
            "default_state": {**activation["default_state"], "capacity": 1},
        }
        bindings["packages"] = {"activation": open_activation}
        with self.assertRaisesRegex(RENDER.RenderError, "closed capacity zero"):
            RENDER.validate_scenario(scenario, bindings)

    def test_scenario_cli_renders_descriptor_bound_final_candidate(self) -> None:
        acceptance = ROOT.parents[1] / "acceptance"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code_root = root / "code/native-ci"
            renderer = code_root / "activation/render_inputs/render_inputs.py"
            verifier = code_root / "acceptance/verify-receipt.py"
            renderer.parent.mkdir(parents=True)
            verifier.parent.mkdir(parents=True)
            renderer.write_bytes(SCRIPT.read_bytes())
            verifier.write_bytes((acceptance / "verify-receipt.py").read_bytes())
            (code_root / "activation/package.py").write_text(
                "def validate_manifest(value, **_kwargs):\n"
                "    if value.get('default_state') != {\n"
                "        'capacity': 0, 'enabled': False, 'active': False, 'provisioned': False\n"
                "    }:\n"
                "        raise ValueError('default state differs')\n"
            )

            entry = {
                "role": "payload",
                "source": "assets/payload",
                "target": "/opt/buzzci/payload",
                "source_mode": "0400",
                "install_mode": "0400",
                "uid": 0,
                "gid": 0,
                "sha256": "8" * 64,
            }
            zero = {
                "capacity": 0,
                "enabled": False,
                "active": False,
                "provisioned": False,
            }
            activation_draft = {
                "schema": "buzz-ci-capacity-one-activation-draft-v1",
                "source_commit": CANDIDATE,
                "default_state": zero,
                "entries": [entry],
            }
            activation_digest = hashlib.sha256(canonical(activation_draft)).hexdigest()
            activation = {
                **activation_draft,
                "schema": "buzz-ci-capacity-one-activation-package-v1",
                "activation_id": (
                    f"buzz-ci-capacity-one-{CANDIDATE[:12]}-{activation_digest[:12]}"
                ),
                "package_digest": activation_digest,
            }

            manifests: dict[str, dict[str, object]] = {}
            for name in RENDER.PACKAGE_NAMES[:-1]:
                manifest = {key: {} for key in RENDER.PACKAGE_KEYS[name]}
                manifest.update(
                    {
                        "schema": RENDER.PACKAGE_SCHEMAS[name],
                        "source_commit": CANDIDATE,
                        "entries": [entry],
                    }
                )
                if name == "execd":
                    manifest["activation_binding"] = {
                        "source_commit": CANDIDATE,
                        "package_digest": activation_digest,
                        "activation_id": activation["activation_id"],
                    }
                unsigned = {key: value for key, value in manifest.items() if key != "package_digest"}
                manifest["package_digest"] = hashlib.sha256(canonical(unsigned)).hexdigest()
                manifests[name] = manifest
            manifests["activation"] = activation

            references = {
                name: write_json(root, f"inputs/{name}.json", manifest, 0o400)
                for name, manifest in manifests.items()
            }
            public_ref = write_json(root, "inputs/public.json", public_binding(), 0o400)
            scenario = json.loads((acceptance / "scenario.template.json").read_bytes())
            scenario["fixture"].update(
                {
                    "integrated_candidate_sha": CANDIDATE,
                    "source_oid": CANDIDATE,
                    "activation_id": activation["activation_id"],
                    "activation_package_digest": activation_digest,
                }
            )
            template_ref = write_json(
                root,
                "inputs/scenario-template.json",
                {
                    "schema_version": "buzz-ci-checked-render-template/v1",
                    "kind": "capacity-one-scenario",
                    "definitions": {},
                    "document": scenario,
                },
                0o400,
            )
            descriptor = {
                "schema_version": "buzz-ci-capacity-one-scenario-render-input/v1",
                "candidate_sha": CANDIDATE,
                "public_binding": public_ref,
                "package_manifests": references,
                "template": template_ref,
            }
            descriptor_ref = write_json(root, "descriptor.json", descriptor)
            process = subprocess.run(
                [
                    "python3",
                    str(renderer),
                    "render-scenario",
                    "--descriptor",
                    str(root / descriptor_ref["path"]),
                    "--output",
                    "scenario.json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            rendered = json.loads((root / "scenario.json").read_bytes())
            self.assertEqual(rendered, scenario)
            self.assertEqual(rendered["fixture"]["integrated_candidate_sha"], CANDIDATE)

    def make_lifecycle(self, root: Path) -> dict[str, object]:
        proof = {
            "configs_sha256": HEX["config"], "units_sha256": HEX["units"],
            "sockets_absent": True, "processes_absent": True,
            "encrypted_credentials_absent": True, "relay_residue_absent": True,
        }
        trees = {name: digit * 64 for name, digit in zip(RENDER.PACKAGE_NAMES, "89abc", strict=True)}
        contract = {
            "schema_version": "buzz-ci-clean-host-e2e-vm-contract/v2", "candidate_sha": CANDIDATE,
            "state": "state", "candidate_root": "candidate",
            "scenario": {"path": "scenario.json", "sha256": HEX["scenario"]},
            "seccomp_source": {"path": "seccomp.json", "sha256": RENDER.SECCOMP_SHA256},
            "packages": {name: {"path": name, "tree_sha256": trees[name]} for name in RENDER.PACKAGE_NAMES},
        }
        receipt = {"outcome": "pass", "integrated_candidate_sha": CANDIDATE, "scenario_sha256": HEX["scenario"]}
        verifier = {"status": "pass"}
        receipt_ref = write_json(root, "evidence/acceptance-receipt.json", receipt, 0o400)
        verifier_ref = write_json(root, "evidence/verifier.json", verifier, 0o400)
        evidence = {
            "schema_version": "buzz-ci-clean-host-e2e-evidence/v2", "candidate_sha": CANDIDATE,
            "image_sha256": "d" * 64, "tool_sha256": {"qemu": "e" * 64},
            "harness_asset_sha256": {"guest_entry.py": "f" * 64},
            "package_tree_sha256": trees, "scenario_sha256": HEX["scenario"],
            "seccomp_source_sha256": RENDER.SECCOMP_SHA256,
            "receipt_sha256": receipt_ref["sha256"], "verifier_sha256": verifier_ref["sha256"],
            "dormant_proof": proof,
        }
        evidence_ref = write_json(root, "evidence/evidence-manifest.json", evidence, 0o400)
        contract_ref = write_json(root, "evidence/contract.json", contract, 0o400)
        result = {
            "status": "pass", "candidate_sha": CANDIDATE, "vm_state_absent": True,
            "receipt_sha256": receipt_ref["sha256"], "verifier_sha256": verifier_ref["sha256"],
            "evidence_manifest_sha256": evidence_ref["sha256"], "dormant_proof": proof,
        }
        result_ref = write_json(root, "evidence/result.json", result, 0o400)
        return {
            "result": result_ref, "contract": contract_ref, "evidence_manifest": evidence_ref,
            "acceptance_receipt": receipt_ref, "verifier": verifier_ref,
        }

    def run_cli(self, root: Path, action: str, descriptor: dict[str, object], output: str) -> subprocess.CompletedProcess[str]:
        descriptor_ref = write_json(root, "descriptor.json", descriptor)
        return subprocess.run(
            ["python3", str(SCRIPT), action, "--descriptor", str(root / descriptor_ref["path"]), "--output", output],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )

    def test_residue_is_reproducible_and_disclaims_external_gates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lifecycle = self.make_lifecycle(root)
            descriptor = {
                "schema_version": "buzz-ci-residue-receipt-render-input/v1",
                "candidate_sha": CANDIDATE, "lifecycle": lifecycle,
            }
            first = self.run_cli(root, "record-residue", descriptor, "first.json")
            self.assertEqual(first.returncode, 0, first.stderr)
            second = self.run_cli(root, "record-residue", descriptor, "second.json")
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual((root / "first.json").read_bytes(), (root / "second.json").read_bytes())
            value = json.loads((root / "first.json").read_bytes())
            self.assertEqual(value["claims"], {"protected_ci": False, "tier2": False})
            self.assertEqual(value["lifecycle_status"], "verified_pass")
            self.assertEqual((root / "first.json").stat().st_mode & 0o7777, 0o600)

    def test_bound_lifecycle_mutation_fails_without_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lifecycle = self.make_lifecycle(root)
            descriptor = {
                "schema_version": "buzz-ci-residue-receipt-render-input/v1",
                "candidate_sha": CANDIDATE, "lifecycle": lifecycle,
            }
            write_json(root, "descriptor.json", descriptor)
            evidence = root / "evidence/evidence-manifest.json"
            raw = bytearray(evidence.read_bytes())
            raw[10] ^= 1
            evidence.chmod(0o600)
            evidence.write_bytes(raw)
            evidence.chmod(0o400)
            process = subprocess.run(
                ["python3", str(SCRIPT), "record-residue", "--descriptor", str(root / "descriptor.json"), "--output", "rejected.json"],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            self.assertEqual(process.returncode, 64)
            self.assertIn("digest differs", process.stderr)
            self.assertFalse((root / "rejected.json").exists())

    def test_symlinked_reference_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lifecycle = self.make_lifecycle(root)
            target = root / "evidence/verifier.json"
            link = root / "verifier-link.json"
            link.symlink_to(target)
            lifecycle["verifier"] = {
                **lifecycle["verifier"], "path": "verifier-link.json",
            }
            descriptor = {
                "schema_version": "buzz-ci-residue-receipt-render-input/v1",
                "candidate_sha": CANDIDATE, "lifecycle": lifecycle,
            }
            process = self.run_cli(root, "record-residue", descriptor, "rejected.json")
            self.assertEqual(process.returncode, 64)
            self.assertFalse((root / "rejected.json").exists())

    def test_template_cycle_and_unknown_directive_are_rejected(self) -> None:
        cycle = {
            "schema_version": "buzz-ci-checked-render-template/v1", "kind": "activation-draft",
            "definitions": {"a": {"$ref": "#/definitions/b"}, "b": {"$ref": "#/definitions/a"}},
            "document": {"$ref": "#/definitions/a"},
        }
        with self.assertRaisesRegex(RENDER.RenderError, "cycle"):
            RENDER.resolve_template(cycle, "activation-draft", {"candidate_sha": CANDIDATE})
        cycle["document"] = {"$env": "SECRET"}
        with self.assertRaisesRegex(RENDER.RenderError, "unknown"):
            RENDER.resolve_template(cycle, "activation-draft", {"candidate_sha": CANDIDATE})

    def test_package_tree_rejects_extra_and_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            package = root_path / "runner"
            (package / "assets").mkdir(parents=True)
            package.chmod(0o700)
            (package / "assets").chmod(0o700)
            payload = b"payload\n"
            source = package / "assets/payload"
            source.write_bytes(payload)
            source.chmod(0o400)
            manifest = minimal_manifest("runner", "assets/payload", payload)
            manifest_ref = write_json(root_path, "runner/package-manifest.json", manifest)
            descriptor = {
                "path": "runner", "manifest_sha256": manifest_ref["sha256"],
                "manifest_bytes": manifest_ref["bytes"], "manifest_mode": manifest_ref["mode"],
            }
            descriptor_path = root_path / "descriptor.json"
            descriptor_path.write_bytes(canonical({"unused": True}))
            descriptor_path.chmod(0o600)
            root = RENDER.DescriptorRoot(descriptor_path)
            try:
                with mock.patch.object(RENDER, "validate_manifest"):
                    _manifest, _manifest_sha, digest = RENDER.validate_package_tree(root, "runner", descriptor, CANDIDATE)
                self.assertRegex(digest, r"^[0-9a-f]{64}$")
                extra = package / "extra"
                extra.write_bytes(b"extra")
                extra.chmod(0o400)
                with mock.patch.object(RENDER, "validate_manifest"), self.assertRaisesRegex(RENDER.RenderError, "extra"):
                    RENDER.validate_package_tree(root, "runner", descriptor, CANDIDATE)
                extra.unlink()
                source.chmod(0o600)
                source.write_bytes(b"PAYLOAD\n")
                source.chmod(0o400)
                with mock.patch.object(RENDER, "validate_manifest"), self.assertRaisesRegex(RENDER.RenderError, "metadata differs"):
                    RENDER.validate_package_tree(root, "runner", descriptor, CANDIDATE)
            finally:
                root.close()

    def test_public_binding_rejects_secret_fields(self) -> None:
        binding = public_binding()
        RENDER.validate_public_binding(binding)
        binding["secret_key"] = "8" * 64
        with self.assertRaisesRegex(RENDER.RenderError, "shape differs|private"):
            RENDER.validate_public_binding(binding)

    def test_sealed_freeze_requires_cross_bound_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            lifecycle = self.make_lifecycle(root_path)
            public_ref = write_json(root_path, "state/public-binding.json", public_binding(), 0o444)
            refs: dict[str, object] = {}
            manifests: dict[str, object] = {}
            activation_digest = "a" * 64
            for name in RENDER.PACKAGE_NAMES:
                payload = name.encode()
                manifest = minimal_manifest(name, f"assets/{name}", payload)
                if name == "activation":
                    unsigned = dict(manifest)
                    unsigned.pop("package_digest")
                    unsigned["schema"] = "buzz-ci-capacity-one-activation-draft-v1"
                    activation_digest = hashlib.sha256(canonical(unsigned)).hexdigest()
                    manifest = {
                        **unsigned, "schema": "buzz-ci-capacity-one-activation-package-v1",
                        "activation_id": f"buzz-ci-capacity-one-{CANDIDATE[:12]}-{activation_digest[:12]}",
                        "package_digest": activation_digest,
                    }
                manifest_name = "activation-manifest.json" if name == "activation" else "package-manifest.json"
                refs[name] = write_json(root_path, f"{name}/{manifest_name}", manifest, 0o400)
                manifests[name] = manifest
            execd = json.loads((root_path / "execd/package-manifest.json").read_bytes())
            unsigned_execd = dict(execd)
            unsigned_execd.pop("package_digest")
            unsigned_execd["activation_binding"] = {
                "source_commit": CANDIDATE, "package_digest": activation_digest,
                "activation_id": f"buzz-ci-capacity-one-{CANDIDATE[:12]}-{activation_digest[:12]}",
            }
            execd = {**unsigned_execd, "package_digest": hashlib.sha256(canonical(unsigned_execd)).hexdigest()}
            (root_path / "execd/package-manifest.json").chmod(0o600)
            refs["execd"] = write_json(root_path, "execd/package-manifest.json", execd, 0o400)
            manifests["execd"] = execd
            descriptor = {
                "schema_version": "buzz-ci-sealed-freeze-receipt-render-input/v1", "candidate_sha": CANDIDATE,
                "lifecycle": lifecycle, "public_binding": public_ref, "package_manifests": refs,
            }
            descriptor_path = root_path / "descriptor.json"
            descriptor_path.write_bytes(canonical(descriptor))
            descriptor_path.chmod(0o600)
            root = RENDER.DescriptorRoot(descriptor_path)
            validator = mock.Mock()
            validator.validate_manifest.return_value = None
            trees = {name: digit * 64 for name, digit in zip(RENDER.PACKAGE_NAMES, "89abc", strict=True)}
            def fake_tree(_root: object, name: str, _descriptor: object, _candidate: str) -> tuple[object, str, str]:
                return manifests[name], refs[name]["sha256"], trees[name]
            try:
                with (
                    mock.patch.object(RENDER, "activation_package_module", return_value=validator),
                    mock.patch.object(RENDER, "validate_manifest"),
                    mock.patch.object(RENDER, "validate_package_tree", side_effect=fake_tree),
                ):
                    output = RENDER.record_sealed_freeze(root, descriptor)
                self.assertEqual(output["claims"], {"protected_ci": False, "tier2": False})
                self.assertEqual(set(output["package_manifest_sha256"]), set(RENDER.PACKAGE_NAMES))
            finally:
                root.close()


if __name__ == "__main__":
    unittest.main()

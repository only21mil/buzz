#!/usr/bin/env python3
"""Focused tests for descriptor-bound activation input rendering."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "render_inputs.py"
TEMPLATE_GENERATOR = ROOT / "generate_checked_templates.py"
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
TIMING = json.loads(
    (ROOT.parents[0] / "tests/clean_host_e2e/timing-contract.json").read_bytes()
)


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def write_json(root: Path, relative: str, value: object, mode: int = 0o600) -> dict[str, object]:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = canonical(value)
    path.write_bytes(raw)
    path.chmod(mode)
    return {"path": relative, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw), "mode": f"{mode:04o}"}


def write_declared_json(
    root: Path, relative: str, value: object, mode: int = 0o600,
) -> dict[str, object]:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = RENDER.canonical_declared(value)
    path.write_bytes(raw)
    path.chmod(mode)
    return {
        "path": relative,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "mode": f"{mode:04o}",
    }


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
        "schema_version": "buzz-ci-clean-host-e2e-public-binding/v3",
        "relay_url": "wss://relay.test.invalid:3443",
        "relay_http_origin": "https://relay.test.invalid:3443",
        "acceptance_actor": {"public_key": keys[0], "generation": 1},
        "keyholder_public_spec": {
            "schema_version": 2,
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
                "binding_receipt_path": "/var/lib/buzzci/activation-controller/controld-acceptance-v2.json",
                "credential_selector": "acceptance-actor.key",
            },
        },
    }


def acceptance_template() -> dict[str, object]:
    package = RENDER.activation_package_module()
    return package.production_acceptance_template(
        actor_public_key="79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        actor_generation=1,
        ci_signer_public_key="c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        candidate_sha=CANDIDATE,
        workflow_id="0123456789abcdef0123456789abcdef",
        workflow_digest="1" * 64,
        job_id="capacity-one-fixture",
        channel_id="12345678-1234-4abc-8def-123456789abc",
        repository_owner_public_key="22" * 32,
        repository_id="buzz",
        source_clone_url="https://relay.example.invalid/git/buzz",
        time_reference=1_800_000_000,
    )


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
    def test_systemd_platform_binding_matches_activation_validator(self) -> None:
        self.assertEqual(RENDER.PLATFORM_SYSTEMD, RENDER.activation_package_module().PLATFORM_SYSTEMD)

    def test_production_scenario_template_generator_is_deterministic_and_no_clobber(self) -> None:
        scenario_path = ROOT.parents[1] / "acceptance/scenario.template.json"
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "scenario-template.json"
            command = [
                "python3", str(TEMPLATE_GENERATOR), "capacity-one-scenario",
                "--input", str(scenario_path), "--output", str(output),
            ]
            first = subprocess.run(
                command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            template = json.loads(output.read_bytes())
            self.assertEqual(template["kind"], "capacity-one-scenario")
            self.assertEqual(
                template["document"]["fixture"]["integrated_candidate_sha"],
                {"$copy": "candidate_sha"},
            )
            self.assertEqual(
                template["document"]["fixture"]["grant_event_id"],
                {"$copy": "activation_grant_event_id"},
            )
            self.assertEqual(
                template["document"]["fixture"]["manifest_digest"],
                {"$copy": "activation_fixture_manifest_sha256"},
            )
            expected = output.read_bytes()
            second = subprocess.run(
                command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(second.returncode, 64)
            self.assertEqual(output.read_bytes(), expected)

            scenario = json.loads(scenario_path.read_bytes())
            nested_reordered = json.loads(json.dumps(scenario))
            nested_reordered["fixture"] = {
                key: nested_reordered["fixture"][key]
                for key in reversed(nested_reordered["fixture"])
            }
            for label, value in (
                ("top", {key: scenario[key] for key in reversed(scenario)}),
                ("nested", nested_reordered),
            ):
                reordered = Path(temporary) / f"{label}-reordered-scenario.json"
                rejected_output = Path(temporary) / f"{label}-reordered-template.json"
                reordered.write_bytes(RENDER.compact_declared(value))
                reordered.chmod(0o600)
                rejected = subprocess.run(
                    [
                        "python3", str(TEMPLATE_GENERATOR), "capacity-one-scenario",
                        "--input", str(reordered), "--output", str(rejected_output),
                    ],
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(rejected.returncode, 64)
                self.assertIn("declaration order differs", rejected.stderr)
                self.assertFalse(rejected_output.exists())

    def test_scenario_wire_parser_matches_installed_verifier_literal_bytes(self) -> None:
        scenario = json.loads(
            (ROOT.parents[1] / "acceptance/scenario.template.json").read_bytes()
        )
        raw = RENDER.canonical_scenario(scenario)
        verifier = RENDER.receipt_verifier_module()
        self.assertFalse(raw.endswith(b"\n"))
        self.assertEqual(RENDER.parse_scenario_json(raw, "scenario"), scenario)
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            verifier._digest(verifier._ordered_scenario(scenario)),
        )
        top_reordered = RENDER.compact_declared({
            key: scenario[key] for key in reversed(scenario)
        })
        nested_reordered_value = json.loads(raw)
        nested_reordered_value["fixture"] = {
            key: nested_reordered_value["fixture"][key]
            for key in reversed(nested_reordered_value["fixture"])
        }
        nested_reordered = RENDER.compact_declared(nested_reordered_value)
        for label, payload in (
            ("top-level reorder", top_reordered),
            ("nested reorder", nested_reordered),
            ("trailing LF", raw + b"\n"),
        ):
            with self.subTest(label=label), self.assertRaisesRegex(
                RENDER.RenderError, "canonical scenario-order JSON without trailing LF",
            ):
                RENDER.parse_scenario_json(payload, "scenario")
        duplicate = b'{"schema_version":"buzz-ci-capacity-one-scenario/v2",' + raw[1:]
        with self.assertRaisesRegex(RENDER.RenderError, "duplicate JSON key"):
            RENDER.parse_scenario_json(duplicate, "scenario")

    def test_non_scenario_renderer_outputs_remain_sorted_canonical_plus_lf(self) -> None:
        value = {"z": 1, "a": {"y": 2, "b": 3}}
        for action in set(RENDER.DESCRIPTOR_SCHEMAS) - {"render-scenario"}:
            with self.subTest(action=action):
                payload = RENDER.render_output(action, value)
                self.assertEqual(payload, canonical(value))
                self.assertTrue(payload.endswith(b"\n"))

    def test_acceptance_client_identity_is_cross_bound_to_controld(self) -> None:
        public = public_binding()
        peer = public["keyholder_public_spec"]["peer"]
        manifests = {
            "activation": {"identities": {"controld": {"uid": peer["uid"], "gid": peer["gid"]}}},
            "keyholder": {"identities": {"controld_uid": peer["uid"], "controld_gid": peer["gid"]}},
        }
        RENDER.validate_acceptance_client_binding(public, manifests)
        changed = json.loads(json.dumps(manifests))
        changed["activation"]["identities"]["controld"]["uid"] += 1
        with self.assertRaisesRegex(RENDER.RenderError, "differs from controld"):
            RENDER.validate_acceptance_client_binding(public, changed)
        changed = json.loads(json.dumps(manifests))
        changed["keyholder"]["identities"]["controld_gid"] += 1
        with self.assertRaisesRegex(RENDER.RenderError, "differs from controld"):
            RENDER.validate_acceptance_client_binding(public, changed)

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
            if schema_path.name == "scenario.schema.json":
                self.assertTrue(schema["$id"].endswith("capacity-one-scenario-v2.json"))
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
            "acceptance_template": acceptance_template(),
            "entries": [{
                "role": "fixture_manifest",
                "sha256": fixture["manifest_digest"],
            }],
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
        grant_event_id = RENDER.activation_grant_event_id(activation)
        request_digest = RENDER.activation_request_digest(activation)
        approved_by = RENDER.activation_approved_by(activation)
        self.assertEqual(
            grant_event_id,
            "249147dcef17979a5cca7aa705a28664827324f9a866348df47e460df1ce1493",
        )
        bindings["activation_grant_event_id"] = grant_event_id
        bindings["activation_request_digest"] = request_digest
        bindings["activation_approved_by"] = approved_by
        bindings["activation_fixture_manifest_sha256"] = (
            fixture["manifest_digest"]
        )
        template = {
            "schema_version": "buzz-ci-checked-render-template/v1",
            "kind": "capacity-one-scenario",
            "definitions": {},
            "document": {
                **scenario,
                "fixture": {
                    **scenario["fixture"],
                    "manifest_digest": {
                        "$copy": "activation_fixture_manifest_sha256",
                    },
                    "grant_event_id": {"$copy": "activation_grant_event_id"},
                    "request_digest": {"$copy": "activation_request_digest"},
                    "approved_by": {"$copy": "activation_approved_by"},
                },
            },
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
        scenario["fixture"]["grant_event_id"] = grant_event_id
        scenario["fixture"]["request_digest"] = request_digest
        scenario["fixture"]["approved_by"] = approved_by
        self.assertEqual(rendered, scenario)
        wrong_bindings = {
            **bindings,
            "activation_fixture_manifest_sha256": "9" * 64,
        }
        wrong_rendered = RENDER.resolve_template(
            template, "capacity-one-scenario", wrong_bindings,
        )
        with self.assertRaisesRegex(RENDER.RenderError, "cross-binding differs"):
            RENDER.validate_scenario(wrong_rendered, wrong_bindings)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            descriptor_path = root / "descriptor.json"
            output_path = root / "scenario.json"
            descriptor_path.write_bytes(canonical(descriptor))
            output_path.write_bytes(RENDER.canonical_scenario(rendered))
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

        bindings["packages"] = {"activation": activation}
        stale = json.loads(json.dumps(scenario))
        stale["fixture"]["grant_event_id"] = "8" * 64
        with self.assertRaisesRegex(RENDER.RenderError, "cross-binding differs"):
            RENDER.validate_scenario(stale, bindings)
        stale_request = json.loads(json.dumps(scenario))
        stale_request["fixture"]["request_digest"] = "8" * 64
        with self.assertRaisesRegex(RENDER.RenderError, "cross-binding differs"):
            RENDER.validate_scenario(stale_request, bindings)
        stale_approver = json.loads(json.dumps(scenario))
        stale_approver["fixture"]["approved_by"] = "8" * 64
        with self.assertRaisesRegex(RENDER.RenderError, "cross-binding differs"):
            RENDER.validate_scenario(stale_approver, bindings)
        bindings["activation_grant_event_id"] = "9" * 64
        with self.assertRaisesRegex(RENDER.RenderError, "renderer binding differs"):
            RENDER.validate_scenario(scenario, bindings)
        bindings["activation_grant_event_id"] = grant_event_id
        wrong_fixture = json.loads(json.dumps(scenario))
        wrong_fixture["fixture"]["manifest_digest"] = "9" * 64
        with self.assertRaisesRegex(RENDER.RenderError, "cross-binding differs"):
            RENDER.validate_scenario(wrong_fixture, bindings)
        missing = json.loads(json.dumps(scenario))
        del missing["fixture"]["grant_event_id"]
        with self.assertRaisesRegex(RENDER.RenderError, "shape differs"):
            RENDER.validate_scenario(missing, bindings)
        extra = json.loads(json.dumps(scenario))
        extra["fixture"]["caller_grant_event_id"] = grant_event_id
        with self.assertRaisesRegex(RENDER.RenderError, "shape differs"):
            RENDER.validate_scenario(extra, bindings)

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
                "def validate_acceptance_template(value):\n"
                "    if set(value) != {'actor', 'time_reference', 'run_event', 'grant_event', 'rerun_event', 'tombstone_event'}:\n"
                "        raise ValueError('template shape differs')\n"
                "    return value\n"
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
            fixture_entry = {
                **entry,
                "role": "fixture_manifest",
                "source": "assets/fixture-manifest.json",
                "target": "/usr/share/buzzci/execd-v2/fixture/fixture-manifest.json",
                "sha256": hashlib.sha256(
                    (acceptance / "fixtures/fixture-manifest.json").read_bytes(),
                ).hexdigest(),
            }
            zero = {
                "capacity": 0,
                "enabled": False,
                "active": False,
                "provisioned": False,
            }
            activation_draft = {
                "schema": "buzz-ci-capacity-one-activation-draft-v2",
                "source_commit": CANDIDATE,
                "default_state": zero,
                "acceptance_template": acceptance_template(),
                "identities": {"controld": {"uid": 1201, "gid": 1201}},
                "entries": [entry, fixture_entry],
            }
            activation_digest = hashlib.sha256(canonical(activation_draft)).hexdigest()
            activation = {
                **activation_draft,
                "schema": "buzz-ci-capacity-one-activation-package-v2",
                "activation_id": (
                    f"buzz-ci-capacity-one-{CANDIDATE[:12]}-{activation_digest[:12]}"
                ),
                "package_digest": activation_digest,
            }

            public_raw = RENDER.canonical_public_binding(public_binding())
            manifests: dict[str, dict[str, object]] = {}
            for name in RENDER.PACKAGE_NAMES[:-1]:
                manifest = {key: {} for key in RENDER.PACKAGE_KEYS[name]}
                manifest_entry = dict(entry)
                manifest_entry["role"] = "binary"
                if name == "keyholder":
                    manifest_entry["size"] = 1
                manifest.update(
                    {
                        "schema": RENDER.PACKAGE_SCHEMAS[name],
                        "source_commit": CANDIDATE,
                        "entries": [manifest_entry],
                    }
                )
                manifest["binary_provenance_sha256"] = "9" * 64
                if name == "keyholder":
                    manifest["identities"] = {
                        "controld_uid": 1201,
                        "controld_gid": 1201,
                    }
                    manifest["public_binding_sha256"] = hashlib.sha256(public_raw).hexdigest()
                    manifest["acceptance_public_spec_sha256"] = "a" * 64
                if name == "execd":
                    manifest["activation_binding"] = {
                        "source_commit": CANDIDATE,
                        "package_digest": activation_digest,
                        "activation_id": activation["activation_id"],
                    }
                unsigned = {key: value for key, value in manifest.items() if key != "package_digest"}
                manifest["package_digest"] = hashlib.sha256(canonical(unsigned)).hexdigest()
                manifests[name] = manifest
            activation_draft["components"] = [
                {
                    "name": name,
                    "package_manifest_sha256": hashlib.sha256(canonical(manifests[name])).hexdigest(),
                    "package_digest": manifests[name]["package_digest"],
                }
                for name in ("runner", "controld")
            ]
            activation_digest = hashlib.sha256(canonical(activation_draft)).hexdigest()
            activation = {
                **activation_draft,
                "schema": "buzz-ci-capacity-one-activation-package-v2",
                "activation_id": f"buzz-ci-capacity-one-{CANDIDATE[:12]}-{activation_digest[:12]}",
                "package_digest": activation_digest,
            }
            execd_unsigned = {
                key: value for key, value in manifests["execd"].items()
                if key != "package_digest"
            }
            execd_unsigned["activation_binding"] = {
                "source_commit": CANDIDATE,
                "package_digest": activation_digest,
                "activation_id": activation["activation_id"],
            }
            manifests["execd"] = {
                **execd_unsigned,
                "package_digest": hashlib.sha256(canonical(execd_unsigned)).hexdigest(),
            }
            manifests["activation"] = activation

            references = {
                name: write_json(root, f"inputs/{name}.json", manifest, 0o400)
                for name, manifest in manifests.items()
            }
            public_path = root / "inputs/public.json"
            public_path.write_bytes(public_raw)
            public_path.chmod(0o400)
            public_ref = file_ref(root, "inputs/public.json")
            source_scenario = json.loads((acceptance / "scenario.template.json").read_bytes())
            scenario = json.loads(json.dumps(source_scenario))
            grant_event_id = hashlib.sha256(
                RENDER.compact_declared(activation["acceptance_template"]["grant_event"]),
            ).hexdigest()
            request_digest = hashlib.sha256(
                RENDER.compact_declared(activation["acceptance_template"]["run_event"]),
            ).hexdigest()
            approved_by = activation["acceptance_template"]["actor"]["public_key"]
            self.assertEqual(
                grant_event_id,
                "249147dcef17979a5cca7aa705a28664827324f9a866348df47e460df1ce1493",
            )
            scenario["fixture"].update(
                {
                    "integrated_candidate_sha": CANDIDATE,
                    "source_oid": CANDIDATE,
                    "activation_id": activation["activation_id"],
                    "activation_package_digest": activation_digest,
                    "grant_event_id": grant_event_id,
                    "request_digest": request_digest,
                    "approved_by": approved_by,
                }
            )
            template_path = root / "inputs/scenario-template.json"
            template_process = subprocess.run(
                [
                    "python3", str(TEMPLATE_GENERATOR), "capacity-one-scenario",
                    "--input", str(acceptance / "scenario.template.json"),
                    "--output", str(template_path),
                ],
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            self.assertEqual(template_process.returncode, 0, template_process.stderr)
            template_path.chmod(0o400)
            template_ref = file_ref(root, "inputs/scenario-template.json")
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
            rendered_raw = (root / "scenario.json").read_bytes()
            rendered = json.loads(rendered_raw)
            self.assertEqual(rendered, scenario)
            self.assertEqual(rendered["fixture"]["integrated_candidate_sha"], CANDIDATE)
            self.assertEqual(rendered["fixture"]["grant_event_id"], grant_event_id)
            self.assertEqual(rendered_raw, RENDER.canonical_scenario(scenario))
            self.assertFalse(rendered_raw.endswith(b"\n"))

    def make_lifecycle(self, root: Path) -> dict[str, object]:
        proof = {
            "configs_sha256": HEX["config"], "units_sha256": HEX["units"],
            "sockets_absent": True, "processes_absent": True,
            "encrypted_credentials_absent": True, "relay_residue_absent": True,
        }
        trees = {name: digit * 64 for name, digit in zip(RENDER.PACKAGE_NAMES, "89abc", strict=True)}
        prior_trees = {name: digit * 64 for name, digit in zip(RENDER.PRIOR_PACKAGE_NAMES, "de", strict=True)}
        prior_activation = {
            "activation_id": f"buzz-ci-capacity-one-{CANDIDATE[:12]}-{'d' * 12}", "package_digest": "d" * 64,
            "receipt_state": "rolled_back", "rollback_cleanup_sha256": "e" * 64, "execd_reinstall": "installed",
        }
        harness_sha = hashlib.sha256(
            (ROOT.parents[0] / "tests/clean_host_e2e/harness.py").read_bytes()
        ).hexdigest()
        timing_asset_sha = hashlib.sha256(
            (ROOT.parents[0] / "tests/clean_host_e2e/timing-contract.json").read_bytes()
        ).hexdigest()
        timing_sha = hashlib.sha256(RENDER.canonical_declared(TIMING)).hexdigest()
        contract = {
            "schema_version": RENDER.CLEAN_HOST_CONTRACT_SCHEMA, "candidate_sha": CANDIDATE,
            "state": "state", "candidate_root": "candidate",
            "harness_sha256": harness_sha, "timing_asset_sha256": timing_asset_sha,
            "timing": TIMING, "timing_sha256": timing_sha,
            "platform_systemd": RENDER.PLATFORM_SYSTEMD,
            "scenario": {"path": "scenario.json", "sha256": HEX["scenario"]},
            "seccomp_source": {"path": "seccomp.json", "sha256": RENDER.SECCOMP_SHA256},
            "packages": {name: {"path": name, "tree_sha256": trees[name]} for name in RENDER.PACKAGE_NAMES},
            "prior_packages": {name: {"path": f"prior/{name}", "tree_sha256": prior_trees[name]} for name in RENDER.PRIOR_PACKAGE_NAMES},
            "prior_scenario": {"path": "prior/scenario.json", "sha256": "f" * 64},
        }
        receipt = {"outcome": "pass", "integrated_candidate_sha": CANDIDATE, "scenario_sha256": HEX["scenario"]}
        verifier = {"outcome": "pass", "status": "verified"}
        receipt_ref = write_declared_json(root, "evidence/acceptance-receipt.json", receipt, 0o400)
        verifier_ref = write_declared_json(root, "evidence/verifier.json", verifier, 0o400)
        evidence = {
            "schema_version": RENDER.CLEAN_HOST_EVIDENCE_SCHEMA, "candidate_sha": CANDIDATE,
            "harness_sha256": harness_sha,
            "timing_asset_sha256": timing_asset_sha,
            "image_sha256": "f" * 64,
            "tool_sha256": {name: "1" * 64 for name in RENDER.HARNESS_TOOLS},
            "harness_asset_sha256": {
                **{name: "2" * 64 for name in RENDER.HARNESS_ASSETS},
                "harness.py": harness_sha,
                "timing-contract.json": timing_asset_sha,
            },
            "timing": TIMING, "timing_sha256": timing_sha,
            "package_tree_sha256": trees, "scenario_sha256": HEX["scenario"],
            "prior_package_tree_sha256": prior_trees, "prior_scenario_sha256": "f" * 64,
            "prior_activation": prior_activation,
            "seccomp_source_sha256": RENDER.SECCOMP_SHA256,
            "transfer_bytes": RENDER.TRANSFER_BYTES, "transfer_sha256": "3" * 64,
            "receipt_sha256": receipt_ref["sha256"], "verifier_sha256": verifier_ref["sha256"],
            "dormant_proof": proof,
        }
        evidence_ref = write_declared_json(root, "evidence/evidence-manifest.json", evidence, 0o400)
        contract_ref = write_json(root, "evidence/contract.json", contract, 0o400)
        result = {
            "status": "pass", "candidate_sha": CANDIDATE,
            "harness_sha256": harness_sha, "timing_asset_sha256": timing_asset_sha,
            "timing_sha256": timing_sha,
            "receipt_sha256": receipt_ref["sha256"], "verifier_sha256": verifier_ref["sha256"],
            "evidence_manifest_sha256": evidence_ref["sha256"],
            "dormant_proof": proof, "vm_state_absent": True,
        }
        result_ref = write_declared_json(root, "evidence/result.json", result, 0o400)
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

    def test_lifecycle_reader_accepts_literal_harness_canonical_order_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            descriptor_path = root_path / "descriptor.json"
            descriptor_path.write_bytes(canonical({"unused": True}))
            descriptor_path.chmod(0o600)
            result = {
                "status": "pass",
                "candidate_sha": CANDIDATE,
                "vm_state_absent": True,
            }
            result_path = root_path / "result.json"
            result_path.write_bytes(RENDER.canonical_declared(result))
            result_path.chmod(0o400)
            root = RENDER.DescriptorRoot(descriptor_path)
            try:
                value, raw, _ = root.declared_json_ref(
                    file_ref(root_path, "result.json"), "harness result",
                )
                self.assertEqual(value, result)
                self.assertEqual(raw, b'{"status":"pass","candidate_sha":"' + CANDIDATE.encode() + b'","vm_state_absent":true}\n')
                with self.assertRaisesRegex(RENDER.RenderError, "canonical"):
                    root.json_ref(file_ref(root_path, "result.json"), "harness result")
                result_path.chmod(0o600)
                result_path.write_bytes(json.dumps(result, indent=2).encode() + b"\n")
                result_path.chmod(0o400)
                with self.assertRaisesRegex(RENDER.RenderError, "declaration-order"):
                    root.declared_json_ref(
                        file_ref(root_path, "result.json"), "harness result",
                    )
            finally:
                root.close()

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

    def test_public_binding_reference_requires_ceremony_declaration_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            descriptor_path = root_path / "descriptor.json"
            descriptor_path.write_bytes(canonical({"unused": True}))
            descriptor_path.chmod(0o600)
            binding_path = root_path / "public-binding.json"
            binding_path.write_bytes(canonical(public_binding()))
            binding_path.chmod(0o444)
            root = RENDER.DescriptorRoot(descriptor_path)
            try:
                with self.assertRaisesRegex(RENDER.RenderError, "schema-order"):
                    root.public_binding_ref(
                        file_ref(root_path, "public-binding.json"), "public binding",
                    )
                binding_path.chmod(0o600)
                binding_path.write_bytes(
                    RENDER.canonical_public_binding(public_binding()),
                )
                binding_path.chmod(0o444)
                value, raw, relative = root.public_binding_ref(
                    file_ref(root_path, "public-binding.json"), "public binding",
                )
                self.assertEqual(value, public_binding())
                self.assertEqual(raw, RENDER.canonical_public_binding(value))
                self.assertEqual(relative, "public-binding.json")
            finally:
                root.close()

    def test_sealed_freeze_requires_cross_bound_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            lifecycle = self.make_lifecycle(root_path)
            public_path = root_path / "state/public-binding.json"
            public_path.parent.mkdir(parents=True)
            public_path.write_bytes(RENDER.canonical_public_binding(public_binding()))
            public_path.chmod(0o444)
            public_ref = file_ref(root_path, "state/public-binding.json")
            refs: dict[str, object] = {}
            manifests: dict[str, object] = {}
            activation_digest = "a" * 64
            for name in RENDER.PACKAGE_NAMES:
                payload = name.encode()
                manifest = minimal_manifest(name, f"assets/{name}", payload)
                if name == "keyholder":
                    manifest["public_binding_sha256"] = public_ref["sha256"]
                if name == "activation":
                    unsigned = dict(manifest)
                    unsigned.pop("package_digest")
                    unsigned["schema"] = "buzz-ci-capacity-one-activation-draft-v2"
                    activation_digest = hashlib.sha256(canonical(unsigned)).hexdigest()
                    manifest = {
                        **unsigned, "schema": "buzz-ci-capacity-one-activation-package-v2",
                        "activation_id": f"buzz-ci-capacity-one-{CANDIDATE[:12]}-{activation_digest[:12]}",
                        "package_digest": activation_digest,
                    }
                manifest_name = "activation-manifest.json" if name == "activation" else "package-manifest.json"
                refs[name] = write_json(root_path, f"{name}/{manifest_name}", manifest, 0o400)
                manifests[name] = manifest
            activation = manifests["activation"]
            unsigned_activation = {
                key: value for key, value in activation.items() if key not in {"activation_id", "package_digest"}
            }
            unsigned_activation["schema"] = "buzz-ci-capacity-one-activation-draft-v2"
            unsigned_activation["components"] = [
                {
                    "name": name,
                    "package_manifest_sha256": refs[name]["sha256"],
                    "package_digest": manifests[name]["package_digest"],
                }
                for name in ("runner", "controld")
            ]
            activation_digest = hashlib.sha256(canonical(unsigned_activation)).hexdigest()
            activation = {
                **unsigned_activation,
                "schema": "buzz-ci-capacity-one-activation-package-v2",
                "activation_id": f"buzz-ci-capacity-one-{CANDIDATE[:12]}-{activation_digest[:12]}",
                "package_digest": activation_digest,
            }
            (root_path / "activation/activation-manifest.json").chmod(0o600)
            refs["activation"] = write_json(
                root_path, "activation/activation-manifest.json", activation, 0o400,
            )
            manifests["activation"] = activation
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

    def test_clean_host_rejects_recanonicalized_lane_digest_scenario(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            (root_path / "state").mkdir()
            (root_path / "candidate").mkdir()
            public_raw = RENDER.canonical_public_binding(public_binding())
            public_path = root_path / "state/public-binding.json"
            public_path.write_bytes(public_raw)
            public_path.chmod(0o444)
            activation = {
                "activation_id": f"buzz-ci-capacity-one-{CANDIDATE[:12]}-{'a' * 12}",
                "package_digest": "a" * 64,
                "default_state": {"capacity": 0, "enabled": False, "active": False, "provisioned": False},
                "acceptance_template": acceptance_template(),
                "entries": [{"role": "fixture_manifest", "sha256": "b" * 64}],
                "platform_systemd": RENDER.PLATFORM_SYSTEMD,
            }
            grant_event_id = RENDER.activation_grant_event_id(activation)
            scenario = json.loads(
                (ROOT.parents[1] / "acceptance/scenario.template.json").read_bytes()
            )
            scenario["fixture"].update({
                "integrated_candidate_sha": CANDIDATE,
                "source_oid": CANDIDATE,
                "activation_id": activation["activation_id"],
                "activation_package_digest": activation["package_digest"],
                "grant_event_id": grant_event_id,
                "manifest_digest": "c" * 64,
            })
            scenario_path = root_path / "state/scenario.json"
            scenario_path.write_bytes(RENDER.canonical_scenario(scenario))
            scenario_path.chmod(0o400)
            seccomp_path = root_path / "state/seccomp.json"
            seccomp_path.write_bytes(b"seccomp\n")
            seccomp_path.chmod(0o400)
            manifests = {
                name: ({
                    "activation_binding": {
                        "source_commit": CANDIDATE,
                        "activation_id": activation["activation_id"],
                        "package_digest": activation["package_digest"],
                    }
                } if name == "execd" else {})
                for name in RENDER.PACKAGE_NAMES
            }
            manifests["activation"] = activation
            descriptor = {
                "schema_version": "buzz-ci-clean-host-e2e-render-input/v3",
                "candidate_sha": CANDIDATE,
                "state": "state",
                "candidate_root": "candidate",
                "public_binding": file_ref(root_path, "state/public-binding.json"),
                "scenario": file_ref(root_path, "state/scenario.json"),
                "seccomp_source": file_ref(root_path, "state/seccomp.json"),
                "packages": {name: {"path": name} for name in RENDER.PACKAGE_NAMES},
                "prior_packages": {name: {"path": f"prior/{name}"} for name in RENDER.PRIOR_PACKAGE_NAMES},
                "prior_scenario": file_ref(root_path, "state/scenario.json"),
            }
            descriptor_path = root_path / "descriptor.json"
            descriptor_path.write_bytes(canonical(descriptor))
            descriptor_path.chmod(0o600)
            descriptor_root = RENDER.DescriptorRoot(descriptor_path)
            try:
                with (
                    mock.patch.object(
                        RENDER.subprocess, "run",
                        return_value=subprocess.CompletedProcess([], 0, CANDIDATE + "\n", ""),
                    ),
                    mock.patch.object(
                        RENDER, "candidate_blob",
                        side_effect=lambda _root, _candidate, relative: RENDER.checked_renderer_asset(relative),
                    ),
                    mock.patch.object(RENDER, "SECCOMP_SHA256", hashlib.sha256(b"seccomp\n").hexdigest()),
                    mock.patch.object(RENDER, "validate_package_tree", side_effect=lambda _root, name, _value, _candidate: (manifests[name], name[0] * 64, name[-1] * 64)),
                    mock.patch.object(RENDER, "_validate_activation_component_package_bindings"),
                    mock.patch.object(RENDER, "validate_keyholder_public_binding"),
                ):
                    with self.assertRaisesRegex(RENDER.RenderError, "cross-binding differs"):
                        RENDER.clean_host_contract(descriptor_root, descriptor)
            finally:
                descriptor_root.close()

    def test_activation_component_manifests_cross_bind_both_packages(self) -> None:
        manifests = {
            "runner": {"package_digest": "1" * 64},
            "controld": {"package_digest": "2" * 64},
            "activation": {
                "components": [
                    {"name": "runner", "package_manifest_sha256": "3" * 64, "package_digest": "1" * 64},
                    {"name": "controld", "package_manifest_sha256": "4" * 64, "package_digest": "2" * 64},
                ],
            },
        }
        digests = {"runner": "3" * 64, "controld": "4" * 64, "activation": "5" * 64}
        RENDER._validate_activation_component_package_bindings(manifests, digests)
        stale = copy.deepcopy(manifests)
        stale["activation"]["components"][0]["package_manifest_sha256"] = "6" * 64
        with self.assertRaisesRegex(RENDER.RenderError, "runner package cross-binding differs"):
            RENDER._validate_activation_component_package_bindings(stale, digests)
        swapped = dict(digests)
        swapped["runner"], swapped["controld"] = swapped["controld"], swapped["runner"]
        with self.assertRaisesRegex(RENDER.RenderError, "runner package cross-binding differs"):
            RENDER._validate_activation_component_package_bindings(manifests, swapped)
        wrong_digest = copy.deepcopy(manifests)
        wrong_digest["activation"]["components"][1]["package_digest"] = "7" * 64
        with self.assertRaisesRegex(RENDER.RenderError, "controld package cross-binding differs"):
            RENDER._validate_activation_component_package_bindings(wrong_digest, digests)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Generate production checked templates from validated activation inputs."""

from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any


ACTIVATION_DIR = Path(__file__).resolve().parent.parent
RENDER_DIR = Path(__file__).resolve().parent


class TemplateError(ValueError):
    """Stable rejection for an unsafe or invalid template source."""


def load_local_module(path: Path, name: str) -> Any:
    """Load one exact sibling without relying on generic import names."""
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise ImportError("module loader is unavailable")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception as error:
        raise TemplateError(f"local validator is unavailable: {path.name}") from error


def activation_package_module() -> Any:
    return load_local_module(
        ACTIVATION_DIR / "package.py", "buzz_ci_activation_package_for_template_generator",
    )


def renderer_module() -> Any:
    return load_local_module(
        RENDER_DIR / "render_inputs.py", "buzz_ci_render_inputs_for_template_generator",
    )


def checked_activation_template(draft: dict[str, Any]) -> dict[str, Any]:
    activation_package = activation_package_module()
    render_inputs = renderer_module()
    try:
        activation_package.validate_manifest(draft, require_digest=False)
    except (KeyError, TypeError, ValueError) as error:
        raise TemplateError(f"activation draft validation failed: {error}") from error
    if draft.get("schema") != activation_package.DRAFT_SCHEMA:
        raise TemplateError("activation template source is not a draft")
    document = copy.deepcopy(draft)
    document["source_commit"] = {"$copy": "candidate_sha"}
    document["acceptance_template"]["actor"] = {
        "$copy": "public_binding.acceptance_actor",
    }
    document["acceptance_template"]["export_subject"] = {
        "$copy": "public_binding.keyholder_public_spec.selectors.nip98.public_key",
    }
    document["acceptance_template"]["export_generation"] = {
        "$copy": "public_binding.keyholder_public_spec.selectors.nip98.generation",
    }
    components = {
        component["name"]: component for component in document["components"]
    }
    for name, component in components.items():
        if name != "qualification":
            component["source_commit"] = {"$copy": "candidate_sha"}
    for name in render_inputs.PRE_ACTIVATION_PACKAGE_NAMES:
        component = components[name]
        for field in ("binary_sha256", "provenance_sha256", "source_commit"):
            component[field] = {"$copy": f"package_components.{name}.{field}"}
    for name in ("runner", "controld"):
        component = components[name]
        component["package_manifest_sha256"] = {
            "$copy": f"package_manifest_sha256.{name}",
        }
        component["package_digest"] = {"$copy": f"packages.{name}.package_digest"}
    execd = components["execd"]
    for field in ("binary_sha256", "provenance_sha256", "source_commit"):
        execd[field] = {"$copy": f"execd_preactivation.{field}"}
    return {
        "schema_version": "buzz-ci-checked-render-template/v1",
        "kind": "activation-draft",
        "definitions": {},
        "document": document,
    }


def checked_scenario_template(scenario: dict[str, Any]) -> dict[str, Any]:
    render_inputs = renderer_module()
    try:
        canonical = render_inputs.canonical_scenario(scenario)
    except (
        ImportError,
        KeyError,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
        render_inputs.RenderError,
    ) as error:
        raise TemplateError(f"capacity-one scenario validation failed: {error}") from error
    if render_inputs.compact_declared(scenario) != canonical:
        raise TemplateError("capacity-one scenario declaration order differs")
    document = copy.deepcopy(scenario)
    fixture = document["fixture"]
    for field, binding in (
        ("integrated_candidate_sha", "candidate_sha"),
        ("source_oid", "candidate_sha"),
        ("activation_id", "packages.activation.activation_id"),
        ("activation_package_digest", "packages.activation.package_digest"),
        ("run_id", "activation_run_id"),
        ("failure_run_id", "activation_failure_run_id"),
        ("failure_selector", "activation_failure_selector"),
        ("request_digest", "activation_request_digest"),
        ("failure_request_digest", "activation_failure_request_digest"),
        ("manifest_digest", "activation_fixture_manifest_sha256"),
        ("grant_event_id", "activation_grant_event_id"),
        ("approved_by", "activation_approved_by"),
        ("export_subject", "activation_export_subject"),
        ("export_generation", "activation_export_generation"),
        ("export_authorization_digest", "activation_export_authorization_digest"),
    ):
        fixture[field] = {"$copy": binding}
    return {
        "schema_version": "buzz-ci-checked-render-template/v1",
        "kind": "capacity-one-scenario",
        "definitions": {},
        "document": document,
    }


def read_json(path: Path, where: str) -> tuple[dict[str, Any], bytes, os.stat_result]:
    activation_package = activation_package_module()
    absolute = Path(os.path.abspath(path))
    if Path(os.path.realpath(absolute)) != absolute:
        raise TemplateError(f"{where} path contains a symbolic component")
    try:
        value, raw, metadata = activation_package.parse_json(absolute)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise TemplateError(f"{where} is unavailable or invalid") from error
    if metadata.st_uid != os.geteuid() or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise TemplateError(f"{where} metadata is unsafe")
    return value, raw, metadata


def write_output(path: Path, payload: bytes) -> None:
    absolute = Path(os.path.abspath(path))
    parent = absolute.parent
    metadata = parent.lstat()
    if (
        Path(os.path.realpath(parent)) != parent
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise TemplateError("output parent metadata is unsafe")
    descriptor = os.open(
        absolute,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            view = view[os.write(descriptor, view):]
        os.fsync(descriptor)
        if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o600:
            raise TemplateError("output mode differs")
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("activation-draft", "capacity-one-scenario"))
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        value, raw, metadata = read_json(arguments.input, "template input")
        if arguments.kind == "activation-draft":
            activation_package = activation_package_module()
            if stat.S_IMODE(metadata.st_mode) != 0o600:
                raise TemplateError("activation draft input mode must be 0600")
            if activation_package.canonical_json(value) != raw:
                raise TemplateError("activation draft input is not canonical JSON plus LF")
            output = checked_activation_template(value)
        else:
            output = checked_scenario_template(value)
        write_output(arguments.output, renderer_module().canonical(output))
        return 0
    except (OSError, TemplateError) as error:
        print(f"generate_checked_templates: {error}", file=sys.stderr)
        return 64


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Render exact, descriptor-bound Buzz CI activation inputs."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
from typing import Any


MAX_JSON = 1024 * 1024
MAX_FILE = 64 * 1024 * 1024
MAX_TREE_FILES = 1024
MAX_TREE_BYTES = 64 * 1024 * 1024
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MODE = re.compile(r"^[0-7]{4}$")
PACKAGE_NAMES = ("runner", "controld", "keyholder", "execd", "activation")
PRE_ACTIVATION_PACKAGE_NAMES = PACKAGE_NAMES[:3]
SECCOMP_SHA256 = "2598b3b98e6970f37f917e210202fa8976aefcd99abf8955803a6e35bba17eb4"
PACKAGE_SCHEMAS = {
    "runner": "buzz-ci-runner-install-package-v2",
    "controld": "buzz-ci-controld-install-package-v2",
    "keyholder": "buzz-ci-keyholder-acceptance-package-v2",
    "execd": "buzz-ci-execd-install-package-v1",
}
PACKAGE_KEYS = {
    "runner": {"schema", "package_id", "source_commit", "binary_provenance_sha256", "default_state", "peer_policy", "package_uid", "package_gid", "identities", "directories", "entries", "package_digest"},
    "controld": {"schema", "package_id", "source_commit", "binary_provenance_sha256", "default_state", "daemon_contract", "package_uid", "package_gid", "identity", "directories", "entries", "package_digest"},
    "keyholder": {"schema", "package_id", "source_commit", "package_uid", "package_gid", "identities", "runtime_contract", "credential_contract", "directories", "entries", "package_digest"},
    "execd": {"schema", "package_id", "source_commit", "binary_provenance_sha256", "default_state", "runtime_contract", "activation_owned_targets", "activation_binding", "seccomp_contract", "install_receipt", "package_uid", "package_gid", "directories", "entries", "package_digest"},
}

DESCRIPTOR_SCHEMAS = {
    "render-draft": "buzz-ci-activation-draft-render-input/v1",
    "render-scenario": "buzz-ci-capacity-one-scenario-render-input/v1",
    "render-clean-host": "buzz-ci-clean-host-contract-render-input/v1",
    "record-residue": "buzz-ci-residue-receipt-render-input/v1",
    "record-sealed-freeze": "buzz-ci-sealed-freeze-receipt-render-input/v1",
}


class RenderError(RuntimeError):
    """Fail-closed input rejection."""


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RenderError("duplicate JSON key")
        result[key] = value
    return result


def parse_canonical_json(raw: bytes, where: str) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RenderError(f"{where} is not valid JSON") from error
    if not isinstance(value, dict):
        raise RenderError(f"{where} is not a JSON object")
    if canonical(value) != raw:
        raise RenderError(f"{where} is not canonical JSON plus LF")
    return value


def require_keys(value: object, expected: set[str], where: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise RenderError(f"{where} shape differs")
    return value


def require_sha(value: object, where: str, *, git: bool = False) -> str:
    pattern = HEX40 if git else HEX64
    zeros = "0" * (40 if git else 64)
    if not isinstance(value, str) or pattern.fullmatch(value) is None or value == zeros:
        raise RenderError(f"{where} is not an exact nonzero digest")
    return value


def normalized(value: object, where: str) -> str:
    if not isinstance(value, str):
        raise RenderError(f"{where} path is not text")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise RenderError(f"{where} path is not descriptor-relative")
    return path.as_posix()


def mode_value(value: object, where: str) -> int:
    if not isinstance(value, str) or MODE.fullmatch(value) is None:
        raise RenderError(f"{where} mode is invalid")
    return int(value, 8)


class DescriptorRoot:
    """Read one immutable input graph below the descriptor directory."""

    def __init__(self, descriptor: Path):
        absolute = Path(os.path.abspath(descriptor))
        if Path(os.path.realpath(absolute)) != absolute:
            raise RenderError("descriptor path contains a symbolic component")
        descriptor_fd = os.open(absolute, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(descriptor_fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > MAX_JSON:
                raise RenderError("descriptor metadata is unsafe")
            if stat.S_IMODE(metadata.st_mode) != 0o600:
                raise RenderError("descriptor mode must be 0600")
            raw = self._read_fd(descriptor_fd, metadata.st_size, MAX_JSON, "descriptor")
        finally:
            os.close(descriptor_fd)
        self.descriptor = parse_canonical_json(raw, "descriptor")
        self.base = absolute.parent
        self.base_fd = os.open(self.base, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        base_metadata = os.fstat(self.base_fd)
        if base_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            os.close(self.base_fd)
            raise RenderError("descriptor directory is writable by another identity")

    def close(self) -> None:
        os.close(self.base_fd)

    @staticmethod
    def _read_fd(fd: int, size: int, maximum: int, where: str) -> bytes:
        if size > maximum:
            raise RenderError(f"{where} exceeds its fixed bound")
        before = os.fstat(fd)
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(fd, min(1024 * 1024, maximum + 1 - total)):
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise RenderError(f"{where} exceeds its fixed bound")
        after = os.fstat(fd)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_mode, item.st_nlink)
        if identity(before) != identity(after) or total != size:
            raise RenderError(f"{where} changed while read")
        return b"".join(chunks)

    def _open_parent(self, relative: str) -> tuple[int, str]:
        parts = PurePosixPath(normalized(relative, "input")).parts
        current = os.dup(self.base_fd)
        try:
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=current)
                metadata = os.fstat(child)
                if not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                    os.close(child)
                    raise RenderError(f"unsafe input parent: {relative}")
                os.close(current)
                current = child
            return current, parts[-1]
        except BaseException:
            os.close(current)
            raise

    def read_ref(self, value: object, where: str, maximum: int = MAX_FILE) -> tuple[bytes, str]:
        ref = require_keys(value, {"path", "sha256", "bytes", "mode"}, where)
        relative = normalized(ref["path"], where)
        digest = require_sha(ref["sha256"], f"{where} sha256")
        expected_mode = mode_value(ref["mode"], where)
        size = ref["bytes"]
        if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= maximum:
            raise RenderError(f"{where} byte count is invalid")
        parent, name = self._open_parent(relative)
        try:
            fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
        finally:
            os.close(parent)
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise RenderError(f"{where} is not one regular file")
            if metadata.st_size != size or stat.S_IMODE(metadata.st_mode) != expected_mode:
                raise RenderError(f"{where} size or mode differs")
            raw = self._read_fd(fd, size, maximum, where)
        finally:
            os.close(fd)
        if hashlib.sha256(raw).hexdigest() != digest:
            raise RenderError(f"{where} digest differs")
        return raw, relative

    def json_ref(self, value: object, where: str) -> tuple[dict[str, Any], bytes, str]:
        raw, relative = self.read_ref(value, where, MAX_JSON)
        return parse_canonical_json(raw, where), raw, relative

    def open_directory(self, relative: object, where: str) -> int:
        path = normalized(relative, where)
        parent, name = self._open_parent(path)
        try:
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
        finally:
            os.close(parent)
        metadata = os.fstat(fd)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            os.close(fd)
            raise RenderError(f"{where} directory metadata is unsafe")
        return fd


def walk_tree(root_fd: int, prefix: str = "") -> list[tuple[str, int, bytes]]:
    records: list[tuple[str, int, bytes]] = []
    total = 0
    seen_directories: set[tuple[int, int]] = set()

    def visit(directory_fd: int, base: str) -> None:
        nonlocal total
        directory_metadata = os.fstat(directory_fd)
        identity = (directory_metadata.st_dev, directory_metadata.st_ino)
        if identity in seen_directories:
            raise RenderError("package directory cycle or alias detected")
        seen_directories.add(identity)
        try:
            names = sorted(os.listdir(directory_fd))
        except OSError as error:
            raise RenderError("package directory could not be enumerated") from error
        for name in names:
            if name in {".", ".."} or "/" in name or "\0" in name:
                raise RenderError("package tree contains an invalid name")
            relative = f"{base}/{name}" if base else name
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                    raise RenderError(f"unsafe package directory: {relative}")
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd)
                try:
                    visit(child, relative)
                finally:
                    os.close(child)
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise RenderError(f"package member is not one regular file: {relative}")
            fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd)
            try:
                opened = os.fstat(fd)
                if (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_nlink, opened.st_size) != (
                    metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink, metadata.st_size,
                ):
                    raise RenderError(f"package member changed before read: {relative}")
                raw = DescriptorRoot._read_fd(fd, metadata.st_size, MAX_FILE, relative)
            finally:
                os.close(fd)
            total += len(raw)
            if len(records) >= MAX_TREE_FILES or total > MAX_TREE_BYTES:
                raise RenderError("package tree exceeds its fixed bound")
            records.append((relative, stat.S_IMODE(metadata.st_mode), raw))

    visit(root_fd, prefix)
    if not records:
        raise RenderError("package tree is empty")
    return records


def tree_sha256(records: list[tuple[str, int, bytes]]) -> str:
    digest = hashlib.sha256()
    for relative, mode, raw in records:
        digest.update(relative.encode())
        digest.update(b"\0")
        digest.update(f"{mode:04o}".encode())
        digest.update(b"\0")
        digest.update(hashlib.sha256(raw).digest())
    return digest.hexdigest()


def manifest_digest(manifest: dict[str, Any], name: str) -> str:
    claimed = require_sha(manifest.get("package_digest"), "package manifest digest")
    unsigned = dict(manifest)
    del unsigned["package_digest"]
    if name == "activation":
        if "activation_id" not in unsigned:
            raise RenderError("activation package ID is absent")
        del unsigned["activation_id"]
        unsigned["schema"] = "buzz-ci-capacity-one-activation-draft-v2"
    if hashlib.sha256(canonical(unsigned)).hexdigest() != claimed:
        raise RenderError("package manifest digest differs")
    return claimed


def validate_manifest(manifest: dict[str, Any], candidate: str, name: str) -> None:
    if name in PACKAGE_KEYS and (set(manifest) != PACKAGE_KEYS[name] or manifest.get("schema") != PACKAGE_SCHEMAS[name]):
        raise RenderError(f"{name} package manifest has missing or extra fields")
    if manifest.get("source_commit") != candidate:
        raise RenderError(f"{name} package candidate differs")
    manifest_digest(manifest, name)
    entries = manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        raise RenderError(f"{name} package inventory is empty")
    sources: set[str] = set()
    for item in entries:
        base_entry = {"role", "source", "target", "source_mode", "install_mode", "uid", "gid", "sha256"}
        active_entry = base_entry | {"active_source", "active_source_mode", "active_sha256"}
        if not isinstance(item, dict) or frozenset(item) not in {frozenset(base_entry), frozenset(active_entry)}:
            raise RenderError(f"{name} package entry shape differs")
        source = normalized(item["source"], f"{name} package source")
        if source in sources:
            raise RenderError(f"{name} package source is duplicated")
        sources.add(source)
        mode_value(item["source_mode"], f"{name} package source")
        require_sha(item["sha256"], f"{name} package source")
        if "active_source" in item:
            required = {"active_source", "active_source_mode", "active_sha256"}
            if not required <= set(item):
                raise RenderError(f"{name} active package entry is incomplete")
            active = normalized(item["active_source"], f"{name} active source")
            if active in sources:
                raise RenderError(f"{name} active package source is duplicated")
            sources.add(active)
            mode_value(item["active_source_mode"], f"{name} active source")
            require_sha(item["active_sha256"], f"{name} active source")


def load_manifests(root: DescriptorRoot, value: object, candidate: str, names: tuple[str, ...]) -> tuple[dict[str, Any], dict[str, str]]:
    descriptors = require_keys(value, set(names), "package manifests")
    manifests: dict[str, Any] = {}
    digests: dict[str, str] = {}
    for name in names:
        manifest, raw, _ = root.json_ref(descriptors[name], f"{name} package manifest")
        validate_manifest(manifest, candidate, name)
        manifests[name] = manifest
        digests[name] = hashlib.sha256(raw).hexdigest()
    if "activation" in manifests:
        activation = manifests["activation"]
        try:
            activation_package_module().validate_manifest(activation)
        except (KeyError, TypeError, ValueError) as error:
            raise RenderError(f"activation package validation failed: {error}") from error
        expected_id = f"buzz-ci-capacity-one-{candidate[:12]}-{activation['package_digest'][:12]}"
        if activation.get("activation_id") != expected_id:
            raise RenderError("activation ID differs from candidate and package digest")
        binding = manifests["execd"].get("activation_binding")
        if not isinstance(binding, dict) or any(
            binding.get(field) != expected for field, expected in (
                ("source_commit", candidate),
                ("package_digest", activation["package_digest"]),
                ("activation_id", activation["activation_id"]),
            )
        ):
            raise RenderError("execd package activation cross-binding differs")
    return manifests, digests


def validate_public_binding(value: dict[str, Any]) -> None:
    require_keys(value, {"schema_version", "relay_url", "relay_http_origin", "acceptance_actor", "keyholder_public_spec"}, "public binding")
    if value["schema_version"] != "buzz-ci-clean-host-e2e-public-binding/v3":
        raise RenderError("public binding schema differs")
    actor = require_keys(value["acceptance_actor"], {"public_key", "generation"}, "acceptance actor")
    require_sha(actor["public_key"], "acceptance actor public key")
    if actor["generation"] != 1:
        raise RenderError("acceptance actor generation differs")
    spec = require_keys(value["keyholder_public_spec"], {"schema_version", "peer", "selectors", "nip98_origin", "acceptance"}, "keyholder public spec")
    if spec["schema_version"] != 2 or value["relay_http_origin"] != spec["nip98_origin"]:
        raise RenderError("public binding origin differs")
    selectors = require_keys(spec["selectors"], {"ci_event", "nip98", "manifest"}, "keyholder selectors")
    peer = require_keys(spec["peer"], {"uid", "gid", "allowed_operations"}, "keyholder public peer")
    if any(isinstance(peer[field], bool) or not isinstance(peer[field], int) or not 1 <= peer[field] <= 0xFFFFFFFF for field in ("uid", "gid")):
        raise RenderError("keyholder public peer identity differs")
    if peer["allowed_operations"] != [
        "describe", "sign_ci_event", "nip98_authorize", "sign_manifest",
        "describe_acceptance", "sign_acceptance_mutation",
    ]:
        raise RenderError("keyholder public operations differ")
    if spec["acceptance"] != {
        "binding_receipt_path": "/var/lib/buzzci/activation-controller/controld-acceptance-v2.json",
        "credential_selector": "acceptance-actor.key",
    }:
        raise RenderError("public acceptance selector differs")
    keys = []
    for name, selector_value in selectors.items():
        selector = require_keys(selector_value, {"public_key", "generation"}, f"{name} selector")
        keys.append(require_sha(selector["public_key"], f"{name} public key"))
        if selector["generation"] != 1:
            raise RenderError(f"{name} generation differs")
    if len(set(keys + [actor["public_key"]])) != 4:
        raise RenderError("public binding keys collide")
    forbidden = ("secret", "private", "credential", "seed", "token")
    stack: list[object] = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            if any(key != "credential_selector" and any(word in key.lower() for word in forbidden) for key in item):
                raise RenderError("public binding contains a private field")
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)


def validate_acceptance_client_binding(
    public: dict[str, Any], manifests: dict[str, Any],
) -> None:
    try:
        peer = public["keyholder_public_spec"]["peer"]
        keyholder_identities = manifests["keyholder"]["identities"]
    except (KeyError, TypeError) as error:
        raise RenderError("acceptance client identity binding is incomplete") from error
    observed = (peer.get("uid"), peer.get("gid"))
    if observed != (
        keyholder_identities.get("controld_uid"),
        keyholder_identities.get("controld_gid"),
    ):
        raise RenderError("acceptance client identity differs from controld")
    if "activation" in manifests:
        try:
            activation_controld = manifests["activation"]["identities"]["controld"]
        except (KeyError, TypeError) as error:
            raise RenderError("acceptance client identity binding is incomplete") from error
        if observed != (activation_controld.get("uid"), activation_controld.get("gid")):
            raise RenderError("acceptance client identity differs from controld")


def copy_path(bindings: dict[str, Any], path: object) -> Any:
    if not isinstance(path, str) or not re.fullmatch(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*", path):
        raise RenderError("template copy path is invalid")
    current: Any = bindings
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            raise RenderError(f"template copy path is missing: {path}")
        current = current[part]
    return json.loads(json.dumps(current))


def resolve_template(template: dict[str, Any], kind: str, bindings: dict[str, Any]) -> Any:
    require_keys(template, {"schema_version", "kind", "definitions", "document"}, "checked template")
    if template["schema_version"] != "buzz-ci-checked-render-template/v1" or template["kind"] != kind:
        raise RenderError("checked template kind differs")
    definitions = template["definitions"]
    if not isinstance(definitions, dict):
        raise RenderError("checked template definitions differ")

    def pointer(value: str) -> tuple[str, ...]:
        if not value.startswith("#/definitions/"):
            raise RenderError("template reference escapes definitions")
        parts = value[2:].split("/")
        if not parts or any(not part or "~" in part for part in parts):
            raise RenderError("template reference is invalid")
        return tuple(parts)

    active: set[tuple[str, ...]] = set()

    def dereference(parts: tuple[str, ...]) -> Any:
        if parts in active:
            raise RenderError("template reference cycle detected")
        current: Any = template
        for part in parts:
            if not isinstance(current, dict) or part not in current:
                raise RenderError("template reference is missing")
            current = current[part]
        active.add(parts)
        try:
            return visit(current)
        finally:
            active.remove(parts)

    def visit(value: Any) -> Any:
        if isinstance(value, dict):
            if set(value) == {"$copy"}:
                return copy_path(bindings, value["$copy"])
            if set(value) == {"$ref"}:
                return dereference(pointer(value["$ref"]))
            if any(key.startswith("$") for key in value):
                raise RenderError("unknown template directive")
            return {key: visit(nested) for key, nested in value.items()}
        if isinstance(value, list):
            return [visit(item) for item in value]
        return value

    return visit(template["document"])


def load_template_bindings(root: DescriptorRoot, descriptor: dict[str, Any], names: tuple[str, ...]) -> tuple[dict[str, Any], dict[str, Any]]:
    candidate = require_sha(descriptor["candidate_sha"], "candidate", git=True)
    public, public_raw, _ = root.json_ref(descriptor["public_binding"], "public binding")
    validate_public_binding(public)
    manifests, manifest_file_sha = load_manifests(root, descriptor["package_manifests"], candidate, names)
    validate_acceptance_client_binding(public, manifests)
    bindings = {
        "candidate_sha": candidate,
        "public_binding": public,
        "packages": manifests,
        "package_manifest_sha256": manifest_file_sha,
        "public_binding_sha256": hashlib.sha256(public_raw).hexdigest(),
    }
    template, _raw, _ = root.json_ref(descriptor["template"], "checked template")
    return template, bindings


def activation_package_module() -> Any:
    path = Path(__file__).resolve().parent.parent / "package.py"
    spec = importlib.util.spec_from_file_location("buzz_ci_activation_package_for_renderer", path)
    if spec is None or spec.loader is None:
        raise RenderError("activation package validator is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def execd_preactivation_module() -> Any:
    path = Path(__file__).resolve().parents[2] / "execd" / "freeze_package.py"
    spec = importlib.util.spec_from_file_location(
        "buzz_ci_execd_preactivation_for_renderer", path
    )
    if spec is None or spec.loader is None:
        raise RenderError("execd pre-activation input validator is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_execd_preactivation(
    root: DescriptorRoot,
    value: object,
    candidate: str,
) -> tuple[dict[str, Any], str]:
    raw, _relative = root.read_ref(value, "execd pre-activation input", MAX_JSON)
    try:
        preactivation = execd_preactivation_module().parse_preactivation_input(raw)
    except (KeyError, TypeError, ValueError) as error:
        raise RenderError(f"execd pre-activation input validation failed: {error}") from error
    if preactivation["source_commit"] != candidate:
        raise RenderError("execd pre-activation input candidate differs")
    return preactivation, hashlib.sha256(raw).hexdigest()


def receipt_verifier_module() -> Any:
    path = Path(__file__).resolve().parents[2] / "acceptance" / "verify-receipt.py"
    spec = importlib.util.spec_from_file_location("buzz_ci_acceptance_verifier_for_renderer", path)
    if spec is None or spec.loader is None:
        raise RenderError("acceptance scenario validator is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def render_draft(root: DescriptorRoot, descriptor: dict[str, Any]) -> dict[str, Any]:
    require_keys(
        descriptor,
        {
            "schema_version",
            "candidate_sha",
            "public_binding",
            "package_manifests",
            "execd_preactivation",
            "template",
        },
        "draft descriptor",
    )
    template, bindings = load_template_bindings(root, descriptor, PRE_ACTIVATION_PACKAGE_NAMES)
    preactivation, preactivation_sha256 = load_execd_preactivation(
        root, descriptor["execd_preactivation"], bindings["candidate_sha"]
    )
    bindings["execd_preactivation"] = preactivation
    bindings["execd_preactivation_sha256"] = preactivation_sha256
    value = resolve_template(template, "activation-draft", bindings)
    if not isinstance(value, dict):
        raise RenderError("activation draft template did not render an object")
    try:
        activation_package_module().validate_manifest(value, require_digest=False)
    except (KeyError, TypeError, ValueError) as error:
        raise RenderError(f"activation draft validation failed: {error}") from error
    if value["source_commit"] != bindings["candidate_sha"]:
        raise RenderError("activation draft candidate differs")
    if value["acceptance_template"]["actor"] != bindings["public_binding"]["acceptance_actor"]:
        raise RenderError("activation draft public actor differs")
    return value


def validate_scenario(value: object, bindings: dict[str, Any]) -> dict[str, Any]:
    scenario = require_keys(value, {"schema_version", "fixture", "driver"}, "capacity-one scenario")
    if scenario["schema_version"] != "buzz-ci-capacity-one-scenario/v2":
        raise RenderError("capacity-one scenario schema differs")
    fixture = scenario["fixture"]
    if not isinstance(fixture, dict):
        raise RenderError("capacity-one scenario fixture differs")
    activation = bindings["packages"]["activation"]
    if activation.get("default_state") != {
        "capacity": 0,
        "enabled": False,
        "active": False,
        "provisioned": False,
    }:
        raise RenderError("activation package does not stage at closed capacity zero")
    expected = {
        "integrated_candidate_sha": bindings["candidate_sha"],
        "source_oid": bindings["candidate_sha"],
        "activation_id": activation["activation_id"],
        "activation_package_digest": activation["package_digest"],
    }
    if any(fixture.get(key) != wanted for key, wanted in expected.items()):
        raise RenderError("capacity-one scenario cross-binding differs")
    required = {
        "integrated_candidate_sha", "activation_id", "activation_package_digest", "run_id",
        "job_id", "request_digest", "manifest_digest", "source_oid", "approval_id",
        "grant_event_id", "grant_digest", "approved_by", "export_subject",
        "export_authorization_digest", "controller_generation", "runner_generation",
        "expected_log", "expected_artifacts",
    }
    require_keys(fixture, required, "capacity-one fixture")
    try:
        ordered = receipt_verifier_module()._ordered_scenario(scenario)
    except (KeyError, TypeError, ValueError) as error:
        raise RenderError(f"capacity-one scenario validation failed: {error}") from error
    if ordered != scenario:
        raise RenderError("capacity-one scenario normalization differs")
    return scenario


def render_scenario(root: DescriptorRoot, descriptor: dict[str, Any]) -> dict[str, Any]:
    require_keys(descriptor, {"schema_version", "candidate_sha", "public_binding", "package_manifests", "template"}, "scenario descriptor")
    template, bindings = load_template_bindings(root, descriptor, PACKAGE_NAMES)
    return validate_scenario(resolve_template(template, "capacity-one-scenario", bindings), bindings)


def validate_package_tree(root: DescriptorRoot, name: str, package: dict[str, Any], candidate: str) -> tuple[dict[str, Any], str, str]:
    package = require_keys(package, {"path", "manifest_sha256", "manifest_bytes", "manifest_mode"}, f"{name} package tree")
    package_path = normalized(package["path"], f"{name} package tree")
    manifest_name = "activation-manifest.json" if name == "activation" else "package-manifest.json"
    manifest_ref = {
        "path": f"{package_path}/{manifest_name}",
        "sha256": package["manifest_sha256"],
        "bytes": package["manifest_bytes"],
        "mode": package["manifest_mode"],
    }
    manifest, manifest_raw, _ = root.json_ref(manifest_ref, f"{name} package manifest")
    validate_manifest(manifest, candidate, name)
    directory = root.open_directory(package_path, f"{name} package tree")
    try:
        records = walk_tree(directory)
    finally:
        os.close(directory)
    record_map = {relative: (mode, raw) for relative, mode, raw in records}
    expected = {manifest_name}
    for item in manifest["entries"]:
        for source_field, mode_field, digest_field in (
            ("source", "source_mode", "sha256"),
            ("active_source", "active_source_mode", "active_sha256"),
        ):
            if source_field not in item:
                continue
            source = normalized(item[source_field], f"{name} package source")
            expected.add(source)
            actual = record_map.get(source)
            if actual is None:
                raise RenderError(f"{name} package source is missing: {source}")
            if actual[0] != mode_value(item[mode_field], f"{name} package source") or hashlib.sha256(actual[1]).hexdigest() != item[digest_field]:
                raise RenderError(f"{name} package source metadata differs: {source}")
    for component in manifest.get("components", []):
        if not isinstance(component, dict) or "provenance_source" not in component or "provenance_sha256" not in component:
            raise RenderError("activation component provenance shape differs")
        source = normalized(component["provenance_source"], "activation component provenance")
        expected.add(source)
        actual = record_map.get(source)
        if actual is None or hashlib.sha256(actual[1]).hexdigest() != component["provenance_sha256"]:
            raise RenderError(f"activation component provenance differs: {source}")
        if "package_manifest_source" in component:
            package_source = normalized(
                component["package_manifest_source"],
                "activation component package manifest",
            )
            expected.add(package_source)
            package_actual = record_map.get(package_source)
            if (
                package_actual is None
                or hashlib.sha256(package_actual[1]).hexdigest()
                != component.get("package_manifest_sha256")
            ):
                raise RenderError(
                    f"activation component package manifest differs: {package_source}"
                )
    if "binary_provenance_sha256" in manifest:
        source = "binary-provenance.json"
        expected.add(source)
        actual = record_map.get(source)
        if actual is None or hashlib.sha256(actual[1]).hexdigest() != manifest["binary_provenance_sha256"]:
            raise RenderError(f"{name} binary provenance differs")
    if set(record_map) != expected:
        raise RenderError(f"{name} package tree has missing or extra members")
    return manifest, hashlib.sha256(manifest_raw).hexdigest(), tree_sha256(records)


def clean_host_contract(root: DescriptorRoot, descriptor: dict[str, Any]) -> dict[str, Any]:
    require_keys(descriptor, {"schema_version", "candidate_sha", "state", "candidate_root", "public_binding", "scenario", "seccomp_source", "packages"}, "clean-host descriptor")
    candidate = require_sha(descriptor["candidate_sha"], "candidate", git=True)
    state = normalized(descriptor["state"], "state")
    candidate_root = normalized(descriptor["candidate_root"], "candidate root")
    state_fd = root.open_directory(state, "state")
    os.close(state_fd)
    candidate_fd = root.open_directory(candidate_root, "candidate root")
    os.close(candidate_fd)
    public, _public_raw, public_path = root.json_ref(descriptor["public_binding"], "public binding")
    if public_path != f"{state}/public-binding.json":
        raise RenderError("public binding is not the prepared state binding")
    validate_public_binding(public)
    try:
        resolved = subprocess.run(
            ["git", "-C", str(root.base / candidate_root), "rev-parse", "HEAD^{commit}"],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, timeout=10,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as error:
        raise RenderError("candidate Git identity could not be verified") from error
    if resolved != candidate:
        raise RenderError("candidate root HEAD differs")
    scenario, scenario_raw, scenario_path = root.json_ref(descriptor["scenario"], "scenario")
    seccomp_raw, seccomp_path = root.read_ref(descriptor["seccomp_source"], "seccomp source", 16 * 1024 * 1024)
    if hashlib.sha256(seccomp_raw).hexdigest() != SECCOMP_SHA256:
        raise RenderError("seccomp source differs from the frozen contract")
    package_descriptors = require_keys(descriptor["packages"], set(PACKAGE_NAMES), "package trees")
    manifests: dict[str, Any] = {}
    tree_digests: dict[str, str] = {}
    paths: dict[str, str] = {}
    for name in PACKAGE_NAMES:
        package_value = package_descriptors[name]
        if not isinstance(package_value, dict):
            raise RenderError(f"{name} package descriptor differs")
        manifests[name], _manifest_sha, tree_digests[name] = validate_package_tree(root, name, package_value, candidate)
        paths[name] = normalized(package_value["path"], f"{name} package path")
    bindings = {"candidate_sha": candidate, "packages": manifests}
    validate_scenario(scenario, bindings)
    activation = manifests["activation"]
    binding = manifests["execd"].get("activation_binding")
    if not isinstance(binding, dict) or any(binding.get(key) != value for key, value in (
        ("source_commit", candidate), ("activation_id", activation["activation_id"]), ("package_digest", activation["package_digest"]),
    )):
        raise RenderError("execd package activation binding differs")
    return {
        "candidate_root": candidate_root,
        "candidate_sha": candidate,
        "packages": {name: {"path": paths[name], "tree_sha256": tree_digests[name]} for name in PACKAGE_NAMES},
        "scenario": {"path": scenario_path, "sha256": hashlib.sha256(scenario_raw).hexdigest()},
        "schema_version": "buzz-ci-clean-host-e2e-vm-contract/v2",
        "seccomp_source": {"path": seccomp_path, "sha256": SECCOMP_SHA256},
        "state": state,
    }


def lifecycle_evidence(root: DescriptorRoot, descriptor: dict[str, Any]) -> dict[str, Any]:
    refs = require_keys(descriptor["lifecycle"], {"result", "contract", "evidence_manifest", "acceptance_receipt", "verifier"}, "lifecycle outputs")
    values: dict[str, dict[str, Any]] = {}
    raws: dict[str, bytes] = {}
    for name, ref in refs.items():
        values[name], raws[name], _ = root.json_ref(ref, f"lifecycle {name}")
    candidate = require_sha(descriptor["candidate_sha"], "candidate", git=True)
    result = values["result"]
    contract = values["contract"]
    evidence = values["evidence_manifest"]
    receipt = values["acceptance_receipt"]
    verifier = values["verifier"]
    require_keys(contract, {"schema_version", "state", "candidate_root", "candidate_sha", "scenario", "seccomp_source", "packages"}, "lifecycle contract")
    require_keys(evidence, {"schema_version", "candidate_sha", "image_sha256", "tool_sha256", "harness_asset_sha256", "package_tree_sha256", "scenario_sha256", "seccomp_source_sha256", "receipt_sha256", "verifier_sha256", "dormant_proof"}, "lifecycle evidence manifest")
    require_keys(result, {"status", "candidate_sha", "receipt_sha256", "verifier_sha256", "evidence_manifest_sha256", "dormant_proof", "vm_state_absent"}, "lifecycle result")
    require_keys(verifier, {"status"}, "installed verifier output")
    if contract.get("schema_version") != "buzz-ci-clean-host-e2e-vm-contract/v2" or contract.get("candidate_sha") != candidate:
        raise RenderError("lifecycle contract candidate differs")
    normalized(contract["state"], "lifecycle state")
    normalized(contract["candidate_root"], "lifecycle candidate root")
    contract_scenario = require_keys(contract["scenario"], {"path", "sha256"}, "lifecycle scenario")
    normalized(contract_scenario["path"], "lifecycle scenario")
    require_sha(contract_scenario["sha256"], "lifecycle scenario")
    contract_seccomp = require_keys(contract["seccomp_source"], {"path", "sha256"}, "lifecycle seccomp source")
    normalized(contract_seccomp["path"], "lifecycle seccomp source")
    if contract_seccomp["sha256"] != SECCOMP_SHA256:
        raise RenderError("lifecycle seccomp source differs")
    if evidence.get("schema_version") != "buzz-ci-clean-host-e2e-evidence/v2" or evidence.get("candidate_sha") != candidate:
        raise RenderError("lifecycle evidence candidate differs")
    require_sha(evidence["image_sha256"], "lifecycle image")
    for field in ("tool_sha256", "harness_asset_sha256"):
        digest_map = evidence[field]
        if not isinstance(digest_map, dict) or not digest_map:
            raise RenderError(f"lifecycle {field} differs")
        for name, digest in digest_map.items():
            if not isinstance(name, str) or not name or "/" in name:
                raise RenderError(f"lifecycle {field} name differs")
            require_sha(digest, f"lifecycle {field} digest")
    if evidence["seccomp_source_sha256"] != SECCOMP_SHA256:
        raise RenderError("lifecycle evidence seccomp source differs")
    if result.get("status") != "pass" or result.get("candidate_sha") != candidate or result.get("vm_state_absent") is not True:
        raise RenderError("clean-host lifecycle did not return verified pass with absent state")
    if receipt.get("outcome") != "pass" or receipt.get("integrated_candidate_sha") != candidate:
        raise RenderError("acceptance lifecycle receipt did not pass for the candidate")
    if verifier.get("status") != "pass":
        raise RenderError("installed verifier lifecycle output did not pass")
    scenario_sha = contract.get("scenario", {}).get("sha256") if isinstance(contract.get("scenario"), dict) else None
    if not isinstance(scenario_sha, str) or any(item.get("scenario_sha256") != scenario_sha for item in (evidence, receipt)):
        raise RenderError("lifecycle scenario binding differs")
    expected_digests = {
        "receipt_sha256": hashlib.sha256(raws["acceptance_receipt"]).hexdigest(),
        "verifier_sha256": hashlib.sha256(raws["verifier"]).hexdigest(),
    }
    if any(evidence.get(key) != digest or result.get(key) != digest for key, digest in expected_digests.items()):
        raise RenderError("lifecycle output digest differs")
    evidence_digest = hashlib.sha256(raws["evidence_manifest"]).hexdigest()
    if result.get("evidence_manifest_sha256") != evidence_digest:
        raise RenderError("lifecycle evidence manifest digest differs")
    contract_trees = contract.get("packages")
    evidence_trees = evidence.get("package_tree_sha256")
    if not isinstance(contract_trees, dict) or not isinstance(evidence_trees, dict) or set(contract_trees) != set(PACKAGE_NAMES) or set(evidence_trees) != set(PACKAGE_NAMES):
        raise RenderError("lifecycle package tree set differs")
    if any(not isinstance(contract_trees[name], dict) or contract_trees[name].get("tree_sha256") != evidence_trees[name] for name in PACKAGE_NAMES):
        raise RenderError("lifecycle package tree binding differs")
    for name in PACKAGE_NAMES:
        require_keys(contract_trees[name], {"path", "tree_sha256"}, f"lifecycle {name} package")
        normalized(contract_trees[name]["path"], f"lifecycle {name} package")
        require_sha(evidence_trees[name], f"lifecycle {name} package tree")
    proof = evidence.get("dormant_proof")
    required_proof = {"configs_sha256", "units_sha256", "sockets_absent", "processes_absent", "encrypted_credentials_absent", "relay_residue_absent"}
    if not isinstance(proof, dict) or set(proof) != required_proof or proof != result.get("dormant_proof"):
        raise RenderError("lifecycle dormant proof differs")
    if any(proof.get(name) is not True for name in ("sockets_absent", "processes_absent", "encrypted_credentials_absent", "relay_residue_absent")):
        raise RenderError("lifecycle residue is not absent")
    require_sha(proof["configs_sha256"], "dormant config digest")
    require_sha(proof["units_sha256"], "dormant unit digest")
    return {
        "candidate_sha": candidate,
        "scenario_sha256": scenario_sha,
        "package_tree_sha256": evidence_trees,
        "dormant_proof": proof,
        "contract_sha256": hashlib.sha256(raws["contract"]).hexdigest(),
        "evidence_manifest_sha256": evidence_digest,
        "contract": contract,
        **expected_digests,
    }


def record_residue(root: DescriptorRoot, descriptor: dict[str, Any]) -> dict[str, Any]:
    require_keys(descriptor, {"schema_version", "candidate_sha", "lifecycle"}, "residue descriptor")
    evidence = lifecycle_evidence(root, descriptor)
    return {
        "candidate_sha": evidence["candidate_sha"],
        "claims": {"protected_ci": False, "tier2": False},
        "contract_sha256": evidence["contract_sha256"],
        "dormant_proof": evidence["dormant_proof"],
        "evidence_manifest_sha256": evidence["evidence_manifest_sha256"],
        "lifecycle_status": "verified_pass",
        "receipt_sha256": evidence["receipt_sha256"],
        "schema_version": "buzz-ci-clean-host-residue-receipt-input/v1",
        "verifier_sha256": evidence["verifier_sha256"],
    }


def record_sealed_freeze(root: DescriptorRoot, descriptor: dict[str, Any]) -> dict[str, Any]:
    require_keys(descriptor, {"schema_version", "candidate_sha", "lifecycle", "public_binding", "package_manifests"}, "sealed-freeze descriptor")
    evidence = lifecycle_evidence(root, descriptor)
    public, public_raw, public_path = root.json_ref(descriptor["public_binding"], "public binding")
    validate_public_binding(public)
    contract = evidence["contract"]
    if public_path != f"{contract['state']}/public-binding.json":
        raise RenderError("sealed-freeze public binding differs from the lifecycle state")
    manifests, manifest_file_sha = load_manifests(root, descriptor["package_manifests"], evidence["candidate_sha"], PACKAGE_NAMES)
    package_refs = require_keys(descriptor["package_manifests"], set(PACKAGE_NAMES), "sealed-freeze manifests")
    for name in PACKAGE_NAMES:
        contract_package = contract["packages"][name]
        manifest_name = "activation-manifest.json" if name == "activation" else "package-manifest.json"
        expected_path = f"{contract_package['path']}/{manifest_name}"
        if package_refs[name].get("path") != expected_path:
            raise RenderError(f"sealed-freeze manifest path differs from lifecycle package: {name}")
        package_descriptor = {
            "path": contract_package["path"],
            "manifest_sha256": package_refs[name]["sha256"],
            "manifest_bytes": package_refs[name]["bytes"],
            "manifest_mode": package_refs[name]["mode"],
        }
        observed, _manifest_sha, observed_tree = validate_package_tree(root, name, package_descriptor, evidence["candidate_sha"])
        if observed != manifests[name] or observed_tree != evidence["package_tree_sha256"][name]:
            raise RenderError(f"sealed-freeze package differs from lifecycle evidence: {name}")
    return {
        "candidate_sha": evidence["candidate_sha"],
        "claims": {"protected_ci": False, "tier2": False},
        "contract_sha256": evidence["contract_sha256"],
        "evidence_manifest_sha256": evidence["evidence_manifest_sha256"],
        "lifecycle_status": "verified_pass",
        "package_manifest_sha256": manifest_file_sha,
        "package_tree_sha256": evidence["package_tree_sha256"],
        "public_binding_sha256": hashlib.sha256(public_raw).hexdigest(),
        "receipt_sha256": evidence["receipt_sha256"],
        "scenario_sha256": evidence["scenario_sha256"],
        "schema_version": "buzz-ci-sealed-freeze-receipt-input/v1",
        "verifier_sha256": evidence["verifier_sha256"],
    }


def render(action: str, root: DescriptorRoot) -> dict[str, Any]:
    descriptor = root.descriptor
    if descriptor.get("schema_version") != DESCRIPTOR_SCHEMAS[action]:
        raise RenderError("descriptor schema does not match the selected action")
    return {
        "render-draft": render_draft,
        "render-scenario": render_scenario,
        "render-clean-host": clean_host_contract,
        "record-residue": record_residue,
        "record-sealed-freeze": record_sealed_freeze,
    }[action](root, descriptor)


def write_output(root: DescriptorRoot, relative: str, payload: bytes) -> None:
    output = normalized(relative, "output")
    parent, name = root._open_parent(output)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(payload)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
        if stat.S_IMODE(os.fstat(fd).st_mode) != 0o600:
            raise RenderError("output mode differs")
    finally:
        os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=tuple(DESCRIPTOR_SCHEMAS))
    parser.add_argument("--descriptor", required=True, type=Path)
    parser.add_argument("--output", required=True, help="descriptor-relative output path")
    arguments = parser.parse_args()
    root: DescriptorRoot | None = None
    try:
        root = DescriptorRoot(arguments.descriptor)
        value = render(arguments.action, root)
        write_output(root, arguments.output, canonical(value))
        return 0
    except (OSError, RenderError) as error:
        print(f"render_inputs: {error}", file=sys.stderr)
        return 64
    finally:
        if root is not None:
            root.close()


if __name__ == "__main__":
    raise SystemExit(main())

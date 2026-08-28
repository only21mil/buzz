#!/usr/bin/env python3
"""Fail-closed, secret-safe Sats roster migration primitives."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time
from typing import Any

import yaml


BUNDLE = Path(__file__).resolve().parent
MANIFEST_PATH = BUNDLE / "roster.json"
PAYLOADS = BUNDLE / "payloads"
EXPECTED_BASE = "5ac44f9ff2d16d61f562e4de16f012ae0be9fd47"
EXPECTED_INSTALL_ROOT = "/home/victor/.local/libexec/buzz/fleet/roster-5ac44f9f-v1"
EXPECTED_CONFIG_ROOT = "/home/victor/.config/buzz/agents"
EXPECTED_RELAY = "wss://framework-desktop.tail69757d.ts.net:38443"
EXPECTED_OWNER = "4a34c131ec5cb5dd9a200bac619bbd103c0793e068fad278d1de59203d05b97d"
EXPECTED_MEMBERSHIP_SHA256 = "0521668ecda6d2d79c0a795ac2cbe501d96d5a444b3b34ece53f3c3b831d01c2"
EXPECTED_SWEEP_TIMER = "buzz-sats-channel-sweep.timer"
EXPECTED_SWEEP_SERVICE = "buzz-sats-channel-sweep.service"
EXPECTED_OWNER_KEY_VAR = "BUZZ_OWNER_PRIVATE_KEY"
EXPECTED_RETAINED_AGENTS = [
    "sats-codex",
    "sats-codex-2",
    "sats-codex-r",
    "sats-glm",
    "sats-dsv4f",
    "sats-glm52",
    "alpheus-claude-code",
    "alpheus-codex",
]
EXPECTED_PRESERVE_UNITS = [
    "hermes-gateway.service",
    "buzz-agent@mempool.service",
    "buzz-agent@genesis.service",
]
EXPECTED_DESKTOP = {
    "appimage": "/home/victor/work/buzz-client/Buzz_0.5.9-test.11_amd64.AppImage",
    "appimage_sha256": "404829a7fba15a9887e847c3b0fbf5b208f6759e097367bba51ca044437f2009",
    "manifest": "/home/victor/work/buzz-client/Buzz_0.5.9-test.11_amd64.AppImage.manifest.json",
    "manifest_sha256": "b18b3b5185da563a267df2f31336ac26138d39b6808616c6735bf76d6f611168",
    "source_sha": "1543c1ffed7aa193e5cdcaf8560fa18ab8354103",
    "icon": "/home/victor/work/buzz-client/buzz.png",
    "icon_sha256": "c401bb5c0783e37275d811d87af46f4f5246dff40b1a85b4a8fc771f065cb51e",
}
EXPECTED_MEMBERSHIP_SWEEP_DEPENDENCY = {
    "activation_manifest_schema": "buzz-mempool-genesis-activation-bundle-v3",
    "source_commit": EXPECTED_BASE,
    "source_tree": "191cc2831e94c9aa60a2dd91ff67aedb280c2155",
    "staged_diff_sha256": "107c26530f020af6d9bafa46db79012f7afc134d50bbd043bccc1daa545ca1d2",
    "generator_sources": {
        "scripts/mempool-genesis/activation/templates/buzz-sats-channel-sweep.sh":
            "2d3af932d6706adc7e93b726b3d0b32bcb230e5418f64a944c09fc0e0b5b91e3",
        "scripts/mempool-genesis/activation/templates/buzz-sats-channel-sweep.service":
            "564ff73439a7ad919d9ca292a6df8b52473ae32b3314832db11a16becb46f9d0",
    },
    "ops_targets": {
        "membership_sweep": {
            "target": "/home/victor/.local/libexec/buzz/buzz-sats-channel-sweep",
            "source": "ops-root/home/victor/.local/libexec/buzz/buzz-sats-channel-sweep",
            "mode": "0700", "uid": 1000,
        },
        "membership_sweep_service": {
            "target": "/home/victor/.config/systemd/user/buzz-sats-channel-sweep.service",
            "source": "ops-root/home/victor/.config/systemd/user/buzz-sats-channel-sweep.service",
            "mode": "0600", "uid": 1000, "gid": 1000,
            "sha256": "564ff73439a7ad919d9ca292a6df8b52473ae32b3314832db11a16becb46f9d0",
        },
    },
}
BUZZ_CLI = Path("/home/victor/work/buzz-agents/bin/buzz")
SYSTEMCTL = Path("/usr/bin/systemctl")
PYTHON = Path("/usr/bin/python3")
NOSTR_TOOL = Path("/home/victor/.agents/tools/nostr_min.py")
SUPPORTED_ENABLEMENT = {"enabled", "disabled"}
SUPPORTED_ACTIVITY = {"active", "inactive"}
SUPPORTED_CHANNEL_ROLES = {"owner", "admin", "member", "guest", "bot"}


class MigrationError(RuntimeError):
    pass


def load_manifest(path: Path = MANIFEST_PATH) -> dict[str, Any]:
    data = json.loads(path.read_text())
    validate_manifest(data)
    return data


def validate_manifest(data: dict[str, Any]) -> None:
    if data.get("schema_version") != 1 or data.get("base_commit") != EXPECTED_BASE:
        raise MigrationError("unexpected roster contract version or base")
    if data.get("install_root") != EXPECTED_INSTALL_ROOT or data.get("config_root") != EXPECTED_CONFIG_ROOT:
        raise MigrationError("Buzz-owned install roots changed")
    if data.get("relay_url") != EXPECTED_RELAY or data.get("owner_pubkey") != EXPECTED_OWNER:
        raise MigrationError("relay or owner binding changed")
    if data.get("standing_sweep_timer") != EXPECTED_SWEEP_TIMER:
        raise MigrationError("standing sweep timer binding changed")
    if data.get("standing_sweep_service") != EXPECTED_SWEEP_SERVICE:
        raise MigrationError("standing sweep service binding changed")
    if data.get("owner_private_key_var") != EXPECTED_OWNER_KEY_VAR:
        raise MigrationError("owner key binding changed")
    expected_live_files = {
        "launcher": f"{EXPECTED_INSTALL_ROOT}/launch-buzz-agent",
        "desktop_launcher": f"{EXPECTED_INSTALL_ROOT}/launch-buzz-desktop",
        "desktop_entry": "/home/victor/.local/share/applications/buzz.desktop",
        "directory_sync": f"{EXPECTED_INSTALL_ROOT}/buzz-sats-directory-sync.py",
        "directory_sync_compat": "/home/victor/.agents/tools/buzz-sats-directory-sync.py",
        "membership_sweep": "/home/victor/.local/libexec/buzz/buzz-sats-channel-sweep",
        "membership_sweep_service": "/home/victor/.config/systemd/user/buzz-sats-channel-sweep.service",
        "agent_service": "/home/victor/.config/systemd/user/buzz-sats-agent@.service",
        "secrets": "/home/victor/.config/sats/secrets.env",
    }
    if data.get("live_files") != expected_live_files or data.get("publish_kinds") != [0, 10100]:
        raise MigrationError("installed file or publication scope changed")
    if data.get("retained_agents") != EXPECTED_RETAINED_AGENTS:
        raise MigrationError("retained agent inventory changed")
    if data.get("preserve_units") != EXPECTED_PRESERVE_UNITS:
        raise MigrationError("protected Hermes or system-agent baseline changed")
    if data.get("desktop") != EXPECTED_DESKTOP:
        raise MigrationError("reviewed Buzz desktop binding changed")
    if data.get("membership_sweep_dependency") != EXPECTED_MEMBERSHIP_SWEEP_DEPENDENCY:
        raise MigrationError("reviewed membership-sweep dependency changed")
    targets = data.get("targets", [])
    expected = {"sats-dsv4f", "sats-glm", "sats-glm52", "sats-codex-2"}
    if {item.get("slug") for item in targets} != expected:
        raise MigrationError("target inventory changed")
    for field in ("slug", "pubkey", "home", "prompt", "private_key_var", "auth_tag_var"):
        values = [item.get(field) for item in targets]
        if len(values) != len(set(values)) or any(not value for value in values):
            raise MigrationError(f"target {field} values must be nonempty and unique")
    by_slug = {item["slug"]: item for item in targets}
    expected_identities = {
        "sats-dsv4f": ("Knots", "Sats DSV4F", "3b1293bdf1f3885417eb1df302b5f31401fb740ad6e25b83a7aab210abc549bb", "qwen", 8328),
        "sats-glm": ("Segwit", "Sats GLM5.2.1", "b7d2ebed4d4f15a28c71b8a83f3a717770a37bd65bd29e95aea4faa6106c445a", "glm", 8327),
        "sats-glm52": ("Ledger", "Sats GLM5.2", "d0abfb7c343012552a44009b2f33bb6a6ada54b4e6d408fffeed58d388d1f2af", "glm", 8329),
        "sats-codex-2": ("UTXO", "Sats Codex-2", "aefa6783cdf2f33f9aa3705b41e5ae3ec214318c64db48f1410fc77db015f2ec", "codex", None),
    }
    actual_identities = {
        slug: (item.get("display_name"), item.get("previous_display_name"), item.get("pubkey"), item.get("agent_type"), item.get("port"))
        for slug, item in by_slug.items()
    }
    if actual_identities != expected_identities:
        raise MigrationError("surviving Buzz identity contract changed")
    expected_bindings = {
        "sats-dsv4f": (
            "/home/victor/work/buzz-agents/sats-dsv4f/home", f"{EXPECTED_CONFIG_ROOT}/sats-dsv4f-system.md",
            "BUZZ_SATS_DSV4F_PRIVATE_KEY", "BUZZ_SATS_DSV4F_AUTH_TAG",
            "/home/victor/.config/sats-dsv4f/cliproxyapi.yaml", "sats-dsv4f-proxy.service",
            "BUZZ_SATS_DSV4F_PROXY_TOKEN",
        ),
        "sats-glm": (
            "/home/victor/work/buzz-agents/sats-glm/home", f"{EXPECTED_CONFIG_ROOT}/sats-glm-system.md",
            "BUZZ_SATS_GLM_PRIVATE_KEY", "BUZZ_SATS_GLM_AUTH_TAG",
            "/home/victor/.config/sats-glm/cliproxyapi.yaml", "sats-glm-proxy.service",
            "BUZZ_SATS_GLM_PROXY_TOKEN",
        ),
        "sats-glm52": (
            "/home/victor/work/buzz-agents/sats-glm52/home", f"{EXPECTED_CONFIG_ROOT}/sats-glm52-system.md",
            "BUZZ_SATS_GLM52_PRIVATE_KEY", "BUZZ_SATS_GLM52_AUTH_TAG",
            "/home/victor/.config/sats-glm52/cliproxyapi.yaml", "sats-glm52-proxy.service",
            "BUZZ_SATS_GLM52_PROXY_TOKEN",
        ),
        "sats-codex-2": (
            "/home/victor/work/buzz-agents/sats-codex-2/home", f"{EXPECTED_CONFIG_ROOT}/sats-codex-2-system.md",
            "BUZZ_SATS_CODEX2_PRIVATE_KEY", "BUZZ_SATS_CODEX2_AUTH_TAG", None, None, None,
        ),
    }
    actual_bindings = {
        slug: (
            item.get("home"), item.get("prompt"), item.get("private_key_var"), item.get("auth_tag_var"),
            item.get("proxy_config"), item.get("proxy_unit"), item.get("proxy_token_var"),
        )
        for slug, item in by_slug.items()
    }
    if actual_bindings != expected_bindings:
        raise MigrationError("surviving Buzz runtime or authorization binding changed")
    qwen = by_slug["sats-dsv4f"]
    if qwen["model"] != "qwen/qwen3.8-flash" or qwen["reasoning"] != {"enabled": True, "effort": None}:
        raise MigrationError("Knots model or reasoning contract changed")
    if qwen["context_tokens"] != 1_000_000 or qwen["compact_tokens"] != 950_000:
        raise MigrationError("Knots context contract changed")
    for slug in ("sats-glm", "sats-glm52"):
        target = by_slug[slug]
        if target["model"] != "z-ai/glm-5.3-flash" or target["reasoning"] != {"enabled": True, "effort": "max"}:
            raise MigrationError(f"{slug} model or reasoning contract changed")
        if target["context_tokens"] != 1_048_576 or target["compact_tokens"] != 1_000_000:
            raise MigrationError(f"{slug} context contract changed")
    codex = by_slug["sats-codex-2"]
    if codex["model"] != "gpt-5.6-sol" or codex["reasoning"].get("effort") != "high":
        raise MigrationError("UTXO must preserve GPT-5.6 Sol high")
    hermes = data.get("hermes_retirement", {})
    if hermes.get("secret_variables") != ["BUZZ_SATS_HERMES_PRIVATE_KEY", "BUZZ_SATS_HERMES_AUTH_TAG"]:
        raise MigrationError("Hermes secret allowlist changed")
    if len(hermes.get("memberships", [])) != 27 or len(set(hermes["memberships"])) != 27:
        raise MigrationError("Hermes retirement must name exactly 27 memberships")
    membership_digest = hashlib.sha256(
        json.dumps(sorted(hermes["memberships"]), separators=(",", ":")).encode()
    ).hexdigest()
    if membership_digest != EXPECTED_MEMBERSHIP_SHA256:
        raise MigrationError("Hermes membership retirement set changed")
    expected_hermes = {
        "slug": "sats-hermes",
        "pubkey": "fc2cd7a09dfebfc20cd9ee4cc9ec03536d7ad4ef5d0e2d961e9fdb064511e6ba",
        "secret_variables": ["BUZZ_SATS_HERMES_PRIVATE_KEY", "BUZZ_SATS_HERMES_AUTH_TAG"],
        "agent_unit": "buzz-sats-agent@sats-hermes.service",
        "reaper_timer": "agent-child-reaper@sats-hermes.timer",
        "launcher_prompt": f"{EXPECTED_CONFIG_ROOT}/sats-hermes-system.md",
        "memberships": hermes["memberships"],
    }
    if hermes != expected_hermes:
        raise MigrationError("retired Buzz identity changed")
    fleet_prompts = data.get("fleet_prompts", [])
    expected_prompt_names = {
        "sats-codex-system.md", "sats-codex-2-system.md", "sats-codex-r-system.md",
        "sats-glm-system.md", "sats-dsv4f-system.md", "sats-glm52-system.md",
        "alpheus-claude-code-system.md", "alpheus-codex-system.md",
    }
    if {item.get("name") for item in fleet_prompts} != expected_prompt_names or len(fleet_prompts) != 8:
        raise MigrationError("fleet prompt inventory changed")
    prompt_slugs = [item["name"].removesuffix("-system.md") for item in fleet_prompts]
    if prompt_slugs != EXPECTED_RETAINED_AGENTS:
        raise MigrationError("retained agent and prompt order changed")
    for item in fleet_prompts:
        source = PAYLOADS / "prompts" / item["name"]
        if item.get("path") != f"{EXPECTED_CONFIG_ROOT}/{item['name']}":
            raise MigrationError("fleet prompt escaped the Buzz config root")
        if not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest() != item.get("sha256"):
            raise MigrationError(f"fleet prompt digest mismatch for {item['name']}")
    if "/home/victor/projects" in json.dumps(data, sort_keys=True):
        raise MigrationError("manifest retains a source-checkout runtime dependency")


def rooted(root: Path, absolute: str) -> Path:
    if not absolute.startswith("/"):
        raise MigrationError(f"path is not absolute: {absolute}")
    return root / absolute.lstrip("/") if root != Path("/") else Path(absolute)


def validate_execution_mode(root: Path, execute_external: bool, operation: str) -> None:
    if (root == Path("/")) != execute_external:
        raise MigrationError(f"{operation} execution mode does not match its root")


def install_boundary(root: Path) -> Path:
    return root if root != Path("/") else Path("/home/victor")


def validate_owned_directory_chain(root: Path, absolute: str) -> Path:
    target = rooted(root, absolute)
    boundary = install_boundary(root)
    if target != boundary and boundary not in target.parents:
        raise MigrationError(f"install path escaped its owned boundary: {target}")
    current = boundary
    relative = target.relative_to(boundary)
    for component in (Path("."), *relative.parents[::-1], relative):
        candidate = boundary if component == Path(".") else boundary / component
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            break
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise MigrationError(f"unsafe install directory type: {candidate}")
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise MigrationError(f"unsafe install directory owner or mode: {candidate}")
        current = candidate
    return target


def preflight_install_roots(manifest: dict[str, Any], root: Path) -> tuple[Path, ...]:
    install_directories = (
        manifest["install_root"],
        manifest["config_root"],
    )
    required_directories = (
        str(Path(manifest["live_files"]["desktop_entry"]).parent),
        str(Path(manifest["live_files"]["directory_sync_compat"]).parent),
    )
    validated = [
        validate_owned_directory_chain(root, directory)
        for directory in install_directories
    ]
    for directory in required_directories:
        target = validate_owned_directory_chain(root, directory)
        if not target.is_dir():
            raise MigrationError(f"required install directory is missing: {target}")
        validated.append(target)
    return tuple(validated)


def create_owned_directory_chain(root: Path, absolute: str) -> Path:
    target = validate_owned_directory_chain(root, absolute)
    boundary = install_boundary(root)
    current = boundary
    for part in target.relative_to(boundary).parts:
        current = current / part
        if not current.exists():
            current.mkdir(mode=0o700)
        validate_owned_directory_chain(root, str(current) if root == Path("/") else "/" + str(current.relative_to(root)))
    return target


def dependency_descriptor(
    path: Path,
    *,
    owner_uid: int,
    executable: bool,
    allow_symlink: bool = False,
) -> dict[str, Any]:
    try:
        link_info = path.lstat()
    except OSError as error:
        raise MigrationError(f"required dependency is missing: {path}") from error
    if stat.S_ISLNK(link_info.st_mode):
        if not allow_symlink or link_info.st_uid != owner_uid:
            raise MigrationError(f"unsafe dependency symlink: {path}")
        try:
            resolved = path.resolve(strict=True)
        except OSError as error:
            raise MigrationError(f"broken dependency symlink: {path}") from error
    else:
        resolved = path
    try:
        info = resolved.stat()
    except OSError as error:
        raise MigrationError(f"required dependency is unreadable: {path}") from error
    mode = stat.S_IMODE(info.st_mode)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid or mode & 0o022:
        raise MigrationError(f"unsafe dependency owner, type, or mode: {path}")
    if not allow_symlink and info.st_nlink != 1:
        raise MigrationError(f"unsafe dependency link count: {path}")
    if executable and not mode & 0o111:
        raise MigrationError(f"dependency is not executable: {path}")
    try:
        raw = resolved.read_bytes()
    except OSError as error:
        raise MigrationError(f"required dependency cannot be read: {path}") from error
    return {
        "path": str(path),
        "resolved": str(resolved),
        "owner_uid": info.st_uid,
        "owner_gid": info.st_gid,
        "mode": f"{mode:04o}",
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def reject_duplicate_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MigrationError(f"activation manifest has duplicate field: {key}")
        result[key] = value
    return result


def validate_membership_sweep_dependency(
    roster: dict[str, Any],
    root: Path,
    activation_manifest_path: Path | None,
    activation_manifest_sha256: str | None,
) -> dict[str, Any]:
    if activation_manifest_path is None or activation_manifest_sha256 is None:
        raise MigrationError("reviewed activation manifest path and SHA-256 are required")
    if (
        not activation_manifest_path.is_absolute()
        or os.path.normpath(str(activation_manifest_path)) != str(activation_manifest_path)
        or not re.fullmatch(r"[0-9a-f]{64}", activation_manifest_sha256)
    ):
        raise MigrationError("activation manifest path or SHA-256 is invalid")
    manifest_descriptor = dependency_descriptor(
        activation_manifest_path, owner_uid=os.getuid(), executable=False,
    )
    try:
        activation_raw = activation_manifest_path.read_bytes()
    except OSError as error:
        raise MigrationError("activation manifest is unreadable") from error
    if (
        manifest_descriptor["sha256"] != activation_manifest_sha256
        or hashlib.sha256(activation_raw).hexdigest() != activation_manifest_sha256
    ):
        raise MigrationError("activation manifest SHA-256 mismatch")
    try:
        activation = json.loads(
            activation_raw.decode("utf-8"), object_pairs_hook=reject_duplicate_json_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MigrationError("activation manifest is unreadable") from error
    contract = roster["membership_sweep_dependency"]
    for field in ("activation_manifest_schema", "source_commit", "source_tree"):
        activation_field = "schema" if field == "activation_manifest_schema" else field
        if activation.get(activation_field) != contract[field]:
            raise MigrationError(f"activation manifest {activation_field} binding mismatch")
    if not re.fullmatch(r"[0-9a-f]{64}", activation.get("package_digest", "")):
        raise MigrationError("activation manifest package digest is invalid")

    sources = activation.get("generator_sources")
    if not isinstance(sources, list):
        raise MigrationError("activation manifest generator source inventory is invalid")
    source_by_path: dict[str, dict[str, Any]] = {}
    for source in sources:
        if not isinstance(source, dict) or not isinstance(source.get("path"), str):
            raise MigrationError("activation manifest generator source record is invalid")
        if source["path"] in source_by_path:
            raise MigrationError("activation manifest generator source path is duplicated")
        source_by_path[source["path"]] = source
    for path, expected_sha256 in contract["generator_sources"].items():
        record = source_by_path.get(path)
        if record is None or record.get("sha256") != expected_sha256:
            raise MigrationError(f"activation generator source binding mismatch: {path}")

    raw_targets = activation.get("ops_targets")
    if not isinstance(raw_targets, list):
        raise MigrationError("activation manifest ops target inventory is invalid")
    targets: dict[str, dict[str, Any]] = {}
    for record in raw_targets:
        if not isinstance(record, dict) or not isinstance(record.get("target"), str):
            raise MigrationError("activation manifest ops target record is invalid")
        if record["target"] in targets:
            raise MigrationError("activation manifest ops target is duplicated")
        targets[record["target"]] = record

    package_root = activation_manifest_path.parent.resolve()
    verified_targets: dict[str, dict[str, Any]] = {}
    for name, expected in contract["ops_targets"].items():
        record = targets.get(expected["target"])
        if record is None:
            raise MigrationError(f"activation manifest is missing {name}")
        expected_fields = ("target", "source", "mode", "uid") + (("gid",) if "gid" in expected else ())
        for field in expected_fields:
            if record.get(field) != expected[field]:
                raise MigrationError(f"activation manifest {name} {field} mismatch")
        target_sha256 = record.get("sha256")
        if not re.fullmatch(r"[0-9a-f]{64}", target_sha256 or ""):
            raise MigrationError(f"activation manifest {name} SHA-256 is invalid")
        if expected.get("sha256") is not None and target_sha256 != expected["sha256"]:
            raise MigrationError(f"activation manifest {name} SHA-256 mismatch")
        source_path = (package_root / record["source"]).resolve()
        try:
            source_path.relative_to(package_root)
        except ValueError as error:
            raise MigrationError(f"activation manifest {name} source escapes its package") from error
        source_descriptor = dependency_descriptor(
            source_path, owner_uid=os.getuid(), executable=name == "membership_sweep",
        )
        expected_gid = expected.get("gid", os.getgid())
        if (
            source_descriptor["owner_gid"] != expected_gid
            or source_descriptor["mode"] != expected["mode"]
            or source_descriptor["sha256"] != target_sha256
        ):
            raise MigrationError(f"activation package {name} bytes or mode mismatch")
        installed_path = rooted(root, expected["target"])
        installed_descriptor = dependency_descriptor(
            installed_path, owner_uid=os.getuid(), executable=name == "membership_sweep",
        )
        if (
            installed_descriptor["owner_gid"] != expected_gid
            or installed_descriptor["mode"] != expected["mode"]
            or installed_descriptor["sha256"] != target_sha256
        ):
            raise MigrationError(f"installed {name} bytes or mode mismatch")
        verified_targets[name] = {
            "target": expected["target"], "mode": expected["mode"], "sha256": target_sha256,
        }
    service_path = rooted(root, contract["ops_targets"]["membership_sweep_service"]["target"])
    expected_exec = f"ExecStart={contract['ops_targets']['membership_sweep']['target']}"
    service_lines = service_path.read_text().splitlines()
    if service_lines.count(expected_exec) != 1:
        raise MigrationError("installed membership-sweep service ExecStart binding mismatch")
    return {
        "activation_manifest": manifest_descriptor,
        "package_digest": activation["package_digest"],
        "source_commit": activation["source_commit"],
        "source_tree": activation["source_tree"],
        "ops_targets": verified_targets,
    }


def run_preflight_command(argv: list[str], *, input_bytes: bytes | None = None) -> None:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        result = subprocess.run(
            argv,
            input=input_bytes,
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError as error:
        raise MigrationError(f"dependency preflight could not execute: {argv[0]}") from error
    if result.returncode:
        raise MigrationError(f"dependency preflight failed: {argv[0]}")


def external_dependency_descriptors() -> dict[str, dict[str, Any]]:
    publisher = PAYLOADS / "buzz-sats-directory-sync.py"
    return {
        "buzz": dependency_descriptor(BUZZ_CLI, owner_uid=os.getuid(), executable=True),
        "systemctl": dependency_descriptor(SYSTEMCTL, owner_uid=0, executable=True),
        "python": dependency_descriptor(PYTHON, owner_uid=0, executable=True, allow_symlink=True),
        "nostr_min": dependency_descriptor(NOSTR_TOOL, owner_uid=os.getuid(), executable=False),
        "publisher": dependency_descriptor(publisher, owner_uid=os.getuid(), executable=False),
    }


def preflight_external_dependencies(owner_private_key: str) -> dict[str, dict[str, Any]]:
    if not re.fullmatch(r"[0-9a-fA-F]{64}", owner_private_key):
        raise MigrationError("owner private key has invalid format")
    publisher = PAYLOADS / "buzz-sats-directory-sync.py"
    dependencies = external_dependency_descriptors()
    run_preflight_command([str(BUZZ_CLI), "--version"])
    run_preflight_command([str(SYSTEMCTL), "--version"])
    run_preflight_command([str(PYTHON), "--version"])
    run_preflight_command(
        [str(PYTHON), str(publisher), "--preflight-owner"],
        input_bytes=owner_private_key.encode(),
    )
    return dependencies


def validate_private_file_metadata(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise MigrationError(f"required private file is missing: {path}") from error
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or mode != 0o600
    ):
        raise MigrationError(f"required private file metadata is unsafe: {path}")
    return {"path": str(path), "owner_uid": metadata.st_uid, "mode": f"{mode:04o}"}


def preflight_desktop_artifact(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    desktop = manifest["desktop"]
    descriptors = {
        "appimage": dependency_descriptor(
            Path(desktop["appimage"]), owner_uid=os.getuid(), executable=True,
        ),
        "manifest": dependency_descriptor(
            Path(desktop["manifest"]), owner_uid=os.getuid(), executable=False,
        ),
        "icon": dependency_descriptor(
            Path(desktop["icon"]), owner_uid=os.getuid(), executable=False,
        ),
    }
    for name in ("appimage", "manifest", "icon"):
        if descriptors[name]["sha256"] != desktop[f"{name}_sha256"]:
            raise MigrationError(f"reviewed desktop {name} digest mismatch")
    try:
        artifact_manifest = json.loads(Path(desktop["manifest"]).read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MigrationError("reviewed desktop manifest is unreadable") from error
    if (
        artifact_manifest.get("artifact_sha256") != desktop["appimage_sha256"]
        or artifact_manifest.get("source_sha") != desktop["source_sha"]
        or artifact_manifest.get("repository") != "only21mil/buzz"
    ):
        raise MigrationError("reviewed desktop manifest binding mismatch")
    return descriptors


def preflight_public_host(
    manifest: dict[str, Any],
    activation_manifest_path: Path | None,
    activation_manifest_sha256: str | None,
) -> dict[str, Any]:
    preflight_install_roots(manifest, Path("/"))
    membership_sweep = validate_membership_sweep_dependency(
        manifest, Path("/"), activation_manifest_path, activation_manifest_sha256,
    )
    dependencies = external_dependency_descriptors()
    run_preflight_command([str(BUZZ_CLI), "--version"])
    run_preflight_command([str(SYSTEMCTL), "--version"])
    run_preflight_command([str(PYTHON), "--version"])
    secret_metadata = validate_private_file_metadata(Path(manifest["live_files"]["secrets"]))
    desktop = preflight_desktop_artifact(manifest)
    unit_states = preflight_unit_states(manifest)
    return {
        "status": "pass",
        "raw_secrets": False,
        "dependencies": dependencies,
        "secret_metadata": secret_metadata,
        "desktop": desktop,
        "membership_sweep": membership_sweep,
        "unit_states": unit_states,
    }


def digest_bytes(data: bytes, length: int = 16) -> str:
    return hashlib.sha256(data).hexdigest()[:length]


def descriptor(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise MigrationError(f"refusing symlink: {path}")
    if not path.exists():
        return {"present": False}
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode):
        raise MigrationError(f"not a regular file: {path}")
    raw = path.read_bytes()
    return {
        "present": True,
        "owner_uid": metadata.st_uid,
        "owner_gid": metadata.st_gid,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "nlink": metadata.st_nlink,
        "inode": metadata.st_ino,
        "size": len(raw),
        "sha256_16": digest_bytes(raw),
    }


def atomic_write(path: Path, data: bytes, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if mode is not None:
            os.chmod(name, mode)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def parse_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.removeprefix("export ").strip()] = value.strip().strip("\"").strip("'")
    return values


def validate_nip_oa_conditions(conditions: str) -> None:
    if not isinstance(conditions, str):
        raise MigrationError("Hermes auth conditions must be a string")
    if conditions == "":
        return
    if any(character.isspace() for character in conditions):
        raise MigrationError("Hermes auth conditions contain whitespace")
    for clause in conditions.split("&"):
        kind = re.fullmatch(r"kind=(0|[1-9][0-9]*)", clause)
        created = re.fullmatch(r"created_at[<>](0|[1-9][0-9]*)", clause)
        if kind:
            if int(kind.group(1)) > 65535:
                raise MigrationError("Hermes auth kind condition is out of range")
        elif created:
            if int(created.group(1)) > 4294967295:
                raise MigrationError("Hermes auth created_at condition is out of range")
        else:
            raise MigrationError("Hermes auth conditions are not canonical NIP-OA")


def validate_hermes_secret_assignments(raw: bytes, manifest: dict[str, Any]) -> None:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise MigrationError("secrets file is not UTF-8") from error
    variables = manifest["hermes_retirement"]["secret_variables"]
    found: dict[str, list[str]] = {name: [] for name in variables}
    assignment = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*?)\s*$")
    for line in lines:
        match = assignment.fullmatch(line)
        if match and match.group(1) in found:
            found[match.group(1)].append(match.group(2).strip())
    if any(len(values) != 1 for values in found.values()):
        raise MigrationError("Hermes secret variables must each occur exactly once")

    def unquote(value: str) -> str:
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            return value[1:-1]
        return value

    private_key = unquote(found[variables[0]][0])
    if not re.fullmatch(r"[0-9a-fA-F]{64}", private_key):
        raise MigrationError("Hermes private key has invalid format")
    raw_auth = unquote(found[variables[1]][0])
    try:
        auth = json.loads(raw_auth)
    except json.JSONDecodeError as error:
        raise MigrationError("Hermes auth tag has invalid JSON") from error
    if (
        not isinstance(auth, list)
        or len(auth) != 4
        or auth[0] != "auth"
        or not isinstance(auth[1], str)
        or auth[1] != manifest["owner_pubkey"]
        or not isinstance(auth[2], str)
        or not isinstance(auth[3], str)
        or not re.fullmatch(r"[0-9a-f]{128}", auth[3])
    ):
        raise MigrationError("Hermes auth tag has invalid format")
    validate_nip_oa_conditions(auth[2])


def remove_env_variables(raw: bytes, variables: list[str]) -> bytes:
    names = set(variables)
    out: list[bytes] = []
    counts = {name: 0 for name in names}
    for line in raw.splitlines(keepends=True):
        match = re.match(rb"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=", line)
        if match and match.group(1).decode() in names:
            counts[match.group(1).decode()] += 1
            continue
        out.append(line)
    if any(count != 1 for count in counts.values()):
        raise MigrationError("Hermes secret variables must each occur exactly once")
    return b"".join(out)


def patch_proxy(raw: bytes, target: dict[str, Any]) -> bytes:
    data = yaml.safe_load(raw)
    providers = data.get("openai-compatibility") if isinstance(data, dict) else None
    if not isinstance(providers, list) or len(providers) != 1:
        raise MigrationError(f"{target['slug']} proxy must contain one compatibility provider")
    provider = providers[0]
    models = provider.get("models")
    if not isinstance(models, list) or len(models) != 1:
        raise MigrationError(f"{target['slug']} proxy must expose one model")
    provider["name"] = f"openrouter-{target['alias']}"
    model = models[0]
    model["name"] = target["model"]
    model["alias"] = target["alias"]
    model["display-name"] = target["display_name"]
    payload = data.setdefault("payload", {})
    selector = [{"name": target["alias"], "protocol": "openai", "from-protocol": "claude"}]
    params = {
        "provider.data_collection": "deny",
        "provider.require_parameters": True,
        "provider.zdr": True,
    }
    if target["reasoning"]["effort"] is None:
        params["reasoning.enabled"] = True
        payload["filter"] = []
    else:
        params["reasoning.effort"] = target["reasoning"]["effort"]
        payload["filter"] = [{"models": selector, "params": ["reasoning_effort"]}]
    payload["override"] = [{"models": selector, "params": params}]
    if data.get("port") != target["port"] or data.get("host") != "127.0.0.1":
        raise MigrationError(f"{target['slug']} proxy endpoint changed")
    return yaml.safe_dump(data, sort_keys=False).encode()


def backup_paths(manifest: dict[str, Any], root: Path) -> list[Path]:
    paths = [
        rooted(root, manifest["live_files"]["launcher"]),
        rooted(root, manifest["live_files"]["desktop_launcher"]),
        rooted(root, manifest["live_files"]["desktop_entry"]),
        rooted(root, manifest["live_files"]["directory_sync"]),
        rooted(root, manifest["live_files"]["directory_sync_compat"]),
        rooted(root, manifest["live_files"]["agent_service"]),
        rooted(root, manifest["live_files"]["secrets"]),
        rooted(root, manifest["hermes_retirement"]["launcher_prompt"]),
    ]
    paths.extend(rooted(root, item["path"]) for item in manifest["fleet_prompts"])
    for target in manifest["targets"]:
        if target.get("proxy_config"):
            paths.append(rooted(root, target["proxy_config"]))
    return paths


def make_backup(manifest: dict[str, Any], root: Path, receipt_dir: Path) -> dict[str, Any]:
    if receipt_dir.exists():
        raise MigrationError("receipt directory already exists")
    receipt_dir.mkdir(parents=True, mode=0o700)
    os.chmod(receipt_dir, 0o700)
    backups = receipt_dir / "files"
    backups.mkdir(mode=0o700)
    inventory: dict[str, Any] = {}
    for index, path in enumerate(backup_paths(manifest, root)):
        desc = descriptor(path)
        if desc["present"] and (desc["nlink"] != 1 or desc["owner_uid"] != os.getuid()):
            raise MigrationError(f"unsafe owner or link count: {path}")
        inventory[str(path)] = desc
        if desc["present"]:
            destination = backups / f"{index:02d}.bak"
            shutil.copyfile(path, destination)
            os.chmod(destination, 0o600)
            with destination.open("rb") as handle:
                os.fsync(handle.fileno())
            desc["backup"] = destination.name
    receipt = {
        "schema_version": 1,
        "status": "backup_complete",
        "manifest_sha256": hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest(),
        "root": str(root),
        "files": inventory,
        "operations": [],
    }
    atomic_write(receipt_dir / "receipt.json", json.dumps(receipt, indent=2, sort_keys=True).encode() + b"\n", 0o600)
    return receipt


def service_state(unit: str) -> dict[str, str]:
    state = {}
    for verb in ("is-enabled", "is-active"):
        try:
            result = subprocess.run(
                [str(SYSTEMCTL), "--user", verb, unit],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
                text=True,
            )
        except OSError as error:
            raise MigrationError("systemctl state preflight could not execute") from error
        state[verb] = result.stdout.strip() or f"exit-{result.returncode}"
    return state


def managed_units(manifest: dict[str, Any]) -> list[str]:
    units = retained_runtime_units(manifest)
    hermes = manifest["hermes_retirement"]
    units.extend([hermes["agent_unit"], hermes["reaper_timer"]])
    units.append(manifest["standing_sweep_service"])
    units.append(manifest["standing_sweep_timer"])
    return units


def retained_runtime_units(manifest: dict[str, Any]) -> list[str]:
    proxies = [target["proxy_unit"] for target in manifest["targets"] if target.get("proxy_unit")]
    agents = [f"buzz-sats-agent@{slug}.service" for slug in manifest["retained_agents"]]
    return proxies + agents


def validate_unit_state(manifest: dict[str, Any], unit: str, state: Any) -> None:
    if not isinstance(state, dict) or set(state) != {"is-enabled", "is-active"}:
        raise MigrationError(f"invalid prior service state for {unit}")
    allowed_enablement = (
        SUPPORTED_ENABLEMENT | {"static"}
        if unit == manifest["standing_sweep_service"]
        else SUPPORTED_ENABLEMENT
    )
    if state["is-enabled"] not in allowed_enablement:
        raise MigrationError(f"unsupported prior enablement state for {unit}")
    if state["is-active"] not in SUPPORTED_ACTIVITY:
        raise MigrationError(f"unsupported prior activity state for {unit}")


def validate_unit_states(manifest: dict[str, Any], states: dict[str, dict[str, str]]) -> None:
    expected_units = set(managed_units(manifest))
    if set(states) != expected_units:
        raise MigrationError("service-state inventory changed")
    for unit in managed_units(manifest):
        validate_unit_state(manifest, unit, states.get(unit))


def preflight_unit_states(manifest: dict[str, Any]) -> dict[str, dict[str, str]]:
    sweep = set(sweep_units(manifest))
    states = {
        unit: service_state(unit)
        for unit in managed_units(manifest)
        if unit not in sweep
    }
    for unit, state in states.items():
        validate_unit_state(manifest, unit, state)
    last_error: MigrationError | None = None
    for attempt in range(20):
        states.update({unit: service_state(unit) for unit in sweep_units(manifest)})
        try:
            for unit in sweep_units(manifest):
                validate_unit_state(manifest, unit, states[unit])
        except MigrationError as error:
            last_error = error
            if attempt == 19:
                raise MigrationError(
                    f"membership-sweep units did not reach a stable supported state: {error}"
                ) from error
            time.sleep(0.1)
            continue
        validate_unit_states(manifest, states)
        return states
    raise AssertionError(f"unreachable membership-sweep preflight state: {last_error}")


class Executor:
    def __init__(self, manifest: dict[str, Any], secrets: dict[str, str], dry_run: bool):
        self.manifest = manifest
        self.secrets = secrets
        self.dry_run = dry_run
        self.operations: list[list[str]] = []

    def command(
        self,
        argv: list[str],
        identity: dict[str, Any] | None = None,
        allowed_returncodes: tuple[int, ...] = (0,),
    ) -> bytes:
        self.operations.append(argv)
        if self.dry_run:
            return b"{}"
        env = os.environ.copy()
        if identity:
            env["BUZZ_PRIVATE_KEY"] = self.secrets[identity["private_key_var"]]
            auth_tag_var = identity.get("auth_tag_var")
            env["BUZZ_AUTH_TAG"] = self.secrets.get(auth_tag_var, "") if auth_tag_var else ""
            env["BUZZ_RELAY_URL"] = self.manifest["relay_url"]
        try:
            result = subprocess.run(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
        except OSError as error:
            raise MigrationError(f"command could not execute: {argv[0]}") from error
        if result.returncode not in allowed_returncodes:
            raise MigrationError(f"command failed without exposing output: {argv[0]} {argv[1]}")
        return result.stdout


def profile_field_snapshot(profile: dict[str, Any], field: str) -> dict[str, Any]:
    if field not in profile:
        return {"present": False}
    value = profile[field]
    if not isinstance(value, str):
        raise MigrationError(f"kind-0 {field} must be a string when present")
    return {"present": True, "value": value}


def validate_kind0_snapshots(manifest: dict[str, Any], snapshots: dict[str, Any]) -> None:
    if set(snapshots) != {target["slug"] for target in manifest["targets"]}:
        raise MigrationError("kind-0 snapshot inventory changed")
    for target in manifest["targets"]:
        snapshot = snapshots[target["slug"]]
        if not isinstance(snapshot, dict) or set(snapshot) != {"name", "display_name"}:
            raise MigrationError(f"invalid kind-0 snapshot for {target['slug']}")
        for field in ("name", "display_name"):
            state = snapshot[field]
            if not isinstance(state, dict) or set(state) not in ({"present"}, {"present", "value"}):
                raise MigrationError(f"invalid kind-0 {field} snapshot for {target['slug']}")
            if state.get("present") is True:
                if set(state) != {"present", "value"} or not isinstance(state["value"], str):
                    raise MigrationError(f"invalid present kind-0 {field} snapshot for {target['slug']}")
            elif state != {"present": False}:
                raise MigrationError(f"invalid absent kind-0 {field} snapshot for {target['slug']}")


def snapshot_kind0_names(manifest: dict[str, Any], executor: Executor) -> dict[str, Any]:
    snapshots: dict[str, Any] = {}
    for target in manifest["targets"]:
        raw = executor.command(
            [str(BUZZ_CLI), "--format", "json", "users", "get", "--pubkey", target["pubkey"]],
            target,
        )
        try:
            profiles = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise MigrationError(f"kind-0 snapshot is invalid JSON for {target['slug']}") from error
        matches = [
            profile for profile in profiles
            if isinstance(profile, dict) and profile.get("pubkey") == target["pubkey"]
        ] if isinstance(profiles, list) else []
        if len(matches) != 1:
            raise MigrationError(f"kind-0 snapshot cardinality failed for {target['slug']}")
        profile = matches[0]
        snapshots[target["slug"]] = {
            "name": profile_field_snapshot(profile, "name"),
            "display_name": profile_field_snapshot(profile, "display_name"),
        }
    validate_kind0_snapshots(manifest, snapshots)
    return snapshots


def parse_channel_members(raw: bytes) -> dict[str, str]:
    """Parse the exact `buzz channels members` JSON contract.

    The CLI currently degrades malformed relay responses to an empty JSON
    array. A real channel always has at least its owner, so accepting `[]`
    would turn transport/parser failure into a false absence readback.
    """
    try:
        members = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MigrationError("channel membership readback is invalid JSON") from error
    if not isinstance(members, list):
        raise MigrationError("channel membership readback is not an array")
    if not members:
        raise MigrationError("channel membership readback is empty or degraded")
    roles: dict[str, str] = {}
    for member in members:
        if not isinstance(member, dict) or set(member) != {"pubkey", "role"}:
            raise MigrationError("channel membership readback has invalid object keys")
        pubkey = member["pubkey"]
        role = member["role"]
        if not isinstance(pubkey, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", pubkey):
            raise MigrationError("channel membership readback has invalid pubkey")
        if not isinstance(role, str) or role not in SUPPORTED_CHANNEL_ROLES:
            raise MigrationError("channel membership readback has invalid role")
        normalized = pubkey.lower()
        if normalized in roles:
            raise MigrationError("channel membership readback has duplicate pubkey")
        roles[normalized] = role
    return roles


def require_member_role(
    roles: dict[str, str],
    pubkey: str,
    expected_role: str | None,
    *,
    channel: str,
) -> None:
    actual = roles.get(pubkey.lower())
    if actual != expected_role:
        expected = "absent" if expected_role is None else expected_role
        observed = "absent" if actual is None else actual
        raise MigrationError(
            f"channel membership readback mismatch for {channel}: expected {expected}, observed {observed}"
        )


def wait_for_member_role(
    executor: Executor,
    owner_identity: dict[str, Any],
    channel: str,
    pubkey: str,
    expected_role: str | None,
    *,
    attempts: int = 20,
    delay: float = 0.1,
) -> None:
    last_error: MigrationError | None = None
    for attempt in range(attempts):
        payload = executor.command(
            [str(BUZZ_CLI), "channels", "members", "--channel", channel],
            owner_identity,
        )
        if executor.dry_run:
            return
        try:
            require_member_role(
                parse_channel_members(payload), pubkey, expected_role, channel=channel,
            )
            return
        except MigrationError as error:
            last_error = error
        if attempt != attempts - 1:
            time.sleep(delay)
    raise MigrationError(f"bounded membership readback did not converge for {channel}") from last_error


def snapshot_hermes_memberships(manifest: dict[str, Any], executor: Executor) -> dict[str, str]:
    hermes = manifest["hermes_retirement"]
    owner_identity = {"private_key_var": manifest["owner_private_key_var"]}
    snapshot: dict[str, str] = {}
    for channel in hermes["memberships"]:
        roles = parse_channel_members(executor.command(
            [str(BUZZ_CLI), "channels", "members", "--channel", channel],
            owner_identity,
        ))
        role = roles.get(hermes["pubkey"].lower())
        snapshot[channel] = role or "absent"
    return snapshot


def preflight_restore_memberships(manifest: dict[str, Any], executor: Executor) -> dict[str, str]:
    hermes = manifest["hermes_retirement"]
    owner_identity = {"private_key_var": manifest["owner_private_key_var"]}
    snapshot: dict[str, str] = {}
    for channel in hermes["memberships"]:
        roles = parse_channel_members(executor.command(
            [str(BUZZ_CLI), "channels", "members", "--channel", channel],
            owner_identity,
        ))
        role = roles.get(hermes["pubkey"].lower())
        snapshot[channel] = role or "absent"
    return snapshot


def validate_membership_snapshot(manifest: dict[str, Any], snapshot: Any) -> dict[str, str]:
    channels = set(manifest["hermes_retirement"]["memberships"])
    if (
        not isinstance(snapshot, dict)
        or set(snapshot) != channels
        or any(role not in SUPPORTED_CHANNEL_ROLES | {"absent"} for role in snapshot.values())
    ):
        raise MigrationError("Hermes membership snapshot is incomplete or invalid")
    return snapshot


def membership_role_counts(snapshot: dict[str, str]) -> dict[str, int]:
    return {
        role: sum(value == role for value in snapshot.values())
        for role in sorted(set(snapshot.values()))
    }


def transaction_checkpoint(_name: str) -> None:
    """Fault-injection seam used by deterministic transaction tests."""


def sweep_units(manifest: dict[str, Any]) -> list[str]:
    return [manifest["standing_sweep_timer"], manifest["standing_sweep_service"]]


def stop_and_wait_sweep(
    manifest: dict[str, Any],
    executor: Executor,
    prior_states: dict[str, dict[str, str]],
) -> None:
    units = sweep_units(manifest)
    executor.command([str(SYSTEMCTL), "--user", "stop", *units])
    if executor.dry_run:
        return
    last: dict[str, dict[str, str]] = {}
    for attempt in range(20):
        last = {unit: read_unit_state(executor, unit) for unit in units}
        enablement_unchanged = all(
            last[unit]["is-enabled"] == prior_states[unit]["is-enabled"] for unit in units
        )
        if enablement_unchanged and all(last[unit]["is-active"] == "inactive" for unit in units):
            return
        if attempt != 19:
            time.sleep(0.1)
    raise MigrationError("standing sweep timer or service did not stop cleanly")


def write_files(manifest: dict[str, Any], root: Path) -> None:
    create_owned_directory_chain(root, manifest["install_root"])
    create_owned_directory_chain(root, manifest["config_root"])
    launcher_source = PAYLOADS / "launch_buzz_agent.sh"
    atomic_write(rooted(root, manifest["live_files"]["launcher"]), launcher_source.read_bytes(), 0o755)
    desktop_launcher_source = PAYLOADS / "launch_buzz_desktop.sh"
    atomic_write(
        rooted(root, manifest["live_files"]["desktop_launcher"]),
        desktop_launcher_source.read_bytes(),
        0o700,
    )
    desktop_entry_source = PAYLOADS / "buzz.desktop"
    atomic_write(
        rooted(root, manifest["live_files"]["desktop_entry"]),
        desktop_entry_source.read_bytes(),
        0o644,
    )
    for prompt in manifest["fleet_prompts"]:
        source = PAYLOADS / "prompts" / prompt["name"]
        atomic_write(rooted(root, prompt["path"]), source.read_bytes(), 0o600)
    for target in manifest["targets"]:
        if target.get("proxy_config"):
            destination = rooted(root, target["proxy_config"])
            atomic_write(destination, patch_proxy(destination.read_bytes(), target), 0o600)
    directory_source = BUNDLE / "payloads" / "buzz-sats-directory-sync.py"
    atomic_write(rooted(root, manifest["live_files"]["directory_sync"]), directory_source.read_bytes(), 0o755)
    compatibility_source = BUNDLE / "payloads" / "buzz-sats-directory-sync-wrapper.py"
    atomic_write(rooted(root, manifest["live_files"]["directory_sync_compat"]), compatibility_source.read_bytes(), 0o755)
    service_source = PAYLOADS / "buzz-sats-agent@.service"
    atomic_write(rooted(root, manifest["live_files"]["agent_service"]), service_source.read_bytes(), 0o644)
    secrets_path = rooted(root, manifest["live_files"]["secrets"])
    redacted = remove_env_variables(secrets_path.read_bytes(), manifest["hermes_retirement"]["secret_variables"])
    atomic_write(secrets_path, redacted, 0o600)
    hermes_prompt = rooted(root, manifest["hermes_retirement"]["launcher_prompt"])
    if hermes_prompt.exists():
        hermes_prompt.unlink()


def execute_apply(
    manifest: dict[str, Any],
    executor: Executor,
    root: Path,
    prior_states: dict[str, dict[str, str]] | None = None,
    prior_memberships: dict[str, str] | None = None,
) -> None:
    hermes = manifest["hermes_retirement"]
    systemctl = [str(SYSTEMCTL), "--user"]
    hermes_identity = {
        "private_key_var": hermes["secret_variables"][0],
        "auth_tag_var": hermes["secret_variables"][1],
    }
    owner_identity = {"private_key_var": manifest["owner_private_key_var"]}
    if prior_states is None:
        if not executor.dry_run:
            raise MigrationError("live apply requires preflighted service states")
        prior_states = {
            unit: {"is-enabled": "enabled", "is-active": "active"}
            for unit in managed_units(manifest)
        }
    validate_unit_states(manifest, prior_states)
    if not executor.dry_run:
        if (
            not isinstance(prior_memberships, dict)
            or set(prior_memberships) != set(hermes["memberships"])
            or any(role not in SUPPORTED_CHANNEL_ROLES | {"absent"} for role in prior_memberships.values())
        ):
            raise MigrationError("live apply requires exact preflighted Hermes memberships")
    stop_and_wait_sweep(manifest, executor, prior_states)
    transaction_checkpoint("sweep_stopped")
    executor.command(systemctl + ["disable", "--now", hermes["agent_unit"], hermes["reaper_timer"]])
    if not executor.dry_run:
        for unit in (hermes["agent_unit"], hermes["reaper_timer"]):
            if read_unit_state(executor, unit) != {"is-enabled": "disabled", "is-active": "inactive"}:
                raise MigrationError(f"retired unit did not stop cleanly: {unit}")
    transaction_checkpoint("hermes_units_stopped")
    executor.command([str(BUZZ_CLI), "agents", "archive", hermes["pubkey"], "--reason", "retired"], hermes_identity)
    archived = executor.command([str(BUZZ_CLI), "agents", "archived"], hermes_identity)
    if not executor.dry_run and hermes["pubkey"].encode() not in archived:
        raise MigrationError("Hermes archive readback failed")
    transaction_checkpoint("hermes_archived")
    for channel in hermes["memberships"]:
        before = executor.command(
            [str(BUZZ_CLI), "channels", "members", "--channel", channel], owner_identity,
        )
        if executor.dry_run:
            executor.command([str(BUZZ_CLI), "channels", "leave", "--channel", channel], hermes_identity)
        else:
            expected_role = None if prior_memberships[channel] == "absent" else prior_memberships[channel]
            require_member_role(
                parse_channel_members(before), hermes["pubkey"], expected_role, channel=channel,
            )
            if expected_role is not None:
                executor.command([str(BUZZ_CLI), "channels", "leave", "--channel", channel], hermes_identity)
        wait_for_member_role(
            executor, owner_identity, channel, hermes["pubkey"], None,
        )
    transaction_checkpoint("memberships_left")
    write_files(manifest, root)
    transaction_checkpoint("files_written")
    if root != Path("/"):
        return
    installed_publisher = rooted(root, manifest["live_files"]["directory_sync"])
    if not executor.dry_run:
        installed_descriptor = dependency_descriptor(
            installed_publisher,
            owner_uid=os.getuid(),
            executable=True,
        )
        if installed_descriptor["sha256"] != hashlib.sha256((PAYLOADS / "buzz-sats-directory-sync.py").read_bytes()).hexdigest():
            raise MigrationError("installed directory publisher digest mismatch")
    executor.command(systemctl + ["daemon-reload"])
    transaction_checkpoint("services_reloaded")
    for unit in retained_runtime_units(manifest):
        restart_retained_unit(executor, unit, prior_states[unit])
    transaction_checkpoint("retained_units_restarted")
    sync_env = os.environ.copy()
    sync_env.update(executor.secrets)
    sync_env.pop(hermes["secret_variables"][0], None)
    sync_env.pop(hermes["secret_variables"][1], None)
    args = [str(PYTHON), str(installed_publisher), "--sync-kind0"]
    for target in manifest["targets"]:
        args.extend(["--prefix", target["private_key_var"].removeprefix("BUZZ_").removesuffix("_PRIVATE_KEY")])
    executor.operations.append(args)
    if not executor.dry_run:
        try:
            result = subprocess.run(args, env=sync_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError as error:
            raise MigrationError("directory publisher could not execute") from error
        if result.returncode:
            raise MigrationError("directory publication failed without exposing output")
    transaction_checkpoint("profiles_published")
    for unit in (manifest["standing_sweep_service"], manifest["standing_sweep_timer"]):
        reconcile_unit(executor, unit, prior_states[unit])
    transaction_checkpoint("sweep_reconciled")


def restore_backed_up_files(receipt: dict[str, Any], receipt_dir: Path) -> None:
    for path_text, desc in receipt["files"].items():
        path = Path(path_text)
        if desc["present"]:
            backup = receipt_dir / "files" / desc["backup"]
            atomic_write(path, backup.read_bytes(), int(desc["mode"], 8))
        elif path.exists():
            path.unlink()


def recover_failed_apply(
    manifest: dict[str, Any],
    receipt: dict[str, Any],
    receipt_dir: Path,
    execute_external: bool,
    secrets: dict[str, str],
) -> None:
    prior_states = receipt.get("pre_service_state")
    pre_kind0_names = receipt.get("pre_kind0_names")
    recovery_executor = Executor(manifest, secrets, dry_run=False) if execute_external else None
    try:
        if recovery_executor is not None:
            validate_unit_states(manifest, prior_states)
            validate_kind0_snapshots(manifest, pre_kind0_names)
            stop_and_wait_sweep(manifest, recovery_executor, prior_states)
        restore_backed_up_files(receipt, receipt_dir)
        if recovery_executor is not None:
            secrets_path = rooted(Path(receipt["root"]), manifest["live_files"]["secrets"])
            validate_hermes_secret_assignments(secrets_path.read_bytes(), manifest)
            execute_restore_external(
                manifest,
                recovery_executor,
                prior_states,
                pre_kind0_names,
                validate_membership_snapshot(manifest, receipt.get("pre_memberships")),
            )
            receipt["relay_memberships"] = {
                "status": "restored", "count": len(manifest["hermes_retirement"]["memberships"]),
                "roles": membership_role_counts(receipt["pre_memberships"]),
                "source": "live_post_readback",
            }
    finally:
        if recovery_executor is not None:
            receipt["recovery_operations"] = recovery_executor.operations


def apply(
    root: Path,
    receipt_dir: Path,
    execute_external: bool,
    activation_manifest_path: Path | None = None,
    activation_manifest_sha256: str | None = None,
) -> Path:
    root = root.resolve()
    receipt_dir = receipt_dir.resolve()
    validate_execution_mode(root, execute_external, "apply")
    manifest = load_manifest()
    preflight_install_roots(manifest, root)
    public_preflight_state = (
        preflight_public_host(manifest, activation_manifest_path, activation_manifest_sha256)
        if execute_external
        else None
    )
    fixture_sweep_state = (
        None
        if execute_external
        else validate_membership_sweep_dependency(
            manifest, root, activation_manifest_path, activation_manifest_sha256,
        )
    )
    secrets_path = rooted(root, manifest["live_files"]["secrets"])
    secrets_raw = secrets_path.read_bytes()
    validate_hermes_secret_assignments(secrets_raw, manifest)
    secrets = parse_env(secrets_path)
    required = set(manifest["hermes_retirement"]["secret_variables"])
    if execute_external:
        required.add(manifest["owner_private_key_var"])
    required.update(item["private_key_var"] for item in manifest["targets"])
    required.update(item["auth_tag_var"] for item in manifest["targets"])
    if not required.issubset(secrets):
        raise MigrationError("required identity variables are missing")
    dependency_state = None
    prior_states = None
    pre_kind0_names = None
    pre_memberships = None
    preflight_operations: list[list[str]] = []
    if execute_external:
        dependency_state = preflight_external_dependencies(secrets[manifest["owner_private_key_var"]])
        prior_states = public_preflight_state["unit_states"]
        preflight_executor = Executor(manifest, secrets, dry_run=False)
        pre_kind0_names = snapshot_kind0_names(manifest, preflight_executor)
        pre_memberships = snapshot_hermes_memberships(manifest, preflight_executor)
        preflight_operations = preflight_executor.operations
    receipt = make_backup(manifest, root, receipt_dir)
    if prior_states is not None:
        receipt["pre_service_state"] = prior_states
        receipt["pre_kind0_names"] = pre_kind0_names
        receipt["pre_memberships"] = pre_memberships
        receipt["dependency_state"] = dependency_state
        receipt["public_preflight_state"] = public_preflight_state
        receipt["preflight_operations"] = preflight_operations
    elif fixture_sweep_state is not None:
        receipt["public_preflight_state"] = {"membership_sweep": fixture_sweep_state}
    atomic_write(receipt_dir / "receipt.json", json.dumps(receipt, indent=2, sort_keys=True).encode() + b"\n", 0o600)
    executor = Executor(manifest, secrets, dry_run=not execute_external)
    try:
        execute_apply(manifest, executor, root, prior_states, pre_memberships)
    except Exception as error:
        receipt["status"] = "apply_recovery_in_progress"
        receipt["apply_error_type"] = type(error).__name__
        receipt["operations"] = executor.operations
        atomic_write(receipt_dir / "receipt.json", json.dumps(receipt, indent=2, sort_keys=True).encode() + b"\n", 0o600)
        try:
            recover_failed_apply(manifest, receipt, receipt_dir, execute_external, secrets)
        except Exception as recovery_error:
            receipt["status"] = "apply_failed_partial"
            receipt["relay_memberships"] = {
                "status": "pending", "reason": "automatic_recovery_incomplete",
            }
            receipt["recovery_error_type"] = type(recovery_error).__name__
            if "recovery_operations" not in receipt and execute_external:
                receipt["recovery_operations"] = []
            atomic_write(receipt_dir / "receipt.json", json.dumps(receipt, indent=2, sort_keys=True).encode() + b"\n", 0o600)
            raise MigrationError("apply failed and automatic recovery was partial") from recovery_error
        receipt["status"] = "apply_failed_rolled_back"
        atomic_write(receipt_dir / "receipt.json", json.dumps(receipt, indent=2, sort_keys=True).encode() + b"\n", 0o600)
        raise MigrationError("apply failed and automatic recovery completed") from error
    receipt["status"] = "complete"
    receipt["relay_memberships"] = (
        {
            "status": "removed", "count": len(manifest["hermes_retirement"]["memberships"]),
            "pre_roles": membership_role_counts(pre_memberships),
            "source": "live_post_readback",
        }
        if execute_external
        else {"status": "not_checked", "pending": "live_post_readback"}
    )
    receipt["operations"] = executor.operations
    receipt["rollback_commands"] = [
        "python3",
        str(BUNDLE / "rollback.py"),
        "--receipt-dir",
        str(receipt_dir),
    ]
    if execute_external:
        receipt["rollback_commands"].append("--execute-external")
    receipt["post_files"] = {str(path): descriptor(path) for path in backup_paths(manifest, root)}
    atomic_write(receipt_dir / "receipt.json", json.dumps(receipt, indent=2, sort_keys=True).encode() + b"\n", 0o600)
    return receipt_dir / "receipt.json"


def verify(
    root: Path,
    activation_manifest_path: Path | None = None,
    activation_manifest_sha256: str | None = None,
) -> dict[str, Any]:
    manifest = load_manifest()
    errors: list[str] = []
    membership_sweep_state = validate_membership_sweep_dependency(
        manifest, root, activation_manifest_path, activation_manifest_sha256,
    )
    launcher_path = rooted(root, manifest["live_files"]["launcher"])
    launcher = launcher_path.read_text()
    if launcher_path.read_bytes() != (PAYLOADS / "launch_buzz_agent.sh").read_bytes():
        errors.append("installed launcher differs from reviewed payload")
    if "/home/victor/projects" in launcher:
        errors.append("launcher retains a source-checkout runtime dependency")
    desktop_launcher_path = rooted(root, manifest["live_files"]["desktop_launcher"])
    desktop_launcher = desktop_launcher_path.read_text()
    if desktop_launcher_path.read_bytes() != (PAYLOADS / "launch_buzz_desktop.sh").read_bytes():
        errors.append("installed desktop launcher differs from reviewed payload")
    desktop_entry_path = rooted(root, manifest["live_files"]["desktop_entry"])
    desktop_entry = desktop_entry_path.read_text()
    if desktop_entry_path.read_bytes() != (PAYLOADS / "buzz.desktop").read_bytes():
        errors.append("installed desktop entry differs from reviewed payload")
    if (
        "/home/victor/projects" in desktop_launcher + desktop_entry
        or "0.5.8" in desktop_launcher + desktop_entry
        or manifest["desktop"]["appimage"] not in desktop_launcher
        or manifest["live_files"]["desktop_launcher"] not in desktop_entry
    ):
        errors.append("desktop still depends on Simplelift or the 0.5.8 artifact")
    service_path = rooted(root, manifest["live_files"]["agent_service"])
    if service_path.read_bytes() != (PAYLOADS / "buzz-sats-agent@.service").read_bytes():
        errors.append("installed agent service differs from reviewed payload")
    directory_path = rooted(root, manifest["live_files"]["directory_sync"])
    if directory_path.read_bytes() != (PAYLOADS / "buzz-sats-directory-sync.py").read_bytes():
        errors.append("installed directory publisher differs from reviewed payload")
    compatibility_path = rooted(root, manifest["live_files"]["directory_sync_compat"])
    if compatibility_path.read_bytes() != (PAYLOADS / "buzz-sats-directory-sync-wrapper.py").read_bytes():
        errors.append("installed directory compatibility entry point differs from reviewed payload")
    for path, mode in (
        (launcher_path, 0o755),
        (desktop_launcher_path, 0o700),
        (desktop_entry_path, 0o644),
        (directory_path, 0o755),
        (compatibility_path, 0o755),
        (service_path, 0o644),
    ):
        desc = descriptor(path)
        if not desc["present"] or desc["owner_uid"] != os.getuid() or desc["nlink"] != 1 or desc["mode"] != f"{mode:04o}":
            errors.append(f"unsafe installed file metadata: {path}")
    expected_launcher = {
        "sats-dsv4f": ("qwen38-flash", "1000000", "Knots"),
        "sats-glm": ("glm53-flash-max", "1048576", "Segwit"),
        "sats-glm52": ("glm53-flash-max", "1048576", "Ledger"),
        "sats-codex-2": ("gpt-5.6-sol", "high", "UTXO"),
    }
    for slug, needles in expected_launcher.items():
        if f"{slug})" not in launcher or any(needle not in launcher for needle in needles):
            errors.append(f"launcher mismatch for {slug}")
    if "sats-hermes)" in launcher or "BUZZ_SATS_HERMES_" in launcher:
        errors.append("Hermes remains in launcher")
    secrets = parse_env(rooted(root, manifest["live_files"]["secrets"]))
    if any(name in secrets for name in manifest["hermes_retirement"]["secret_variables"]):
        errors.append("Hermes secret variables remain")
    for item in manifest["fleet_prompts"]:
        prompt = rooted(root, item["path"])
        desc = descriptor(prompt)
        if (
            not desc["present"]
            or desc["owner_uid"] != os.getuid()
            or desc["nlink"] != 1
            or desc["mode"] != "0600"
            or hashlib.sha256(prompt.read_bytes()).hexdigest() != item["sha256"]
            or item["path"] not in launcher
            or f"system_prompt_sha256={item['sha256']}" not in launcher
        ):
            errors.append(f"fleet prompt install mismatch for {item['name']}")
    for target in manifest["targets"]:
        prompt = rooted(root, target["prompt"])
        if not prompt.exists() or target["display_name"] not in prompt.read_text():
            errors.append(f"prompt mismatch for {target['slug']}")
        else:
            block_match = re.search(
                rf"(?ms)^  {re.escape(target['slug'])}\)\n(?P<body>.*?)^    ;;$",
                launcher,
            )
            expected_hash = hashlib.sha256(prompt.read_bytes()).hexdigest()
            if not block_match or f"system_prompt_sha256={expected_hash}" not in block_match.group("body"):
                errors.append(f"launcher prompt digest mismatch for {target['slug']}")
        if target.get("proxy_config"):
            data = yaml.safe_load(rooted(root, target["proxy_config"]).read_bytes())
            model = data["openai-compatibility"][0]["models"][0]
            if model.get("name") != target["model"] or model.get("alias") != target["alias"]:
                errors.append(f"proxy model mismatch for {target['slug']}")
            params = data["payload"]["override"][0]["params"]
            if target["reasoning"]["effort"] is None:
                if params.get("reasoning.enabled") is not True or "reasoning.effort" in params or data["payload"].get("filter"):
                    errors.append("Knots reasoning contract mismatch")
            elif params.get("reasoning.effort") != "max":
                errors.append(f"mandatory max reasoning absent for {target['slug']}")
            if data.get("port") != target["port"]:
                errors.append(f"port changed for {target['slug']}")
    if rooted(root, manifest["hermes_retirement"]["launcher_prompt"]).exists():
        errors.append("Hermes prompt remains")
    directory = rooted(root, manifest["live_files"]["directory_sync"]).read_text()
    if '"HERMES":' in directory or '"DSV4F": ("qwen", "Knots"' not in directory:
        errors.append("directory publisher roster mismatch")
    if errors:
        raise MigrationError("; ".join(errors))
    return {
        "status": "pass",
        "targets": [item["slug"] for item in manifest["targets"]],
        "relay_memberships": {
            "status": "not_checked",
            "pending": "live_post_readback",
            "expected_count": len(manifest["hermes_retirement"]["memberships"]),
        },
        "membership_sweep_dependency": membership_sweep_state,
        "secrets_reported": False,
    }


def validate_restore_state(manifest: dict[str, Any], receipt: dict[str, Any]) -> dict[str, dict[str, str]]:
    states = receipt.get("pre_service_state")
    if not isinstance(states, dict):
        raise MigrationError("live rollback receipt has no prior service state")
    validate_unit_states(manifest, states)
    tool_dir = Path("/home/victor/.agents/tools")
    tool = tool_dir / "nostr_min.py"
    if (
        not tool_dir.is_dir()
        or tool_dir.is_symlink()
        or tool_dir.stat().st_uid != os.getuid()
        or not tool.is_file()
        or tool.is_symlink()
        or tool.stat().st_uid != os.getuid()
    ):
        raise MigrationError("installed nostr_min dependency is missing or unsafe")
    return states


def read_unit_state(executor: Executor, unit: str) -> dict[str, str]:
    return {
        "is-enabled": executor.command(
            [str(SYSTEMCTL), "--user", "is-enabled", unit],
            allowed_returncodes=(0, 1, 3, 4),
        ).decode().strip(),
        "is-active": executor.command(
            [str(SYSTEMCTL), "--user", "is-active", unit],
            allowed_returncodes=(0, 1, 3, 4),
        ).decode().strip(),
    }


def reconcile_unit(executor: Executor, unit: str, prior: dict[str, str]) -> None:
    enabled = prior["is-enabled"]
    active = prior["is-active"]
    if enabled != "static":
        executor.command([str(SYSTEMCTL), "--user", "enable" if enabled == "enabled" else "disable", unit])
    executor.command([str(SYSTEMCTL), "--user", "restart" if active == "active" else "stop", unit])
    if executor.dry_run:
        return
    actual = read_unit_state(executor, unit)
    if actual != prior:
        raise MigrationError(f"service-state readback mismatch for {unit}")


def restart_retained_unit(executor: Executor, unit: str, prior: dict[str, str]) -> None:
    executor.command([
        str(SYSTEMCTL), "--user",
        "restart" if prior["is-active"] == "active" else "stop",
        unit,
    ])
    if executor.dry_run:
        return
    if read_unit_state(executor, unit) != prior:
        raise MigrationError(f"retained service-state readback mismatch for {unit}")


def run_directory_rollback(
    manifest: dict[str, Any],
    executor: Executor,
    pre_kind0_names: dict[str, Any],
) -> None:
    validate_kind0_snapshots(manifest, pre_kind0_names)
    args = [
        str(PYTHON),
        str(BUNDLE / "payloads" / "buzz-sats-directory-sync.py"),
        "--previous-names",
        "--restore-kind0-stdin",
    ]
    restore_by_prefix: dict[str, Any] = {}
    for target in manifest["targets"]:
        prefix = target["private_key_var"].removeprefix("BUZZ_").removesuffix("_PRIVATE_KEY")
        args.extend(["--prefix", prefix])
        restore_by_prefix[prefix] = pre_kind0_names[target["slug"]]
    executor.operations.append(args)
    env = os.environ.copy()
    env.update(executor.secrets)
    try:
        result = subprocess.run(
            args,
            input=json.dumps(restore_by_prefix, sort_keys=True).encode(),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError as error:
        raise MigrationError("directory rollback publisher could not execute") from error
    if result.returncode:
        raise MigrationError(f"directory rollback publisher exited {result.returncode}")


def execute_restore_external(
    manifest: dict[str, Any],
    executor: Executor,
    prior_states: dict[str, dict[str, str]],
    pre_kind0_names: dict[str, Any],
    prior_memberships: dict[str, str] | None = None,
    directory_runner=None,
) -> None:
    hermes = manifest["hermes_retirement"]
    identity = {"private_key_var": hermes["secret_variables"][0], "auth_tag_var": hermes["secret_variables"][1]}
    owner_identity = {"private_key_var": manifest["owner_private_key_var"]}
    if prior_memberships is None and executor.dry_run:
        prior_memberships = {channel: "member" for channel in hermes["memberships"]}
    prior_memberships = validate_membership_snapshot(manifest, prior_memberships)
    executor.command([str(SYSTEMCTL), "--user", "daemon-reload"])
    archived = executor.command([str(BUZZ_CLI), "agents", "archived"], identity)
    if executor.dry_run or hermes["pubkey"].encode() in archived:
        executor.command([str(BUZZ_CLI), "agents", "unarchive", hermes["pubkey"]], identity)
    archived = executor.command([str(BUZZ_CLI), "agents", "archived"], identity)
    if not executor.dry_run and hermes["pubkey"].encode() in archived:
        raise MigrationError("Hermes unarchive readback failed")
    for channel in hermes["memberships"]:
        members_raw = executor.command(
            [str(BUZZ_CLI), "channels", "members", "--channel", channel],
            owner_identity,
        )
        desired_role = prior_memberships[channel]
        current_role = None if executor.dry_run else parse_channel_members(members_raw).get(hermes["pubkey"].lower())
        if desired_role == "absent":
            if executor.dry_run or current_role is not None:
                executor.command(
                    [
                        str(BUZZ_CLI), "channels", "remove-member", "--channel", channel,
                        "--pubkey", hermes["pubkey"],
                    ],
                    owner_identity,
                )
            expected_role = None
        else:
            if executor.dry_run or current_role != desired_role:
                executor.command(
                    [
                        str(BUZZ_CLI), "channels", "add-member", "--channel", channel,
                        "--pubkey", hermes["pubkey"], "--role", desired_role,
                    ],
                    owner_identity,
                )
            expected_role = desired_role
        wait_for_member_role(
            executor, owner_identity, channel, hermes["pubkey"], expected_role,
        )
    (directory_runner or run_directory_rollback)(manifest, executor, pre_kind0_names)
    for unit in managed_units(manifest):
        if unit in sweep_units(manifest):
            continue
        reconcile_unit(executor, unit, prior_states[unit])
    for unit in (manifest["standing_sweep_service"], manifest["standing_sweep_timer"]):
        reconcile_unit(executor, unit, prior_states[unit])


def restore(receipt_dir: Path, execute_external: bool) -> None:
    receipt_path = receipt_dir / "receipt.json"
    receipt = json.loads(receipt_path.read_text())
    manifest = load_manifest()
    if receipt.get("manifest_sha256") != hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest():
        raise MigrationError("receipt belongs to another manifest")
    root_text = receipt.get("root")
    if not isinstance(root_text, str) or not root_text.startswith("/") or os.path.normpath(root_text) != root_text:
        raise MigrationError("rollback receipt has an invalid root")
    receipt_root = Path(root_text).resolve()
    validate_execution_mode(receipt_root, execute_external, "rollback")
    preflight_install_roots(manifest, receipt_root)
    sweep_state = receipt.get("public_preflight_state", {}).get("membership_sweep", {})
    activation_descriptor = sweep_state.get("activation_manifest", {})
    activation_path = activation_descriptor.get("path")
    activation_sha256 = activation_descriptor.get("sha256")
    if not isinstance(activation_path, str) or not isinstance(activation_sha256, str):
        raise MigrationError("rollback receipt has no activation-manifest binding")
    validate_membership_sweep_dependency(
        manifest, receipt_root, Path(activation_path), activation_sha256,
    )
    prior_states = None
    pre_kind0_names = None
    current_secrets: dict[str, str] = {}
    if execute_external:
        prior_states = validate_restore_state(manifest, receipt)
        pre_kind0_names = receipt.get("pre_kind0_names")
        validate_kind0_snapshots(manifest, pre_kind0_names)
        pre_memberships = validate_membership_snapshot(manifest, receipt.get("pre_memberships"))
        current_secrets = parse_env(Path(manifest["live_files"]["secrets"]))
        owner_var = manifest["owner_private_key_var"]
        if owner_var not in current_secrets:
            raise MigrationError("owner identity is missing before rollback")
        receipt["rollback_dependency_state"] = preflight_external_dependencies(current_secrets[owner_var])
        restore_preflight_executor = Executor(manifest, current_secrets, dry_run=False)
        receipt["rollback_pre_memberships"] = preflight_restore_memberships(
            manifest, restore_preflight_executor,
        )
        receipt["rollback_preflight_operations"] = restore_preflight_executor.operations
    receipt["status"] = "rollback_in_progress"
    receipt["relay_memberships"] = {"status": "pending", "reason": "rollback_in_progress"}
    receipt["rollback_operations"] = []
    atomic_write(receipt_path, json.dumps(receipt, indent=2, sort_keys=True).encode() + b"\n", 0o600)
    executor = Executor(manifest, current_secrets, dry_run=False) if execute_external else None
    try:
        if executor is not None:
            stop_and_wait_sweep(manifest, executor, prior_states)
        restore_backed_up_files(receipt, receipt_dir)
        if execute_external:
            secrets_path = Path(manifest["live_files"]["secrets"])
            validate_hermes_secret_assignments(secrets_path.read_bytes(), manifest)
            executor.secrets = parse_env(secrets_path)
            if manifest["owner_private_key_var"] not in executor.secrets:
                raise MigrationError("owner identity is missing after byte restoration")
            execute_restore_external(
                manifest, executor, prior_states, pre_kind0_names, pre_memberships,
            )
            receipt["rollback_operations"] = executor.operations
    except Exception as error:
        receipt["status"] = "rollback_failed"
        receipt["relay_memberships"] = {"status": "pending", "reason": "rollback_incomplete"}
        receipt["rollback_error_type"] = type(error).__name__
        if executor is not None:
            receipt["rollback_operations"] = executor.operations
        atomic_write(receipt_path, json.dumps(receipt, indent=2, sort_keys=True).encode() + b"\n", 0o600)
        raise
    receipt["status"] = "rolled_back"
    receipt["relay_memberships"] = (
        {
            "status": "restored", "count": len(manifest["hermes_retirement"]["memberships"]),
            "roles": membership_role_counts(pre_memberships),
            "source": "live_post_readback",
        }
        if execute_external
        else {"status": "not_checked", "pending": "live_post_readback"}
    )
    atomic_write(receipt_path, json.dumps(receipt, indent=2, sort_keys=True).encode() + b"\n", 0o600)

#!/usr/bin/env python3
"""Generate a credential-free Mempool and Genesis activation package."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[2]
TEMPLATE_DIR = SCRIPT_DIR / "templates"
INPUT_SCHEMA = "buzz-mempool-genesis-activation-input-v1"
BUNDLE_SCHEMA = "buzz-mempool-genesis-activation-bundle-v3"
REVIEW_FILES_SCHEMA = "buzz-agent-review-files-v1"
TIER2_EVIDENCE_SCHEMA = "tier2-evidence-v2"
TIER2_ENGINE_PATH = Path("/home/victor/.agents/skills/codex-review/scripts/tier2")
TIER2_ENGINE_MODE = 0o750
TIER2_REVIEW = {
    "producer_provider": "gpt",
    "reviewer_provider": "claude",
    "model": "claude-opus-5",
    "effort": "high",
    "engine_subcommands": ["prepare", "review", "check"],
}
TIER2_CANDIDATE_PATHS = ("bundle-manifest.json", "metadata/review-files.json")
BUNDLE_ID = "mempool-genesis-activation-20260825"
RUNTIME_TARGET_COUNT = 22
REVIEW_PATH_COUNT = 19
CODEX_CLI_PATH = "/usr/local/libexec/buzz/codex"
CODEX_ACP_PATH = "/usr/local/libexec/buzz/codex-acp"
NODE_PATH = "/usr/local/libexec/buzz/node"
ENV_NODE_SHEBANG = b"#!/usr/bin/env node\n"
PINNED_NODE_SHEBANG = f"#!{NODE_PATH}\n".encode()
CURRENT_REVIEW_POLICY = (
    "Any required Tier 2 review follows the current opposite-provider runbook in "
    "Agent-Shared/adapters/sats-shared-common.md § Verification and review. For GPT- "
    "or local-produced work, use one independent Claude Opus 5 reviewer at high reasoning. "
    "For Claude- or parent-produced work, use one independent GPT-5.6 Sol reviewer at high "
    "reasoning. Fable 5 is not a review or escalation route. Reviewer identity must differ "
    "from producer identity. Sol `xhigh` is allowed only on explicit Victor or Rachel "
    "instruction. Luna is producer-only and never a reviewer."
)
OWNER_PUBKEY = "4a34c131ec5cb5dd9a200bac619bbd103c0793e068fad278d1de59203d05b97d"
ASSIGNER_PUBKEYS = (
    OWNER_PUBKEY,
    "7806a7beb69ba4fd3b6e9b86d56931a446b62666e9794533f87fb2d1b956684f",
    "73c705675d848ad38a919a5fa07687f55b4f0863c21969941c216b44f9e7a812",
    "aefa6783cdf2f33f9aa3705b41e5ae3ec214318c64db48f1410fc77db015f2ec",
    "db965b1f484ec4ebd3b0041091e890e2cd28e64732d9be53fd07ba640255af61",
)
ALLOWLIST = ",".join(ASSIGNER_PUBKEYS)
HEX64 = re.compile(r"^[0-9a-f]{64}$")
PLACEHOLDERS = {
    "mempool": "DESKTOP_SAVE_REQUIRED_MEMPOOL_PUBKEY",
    "genesis": "DESKTOP_SAVE_REQUIRED_GENESIS_PUBKEY",
}


@dataclass(frozen=True)
class TargetSpec:
    target: str
    source: str
    mode: int
    uid: int = 0
    gid: int = 0
    source_kind: str = "system"


COMMON_TARGETS = (
    TargetSpec(
        "/etc/systemd/system/buzz-agent@.service",
        "scripts/mempool-genesis/buzz-agent@.service",
        0o644,
        source_kind="repo",
    ),
    TargetSpec(
        "/etc/systemd/system/buzz-agent@mempool.service.d/ci-migration.conf",
        "scripts/mempool-genesis/activation/templates/systemd/"
        "buzz-agent@mempool.service.d/ci-migration.conf",
        0o644,
        source_kind="repo",
    ),
    TargetSpec(
        "/etc/systemd/system/buzz-agent@genesis.service.d/capability-parity.conf",
        "scripts/mempool-genesis/activation/templates/systemd/"
        "buzz-agent@genesis.service.d/capability-parity.conf",
        0o644,
        source_kind="repo",
    ),
    TargetSpec(
        "/usr/local/libexec/buzz/run-buzz-agent",
        "/usr/local/libexec/buzz/run-buzz-agent",
        0o755,
    ),
    TargetSpec(
        "/usr/local/libexec/buzz/verify-installed-agent",
        "scripts/mempool-genesis/verify-installed-agent",
        0o755,
        source_kind="repo",
    ),
    TargetSpec(
        "/usr/local/libexec/buzz/buzz-agent-key-handoff",
        "/usr/local/libexec/buzz/buzz-agent-key-handoff",
        0o755,
    ),
    TargetSpec(
        "/usr/local/libexec/buzz/export-managed-agent-key",
        "/usr/local/libexec/buzz/export-managed-agent-key",
        0o755,
    ),
    TargetSpec(
        "/usr/local/sbin/buzz-install-agent-key",
        "/usr/local/sbin/buzz-install-agent-key",
        0o755,
    ),
    TargetSpec(
        "/etc/sudoers.d/buzz-agent-key-handoff",
        "scripts/mempool-genesis/buzz-agent-key-handoff.sudoers",
        0o440,
        source_kind="repo",
    ),
    TargetSpec(
        "/usr/local/sbin/install-enrollment-map",
        "scripts/mempool-genesis/install-enrollment-map",
        0o755,
        source_kind="repo",
    ),
    TargetSpec(NODE_PATH, NODE_PATH, 0o755),
    TargetSpec(CODEX_CLI_PATH, CODEX_CLI_PATH, 0o755),
    TargetSpec(
        CODEX_ACP_PATH,
        CODEX_ACP_PATH,
        0o755,
    ),
    TargetSpec(
        "/usr/local/libexec/buzz/codex-code-mode-host",
        "/usr/local/libexec/buzz/codex-code-mode-host",
        0o755,
    ),
    TargetSpec(
        "/usr/local/libexec/buzz/buzz-acp",
        "/usr/local/libexec/buzz/buzz-acp",
        0o755,
    ),
    TargetSpec(
        "/usr/local/libexec/buzz/buzz-dev-mcp",
        "/usr/local/libexec/buzz/buzz-dev-mcp",
        0o755,
    ),
    TargetSpec(
        "/usr/lib/systemd/system/service.d/10-timeout-abort.conf",
        "/usr/lib/systemd/system/service.d/10-timeout-abort.conf",
        0o644,
    ),
)

EXPECTED_PATHS = {
    slug: (
        f"/etc/buzz-agents/{slug}.env",
        f"/etc/buzz-agents/prompts/{slug}.md",
        "/etc/systemd/system/buzz-agent@.service",
        (
            "/etc/systemd/system/buzz-agent@mempool.service.d/ci-migration.conf"
            if slug == "mempool"
            else "/etc/systemd/system/buzz-agent@genesis.service.d/capability-parity.conf"
        ),
        "/usr/local/libexec/buzz/run-buzz-agent",
        "/usr/local/libexec/buzz/verify-installed-agent",
        "/usr/local/libexec/buzz/buzz-agent-key-handoff",
        "/usr/local/libexec/buzz/export-managed-agent-key",
        "/usr/local/sbin/buzz-install-agent-key",
        "/etc/buzz-agents/enrollment-keys.json",
        "/etc/sudoers.d/buzz-agent-key-handoff",
        "/usr/local/sbin/install-enrollment-map",
        "/usr/local/libexec/buzz/node",
        "/usr/local/libexec/buzz/codex",
        "/usr/local/libexec/buzz/codex-acp",
        "/usr/local/libexec/buzz/codex-code-mode-host",
        "/usr/local/libexec/buzz/buzz-acp",
        "/usr/local/libexec/buzz/buzz-dev-mcp",
        "/usr/lib/systemd/system/service.d/10-timeout-abort.conf",
    )
    for slug in ("mempool", "genesis")
}


def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    digest = hashlib.sha256()
    try:
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def require_regular(
    path: Path,
    expected_mode: int | None = None,
    *,
    owner_uid: int | None = None,
) -> os.stat_result:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError(f"unsafe source file: {path}")
    if expected_mode is not None and stat.S_IMODE(metadata.st_mode) != expected_mode:
        raise ValueError(f"source mode mismatch: {path}")
    if owner_uid is not None and metadata.st_uid != owner_uid:
        raise ValueError(f"source owner mismatch: {path}")
    return metadata


def make_private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ValueError(f"unsafe private directory: {path}")


def write_bytes(path: Path, payload: bytes, mode: int) -> None:
    make_private_directory(path.parent)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        mode,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write while generating activation package")
            view = view[written:]
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def copy_file(source: Path, destination: Path, mode: int) -> None:
    require_regular(source)
    make_private_directory(destination.parent)
    source_descriptor = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    destination_descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        mode,
    )
    try:
        while chunk := os.read(source_descriptor, 1024 * 1024):
            view = memoryview(chunk)
            while view:
                written = os.write(destination_descriptor, view)
                if written <= 0:
                    raise OSError("short write while copying activation source")
                view = view[written:]
        os.fchmod(destination_descriptor, mode)
        os.fsync(destination_descriptor)
    finally:
        os.close(destination_descriptor)
        os.close(source_descriptor)


def rooted(root: Path, absolute: str) -> Path:
    return root / absolute.lstrip("/")


def load_inputs(path: Path, allow_placeholders: bool) -> tuple[dict[str, str], bool]:
    require_regular(path, 0o600, owner_uid=os.getuid())
    value = json.loads(path.read_bytes(), object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "mempool_pubkey",
        "genesis_pubkey",
    }:
        raise ValueError("activation input has the wrong fields")
    if value["schema"] != INPUT_SCHEMA:
        raise ValueError("activation input schema mismatch")
    result: dict[str, str] = {}
    complete = True
    for slug in ("mempool", "genesis"):
        raw_key = value[f"{slug}_pubkey"]
        if not isinstance(raw_key, str):
            raise ValueError(f"{slug} public key must be a string")
        if raw_key == PLACEHOLDERS[slug]:
            complete = False
            if not allow_placeholders:
                raise ValueError(f"{slug} public key still requires Desktop save")
        elif not HEX64.fullmatch(raw_key):
            raise ValueError(f"{slug} public key must be 64 lowercase hex characters")
        result[slug] = raw_key
    if complete:
        if result["mempool"] == result["genesis"]:
            raise ValueError("Mempool and Genesis public keys must differ")
        if result["mempool"] in ASSIGNER_PUBKEYS or result["genesis"] in ASSIGNER_PUBKEYS:
            raise ValueError("new agent public keys must not reuse an assignment-roster identity")
    return result, complete


def validate_env(payload: bytes, slug: str) -> None:
    values: dict[str, str] = {}
    for line in payload.decode().splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in values:
            raise ValueError(f"invalid or duplicate env line for {slug}: {line}")
        values[key] = value
    required = {
        "BUZZ_ACP_AGENT_COMMAND": CODEX_ACP_PATH,
        "BUZZ_ACP_MCP_COMMAND": "/usr/local/libexec/buzz/buzz-dev-mcp",
        "BUZZ_ACP_RESPOND_TO": "allowlist",
        "BUZZ_ACP_RESPOND_TO_ALLOWLIST": ALLOWLIST,
        "BUZZ_ACP_ALLOWED_RESPOND_TO": "allowlist",
        "BUZZ_ACP_AGENT_OWNER": OWNER_PUBKEY,
        "BUZZ_RELAY_URL": "wss://framework-desktop.tail69757d.ts.net:38443",
        "CODEX_PATH": CODEX_CLI_PATH,
    }
    for key, expected in required.items():
        if values.get(key) != expected:
            raise ValueError(f"{slug} env has wrong {key}")
    if "PATH" in values:
        raise ValueError(f"{slug} env must not override the reviewed service PATH")


def render_prompt(path: Path, slug: str) -> bytes:
    text = path.read_text()
    if text.count(CURRENT_REVIEW_POLICY) != 1:
        raise ValueError(f"{slug} prompt does not contain exactly one current review-policy block")
    return text.encode()


def validate_prompt(payload: bytes, slug: str) -> None:
    text = payload.decode()
    required = (
        "Victor remains your sole cryptographic owner.",
        "Victor, Rachel, Sats Codex, Sats Codex-2, and Archimedes Codex may assign you bounded work.",
        "Victor or Rachel may approve gated actions with equal authority.",
        "Rachel's or Archimedes Codex's assignment authority never widens that scope",
        "Your identity and memory scope are Sats/Victor only.",
        "inside the private Buzz community on framework-desktop.",
        CURRENT_REVIEW_POLICY,
    )
    for sentence in required:
        if sentence not in text:
            raise ValueError(f"{slug} prompt misses required authority text: {sentence}")
    for retired in ("reviewer at explicit `xhigh`", "opposite-provider review, and double-model review are retired"):
        if retired in text:
            raise ValueError(f"{slug} prompt retains retired review policy: {retired}")


def artifact_fingerprint(records: list[dict[str, object]]) -> str:
    payload = "".join(
        f"A\t{record['sha256']}\t{record['mode']}\t{record['target']}\n"
        for record in sorted(records, key=lambda record: str(record["target"]).encode())
    ).encode()
    return sha256_bytes(payload)


def source_path(spec: TargetSpec, system_root: Path, repo_root: Path) -> Path:
    return rooted(system_root, spec.source) if spec.source_kind == "system" else repo_root / spec.source


def source_inventory(repo_root: Path) -> list[dict[str, str]]:
    paths = (
        SCRIPT_DIR / "README.md",
        SCRIPT_DIR / "generate-activation-bundle.py",
        SCRIPT_DIR / "install-activation-bundle.py",
        SCRIPT_DIR / "make-tier1-receipt.py",
        SCRIPT_DIR / "tier2-evidence-verifier.py",
        SCRIPT_DIR / "input.template.json",
        SCRIPT_DIR / "tests/test_activation.py",
        TEMPLATE_DIR / "mempool.env",
        TEMPLATE_DIR / "genesis.env",
        TEMPLATE_DIR / "mempool.md",
        TEMPLATE_DIR / "genesis.md",
        TEMPLATE_DIR / "buzz-sats-channel-sweep.sh",
        TEMPLATE_DIR / "systemd/buzz-agent@mempool.service.d/ci-migration.conf",
        TEMPLATE_DIR / "systemd/buzz-agent@genesis.service.d/capability-parity.conf",
        repo_root / "scripts/mempool-genesis/buzz-agent@.service",
        repo_root / "scripts/mempool-genesis/verify-installed-agent",
        repo_root / "scripts/mempool-genesis/buzz-agent-key-handoff.sudoers",
        repo_root / "scripts/mempool-genesis/install-enrollment-map",
    )
    records: list[dict[str, str]] = []
    for path in paths:
        metadata = require_regular(path)
        records.append(
            {
                "path": str(path.relative_to(repo_root)),
                "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
                "sha256": sha256_file(path),
            }
        )
    return sorted(records, key=lambda record: record["path"].encode())


def tier2_engine_record(path: Path) -> dict[str, str]:
    resolved = path.resolve(strict=True)
    metadata = require_regular(resolved, TIER2_ENGINE_MODE, owner_uid=os.getuid())
    return {
        "path": str(resolved),
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "sha256": sha256_file(resolved),
    }


def git_value(repo_root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=repo_root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C"},
    ).stdout.strip()


def add_target(
    stage: Path,
    records: list[dict[str, object]],
    target: str,
    payload: bytes,
    mode: int,
    uid: int = 0,
    gid: int = 0,
) -> None:
    relative = Path("install-root") / target.lstrip("/")
    write_bytes(stage / relative, payload, mode)
    records.append(
        {
            "target": target,
            "source": str(relative),
            "mode": f"{mode:04o}",
            "uid": uid,
            "gid": gid,
            "sha256": sha256_bytes(payload),
        }
    )


def render_codex_acp(source: Path) -> bytes:
    require_regular(source)
    descriptor = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    payload = b"".join(chunks)
    if payload.startswith(ENV_NODE_SHEBANG):
        return PINNED_NODE_SHEBANG + payload[len(ENV_NODE_SHEBANG) :]
    if payload.startswith(PINNED_NODE_SHEBANG):
        return payload
    raise ValueError("codex-acp source does not use the reviewed Node interpreter contract")


def replace_output(temporary: Path, output: Path, replace: bool) -> None:
    if output.exists() or output.is_symlink():
        if not replace:
            raise ValueError("output path already exists")
        if output.is_symlink() or not output.is_dir():
            raise ValueError("refusing to replace unsafe output path")
        previous = output.with_name(f".{output.name}.previous.{os.getpid()}")
        if previous.exists() or previous.is_symlink():
            raise ValueError("stale replacement path exists")
        os.rename(output, previous)
        try:
            os.rename(temporary, output)
        except Exception:
            os.rename(previous, output)
            raise
        shutil.rmtree(previous)
    else:
        os.rename(temporary, output)
    descriptor = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def generate(
    inputs_path: Path,
    output: Path,
    system_root: Path,
    repo_root: Path,
    allow_placeholders: bool,
    replace: bool,
) -> dict[str, object]:
    pubkeys, complete = load_inputs(inputs_path, allow_placeholders)
    engine_record = tier2_engine_record(TIER2_ENGINE_PATH)
    output_parent = output.parent.resolve(strict=True)
    parent_metadata = output_parent.lstat()
    if not stat.S_ISDIR(parent_metadata.st_mode) or stat.S_IMODE(parent_metadata.st_mode) & 0o077:
        raise ValueError("package parent must be an owner-only directory")
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.build.", dir=output_parent))
    temporary.chmod(0o700)
    try:
        records: list[dict[str, object]] = []
        for slug in ("mempool", "genesis"):
            env_payload = (TEMPLATE_DIR / f"{slug}.env").read_bytes()
            prompt_payload = render_prompt(TEMPLATE_DIR / f"{slug}.md", slug)
            validate_env(env_payload, slug)
            validate_prompt(prompt_payload, slug)
            add_target(temporary, records, f"/etc/buzz-agents/{slug}.env", env_payload, 0o600)
            add_target(
                temporary,
                records,
                f"/etc/buzz-agents/prompts/{slug}.md",
                prompt_payload,
                0o644,
            )
        for spec in COMMON_TARGETS:
            source = source_path(spec, system_root, repo_root)
            if spec.target == CODEX_ACP_PATH:
                add_target(
                    temporary,
                    records,
                    spec.target,
                    render_codex_acp(source),
                    spec.mode,
                    spec.uid,
                    spec.gid,
                )
                continue
            destination = temporary / "install-root" / spec.target.lstrip("/")
            copy_file(source, destination, spec.mode)
            records.append(
                {
                    "target": spec.target,
                    "source": str(Path("install-root") / spec.target.lstrip("/")),
                    "mode": f"{spec.mode:04o}",
                    "uid": spec.uid,
                    "gid": spec.gid,
                    "sha256": sha256_file(destination),
                }
            )
        enrollment = {
            "schema": "buzz-agent-enrollment-keys-v1",
            "keys": {"mempool": pubkeys["mempool"], "genesis": pubkeys["genesis"]},
        }
        add_target(
            temporary,
            records,
            "/etc/buzz-agents/enrollment-keys.json",
            canonical_json(enrollment),
            0o600,
        )
        by_target = {str(record["target"]): record for record in records}
        if len(by_target) != RUNTIME_TARGET_COUNT or len(records) != RUNTIME_TARGET_COUNT:
            raise ValueError(
                f"activation runtime target set must contain {RUNTIME_TARGET_COUNT} unique paths"
            )
        review_files = {
            slug: [
                {"path": path, "sha256": str(by_target[path]["sha256"])}
                for path in EXPECTED_PATHS[slug]
            ]
            for slug in ("mempool", "genesis")
        }
        if any(len(files) != REVIEW_PATH_COUNT for files in review_files.values()):
            raise ValueError(
                f"each installed review closure must contain exactly {REVIEW_PATH_COUNT} paths"
            )

        sweep_template = (TEMPLATE_DIR / "buzz-sats-channel-sweep.sh").read_text()
        sweep_payload = (
            sweep_template.replace("__MEMPOOL_PUBLIC_KEY__", pubkeys["mempool"])
            .replace("__GENESIS_PUBLIC_KEY__", pubkeys["genesis"])
            .encode()
        )
        if b"__MEMPOOL_PUBLIC_KEY__" in sweep_payload or b"__GENESIS_PUBLIC_KEY__" in sweep_payload:
            raise ValueError("sweep public-key substitution failed")
        sweep_relative = Path("ops-root/home/victor/.agents/tools/buzz-sats-channel-sweep.sh")
        write_bytes(temporary / sweep_relative, sweep_payload, 0o700)
        ops_record = {
            "target": "/home/victor/.agents/tools/buzz-sats-channel-sweep.sh",
            "source": str(sweep_relative),
            "mode": "0700",
            "uid": 1000,
            "gid": 1000,
            "sha256": sha256_bytes(sweep_payload),
            "scope": "Victor-owner-authenticated all-open-channel fixed public-key roster",
        }

        sources = source_inventory(repo_root)
        runtime_fingerprint = artifact_fingerprint(records)
        digest_input = {
            "schema": BUNDLE_SCHEMA,
            "bundle_id": BUNDLE_ID,
            "inputs": pubkeys,
            "input_status": "complete" if complete else "desktop-save-required",
            "runtime_targets": sorted(records, key=lambda record: str(record["target"]).encode()),
            "ops_targets": [ops_record],
            "review_files": review_files,
            "expected_closure_paths": {slug: list(paths) for slug, paths in EXPECTED_PATHS.items()},
            "generator_sources": sources,
            "tier2_review": TIER2_REVIEW,
            "tier2_engine": engine_record,
            "tier2_evidence_schema": TIER2_EVIDENCE_SCHEMA,
            "tier2_candidate_paths": list(TIER2_CANDIDATE_PATHS),
        }
        package_digest = sha256_bytes(canonical_json(digest_input))

        review_record = {
            "schema": REVIEW_FILES_SCHEMA,
            "status": "pending-tier2-v2" if complete else "blocked-on-desktop-pubkeys",
            "runtime_artifact_fingerprint": runtime_fingerprint,
            "package_digest": package_digest,
            "files": review_files,
        }
        review_payload = canonical_json(review_record)
        review_relative = Path("metadata/review-files.json")
        write_bytes(temporary / review_relative, review_payload, 0o600)

        manifest = {
            "schema": BUNDLE_SCHEMA,
            "bundle_id": BUNDLE_ID,
            "source_commit": git_value(repo_root, "rev-parse", "HEAD"),
            "source_branch": git_value(repo_root, "branch", "--show-current"),
            "generator_sources": sources,
            "inputs": pubkeys,
            "input_status": "complete" if complete else "desktop-save-required",
            "ready_for_parent_tier1": complete,
            "installable": False,
            "runtime_artifact_fingerprint": runtime_fingerprint,
            "package_digest": package_digest,
            "runtime_targets": sorted(records, key=lambda record: str(record["target"]).encode()),
            "ops_targets": [ops_record],
            "review_files": review_files,
            "expected_closure_paths": {slug: list(paths) for slug, paths in EXPECTED_PATHS.items()},
            "review_files_record": {
                "path": str(review_relative),
                "sha256": sha256_bytes(review_payload),
            },
            "tier2_review": TIER2_REVIEW,
            "tier2_engine": engine_record,
            "tier2_evidence_schema": TIER2_EVIDENCE_SCHEMA,
            "tier2_candidate_paths": list(TIER2_CANDIDATE_PATHS),
        }
        manifest_payload = canonical_json(manifest)
        write_bytes(temporary / "bundle-manifest.json", manifest_payload, 0o600)
        input_contract = {
            "schema": INPUT_SCHEMA,
            "required_after_desktop_save": {
                "mempool_pubkey": "distinct 64-character lowercase hex x-only public key",
                "genesis_pubkey": "distinct 64-character lowercase hex x-only public key",
            },
            "forbidden": [
                "private keys",
                "auth tags",
                "OAuth or provider credentials",
                "Desktop keyring files",
            ],
            "must_not_reuse_assignment_roster": list(ASSIGNER_PUBKEYS),
            "placeholder_generation_is_not_installable": True,
        }
        write_bytes(temporary / "input-contract.json", canonical_json(input_contract), 0o600)
        replace_output(temporary, output, replace)
        return manifest
    except Exception:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--system-source-root", default="/")
    parser.add_argument("--repo-root", default=str(REPO_ROOT))
    parser.add_argument("--allow-placeholders", action="store_true")
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()
    manifest = generate(
        Path(args.inputs).resolve(strict=True),
        Path(args.output).absolute(),
        Path(args.system_source_root).resolve(strict=True),
        Path(args.repo_root).resolve(strict=True),
        args.allow_placeholders,
        args.replace,
    )
    print(canonical_json(manifest).decode(), end="")


if __name__ == "__main__":
    main()

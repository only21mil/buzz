#!/usr/bin/env python3
"""Prepare and run a fail-closed clean-host activation acceptance container."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

SCHEMA = "buzz-ci-clean-host-e2e-contract/v1"
BINDING_SCHEMA = "buzz-ci-clean-host-e2e-public-binding/v1"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
PACKAGE_NAMES = ("runner", "controld", "keyholder", "execd", "activation")
KEY_NAMES = ("ci-event", "nip98", "manifest", "acceptance-actor")
REQUIRED_CANDIDATE_FILES = (
    "deploy/native-ci/runner/install.py",
    "deploy/native-ci/controld/install.py",
    "deploy/native-ci/keyholder/install.py",
    "deploy/native-ci/execd/install.py",
    "deploy/native-ci/activation/controller.py",
)
MAX_TREE_FILES = 512
MAX_INPUT_BYTES = 64 * 1024 * 1024


class HarnessError(RuntimeError):
    """Stable fail-closed harness error."""


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"


def load_json(path: Path, maximum: int = 1024 * 1024) -> object:
    raw = path.read_bytes()
    if not raw or len(raw) > maximum:
        raise HarnessError(f"invalid JSON input size: {path.name}")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as error:
        raise HarnessError(f"invalid JSON input: {path.name}") from error


def private_directory(path: Path, *, create: bool = False) -> Path:
    absolute = Path(os.path.abspath(path))
    if create:
        absolute.mkdir(mode=0o700, parents=True, exist_ok=False)
    metadata = absolute.lstat()
    if Path(os.path.realpath(absolute)) != absolute or not stat.S_ISDIR(metadata.st_mode):
        raise HarnessError("state must be a real directory")
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise HarnessError("state must be owned by the caller with mode 0700")
    return absolute


def safe_input(path_value: str, *, directory: bool) -> Path:
    path = Path(os.path.abspath(path_value))
    metadata = path.lstat()
    if Path(os.path.realpath(path)) != path:
        raise HarnessError(f"input must not contain symbolic links: {path.name}")
    if directory != stat.S_ISDIR(metadata.st_mode):
        raise HarnessError(f"input type differs: {path.name}")
    if not directory and not stat.S_ISREG(metadata.st_mode):
        raise HarnessError(f"input is not a regular file: {path.name}")
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise HarnessError(f"input is group or world writable: {path.name}")
    return path


def sha256_tree(path: Path) -> str:
    digest = hashlib.sha256()
    count = 0
    total = 0
    for item in sorted(path.rglob("*"), key=lambda value: value.relative_to(path).as_posix()):
        relative = item.relative_to(path).as_posix()
        metadata = item.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise HarnessError(f"package contains a non-regular input: {relative}")
        count += 1
        total += metadata.st_size
        if count > MAX_TREE_FILES or total > MAX_INPUT_BYTES:
            raise HarnessError("package input exceeds the harness bound")
        digest.update(relative.encode())
        digest.update(b"\0")
        digest.update(f"{stat.S_IMODE(metadata.st_mode):04o}".encode())
        digest.update(b"\0")
        digest.update(hashlib.sha256(item.read_bytes()).digest())
    return digest.hexdigest()


def input_digest(path: Path) -> str:
    return sha256_tree(path) if path.is_dir() else hashlib.sha256(path.read_bytes()).hexdigest()


def run_checked(argv: list[str], *, stdin: bytes | None = None) -> bytes:
    result = subprocess.run(
        argv,
        input=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )
    if result.returncode != 0:
        raise HarnessError(f"command failed without accepted evidence: {Path(argv[0]).name}")
    return result.stdout


def openssl_key(private_path: Path) -> str:
    pem = run_checked(["openssl", "ecparam", "-name", "secp256k1", "-genkey", "-noout"])
    private_path.write_bytes(pem)
    private_path.chmod(0o400)
    encoded_der = run_checked(["openssl", "ec", "-in", str(private_path), "-pubout", "-outform", "DER"])
    encoded = encoded_der[-65:]
    if len(encoded) != 65 or encoded[0] != 4:
        raise HarnessError("OpenSSL returned a non-secp256k1 public key")
    text = run_checked(["openssl", "ec", "-in", str(private_path), "-text", "-noout"]).decode()
    private_match = re.search(r"priv:\s*((?:[0-9a-f]{2}:?|\s)+)pub:", text, re.I)
    if private_match is None:
        raise HarnessError("OpenSSL private key output is unsupported")
    raw = bytes.fromhex("".join(re.findall(r"[0-9a-f]{2}", private_match.group(1), re.I)))
    if len(raw) != 32:
        raise HarnessError("OpenSSL returned an invalid private scalar")
    private_path.chmod(0o600)
    private_path.write_bytes(raw)
    private_path.chmod(0o400)
    return encoded[1:33].hex()


def prepare(state_arg: Path, controld_uid: int, controld_gid: int) -> dict[str, object]:
    if not 1 <= controld_uid <= 0xFFFFFFFF or not 1 <= controld_gid <= 0xFFFFFFFF:
        raise HarnessError("controld identity is invalid")
    state = private_directory(state_arg, create=True)
    private = state / "private"
    private.mkdir(mode=0o700)
    public: dict[str, str] = {}
    for name in KEY_NAMES:
        public[name] = openssl_key(private / f"{name}.key")
    ca_key = private / "ca.key"
    server_key = private / "relay.key"
    run_checked(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(ca_key)])
    run_checked(["openssl", "req", "-x509", "-new", "-key", str(ca_key), "-subj", "/CN=Buzz CI disposable E2E CA", "-days", "1", "-out", str(state / "ca.crt")])
    run_checked(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(server_key), "-subj", "/CN=relay.test.invalid", "-addext", "subjectAltName=DNS:relay.test.invalid", "-out", str(private / "relay.csr")])
    run_checked(["openssl", "x509", "-req", "-in", str(private / "relay.csr"), "-CA", str(state / "ca.crt"), "-CAkey", str(ca_key), "-CAcreateserial", "-days", "1", "-copy_extensions", "copy", "-out", str(state / "relay.crt")])
    for path in private.iterdir():
        path.chmod(0o400)
    binding = {
        "schema_version": BINDING_SCHEMA,
        "relay_url": "wss://relay.test.invalid:3443",
        "relay_http_origin": "https://relay.test.invalid:3443",
        "acceptance_actor": {"public_key": public["acceptance-actor"], "generation": 1},
        "keyholder_public_spec": {
            "schema_version": 1,
            "peer": {"uid": controld_uid, "gid": controld_gid, "allowed_operations": ["describe", "sign_ci_event", "nip98_authorize", "sign_manifest", "describe_acceptance", "sign_acceptance_mutation"]},
            "selectors": {
                "ci_event": {"public_key": public["ci-event"], "generation": 1},
                "nip98": {"public_key": public["nip98"], "generation": 1},
                "manifest": {"public_key": public["manifest"], "generation": 1},
            },
            "nip98_origin": "https://relay.test.invalid:3443",
            "acceptance": {"binding_receipt_path": "/var/lib/buzzci/activation-controller/controld-acceptance-v1.json", "credential_selector": "acceptance-actor.key"},
        },
    }
    (state / "public-binding.json").write_bytes(canonical(binding))
    (state / "public-binding.json").chmod(0o444)
    return {"status": "prepared", "state": str(state), "public_binding": str(state / "public-binding.json")}


def validate_contract(path: Path) -> tuple[dict[str, object], dict[str, Path]]:
    value = load_json(path)
    required = {"schema_version", "candidate_root", "candidate_sha", "image", "image_id", "state", "scenario", "packages"}
    if not isinstance(value, dict) or set(value) != required or value["schema_version"] != SCHEMA:
        raise HarnessError("contract shape or schema differs")
    if not isinstance(value["candidate_sha"], str) or HEX40.fullmatch(value["candidate_sha"]) is None:
        raise HarnessError("candidate SHA is invalid")
    if not isinstance(value["image"], str) or not value["image"] or not isinstance(value["image_id"], str) or IMAGE_ID.fullmatch(value["image_id"]) is None:
        raise HarnessError("container image binding is invalid")
    candidate = safe_input(str(value["candidate_root"]), directory=True)
    state = private_directory(Path(str(value["state"])))
    paths: dict[str, Path] = {"candidate": candidate, "state": state}
    packages = value["packages"]
    if not isinstance(packages, dict) or tuple(sorted(packages)) != tuple(sorted(PACKAGE_NAMES)):
        raise HarnessError("package set differs")
    for name, descriptor in [("scenario", value["scenario"]), *packages.items()]:
        if not isinstance(descriptor, dict) or set(descriptor) != {"path", "sha256"} or not isinstance(descriptor["sha256"], str) or HEX64.fullmatch(descriptor["sha256"]) is None:
            raise HarnessError(f"invalid input descriptor: {name}")
        item = safe_input(str(descriptor["path"]), directory=name != "scenario")
        if input_digest(item) != descriptor["sha256"]:
            raise HarnessError(f"input digest differs: {name}")
        paths[name] = item
    actual_sha = run_checked(["git", "-C", str(candidate), "rev-parse", "HEAD"]).decode().strip()
    if actual_sha != value["candidate_sha"]:
        raise HarnessError("candidate HEAD differs")
    if run_checked(["git", "-C", str(candidate), "status", "--porcelain"]):
        raise HarnessError("candidate worktree is not clean")
    for relative in REQUIRED_CANDIDATE_FILES:
        item = candidate / relative
        if not item.is_file():
            raise HarnessError(f"candidate prerequisite missing: {relative}")
    binding = load_json(state / "public-binding.json")
    if not isinstance(binding, dict) or binding.get("schema_version") != BINDING_SCHEMA:
        raise HarnessError("prepared public binding is missing")
    for name in KEY_NAMES:
        key = state / "private" / f"{name}.key"
        metadata = key.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o400:
            raise HarnessError("ephemeral test credential metadata differs")
    validate_package_binding(paths["keyholder"], paths["activation"], binding)
    image_id = run_checked(["docker", "image", "inspect", str(value["image"]), "--format", "{{.Id}}"]).decode().strip()
    if image_id != value["image_id"]:
        raise HarnessError("local container image ID differs")
    return value, paths


def package_asset(package: Path, manifest: dict[str, object], role: str, *, active: bool = False) -> bytes:
    entries = manifest.get("entries")
    entry = next((item for item in entries if isinstance(item, dict) and item.get("role") == role), None) if isinstance(entries, list) else None
    field = "active_source" if active else "source"
    digest_field = "active_sha256" if active else "sha256"
    if not isinstance(entry, dict) or not isinstance(entry.get(field), str) or not isinstance(entry.get(digest_field), str):
        raise HarnessError(f"package binding asset is absent: {role}")
    source = package / entry[field]
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != entry[digest_field]:
        raise HarnessError(f"package binding asset digest differs: {role}")
    return raw


def validate_package_binding(keyholder: Path, activation: Path, binding: object) -> None:
    if not isinstance(binding, dict):
        raise HarnessError("public binding shape differs")
    keyholder_manifest = load_json(keyholder / "package-manifest.json")
    activation_manifest = load_json(activation / "activation-manifest.json")
    if not isinstance(keyholder_manifest, dict) or not isinstance(activation_manifest, dict):
        raise HarnessError("package manifest shape differs")
    keyholder_config = json.loads(package_asset(keyholder, keyholder_manifest, "config"))
    if keyholder_config != binding.get("keyholder_public_spec"):
        raise HarnessError("keyholder package differs from the ephemeral public binding")
    if activation_manifest.get("acceptance_template", {}).get("actor") != binding.get("acceptance_actor"):
        raise HarnessError("activation actor differs from the ephemeral public binding")
    controld = json.loads(package_asset(activation, activation_manifest, "controld_config", active=True))
    expected_spec = binding["keyholder_public_spec"]
    if (
        controld.get("relay_url") != binding.get("relay_url")
        or controld.get("relay_http_origin") != binding.get("relay_http_origin")
        or controld.get("keyholder_selectors") != expected_spec.get("selectors")
        or (controld.get("keyholder_uid"), controld.get("keyholder_gid"))
        != (expected_spec.get("peer", {}).get("uid"), expected_spec.get("peer", {}).get("gid"))
    ):
        raise HarnessError("activation provider config differs from the hermetic relay/keyholder binding")


def docker_run(contract: dict[str, object], paths: dict[str, Path], results: Path) -> dict[str, object]:
    results = private_directory(results, create=True)
    harness_root = Path(__file__).resolve().parent
    container_name = f"buzzci-clean-e2e-{os.getpid()}-{int(time.time())}"
    mounts = [
        (paths["candidate"], "/candidate", "ro"),
        (paths["state"], "/harness-state", "rw"),
        (results, "/results", "rw"),
        (harness_root, "/harness", "ro"),
        (paths["scenario"], "/inputs/scenario.json", "ro"),
    ]
    for name in PACKAGE_NAMES:
        mounts.append((paths[name], f"/inputs/{name}", "ro"))
    inner = dict(contract)
    inner["candidate_root"] = "/candidate"
    inner["state"] = "/harness-state"
    inner["scenario"] = {"path": "/inputs/scenario.json", "sha256": contract["scenario"]["sha256"]}
    inner["packages"] = {name: {"path": f"/inputs/{name}", "sha256": contract["packages"][name]["sha256"]} for name in PACKAGE_NAMES}
    inner_path = results / "container-contract.json"
    inner_path.write_bytes(canonical(inner))
    inner_path.chmod(0o400)
    command = [
        "docker", "run", "--detach", "--name", container_name, "--privileged",
        "--security-opt", "seccomp=unconfined", "--hostname", "buzzci-e2e",
        "--add-host", "relay.test.invalid:127.0.0.1", "--stop-signal", "SIGRTMIN+3",
        "--tmpfs", "/run", "--tmpfs", "/run/lock", "--tmpfs", "/tmp:exec,mode=1777",
    ]
    for source, target, mode in mounts:
        command.extend(["--mount", f"type=bind,src={source},dst={target},{mode}"])
    command.extend([str(contract["image"]), "/sbin/init"])
    started = False
    try:
        run_checked(command)
        started = True
        deadline = time.monotonic() + 30
        while True:
            state = subprocess.run(["docker", "exec", container_name, "systemctl", "is-system-running"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.decode().strip()
            if state in {"running", "degraded"}:
                break
            if time.monotonic() >= deadline:
                raise HarnessError("container systemd did not become available")
            time.sleep(0.25)
        output = run_checked(["docker", "exec", container_name, "python3", "/harness/container_entry.py", "/results/container-contract.json"])
        result = json.loads(output)
        if result.get("status") != "pass":
            raise HarnessError("container did not return a pass result")
        return result
    finally:
        if started:
            subprocess.run(["docker", "stop", "--time", "10", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["docker", "rm", "--force", container_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    prepare_parser = sub.add_parser("prepare")
    prepare_parser.add_argument("--state", type=Path, required=True)
    prepare_parser.add_argument("--controld-uid", type=int, required=True)
    prepare_parser.add_argument("--controld-gid", type=int, required=True)
    for name in ("preflight", "run"):
        child = sub.add_parser(name)
        child.add_argument("--contract", type=Path, required=True)
        if name == "run":
            child.add_argument("--results", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        if arguments.action == "prepare":
            result = prepare(arguments.state, arguments.controld_uid, arguments.controld_gid)
        else:
            contract, paths = validate_contract(arguments.contract)
            result = {"status": "ready", "candidate_sha": contract["candidate_sha"], "image_id": contract["image_id"]}
            if arguments.action == "run":
                result = docker_run(contract, paths, arguments.results)
        sys.stdout.buffer.write(canonical(result))
        return 0
    except (OSError, ValueError, HarnessError, subprocess.SubprocessError) as error:
        sys.stderr.buffer.write(canonical({"status": "error", "error": str(error)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

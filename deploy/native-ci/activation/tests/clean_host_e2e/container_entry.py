#!/usr/bin/env python3
"""Execute the exact activation path inside a disposable systemd container."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time

UNITS = (
    "buzz-ci-capacity-one.target",
    "buzz-ci-controld.service",
    "buzz-ci-controld-acceptance.socket",
    "buzz-ci-acceptance-control.service",
    "buzz-ci-acceptance-control.socket",
    "buzz-ci-runner.service",
    "buzz-ci-runner.socket",
    "buzz-ci-execd.service",
    "buzz-ci-execd.socket",
    "buzz-ci-executor.service",
    "buzz-ci-executor.socket",
    "buzz-ci-keyholder.service",
    "buzz-ci-keyholder.socket",
)
SOCKETS = (
    "/run/buzzci/acceptance-control.sock",
    "/run/buzzci/controld-acceptance.sock",
    "/run/buzzci/runner-control.sock",
    "/run/buzzci/execd.sock",
    "/run/buzzci/executor.sock",
    "/run/buzzci/keyholder.sock",
)
KEY_NAMES = ("ci-event", "nip98", "manifest", "acceptance-actor")


class EntryError(RuntimeError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"


def command(argv: list[str], *, stdin: bytes | None = None, allow_failure: bool = False) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        argv,
        input=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )
    if result.returncode != 0 and not allow_failure:
        raise EntryError(f"in-container command failed: {Path(argv[0]).name}")
    return result


def require_tools() -> None:
    if Path("/proc/1/comm").read_text().strip() != "systemd":
        raise EntryError("PID 1 is not systemd")
    for name in ("python3", "openssl", "pgrep", "systemd-creds", "systemd-run", "systemd-sysusers", "systemd-tmpfiles", "systemctl", "update-ca-certificates"):
        if shutil.which(name) is None:
            raise EntryError(f"required container tool is absent: {name}")


def package_manifest(package: Path, name: str) -> dict[str, object]:
    candidates = {
        "activation": "activation-manifest.json",
        "runner": "package-manifest.json",
        "controld": "package-manifest.json",
        "keyholder": "package-manifest.json",
        "execd": "package-manifest.json",
    }
    path = package / candidates[name]
    if not path.is_file():
        raise EntryError(f"{name} package manifest is absent")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict) or not isinstance(value.get("entries"), list):
        raise EntryError(f"{name} package manifest shape differs")
    return value


def install_ca_and_credentials(state: Path) -> None:
    ca_target = Path("/usr/local/share/ca-certificates/buzzci-disposable-e2e.crt")
    shutil.copyfile(state / "ca.crt", ca_target)
    ca_target.chmod(0o644)
    command(["update-ca-certificates"])
    target_root = Path("/etc/credstore.encrypted/buzzci-keyholder")
    target_root.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name in KEY_NAMES:
        source = state / "private" / f"{name}.key"
        target = target_root / f"{name}.key"
        command(["systemd-creds", "encrypt", f"--name={name}.key", str(source), str(target)])
        target.chmod(0o400)
        metadata = target.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o400:
            raise EntryError("encrypted credential metadata differs")


def create_principals(activation: Path) -> None:
    manifest = package_manifest(activation, "activation")
    entry = next((item for item in manifest["entries"] if item.get("role") == "sysusers"), None)
    if not isinstance(entry, dict) or not isinstance(entry.get("source"), str):
        raise EntryError("activation sysusers asset is absent")
    source = activation / entry["source"]
    if hashlib.sha256(source.read_bytes()).hexdigest() != entry.get("sha256"):
        raise EntryError("activation sysusers asset digest differs")
    command(["systemd-sysusers", str(source)])


def install_components(candidate: Path, packages: dict[str, dict[str, str]]) -> None:
    for name in ("runner", "controld"):
        command(["python3", str(candidate / f"deploy/native-ci/{name}/install.py"), "install", "--package", packages[name]["path"]])
    command(["python3", str(candidate / "deploy/native-ci/keyholder/install.py"), "install", "--package", packages["keyholder"]["path"]])
    command(["python3", str(candidate / "deploy/native-ci/execd/install.py"), "install", "--package", packages["execd"]["path"]])
    command(["systemctl", "daemon-reload"])


def tree_state(root: Path) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    if not root.exists():
        return result
    for path in sorted(root.rglob("*")):
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise EntryError(f"non-regular config state: {path}")
        result[str(path.relative_to(root))] = {
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "mode": stat.S_IMODE(metadata.st_mode),
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
        }
    return result


def unit_state() -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for unit in UNITS:
        process = command(["systemctl", "show", unit, "--property=LoadState,ActiveState,SubState,UnitFileState,MainPID,InvocationID", "--value"], allow_failure=True)
        values = process.stdout.decode().splitlines()
        if process.returncode != 0 or len(values) != 6:
            result[unit] = {"LoadState": "not-found", "ActiveState": "inactive", "SubState": "dead", "UnitFileState": "", "MainPID": "0", "InvocationID": ""}
        else:
            result[unit] = dict(zip(("LoadState", "ActiveState", "SubState", "UnitFileState", "MainPID", "InvocationID"), values, strict=True))
    return result


def start_relay(state: Path) -> None:
    command([
        "systemd-run", "--unit=buzzci-e2e-relay.service", "--property=Type=simple",
        "/usr/bin/python3", "/harness/local_tls_relay.py",
        "--certificate", str(state / "relay.crt"), "--private-key", str(state / "private/relay.key"),
        "--object-root", "/var/lib/buzzci-e2e-relay/objects",
    ])
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        probe = command(["openssl", "s_client", "-connect", "relay.test.invalid:3443", "-servername", "relay.test.invalid", "-CAfile", str(state / "ca.crt"), "-brief"], stdin=b"", allow_failure=True)
        if probe.returncode == 0:
            return
        time.sleep(0.1)
    raise EntryError("local TLS relay did not become ready")


def dormant_proof(baseline_configs: dict[str, dict[str, object]], baseline_units: dict[str, dict[str, str]]) -> dict[str, object]:
    current_configs = tree_state(Path("/etc/buzzci"))
    if current_configs != baseline_configs:
        raise EntryError("rollback did not restore the exact dormant config tree")
    current_units = unit_state()
    for unit, state in current_units.items():
        if state["ActiveState"] != "inactive" or state["MainPID"] != "0":
            raise EntryError(f"unit remains active after rollback: {unit}")
        before = baseline_units[unit]
        if (state["LoadState"], state["UnitFileState"]) != (before["LoadState"], before["UnitFileState"]):
            raise EntryError(f"unit install/enable state differs after rollback: {unit}")
    present = [path for path in SOCKETS if Path(path).exists()]
    if present:
        raise EntryError("socket path remains after rollback")
    process = command(["pgrep", "-a", "-f", "buzz-ci-(?:runner|controld|execd|executor|keyholder|acceptance)"], allow_failure=True)
    if process.returncode == 0 and process.stdout.strip():
        raise EntryError("Buzz CI process remains after rollback")
    return {
        "configs_sha256": hashlib.sha256(canonical(current_configs)).hexdigest(),
        "units_sha256": hashlib.sha256(canonical(current_units)).hexdigest(),
        "sockets_absent": list(SOCKETS),
        "processes_absent": True,
    }


def cleanup(candidate: Path, activation_package: str, state: Path, attempted_stage: bool) -> list[str]:
    errors: list[str] = []
    if attempted_stage:
        installed = Path("/usr/libexec/buzz-ci-activation-controller")
        controller = str(installed if installed.is_file() else candidate / "deploy/native-ci/activation/controller.py")
        result = command([controller, "rollback", "--package", activation_package], allow_failure=True)
        if result.returncode != 0:
            errors.append("controller rollback failed")
    for unit in UNITS:
        command(["systemctl", "stop", unit], allow_failure=True)
    command(["systemctl", "stop", "buzzci-e2e-relay.service"], allow_failure=True)
    credential_root = Path("/etc/credstore.encrypted/buzzci-keyholder")
    for name in KEY_NAMES:
        try:
            (credential_root / f"{name}.key").unlink()
        except FileNotFoundError:
            pass
        except OSError:
            errors.append("encrypted test credential removal failed")
    try:
        credential_root.rmdir()
    except FileNotFoundError:
        pass
    except OSError:
        errors.append("encrypted credential directory removal failed")
    for name in (*KEY_NAMES, "ca", "relay"):
        try:
            (state / "private" / f"{name}.key").unlink()
        except FileNotFoundError:
            pass
        except OSError:
            errors.append("ephemeral test credential removal failed")
    for name in ("relay.csr",):
        try:
            (state / "private" / name).unlink()
        except FileNotFoundError:
            pass
        except OSError:
            errors.append("ephemeral test credential request removal failed")
    ca_target = Path("/usr/local/share/ca-certificates/buzzci-disposable-e2e.crt")
    try:
        ca_target.unlink()
        if command(["update-ca-certificates", "--fresh"], allow_failure=True).returncode != 0:
            errors.append("test CA trust removal failed")
    except FileNotFoundError:
        pass
    except OSError:
        errors.append("test CA removal failed")
    return errors


def execute(contract: dict[str, object]) -> dict[str, object]:
    require_tools()
    candidate = Path(str(contract["candidate_root"]))
    state = Path(str(contract["state"]))
    packages = contract["packages"]
    activation_package = packages["activation"]["path"]
    attempted_stage = False
    baseline_configs: dict[str, dict[str, object]] | None = None
    baseline_units: dict[str, dict[str, str]] | None = None
    receipt = Path("/results/acceptance-receipt.json")
    verifier = Path("/results/verifier.json")
    primary_error: Exception | None = None
    result: dict[str, object] | None = None
    try:
        install_ca_and_credentials(state)
        create_principals(Path(activation_package))
        install_components(candidate, packages)
        baseline_configs = tree_state(Path("/etc/buzzci"))
        baseline_units = unit_state()
        start_relay(state)
        controller = str(candidate / "deploy/native-ci/activation/controller.py")
        command(["python3", controller, "check", "--package", activation_package])
        attempted_stage = True
        command(["python3", controller, "stage", "--package", activation_package, "--scenario", contract["scenario"]["path"]])
        command(["/usr/libexec/buzz-ci-activation-controller", "activate", "--package", activation_package])
        scenario = Path(contract["scenario"]["path"]).read_bytes()
        canary = command(["/usr/libexec/buzz-ci-capacity-one-canary"], stdin=scenario)
        receipt.write_bytes(canary.stdout)
        receipt.chmod(0o400)
        verified = command(["/usr/libexec/buzz-ci-verify-acceptance-receipt", contract["scenario"]["path"], str(receipt)])
        verifier.write_bytes(verified.stdout)
        verifier.chmod(0o400)
        result = {
            "status": "pass",
            "candidate_sha": contract["candidate_sha"],
            "receipt_sha256": hashlib.sha256(canary.stdout).hexdigest(),
            "verifier_sha256": hashlib.sha256(verified.stdout).hexdigest(),
        }
    except Exception as error:
        primary_error = error
    cleanup_errors = cleanup(candidate, activation_package, state, attempted_stage)
    if baseline_configs is not None and baseline_units is not None:
        try:
            proof = dormant_proof(baseline_configs, baseline_units)
            if result is not None:
                result["dormant_proof"] = proof
        except Exception as error:
            cleanup_errors.append(str(error))
    if primary_error is not None or cleanup_errors:
        message = str(primary_error) if primary_error is not None else "cleanup proof failed"
        if cleanup_errors:
            message = f"{message}; {'; '.join(cleanup_errors)}"
        raise EntryError(message)
    if result is None:
        raise EntryError("acceptance returned no result")
    return result


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        return 2
    try:
        contract = json.loads(Path(argv[0]).read_bytes())
        result = execute(contract)
        sys.stdout.buffer.write(canonical(result))
        return 0
    except (OSError, ValueError, EntryError, subprocess.SubprocessError) as error:
        sys.stderr.buffer.write(canonical({"status": "error", "error": str(error)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

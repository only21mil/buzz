#!/usr/bin/env python3
"""Reject contradictory ownership across the five native CI package manifests."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


PACKAGE_SCHEMAS = {
    "runner": "buzz-ci-runner-install-package-v2",
    "controld": "buzz-ci-controld-install-package-v2",
    "keyholder": "buzz-ci-keyholder-acceptance-package-v2",
    "execd": "buzz-ci-execd-install-package-v1",
    "activation": "buzz-ci-capacity-one-activation-package-v2",
}
EXPLICIT_IDENTICAL_SHARES = {
    "/etc/buzzci/runner-v2.json": frozenset({"runner", "activation"}),
    "/etc/buzzci/controld-v2.json": frozenset({"controld", "activation"}),
}
REQUIRED_CATEGORIES = frozenset({
    "binary", "config", "unit", "socket", "drop_in", "tmpfiles", "sysusers", "fixture", "receipt",
})
ACTIVATION_RECEIPT = {
    "path": "/var/lib/buzzci/activation-controller/receipt-v1.json",
    "mode": "0600",
    "uid": 0,
    "gid": 0,
    "schema": "buzz-ci-capacity-one-activation-receipt-v1",
}
CONTROLD_ACCEPTANCE_TARGET = "/etc/systemd/system/buzz-ci-controld-acceptance.socket"
CONTROLD_ACCEPTANCE_SOURCE = Path(
    "deploy/native-ci/controld/templates/buzz-ci-controld-acceptance.socket"
)
CONTROLD_ACCEPTANCE_NAME = CONTROLD_ACCEPTANCE_SOURCE.name


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _category(role: str, target: str) -> str:
    if ".service.d/" in target or ".socket.d/" in target:
        return "drop_in"
    if target.endswith(".service") or target.endswith(".target"):
        return "unit"
    if target.endswith(".socket"):
        return "socket"
    if "/tmpfiles.d/" in target:
        return "tmpfiles"
    if "/sysusers.d/" in target:
        return "sysusers"
    if "fixture" in role or "fixture" in target:
        return "fixture"
    if role == "config" or role.endswith("_config"):
        return "config"
    if role == "binary" or role.endswith("_binary") or target.startswith("/usr/libexec/"):
        return "binary"
    return "other"


def _entry_claim(package: str, entry: dict[str, Any]) -> dict[str, object]:
    required = {"role", "target", "sha256", "install_mode", "uid", "gid"}
    if not required <= set(entry):
        raise ValueError(f"{package} package entry is incomplete")
    return {
        "package": package,
        "category": _category(str(entry["role"]), str(entry["target"])),
        "target": entry["target"],
        "sha256": entry["sha256"],
        "mode": entry["install_mode"],
        "uid": entry["uid"],
        "gid": entry["gid"],
    }


def check_source_inventory(source_root: Path) -> dict[str, object]:
    native_ci = source_root / "deploy/native-ci"
    matches = sorted(
        path.relative_to(source_root)
        for path in native_ci.rglob(CONTROLD_ACCEPTANCE_NAME)
    )
    if matches != [CONTROLD_ACCEPTANCE_SOURCE]:
        raise ValueError(
            "controld acceptance socket must have exactly one canonical source: "
            f"{[str(path) for path in matches]}"
        )
    canonical = source_root / CONTROLD_ACCEPTANCE_SOURCE
    if not canonical.is_file() or canonical.is_symlink():
        raise ValueError("controld acceptance socket canonical source is not a regular file")
    return {
        "controld_acceptance_source": str(CONTROLD_ACCEPTANCE_SOURCE),
        "sha256": hashlib.sha256(canonical.read_bytes()).hexdigest(),
    }


def check_inventory(
    manifests: dict[str, dict[str, Any]], *, source_root: Path | None = None,
) -> dict[str, object]:
    if set(manifests) != set(PACKAGE_SCHEMAS):
        raise ValueError("final package set must contain runner, controld, keyholder, execd, and activation")
    claims: list[dict[str, object]] = []
    entries_by_package: dict[str, dict[str, dict[str, Any]]] = {}
    for package in sorted(manifests):
        manifest = manifests[package]
        if manifest.get("schema") != PACKAGE_SCHEMAS[package]:
            raise ValueError(f"{package} package schema differs")
        entries = manifest.get("entries")
        if not isinstance(entries, list):
            raise ValueError(f"{package} package entries are absent")
        by_target: dict[str, dict[str, Any]] = {}
        for raw in entries:
            if not isinstance(raw, dict):
                raise ValueError(f"{package} package entry is invalid")
            claim = _entry_claim(package, raw)
            target = str(claim["target"])
            if target in by_target:
                raise ValueError(f"{package} package target is duplicated: {target}")
            by_target[target] = raw
            claims.append(claim)
        entries_by_package[package] = by_target

    receipt_claims = [
        {"package": "activation", "category": "receipt", "target": ACTIVATION_RECEIPT["path"],
         "sha256": None, "mode": ACTIVATION_RECEIPT["mode"], "uid": 0, "gid": 0,
         "schema": ACTIVATION_RECEIPT["schema"]},
    ]
    execd = manifests["execd"]
    for contract_name, contract in (
        ("install_receipt", execd.get("install_receipt")),
        ("seccomp_receipt", {
            "path": execd.get("seccomp_contract", {}).get("runtime_receipt")
            if isinstance(execd.get("seccomp_contract"), dict) else None,
            "mode": "0600", "uid": 0, "gid": 0,
            "schema": "buzz-ci-execd-seccomp-install-receipt-v1",
        }),
    ):
        if not isinstance(contract, dict) or not isinstance(contract.get("path"), str):
            raise ValueError(f"execd {contract_name} contract is absent")
        receipt_claims.append({
            "package": "execd", "category": "receipt", "target": contract["path"],
            "sha256": None, "mode": contract.get("mode"), "uid": contract.get("uid"),
            "gid": contract.get("gid"), "schema": contract.get("schema"),
        })
    claims.extend(receipt_claims)

    by_target: dict[str, list[dict[str, object]]] = {}
    for claim in claims:
        by_target.setdefault(str(claim["target"]), []).append(claim)
    for target, duplicates in by_target.items():
        if len(duplicates) == 1:
            continue
        packages = frozenset(str(item["package"]) for item in duplicates)
        if EXPLICIT_IDENTICAL_SHARES.get(target) != packages or len(duplicates) != len(packages):
            raise ValueError(f"undeclared final package ownership collision: {target}")
        identity = {(item["sha256"], item["mode"], item["uid"], item["gid"]) for item in duplicates}
        if len(identity) != 1:
            raise ValueError(f"divergent explicitly shared package target: {target}")
    for target, expected_packages in EXPLICIT_IDENTICAL_SHARES.items():
        observed_packages = frozenset(str(item["package"]) for item in by_target.get(target, []))
        if observed_packages != expected_packages:
            raise ValueError(f"explicitly shared package target is incomplete: {target}")

    controld_acceptance_claims = by_target.get(CONTROLD_ACCEPTANCE_TARGET, [])
    if (
        len(controld_acceptance_claims) != 1
        or controld_acceptance_claims[0]["package"] != "controld"
    ):
        raise ValueError("controld must solely own its acceptance socket package target")

    activation = manifests["activation"]
    effective = activation.get("effective_systemd")
    if not isinstance(effective, list):
        raise ValueError("activation effective systemd inventory is absent")
    effective_count = 0
    for unit in effective:
        if not isinstance(unit, dict) or not isinstance(unit.get("drop_ins"), list):
            raise ValueError("activation effective systemd entry is invalid")
        for record in (unit.get("fragment"), *unit["drop_ins"]):
            if not isinstance(record, dict):
                raise ValueError("activation effective systemd path is invalid")
            owner = record.get("owner")
            target = record.get("path")
            entry = entries_by_package.get(str(owner), {}).get(str(target))
            if not isinstance(entry, dict) or entry.get("sha256") != record.get("sha256"):
                raise ValueError(f"effective systemd owner or bytes differ: {target}")
            effective_count += 1

    ordered = sorted(claims, key=lambda item: (str(item["target"]).encode(), str(item["package"]).encode()))
    categories: dict[str, int] = {}
    for claim in ordered:
        categories[str(claim["category"])] = categories.get(str(claim["category"]), 0) + 1
    missing_categories = sorted(REQUIRED_CATEGORIES - set(categories))
    if missing_categories:
        raise ValueError(f"final package inventory categories are incomplete: {missing_categories}")
    report = {
        "status": "pass",
        "packages": sorted(manifests),
        "claims": len(ordered),
        "effective_systemd_paths": effective_count,
        "explicit_identical_shares": sorted(EXPLICIT_IDENTICAL_SHARES),
        "categories": dict(sorted(categories.items())),
        "inventory_sha256": hashlib.sha256(_canonical(ordered)).hexdigest(),
    }
    if source_root is not None:
        report["source_inventory"] = check_source_inventory(source_root)
    return report


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"package manifest must be an object: {path}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for package in PACKAGE_SCHEMAS:
        parser.add_argument(f"--{package}", type=Path, required=True)
    parser.add_argument(
        "--source-root",
        type=Path,
        default=Path(__file__).resolve().parents[3],
        help="repository root used to enforce the sole canonical controld socket source",
    )
    arguments = parser.parse_args()
    report = check_inventory(
        {package: _load(getattr(arguments, package)) for package in PACKAGE_SCHEMAS},
        source_root=arguments.source_root.resolve(),
    )
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

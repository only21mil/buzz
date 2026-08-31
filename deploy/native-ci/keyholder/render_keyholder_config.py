#!/usr/bin/env python3
"""Render the closed static keyholder config without activation-bound values."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
from urllib.parse import urlsplit

HEX64 = re.compile(r"^[0-9a-f]{64}$")
OPERATIONS = [
    "describe",
    "sign_ci_event",
    "nip98_authorize",
    "sign_manifest",
    "describe_acceptance",
    "sign_acceptance_mutation",
]
IDENTITY_KEYS = {"public_key", "generation"}
SPEC_KEYS = {"schema_version", "peer", "selectors", "nip98_origin", "acceptance"}
PEER_KEYS = {"uid", "gid"}
SELECTOR_KEYS = {"ci_event", "nip98", "manifest"}
ACCEPTANCE_KEYS = {
    "binding_receipt_path",
    "credential_selector",
}
BINDING_RECEIPT_PATH = "/var/lib/buzzci/activation-controller/controld-acceptance-v2.json"
ACCEPTANCE_CREDENTIAL_SELECTOR = "acceptance-actor.key"


def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _object(value: object, keys: set[str], where: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"invalid {where} fields")
    return value


def _u32(value: object, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 0xFFFF_FFFF:
        raise ValueError(f"invalid {where}")
    return value


def _identity(value: object, where: str) -> dict[str, object]:
    identity = _object(value, IDENTITY_KEYS, where)
    public_key = identity["public_key"]
    if not isinstance(public_key, str) or not HEX64.fullmatch(public_key) or public_key == "0" * 64:
        raise ValueError(f"invalid {where} public key")
    generation = identity["generation"]
    if isinstance(generation, bool) or not isinstance(generation, int) or not 1 <= generation <= (1 << 64) - 1:
        raise ValueError(f"invalid {where} generation")
    return {"public_key": public_key, "generation": generation}


def validate_spec(value: object) -> dict[str, object]:
    spec = _object(value, SPEC_KEYS, "keyholder spec")
    if spec["schema_version"] != 2:
        raise ValueError("invalid schema version")
    peer = _object(spec["peer"], PEER_KEYS, "peer")
    selectors = _object(spec["selectors"], SELECTOR_KEYS, "selectors")
    rendered_selectors = {name: _identity(selectors[name], name) for name in sorted(SELECTOR_KEYS)}
    selector_keys = [item["public_key"] for item in rendered_selectors.values()]
    if len(set(selector_keys)) != 3:
        raise ValueError("selector public keys must be distinct")
    origin = spec["nip98_origin"]
    if not isinstance(origin, str):
        raise ValueError("invalid NIP-98 origin")
    parsed = urlsplit(origin)
    if parsed.scheme != "https" or not parsed.netloc or parsed.path not in {"", "/"} or parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValueError("invalid NIP-98 origin")
    acceptance = _object(spec["acceptance"], ACCEPTANCE_KEYS, "acceptance")
    if acceptance != {
        "binding_receipt_path": BINDING_RECEIPT_PATH,
        "credential_selector": ACCEPTANCE_CREDENTIAL_SELECTOR,
    }:
        raise ValueError("acceptance binding contract differs")
    return {
        "schema_version": 2,
        "peer": {
            "uid": _u32(peer["uid"], "peer uid"),
            "gid": _u32(peer["gid"], "peer gid"),
            "allowed_operations": OPERATIONS,
        },
        "selectors": rendered_selectors,
        "nip98_origin": origin.removesuffix("/"),
        "acceptance": acceptance,
    }


def validate_config(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != SPEC_KEYS:
        raise ValueError("invalid keyholder config fields")
    peer = value.get("peer")
    if not isinstance(peer, dict) or set(peer) != PEER_KEYS | {"allowed_operations"}:
        raise ValueError("invalid keyholder peer fields")
    if peer["allowed_operations"] != OPERATIONS:
        raise ValueError("invalid keyholder operation set")
    spec = dict(value)
    spec["peer"] = {"uid": peer["uid"], "gid": peer["gid"]}
    rendered = validate_spec(spec)
    if rendered != value:
        raise ValueError("keyholder config is not canonical")
    return rendered


def load_spec(path: Path) -> dict[str, object]:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or mode not in {0o400, 0o600, 0o644}
        ):
            raise ValueError("public acceptance spec metadata is invalid")
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, 64 * 1024):
            size += len(chunk)
            if size > 256 * 1024:
                raise ValueError("public acceptance spec has invalid size")
            chunks.append(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(descriptor)
    if not raw or len(raw) > 256 * 1024:
        raise ValueError("public acceptance spec has invalid size")
    return validate_spec(json.loads(raw, object_pairs_hook=reject_duplicates))


def config_bytes(path: Path) -> bytes:
    return canonical_json(load_spec(path))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-spec", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    payload = config_bytes(arguments.public_spec)
    if arguments.output is None:
        print(payload.decode(), end="")
    else:
        arguments.output.write_bytes(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

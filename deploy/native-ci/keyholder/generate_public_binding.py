#!/usr/bin/env python3
"""Generate the production public binding from public key readbacks only."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import stat
import sys
from urllib.parse import urlsplit

KEYHOLDER_DIR = Path(__file__).resolve().parent
if str(KEYHOLDER_DIR) not in sys.path:
    sys.path.insert(0, str(KEYHOLDER_DIR))

import freeze_package
import render_keyholder_config

PUBLIC_KEY_FILE_BYTES = 65
PUBLIC_KEY = re.compile(r"^[0-9a-f]{64}$")
SECP256K1_FIELD = (1 << 256) - (1 << 32) - 977
PUBLIC_INPUT_MODES = {0o400, 0o444, 0o600, 0o644}
OUTPUT_MODE = 0o600


def _read_public_key(path: Path, role: str) -> str:
    absolute = Path(os.path.abspath(path))
    if Path(os.path.realpath(absolute)) != absolute:
        raise ValueError(f"{role} public key path contains a symbolic component")
    descriptor = os.open(
        absolute,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) not in PUBLIC_INPUT_MODES
            or before.st_size != PUBLIC_KEY_FILE_BYTES
        ):
            raise ValueError(f"{role} public key metadata is unsafe")
        raw = b""
        while chunk := os.read(descriptor, PUBLIC_KEY_FILE_BYTES + 1 - len(raw)):
            raw += chunk
            if len(raw) > PUBLIC_KEY_FILE_BYTES:
                raise ValueError(f"{role} public key encoding is invalid")
        after = os.fstat(descriptor)
        stable = (
            "st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid",
            "st_size", "st_mtime_ns",
        )
        if any(getattr(before, field) != getattr(after, field) for field in stable):
            raise ValueError(f"{role} public key changed while read")
    finally:
        os.close(descriptor)
    try:
        encoded = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError(f"{role} public key encoding is invalid") from error
    if not encoded.endswith("\n") or PUBLIC_KEY.fullmatch(encoded[:-1]) is None:
        raise ValueError(f"{role} public key must be 64 lowercase hex bytes plus LF")
    public_key = encoded[:-1]
    x_coordinate = int(public_key, 16)
    if x_coordinate == 0 or x_coordinate >= SECP256K1_FIELD:
        raise ValueError(f"{role} public key is not a nonzero BIP-340 x-only key")
    curve_value = (pow(x_coordinate, 3, SECP256K1_FIELD) + 7) % SECP256K1_FIELD
    y_coordinate = pow(curve_value, (SECP256K1_FIELD + 1) // 4, SECP256K1_FIELD)
    if pow(y_coordinate, 2, SECP256K1_FIELD) != curve_value:
        raise ValueError(f"{role} public key is not a BIP-340 x-only key")
    return public_key


def _generation(value: int, role: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value != 1:
        raise ValueError(f"{role} generation must be exactly 1 for public-binding v3")
    return value


def _validate_origins(relay_url: str, relay_http_origin: str) -> None:
    values = ((relay_url, "wss", "relay URL"), (relay_http_origin, "https", "relay HTTP origin"))
    authorities: list[str] = []
    for value, scheme, where in values:
        if (
            not isinstance(value, str)
            or not value.isascii()
            or len(value) > 2048
            or any(ord(character) <= 0x20 or ord(character) == 0x7F for character in value)
        ):
            raise ValueError(f"{where} encoding is invalid")
        parsed = urlsplit(value)
        try:
            parsed.port
        except ValueError as error:
            raise ValueError(f"{where} port is invalid") from error
        if (
            parsed.scheme != scheme
            or not parsed.netloc
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
            or parsed.netloc != parsed.netloc.lower()
            or value != f"{scheme}://{parsed.netloc}"
        ):
            raise ValueError(f"{where} is not a canonical secure origin")
        authorities.append(parsed.netloc)
    if authorities[0] != authorities[1]:
        raise ValueError("relay URL and HTTP origin authorities differ")


def binding_bytes(
    *,
    relay_url: str,
    relay_http_origin: str,
    controld_uid: int,
    controld_gid: int,
    ci_event_public_key: Path,
    ci_event_generation: int,
    nip98_public_key: Path,
    nip98_generation: int,
    manifest_public_key: Path,
    manifest_generation: int,
    acceptance_actor_public_key: Path,
    acceptance_actor_generation: int,
) -> bytes:
    _validate_origins(relay_url, relay_http_origin)
    if (
        isinstance(controld_uid, bool)
        or not isinstance(controld_uid, int)
        or not 1 <= controld_uid <= 0xFFFF_FFFF
        or isinstance(controld_gid, bool)
        or not isinstance(controld_gid, int)
        or not 1 <= controld_gid <= 0xFFFF_FFFF
    ):
        raise ValueError("controld UID and GID must be nonzero u32 values")
    identities = {
        "ci_event": {
            "public_key": _read_public_key(ci_event_public_key, "ci-event"),
            "generation": _generation(ci_event_generation, "ci-event"),
        },
        "nip98": {
            "public_key": _read_public_key(nip98_public_key, "nip98"),
            "generation": _generation(nip98_generation, "nip98"),
        },
        "manifest": {
            "public_key": _read_public_key(manifest_public_key, "manifest"),
            "generation": _generation(manifest_generation, "manifest"),
        },
        "acceptance_actor": {
            "public_key": _read_public_key(
                acceptance_actor_public_key, "acceptance-actor",
            ),
            "generation": _generation(
                acceptance_actor_generation, "acceptance-actor",
            ),
        },
    }
    public_keys = [identity["public_key"] for identity in identities.values()]
    if len(set(public_keys)) != len(public_keys):
        raise ValueError("all four public key roles must be distinct")
    binding = {
        "schema_version": freeze_package.PUBLIC_BINDING_SCHEMA,
        "relay_url": relay_url,
        "relay_http_origin": relay_http_origin,
        "acceptance_actor": identities["acceptance_actor"],
        "keyholder_public_spec": {
            "schema_version": 2,
            "peer": {
                "uid": controld_uid,
                "gid": controld_gid,
                "allowed_operations": render_keyholder_config.OPERATIONS,
            },
            "selectors": {
                "ci_event": identities["ci_event"],
                "nip98": identities["nip98"],
                "manifest": identities["manifest"],
            },
            "nip98_origin": relay_http_origin,
            "acceptance": {
                "binding_receipt_path": render_keyholder_config.BINDING_RECEIPT_PATH,
                "credential_selector": render_keyholder_config.ACCEPTANCE_CREDENTIAL_SELECTOR,
            },
        },
    }
    payload = freeze_package.canonical_public_binding(binding)
    freeze_package.project_public_binding_bytes(payload)
    return payload


def _private_output_parent(path: Path) -> tuple[Path, Path]:
    absolute = Path(os.path.abspath(path))
    parent = absolute.parent
    if Path(os.path.realpath(parent)) != parent:
        raise ValueError("output parent contains a symbolic component")
    metadata = parent.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ValueError("output parent must be an owner-held mode-0700 directory")
    return absolute, parent


def write_binding(path: Path, payload: bytes) -> None:
    absolute, parent = _private_output_parent(path)
    descriptor = os.open(
        absolute,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        OUTPUT_MODE,
    )
    created_identity: tuple[int, int] | None = None
    try:
        os.fchmod(descriptor, OUTPUT_MODE)
        created = os.fstat(descriptor)
        created_identity = (created.st_dev, created.st_ino)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("public binding write did not advance")
            view = view[written:]
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != OUTPUT_MODE
            or metadata.st_size != len(payload)
        ):
            raise OSError("public binding output metadata differs")
    except BaseException:
        try:
            live = absolute.lstat()
            if created_identity == (live.st_dev, live.st_ino):
                absolute.unlink()
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(descriptor)
    directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def generate(output: Path, **arguments: object) -> None:
    write_binding(output, binding_bytes(**arguments))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--relay-url", required=True)
    parser.add_argument("--relay-http-origin", required=True)
    parser.add_argument("--controld-uid", type=int, required=True)
    parser.add_argument("--controld-gid", type=int, required=True)
    for option in ("ci-event", "nip98", "manifest", "acceptance-actor"):
        parser.add_argument(f"--{option}-public-key", type=Path, required=True)
        parser.add_argument(f"--{option}-generation", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = vars(parser.parse_args())
    output = arguments.pop("output")
    try:
        generate(output, **arguments)
    except (OSError, ValueError) as error:
        print(f"generate_public_binding: {error}", file=sys.stderr)
        return 64
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Bind promotion event evidence to the configured Buzz relay origin."""

from __future__ import annotations

import argparse
import copy
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping, NoReturn
from urllib.parse import urlsplit


SECTIONS = ("staging", "production_canary", "deliberate_red")
DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class EvidenceError(Exception):
    """Promotion evidence could not be safely populated."""


def refuse(message: str) -> NoReturn:
    raise EvidenceError(message)


def canonical_relay_origin(value: Any, path: str = "relay_url") -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        refuse(f"{path} must be a non-empty URL without surrounding whitespace")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        refuse(f"{path} is not a valid relay URL")
    scheme = {"ws": "http", "wss": "https", "http": "http", "https": "https"}.get(
        parsed.scheme
    )
    if scheme is None or parsed.hostname is None:
        refuse(f"{path} must use http, https, ws, or wss")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        refuse(f"{path} must not contain credentials")
    if "?" in value or "#" in value or parsed.path not in ("", "/"):
        refuse(f"{path} must be an origin without path, query, or fragment")

    hostname = parsed.hostname.lower()
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            hostname.encode("ascii")
        except UnicodeEncodeError:
            refuse(f"{path} hostname must use ASCII or an IP address")
        labels = hostname.rstrip(".").split(".")
        if not labels or any(DNS_LABEL.fullmatch(label) is None for label in labels):
            refuse(f"{path} hostname is invalid")
        hostname = ".".join(labels)
        authority = hostname
    else:
        hostname = address.compressed
        authority = f"[{hostname}]" if address.version == 6 else hostname

    default_port = 443 if scheme == "https" else 80
    if port is not None and port != default_port:
        authority = f"{authority}:{port}"
    return f"{scheme}://{authority}"


def configured_relay_origin(cli_value: str | None, environ: Mapping[str, str]) -> str:
    configured = cli_value if cli_value is not None else environ.get("BUZZ_RELAY_URL")
    if configured is None or not configured:
        refuse("BUZZ_RELAY_URL or --relay-url is required; no relay fallback is permitted")
    return canonical_relay_origin(configured, "configured relay URL")


def populate_event_evidence(section: Any, relay_origin: str, path: str) -> dict[str, Any]:
    if not isinstance(section, dict):
        refuse(f"{path} must be an object")
    result = copy.deepcopy(section)
    existing = result.get("relay_url")
    if existing is not None:
        current = canonical_relay_origin(existing, f"{path}.relay_url")
        if current != relay_origin:
            refuse(f"{path}.relay_url conflicts with the configured relay origin")
    result["relay_url"] = relay_origin
    return result


def populate_promotion_evidence(bundle: Any, configured_url: Any) -> dict[str, Any]:
    if not isinstance(bundle, dict):
        refuse("promotion evidence must be an object")
    origin = canonical_relay_origin(configured_url, "configured relay URL")
    result = copy.deepcopy(bundle)
    for section_name in SECTIONS:
        section = result.get(section_name)
        if not isinstance(section, dict):
            refuse(f"{section_name} must be an object")
        evidence = section.get("event_evidence")
        section["event_evidence"] = populate_event_evidence(
            evidence, origin, f"{section_name}.event_evidence"
        )
    return result


def load_private_json(path: Path) -> Any:
    try:
        info = path.lstat()
    except OSError as exc:
        refuse(f"cannot inspect input evidence: {exc}")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        refuse("input evidence must be a regular non-symlink file")
    if stat.S_IMODE(info.st_mode) != 0o600:
        refuse("input evidence must have mode 0600")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        refuse(f"cannot read input evidence JSON: {exc}")


def write_private_json(path: Path, value: Any) -> None:
    try:
        parent_info = path.parent.lstat()
    except OSError as exc:
        refuse(f"cannot inspect output directory: {exc}")
    if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode) \
            or stat.S_IMODE(parent_info.st_mode) != 0o700:
        refuse("output directory must have mode 0700")
    encoded = json.dumps(value, indent=2, sort_keys=True).encode() + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        refuse("output evidence already exists")
    except OSError as exc:
        refuse(f"cannot create output evidence: {exc}")
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            os.unlink(path)
        except OSError:
            pass
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Populate promotion signed-event evidence from the configured relay origin."
    )
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--relay-url", help="trusted relay configuration; overrides BUZZ_RELAY_URL")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        input_path = Path(os.path.abspath(args.input))
        output_path = Path(os.path.abspath(args.output))
        if input_path == output_path:
            refuse("input and output evidence paths must differ")
        relay_origin = configured_relay_origin(args.relay_url, os.environ)
        bundle = populate_promotion_evidence(load_private_json(input_path), relay_origin)
        write_private_json(output_path, bundle)
    except EvidenceError as exc:
        print(f"REFUSED: {exc}", file=os.sys.stderr)
        return 2
    print(json.dumps({"output": str(output_path), "relay_url": relay_origin}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

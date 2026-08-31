#!/usr/bin/env python3
"""Loopback TLS relay with full NIP-98 and Nostr signature verification."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import ssl
import threading
import time
from urllib.parse import parse_qs, urlsplit

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX128 = re.compile(r"^[0-9a-f]{128}$")
OBJECT_PATH = re.compile(r"^/ci/(?:logs|artifacts)/[A-Za-z0-9._/-]{1,512}$")
MAX_BODY = 64 * 1024
MAX_AUTH = 16 * 1024


class RelayError(ValueError):
    pass


def tagged_hash(tag: str, payload: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + payload).digest()


def inverse(value: int) -> int:
    return pow(value, P - 2, P)


def point_add(left: tuple[int, int] | None, right: tuple[int, int] | None) -> tuple[int, int] | None:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 != y2 or y1 == 0):
        return None
    slope = (3 * x1 * x1 * inverse(2 * y1)) % P if left == right else ((y2 - y1) * inverse(x2 - x1)) % P
    x3 = (slope * slope - x1 - x2) % P
    return x3, (slope * (x1 - x3) - y1) % P


def point_mul(scalar: int, point: tuple[int, int] | None = G) -> tuple[int, int] | None:
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def lift_x(x: int) -> tuple[int, int] | None:
    if x >= P:
        return None
    y = pow((pow(x, 3, P) + 7) % P, (P + 1) // 4, P)
    if pow(y, 2, P) != (pow(x, 3, P) + 7) % P:
        return None
    return x, y if y % 2 == 0 else P - y


def schnorr_verify(message: bytes, public_hex: str, signature_hex: str) -> bool:
    if len(message) != 32 or HEX64.fullmatch(public_hex) is None or HEX128.fullmatch(signature_hex) is None:
        return False
    public = bytes.fromhex(public_hex)
    signature = bytes.fromhex(signature_hex)
    point = lift_x(int.from_bytes(public, "big"))
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if point is None or r >= P or s >= N:
        return False
    challenge = int.from_bytes(tagged_hash("BIP0340/challenge", signature[:32] + public + message), "big") % N
    negative = (point[0], (-point[1]) % P)
    computed = point_add(point_mul(s), point_mul(challenge, negative))
    return computed is not None and computed[1] % 2 == 0 and computed[0] == r


def event_id(event: dict[str, object]) -> str:
    serialized = json.dumps(
        [0, event["pubkey"], event["created_at"], event["kind"], event["tags"], event["content"]],
        ensure_ascii=False, separators=(",", ":"),
    ).encode()
    return hashlib.sha256(serialized).hexdigest()


def verify_event(value: object, *, expected_public_key: str | None = None) -> dict[str, object]:
    fields = {"id", "pubkey", "created_at", "kind", "tags", "content", "sig"}
    if not isinstance(value, dict) or set(value) != fields:
        raise RelayError("event shape rejected")
    if (
        not isinstance(value["pubkey"], str) or HEX64.fullmatch(value["pubkey"]) is None
        or expected_public_key is not None and value["pubkey"] != expected_public_key
        or not isinstance(value["created_at"], int) or isinstance(value["created_at"], bool) or value["created_at"] < 1
        or not isinstance(value["kind"], int) or isinstance(value["kind"], bool) or not 0 <= value["kind"] <= 65535
        or not isinstance(value["tags"], list) or not isinstance(value["content"], str)
        or not isinstance(value["id"], str) or HEX64.fullmatch(value["id"]) is None
        or not isinstance(value["sig"], str) or HEX128.fullmatch(value["sig"]) is None
    ):
        raise RelayError("event fields rejected")
    for tag in value["tags"]:
        if not isinstance(tag, list) or not tag or any(not isinstance(item, str) for item in tag):
            raise RelayError("event tags rejected")
    computed = event_id(value)
    if value["id"] != computed or not schnorr_verify(bytes.fromhex(computed), value["pubkey"], value["sig"]):
        raise RelayError("event signature rejected")
    return value


def tag_value(tags: list[list[str]], name: str, *, required: bool = True) -> str | None:
    values = [tag[1] for tag in tags if len(tag) == 2 and tag[0] == name]
    if len(values) != (1 if required else 0) and not (not required and len(values) == 1):
        raise RelayError("NIP-98 tag multiplicity rejected")
    return values[0] if values else None


def verify_nip98(header: str, method: str, url: str, body: bytes, expected_public_key: str, now: int | None = None) -> None:
    if not header.startswith("Nostr ") or len(header) > MAX_AUTH:
        raise RelayError("NIP-98 authorization rejected")
    try:
        raw = base64.b64decode(header[6:], validate=True)
        value = json.loads(raw)
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RelayError("NIP-98 encoding rejected") from error
    event = verify_event(value, expected_public_key=expected_public_key)
    current = int(time.time()) if now is None else now
    if event["kind"] != 27235 or event["content"] != "" or abs(current - event["created_at"]) > 60:
        raise RelayError("NIP-98 kind, content, or time rejected")
    tags = event["tags"]
    if tag_value(tags, "u") != url or tag_value(tags, "method") != method:
        raise RelayError("NIP-98 request binding rejected")
    payload_values = [tag[1] for tag in tags if len(tag) == 2 and tag[0] == "payload"]
    if body:
        if payload_values != [hashlib.sha256(body).hexdigest()]:
            raise RelayError("NIP-98 payload binding rejected")
    elif payload_values:
        raise RelayError("NIP-98 empty payload binding rejected")


class RelayState:
    def __init__(self, object_root: Path, origin: str, nip98_public_key: str) -> None:
        self.object_root = object_root
        self.origin = origin.rstrip("/")
        self.nip98_public_key = nip98_public_key
        self.events: dict[str, dict[str, object]] = {}
        self.accepted: list[tuple[int, str, dict[str, object]]] = []
        self.cursor = 0
        self.lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    server: "RelayServer"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _json(self, status: int, value: object) -> None:
        raw = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _body(self) -> bytes | None:
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            return None
        if not 0 <= length <= MAX_BODY:
            return None
        raw = self.rfile.read(length)
        return raw if len(raw) == length else None

    def _authorize(self, method: str, body: bytes) -> bool:
        try:
            verify_nip98(
                self.headers.get("Authorization", ""), method,
                self.server.state.origin + self.path, body, self.server.state.nip98_public_key,
            )
            return True
        except RelayError:
            return False

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path != "/ci/control/accepted" or not self._authorize("GET", b""):
            self._json(403, {"error": "rejected"})
            return
        try:
            query = parse_qs(parsed.query, strict_parsing=True)
            if set(query) != {"channel_id", "after_cursor", "limit"} or any(len(values) != 1 for values in query.values()):
                raise ValueError("query shape")
            channel = query["channel_id"][0]
            after = int(query["after_cursor"][0])
            limit = int(query["limit"][0])
        except (KeyError, ValueError, IndexError):
            self._json(400, {"error": "invalid query"})
            return
        if not channel or after < 0 or limit != 1:
            self._json(400, {"error": "invalid query"})
            return
        accepted = None
        with self.server.state.lock:
            for cursor, event_channel, event in self.server.state.accepted:
                if cursor > after and event_channel == channel:
                    accepted = {"channel_id": channel, "watch_cursor": cursor, "event": event}
                    break
        self._json(200, {"accepted": accepted})

    def do_POST(self) -> None:
        raw = self._body()
        if self.path != "/events" or raw is None or not self._authorize("POST", raw):
            self._json(403, {"error": "rejected"})
            return
        try:
            event = verify_event(json.loads(raw))
        except (json.JSONDecodeError, RelayError):
            self._json(400, {"error": "invalid event"})
            return
        event_id_value = event["id"]
        channel = next((tag[1] for tag in event["tags"] if len(tag) >= 2 and tag[0] == "h"), None) if event["kind"] == 46100 else None
        if event["kind"] == 46100 and (not isinstance(channel, str) or not channel):
            self._json(400, {"error": "run event lacks channel"})
            return
        with self.server.state.lock:
            duplicate = event_id_value in self.server.state.events
            if not duplicate:
                self.server.state.events[event_id_value] = event
                if isinstance(channel, str):
                    self.server.state.cursor += 1
                    self.server.state.accepted.append((self.server.state.cursor, channel, event))
        self._json(200, {"event_id": event_id_value, "accepted": not duplicate, "message": "stored" if not duplicate else "duplicate:stored"})

    def do_PUT(self) -> None:
        parsed = urlsplit(self.path)
        raw = self._body()
        if raw is None or parsed.query or parsed.fragment or OBJECT_PATH.fullmatch(parsed.path) is None or not self._authorize("PUT", raw):
            self._json(403, {"error": "rejected"})
            return
        digest = hashlib.sha256(raw).hexdigest()
        if parsed.path.rsplit("/", 1)[-1] != digest:
            self._json(400, {"error": "digest mismatch"})
            return
        target = self.server.state.object_root / digest
        with self.server.state.lock:
            if target.exists() and target.read_bytes() != raw:
                self._json(409, {"error": "object collision"})
                return
            if not target.exists():
                target.write_bytes(raw)
                target.chmod(0o400)
        self._json(200, {"url": self.server.state.origin + parsed.path, "sha256": digest, "byte_length": len(raw)})


class RelayServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], state: RelayState) -> None:
        super().__init__(address, Handler)
        self.state = state


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--public-config", type=Path, required=True)
    parser.add_argument("--object-root", type=Path, required=True)
    arguments = parser.parse_args()
    config = json.loads(arguments.public_config.read_bytes())
    if not isinstance(config, dict) or set(config) != {"origin", "nip98_public_key"} or HEX64.fullmatch(str(config["nip98_public_key"])) is None:
        return 1
    arguments.object_root.mkdir(mode=0o700, parents=True, exist_ok=False)
    state = RelayState(arguments.object_root, str(config["origin"]), str(config["nip98_public_key"]))
    server = RelayServer(("127.0.0.1", 3443), state)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(arguments.certificate, arguments.private_key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

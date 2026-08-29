#!/usr/bin/env python3
"""Bounded loopback TLS relay for disposable capacity-one acceptance."""

from __future__ import annotations

import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import ssl
import threading
from urllib.parse import parse_qs, urlsplit

MAX_BODY = 64 * 1024
HEX64 = re.compile(r"^[0-9a-f]{64}$")
OBJECT_PATH = re.compile(r"^/ci/(?:logs|artifacts)/[A-Za-z0-9._/-]{1,512}$")


class RelayState:
    def __init__(self, object_root: Path) -> None:
        self.object_root = object_root
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

    def _authorized(self) -> bool:
        value = self.headers.get("Authorization", "")
        return value.startswith("Nostr ") and 16 <= len(value) <= 16 * 1024

    def _body(self) -> bytes | None:
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            return None
        if not 0 <= length <= MAX_BODY:
            return None
        raw = self.rfile.read(length)
        return raw if len(raw) == length else None

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path == "/health":
            self._json(200, {"status": "ready"})
            return
        if parsed.path != "/ci/control/accepted" or not self._authorized():
            self._json(403, {"error": "rejected"})
            return
        query = parse_qs(parsed.query, strict_parsing=True)
        try:
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
        if self.path != "/events" or not self._authorized():
            self._json(403, {"error": "rejected"})
            return
        raw = self._body()
        try:
            event = json.loads(raw) if raw is not None else None
        except json.JSONDecodeError:
            event = None
        if not isinstance(event, dict) or not isinstance(event.get("id"), str) or HEX64.fullmatch(event["id"]) is None:
            self._json(400, {"error": "invalid event"})
            return
        event_id = event["id"]
        channel = next((tag[1] for tag in event.get("tags", []) if isinstance(tag, list) and len(tag) >= 2 and tag[0] == "h"), None) if event.get("kind") == 46100 else None
        if event.get("kind") == 46100 and (not isinstance(channel, str) or not channel):
            self._json(400, {"error": "run event lacks channel"})
            return
        with self.server.state.lock:
            duplicate = event_id in self.server.state.events
            if not duplicate:
                self.server.state.events[event_id] = event
                if isinstance(channel, str):
                    self.server.state.cursor += 1
                    self.server.state.accepted.append((self.server.state.cursor, channel, event))
        self._json(200, {"event_id": event_id, "accepted": not duplicate, "message": "stored" if not duplicate else "duplicate:stored"})

    def do_PUT(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.query or parsed.fragment or OBJECT_PATH.fullmatch(parsed.path) is None or not self._authorized():
            self._json(403, {"error": "rejected"})
            return
        raw = self._body()
        if raw is None:
            self._json(400, {"error": "invalid body"})
            return
        digest = hashlib.sha256(raw).hexdigest()
        if parsed.path.rsplit("/", 1)[-1] != digest:
            self._json(400, {"error": "digest mismatch"})
            return
        target = self.server.state.object_root / digest
        if target.exists() and target.read_bytes() != raw:
            self._json(409, {"error": "object collision"})
            return
        if not target.exists():
            target.write_bytes(raw)
            target.chmod(0o400)
        self._json(200, {"url": f"https://relay.test.invalid:3443{parsed.path}", "sha256": digest, "byte_length": len(raw)})


class RelayServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], state: RelayState) -> None:
        super().__init__(address, Handler)
        self.state = state


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--object-root", type=Path, required=True)
    arguments = parser.parse_args()
    arguments.object_root.mkdir(mode=0o700, parents=True, exist_ok=False)
    server = RelayServer(("127.0.0.1", 3443), RelayState(arguments.object_root))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(arguments.certificate, arguments.private_key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

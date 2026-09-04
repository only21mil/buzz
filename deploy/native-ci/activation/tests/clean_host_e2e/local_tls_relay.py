#!/usr/bin/env python3
"""Loopback TLS relay that enforces the production relay's CI admission rules.

The rules mirror ``crates/buzz-relay`` for the routes the native-CI daemons use:
``POST /events`` (api/bridge.rs ``submit_event`` and handlers/ingest.rs),
``POST /query`` (api/bridge.rs ``query_events``: the exact-event read-back
controld issues before it re-signs a refused publication),
``GET /ci/control/accepted`` (api/ci.rs ``next_accepted_control``), and
``PUT /ci/logs|artifacts/...`` (api/ci.rs ``put_ci_evidence``). Every request
carries a NIP-98 token; the token pubkey is the only identity the relay knows.

One opt-in fault mode, ``stale-terminal-publication-recovery``, is armed by a
flag file the guest writes before the relay starts. It answers the first publish
of the terminal kind-46101 run status with the production drift refusal and
stores nothing, so controld must read the event back through ``POST /query``
before it re-signs and publishes again. The relay records the refused id and
whether that read-back happened next to the flag, so the guest can prove the
fault fired and the recovery path ran (M11 failed exactly there: no query).
"""

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
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
REPO_COORDINATE = re.compile(r"^30617:[0-9a-f]{64}:[^:]+$")
OBJECT_PATH = re.compile(r"^/ci/(logs|artifacts)/([A-Za-z0-9._-]{1,128})(?:/[A-Za-z0-9._-]{1,128}){3,4}/([0-9a-f]{64})$")
MAX_BODY = 64 * 1024
MAX_AUTH = 16 * 1024
# handlers/ingest.rs MAX_TIMESTAMP_DRIFT_SECS and MAX_EVENT_CONTENT_BYTES.
MAX_EVENT_DRIFT = 900
MAX_CONTENT_BYTES = 256 * 1024
# buzz-auth nip98.rs TIMESTAMP_TOLERANCE_SECS.
MAX_TOKEN_DRIFT = 60
KIND_DELETION = 5
KIND_CI_REQUEST = 46_100
KIND_CI_RUN_STATUS = 46_101
KIND_CI_STATUS_MIN = 46_101
KIND_CI_STATUS_MAX = 46_106
KIND_CI_GRANT = 46_107
# buzz-core ci.rs CiRunState: every other state is terminal.
OPEN_RUN_STATES = frozenset({"queued", "running"})
FAULT_STALE_TERMINAL = "stale-terminal-publication-recovery"
RELAY_FAULTS = frozenset({FAULT_STALE_TERMINAL})
FAULT_RECORD_NAME = "fault-fired.json"
MAX_QUERY_FILTERS = 16
# handlers/ingest.rs: kinds that bypass the generic member-or-open gate.
MEMBERSHIP_EXEMPT_KINDS = frozenset({9021, 9007, 40003, 9002, 9005, 9008})
GRANT_ROLES = frozenset({"owner", "admin"})
MEMBER_ROLES = GRANT_ROLES | {"member"}


class RelayError(ValueError):
    pass


class Refusal(Exception):
    """One production-shaped refusal: HTTP status and the relay's message."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


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


def verify_event(value: object) -> dict[str, object]:
    fields = {"id", "pubkey", "created_at", "kind", "tags", "content", "sig"}
    if not isinstance(value, dict) or set(value) != fields:
        raise RelayError("event shape rejected")
    if (
        not isinstance(value["pubkey"], str) or HEX64.fullmatch(value["pubkey"]) is None
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


def verify_nip98(header: str, method: str, url: str, body: bytes, now: int | None = None) -> dict[str, object]:
    """Verify one NIP-98 token and return its event; the caller reads `pubkey` and `id`."""
    if not header.startswith("Nostr ") or len(header) > MAX_AUTH:
        raise RelayError("NIP-98 authorization rejected")
    try:
        raw = base64.b64decode(header[6:], validate=True)
        value = json.loads(raw)
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RelayError("NIP-98 encoding rejected") from error
    event = verify_event(value)
    current = int(time.time()) if now is None else now
    if event["kind"] != 27235 or event["content"] != "" or abs(current - event["created_at"]) > MAX_TOKEN_DRIFT:
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
    return event


def first_tag(tags: list[list[str]], name: str) -> str | None:
    return next((tag[1] for tag in tags if len(tag) >= 2 and tag[0] == name), None)


def parse_content(event: dict[str, object], what: str) -> dict[str, object]:
    try:
        content = json.loads(str(event["content"]))
    except json.JSONDecodeError as error:
        raise Refusal(400, f"invalid: {what} content is not valid JSON") from error
    if not isinstance(content, dict):
        raise Refusal(400, f"invalid: {what} content is not an object")
    return content


class RelayState:
    """One community, one channel roster, one static CI signer set.

    ``members`` maps pubkey to role (owner, admin, member), the relay's
    ``channel_members`` row. ``static_signers`` is the relay operator's
    ``BUZZ_CI_STATUS_SIGNER_PUBKEYS``; grants accepted through kind 46107 add
    to it per repository and window.
    """

    def __init__(
        self, object_root: Path, origin: str, channel_id: str, visibility: str,
        members: dict[str, str], static_signers: set[str],
    ) -> None:
        if UUID.fullmatch(channel_id) is None or visibility not in {"open", "private"}:
            raise ValueError("relay channel rejected")
        if any(HEX64.fullmatch(key) is None or role not in MEMBER_ROLES for key, role in members.items()):
            raise ValueError("relay roster rejected")
        if any(HEX64.fullmatch(key) is None for key in static_signers):
            raise ValueError("relay signer set rejected")
        self.object_root = object_root
        self.origin = origin.rstrip("/")
        self.channel_id = channel_id
        self.visibility = visibility
        self.members = dict(members)
        self.static_signers = set(static_signers)
        self.events: dict[str, dict[str, object]] = {}
        self.event_channels: dict[str, str | None] = {}
        self.accepted: list[tuple[int, str, dict[str, object]]] = []
        self.grants: list[tuple[str, str, int, int | None]] = []
        self.run_ids: set[tuple[str, str]] = set()
        self.seen_tokens: set[str] = set()
        self.cursor = 0
        self.lock = threading.Lock()
        self.fault: str | None = None
        self.fault_root: Path | None = None
        self.stale_event_id: str | None = None
        self.stale_queried = False

    def arm_fault(self, flag: Path) -> None:
        """Read the guest's flag file; an unknown mode is a configuration error."""
        mode = flag.read_bytes().decode().strip()
        if mode not in RELAY_FAULTS:
            raise ValueError("relay fault mode rejected")
        self.fault = mode
        self.fault_root = flag.parent

    def refuses_as_stale(self, event: dict[str, object]) -> bool:
        """Stale-terminal fault, one shot: the first terminal run status fails
        the production drift check and is not stored. The caller holds ``lock``."""
        if self.fault != FAULT_STALE_TERMINAL or self.stale_event_id is not None or event["kind"] != KIND_CI_RUN_STATUS:
            return False
        try:
            state = parse_content(event, "CI event").get("state")
        except Refusal:
            return False
        if not isinstance(state, str) or state in OPEN_RUN_STATES:
            return False
        self.stale_event_id = str(event["id"])
        self.write_fault_record()
        return True

    def note_query(self, ids: set[str] | None, kinds: list[object]) -> None:
        """Record the exact-event read-back of the refused publication."""
        if self.stale_event_id is None or self.stale_queried or ids is None or self.stale_event_id not in ids or KIND_CI_RUN_STATUS not in kinds:
            return
        self.stale_queried = True
        self.write_fault_record()

    def write_fault_record(self) -> None:
        assert self.fault_root is not None
        record = json.dumps({
            "mode": self.fault, "refused_event_id": self.stale_event_id, "queried": self.stale_queried,
        }, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        pending = self.fault_root / (FAULT_RECORD_NAME + ".next")
        pending.write_bytes(record)
        pending.chmod(0o400)
        pending.replace(self.fault_root / FAULT_RECORD_NAME)

    def visible_to(self, event: dict[str, object], caller: str) -> bool:
        # api/bridge.rs event_in_accessible_channel: a channel-scoped event is
        # readable only by a member (or by anyone when the channel is open).
        channel = self.event_channels.get(str(event["id"]))
        if channel is None:
            return True
        return channel == self.channel_id and (caller in self.members or self.visibility == "open")

    def active_signers(self, target_repo_a: str, now: int) -> set[str]:
        signers = set(self.static_signers)
        for repo, signer, valid_from, valid_until in self.grants:
            if repo == target_repo_a and valid_from <= now and (valid_until is None or valid_until > now):
                signers.add(signer)
        return signers

    def require_membership(self, channel: str, pubkey: str) -> None:
        # handlers/ingest.rs check_channel_membership: member, or open channel.
        if channel != self.channel_id:
            raise Refusal(400, "restricted: not a channel member")
        if pubkey not in self.members and self.visibility != "open":
            raise Refusal(400, "restricted: not a channel member")

    def require_signer(self, target_repo_a: str, pubkey: str, now: int) -> None:
        # api/ci.rs authorize_ci_signer.
        if pubkey not in self.active_signers(target_repo_a, now):
            raise Refusal(403, "CI signer is not authorized")

    def request_repository(self, request_id: str) -> str:
        event = self.events.get(request_id)
        if event is None or event["kind"] != KIND_CI_REQUEST:
            raise Refusal(404, "CI request not found")
        return str(parse_content(event, "CI request")["target_repo_a"])


def admit_event(state: RelayState, token_pubkey: str, event: dict[str, object], now: int) -> tuple[str | None, bool]:
    """Apply the production POST /events rules; return (channel, accepted).

    Raises :class:`Refusal` with the relay's status and message. The caller
    holds ``state.lock``.
    """
    kind = int(event["kind"])
    tags = event["tags"]
    assert isinstance(tags, list)
    if state.refuses_as_stale(event) or abs(int(event["created_at"]) - now) > MAX_EVENT_DRIFT:
        raise Refusal(400, "invalid: event timestamp too far from server time")
    if len(str(event["content"]).encode()) > MAX_CONTENT_BYTES:
        raise Refusal(400, "invalid: content exceeds maximum size")
    if event["pubkey"] != token_pubkey:
        raise Refusal(403, "invalid: event pubkey does not match authenticated identity")
    pubkey = str(event["pubkey"])
    channel = first_tag(tags, "h")
    if kind == KIND_DELETION:
        targets = [tag[1] for tag in tags if len(tag) >= 2 and tag[0] == "e"]
        if len(targets) != 1:
            raise Refusal(400, "invalid: deletion events must reference exactly one target via e or a tag")
        target = state.events.get(targets[0])
        if target is None:
            raise Refusal(400, "invalid: target event not found")
        if target["pubkey"] != pubkey:
            raise Refusal(400, "invalid: must be event author")
        channel = state.event_channels.get(targets[0])
    if KIND_CI_REQUEST <= kind <= KIND_CI_GRANT and channel is None:
        raise Refusal(400, "invalid: CI events require a channel h tag")
    if channel is not None and kind not in MEMBERSHIP_EXEMPT_KINDS:
        state.require_membership(channel, pubkey)
    if kind == KIND_CI_GRANT:
        if state.members.get(pubkey) not in GRANT_ROLES:
            raise Refusal(403, "restricted: only a channel owner or admin may issue a CI signer grant")
        content = parse_content(event, "CI grant")
        valid_from = content.get("valid_from")
        valid_until = content.get("valid_until")
        if (
            set(content) - {"schema_version", "target_repo_a", "signer_pubkey", "valid_from", "valid_until"}
            or content.get("schema_version") != 1
            or not isinstance(content.get("target_repo_a"), str)
            or REPO_COORDINATE.fullmatch(content["target_repo_a"]) is None
            or not isinstance(content.get("signer_pubkey"), str)
            or HEX64.fullmatch(content["signer_pubkey"]) is None
            or not isinstance(valid_from, int) or isinstance(valid_from, bool)
            or valid_until is not None and (not isinstance(valid_until, int) or isinstance(valid_until, bool))
            or valid_until is not None and valid_until <= valid_from
        ):
            raise Refusal(400, "invalid: CI grant content rejected")
    elif kind == KIND_CI_REQUEST:
        content = parse_content(event, "CI request")
        run_id = content.get("run_id")
        if content.get("actor") != pubkey:
            raise Refusal(400, "invalid: request actor does not match event signer")
        if not isinstance(run_id, str) or UUID.fullmatch(run_id) is None or first_tag(tags, "run") != run_id:
            raise Refusal(400, "invalid: CI request run tag rejected")
        if not isinstance(content.get("target_repo_a"), str) or first_tag(tags, "a") != content["target_repo_a"]:
            raise Refusal(400, "invalid: CI request repository tag rejected")
        # buzz-db ci.rs prepare_request: an initial request must create its
        # run; a rerun (attempt 2 or later) must find the run it extends.
        attempt = content.get("attempt")
        if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
            raise Refusal(400, "invalid: CI request attempt rejected")
        exists = (channel, run_id) in state.run_ids
        if event["id"] not in state.events and exists == (attempt == 1):
            raise Refusal(400, "invalid: CI run ID or initial request event ID already exists" if exists else "invalid: CI rerun names an unknown run")
    elif KIND_CI_STATUS_MIN <= kind <= KIND_CI_STATUS_MAX:
        content = parse_content(event, "CI event")
        if content.get("relay_signer") != pubkey:
            raise Refusal(400, "invalid: status signer does not match event signer")
        if not isinstance(content.get("target_repo_a"), str):
            raise Refusal(400, "invalid: CI event missing target_repo_a")
        if pubkey not in state.active_signers(content["target_repo_a"], now):
            raise Refusal(400, "invalid: unauthorized CI status signer")
    identifier = str(event["id"])
    if identifier in state.events:
        return channel, False
    state.events[identifier] = event
    state.event_channels[identifier] = channel
    if kind == KIND_CI_GRANT:
        content = parse_content(event, "CI grant")
        state.grants.append((
            str(content["target_repo_a"]), str(content["signer_pubkey"]),
            int(content["valid_from"]), None if content.get("valid_until") is None else int(content["valid_until"]),
        ))
    if kind == KIND_CI_REQUEST:
        assert channel is not None
        state.run_ids.add((channel, str(parse_content(event, "CI request")["run_id"])))
        state.cursor += 1
        state.accepted.append((state.cursor, channel, event))
    return channel, True


def hex_list(filter_value: dict[str, object], name: str) -> set[str] | None:
    values = filter_value.get(name)
    if values is None:
        return None
    if not isinstance(values, list) or any(not isinstance(item, str) or HEX64.fullmatch(item) is None for item in values):
        raise Refusal(400, f"invalid filters: {name}")
    return set(values)


def bounded_int(filter_value: dict[str, object], name: str) -> int | None:
    value = filter_value.get(name)
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise Refusal(400, f"invalid filters: {name}")
    return value


def query_events(state: RelayState, caller: str, raw: bytes) -> list[dict[str, object]]:
    """Apply the production POST /query rules; return the matching events.

    api/bridge.rs ``query_events_authed``: the body is a JSON array of filters;
    the kind gates run before any read; results are limited to channels the
    caller can access and follow the ``created_at DESC, id ASC`` order. The
    caller holds ``state.lock``.
    """
    try:
        filters = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Refusal(400, "invalid filters: body is not JSON") from error
    if not isinstance(filters, list) or not filters or len(filters) > MAX_QUERY_FILTERS or any(not isinstance(item, dict) for item in filters):
        raise Refusal(400, "invalid filters: expected an array of filter objects")
    results: list[dict[str, object]] = []
    for filter_value in filters:
        kinds = filter_value.get("kinds")
        # handlers/req.rs p_gated_filters_authorized: a filter that names no
        # kind can match every gated kind, so the relay refuses it before any
        # read. controld always names the exact kind (source.rs
        # publication_exists); the stub applies the gate regardless of `ids`.
        if (
            not isinstance(kinds, list) or not kinds
            or any(not isinstance(kind, int) or isinstance(kind, bool) or not 0 <= kind <= 65535 for kind in kinds)
        ):
            raise Refusal(403, "restricted: p-gated kinds require #p tag matching your pubkey")
        ids = hex_list(filter_value, "ids")
        state.note_query(ids, kinds)
        authors = hex_list(filter_value, "authors")
        since = bounded_int(filter_value, "since")
        until = bounded_int(filter_value, "until")
        limit = bounded_int(filter_value, "limit")
        matched = [
            event for event in state.events.values()
            if event["kind"] in kinds
            and (ids is None or event["id"] in ids)
            and (authors is None or event["pubkey"] in authors)
            and (since is None or int(event["created_at"]) >= since)
            and (until is None or int(event["created_at"]) <= until)
            and state.visible_to(event, caller)
        ]
        matched.sort(key=lambda event: (-int(event["created_at"]), str(event["id"])))
        results.extend(matched if limit is None else matched[:limit])
    return results


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

    def _authenticate(self, method: str, body: bytes) -> str:
        """Return the token pubkey; raise Refusal(401) like verify_bridge_auth."""
        try:
            token = verify_nip98(
                self.headers.get("Authorization", ""), method, self.server.state.origin + self.path, body,
            )
        except RelayError as error:
            raise Refusal(401, f"NIP-98: {error}") from error
        with self.server.state.lock:
            if token["id"] in self.server.state.seen_tokens:
                raise Refusal(401, "NIP-98: replayed authorization")
            self.server.state.seen_tokens.add(str(token["id"]))
        return str(token["pubkey"])

    def _refuse(self, refusal: Refusal) -> None:
        self._json(refusal.status, {"error": refusal.message})

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        try:
            if parsed.path != "/ci/control/accepted":
                raise Refusal(404, "not found")
            caller = self._authenticate("GET", b"")
            try:
                query = parse_qs(parsed.query, strict_parsing=True)
                if set(query) != {"channel_id", "after_cursor", "limit"} or any(len(values) != 1 for values in query.values()):
                    raise ValueError("query shape")
                channel = query["channel_id"][0]
                after = int(query["after_cursor"][0])
                limit = int(query["limit"][0])
            except (KeyError, ValueError, IndexError) as error:
                raise Refusal(400, "invalid query") from error
            if UUID.fullmatch(channel) is None or after < 0 or limit != 1:
                raise Refusal(400, "invalid query")
            accepted = None
            with self.server.state.lock:
                for cursor, event_channel, event in self.server.state.accepted:
                    if cursor > after and event_channel == channel:
                        # api/ci.rs next_accepted_control: a non-empty result
                        # is gated on the caller's signer authority for the
                        # request's repository; an empty result is not.
                        repository = str(parse_content(event, "CI request")["target_repo_a"])
                        self.server.state.require_signer(repository, caller, int(time.time()))
                        accepted = {"channel_id": channel, "watch_cursor": cursor, "event": event}
                        break
        except Refusal as refusal:
            self._refuse(refusal)
            return
        self._json(200, {"accepted": accepted})

    def do_POST(self) -> None:
        raw = self._body()
        try:
            if self.path not in {"/events", "/query"} or raw is None:
                raise Refusal(404, "not found")
            caller = self._authenticate("POST", raw)
            if self.path == "/query":
                with self.server.state.lock:
                    found = query_events(self.server.state, caller, raw)
                self._json(200, found)
                return
            try:
                event = verify_event(json.loads(raw))
            except (json.JSONDecodeError, RelayError) as error:
                raise Refusal(400, f"invalid event: {error}") from error
            with self.server.state.lock:
                _channel, accepted = admit_event(self.server.state, caller, event, int(time.time()))
        except Refusal as refusal:
            self._refuse(refusal)
            return
        self._json(200, {
            "event_id": event["id"], "accepted": accepted,
            "message": "stored" if accepted else "duplicate:stored",
        })

    def do_PUT(self) -> None:
        parsed = urlsplit(self.path)
        raw = self._body()
        try:
            match = OBJECT_PATH.fullmatch(parsed.path)
            if raw is None or parsed.query or parsed.fragment or match is None:
                raise Refusal(404, "not found")
            caller = self._authenticate("PUT", raw)
            digest = hashlib.sha256(raw).hexdigest()
            if match.group(3) != digest:
                raise Refusal(400, "digest mismatch")
            with self.server.state.lock:
                # api/ci.rs put_ci_evidence: the request event must exist and
                # the caller must be an authorized signer for its repository.
                repository = self.server.state.request_repository(match.group(2))
                self.server.state.require_signer(repository, caller, int(time.time()))
                target = self.server.state.object_root / digest
                if target.exists() and target.read_bytes() != raw:
                    raise Refusal(409, "object collision")
                if not target.exists():
                    target.write_bytes(raw)
                    target.chmod(0o400)
        except Refusal as refusal:
            self._refuse(refusal)
            return
        self._json(200, {"url": self.server.state.origin + parsed.path, "sha256": digest, "byte_length": len(raw)})


class RelayServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[int, int] | tuple[str, int], state: RelayState) -> None:
        super().__init__(address, Handler)
        self.state = state


def state_from_config(config: object, object_root: Path) -> RelayState:
    if (
        not isinstance(config, dict)
        or set(config) != {"origin", "channel", "ci_status_signer_pubkeys"}
        or not isinstance(config["origin"], str)
        or not isinstance(config["channel"], dict)
        or set(config["channel"]) != {"id", "visibility", "members"}
        or not isinstance(config["channel"]["members"], dict)
        or not isinstance(config["ci_status_signer_pubkeys"], list)
    ):
        raise ValueError("relay public config rejected")
    channel = config["channel"]
    return RelayState(
        object_root, config["origin"], str(channel["id"]), str(channel["visibility"]),
        {str(key): str(role) for key, role in channel["members"].items()},
        {str(key) for key in config["ci_status_signer_pubkeys"]},
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--public-config", type=Path, required=True)
    parser.add_argument("--object-root", type=Path, required=True)
    parser.add_argument("--fault-flag", type=Path, help="opt-in fault mode file; absent means no fault")
    arguments = parser.parse_args()
    try:
        config = json.loads(arguments.public_config.read_bytes())
        arguments.object_root.mkdir(mode=0o700, parents=True, exist_ok=False)
        state = state_from_config(config, arguments.object_root)
        if arguments.fault_flag is not None and arguments.fault_flag.is_file():
            state.arm_fault(arguments.fault_flag)
    except (OSError, ValueError):
        return 1
    server = RelayServer(("127.0.0.1", 3443), state)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(arguments.certificate, arguments.private_key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

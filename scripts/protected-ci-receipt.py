#!/usr/bin/env python3
"""Acquire and validate an exact-head GitHub protected-CI receipt.

The receipt is operator-acquired point-in-time evidence. GitHub does not sign
REST responses, so the receipt retains the exact response bodies it was derived
from: the repository, the default-branch ref, the pull request (pull-request
scope), the branch rules, the rulesets, and the check runs. Offline validation
recomputes every recorded hash and replays the retained bodies through the
acquisition sequence, so a hand-edited receipt fails without network access. A
receipt built without contacting GitHub can still be internally consistent, so
consumers must run `validate --reverify`, which requires the live GitHub
authority to match the receipt binding exactly: the rulesets, required
contexts, and exact-head check runs, plus the scope authority. A main receipt
needs the live default-branch head at the receipt head; a pull-request receipt
needs the live pull request open, non-draft, at the receipt head, based on the
default branch, with the base unmoved.
"""

from __future__ import annotations

import argparse
import ctypes
import datetime as dt
from email.utils import parsedate_to_datetime
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
from typing import Any, Callable
from urllib.parse import parse_qsl, urlsplit
import uuid


REPOSITORY = "only21mil/buzz"
HOST = "github.com"
API_ORIGIN = "https://api.github.com"
API_VERSION = "2022-11-28"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_PAGES = 20
MAX_RECORDS = 2_000
MAX_GH_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_RECEIPT_BYTES = 4 * 1024 * 1024
GH_PATH = "/usr/bin/gh"
GH_UID = 0
GH_GID = 0
GH_MODE = 0o755
GH_SHA256 = "16fdbf30d6f97bc5b0fb94745e00fa06ae68beb6c6653d7f584b32602800397d"
RENAME_NOREPLACE = 1
ACQUISITION_SNAPSHOTS = 2
# Retained-body order for each scope. Offline validation replays exactly this
# sequence, so a receipt with bodies missing, reordered, or added fails.
PULL_REQUEST_ACQUISITION = (
    "repository", "pull_request", "base_ref", "snapshot",
    "pull_request", "base_ref", "snapshot",
    "repository", "pull_request", "base_ref",
)
MAIN_ACQUISITION = (
    "repository", "base_ref", "snapshot", "base_ref", "snapshot", "repository", "base_ref",
)
assert PULL_REQUEST_ACQUISITION.count("snapshot") == ACQUISITION_SNAPSHOTS
assert MAIN_ACQUISITION.count("snapshot") == ACQUISITION_SNAPSHOTS
AUTHORITY_PATHS = [
    re.compile(rf"^/repos/{re.escape(REPOSITORY)}$"),
    re.compile(rf"^/repos/{re.escape(REPOSITORY)}/git/ref/heads/main$"),
    re.compile(rf"^/repos/{re.escape(REPOSITORY)}/pulls/[1-9][0-9]*$"),
    re.compile(rf"^/repos/{re.escape(REPOSITORY)}/rules/branches/main$"),
    re.compile(rf"^/repos/{re.escape(REPOSITORY)}/commits/[0-9a-f]{{40}}/check-runs$"),
    re.compile(rf"^/repos/{re.escape(REPOSITORY)}/rulesets/[1-9][0-9]*$"),
    re.compile(r"^/orgs/only21mil/rulesets/[1-9][0-9]*$"),
    re.compile(r"^/enterprises/only21mil/rulesets/[1-9][0-9]*$"),
]


class ReceiptError(Exception):
    exit_code = 4


class ProviderError(ReceiptError):
    exit_code = 3


class GateError(ReceiptError):
    exit_code = 4


class OutputError(ReceiptError):
    exit_code = 5


def refuse(condition: bool, message: str, error: type[ReceiptError] = GateError) -> None:
    if not condition:
        raise error(message)


def object_(value: Any, path: str) -> dict[str, Any]:
    refuse(isinstance(value, dict), f"{path} must be an object")
    return value


def array(value: Any, path: str) -> list[Any]:
    refuse(isinstance(value, list), f"{path} must be an array")
    return value


def text(value: Any, path: str) -> str:
    refuse(isinstance(value, str) and bool(value), f"{path} must be a non-empty string")
    return value


def integer(value: Any, path: str) -> int:
    refuse(isinstance(value, int) and not isinstance(value, bool), f"{path} must be an integer")
    return value


def positive(value: Any, path: str) -> int:
    result = integer(value, path)
    refuse(result > 0, f"{path} must be positive")
    return result


def exact_fields(value: dict[str, Any], required: set[str], path: str) -> None:
    missing = required - value.keys()
    unknown = value.keys() - required
    refuse(not missing, f"{path} missing fields: {sorted(missing)}")
    refuse(not unknown, f"{path} unknown fields: {sorted(unknown)}")


def canonical_json(value: Any) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                           allow_nan=False) + "\n").encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise GateError(f"receipt is not canonical JSON: {exc}") from exc


def require_bounded_json_depth(value: Any, maximum: int = 128) -> None:
    stack = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > maximum:
            raise RecursionError("JSON nesting limit exceeded")
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def iso8601(value: Any, path: str, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    result = text(value, path)
    try:
        parsed = dt.datetime.fromisoformat(result.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GateError(f"{path} must be RFC 3339") from exc
    refuse(parsed.tzinfo is not None, f"{path} must include an offset")
    return result


def sha40(value: Any, path: str) -> str:
    result = text(value, path)
    refuse(SHA40.fullmatch(result) is not None, f"{path} must be a lowercase 40-hex SHA")
    return result


def trusted_repository_url(value: Any, path: str, redact_external: bool = False) -> str | None:
    if redact_external and (not isinstance(value, str) or not value):
        return None
    raw = text(value, path)
    refuse(len(raw) <= 2_048, f"{path} is too long")
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError:
        if redact_external:
            return None
        raise GateError(f"{path} is not a valid URL")
    trusted = (
        parsed.scheme == "https" and parsed.hostname == "github.com" and port is None
        and parsed.username is None and parsed.password is None
        and parsed.query == "" and parsed.fragment == ""
        and parsed.path.startswith(f"/{REPOSITORY}/")
    )
    if redact_external and not trusted:
        return None
    refuse(trusted, f"{path} must be a trusted repository URL")
    return raw


def api_endpoint(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ProviderError("GitHub API URL is invalid") from exc
    if parsed.scheme:
        refuse(parsed.scheme == "https" and parsed.netloc == "api.github.com" and
               parsed.username is None and parsed.password is None and port is None,
               "pagination next URL is off the GitHub API origin", ProviderError)
        refuse(parsed.fragment == "", "pagination next URL is unsafe", ProviderError)
    else:
        refuse(value.startswith("/") and "#" not in value and parsed.netloc == "",
               "invalid GitHub API endpoint", ProviderError)
    path = parsed.path
    try:
        query_items = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    except ValueError as exc:
        raise ProviderError("GitHub API query is malformed") from exc
    refuse(len(query_items) == len({key for key, _ in query_items}),
           "GitHub API query has duplicate keys", ProviderError)
    query = dict(query_items)
    static = {
        "/user",
        f"/repos/{REPOSITORY}",
    }
    no_query_patterns = [
        rf"^/repos/{re.escape(REPOSITORY)}/pulls/[1-9][0-9]*$",
        rf"^/repos/{re.escape(REPOSITORY)}/git/ref/heads/[A-Za-z0-9._%-]+$",
        rf"^/repos/{re.escape(REPOSITORY)}/commits/[0-9a-f]{{40}}$",
        rf"^/repos/{re.escape(REPOSITORY)}/compare/main\.\.\.[0-9a-f]{{40}}$",
        rf"^/repos/{re.escape(REPOSITORY)}/rulesets/[1-9][0-9]*$",
        r"^/orgs/only21mil/rulesets/[1-9][0-9]*$",
        r"^/enterprises/only21mil/rulesets/[1-9][0-9]*$",
    ]
    if path in static or any(re.fullmatch(pattern, path) for pattern in no_query_patterns):
        refuse(not query, f"query is forbidden for {path}", ProviderError)
    elif path == f"/repos/{REPOSITORY}/rules/branches/main":
        refuse(query.get("per_page") == "100" and set(query) <= {"per_page", "page"},
               "branch-rules query is not allowlisted", ProviderError)
        if "page" in query:
            refuse(query["page"].isdigit() and int(query["page"]) >= 2,
                   "pagination page must be at least 2", ProviderError)
    elif re.fullmatch(rf"/repos/{re.escape(REPOSITORY)}/commits/[0-9a-f]{{40}}/check-runs", path):
        refuse(query.get("filter") == "all" and query.get("per_page") == "100" and
               set(query) <= {"filter", "per_page", "page"},
               "check-runs query is not allowlisted", ProviderError)
        if "page" in query:
            refuse(query["page"].isdigit() and int(query["page"]) >= 2,
                   "pagination page must be at least 2", ProviderError)
    else:
        raise ProviderError(f"GitHub API resource is not allowlisted: {path}")
    if parsed.scheme:
        refuse("page" in query, "absolute GitHub URL is allowed only for pagination", ProviderError)
    return value


def retains_body(endpoint: str) -> bool:
    """Whether a request's exact response body is retained in the receipt.

    The repository, default-branch ref, pull request, branch rules, rulesets,
    and check runs are authority the validator replays; other requests keep
    just their body hash.
    """
    path = urlsplit(endpoint).path
    return any(pattern.fullmatch(path) for pattern in AUTHORITY_PATHS)


def parse_headers(raw: str) -> tuple[int, dict[str, str], str]:
    """Parse the final HTTP response emitted by `gh api -i`."""
    normalized = raw.replace("\r\n", "\n")
    starts = [m.start() for m in re.finditer(r"(?m)^HTTP/\S+ \d{3}(?: .*)?\n", normalized)]
    refuse(bool(starts), "GitHub response has no HTTP status", ProviderError)
    block = normalized[starts[-1]:]
    header_text, separator, body = block.partition("\n\n")
    refuse(bool(separator), "GitHub response has no header terminator", ProviderError)
    lines = header_text.splitlines()
    match = re.match(r"^HTTP/\S+ (\d{3})(?: .*)?$", lines[0])
    refuse(match is not None, "GitHub response has an invalid status line", ProviderError)
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(":")
        refuse(bool(separator), "GitHub response has an invalid header", ProviderError)
        headers[name.strip().lower()] = value.strip()
    return int(match.group(1)), headers, body


def bounded_response(raw: Any, endpoint: str) -> str:
    if isinstance(raw, bytes):
        encoded = raw
    elif isinstance(raw, str):
        try:
            encoded = raw.encode("utf-8")
        except UnicodeError as exc:
            raise ProviderError(f"GitHub returned invalid UTF-8 for {endpoint}") from exc
    else:
        raise ProviderError(f"GitHub returned an invalid response type for {endpoint}")
    refuse(len(encoded) <= MAX_GH_RESPONSE_BYTES,
           f"GitHub response exceeds the byte limit for {endpoint}", ProviderError)
    try:
        return encoded.decode("utf-8")
    except UnicodeError as exc:
        raise ProviderError(f"GitHub returned invalid UTF-8 for {endpoint}") from exc


def next_link(value: str | None) -> str | None:
    if not value:
        return None
    for part in value.split(","):
        match = re.match(r'\s*<([^>]+)>\s*;\s*rel="([^"]+)"\s*$', part)
        refuse(match is not None, "GitHub Link header is malformed", ProviderError)
        assert match is not None
        if match.group(2) == "next":
            return api_endpoint(match.group(1))
    return None


class GhClient:
    def __init__(self, gh: str, identity: dict[str, Any] | None = None,
                 runner: Callable[..., subprocess.CompletedProcess[Any]] = subprocess.run):
        self.gh = gh
        self.identity = identity or {
            "path": GH_PATH, "uid": GH_UID, "gid": GH_GID,
            "mode": "0755", "sha256": GH_SHA256,
        }
        self.runner = runner
        self.requests: list[dict[str, Any]] = []

    def request(self, endpoint: str, page: int) -> tuple[Any, str | None, str]:
        endpoint = api_endpoint(endpoint)
        command = [
            self.gh, "api", "--hostname", HOST, "--method", "GET", "-i",
            "-H", "Accept: application/vnd.github+json",
            "-H", f"X-GitHub-Api-Version: {API_VERSION}", endpoint,
        ]
        token = os.environ.get("GH_TOKEN")
        refuse(bool(token), "GH_TOKEN is required", ProviderError)
        env = {
            "GH_TOKEN": token,
            "GH_PROMPT_DISABLED": "1",
            "GH_HOST": HOST,
            "LC_ALL": "C.UTF-8",
            "NO_COLOR": "1",
        }
        try:
            completed = self.runner(command, text=False, capture_output=True, env=env, check=False,
                                    timeout=60)
        except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
            raise ProviderError(f"GitHub GET could not run for {endpoint}") from exc
        refuse(completed.returncode == 0,
               f"GitHub GET failed for {endpoint}", ProviderError)
        response = bounded_response(completed.stdout, endpoint)
        status, headers, body = parse_headers(response)
        refuse(status == 200, f"GitHub GET returned HTTP {status} for {endpoint}", ProviderError)
        request_id = headers.get("x-github-request-id")
        date = headers.get("date")
        refuse(bool(request_id), "GitHub response lacks X-GitHub-Request-Id", ProviderError)
        refuse(bool(date), "GitHub response lacks Date", ProviderError)
        try:
            parsed = json.loads(body)
            require_bounded_json_depth(parsed)
        except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
            raise ProviderError(f"GitHub returned invalid JSON for {endpoint}") from exc
        self.requests.append({
            "endpoint": endpoint, "page": page, "status": status,
            "request_id": request_id, "date": date, "etag": headers.get("etag"),
            "body_sha256": hashlib.sha256(body.encode()).hexdigest(),
            "body": body if retains_body(endpoint) else None,
        })
        return parsed, next_link(headers.get("link")), date

    def one(self, endpoint: str) -> Any:
        body, link, _ = self.request(endpoint, 1)
        refuse(link is None, f"unexpected pagination for {endpoint}", ProviderError)
        return body

    def pages(self, endpoint: str, kind: str) -> list[Any]:
        current: str | None = endpoint
        seen: set[str] = set()
        bodies: list[Any] = []
        for page in range(1, MAX_PAGES + 1):
            assert current is not None
            key = api_endpoint(current)
            refuse(key not in seen, "GitHub pagination cycle", ProviderError)
            seen.add(key)
            body, current, _ = self.request(key, page)
            bodies.append(body)
            if current is None:
                return assemble_pages(bodies, kind)
        raise ProviderError("GitHub pagination page cap exceeded")


def assemble_pages(bodies: list[Any], kind: str) -> list[Any]:
    """Join paginated GitHub bodies into one record list with the same checks live and on replay."""
    records: list[Any] = []
    total: int | None = None
    for body in bodies:
        if kind == "array":
            values = array(body, "GitHub page")
        else:
            envelope = object_(body, "check-runs page")
            page_total = integer(envelope.get("total_count"), "check-runs total_count")
            total = page_total if total is None else total
            refuse(total == page_total, "check-runs total_count changed during pagination", ProviderError)
            values = array(envelope.get("check_runs"), "check-runs")
        records.extend(values)
        refuse(len(records) <= MAX_RECORDS, "GitHub pagination record cap exceeded", ProviderError)
    if kind == "checks":
        refuse(total == len(records), "check-runs total_count does not match pages", ProviderError)
        ids = [positive(object_(item, "check run").get("id"), "check run id") for item in records]
        refuse(len(ids) == len(set(ids)), "duplicate check-run id across pages", ProviderError)
    return records


class RetainedClient:
    """Replay the retained response bodies of a receipt in acquisition order."""

    def __init__(self, records: list[tuple[str, int, Any]]):
        self.records = records
        self.position = 0

    def exhausted(self) -> bool:
        return self.position >= len(self.records)

    def take(self, endpoint: str, page: int) -> Any:
        refuse(self.position < len(self.records),
               f"retained provider bodies end before {endpoint}")
        recorded_endpoint, recorded_page, body = self.records[self.position]
        if page == 1:
            refuse(recorded_endpoint == endpoint and recorded_page == 1,
                   f"retained provider bodies are out of acquisition order at {endpoint}")
        else:
            refuse(recorded_page == page and
                   urlsplit(recorded_endpoint).path == urlsplit(endpoint).path,
                   f"retained pagination is out of order at {endpoint}")
        self.position += 1
        return body

    def one(self, endpoint: str) -> Any:
        return self.take(endpoint, 1)

    def pages(self, endpoint: str, kind: str) -> list[Any]:
        path = urlsplit(endpoint).path
        bodies = [self.take(endpoint, 1)]
        while (self.position < len(self.records) and
               self.records[self.position][1] == len(bodies) + 1 and
               urlsplit(self.records[self.position][0]).path == path):
            bodies.append(self.take(endpoint, len(bodies) + 1))
        return assemble_pages(bodies, kind)


def resolve_gh() -> tuple[str, dict[str, Any]]:
    refuse(bool(os.environ.get("GH_TOKEN")), "GH_TOKEN is required", ProviderError)
    discovered = shutil.which("gh")
    refuse(discovered == GH_PATH, f"gh must resolve exactly to {GH_PATH}", ProviderError)
    try:
        path_info = os.lstat(GH_PATH)
    except OSError as exc:
        raise ProviderError(f"cannot stat pinned gh: {exc}") from exc
    refuse(not stat.S_ISLNK(path_info.st_mode) and stat.S_ISREG(path_info.st_mode),
           "pinned gh must be a non-symlink regular file", ProviderError)
    refuse((path_info.st_uid, path_info.st_gid, stat.S_IMODE(path_info.st_mode)) ==
           (GH_UID, GH_GID, GH_MODE), "pinned gh ownership or mode mismatch", ProviderError)
    fd = os.open(GH_PATH, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        digest = hashlib.sha256()
        while chunk := os.read(fd, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    refuse((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
           (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
           "pinned gh changed while hashing", ProviderError)
    refuse(digest.hexdigest() == GH_SHA256, "pinned gh digest mismatch", ProviderError)
    identity = {
        "path": GH_PATH, "uid": GH_UID, "gid": GH_GID,
        "mode": f"{GH_MODE:04o}", "sha256": GH_SHA256,
    }
    return GH_PATH, identity


def require_pr(value: Any, number: int, head: str, base: str) -> dict[str, Any]:
    pr = object_(value, "pull request")
    refuse(positive(pr.get("number"), "pull request number") == number, "pull request number drift")
    refuse(pr.get("state") == "open" and pr.get("draft") is False,
           "pull request must be open and non-draft")
    head_data = object_(pr.get("head"), "pull request head")
    base_data = object_(pr.get("base"), "pull request base")
    head_repo = object_(head_data.get("repo"), "pull request head repository").get("full_name")
    base_repo = object_(base_data.get("repo"), "pull request base repository").get("full_name")
    refuse(head_repo == REPOSITORY and base_repo == REPOSITORY, "pull request must be internal")
    refuse(sha40(head_data.get("sha"), "pull request head SHA") == head, "pull request head SHA drift")
    refuse(base_data.get("ref") == base, "pull request base ref drift")
    return pr


def require_repository(value: Any, repository_id: int, origin: str) -> dict[str, Any]:
    """Require a repository body to name the pinned repository with main as default."""
    repository = object_(value, origin)
    refuse(repository.get("full_name") == REPOSITORY and
           positive(repository.get("id"), f"{origin} id") == repository_id and
           repository.get("default_branch") == "main",
           f"{origin} authority does not match the receipt")
    return repository


def require_pr_authority(value: Any, number: int, head: str, base_sha: str,
                         origin: str) -> dict[str, Any]:
    """Require a pull-request body to still carry the receipt's scope authority."""
    pr = object_(value, origin)
    refuse(positive(pr.get("number"), f"{origin} number") == number, f"{origin} number drift")
    label = f"{origin} #{number}"
    refuse(pr.get("state") == "open", f"{label} is not open (state {pr.get('state')!r})")
    refuse(pr.get("draft") is False, f"{label} is a draft")
    head_data = object_(pr.get("head"), f"{label} head")
    base_data = object_(pr.get("base"), f"{label} base")
    head_repo = object_(head_data.get("repo"), f"{label} head repository").get("full_name")
    base_repo = object_(base_data.get("repo"), f"{label} base repository").get("full_name")
    refuse(head_repo == REPOSITORY and base_repo == REPOSITORY, f"{label} is not internal")
    pr_head = sha40(head_data.get("sha"), f"{label} head SHA")
    refuse(pr_head == head, f"{label} head is {pr_head}, not the receipt head {head}")
    refuse(base_data.get("ref") == "main", f"{label} base ref is not the default branch main")
    pr_base = sha40(base_data.get("sha"), f"{label} base SHA")
    refuse(pr_base == base_sha,
           f"{label} base moved from {base_sha} to {pr_base}; reacquire the receipt")
    return pr


def require_ref(value: Any, expected_ref: str, expected_sha: str | None = None) -> str:
    ref = object_(value, expected_ref)
    refuse(ref.get("ref") == expected_ref, f"{expected_ref} identity drift")
    commit = object_(ref.get("object"), f"{expected_ref} object")
    refuse(commit.get("type") == "commit", f"{expected_ref} does not resolve to a commit")
    result = sha40(commit.get("sha"), f"{expected_ref} SHA")
    if expected_sha is not None:
        refuse(result == expected_sha, f"{expected_ref} SHA drift")
    return result


def required_checks(branch_rules: list[Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    checks: set[tuple[str, int]] = set()
    names: dict[str, int] = {}
    rulesets: set[tuple[int, str, str]] = set()
    strict_values: list[bool] = []
    for index, raw in enumerate(branch_rules):
        rule = object_(raw, f"branch rule {index}")
        ruleset_id = positive(rule.get("ruleset_id"), f"branch rule {index} ruleset_id")
        source_type = text(rule.get("ruleset_source_type"),
                           f"branch rule {index} ruleset_source_type")
        source = text(rule.get("ruleset_source"), f"branch rule {index} ruleset_source")
        rulesets.add((ruleset_id, source_type, source))
        if rule.get("type") != "required_status_checks":
            continue
        parameters = object_(rule.get("parameters"), f"branch rule {index} parameters")
        strict = parameters.get("strict_required_status_checks_policy")
        refuse(isinstance(strict, bool), "required-status-check strict policy must be boolean")
        strict_values.append(strict)
        for raw_check in array(parameters.get("required_status_checks"), "required status checks"):
            check = object_(raw_check, "required status check")
            name = text(check.get("context"), "required status check context")
            app_id = positive(check.get("integration_id"), "required status check integration_id")
            refuse(name not in names or names[name] == app_id,
                   f"required check {name!r} is mapped to more than one GitHub App")
            names[name] = app_id
            checks.add((name, app_id))
    refuse(bool(checks), "no app-bound required status checks apply")
    refuse(bool(strict_values) and all(strict_values), "all required-status-check rules must be strict")
    check_values = [{"name": name, "integration_id": app_id} for name, app_id in sorted(checks)]
    ruleset_values = [
        {"id": ruleset_id, "source_type": source_type, "source": source}
        for ruleset_id, source_type, source in sorted(rulesets)
    ]
    return check_values, ruleset_values, True


def confirm_active_rulesets(client: GhClient,
                            rulesets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    confirmed = []
    for ruleset in rulesets:
        source_type = ruleset["source_type"]
        source = ruleset["source"]
        ruleset_id = ruleset["id"]
        if source_type == "Repository":
            refuse(source.count("/") == 1, "repository ruleset source is invalid", ProviderError)
            endpoint = f"/repos/{source}/rulesets/{ruleset_id}"
        elif source_type == "Organization":
            refuse("/" not in source, "organization ruleset source is invalid", ProviderError)
            endpoint = f"/orgs/{source}/rulesets/{ruleset_id}"
        elif source_type == "Enterprise":
            refuse("/" not in source, "enterprise ruleset source is invalid", ProviderError)
            endpoint = f"/enterprises/{source}/rulesets/{ruleset_id}"
        else:
            raise ProviderError(f"unsupported ruleset source type {source_type!r}")
        metadata = object_(client.one(endpoint), f"ruleset {ruleset_id}")
        refuse(positive(metadata.get("id"), f"ruleset {ruleset_id} id") == ruleset_id,
               f"ruleset {ruleset_id} identity drift", ProviderError)
        refuse(metadata.get("source_type") == source_type and metadata.get("source") == source,
               f"ruleset {ruleset_id} source drift", ProviderError)
        refuse(metadata.get("enforcement") == "active",
               f"ruleset {ruleset_id} is not active")
        name = text(metadata.get("name"), f"ruleset {ruleset_id} name")
        target = text(metadata.get("target"), f"ruleset {ruleset_id} target")
        bypass_actors = array(metadata.get("bypass_actors"), f"ruleset {ruleset_id} bypass_actors")
        conditions = object_(metadata.get("conditions"), f"ruleset {ruleset_id} conditions")
        rules = array(metadata.get("rules"), f"ruleset {ruleset_id} rules")
        relevant = {
            "id": ruleset_id, "name": name, "target": target,
            "source_type": source_type, "source": source, "enforcement": "active",
            "bypass_actors": bypass_actors, "conditions": conditions, "rules": rules,
        }
        confirmed.append({
            "id": ruleset_id, "name": name, "target": target,
            "source_type": source_type, "source": source, "enforcement": "active",
            "metadata_sha256": sha256_json(relevant),
            "bypass_actors_sha256": sha256_json(bypass_actors),
            "conditions_sha256": sha256_json(conditions),
            "rules_sha256": sha256_json(rules),
        })
    return confirmed


def select_checks(raw_runs: list[Any], required: list[dict[str, Any]], head: str) -> list[dict[str, Any]]:
    runs = [object_(item, "check run") for item in raw_runs]
    result: list[dict[str, Any]] = []
    for requirement in required:
        name = requirement["name"]
        app_id = requirement["integration_id"]
        matches = [
            run for run in runs
            if run.get("name") == name
            and object_(run.get("app"), "check run app").get("id") == app_id
        ]
        refuse(bool(matches), f"required check {name!r} has no run from app {app_id}")
        matches.sort(key=lambda item: positive(item.get("id"), "check run id"), reverse=True)
        latest = matches[0]
        refuse(sha40(latest.get("head_sha"), f"{name} head SHA") == head,
               f"required check {name!r} is not for the exact head")
        refuse(latest.get("status") == "completed", f"required check {name!r} is not completed")
        refuse(latest.get("conclusion") == "success", f"required check {name!r} did not succeed")
        started = iso8601(latest.get("started_at"), f"{name} started_at")
        completed = iso8601(latest.get("completed_at"), f"{name} completed_at")
        assert started is not None and completed is not None
        refuse(dt.datetime.fromisoformat(started.replace("Z", "+00:00")) <=
               dt.datetime.fromisoformat(completed.replace("Z", "+00:00")),
               f"required check {name!r} completed before it started")
        suite = object_(latest.get("check_suite"), f"{name} check_suite")
        app = object_(latest.get("app"), f"{name} app")
        superseded = []
        for old in matches[1:]:
            old_suite = object_(old.get("check_suite"), f"{name} superseded check_suite")
            superseded.append({
                "check_run_id": positive(old.get("id"), "superseded check run id"),
                "check_suite_id": positive(old_suite.get("id"), "superseded check suite id"),
                "provider_status": text(old.get("status"), "superseded status"),
                "conclusion": old.get("conclusion"),
                "started_at": iso8601(old.get("started_at"), "superseded started_at", True),
                "completed_at": iso8601(old.get("completed_at"), "superseded completed_at", True),
            })
        result.append({
            "name": name, "status": "PASS", "integration_id": app_id,
            "app_slug": text(app.get("slug"), f"{name} app slug"), "head_sha": head,
            "check_run_id": positive(latest.get("id"), f"{name} check run id"),
            "check_suite_id": positive(suite.get("id"), f"{name} check suite id"),
            "provider_status": "completed", "conclusion": "success",
            "started_at": started, "completed_at": completed,
            "html_url": trusted_repository_url(latest.get("html_url"), f"{name} html_url"),
            "details_url": trusted_repository_url(latest.get("details_url"),
                                                   f"{name} details_url", redact_external=True),
            "superseded": superseded,
        })
    return result


def snapshot(client: GhClient, owner: str, repo: str, head: str, base: str) -> dict[str, Any]:
    encoded_base = base.replace("/", "%2F")
    rules_endpoint = f"/repos/{owner}/{repo}/rules/branches/{encoded_base}?per_page=100"
    branch_rules = client.pages(rules_endpoint, "array")
    required, rulesets, strict = required_checks(branch_rules)
    confirmed_rulesets = confirm_active_rulesets(client, rulesets)
    runs = client.pages(f"/repos/{owner}/{repo}/commits/{head}/check-runs?filter=all&per_page=100",
                        "checks")
    return {
        "strict": strict,
        "branch_rules_sha256": sha256_json(branch_rules),
        "rulesets": confirmed_rulesets,
        "required_checks": required,
        "checks": select_checks(runs, required, head),
    }


def build_receipt(client: GhClient, number: int, head: str, base: str) -> dict[str, Any]:
    refuse(REPOSITORY.count("/") == 1, "invalid pinned repository", ProviderError)
    owner, repo = REPOSITORY.split("/")
    viewer = object_(client.one("/user"), "viewer")
    repository = object_(client.one(f"/repos/{owner}/{repo}"), "repository")
    refuse(repository.get("full_name") == REPOSITORY, "repository identity drift", ProviderError)
    refuse(repository.get("default_branch") == base, "base is not the repository default branch")
    pr_endpoint = f"/repos/{owner}/{repo}/pulls/{number}"
    pr_a = require_pr(client.one(pr_endpoint), number, head, base)
    base_ref_endpoint = f"/repos/{owner}/{repo}/git/ref/heads/{base.replace('/', '%2F')}"
    head_ref_name = text(object_(pr_a.get("head"), "pull request head").get("ref"), "head ref")
    head_ref_endpoint = f"/repos/{owner}/{repo}/git/ref/heads/{head_ref_name.replace('/', '%2F')}"
    base_sha = require_ref(client.one(base_ref_endpoint), f"refs/heads/{base}")
    refuse(sha40(object_(pr_a.get("base"), "pull request base").get("sha"),
                 "pull request base SHA") == base_sha,
           "pull request base SHA does not match the base ref")
    require_ref(client.one(head_ref_endpoint), f"refs/heads/{head_ref_name}", head)
    commit = object_(client.one(f"/repos/{owner}/{repo}/commits/{head}"), "commit")
    refuse(sha40(commit.get("sha"), "commit SHA") == head, "commit identity drift")
    compare = object_(client.one(f"/repos/{owner}/{repo}/compare/{base}...{head}"), "compare")
    merge_base = sha40(object_(compare.get("merge_base_commit"), "merge base").get("sha"),
                       "merge base SHA")
    refuse(merge_base == base_sha and integer(compare.get("behind_by"), "behind_by") == 0,
           "head is behind or not based on the exact base")
    snap_a = snapshot(client, owner, repo, head, base)
    pr_b = require_pr(client.one(pr_endpoint), number, head, base)
    base_sha_b = require_ref(client.one(base_ref_endpoint), f"refs/heads/{base}", base_sha)
    refuse(sha40(object_(pr_b.get("base"), "pull request base").get("sha"),
                 "pull request base SHA") == base_sha,
           "pull request base SHA drift")
    require_ref(client.one(head_ref_endpoint), f"refs/heads/{head_ref_name}", head)
    snap_b = snapshot(client, owner, repo, head, base)

    def pr_authority(pr: dict[str, Any]) -> dict[str, Any]:
        pr_head = object_(pr.get("head"), "pull request head")
        pr_base = object_(pr.get("base"), "pull request base")
        return {
            "number": pr.get("number"), "state": pr.get("state"), "draft": pr.get("draft"),
            "head_sha": pr_head.get("sha"), "head_ref": pr_head.get("ref"),
            "head_repo": object_(pr_head.get("repo"), "pull request head repository").get("full_name"),
            "base_sha": pr_base.get("sha"), "base_ref": pr_base.get("ref"),
            "base_repo": object_(pr_base.get("repo"), "pull request base repository").get("full_name"),
        }

    repository_c = object_(client.one(f"/repos/{owner}/{repo}"), "final repository")
    refuse(repository_c.get("full_name") == REPOSITORY and
           repository_c.get("default_branch") == base and
           positive(repository_c.get("id"), "final repository id") ==
           positive(repository.get("id"), "repository id"),
           "repository authority drifted after snapshot B", ProviderError)
    pr_c = require_pr(client.one(pr_endpoint), number, head, base)
    base_sha_c = require_ref(client.one(base_ref_endpoint), f"refs/heads/{base}", base_sha)
    require_ref(client.one(head_ref_endpoint), f"refs/heads/{head_ref_name}", head)
    refuse(pr_authority(pr_a) == pr_authority(pr_b) == pr_authority(pr_c) and
           base_sha_b == base_sha_c == base_sha and snap_a == snap_b,
           "protected-CI authority drifted during acquisition", ProviderError)
    final_date = text(client.requests[-1].get("date"), "final response Date")
    try:
        parsed_final_date = parsedate_to_datetime(final_date)
        refuse(parsed_final_date.tzinfo is not None, "final GitHub Date header lacks a timezone",
               ProviderError)
        timestamp = parsed_final_date.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError) as exc:
        raise ProviderError("final GitHub Date header is invalid") from exc
    base_data = object_(pr_a.get("base"), "pull request base")
    return {
        "schema_version": 1, "source": "protected-ci", "scope": "pull-request",
        "repository": REPOSITORY,
        "head_sha": head, "timestamp": timestamp, "overall": "PASS",
        "protected": True, "full_exact_head": True,
        "provider": {
            "kind": "github-rest", "host": HOST, "api_origin": API_ORIGIN,
            "api_version": API_VERSION,
            "client": client.identity,
            "viewer": {"login": text(viewer.get("login"), "viewer login"),
                       "id": positive(viewer.get("id"), "viewer id")},
            "repository_id": positive(repository.get("id"), "repository id"),
            "requests": client.requests,
        },
        "pull_request": {
            "number": number, "url": text(pr_a.get("html_url"), "pull request URL"),
            "state": "open", "draft": False, "head_repo": REPOSITORY,
            "head_ref": head_ref_name, "head_sha": head, "base_repo": REPOSITORY,
            "base_ref": base, "base_sha": base_sha, "merge_base_sha": merge_base,
            "behind_by": 0,
        },
        "protection": {
            "base_ref": f"refs/heads/{base}", "base_sha": base_sha,
            "strict": snap_a["strict"], "branch_rules_sha256": snap_a["branch_rules_sha256"],
            "rulesets": snap_a["rulesets"], "required_checks": snap_a["required_checks"],
        },
        "checks": snap_a["checks"],
    }


def build_main_receipt(client: GhClient, head: str, branch: str) -> dict[str, Any]:
    owner, repo = REPOSITORY.split("/")
    viewer = object_(client.one("/user"), "viewer")
    repository = object_(client.one(f"/repos/{owner}/{repo}"), "repository")
    refuse(repository.get("full_name") == REPOSITORY, "repository identity drift", ProviderError)
    refuse(repository.get("default_branch") == branch, "branch is not the repository default branch")
    ref_endpoint = f"/repos/{owner}/{repo}/git/ref/heads/{branch}"
    require_ref(client.one(ref_endpoint), f"refs/heads/{branch}", head)
    commit = object_(client.one(f"/repos/{owner}/{repo}/commits/{head}"), "commit")
    refuse(sha40(commit.get("sha"), "commit SHA") == head, "commit identity drift")
    snap_a = snapshot(client, owner, repo, head, branch)
    require_ref(client.one(ref_endpoint), f"refs/heads/{branch}", head)
    snap_b = snapshot(client, owner, repo, head, branch)
    repository_c = object_(client.one(f"/repos/{owner}/{repo}"), "final repository")
    refuse(repository_c.get("full_name") == REPOSITORY and
           repository_c.get("default_branch") == branch and
           positive(repository_c.get("id"), "final repository id") ==
           positive(repository.get("id"), "repository id"),
           "repository authority drifted after snapshot B", ProviderError)
    require_ref(client.one(ref_endpoint), f"refs/heads/{branch}", head)
    refuse(snap_a == snap_b, "protected-CI authority drifted during main acquisition",
           ProviderError)
    final_date = text(client.requests[-1].get("date"), "final response Date")
    try:
        parsed_final_date = parsedate_to_datetime(final_date)
        refuse(parsed_final_date.tzinfo is not None, "final GitHub Date header lacks a timezone",
               ProviderError)
        timestamp = parsed_final_date.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError) as exc:
        raise ProviderError("final GitHub Date header is invalid") from exc
    return {
        "schema_version": 1, "source": "protected-ci", "scope": "main",
        "repository": REPOSITORY, "head_sha": head, "timestamp": timestamp,
        "overall": "PASS", "protected": True, "full_exact_head": True,
        "provider": {
            "kind": "github-rest", "host": HOST, "api_origin": API_ORIGIN,
            "api_version": API_VERSION, "client": client.identity,
            "viewer": {"login": text(viewer.get("login"), "viewer login"),
                       "id": positive(viewer.get("id"), "viewer id")},
            "repository_id": positive(repository.get("id"), "repository id"),
            "requests": client.requests,
        },
        "pull_request": None,
        "protection": {
            "base_ref": f"refs/heads/{branch}", "base_sha": head,
            "strict": snap_a["strict"], "branch_rules_sha256": snap_a["branch_rules_sha256"],
            "rulesets": snap_a["rulesets"], "required_checks": snap_a["required_checks"],
        },
        "checks": snap_a["checks"],
    }


def validate_receipt(value: Any, repository: str, head: str,
                     scope: str, now: dt.datetime, max_age_seconds: int) -> dict[str, Any]:
    receipt = object_(value, "receipt")
    top = {"schema_version", "source", "scope", "repository", "head_sha", "timestamp", "overall",
           "protected", "full_exact_head", "provider", "pull_request", "protection", "checks"}
    exact_fields(receipt, top, "receipt")
    refuse(receipt["schema_version"] == 1 and receipt["source"] == "protected-ci",
           "unsupported receipt schema")
    refuse(scope in ("pull-request", "main") and receipt["scope"] == scope,
           "receipt scope mismatch")
    refuse(repository == REPOSITORY and receipt["repository"] == repository, "repository mismatch")
    refuse(sha40(head, "expected head") == receipt["head_sha"], "head mismatch")
    refuse(receipt["overall"] == "PASS" and receipt["protected"] is True and
           receipt["full_exact_head"] is True, "receipt is not a full protected-CI pass")
    timestamp_text = iso8601(receipt["timestamp"], "receipt timestamp")
    assert timestamp_text is not None
    timestamp = dt.datetime.fromisoformat(timestamp_text.replace("Z", "+00:00"))
    refuse(now.tzinfo is not None, "validation clock must include an offset")
    age = (now.astimezone(dt.timezone.utc) - timestamp.astimezone(dt.timezone.utc)).total_seconds()
    refuse(0 <= age <= max_age_seconds, "receipt is future-dated or stale")
    provider = object_(receipt["provider"], "provider")
    exact_fields(provider, {"kind", "host", "api_origin", "api_version", "client", "viewer",
                            "repository_id", "requests"}, "provider")
    refuse((provider["kind"], provider["host"], provider["api_origin"], provider["api_version"]) ==
           ("github-rest", HOST, API_ORIGIN, API_VERSION), "provider identity mismatch")
    client = object_(provider["client"], "provider client")
    exact_fields(client, {"path", "uid", "gid", "mode", "sha256"}, "provider client")
    refuse(client == {"path": GH_PATH, "uid": GH_UID, "gid": GH_GID,
                      "mode": f"{GH_MODE:04o}", "sha256": GH_SHA256},
           "provider client identity mismatch")
    viewer = object_(provider["viewer"], "provider viewer")
    exact_fields(viewer, {"login", "id"}, "provider viewer")
    text(viewer["login"], "provider viewer login")
    positive(viewer["id"], "provider viewer id")
    positive(provider["repository_id"], "provider repository_id")
    requests = array(provider["requests"], "provider requests")
    refuse(bool(requests), "provider requests are empty")
    retained: list[tuple[str, int, Any]] = []
    for index, raw_request in enumerate(requests):
        request = object_(raw_request, f"provider request {index}")
        exact_fields(request, {"endpoint", "page", "status", "request_id", "date", "etag",
                               "body_sha256", "body"}, f"provider request {index}")
        endpoint = api_endpoint(text(request["endpoint"], f"provider request {index} endpoint"))
        page = positive(request["page"], f"provider request {index} page")
        refuse(request["status"] == 200, f"provider request {index} did not return HTTP 200")
        text(request["request_id"], f"provider request {index} request_id")
        text(request["date"], f"provider request {index} date")
        refuse(request["etag"] is None or isinstance(request["etag"], str) and bool(request["etag"]),
               f"provider request {index} etag is invalid")
        body_sha256 = text(request["body_sha256"], f"provider request {index} body_sha256")
        refuse(SHA256.fullmatch(body_sha256) is not None,
               f"provider request {index} body_sha256 is invalid")
        body = request["body"]
        if not retains_body(endpoint):
            refuse(body is None, f"provider request {index} must not retain a body")
            continue
        text(body, f"provider request {index} body")
        refuse(len(body.encode("utf-8")) <= MAX_GH_RESPONSE_BYTES,
               f"provider request {index} body exceeds the byte limit")
        refuse(hashlib.sha256(body.encode("utf-8")).hexdigest() == body_sha256,
               f"provider request {index} retained body does not match body_sha256")
        try:
            parsed_body = json.loads(body)
            require_bounded_json_depth(parsed_body)
        except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
            raise GateError(f"provider request {index} retained body is not valid JSON") from exc
        retained.append((endpoint, page, parsed_body))
    refuse(bool(retained), "receipt retains no provider bodies")
    try:
        final_date = parsedate_to_datetime(requests[-1]["date"])
        refuse(final_date.tzinfo is not None, "final provider Date lacks a timezone")
        final_timestamp = final_date.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError) as exc:
        raise GateError("final provider Date is invalid") from exc
    refuse(final_timestamp == timestamp_text, "receipt timestamp is not bound to the final provider Date")
    if scope == "pull-request":
        pr = object_(receipt["pull_request"], "pull request")
        exact_fields(pr, {"number", "url", "state", "draft", "head_repo", "head_ref", "head_sha",
                          "base_repo", "base_ref", "base_sha", "merge_base_sha", "behind_by"},
                     "pull request")
        positive(pr["number"], "pull request number")
        trusted_repository_url(pr["url"], "pull request URL")
        text(pr["head_ref"], "pull request head_ref")
        sha40(pr["head_sha"], "pull request head_sha")
        sha40(pr["base_sha"], "pull request base_sha")
        sha40(pr["merge_base_sha"], "pull request merge_base_sha")
        refuse(pr.get("head_sha") == head and pr.get("head_repo") == repository and
               pr.get("base_repo") == repository and pr.get("state") == "open" and
               pr.get("draft") is False and pr.get("behind_by") == 0 and
               pr.get("base_ref") == "main" and pr.get("base_sha") == pr.get("merge_base_sha"),
               "pull request binding mismatch")
        base_sha = pr["base_sha"]
    else:
        refuse(receipt["pull_request"] is None, "main receipt must not carry pull-request authority")
        base_sha = head
    protection = object_(receipt["protection"], "protection")
    exact_fields(protection, {"base_ref", "base_sha", "strict", "branch_rules_sha256",
                              "rulesets", "required_checks"}, "protection")
    sha40(protection["base_sha"], "protection base_sha")
    refuse(SHA256.fullmatch(text(protection["branch_rules_sha256"],
                                 "protection branch_rules_sha256")) is not None,
           "protection branch_rules_sha256 is invalid")
    refuse(protection.get("strict") is True and protection.get("base_sha") == base_sha,
           "protection binding mismatch")
    refuse(protection.get("base_ref") == "refs/heads/main", "protection base_ref mismatch")
    raw_rulesets = array(protection["rulesets"], "rulesets")
    refuse(bool(raw_rulesets), "rulesets are empty")
    ruleset_keys = []
    for index, raw_ruleset in enumerate(raw_rulesets):
        ruleset = object_(raw_ruleset, f"ruleset {index}")
        exact_fields(ruleset, {"id", "name", "target", "source_type", "source", "enforcement",
                               "metadata_sha256", "bypass_actors_sha256", "conditions_sha256",
                               "rules_sha256"}, f"ruleset {index}")
        ruleset_keys.append((positive(ruleset["id"], f"ruleset {index} id"),
                             text(ruleset["source_type"], f"ruleset {index} source_type"),
                             text(ruleset["source"], f"ruleset {index} source")))
        text(ruleset["name"], f"ruleset {index} name")
        text(ruleset["target"], f"ruleset {index} target")
        refuse(ruleset["enforcement"] == "active", f"ruleset {index} is not active")
        for hash_field in ("metadata_sha256", "bypass_actors_sha256", "conditions_sha256",
                           "rules_sha256"):
            refuse(SHA256.fullmatch(text(ruleset[hash_field],
                                         f"ruleset {index} {hash_field}")) is not None,
                   f"ruleset {index} {hash_field} is invalid")
    refuse(ruleset_keys == sorted(set(ruleset_keys)), "rulesets must be sorted and unique")
    required = array(protection["required_checks"], "required checks")
    checks = array(receipt["checks"], "checks")
    expected = []
    for index, raw_required in enumerate(required):
        required_check = object_(raw_required, f"required check {index}")
        exact_fields(required_check, {"name", "integration_id"}, f"required check {index}")
        expected.append((text(required_check["name"], f"required check {index} name"),
                         positive(required_check["integration_id"],
                                  f"required check {index} integration_id")))
    actual = []
    check_fields = {
        "name", "status", "integration_id", "app_slug", "head_sha", "check_run_id",
        "check_suite_id", "provider_status", "conclusion", "started_at", "completed_at",
        "html_url", "details_url", "superseded",
    }
    superseded_fields = {"check_run_id", "check_suite_id", "provider_status", "conclusion",
                         "started_at", "completed_at"}
    for index, raw_check in enumerate(checks):
        check = object_(raw_check, f"check {index}")
        exact_fields(check, check_fields, f"check {index}")
        name = text(check["name"], f"check {index} name")
        app_id = positive(check["integration_id"], f"check {index} integration_id")
        actual.append((name, app_id))
        text(check["app_slug"], f"check {index} app_slug")
        sha40(check["head_sha"], f"check {index} head_sha")
        latest_id = positive(check["check_run_id"], f"check {index} check_run_id")
        positive(check["check_suite_id"], f"check {index} check_suite_id")
        started_text = iso8601(check["started_at"], f"check {index} started_at")
        completed_text = iso8601(check["completed_at"], f"check {index} completed_at")
        assert started_text is not None and completed_text is not None
        refuse(dt.datetime.fromisoformat(started_text.replace("Z", "+00:00")) <=
               dt.datetime.fromisoformat(completed_text.replace("Z", "+00:00")),
               f"check {index} completed before it started")
        trusted_repository_url(check["html_url"], f"check {index} html_url")
        refuse(check["details_url"] is None or
               trusted_repository_url(check["details_url"], f"check {index} details_url") is not None,
               f"check {index} details_url is invalid")
        old_ids = []
        for old_index, raw_old in enumerate(array(check["superseded"], f"check {index} superseded")):
            old = object_(raw_old, f"check {index} superseded {old_index}")
            exact_fields(old, superseded_fields, f"check {index} superseded {old_index}")
            old_id = positive(old["check_run_id"], f"check {index} superseded {old_index} id")
            refuse(old_id < latest_id, f"check {index} superseded id is not older")
            old_ids.append(old_id)
            positive(old["check_suite_id"], f"check {index} superseded {old_index} suite id")
            text(old["provider_status"], f"check {index} superseded {old_index} status")
            refuse(old["conclusion"] is None or
                   isinstance(old["conclusion"], str) and bool(old["conclusion"]),
                   f"check {index} superseded {old_index} conclusion is invalid")
            iso8601(old["started_at"], f"check {index} superseded {old_index} started_at", True)
            iso8601(old["completed_at"], f"check {index} superseded {old_index} completed_at", True)
        refuse(old_ids == sorted(set(old_ids), reverse=True),
               f"check {index} superseded ids must be descending and unique")
    refuse(bool(expected) and expected == sorted(set(expected)) and actual == expected,
           "required check inventory mismatch")
    for check in checks:
        refuse(check.get("status") == "PASS" and check.get("provider_status") == "completed" and
               check.get("conclusion") == "success" and check.get("head_sha") == head,
               "check is not an exact-head success")
    replay_retained_bodies(retained, receipt)
    return receipt


def receipt_binding(receipt: dict[str, Any]) -> dict[str, Any]:
    """The authority a snapshot must reproduce for this receipt."""
    protection = receipt["protection"]
    return {
        "strict": protection["strict"],
        "branch_rules_sha256": protection["branch_rules_sha256"],
        "rulesets": protection["rulesets"],
        "required_checks": protection["required_checks"],
        "checks": receipt["checks"],
    }


def require_binding_match(actual: dict[str, Any], receipt: dict[str, Any], origin: str) -> None:
    binding = receipt_binding(receipt)
    for name in ("strict", "branch_rules_sha256", "required_checks", "rulesets", "checks"):
        refuse(actual[name] == binding[name], f"{origin} {name} differs from the receipt binding")


def replay_retained_bodies(retained: list[tuple[str, int, Any]], receipt: dict[str, Any]) -> None:
    """Replay the retained bodies through the acquisition sequence for the receipt's scope.

    Every recorded hash is recomputed here, and every retained repository,
    default-branch ref, and pull-request body must carry the scope authority the
    receipt claims.
    """
    owner, repo = REPOSITORY.split("/")
    client = RetainedClient(retained)
    head = receipt["head_sha"]
    base_sha = receipt["protection"]["base_sha"]
    repository_id = receipt["provider"]["repository_id"]
    if receipt["scope"] == "pull-request":
        steps = PULL_REQUEST_ACQUISITION
        number = receipt["pull_request"]["number"]
    else:
        steps = MAIN_ACQUISITION
        number = 0
    replays = 0
    try:
        for step in steps:
            if step == "repository":
                require_repository(client.one(f"/repos/{owner}/{repo}"), repository_id,
                                   "retained repository")
            elif step == "base_ref":
                require_ref(client.one(f"/repos/{owner}/{repo}/git/ref/heads/main"),
                            "refs/heads/main", base_sha)
            elif step == "pull_request":
                require_pr_authority(client.one(f"/repos/{owner}/{repo}/pulls/{number}"),
                                     number, head, base_sha, "retained pull request")
            else:
                require_binding_match(snapshot(client, owner, repo, head, "main"),
                                      receipt, "retained provider bodies")
                replays += 1
    except ProviderError as exc:
        raise GateError(f"retained provider bodies are inconsistent: {exc}") from exc
    refuse(client.exhausted(), "receipt retains provider bodies beyond the acquisition sequence")
    refuse(replays == ACQUISITION_SNAPSHOTS,
           f"receipt must retain exactly {ACQUISITION_SNAPSHOTS} acquisition snapshots")


def reverify_receipt(receipt: dict[str, Any], client: GhClient) -> None:
    """Require the live GitHub authority to still match an already validated receipt.

    Beyond the rulesets, required contexts, and exact-head check runs, the
    receipt's scope authority is re-read live: a main receipt needs
    refs/heads/main at the receipt head; a pull-request receipt needs the pull
    request open, non-draft, at the receipt head, based on main, with both the
    pull request's base SHA and the live main head equal to the recorded base.
    """
    owner, repo = REPOSITORY.split("/")
    head = receipt["head_sha"]
    require_repository(client.one(f"/repos/{owner}/{repo}"),
                       receipt["provider"]["repository_id"], "live repository")
    main_endpoint = f"/repos/{owner}/{repo}/git/ref/heads/main"
    if receipt["scope"] == "main":
        live_main = require_ref(client.one(main_endpoint), "refs/heads/main")
        refuse(live_main == head,
               f"live refs/heads/main is at {live_main}, not the receipt head {head}")
    else:
        pr = receipt["pull_request"]
        number = pr["number"]
        require_pr_authority(client.one(f"/repos/{owner}/{repo}/pulls/{number}"),
                             number, head, pr["base_sha"], "live pull request")
        live_main = require_ref(client.one(main_endpoint), "refs/heads/main")
        refuse(live_main == pr["base_sha"],
               f"live refs/heads/main moved from {pr['base_sha']} to {live_main}; "
               "reacquire the receipt")
    require_binding_match(snapshot(client, owner, repo, head, "main"), receipt, "live GitHub")


def rename_noreplace(dir_fd: int, source: str, destination: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    refuse(renameat2 is not None, "renameat2 is required for create-only publication", OutputError)
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
                          ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    result = renameat2(dir_fd, os.fsencode(source), dir_fd, os.fsencode(destination),
                       RENAME_NOREPLACE)
    if result != 0:
        error_number = ctypes.get_errno()
        if error_number == errno.EEXIST:
            raise OutputError("output already exists")
        raise OutputError(f"atomic create-only rename failed: {os.strerror(error_number)}")


def safe_publish(path: Path, value: Any) -> None:
    refuse(path.is_absolute(), "output path must be absolute", OutputError)
    refuse(path.name not in ("", ".", ".."), "output basename is invalid", OutputError)
    parent = path.parent
    data = canonical_json(value)
    refuse(len(data) <= MAX_RECEIPT_BYTES, "receipt exceeds the size limit", OutputError)
    try:
        parent_info = os.lstat(parent)
        refuse(stat.S_ISDIR(parent_info.st_mode) and not stat.S_ISLNK(parent_info.st_mode),
               "output parent must be a non-symlink directory", OutputError)
        refuse(parent.resolve(strict=True) == parent, "output parent path must be canonical", OutputError)
        dir_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise OutputError(f"cannot open output parent: {exc}") from exc
    temporary = f".{path.name}.{uuid.uuid4().hex}.tmp"
    published = False
    completed = False
    file_identity: tuple[int, int] | None = None
    try:
        opened_parent = os.fstat(dir_fd)
        refuse((opened_parent.st_dev, opened_parent.st_ino) ==
               (parent_info.st_dev, parent_info.st_ino), "output parent changed before open", OutputError)
        refuse(opened_parent.st_uid == os.geteuid() and stat.S_IMODE(opened_parent.st_mode) == 0o700,
               "output parent must be owned by the caller with mode 0700", OutputError)
        try:
            os.stat(path.name, dir_fd=dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise OutputError("output already exists")
        fd = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=dir_fd)
        try:
            initial = os.fstat(fd)
            file_identity = (initial.st_dev, initial.st_ino)
            refuse(stat.S_ISREG(initial.st_mode) and stat.S_IMODE(initial.st_mode) == 0o600 and
                   initial.st_uid == os.geteuid() and initial.st_gid == os.getegid() and
                   initial.st_nlink == 1, "temporary receipt metadata mismatch", OutputError)
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                refuse(written > 0, "short write while publishing receipt", OutputError)
                view = view[written:]
            os.fsync(fd)
            os.lseek(fd, 0, os.SEEK_SET)
            readback = bytearray()
            while chunk := os.read(fd, 1024 * 1024):
                readback.extend(chunk)
                refuse(len(readback) <= MAX_RECEIPT_BYTES,
                       "temporary receipt exceeded the size limit", OutputError)
            refuse(bytes(readback) == data, "temporary receipt readback mismatch", OutputError)
            rename_noreplace(dir_fd, temporary, path.name)
            published = True
            final_fd = os.fstat(fd)
            final_path = os.stat(path.name, dir_fd=dir_fd, follow_symlinks=False)
            refuse((final_fd.st_dev, final_fd.st_ino) == file_identity and
                   (final_path.st_dev, final_path.st_ino) == file_identity,
                   "published receipt identity mismatch", OutputError)
            refuse(stat.S_ISREG(final_path.st_mode) and stat.S_IMODE(final_path.st_mode) == 0o600 and
                   final_path.st_uid == os.geteuid() and final_path.st_gid == os.getegid() and
                   final_path.st_nlink == 1 and final_path.st_size == len(data),
                   "published receipt metadata mismatch", OutputError)
            os.fsync(dir_fd)
            final_parent = os.fstat(dir_fd)
            final_parent_path = os.lstat(parent)
            refuse((final_parent.st_dev, final_parent.st_ino) ==
                   (parent_info.st_dev, parent_info.st_ino) and
                   (final_parent_path.st_dev, final_parent_path.st_ino) ==
                   (parent_info.st_dev, parent_info.st_ino),
                   "output parent changed during publication", OutputError)
            completed = True
        finally:
            os.close(fd)
    finally:
        if not completed:
            cleanup_name = path.name if published else temporary
            try:
                candidate = os.stat(cleanup_name, dir_fd=dir_fd, follow_symlinks=False)
                if file_identity == (candidate.st_dev, candidate.st_ino):
                    os.unlink(cleanup_name, dir_fd=dir_fd)
                    os.fsync(dir_fd)
            except FileNotFoundError:
                pass
        os.close(dir_fd)


def safe_read_receipt(path: Path) -> bytes:
    refuse(path.is_absolute() and path.name not in ("", ".", ".."),
           "receipt path must be absolute with a valid basename", OutputError)
    parent = path.parent
    try:
        parent_info = os.lstat(parent)
        refuse(stat.S_ISDIR(parent_info.st_mode) and not stat.S_ISLNK(parent_info.st_mode),
               "receipt parent must be a non-symlink directory", OutputError)
        refuse(parent.resolve(strict=True) == parent, "receipt parent path must be canonical", OutputError)
        dir_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise OutputError(f"cannot open receipt parent: {exc}") from exc
    fd = -1
    try:
        opened_parent = os.fstat(dir_fd)
        refuse((opened_parent.st_dev, opened_parent.st_ino) ==
               (parent_info.st_dev, parent_info.st_ino), "receipt parent identity changed", OutputError)
        refuse(opened_parent.st_uid == os.geteuid() and stat.S_IMODE(opened_parent.st_mode) == 0o700,
               "receipt parent must be owned by the caller with mode 0700", OutputError)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
        before = os.fstat(fd)
        refuse(stat.S_ISREG(before.st_mode), "receipt must be a regular file", OutputError)
        refuse(before.st_uid == os.geteuid() and before.st_gid == os.getegid() and
               stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1,
               "receipt must be caller-owned, mode 0600, and single-linked", OutputError)
        refuse(0 < before.st_size <= MAX_RECEIPT_BYTES, "receipt size is outside the allowed range",
               OutputError)
        chunks = bytearray()
        while chunk := os.read(fd, min(1024 * 1024, MAX_RECEIPT_BYTES + 1 - len(chunks))):
            chunks.extend(chunk)
            refuse(len(chunks) <= MAX_RECEIPT_BYTES, "receipt exceeds the size limit", OutputError)
        after = os.fstat(fd)
        path_info = os.stat(path.name, dir_fd=dir_fd, follow_symlinks=False)
        final_parent_path = os.lstat(parent)
        refuse((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
               (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) and
               (path_info.st_dev, path_info.st_ino) == (before.st_dev, before.st_ino),
               "receipt changed while reading", OutputError)
        refuse((final_parent_path.st_dev, final_parent_path.st_ino) ==
               (parent_info.st_dev, parent_info.st_ino), "receipt parent changed while reading",
               OutputError)
        refuse(len(chunks) == before.st_size, "receipt read length mismatch", OutputError)
        return bytes(chunks)
    except OSError as exc:
        raise OutputError(f"cannot read receipt safely: {exc}") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(dir_fd)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    acquire = subparsers.add_parser("acquire", help="acquire a protected-CI receipt")
    acquire.add_argument("--repository", required=True)
    acquire.add_argument("--pull-request", required=True, type=int)
    acquire.add_argument("--head", required=True)
    acquire.add_argument("--base", required=True)
    acquire.add_argument("--output", required=True, type=Path)
    acquire_main = subparsers.add_parser("acquire-main", help="acquire landed-main protected CI")
    acquire_main.add_argument("--repository", required=True)
    acquire_main.add_argument("--head", required=True)
    acquire_main.add_argument("--branch", required=True)
    acquire_main.add_argument("--output", required=True, type=Path)
    validate = subparsers.add_parser("validate", help="validate a saved receipt")
    validate.add_argument("--receipt", required=True, type=Path)
    validate.add_argument("--repository", required=True)
    validate.add_argument("--head", required=True)
    validate.add_argument("--scope", choices=("pull-request", "main"), required=True)
    validate.add_argument("--max-age-seconds", required=True, type=int)
    validate.add_argument("--reverify", action="store_true",
                          help="also require the live GitHub authority to match the receipt")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        refuse(args.repository == REPOSITORY, f"repository must be {REPOSITORY}", ProviderError)
        sha40(args.head, "head")
        if args.command in ("acquire", "acquire-main"):
            gh, identity = resolve_gh()
            client = GhClient(gh, identity)
            if args.command == "acquire":
                refuse(args.pull_request > 0, "pull request number must be positive")
                refuse(args.base == "main", "base must be main")
                value = build_receipt(client, args.pull_request, args.head, args.base)
            else:
                refuse(args.branch == "main", "branch must be main")
                value = build_main_receipt(client, args.head, args.branch)
            safe_publish(args.output, value)
        else:
            refuse(args.max_age_seconds > 0, "max age must be positive")
            raw = safe_read_receipt(args.receipt)
            parsed = json.loads(raw)
            require_bounded_json_depth(parsed)
            refuse(raw.endswith(b"\n") and raw == canonical_json(parsed),
                   "receipt is not canonical JSON plus LF")
            validate_receipt(parsed, args.repository, args.head, args.scope,
                             dt.datetime.now(dt.timezone.utc), args.max_age_seconds)
            if args.reverify:
                gh, identity = resolve_gh()
                reverify_receipt(parsed, GhClient(gh, identity))
    except OSError as exc:
        print(f"protected-ci-receipt: {exc}", file=sys.stderr)
        return 5
    except (json.JSONDecodeError, UnicodeError, RecursionError):
        print("protected-ci-receipt: receipt is not valid bounded UTF-8 JSON", file=sys.stderr)
        return 5
    except ReceiptError as exc:
        print(f"protected-ci-receipt: {exc}", file=sys.stderr)
        return exc.exit_code
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

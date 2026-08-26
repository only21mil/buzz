#!/usr/bin/env python3
"""Sats Tier 2 evidence + closure engine.

Authority: Agent-Shared/adapters/sats-shared-common.md ("Evidence-first Tier 2",
"Tier 2 terminal closure", "Tier 2 transport") and
knowledge/wiki/systems/sats-risk-tiered-node-verification.md.

Tooling only. Standard library only. No network. Deterministic.
Every file this tool creates is mode 0600. Every file it reads must be private
(no group/other bits, not executable, owned by the invoking uid, not a symlink).

Subcommands
  validate-bundle    structural + bounds validation of an evidence bundle,
                     recompute of the artifact fingerprint against live files
  authorize-launch   controller-only: freeze state, mint ONE single-use launch
                     capability for ONE required reviewer provider
  claim-launch       launcher-only: consume the capability exactly once and bind
                     the concrete reviewer identity
  void-launch        launcher-only: void a claimed launch after a post-claim
                     failure that left no recorded result (at most once per
                     reviewer per revision)
  validate-closure   validate + RECORD a review result against the frozen state
  check-closure      consumption gate: terminal accepted closure, revalidated
                     against current files (optionally against a commit)
  schema             print the field contract as JSON

Exit codes (machine-readable slug + code on stderr as one JSON line)
  0  ok
  2  usage error
  3  missing / unreadable file or path
  4  filesystem-mode / ownership / symlink violation
  5  schema or parse error
  6  bound exceeded
  7  capability error (missing, replayed, duplicate, direct-producer, identity)
  8  state error (stale, wrong phase, terminal violation, lineage exhausted)
  9  artifact mutation / fingerprint mismatch
  10 review-result contract error (verdict, risk, profile, mutation check)
  11 git-source-manifest error
  12 void error (already voided, not claimed, void write failed)
  13 closure not terminal / not accepted
  14 lock or concurrency failure
  15 commit verification failure
"""

import argparse
import datetime
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import subprocess
import sys

TOOL_VERSION = "1.0.0"
BUNDLE_SCHEMAS = ("tier2-evidence-v2", "tier2-evidence-v3")
STATE_SCHEMA = "tier2-closure-state-v2"
CAPABILITY_SCHEMA = "tier2-launch-capability-v1"
RESULT_SCHEMA = "tier2-review-result-v3"
RESULT_SCHEMAS = ("tier2-review-result-v2", RESULT_SCHEMA)
MANIFEST_KIND = "git-source-manifest-v1"

# --- hard bounds (contract) ---------------------------------------------------
MAX_BUNDLE_BYTES = 64 * 1024
MAX_REVIEWER_INPUT_BYTES = 256 * 1024
MAX_CHANGED_PATHS = 40
MAX_INVARIANTS = 12
MAX_COMMANDS = 20
MAX_COMMAND_TIMEOUT_S = 600
# --- local operational bounds (documented, not contract) ---------------------
MAX_STATE_BYTES = 1024 * 1024
MAX_CAPABILITY_BYTES = 8 * 1024
MAX_RESULT_BYTES = 32 * 1024
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_MANIFEST_ENTRIES = 5000
MAX_EVENTS = 200
MAX_RISK_SUMMARY_CHARS = 2000
MAX_RISK_ITEMS = 20
MAX_IDENT_CHARS = 128
MAX_FREE_TEXT_CHARS = 4000
DEFAULT_CAPABILITY_TTL_S = 2700
MAX_CAPABILITY_TTL_S = 86400
DEFAULT_MAX_REVIEW_S = 900
MAX_MAX_REVIEW_S = 86400
GIT_TIMEOUT_S = 120
HASH_CHUNK = 1 << 20
HASH_OBJECT_BATCH = 400

VERDICTS = ("PASS", "PASS WITH RISKS", "FAIL")
ACCEPTED_VERDICTS = ("PASS", "PASS WITH RISKS")
PRODUCER_PROVIDERS = ("gpt", "claude", "local", "mixed")
REVIEWER_PROVIDERS = ("gpt", "claude")
CANDIDATE_MODES = ("repo", "files")
PATH_STATUSES = ("A", "M", "D", "T", "R")
SELECTION_CLAIMS = ("selected-and-accepted", "effective-readback")
EFFORTS = ("low", "medium", "high", "xhigh", "max", "ultra")
# Retained only to parse historical Claude result schemas. New authorization
# always requires the GPT provider and cannot mint a Claude capability.
CLAUDE_REVIEW_MODELS = ("fable", "opus")
CLAUDE_REVIEW_CANONICAL = {"fable": "claude-fable-5", "opus": "claude-opus-5"}
CLAUDE_REVIEW_EFFORTS = ("low", "medium", "high")
GPT_REVIEW_MODELS = ("gpt-5.6-sol",)
VOID_REASONS = (
    "preflight",
    "bounded_input",
    "timeout",
    "nonzero_exit",
    "empty_body",
    "malformed_result",
    "missing_verdict",
    "profile_mismatch",
    "mutation_check",
    "post_claim_size",
    "result_write",
    "other",
)
GIT_FILE_MODES = ("100644", "100755")
GIT_SYMLINK_MODE = "120000"
# Modes the candidate manifest may carry. Symlinks are represented by their
# literal target text (never followed); submodules (160000) remain unreviewable.
GIT_MANIFEST_MODES = GIT_FILE_MODES + (GIT_SYMLINK_MODE,)
HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
GIT_OID = re.compile(r"\A[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
IDENT_OK = re.compile(r"\A[0-9A-Za-z][0-9A-Za-z._:@+/-]{0,127}\Z")
BOM = chr(0xFEFF)
# zero-width, bidi-override and invisible-formatting characters (spelled with
# escapes on purpose so this source file contains none of them)
INVISIBLE = frozenset(
    [chr(cp) for cp in range(0x200B, 0x2010)]      # ZWSP..RLM and friends
    + [chr(cp) for cp in range(0x202A, 0x202F)]    # LRE..RLO, PDF
    + [chr(cp) for cp in range(0x2066, 0x206A)]    # LRI..PDI
    + [chr(0x00AD), chr(0x061C), chr(0x180E), chr(0xFEFF)]
)


class Tier2Error(Exception):
    def __init__(self, slug, code, detail, **extra):
        super().__init__(detail)
        self.slug = slug
        self.code = code
        self.detail = detail
        self.extra = extra


def fail(slug, code, detail, **extra):
    raise Tier2Error(slug, code, detail, **extra)


# ---------------------------------------------------------------------------
# time / digest helpers (pure)
# ---------------------------------------------------------------------------

def utcnow():
    return datetime.datetime.now(datetime.UTC)


def iso(dt):
    return dt.astimezone(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(value, label):
    if not isinstance(value, str) or not value:
        fail("schema_invalid", 5, f"{label} must be an ISO-8601 UTC timestamp")
    try:
        dt = datetime.datetime.fromisoformat(value)
    except ValueError:
        fail("schema_invalid", 5, f"{label} is not a parseable ISO-8601 timestamp")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.UTC)
    return dt.astimezone(datetime.UTC)


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_fd(fd):
    h = hashlib.sha256()
    size = 0
    while True:
        chunk = os.read(fd, HASH_CHUNK)
        if not chunk:
            break
        size += len(chunk)
        h.update(chunk)
    return h.hexdigest(), size


# ---------------------------------------------------------------------------
# private-file IO
# ---------------------------------------------------------------------------

def require_abs(path, label):
    if not isinstance(path, str) or not path:
        fail("usage", 2, f"{label} is required")
    if not path.startswith("/"):
        fail("usage", 2, f"{label} must be an absolute path")
    if path != os.path.normpath(path):
        fail("usage", 2, f"{label} must be a normalized absolute path")
    return path


def open_private_fd(path, label, max_bytes):
    """Open a private regular file with O_NOFOLLOW and enforce mode/owner/size."""
    require_abs(path, label)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        fail("file_missing", 3, f"{label} not found: {path}")
    except (IsADirectoryError, NotADirectoryError):
        fail("file_missing", 3, f"{label} is not a regular file: {path}")
    except OSError as exc:
        if exc.errno in (40, 62):  # ELOOP / symlink chain
            fail("mode_violation", 4, f"{label} is a symlink: {path}")
        fail("file_missing", 3, f"{label} cannot be opened (errno {exc.errno}): {path}")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            fail("mode_violation", 4, f"{label} is not a regular file: {path}")
        if st.st_uid != os.getuid():
            fail("mode_violation", 4, f"{label} is not owned by the invoking uid: {path}")
        mode = stat.S_IMODE(st.st_mode)
        if mode & 0o077:
            fail("mode_violation", 4,
                 f"{label} must be private (owner-only); found mode {oct(mode)}: {path}")
        if mode & 0o111:
            fail("mode_violation", 4,
                 f"{label} must not be executable; found mode {oct(mode)}: {path}")
        if not mode & 0o400:
            fail("mode_violation", 4, f"{label} is not owner-readable: {path}")
        if st.st_size > max_bytes:
            fail("bound_exceeded", 6,
                 f"{label} is {st.st_size} bytes; bound is {max_bytes} bytes: {path}")
    except BaseException:
        os.close(fd)
        raise
    return fd, st


def read_private_bytes(path, label, max_bytes):
    fd, st = open_private_fd(path, label, max_bytes)
    try:
        data = b""
        while True:
            chunk = os.read(fd, HASH_CHUNK)
            if not chunk:
                break
            data += chunk
            if len(data) > max_bytes:
                fail("bound_exceeded", 6, f"{label} exceeds {max_bytes} bytes: {path}")
    finally:
        os.close(fd)
    return data, stat.S_IMODE(st.st_mode)


def load_private_json(path, label, max_bytes):
    data, mode = read_private_bytes(path, label, max_bytes)
    if not data:
        fail("schema_invalid", 5, f"{label} is empty: {path}")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        fail("schema_invalid", 5, f"{label} is not valid UTF-8: {path}")
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as exc:
        fail("schema_invalid", 5, f"{label} is not parseable JSON (line {exc.lineno}): {path}")
    if not isinstance(obj, dict):
        fail("schema_invalid", 5, f"{label} must be a JSON object: {path}")
    return obj, sha256_bytes(data), len(data), mode


def write_private_json(path, obj, label):
    """Atomically write private JSON, retaining one recoverable prior version."""
    require_abs(path, label)
    parent = os.path.dirname(path)
    if not os.path.isdir(parent):
        fail("file_missing", 3, f"{label} parent directory does not exist: {parent}")
    data = json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
    tmp = os.path.join(parent, f".{os.path.basename(path)}.{os.getpid()}.{secrets.token_hex(6)}.tmp")
    backup = path + ".bak"
    backup_tmp = os.path.join(
        parent, f".{os.path.basename(backup)}.{os.getpid()}.{secrets.token_hex(6)}.tmp"
    )
    original = None
    try:
        try:
            original = os.stat(path, follow_symlinks=False)
        except FileNotFoundError:
            pass
        if original is not None:
            if not stat.S_ISREG(original.st_mode):
                fail("write_failed", 3, f"{label} target is not a regular file: {path}")
            src_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            backup_fd = os.open(
                backup_tmp,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
            )
            try:
                while True:
                    chunk = os.read(src_fd, 1024 * 1024)
                    if not chunk:
                        break
                    view = memoryview(chunk)
                    while view:
                        view = view[os.write(backup_fd, view):]
                os.fchmod(backup_fd, stat.S_IMODE(original.st_mode))
                os.fchown(backup_fd, original.st_uid, original.st_gid)
                os.fsync(backup_fd)
            finally:
                os.close(backup_fd)
                os.close(src_fd)
            os.replace(backup_tmp, backup)

        fd = os.open(
            tmp,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
            if original is not None:
                os.fchmod(fd, stat.S_IMODE(original.st_mode))
                os.fchown(fd, original.st_uid, original.st_gid)
            else:
                os.fchmod(fd, 0o600)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)

        dir_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError as exc:
        for leftover in (tmp, backup_tmp):
            try:
                os.unlink(leftover)
            except OSError:
                pass
        fail("write_failed", 3, f"{label} could not be written (errno {exc.errno}): {path}")
    return sha256_bytes(data), len(data)


class StateLock:
    """Exclusive advisory lock on <state>.lock so state mutations serialize."""

    def __init__(self, state_path):
        self.path = state_path + ".lock"
        self.fd = None

    def __enter__(self):
        require_abs(self.path, "state lock")
        parent = os.path.dirname(self.path)
        if not os.path.isdir(parent):
            fail("file_missing", 3, f"state parent directory does not exist: {parent}")
        try:
            self.fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        except OSError as exc:
            fail("lock_failed", 14, f"state lock cannot be opened (errno {exc.errno}): {self.path}")
        try:
            st = os.fstat(self.fd)
            if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077:
                fail("mode_violation", 4, f"state lock is not private: {self.path}")
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self.fd)
            self.fd = None
            fail("lock_busy", 14, f"another Tier 2 state mutation holds the lock: {self.path}")
        except BaseException:
            os.close(self.fd)
            self.fd = None
            raise
        return self

    def __exit__(self, *exc):
        if self.fd is not None:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd)
                self.fd = None
        return False


# ---------------------------------------------------------------------------
# scalar validators (pure)
# ---------------------------------------------------------------------------

def want(obj, key, types, label, required=True, default=None):
    if key not in obj or obj[key] is None:
        if required:
            fail("schema_invalid", 5, f"{label}.{key} is required")
        return default
    value = obj[key]
    if not isinstance(value, types) or isinstance(value, bool) and bool not in (
            types if isinstance(types, tuple) else (types,)):
        fail("schema_invalid", 5, f"{label}.{key} has the wrong type")
    return value


def want_str(obj, key, label, required=True, default=None, max_chars=MAX_FREE_TEXT_CHARS,
             allow_empty=False):
    value = want(obj, key, str, label, required=required, default=default)
    if value is None:
        return None
    if not allow_empty and not value.strip():
        fail("schema_invalid", 5, f"{label}.{key} must be a non-empty string")
    if len(value) > max_chars:
        fail("bound_exceeded", 6, f"{label}.{key} exceeds {max_chars} characters")
    check_text_safe(value, f"{label}.{key}")
    return value


def want_int(obj, key, label, required=True, default=None, low=None, high=None):
    value = want(obj, key, int, label, required=required, default=default)
    if value is None:
        return None
    if isinstance(value, bool):
        fail("schema_invalid", 5, f"{label}.{key} must be an integer")
    if low is not None and value < low:
        fail("schema_invalid", 5, f"{label}.{key} must be >= {low}")
    if high is not None and value > high:
        fail("bound_exceeded", 6, f"{label}.{key} must be <= {high}")
    return value


def want_enum(obj, key, allowed, label, required=True, default=None):
    value = want_str(obj, key, label, required=required, default=default)
    if value is None:
        return None
    if value not in allowed:
        fail("schema_invalid", 5, f"{label}.{key} must be one of {list(allowed)}")
    return value


def want_hex64(obj, key, label, required=True):
    value = want_str(obj, key, label, required=required)
    if value is None:
        return None
    if not HEX64.match(value):
        fail("schema_invalid", 5, f"{label}.{key} must be a lowercase 64-hex SHA-256")
    return value


def check_text_safe(value, label, allow_whitespace=True):
    """Reject control and invisible/bidi characters.

    `allow_whitespace=False` (paths, single-line fields) also rejects LF, CR and
    TAB, which are protocol separators for git plumbing and the manifest format.
    """
    for ch in value:
        if ch in ("\n", "\t", "\r"):
            if allow_whitespace and ch != "\r":
                continue
            fail("schema_invalid", 5, f"{label} contains a line break or tab")
        if ord(ch) < 0x20 or ord(ch) == 0x7F:
            fail("schema_invalid", 5, f"{label} contains a control character")
        if ch in INVISIBLE:
            fail("schema_invalid", 5, f"{label} contains an invisible/bidi character")
    return value


def check_identity(value, label):
    if not isinstance(value, str) or not value.strip():
        fail("schema_invalid", 5, f"{label} must be a non-empty identity string")
    if len(value) > MAX_IDENT_CHARS:
        fail("bound_exceeded", 6, f"{label} exceeds {MAX_IDENT_CHARS} characters")
    if not IDENT_OK.match(value):
        fail("schema_invalid", 5,
             f"{label} must match [0-9A-Za-z][0-9A-Za-z._:@+/-]* (no spaces or control chars)")
    return value


def same_identity(a, b):
    return a is not None and b is not None and a.strip().casefold() == b.strip().casefold()


def check_rel_path(value, label):
    if not isinstance(value, str) or not value:
        fail("schema_invalid", 5, f"{label} must be a non-empty relative path")
    if value.startswith("/"):
        fail("schema_invalid", 5, f"{label} must be repo-relative, not absolute: {value}")
    if "\\" in value:
        fail("schema_invalid", 5, f"{label} must not contain a backslash: {value}")
    check_text_safe(value, label, allow_whitespace=False)
    if value != value.strip():
        fail("schema_invalid", 5, f"{label} has leading/trailing whitespace")
    parts = value.split("/")
    for part in parts:
        if part in ("", ".", ".."):
            fail("schema_invalid", 5, f"{label} has an empty or traversal component: {value}")
        if part.casefold() == ".git":
            fail("schema_invalid", 5, f"{label} contains a .git component: {value}")
        if part != part.strip():
            fail("schema_invalid", 5, f"{label} component has leading/trailing whitespace: {value}")
    return value


def check_abs_path(value, label):
    if not isinstance(value, str) or not value.startswith("/"):
        fail("schema_invalid", 5, f"{label} must be an absolute path")
    check_text_safe(value, label, allow_whitespace=False)
    if value != os.path.normpath(value):
        fail("schema_invalid", 5, f"{label} must be normalized: {value}")
    if "\\" in value:
        fail("schema_invalid", 5, f"{label} must not contain a backslash: {value}")
    for part in value.split("/")[1:]:
        if part.casefold() == ".git":
            fail("schema_invalid", 5, f"{label} contains a .git component: {value}")
    return value


def lstat_nofollow(path, label):
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        fail("file_missing", 3, f"{label} cannot be stat'ed (errno {exc.errno}): {path}")


def hash_regular_file(path, label):
    """SHA-256 a regular file opened O_NOFOLLOW. Returns (digest, size, mode)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        fail("artifact_mutated", 9, f"{label} is absent but the bundle records it present: {path}")
    except OSError as exc:
        if exc.errno in (40, 62):
            fail("mode_violation", 4, f"{label} is a symlink: {path}")
        fail("file_missing", 3, f"{label} cannot be read (errno {exc.errno}): {path}")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            fail("mode_violation", 4, f"{label} is not a regular file: {path}")
        digest, size = sha256_fd(fd)
    finally:
        os.close(fd)
    return digest, size, stat.S_IMODE(st.st_mode)


# ---------------------------------------------------------------------------
# git helpers
# ---------------------------------------------------------------------------

def git_env():
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_ALLOW_PROTOCOL": "none",
        "GIT_CONFIG_COUNT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "LC_ALL": "C",
    })
    return env


def git_run(root, args, label, stdin_data=None, timeout=GIT_TIMEOUT_S):
    cmd = ["git", "--no-optional-locks", "--no-replace-objects", "-C", root,
           "-c", "core.quotepath=off"] + list(args)
    try:
        proc = subprocess.run(cmd, input=stdin_data, capture_output=True,
                              timeout=timeout, env=git_env())
    except FileNotFoundError:
        fail("git_unavailable", 3, "git executable not found on PATH")
    except subprocess.TimeoutExpired:
        fail("git_failed", 11, f"git {label} timed out after {timeout}s")
    if proc.returncode != 0:
        fail("git_failed", 11, f"git {label} exited {proc.returncode}")
    return proc.stdout


def git_toplevel(root, label="candidate root"):
    check_abs_path(root, label)
    st = lstat_nofollow(root, label)
    if st is None:
        fail("file_missing", 3, f"{label} does not exist: {root}")
    if not stat.S_ISDIR(st.st_mode):
        fail("mode_violation", 4, f"{label} is not a directory: {root}")
    out = git_run(root, ["rev-parse", "--show-toplevel"], "rev-parse --show-toplevel")
    top = out.decode("utf-8", "strict").strip()
    if os.path.realpath(top) != os.path.realpath(root):
        fail("manifest_invalid", 11,
             f"{label} is not the git work-tree root (toplevel {top}): {root}")
    return os.path.realpath(root)


def git_head(root):
    out = git_run(root, ["rev-parse", "HEAD"], "rev-parse HEAD")
    head = out.decode("utf-8", "strict").strip()
    if not GIT_OID.match(head):
        fail("git_failed", 11, "git HEAD is not a full object id")
    return head


def git_object_format(root):
    out = git_run(root, ["rev-parse", "--show-object-format"], "rev-parse --show-object-format")
    fmt = out.decode("utf-8", "strict").strip()
    if fmt not in ("sha1", "sha256"):
        fail("git_failed", 11, f"unsupported git object format: {fmt}")
    return fmt


def git_commit_tree_and_parents(root, oid, label):
    """Read literal commit headers without replacement or traversal metadata."""
    raw = git_run(root, ["cat-file", "commit", oid], f"cat-file {label}")
    if len(raw) > MAX_MANIFEST_BYTES:
        fail("commit_mismatch", 15,
             f"{label} object exceeds the {MAX_MANIFEST_BYTES}-byte verification bound")
    headers, separator, _message = raw.partition(b"\n\n")
    if not separator:
        fail("commit_mismatch", 15, f"{label} object has no header terminator")

    trees = []
    parents = []
    for line in headers.splitlines():
        if line.startswith(b"tree "):
            trees.append(line[5:])
        elif line.startswith(b"parent "):
            parents.append(line[7:])

    expected_len = 40 if git_object_format(root) == "sha1" else 64

    def decode_oid(raw_oid, field):
        try:
            value = raw_oid.decode("ascii", "strict")
        except UnicodeDecodeError:
            fail("commit_mismatch", 15, f"{label} has a non-ASCII {field} object id")
        if len(value) != expected_len or not GIT_OID.match(value):
            fail("commit_mismatch", 15, f"{label} has an invalid {field} object id")
        return value

    if len(trees) != 1:
        fail("commit_mismatch", 15,
             f"{label} must have exactly one literal tree header; found {len(trees)}")
    return decode_oid(trees[0], "tree"), [
        decode_oid(parent, "parent") for parent in parents
    ]


def split_nul(data):
    parts = data.split(b"\0")
    if parts and parts[-1] == b"":
        parts.pop()
    return parts


def decode_git_path(raw, label):
    try:
        value = raw.decode("utf-8", "strict")
    except UnicodeDecodeError:
        fail("manifest_invalid", 11, f"{label}: git reported a non-UTF-8 path")
    return check_rel_path(value, label)


def git_inventory(root):
    """Exact index-plus-untracked-exclude-standard inventory, including deletions.

    Returns an ordered list of dicts: path, state, source, mode, index_oid.
    Fails closed on unmerged index entries, symlinks, submodules, special files,
    duplicates, .git paths and non-UTF-8 paths.
    """
    entries = {}
    raw = git_run(root, ["ls-files", "-s", "-z"], "ls-files -s")
    for record in split_nul(raw):
        try:
            meta, rawpath = record.split(b"\t", 1)
        except ValueError:
            fail("manifest_invalid", 11, "git ls-files -s produced an unparseable record")
        fields = meta.split(b" ")
        if len(fields) != 3:
            fail("manifest_invalid", 11, "git ls-files -s produced an unparseable header")
        mode = fields[0].decode("ascii", "strict")
        oid = fields[1].decode("ascii", "strict")
        stage = fields[2].decode("ascii", "strict")
        path = decode_git_path(rawpath, "index path")
        if stage != "0":
            fail("manifest_invalid", 11,
                 f"index has an unmerged entry (stage {stage}); resolve before review: {path}")
        if mode == "160000":
            fail("manifest_invalid", 11, f"submodule entries are not reviewable: {path}")
        if mode not in GIT_MANIFEST_MODES:
            fail("manifest_invalid", 11, f"unsupported git mode {mode}: {path}")
        if path in entries:
            fail("manifest_invalid", 11, f"duplicate index path: {path}")
        if not GIT_OID.match(oid):
            fail("manifest_invalid", 11, f"index oid is not a full object id: {path}")
        entries[path] = {"path": path, "source": "index", "mode": mode, "index_oid": oid}

    raw = git_run(root, ["ls-files", "--others", "--exclude-standard", "-z"],
                  "ls-files --others --exclude-standard")
    for rawpath in split_nul(raw):
        path = decode_git_path(rawpath, "untracked path")
        if path in entries:
            fail("manifest_invalid", 11, f"path is both tracked and untracked: {path}")
        entries[path] = {"path": path, "source": "untracked", "mode": None, "index_oid": None}

    ordered = []
    for path in sorted(entries, key=lambda p: p.encode("utf-8")):
        entry = entries[path]
        abspath = os.path.join(root, path)
        st = lstat_nofollow(abspath, f"candidate file {path}")
        if st is None:
            if entry["source"] != "index":
                fail("manifest_invalid", 11,
                     f"git listed an untracked path that does not exist: {path}")
            entry["state"] = "deleted"
        else:
            if stat.S_ISLNK(st.st_mode):
                # A TRACKED symlink (index mode 120000) is reviewable: it is
                # represented by its literal target text and never followed. Any
                # other on-disk symlink (untracked, or an index entry whose mode
                # is not 120000) is not safely representable and fails closed.
                if entry["source"] == "index" and entry["mode"] == GIT_SYMLINK_MODE:
                    entry["state"] = "present"
                    ordered.append(entry)
                    continue
                fail("manifest_invalid", 11, f"candidate path is a symlink: {path}")
            if stat.S_ISDIR(st.st_mode):
                fail("manifest_invalid", 11, f"candidate path is a directory: {path}")
            if not stat.S_ISREG(st.st_mode):
                fail("manifest_invalid", 11, f"candidate path is a special file: {path}")
            entry["state"] = "present"
            if entry["mode"] is None:
                entry["mode"] = "100755" if st.st_mode & 0o111 else "100644"
        if entry["mode"] is None:
            entry["mode"] = "100644"
        ordered.append(entry)
    if len(ordered) > MAX_MANIFEST_ENTRIES:
        fail("bound_exceeded", 6,
             f"candidate inventory has {len(ordered)} entries; bound is {MAX_MANIFEST_ENTRIES}")
    return ordered


def git_blob_oids(root, rel_paths):
    """Blob oids for present files, read through git so filters match a commit."""
    oids = {}
    for start in range(0, len(rel_paths), HASH_OBJECT_BATCH):
        batch = rel_paths[start:start + HASH_OBJECT_BATCH]
        payload = ("\n".join(batch) + "\n").encode("utf-8")
        out = git_run(root, ["hash-object", "--stdin-paths"], "hash-object --stdin-paths",
                      stdin_data=payload)
        lines = out.decode("ascii", "strict").split("\n")
        lines = [line for line in lines if line]
        if len(lines) != len(batch):
            fail("manifest_invalid", 11,
                 f"git hash-object returned {len(lines)} oids for {len(batch)} paths")
        for path, oid in zip(batch, lines):
            if not GIT_OID.match(oid):
                fail("manifest_invalid", 11, f"git hash-object returned a bad oid for {path}")
            oids[path] = oid
    return oids


def hash_symlink_nofollow(root, path, label):
    """Content identity of a TRACKED symlink WITHOUT following it.

    `os.readlink` reads the link's own target text and never opens the
    destination, so a link can never redirect the manifest at content the
    reviewer did not inspect. The recorded blob is git's own object id for that
    target text -- identical to the `ls-tree` / `ls-files -s` symlink oid --
    computed by hashing the target BYTES as a blob on stdin, never the path, so
    git does not follow the link either (git hash-object DOES follow a symlink
    path). Returns (sha256_hex, size, git_blob_oid).
    """
    try:
        target = os.readlink(path)
    except OSError as exc:
        fail("mode_violation", 4,
             f"{label} cannot be read as a symlink (errno {exc.errno}): {path}")
    target_bytes = os.fsencode(target)
    digest = sha256_bytes(target_bytes)
    out = git_run(root, ["hash-object", "-t", "blob", "--stdin"],
                  "hash-object symlink target", stdin_data=target_bytes)
    oid = out.decode("ascii", "strict").strip()
    if not GIT_OID.match(oid):
        fail("manifest_invalid", 11, f"{label}: git produced a bad symlink blob oid: {path}")
    return digest, len(target_bytes), oid


# ---------------------------------------------------------------------------
# evidence bundle validation
# ---------------------------------------------------------------------------

def validate_changed_paths(bundle, label, advisory):
    raw = bundle.get("changed_paths")
    if raw is None:
        if not advisory:
            fail("schema_invalid", 5, f"{label}.changed_paths is required for evidence v2")
        return []
    if not isinstance(raw, list):
        fail("schema_invalid", 5, f"{label}.changed_paths must be a list")
    if len(raw) > MAX_CHANGED_PATHS:
        fail("bound_exceeded", 6,
             f"{label}.changed_paths has {len(raw)} entries; bound is {MAX_CHANGED_PATHS}")
    if not advisory and not raw:
        fail("schema_invalid", 5, f"{label}.changed_paths must not be empty for evidence v2")
    mode = bundle["candidate"]["mode"]
    seen = set()
    out = []
    for idx, item in enumerate(raw):
        item_label = f"{label}.changed_paths[{idx}]"
        if not isinstance(item, dict):
            fail("schema_invalid", 5, f"{item_label} must be an object")
        status = want_enum(item, "status", PATH_STATUSES, item_label)
        path = want_str(item, "path", item_label, max_chars=4096)
        if mode == "files":
            check_abs_path(path, f"{item_label}.path")
        else:
            check_rel_path(path, f"{item_label}.path")
        if path in seen:
            fail("schema_invalid", 5, f"{item_label}.path is a duplicate: {path}")
        seen.add(path)
        entry = {"status": status, "path": path}
        if status == "R":
            from_path = want_str(item, "from_path", item_label, max_chars=4096)
            if mode == "files":
                check_abs_path(from_path, f"{item_label}.from_path")
            else:
                check_rel_path(from_path, f"{item_label}.from_path")
            entry["from_path"] = from_path
        if advisory:
            out.append(entry)
            continue
        if status == "D":
            if item.get("sha256") is not None:
                fail("schema_invalid", 5, f"{item_label}.sha256 must be null for status D")
            entry["sha256"] = None
        else:
            entry["sha256"] = want_hex64(item, "sha256", item_label)
        out.append(entry)
    if not advisory:
        ordered = sorted(out, key=lambda e: e["path"].encode("utf-8"))
        if [e["path"] for e in ordered] != [e["path"] for e in out]:
            fail("schema_invalid", 5,
                 f"{label}.changed_paths must be sorted by path (byte order)")
    return out


def validate_commands(bundle, label):
    raw = bundle.get("commands")
    if raw is None:
        fail("schema_invalid", 5, f"{label}.commands is required (use [] if none)")
    if not isinstance(raw, list):
        fail("schema_invalid", 5, f"{label}.commands must be a list")
    if len(raw) > MAX_COMMANDS:
        fail("bound_exceeded", 6,
             f"{label}.commands has {len(raw)} entries; bound is {MAX_COMMANDS}")
    for idx, item in enumerate(raw):
        item_label = f"{label}.commands[{idx}]"
        if not isinstance(item, dict):
            fail("schema_invalid", 5, f"{item_label} must be an object")
        want_str(item, "cmd", item_label, max_chars=1000)
        want_int(item, "timeout_s", item_label, low=1, high=MAX_COMMAND_TIMEOUT_S)
        want_str(item, "result", item_label, max_chars=2000)
        want_int(item, "exit_code", item_label, required=False, low=-256, high=256)
    return raw


def validate_str_list(bundle, key, label, max_items, required=True):
    raw = bundle.get(key)
    if raw is None:
        if required:
            fail("schema_invalid", 5, f"{label}.{key} is required")
        return []
    if not isinstance(raw, list):
        fail("schema_invalid", 5, f"{label}.{key} must be a list of strings")
    if len(raw) > max_items:
        fail("bound_exceeded", 6,
             f"{label}.{key} has {len(raw)} entries; bound is {max_items}")
    if required and not raw:
        fail("schema_invalid", 5,
             f"{label}.{key} must not be empty (use an explicit \"none\" entry)")
    for idx, item in enumerate(raw):
        if not isinstance(item, str) or not item.strip():
            fail("schema_invalid", 5, f"{label}.{key}[{idx}] must be a non-empty string")
        if len(item) > 1000:
            fail("bound_exceeded", 6, f"{label}.{key}[{idx}] exceeds 1000 characters")
        check_text_safe(item, f"{label}.{key}[{idx}]")
    return list(raw)


def validate_delta(bundle, label):
    delta = bundle.get("delta")
    if not isinstance(delta, dict):
        fail("schema_invalid", 5, f"{label}.delta is required for revision 2")
    dl = f"{label}.delta"
    out = {
        "failed_revision": want_int(delta, "failed_revision", dl, low=1, high=1),
        "failed_evidence_digest": want_hex64(delta, "failed_evidence_digest", dl),
        "failed_artifact_fingerprint": want_hex64(delta, "failed_artifact_fingerprint", dl),
    }
    results = delta.get("failed_results")
    if not isinstance(results, list) or not results:
        fail("schema_invalid", 5, f"{dl}.failed_results must be a non-empty list")
    if len(results) > len(REVIEWER_PROVIDERS):
        fail("bound_exceeded", 6, f"{dl}.failed_results has too many entries")
    seen = set()
    parsed = []
    for idx, item in enumerate(results):
        il = f"{dl}.failed_results[{idx}]"
        if not isinstance(item, dict):
            fail("schema_invalid", 5, f"{il} must be an object")
        provider = want_enum(item, "reviewer_provider", REVIEWER_PROVIDERS, il)
        if provider in seen:
            fail("schema_invalid", 5, f"{il}.reviewer_provider is duplicated")
        seen.add(provider)
        identity = check_identity(want_str(item, "reviewer_identity", il), f"{il}.reviewer_identity")
        digest = want_hex64(item, "result_digest", il)
        verdict = want_enum(item, "verdict", ("FAIL",), il)
        parsed.append({
            "reviewer_provider": provider,
            "reviewer_identity": identity,
            "result_digest": digest,
            "verdict": verdict,
        })
    out["failed_results"] = parsed
    return out


def validate_artifact_target(bundle, label):
    target = bundle.get("artifact_target")
    if not isinstance(target, dict):
        fail("schema_invalid", 5, f"{label}.artifact_target is required for evidence v3")
    tl = f"{label}.artifact_target"
    kind = want_enum(target, "type", (MANIFEST_KIND,), tl)
    out = {
        "type": kind,
        "manifest_path": check_abs_path(want_str(target, "manifest_path", tl, max_chars=4096),
                                        f"{tl}.manifest_path"),
        "manifest_sha256": want_hex64(target, "manifest_sha256", tl),
        "entry_count": want_int(target, "entry_count", tl, low=1, high=MAX_MANIFEST_ENTRIES),
        "root": check_abs_path(want_str(target, "root", tl, max_chars=4096), f"{tl}.root"),
        "root_identity": want_str(target, "root_identity", tl, max_chars=128),
        "base_head": want_str(target, "base_head", tl, max_chars=64),
        "object_format": want_enum(target, "object_format", ("sha1", "sha256"), tl),
        "dirty_fingerprint": want_hex64(target, "dirty_fingerprint", tl),
        "tree_fingerprint": want_hex64(target, "tree_fingerprint", tl),
    }
    if not GIT_OID.match(out["base_head"]):
        fail("schema_invalid", 5, f"{tl}.base_head must be a full git object id")
    if not re.match(r"\A[0-9]+:[0-9]+\Z", out["root_identity"]):
        fail("schema_invalid", 5, f"{tl}.root_identity must be \"<st_dev>:<st_ino>\"")
    for key, sub in (("retained_inventory_tsv", ("path", "sha256", "entry_count", "branch")),
                     ("retained_source_fingerprint", ("path", "sha256"))):
        value = target.get(key)
        if value is None:
            out[key] = None
            continue
        if not isinstance(value, dict):
            fail("schema_invalid", 5, f"{tl}.{key} must be an object")
        rec = {
            "path": check_abs_path(want_str(value, "path", f"{tl}.{key}", max_chars=4096),
                                   f"{tl}.{key}.path"),
            "sha256": want_hex64(value, "sha256", f"{tl}.{key}"),
        }
        if "entry_count" in sub:
            rec["entry_count"] = want_int(value, "entry_count", f"{tl}.{key}", low=0,
                                          high=MAX_MANIFEST_ENTRIES)
        if "branch" in sub:
            rec["branch"] = want_str(value, "branch", f"{tl}.{key}", max_chars=256)
        out[key] = rec
    return out


def parse_bundle(path):
    """Structure + bounds validation. Returns (bundle, digest, size, normalized)."""
    bundle, digest, size, mode = load_private_json(path, "evidence bundle", MAX_BUNDLE_BYTES)
    label = "bundle"
    schema = want_enum(bundle, "schema", BUNDLE_SCHEMAS, label)
    is_v3 = schema == "tier2-evidence-v3"
    review_id = check_identity(want_str(bundle, "review_id", label), f"{label}.review_id")
    revision = want_int(bundle, "revision", label, low=1, high=2)
    producer_provider = want_enum(bundle, "producer_provider", PRODUCER_PROVIDERS, label)
    producer_identity = check_identity(want_str(bundle, "producer_identity", label),
                                       f"{label}.producer_identity")
    purpose = want_str(bundle, "purpose", label, max_chars=400)
    created = parse_iso(bundle.get("created_utc"), f"{label}.created_utc")

    candidate = bundle.get("candidate")
    if not isinstance(candidate, dict):
        fail("schema_invalid", 5, f"{label}.candidate must be an object")
    cmode = want_enum(candidate, "mode", CANDIDATE_MODES, f"{label}.candidate")
    root = None
    base_head = None
    if cmode == "repo":
        root = check_abs_path(want_str(candidate, "root", f"{label}.candidate", max_chars=4096),
                              f"{label}.candidate.root")
        base_head = want_str(candidate, "base_head", f"{label}.candidate", max_chars=64)
        if not GIT_OID.match(base_head):
            fail("schema_invalid", 5, f"{label}.candidate.base_head must be a full git object id")
    else:
        if candidate.get("root") is not None:
            fail("schema_invalid", 5, f"{label}.candidate.root is not allowed in files mode")
        if is_v3:
            fail("schema_invalid", 5, "evidence v3 requires candidate.mode == repo")

    changed_paths = validate_changed_paths(bundle, label, advisory=is_v3)
    invariants = validate_str_list(bundle, "invariants", label, MAX_INVARIANTS)
    commands = validate_commands(bundle, label)
    known_limits = validate_str_list(bundle, "known_limits", label, 20)
    host_readbacks = validate_str_list(bundle, "host_readbacks", label, 20, required=False)

    fingerprints = bundle.get("fingerprints")
    if fingerprints is None:
        fingerprints = {}
    if not isinstance(fingerprints, dict):
        fail("schema_invalid", 5, f"{label}.fingerprints must be an object of name -> hex")
    if len(fingerprints) > 20:
        fail("bound_exceeded", 6, f"{label}.fingerprints has more than 20 entries")
    for name, value in fingerprints.items():
        check_identity(name, f"{label}.fingerprints key")
        if not isinstance(value, str) or not re.match(r"\A[0-9a-f]{8,128}\Z", value):
            fail("schema_invalid", 5, f"{label}.fingerprints.{name} must be lowercase hex")

    artifact_fingerprint = want_hex64(bundle, "artifact_fingerprint", label)
    artifact_target = validate_artifact_target(bundle, label) if is_v3 else None
    if not is_v3 and bundle.get("artifact_target") is not None:
        fail("schema_invalid", 5, f"{label}.artifact_target is only valid for evidence v3")
    delta = validate_delta(bundle, label) if revision == 2 else None
    if revision == 1 and bundle.get("delta") is not None:
        fail("schema_invalid", 5, f"{label}.delta is only valid for revision 2")

    normalized = {
        "schema": schema,
        "review_id": review_id,
        "revision": revision,
        "producer_provider": producer_provider,
        "producer_identity": producer_identity,
        "purpose": purpose,
        "created_utc": iso(created),
        "candidate_mode": cmode,
        "candidate_root": root,
        "candidate_base_head": base_head,
        "changed_paths": changed_paths,
        "changed_paths_advisory": is_v3,
        "invariants": invariants,
        "commands_count": len(commands),
        "known_limits": known_limits,
        "host_readbacks_count": len(host_readbacks),
        "fingerprints": dict(fingerprints),
        "artifact_fingerprint": artifact_fingerprint,
        "artifact_target": artifact_target,
        "delta": delta,
        "bundle_bytes": size,
        "bundle_mode": oct(mode),
    }
    return bundle, digest, size, normalized


# ---------------------------------------------------------------------------
# artifact fingerprint recomputation
# ---------------------------------------------------------------------------

def recompute_v2_fingerprint(norm):
    """SHA-256 over the frozen changed-path records read from the live filesystem."""
    lines = []
    root = norm["candidate_root"]
    for entry in norm["changed_paths"]:
        path = entry["path"]
        abspath = path if norm["candidate_mode"] == "files" else os.path.join(root, path)
        if entry["status"] == "D":
            st = lstat_nofollow(abspath, f"deleted path {path}")
            if st is not None:
                fail("artifact_mutated", 9,
                     f"bundle records {path} deleted but it exists on disk")
            lines.append(f"D\t-\t{path}\n")
            continue
        digest, _size, _mode = hash_regular_file(abspath, f"changed path {path}")
        if digest != entry["sha256"]:
            fail("artifact_mutated", 9,
                 f"content hash mismatch for {path} (bundle {entry['sha256'][:12]}…, "
                 f"disk {digest[:12]}…)")
        lines.append(f"{entry['status']}\t{digest}\t{path}\n")
        if entry["status"] == "R":
            from_path = entry["from_path"]
            from_abs = from_path if norm["candidate_mode"] == "files" else os.path.join(root, from_path)
            st = lstat_nofollow(from_abs, f"rename source {from_path}")
            if st is not None:
                fail("artifact_mutated", 9,
                     f"rename source {from_path} still exists on disk")
            lines.append(f"R-from\t-\t{from_path}\n")
    if norm["candidate_mode"] == "repo":
        st = lstat_nofollow(root, "candidate root")
        if st is None or not stat.S_ISDIR(st.st_mode):
            fail("file_missing", 3, f"candidate root is not a directory: {root}")
    payload = ("".join(lines)).encode("utf-8")
    return sha256_bytes(payload)


def parse_manifest(data, target):
    """Strictly parse a git-source-manifest-v1 JSONL blob."""
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError:
        fail("manifest_invalid", 11, "manifest is not valid UTF-8")
    if text.startswith(BOM):
        fail("manifest_invalid", 11, "manifest starts with a BOM")
    if not text.endswith("\n"):
        fail("manifest_invalid", 11, "manifest must be LF-terminated")
    lines = text.split("\n")
    lines.pop()
    if len(lines) < 2:
        fail("manifest_invalid", 11, "manifest must have a header line and at least one entry")
    try:
        header = json.loads(lines[0])
    except json.JSONDecodeError:
        fail("manifest_invalid", 11, "manifest header line is not parseable JSON")
    if not isinstance(header, dict):
        fail("manifest_invalid", 11, "manifest header must be a JSON object")
    hl = "manifest.header"
    want_enum(header, "manifest", (MANIFEST_KIND,), hl)
    for key in ("root", "root_identity", "base_head", "object_format", "entry_count",
                "dirty_fingerprint", "tree_fingerprint"):
        if key not in header:
            fail("manifest_invalid", 11, f"{hl}.{key} is required")
        if header[key] != target[key]:
            fail("manifest_invalid", 11,
                 f"{hl}.{key} does not match the bundle artifact_target")
    entries = []
    seen = set()
    body = lines[1:]
    if len(body) != target["entry_count"]:
        fail("manifest_invalid", 11,
             f"manifest has {len(body)} entries but artifact_target.entry_count is "
             f"{target['entry_count']}")
    if len(body) > MAX_MANIFEST_ENTRIES:
        fail("bound_exceeded", 6, f"manifest has more than {MAX_MANIFEST_ENTRIES} entries")
    prev = None
    for idx, line in enumerate(body):
        el = f"manifest.entry[{idx}]"
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            fail("manifest_invalid", 11, f"{el} is not parseable JSON")
        if not isinstance(item, dict):
            fail("manifest_invalid", 11, f"{el} must be a JSON object")
        path = check_rel_path(want_str(item, "path", el, max_chars=4096), f"{el}.path")
        if path in seen:
            fail("manifest_invalid", 11, f"{el}.path is a duplicate: {path}")
        seen.add(path)
        encoded = path.encode("utf-8")
        if prev is not None and encoded <= prev:
            fail("manifest_invalid", 11, f"{el}.path breaks byte-order sorting: {path}")
        prev = encoded
        state = want_enum(item, "state", ("present", "deleted"), el)
        source = want_enum(item, "source", ("index", "untracked"), el)
        mode = want_enum(item, "mode", GIT_MANIFEST_MODES, el)
        size = want_int(item, "size", el, low=0, high=1 << 40)
        if state == "present":
            sha = want_hex64(item, "sha256", el)
            blob = want_str(item, "blob", el, max_chars=64)
            if not GIT_OID.match(blob):
                fail("manifest_invalid", 11, f"{el}.blob must be a full git object id")
        else:
            if source != "index":
                fail("manifest_invalid", 11, f"{el}: only tracked paths can be deleted")
            if item.get("sha256") is not None or item.get("blob") is not None:
                fail("manifest_invalid", 11, f"{el}: deleted entries carry null sha256/blob")
            if size != 0:
                fail("manifest_invalid", 11, f"{el}: deleted entries carry size 0")
            sha = None
            blob = None
        entries.append({"path": path, "state": state, "source": source, "mode": mode,
                        "size": size, "sha256": sha, "blob": blob})
    return header, entries


def manifest_dirty_fingerprint(entries):
    payload = "".join(
        f"{e['state']}\t{e['source']}\t{e['mode']}\t{e['sha256'] or '-'}\t{e['path']}\n"
        for e in entries).encode("utf-8")
    return sha256_bytes(payload)


def manifest_tree_fingerprint(pairs):
    """pairs: ordered (mode, oid, path)."""
    payload = "".join(f"{mode}\t{oid}\t{path}\n" for mode, oid, path in pairs).encode("utf-8")
    return sha256_bytes(payload)


def verify_manifest(norm, phase, dirty_candidate=True):
    """Securely recompute the v3 manifest against the current candidate.

    Enforced always: private no-follow manifest outside the repo, manifest
    SHA-256 == artifact_fingerprint, strict header/target agreement, root
    identity, object format, per-file mode/size/content read with O_NOFOLLOW,
    deletions still absent, and the dirty-candidate fingerprint.

    `dirty_candidate=True` (validation, authorization, claim, closure and plain
    consumption) additionally requires HEAD == the reviewed base HEAD before and
    after, exact index-plus-untracked-exclude-standard inventory equality
    including deletions, and git-read blob oids matching the manifest.

    `dirty_candidate=False` is the post-commit consumption phase: the reviewed
    dirty inventory no longer exists as a dirty inventory (untracked files became
    tracked and deletions left the index), so `check-closure --commit` proves the
    same facts from the commit instead — clean state, exact HEAD, sole parent ==
    reviewed base, and an independent Git-blob tree fingerprint.
    """
    target = norm["artifact_target"]
    if target["manifest_sha256"] != norm["artifact_fingerprint"]:
        fail("manifest_invalid", 11,
             "bundle.artifact_fingerprint must equal artifact_target.manifest_sha256")
    root = target["root"]
    manifest_path = target["manifest_path"]
    real_root = os.path.realpath(root)
    real_manifest = os.path.realpath(os.path.dirname(manifest_path))
    if real_manifest == real_root or real_manifest.startswith(real_root + "/"):
        fail("manifest_invalid", 11,
             "the git-source manifest must live outside the reviewed repository")
    data, _mode = read_private_bytes(manifest_path, "git-source manifest", MAX_MANIFEST_BYTES)
    digest = sha256_bytes(data)
    if digest != target["manifest_sha256"]:
        fail("artifact_mutated", 9,
             f"manifest SHA-256 mismatch at {phase} (expected "
             f"{target['manifest_sha256'][:12]}…, found {digest[:12]}…)")
    header, entries = parse_manifest(data, target)

    top = git_toplevel(root)
    st = os.stat(top)
    root_identity = f"{st.st_dev}:{st.st_ino}"
    if root_identity != target["root_identity"]:
        fail("artifact_mutated", 9,
             f"candidate root identity changed at {phase} (expected "
             f"{target['root_identity']}, found {root_identity})")
    fmt = git_object_format(root)
    if fmt != target["object_format"]:
        fail("manifest_invalid", 11,
             f"git object format is {fmt} but the manifest records {target['object_format']}")
    head_before = git_head(root)
    if dirty_candidate and head_before != target["base_head"]:
        fail("artifact_mutated", 9,
             f"candidate HEAD is {head_before[:12]}… but the manifest base_head is "
             f"{target['base_head'][:12]}…")

    if dirty_candidate:
        live = git_inventory(root)
        live_key = [(e["path"], e["state"], e["source"], e["mode"]) for e in live]
        man_key = [(e["path"], e["state"], e["source"], e["mode"]) for e in entries]
        if live_key != man_key:
            live_set = {k[0] for k in live_key}
            man_set = {k[0] for k in man_key}
            added = sorted(live_set - man_set)[:5]
            removed = sorted(man_set - live_set)[:5]
            fail("artifact_mutated", 9,
                 f"candidate inventory differs from the manifest at {phase} "
                 f"(live {len(live_key)} entries, manifest {len(man_key)}; "
                 f"unrecorded {added}; missing {removed})")

    present = [e for e in entries if e["state"] == "present"]
    for entry in entries:
        abspath = os.path.join(root, entry["path"])
        if entry["state"] == "deleted":
            if lstat_nofollow(abspath, f"deleted path {entry['path']}") is not None:
                fail("artifact_mutated", 9,
                     f"manifest records {entry['path']} deleted but it exists on disk")
            continue
        if entry["mode"] == GIT_SYMLINK_MODE:
            # Verify the symlink from its literal target text (os.readlink, never
            # followed). Its git blob oid is checked HERE rather than through
            # git_blob_oids below, whose hash-object path WOULD follow the link.
            sha, size, blob = hash_symlink_nofollow(
                root, abspath, f"candidate symlink {entry['path']}")
            if size != entry["size"]:
                fail("artifact_mutated", 9, f"size mismatch for {entry['path']}")
            if sha != entry["sha256"]:
                fail("artifact_mutated", 9, f"content hash mismatch for {entry['path']}")
            if blob != entry["blob"]:
                fail("artifact_mutated", 9, f"git blob oid mismatch for {entry['path']}")
            continue
        sha, size, fs_mode = hash_regular_file(abspath, f"candidate file {entry['path']}")
        if size != entry["size"]:
            fail("artifact_mutated", 9, f"size mismatch for {entry['path']}")
        if sha != entry["sha256"]:
            fail("artifact_mutated", 9, f"content hash mismatch for {entry['path']}")
        expected_mode = "100755" if fs_mode & 0o111 else "100644"
        if entry["source"] == "untracked" and expected_mode != entry["mode"]:
            fail("artifact_mutated", 9, f"filesystem mode mismatch for {entry['path']}")

    if dirty_candidate:
        # Symlinks are excluded here: git hash-object follows the link and would
        # hash the destination. Their blob oid was already verified git-natively
        # above from the readlink target text.
        regular_present = [e["path"] for e in present if e["mode"] != GIT_SYMLINK_MODE]
        oids = git_blob_oids(root, regular_present)
        for entry in present:
            if entry["mode"] == GIT_SYMLINK_MODE:
                continue
            if oids.get(entry["path"]) != entry["blob"]:
                fail("artifact_mutated", 9, f"git blob oid mismatch for {entry['path']}")

    dirty = manifest_dirty_fingerprint(entries)
    if dirty != target["dirty_fingerprint"]:
        fail("artifact_mutated", 9,
             f"dirty-candidate fingerprint mismatch at {phase} "
             f"(expected {target['dirty_fingerprint'][:12]}…, found {dirty[:12]}…)")
    tree = manifest_tree_fingerprint([(e["mode"], e["blob"], e["path"]) for e in present])
    if tree != target["tree_fingerprint"]:
        fail("artifact_mutated", 9,
             f"candidate-tree fingerprint mismatch at {phase} "
             f"(expected {target['tree_fingerprint'][:12]}…, found {tree[:12]}…)")

    head_after = git_head(root)
    if head_after != head_before:
        fail("artifact_mutated", 9, f"candidate HEAD moved during {phase} verification")
    if dirty_candidate and head_after != target["base_head"]:
        fail("artifact_mutated", 9, f"candidate HEAD left the reviewed base during {phase}")

    for key, label in (("retained_inventory_tsv", "retained TSV inventory"),
                       ("retained_source_fingerprint", "retained source fingerprint")):
        rec = target.get(key)
        if rec is None:
            continue
        rdata, _m = read_private_bytes(rec["path"], label, MAX_MANIFEST_BYTES)
        rdigest = sha256_bytes(rdata)
        if rdigest != rec["sha256"]:
            fail("artifact_mutated", 9,
                 f"{label} SHA-256 mismatch at {phase} (expected {rec['sha256'][:12]}…, "
                 f"found {rdigest[:12]}…)")
        if key == "retained_inventory_tsv":
            rows = [ln for ln in rdata.decode("utf-8", "strict").split("\n") if ln]
            if len(rows) != rec["entry_count"]:
                fail("manifest_invalid", 11,
                     f"{label} has {len(rows)} rows but records entry_count {rec['entry_count']}")

    return {
        "manifest_sha256": digest,
        "entry_count": len(entries),
        "present_count": len(present),
        "deleted_count": len(entries) - len(present),
        "dirty_fingerprint": dirty,
        "tree_fingerprint": tree,
        "reviewed_base_head": target["base_head"],
        "observed_head": head_after,
        "root_identity": root_identity,
        "object_format": fmt,
        "inventory_recomputed": dirty_candidate,
    }


def verify_v2_base_head(norm, phase):
    """v2 repo mode: the recorded base HEAD must BE the live HEAD.

    The v3 manifest path already refuses a candidate whose HEAD is not the
    recorded base_head. Without this, a v2 bundle carrying a fabricated
    base_head was accepted by validate-bundle, authorize-launch, claim-launch,
    validate-closure and the dirty check-closure, and only failed at
    `check-closure --commit` (exit 15, commit_mismatch) — handing the reviewer a
    base that is not real and turning a legitimate promotion into a late,
    confusing false rejection (confirmed gap, L0-5 2026-07-26). Content
    integrity never depended on it, so this is defence in depth plus an honest
    early failure. Called at validation and authorization, before any reviewer
    sees the bundle; later phases keep using the fingerprint/manifest checks so
    a legitimately promoted (committed) candidate still closes.
    """
    if norm["schema"] == "tier2-evidence-v3":
        return None
    if norm["candidate_mode"] != "repo" or not norm["candidate_base_head"]:
        return None
    head = git_head(norm["candidate_root"])
    if head != norm["candidate_base_head"]:
        fail("artifact_mutated", 9,
             f"candidate HEAD is {head[:12]}… but the bundle records base_head "
             f"{norm['candidate_base_head'][:12]}… at {phase}")
    return head


def recompute_artifact_fingerprint(norm, phase, dirty_candidate=True):
    """Recompute + verify the artifact identity against current files."""
    if norm["schema"] == "tier2-evidence-v3":
        info = verify_manifest(norm, phase, dirty_candidate=dirty_candidate)
        return norm["artifact_fingerprint"], info
    recomputed = recompute_v2_fingerprint(norm)
    if recomputed != norm["artifact_fingerprint"]:
        fail("artifact_mutated", 9,
             f"recomputed artifact fingerprint {recomputed[:12]}… does not match "
             f"bundle.artifact_fingerprint {norm['artifact_fingerprint'][:12]}… at {phase}")
    return recomputed, {
        "changed_path_count": len(norm["changed_paths"]),
        "deleted_count": sum(1 for e in norm["changed_paths"] if e["status"] == "D"),
    }


# ---------------------------------------------------------------------------
# closure state
# ---------------------------------------------------------------------------

def required_providers(producer_provider):
    return ["gpt"]


def new_state(norm, controller_identity, now):
    return {
        "schema": STATE_SCHEMA,
        "tool_version": TOOL_VERSION,
        "review_id": norm["review_id"],
        "artifact_schema": norm["schema"],
        "candidate_mode": norm["candidate_mode"],
        "candidate_root": norm["candidate_root"],
        "producer_provider": norm["producer_provider"],
        "producer_identity": norm["producer_identity"],
        "controller_identity": controller_identity,
        "purpose": norm["purpose"],
        "required_reviewer_providers": required_providers(norm["producer_provider"]),
        "current_revision": norm["revision"],
        "next_ordinal": 1,
        "capability_secret": secrets.token_hex(32),
        "capability_ids": {},
        "revisions": {},
        "reviewers": {},
        "lineage": {"terminal": False, "accepted": False, "terminal_utc": None},
        "created_utc": iso(now),
        "updated_utc": iso(now),
        "events": [],
    }


def load_state(path):
    state, digest, size, _mode = load_private_json(path, "closure state", MAX_STATE_BYTES)
    if state.get("schema") != STATE_SCHEMA:
        fail("schema_invalid", 5,
             f"closure state schema must be {STATE_SCHEMA}, found {state.get('schema')!r}")
    for key in ("review_id", "producer_provider", "controller_identity", "capability_secret",
                "required_reviewer_providers", "revisions", "reviewers", "lineage",
                "capability_ids"):
        if key not in state:
            fail("schema_invalid", 5, f"closure state is missing {key}")
    return state, digest, size


def save_state(path, state, now):
    state["updated_utc"] = iso(now)
    if len(state["events"]) > MAX_EVENTS:
        fail("bound_exceeded", 6,
             f"closure state event log exceeds {MAX_EVENTS} entries; open a fresh lineage")
    return write_private_json(path, state, "closure state")


def add_event(state, now, event, **fields):
    entry = {"utc": iso(now), "event": event}
    for key, value in fields.items():
        if value is not None:
            entry[key] = value
    state["events"].append(entry)


def reviewer_record(state, provider, revision, create=False):
    reviewers = state["reviewers"]
    if provider not in reviewers:
        if not create:
            return None
        reviewers[provider] = {"reviewer_identity": None, "revisions": {}}
    revs = reviewers[provider]["revisions"]
    key = str(revision)
    if key not in revs:
        if not create:
            return None
        revs[key] = {
            "phase": "new",
            "ordinal": None,
            "capability_id": None,
            "capability_path": None,
            "authorized_utc": None,
            "claimed_utc": None,
            "recorded_utc": None,
            "void_count": 0,
            "void_reasons": [],
            "retry_count": 0,
            "result_digest": None,
            "verdict": None,
            "accepted": None,
            "terminal": False,
        }
    return revs[key]


def capability_binding(state, payload):
    material = canonical_json({k: v for k, v in payload.items() if k != "binding"})
    return hmac.new(bytes.fromhex(state["capability_secret"]), material, hashlib.sha256).hexdigest()


def load_capability(path):
    cap, digest, _size, _mode = load_private_json(path, "launch capability", MAX_CAPABILITY_BYTES)
    if cap.get("schema") != CAPABILITY_SCHEMA:
        fail("capability_invalid", 7,
             f"launch capability schema must be {CAPABILITY_SCHEMA}")
    label = "capability"
    fields = {
        "capability_id": want_str(cap, "capability_id", label, max_chars=64),
        "review_id": want_str(cap, "review_id", label),
        "revision": want_int(cap, "revision", label, low=1, high=2),
        "ordinal": want_int(cap, "ordinal", label, low=1, high=64),
        "state_path": check_abs_path(want_str(cap, "state_path", label, max_chars=4096),
                                     "capability.state_path"),
        "bundle_path": check_abs_path(want_str(cap, "bundle_path", label, max_chars=4096),
                                      "capability.bundle_path"),
        "bundle_digest": want_hex64(cap, "bundle_digest", label),
        "artifact_fingerprint": want_hex64(cap, "artifact_fingerprint", label),
        "artifact_schema": want_enum(cap, "artifact_schema", BUNDLE_SCHEMAS, label),
        "controller_identity": want_str(cap, "controller_identity", label),
        "producer_provider": want_enum(cap, "producer_provider", PRODUCER_PROVIDERS, label),
        "producer_identity": want_str(cap, "producer_identity", label),
        "reviewer_provider": want_enum(cap, "reviewer_provider", REVIEWER_PROVIDERS, label),
        "reviewer_identity": want_str(cap, "reviewer_identity", label, required=False),
        "issued_utc": iso(parse_iso(cap.get("issued_utc"), "capability.issued_utc")),
        "expires_utc": iso(parse_iso(cap.get("expires_utc"), "capability.expires_utc")),
        "binding": want_hex64(cap, "binding", label),
    }
    if not re.match(r"\A[0-9a-f]{32}\Z", fields["capability_id"]):
        fail("capability_invalid", 7, "capability_id must be 32 lowercase hex characters")
    return cap, fields, digest


def check_lineage_open(state, provider, revision, phase_label):
    lineage = state["lineage"]
    if lineage.get("terminal"):
        fail("lineage_terminal", 8,
             f"review_id {state['review_id']} is terminal "
             f"({lineage.get('terminal_verdict') or 'closed'}); {phase_label} is forbidden")
    prior = reviewer_record(state, provider, 1)
    if revision == 2:
        if prior is None or prior["phase"] != "recorded":
            fail("state_invalid", 8,
                 f"revision 2 requires a recorded revision-1 result for reviewer provider "
                 f"{provider}")
        if prior["verdict"] != "FAIL":
            fail("lineage_terminal", 8,
                 f"revision 2 is only authorized after a revision-1 FAIL; revision 1 was "
                 f"{prior['verdict']}")


def verdict_terminal(revision, verdict):
    if revision == 2:
        return True
    return verdict in ACCEPTED_VERDICTS


def refresh_lineage(state, now):
    required = state["required_reviewer_providers"]
    finals = {}
    for provider in required:
        record = None
        for revision in (2, 1):
            candidate = reviewer_record(state, provider, revision)
            if candidate is not None and candidate["phase"] == "recorded":
                record = candidate
                break
        if record is None:
            state["lineage"]["terminal"] = False
            state["lineage"]["accepted"] = False
            state["lineage"]["terminal_utc"] = None
            state["lineage"]["terminal_verdict"] = None
            return state["lineage"]
        finals[provider] = record
    if not all(rec["terminal"] for rec in finals.values()):
        state["lineage"]["terminal"] = False
        state["lineage"]["accepted"] = False
        state["lineage"]["terminal_utc"] = None
        state["lineage"]["terminal_verdict"] = None
        return state["lineage"]
    accepted = all(rec["accepted"] for rec in finals.values())
    verdicts = sorted({rec["verdict"] for rec in finals.values()})
    state["lineage"]["terminal"] = True
    state["lineage"]["accepted"] = accepted
    state["lineage"]["terminal_utc"] = iso(now)
    state["lineage"]["terminal_verdict"] = verdicts[0] if len(verdicts) == 1 else "/".join(verdicts)
    return state["lineage"]


# ---------------------------------------------------------------------------
# review result
# ---------------------------------------------------------------------------

def parse_result(path):
    result, digest, size, _mode = load_private_json(path, "review result", MAX_RESULT_BYTES)
    label = "result"
    result_schema = result.get("schema")
    if result_schema not in RESULT_SCHEMAS:
        fail("result_contract", 10,
             f"review result schema must be one of {list(RESULT_SCHEMAS)}")
    out = {
        "review_id": check_identity(want_str(result, "review_id", label), f"{label}.review_id"),
        "revision": want_int(result, "revision", label, low=1, high=2),
        "ordinal": want_int(result, "ordinal", label, low=1, high=64),
        "capability_id": want_str(result, "capability_id", label, max_chars=64),
        "bundle_digest": want_hex64(result, "bundle_digest", label),
        "artifact_fingerprint": want_hex64(result, "artifact_fingerprint", label),
        "controller_identity": check_identity(want_str(result, "controller_identity", label),
                                              f"{label}.controller_identity"),
        "producer_provider": want_enum(result, "producer_provider", PRODUCER_PROVIDERS, label),
        "reviewer_provider": want_enum(result, "reviewer_provider", REVIEWER_PROVIDERS, label),
        "reviewer_identity": check_identity(want_str(result, "reviewer_identity", label),
                                            f"{label}.reviewer_identity"),
        "completed_utc": iso(parse_iso(result.get("completed_utc"), f"{label}.completed_utc")),
    }
    verdict = result.get("verdict")
    if not isinstance(verdict, str) or verdict not in VERDICTS:
        fail("result_contract", 10,
             f"{label}.verdict must be exactly one of {list(VERDICTS)}")
    out["verdict"] = verdict
    risk = result.get("risk_summary")
    if not isinstance(risk, str) or not risk.strip():
        fail("result_contract", 10, f"{label}.risk_summary is required")
    if len(risk) > MAX_RISK_SUMMARY_CHARS:
        fail("bound_exceeded", 6,
             f"{label}.risk_summary exceeds {MAX_RISK_SUMMARY_CHARS} characters")
    check_text_safe(risk, f"{label}.risk_summary")
    if verdict == "PASS" and risk.strip().casefold() != "none":
        fail("result_contract", 10, "PASS requires risk_summary == \"none\"")
    if verdict != "PASS" and risk.strip().casefold() == "none":
        fail("result_contract", 10,
             f"{verdict} requires a bounded non-\"none\" risk_summary")
    out["risk_summary"] = risk.strip()

    risks = result.get("risks")
    if risks is not None:
        if not isinstance(risks, list):
            fail("result_contract", 10, f"{label}.risks must be a list")
        if len(risks) > MAX_RISK_ITEMS:
            fail("bound_exceeded", 6, f"{label}.risks exceeds {MAX_RISK_ITEMS} entries")
        for idx, item in enumerate(risks):
            il = f"{label}.risks[{idx}]"
            if not isinstance(item, dict):
                fail("result_contract", 10, f"{il} must be an object")
            want_enum(item, "severity", ("low", "medium", "high"), il)
            want_str(item, "summary", il, max_chars=500)
    out["risk_count"] = len(risks) if isinstance(risks, list) else 0

    profile = result.get("profile_evidence")
    if not isinstance(profile, dict):
        fail("result_contract", 10, f"{label}.profile_evidence is required")
    pl = f"{label}.profile_evidence"
    vehicle = want_str(profile, "vehicle", pl, max_chars=128)
    model = want_str(profile, "model", pl, max_chars=64)
    effort = want_enum(profile, "effort", EFFORTS, pl)
    selection = want_enum(profile, "selection", SELECTION_CLAIMS, pl)
    detail = want_str(profile, "detail", pl, required=False, max_chars=500)
    if out["reviewer_provider"] == "claude":
        if model not in CLAUDE_REVIEW_MODELS:
            fail("result_contract", 10,
                 "claude adversarial reviewer model must be fable or opus")
        if effort not in CLAUDE_REVIEW_EFFORTS:
            fail("result_contract", 10,
                 "claude adversarial reviewer effort must be low, medium, or high")
        if result_schema == RESULT_SCHEMA:
            want_canonical = CLAUDE_REVIEW_CANONICAL[model]
            canonical = want_str(profile, "canonical_model", pl, max_chars=64)
            if canonical != want_canonical:
                fail("result_contract", 10,
                     f"claude canonical_model must be exactly {want_canonical} for model {model}")
            active = profile.get("active_canonical_models")
            if (not isinstance(active, list) or len(active) != 1 or
                    active != [want_canonical]):
                fail("result_contract", 10,
                     f'claude active_canonical_models must be exactly ["{want_canonical}"]')
            zero_usage = profile.get("zero_token_model_usage")
            if not isinstance(zero_usage, list):
                fail("result_contract", 10,
                     "claude zero_token_model_usage must be a list")
            seen_labels = set()
            token_fields = ("inputTokens", "outputTokens",
                            "cacheCreationInputTokens", "cacheReadInputTokens")
            normalized_zero = []
            for idx, item in enumerate(zero_usage):
                zl = f"{pl}.zero_token_model_usage[{idx}]"
                if not isinstance(item, dict):
                    fail("result_contract", 10, f"{zl} must be an object")
                usage_label = want_str(item, "label", zl, max_chars=256)
                if usage_label in seen_labels:
                    fail("result_contract", 10,
                         f"{pl}.zero_token_model_usage labels must be unique")
                seen_labels.add(usage_label)
                zero_canonical = want_str(item, "canonical_model", zl, max_chars=128)
                counts = item.get("token_counts")
                if not isinstance(counts, dict):
                    fail("result_contract", 10, f"{zl}.token_counts must be an object")
                normalized_counts = {}
                for field in token_fields:
                    value = counts.get(field)
                    if (isinstance(value, bool) or not isinstance(value, int) or value < 0):
                        fail("result_contract", 10,
                             f"{zl}.token_counts.{field} must be a nonnegative integer")
                    normalized_counts[field] = value
                if set(counts) != set(token_fields) or sum(normalized_counts.values()) != 0:
                    fail("result_contract", 10,
                         f"{zl}.token_counts must contain exactly four zero counters")
                normalized_zero.append({"label": usage_label,
                                        "canonical_model": zero_canonical,
                                        "token_counts": normalized_counts})
        else:
            canonical = None
            active = None
            normalized_zero = None
    else:
        if model not in GPT_REVIEW_MODELS:
            fail("result_contract", 10,
                 f"gpt reviewer model must be one of {list(GPT_REVIEW_MODELS)}")
        if effort != "xhigh":
            fail("result_contract", 10,
                 "gpt reviewer effort must be exactly xhigh")
        if result.get("victor_authorized_effort") is not True:
            fail("result_contract", 10,
                 "effort xhigh requires explicit Victor authorization "
                 "(result.victor_authorized_effort must be true)")
    out["profile_evidence"] = {"vehicle": vehicle, "model": model, "effort": effort,
                               "selection": selection, "detail": detail}
    if out["reviewer_provider"] == "claude" and result_schema == RESULT_SCHEMA:
        out["profile_evidence"].update({
            "canonical_model": canonical,
            "active_canonical_models": active,
            "zero_token_model_usage": normalized_zero,
        })

    mutation = result.get("mutation_check")
    if not isinstance(mutation, dict):
        fail("result_contract", 10, f"{label}.mutation_check is required")
    ml = f"{label}.mutation_check"
    status = want_enum(mutation, "status", ("unchanged", "changed"), ml)
    before = want_str(mutation, "before", ml, max_chars=256)
    after = want_str(mutation, "after", ml, max_chars=256)
    method = want_str(mutation, "method", ml, max_chars=200)
    if status != "unchanged":
        fail("artifact_mutated", 9,
             "review result reports mutation_check.status != unchanged; review fails closed")
    if before != after:
        fail("artifact_mutated", 9,
             "review result mutation_check before/after fingerprints differ")
    out["mutation_check"] = {"status": status, "before": before, "after": after, "method": method}
    return result, out, digest, size


# ---------------------------------------------------------------------------
# subcommands
# ---------------------------------------------------------------------------

def emit(subcommand, **fields):
    payload = {"ok": True, "subcommand": subcommand, "tool_version": TOOL_VERSION}
    payload.update(fields)
    sys.stdout.write(json.dumps(payload, sort_keys=True, ensure_ascii=False) + "\n")
    sys.stdout.flush()
    return 0


def cmd_validate_bundle(args):
    bundle_path = require_abs(args.bundle, "--bundle")
    _bundle, digest, size, norm = parse_bundle(bundle_path)
    if norm["producer_provider"] != args.producer:
        fail("producer_mismatch", 5,
             f"--producer {args.producer} does not match bundle.producer_provider "
             f"{norm['producer_provider']}")
    extra = args.extra_input_bytes
    if extra < 0:
        fail("usage", 2, "--extra-input-bytes must be >= 0")
    total = size + extra
    if total > MAX_REVIEWER_INPUT_BYTES:
        fail("bound_exceeded", 6,
             f"total reviewer input would be {total} bytes; bound is "
             f"{MAX_REVIEWER_INPUT_BYTES} bytes (narrow scope, never drop evidence)")
    artifact_fp, info = recompute_artifact_fingerprint(norm, "validation")
    verify_v2_base_head(norm, "validation")
    return emit(
        "validate-bundle",
        review_id=norm["review_id"],
        revision=norm["revision"],
        artifact_schema=norm["schema"],
        candidate_mode=norm["candidate_mode"],
        producer_provider=norm["producer_provider"],
        producer_identity=norm["producer_identity"],
        required_reviewer_providers=required_providers(norm["producer_provider"]),
        bundle_digest=digest,
        bundle_bytes=size,
        bundle_mode=norm["bundle_mode"],
        artifact_fingerprint=artifact_fp,
        artifact_info=info,
        reviewer_input_bytes=total,
        reviewer_input_budget_remaining=MAX_REVIEWER_INPUT_BYTES - total,
        counts={
            "changed_paths": len(norm["changed_paths"]),
            "changed_paths_advisory": norm["changed_paths_advisory"],
            "invariants": len(norm["invariants"]),
            "commands": norm["commands_count"],
            "known_limits": len(norm["known_limits"]),
            "host_readbacks": norm["host_readbacks_count"],
        },
        delta_bound=bool(norm["delta"]),
    )


def cmd_authorize_launch(args):
    bundle_path = require_abs(args.bundle, "--bundle")
    state_path = require_abs(args.state, "--state")
    cap_path = require_abs(args.capability, "--capability")
    controller = check_identity(args.controller_identity, "--controller-identity")
    provider = args.reviewer_provider
    reviewer_identity = None
    if args.reviewer_identity is not None:
        reviewer_identity = check_identity(args.reviewer_identity, "--reviewer-identity")
    ttl = args.ttl_seconds
    if ttl < 1 or ttl > MAX_CAPABILITY_TTL_S:
        fail("usage", 2, f"--ttl-seconds must be between 1 and {MAX_CAPABILITY_TTL_S}")

    _bundle, digest, size, norm = parse_bundle(bundle_path)
    required = required_providers(norm["producer_provider"])
    if provider not in required:
        fail("provenance_mismatch", 7,
             f"producer {norm['producer_provider']} requires reviewer provider(s) {required}, "
             f"not {provider}")
    if reviewer_identity is not None and same_identity(reviewer_identity, norm["producer_identity"]):
        fail("direct_producer", 7,
             "reviewer identity equals the producer identity; independent review is required")
    artifact_fp, artifact_info = recompute_artifact_fingerprint(norm, "authorization")
    verify_v2_base_head(norm, "authorization")
    now = utcnow()

    with StateLock(state_path):
        exists = os.path.lexists(state_path)
        if exists:
            state, _sd, _ss = load_state(state_path)
            if state["review_id"] != norm["review_id"]:
                fail("state_invalid", 8,
                     f"closure state belongs to review_id {state['review_id']}, bundle is "
                     f"{norm['review_id']}")
            if not same_identity(state["controller_identity"], controller):
                fail("state_invalid", 8,
                     "controller identity does not match the closure state's controller")
            if state["producer_provider"] != norm["producer_provider"] or \
                    not same_identity(state["producer_identity"], norm["producer_identity"]):
                fail("state_invalid", 8, "bundle producer does not match the closure state")
            if state["artifact_schema"] != norm["schema"]:
                fail("state_invalid", 8,
                     "bundle evidence schema does not match the closure state")
        else:
            if norm["revision"] != 1:
                fail("state_invalid", 8,
                     "revision 2 requires an existing closure state with a recorded FAIL")
            state = new_state(norm, controller, now)

        check_lineage_open(state, provider, norm["revision"], "authorization")

        record = reviewer_record(state, provider, norm["revision"], create=True)
        bound_identity = state["reviewers"][provider]["reviewer_identity"]
        if record["phase"] in ("authorized", "claimed"):
            fail("duplicate_capability", 7,
                 f"reviewer provider {provider} already has a live {record['phase']} capability "
                 f"for revision {norm['revision']}")
        if record["phase"] == "recorded":
            fail("lineage_terminal", 8,
                 f"reviewer provider {provider} already has a recorded result for revision "
                 f"{norm['revision']}")
        if record["phase"] == "voided":
            if record["retry_count"] >= 1:
                fail("void_exhausted", 12,
                     "one void retry was already authorized for this reviewer and revision; "
                     "a second transport failure requires a fresh lineage")
            if bound_identity is None:
                fail("state_invalid", 8,
                     "voided launch has no bound reviewer identity; open a fresh lineage")
            if reviewer_identity is None:
                fail("capability_invalid", 7,
                     "retry authorization must carry --reviewer-identity equal to the "
                     "originally claimed reviewer identity")
            if not same_identity(reviewer_identity, bound_identity):
                fail("identity_mismatch", 7,
                     "retry authorization must reuse the originally claimed reviewer identity")
            record["retry_count"] += 1
        elif bound_identity is not None and reviewer_identity is not None and \
                not same_identity(reviewer_identity, bound_identity):
            fail("identity_mismatch", 7,
                 "reviewer identity differs from the identity already bound for this provider")

        rev_key = str(norm["revision"])
        prior_rev = state["revisions"].get(rev_key)
        if prior_rev is not None:
            if prior_rev["bundle_digest"] != digest or \
                    prior_rev["artifact_fingerprint"] != artifact_fp:
                fail("state_invalid", 8,
                     f"revision {rev_key} was frozen at a different bundle digest / artifact "
                     "fingerprint; mutating a frozen revision is forbidden")
        else:
            if norm["revision"] == 2:
                delta = norm["delta"]
                prev = state["revisions"].get("1")
                if prev is None:
                    fail("state_invalid", 8, "revision 1 was never frozen in this lineage")
                if delta["failed_evidence_digest"] != prev["bundle_digest"]:
                    fail("state_invalid", 8,
                         "delta.failed_evidence_digest does not bind revision 1's bundle digest")
                if delta["failed_artifact_fingerprint"] != prev["artifact_fingerprint"]:
                    fail("state_invalid", 8,
                         "delta.failed_artifact_fingerprint does not bind revision 1's artifact "
                         "fingerprint")
                bound = {d["reviewer_provider"]: d for d in delta["failed_results"]}
                if provider not in bound:
                    fail("state_invalid", 8,
                         f"delta.failed_results does not bind reviewer provider {provider}")
                prior1 = reviewer_record(state, provider, 1)
                if bound[provider]["result_digest"] != prior1["result_digest"]:
                    fail("state_invalid", 8,
                         f"delta.failed_results[{provider}].result_digest does not bind the "
                         "recorded revision-1 result digest")
                if not same_identity(bound[provider]["reviewer_identity"],
                                     state["reviewers"][provider]["reviewer_identity"]):
                    fail("identity_mismatch", 7,
                         "delta must bind the same reviewer identity that produced the FAIL")
            state["revisions"][rev_key] = {
                "bundle_path": bundle_path,
                "bundle_digest": digest,
                "bundle_bytes": size,
                "artifact_fingerprint": artifact_fp,
                "artifact_target": norm["artifact_target"],
                "frozen_utc": iso(now),
            }
        state["current_revision"] = max(state["current_revision"], norm["revision"])

        if bound_identity is None and reviewer_identity is not None:
            state["reviewers"][provider]["reviewer_identity"] = reviewer_identity
        effective_identity = state["reviewers"][provider]["reviewer_identity"]

        ordinal = state["next_ordinal"]
        state["next_ordinal"] = ordinal + 1
        cap_id = secrets.token_hex(16)
        if cap_id in state["capability_ids"]:
            fail("capability_invalid", 7, "capability id collision; retry authorization")
        payload = {
            "schema": CAPABILITY_SCHEMA,
            "tool_version": TOOL_VERSION,
            "capability_id": cap_id,
            "review_id": state["review_id"],
            "revision": norm["revision"],
            "ordinal": ordinal,
            "state_path": state_path,
            "bundle_path": bundle_path,
            "bundle_digest": digest,
            "artifact_fingerprint": artifact_fp,
            "artifact_schema": norm["schema"],
            "candidate_mode": norm["candidate_mode"],
            "candidate_root": norm["candidate_root"],
            "controller_identity": controller,
            "producer_provider": norm["producer_provider"],
            "producer_identity": norm["producer_identity"],
            "reviewer_provider": provider,
            "reviewer_identity": effective_identity,
            "purpose": norm["purpose"],
            "issued_utc": iso(now),
            "expires_utc": iso(now + datetime.timedelta(seconds=ttl)),
        }
        payload["binding"] = capability_binding(state, payload)
        if os.path.lexists(cap_path):
            fail("duplicate_capability", 7,
                 f"--capability path already exists; never overwrite a capability: {cap_path}")

        record.update({
            "phase": "authorized",
            "ordinal": ordinal,
            "capability_id": cap_id,
            "capability_path": cap_path,
            "authorized_utc": iso(now),
        })
        state["capability_ids"][cap_id] = {
            "reviewer_provider": provider,
            "revision": norm["revision"],
            "ordinal": ordinal,
            "status": "issued",
            "issued_utc": iso(now),
        }
        add_event(state, now, "authorize", provider=provider, revision=norm["revision"],
                  ordinal=ordinal, capability_id=cap_id)
        cap_digest, _cap_bytes = write_private_json(cap_path, payload, "launch capability")
        try:
            save_state(state_path, state, now)
        except BaseException:
            try:
                os.unlink(cap_path)
            except OSError:
                pass
            raise

    return emit(
        "authorize-launch",
        review_id=state["review_id"],
        revision=norm["revision"],
        ordinal=ordinal,
        phase="authorized",
        reviewer_provider=provider,
        reviewer_identity=effective_identity,
        controller_identity=controller,
        producer_provider=norm["producer_provider"],
        bundle_digest=digest,
        artifact_fingerprint=artifact_fp,
        artifact_schema=norm["schema"],
        artifact_info=artifact_info,
        capability_id=cap_id,
        capability_path=cap_path,
        capability_digest=cap_digest,
        expires_utc=payload["expires_utc"],
        required_reviewer_providers=state["required_reviewer_providers"],
        retry=bool(record["retry_count"]),
    )


def cmd_claim_launch(args):
    state_path = require_abs(args.state, "--state")
    cap_path = require_abs(args.capability, "--capability")
    reviewer_identity = check_identity(args.reviewer_identity, "--reviewer-identity")
    input_bytes = args.reviewer_input_bytes
    now = utcnow()

    _cap_raw, cap, cap_digest = load_capability(cap_path)
    if cap["state_path"] != state_path:
        fail("capability_invalid", 7,
             "capability is bound to a different closure state path")
    if args.reviewer_provider is not None and args.reviewer_provider != cap["reviewer_provider"]:
        fail("capability_invalid", 7,
             f"--reviewer-provider {args.reviewer_provider} does not match the capability's "
             f"{cap['reviewer_provider']}")

    bundle_path = require_abs(cap["bundle_path"], "capability.bundle_path")
    _bundle, digest, size, norm = parse_bundle(bundle_path)
    if digest != cap["bundle_digest"]:
        fail("artifact_mutated", 9,
             "evidence bundle digest changed since authorization; review fails closed")
    if input_bytes is not None:
        if input_bytes < 0:
            fail("usage", 2, "--reviewer-input-bytes must be >= 0")
        total = max(input_bytes, size)
        if total > MAX_REVIEWER_INPUT_BYTES:
            fail("bound_exceeded", 6,
                 f"declared reviewer input {total} bytes exceeds {MAX_REVIEWER_INPUT_BYTES}")
    artifact_fp, artifact_info = recompute_artifact_fingerprint(norm, "claim")
    if artifact_fp != cap["artifact_fingerprint"]:
        fail("artifact_mutated", 9,
             "artifact fingerprint changed since authorization; review fails closed")

    with StateLock(state_path):
        state, _sd, _ss = load_state(state_path)
        if state["review_id"] != cap["review_id"]:
            fail("capability_invalid", 7, "capability review_id does not match the closure state")
        expected = capability_binding(state, _cap_raw)
        if not hmac.compare_digest(expected, cap["binding"]):
            fail("capability_invalid", 7,
                 "capability binding does not verify against the closure state")
        ledger = state["capability_ids"].get(cap["capability_id"])
        if ledger is None:
            fail("capability_missing", 7,
                 "capability id is unknown to the closure state (forged or wrong state)")
        if ledger["status"] != "issued":
            fail("capability_replayed", 7,
                 f"capability was already {ledger['status']}; capabilities are single-use")
        provider = cap["reviewer_provider"]
        if ledger["reviewer_provider"] != provider or ledger["revision"] != cap["revision"] \
                or ledger["ordinal"] != cap["ordinal"]:
            fail("capability_invalid", 7, "capability ledger fields do not match the capability")
        if same_identity(reviewer_identity, state["producer_identity"]):
            fail("direct_producer", 7,
                 "reviewer identity equals the producer identity; independent review is required")
        record = reviewer_record(state, provider, cap["revision"])
        if record is None or record["phase"] != "authorized":
            fail("state_invalid", 8,
                 f"reviewer provider {provider} revision {cap['revision']} is not in the "
                 f"authorized phase (phase "
                 f"{record['phase'] if record else 'new'})")
        if record["capability_id"] != cap["capability_id"]:
            fail("capability_replayed", 7,
                 "a different capability is live for this reviewer and revision")
        bound = state["reviewers"][provider]["reviewer_identity"]
        if cap["reviewer_identity"] is not None and \
                not same_identity(cap["reviewer_identity"], reviewer_identity):
            # identity mismatch must not consume the capability
            fail("identity_mismatch", 7,
                 "claimed reviewer identity does not match the capability's bound identity; "
                 "the capability was not consumed")
        if bound is not None and not same_identity(bound, reviewer_identity):
            fail("identity_mismatch", 7,
                 "claimed reviewer identity does not match the identity bound to this provider; "
                 "the capability was not consumed")
        if utcnow() > parse_iso(cap["expires_utc"], "capability.expires_utc"):
            fail("stale_capability", 8,
                 f"capability expired at {cap['expires_utc']}; re-authorize a fresh lineage step")
        if state["lineage"].get("terminal"):
            fail("lineage_terminal", 8, "lineage is terminal; claiming a launch is forbidden")

        state["reviewers"][provider]["reviewer_identity"] = reviewer_identity
        record["phase"] = "claimed"
        record["claimed_utc"] = iso(now)
        record["capability_digest"] = cap_digest
        record["reviewer_input_bytes"] = input_bytes
        ledger["status"] = "claimed"
        ledger["claimed_utc"] = iso(now)
        add_event(state, now, "claim", provider=provider, revision=cap["revision"],
                  ordinal=cap["ordinal"], capability_id=cap["capability_id"])
        save_state(state_path, state, now)

    return emit(
        "claim-launch",
        review_id=state["review_id"],
        revision=cap["revision"],
        ordinal=cap["ordinal"],
        phase="claimed",
        reviewer_provider=cap["reviewer_provider"],
        reviewer_identity=reviewer_identity,
        controller_identity=state["controller_identity"],
        producer_provider=state["producer_provider"],
        capability_id=cap["capability_id"],
        bundle_path=bundle_path,
        bundle_digest=digest,
        bundle_bytes=size,
        artifact_fingerprint=artifact_fp,
        artifact_schema=norm["schema"],
        artifact_info=artifact_info,
        candidate_mode=norm["candidate_mode"],
        candidate_root=norm["candidate_root"],
        purpose=norm["purpose"],
        claimed_utc=iso(now),
        result_schema=RESULT_SCHEMA,
        reviewer_input_budget_remaining=MAX_REVIEWER_INPUT_BYTES - size,
    )


def cmd_void_launch(args):
    state_path = require_abs(args.state, "--state")
    cap_path = require_abs(args.capability, "--capability")
    reviewer_identity = check_identity(args.reviewer_identity, "--reviewer-identity")
    reason = args.reason
    now = utcnow()

    _cap_raw, cap, _cap_digest = load_capability(cap_path)
    if cap["state_path"] != state_path:
        fail("capability_invalid", 7, "capability is bound to a different closure state path")

    with StateLock(state_path):
        state, _sd, _ss = load_state(state_path)
        if state["review_id"] != cap["review_id"]:
            fail("capability_invalid", 7, "capability review_id does not match the closure state")
        expected = capability_binding(state, _cap_raw)
        if not hmac.compare_digest(expected, cap["binding"]):
            fail("capability_invalid", 7,
                 "capability binding does not verify against the closure state")
        provider = cap["reviewer_provider"]
        record = reviewer_record(state, provider, cap["revision"])
        if record is None:
            fail("state_invalid", 8, "no launch record exists for this reviewer and revision")
        if record["phase"] == "recorded":
            fail("void_forbidden", 12,
                 "a review result is already recorded; a recorded result is not voidable")
        if record["void_count"] >= 1:
            fail("void_exhausted", 12,
                 "this reviewer and revision were already voided once; a second transport "
                 "failure requires a fresh lineage")
        if record["phase"] != "claimed":
            fail("void_forbidden", 12,
                 f"void requires a claimed launch; phase is {record['phase']}")
        if record["capability_id"] != cap["capability_id"]:
            fail("capability_invalid", 7,
                 "capability does not match the claimed launch for this reviewer and revision")
        bound = state["reviewers"][provider]["reviewer_identity"]
        if not same_identity(bound, reviewer_identity):
            fail("identity_mismatch", 7,
                 "void must carry the claimed reviewer identity")
        if record["void_count"] >= 1:
            fail("void_exhausted", 12,
                 "this reviewer and revision were already voided once; a second transport "
                 "failure requires a fresh lineage")
        record["phase"] = "voided"
        record["void_count"] += 1
        record["void_reasons"].append(reason)
        record["voided_utc"] = iso(now)
        record["claimed_utc"] = None
        ledger = state["capability_ids"].get(cap["capability_id"])
        if ledger is None:
            fail("capability_missing", 7, "capability id is unknown to the closure state")
        ledger["status"] = "voided"
        ledger["voided_utc"] = iso(now)
        add_event(state, now, "void", provider=provider, revision=cap["revision"],
                  ordinal=cap["ordinal"], capability_id=cap["capability_id"], reason=reason)
        save_state(state_path, state, now)

    return emit(
        "void-launch",
        review_id=state["review_id"],
        revision=cap["revision"],
        ordinal=cap["ordinal"],
        phase="voided",
        reason=reason,
        reviewer_provider=cap["reviewer_provider"],
        reviewer_identity=reviewer_identity,
        capability_id=cap["capability_id"],
        void_count=record["void_count"],
        retry_authorized=True,
        retry_identity_required=reviewer_identity,
        voided_utc=iso(now),
    )


def cmd_validate_closure(args):
    bundle_path = require_abs(args.bundle, "--bundle")
    state_path = require_abs(args.state, "--state")
    result_path = require_abs(args.result, "--result")
    max_review_s = args.max_review_seconds
    if max_review_s < 1 or max_review_s > MAX_MAX_REVIEW_S:
        fail("usage", 2, f"--max-review-seconds must be between 1 and {MAX_MAX_REVIEW_S}")
    now = utcnow()

    _bundle, digest, size, norm = parse_bundle(bundle_path)
    artifact_fp, artifact_info = recompute_artifact_fingerprint(norm, "closure")
    _result_raw, res, result_digest, result_size = parse_result(result_path)

    with StateLock(state_path):
        state, _sd, _ss = load_state(state_path)
        if state["review_id"] != norm["review_id"] or state["review_id"] != res["review_id"]:
            fail("state_invalid", 8,
                 "review_id disagreement between bundle, result and closure state")
        if not same_identity(state["controller_identity"], res["controller_identity"]):
            fail("state_invalid", 8, "result controller identity does not match the closure state")
        if state["producer_provider"] != res["producer_provider"] or \
                state["producer_provider"] != norm["producer_provider"]:
            fail("state_invalid", 8, "producer provider disagreement")
        revision = res["revision"]
        if revision != norm["revision"]:
            fail("state_invalid", 8,
                 f"result revision {revision} does not match bundle revision {norm['revision']}")
        frozen = state["revisions"].get(str(revision))
        if frozen is None:
            fail("state_invalid", 8, f"revision {revision} was never authorized in this lineage")
        if frozen["bundle_digest"] != digest:
            fail("artifact_mutated", 9,
                 "evidence bundle digest differs from the digest frozen at authorization")
        if frozen["artifact_fingerprint"] != artifact_fp:
            fail("artifact_mutated", 9,
                 "artifact fingerprint differs from the fingerprint frozen at authorization")
        if res["bundle_digest"] != digest:
            fail("result_contract", 10,
                 "result.bundle_digest does not equal the exact evidence bundle digest")
        if res["artifact_fingerprint"] != artifact_fp:
            fail("result_contract", 10,
                 "result.artifact_fingerprint does not equal the recomputed artifact fingerprint")

        provider = res["reviewer_provider"]
        if provider not in state["required_reviewer_providers"]:
            fail("provenance_mismatch", 7,
                 f"reviewer provider {provider} is not required for producer "
                 f"{state['producer_provider']}")
        if same_identity(res["reviewer_identity"], state["producer_identity"]):
            fail("direct_producer", 7, "reviewer identity equals the producer identity")
        record = reviewer_record(state, provider, revision)
        if record is None:
            fail("unrecorded_review", 8,
                 f"no authorized launch exists for reviewer provider {provider} revision "
                 f"{revision}")
        if record["phase"] == "recorded":
            if record["result_digest"] == result_digest:
                lineage = state["lineage"]
                return emit("validate-closure", review_id=state["review_id"], revision=revision,
                            ordinal=record["ordinal"], phase="recorded", idempotent=True,
                            reviewer_provider=provider,
                            reviewer_identity=state["reviewers"][provider]["reviewer_identity"],
                            verdict=record["verdict"], accepted=record["accepted"],
                            reviewer_terminal=record["terminal"],
                            lineage_terminal=lineage["terminal"],
                            lineage_accepted=lineage["accepted"],
                            result_digest=result_digest, bundle_digest=digest,
                            artifact_fingerprint=artifact_fp,
                            next_action=_next_action(state, record))
            fail("state_invalid", 8,
                 "a different result is already recorded for this reviewer and revision")
        if record["phase"] != "claimed":
            fail("unrecorded_review", 8,
                 f"review result requires a claimed launch; phase is {record['phase']}")
        if record["capability_id"] != res["capability_id"]:
            fail("capability_invalid", 7,
                 "result.capability_id does not match the claimed capability")
        if record["ordinal"] != res["ordinal"]:
            fail("result_contract", 10, "result.ordinal does not match the claimed ordinal")
        bound = state["reviewers"][provider]["reviewer_identity"]
        if not same_identity(bound, res["reviewer_identity"]):
            fail("identity_mismatch", 7,
                 "result reviewer identity does not match the claimed reviewer identity")
        claimed_at = parse_iso(record["claimed_utc"], "state.claimed_utc")
        completed_at = parse_iso(res["completed_utc"], "result.completed_utc")
        if completed_at < claimed_at - datetime.timedelta(seconds=60):
            fail("stale_result", 8,
                 "result.completed_utc predates the claim; the result is not from this launch")
        if (completed_at - claimed_at).total_seconds() > max_review_s:
            fail("stale_result", 8,
                 f"result completed {int((completed_at - claimed_at).total_seconds())}s after "
                 f"the claim; bound is {max_review_s}s")
        if (now - completed_at).total_seconds() > max_review_s:
            fail("stale_result", 8,
                 f"result is {int((now - completed_at).total_seconds())}s old at recording; "
                 f"bound is {max_review_s}s")

        accepted = res["verdict"] in ACCEPTED_VERDICTS
        terminal = verdict_terminal(revision, res["verdict"])
        record.update({
            "phase": "recorded",
            "recorded_utc": iso(now),
            "result_path": result_path,
            "result_digest": result_digest,
            "result_bytes": result_size,
            "verdict": res["verdict"],
            "risk_summary": res["risk_summary"],
            "risk_count": res["risk_count"],
            "profile_evidence": res["profile_evidence"],
            "mutation_check": res["mutation_check"],
            "completed_utc": res["completed_utc"],
            "accepted": accepted,
            "terminal": terminal,
        })
        ledger = state["capability_ids"].get(record["capability_id"])
        if ledger is not None:
            ledger["status"] = "consumed"
            ledger["consumed_utc"] = iso(now)
        add_event(state, now, "record", provider=provider, revision=revision,
                  ordinal=record["ordinal"], capability_id=record["capability_id"],
                  verdict=res["verdict"])
        lineage = refresh_lineage(state, now)
        save_state(state_path, state, now)

    return emit(
        "validate-closure",
        review_id=state["review_id"],
        revision=revision,
        ordinal=record["ordinal"],
        phase="recorded",
        idempotent=False,
        reviewer_provider=provider,
        reviewer_identity=bound,
        controller_identity=state["controller_identity"],
        producer_provider=state["producer_provider"],
        verdict=res["verdict"],
        accepted=accepted,
        risk_summary=res["risk_summary"],
        profile_evidence=res["profile_evidence"],
        mutation_check=res["mutation_check"],
        reviewer_terminal=terminal,
        lineage_terminal=lineage["terminal"],
        lineage_accepted=lineage["accepted"],
        bundle_digest=digest,
        bundle_bytes=size,
        artifact_fingerprint=artifact_fp,
        artifact_info=artifact_info,
        result_digest=result_digest,
        next_action=_next_action(state, record),
    )


def _next_action(state, record):
    lineage = state["lineage"]
    if lineage.get("terminal"):
        return "closed-accepted" if lineage.get("accepted") else "closed-failed-remediate"
    if record["phase"] == "recorded" and record["verdict"] == "FAIL" and not record["terminal"]:
        return "one-correction-wave-authorized"
    return "awaiting-remaining-required-reviewer"


def commit_check(state, norm, commit, artifact_fp):
    if norm["candidate_mode"] != "repo":
        fail("commit_unsupported", 15,
             "--commit requires candidate.mode == repo")
    if not GIT_OID.match(commit):
        fail("usage", 2, "--commit must be a full git object id (40 or 64 lowercase hex)")
    root = norm["candidate_root"]
    git_toplevel(root)
    porcelain = git_run(root, ["status", "--porcelain"], "status --porcelain")
    if porcelain.strip():
        fail("commit_mismatch", 15,
             "git-visible state is not clean; promotion requires a clean worktree")
    head = git_head(root)
    if head != commit:
        fail("commit_mismatch", 15,
             f"HEAD is {head[:12]}… but --commit is {commit[:12]}…")
    commit_tree, parents = git_commit_tree_and_parents(root, commit, "promotion commit")
    if len(parents) != 1:
        fail("commit_mismatch", 15,
             f"commit must have exactly one parent; found {len(parents)}")
    base = None
    target = norm["artifact_target"]
    if target is not None:
        base = target["base_head"]
    elif norm["candidate_base_head"]:
        base = norm["candidate_base_head"]
    if base is None:
        fail("commit_unsupported", 15, "the bundle records no reviewed base HEAD")
    if parents[0] != base:
        fail("commit_mismatch", 15,
             f"commit parent {parents[0][:12]}… is not the reviewed base HEAD {base[:12]}…")

    base_tree, _base_parents = git_commit_tree_and_parents(root, base, "reviewed base commit")
    base_raw = git_run(root, ["ls-tree", "-r", "--full-tree", "-z", base_tree],
                       "ls-tree -r reviewed base")
    base_symlinks = {}
    for record in split_nul(base_raw):
        meta, rawpath = record.split(b"\t", 1)
        mode, kind, oid = meta.decode("ascii", "strict").split(" ")
        if mode != "120000":
            continue
        path = decode_git_path(rawpath, "reviewed-base symlink path")
        if kind != "blob":
            fail("commit_mismatch", 15,
                 f"reviewed-base symlink is not a blob: {path}")
        base_symlinks[path] = (mode, oid)

    raw = git_run(root, ["ls-tree", "-r", "--full-tree", "-z", commit_tree], "ls-tree -r")
    pairs = []
    tree_paths = set()
    commit_symlinks = {}
    for record in split_nul(raw):
        meta, rawpath = record.split(b"\t", 1)
        mode, kind, oid = meta.decode("ascii", "strict").split(" ")
        path = decode_git_path(rawpath, "committed path")
        if kind == "blob" and mode == "120000":
            commit_symlinks[path] = (mode, oid)
        elif kind != "blob" or mode not in GIT_FILE_MODES:
            fail("commit_mismatch", 15,
                 f"committed tree contains an unreviewable entry ({kind} {mode}): {path}")
        pairs.append((mode, oid, path))
        tree_paths.add(path)
    pairs.sort(key=lambda p: p[2].encode("utf-8"))

    symlink_mismatches = sorted(
        path for path in set(base_symlinks) | set(commit_symlinks)
        if base_symlinks.get(path) != commit_symlinks.get(path)
    )[:5]
    if symlink_mismatches:
        fail("commit_mismatch", 15,
             "committed symlinks differ from the reviewed base "
             f"(added, deleted, changed, or type-changed; e.g. {symlink_mismatches})")

    detail = {"commit": commit, "parent": parents[0], "tree_entries": len(pairs),
              "unchanged_symlinks": len(commit_symlinks)}
    if target is not None:
        data, _m = read_private_bytes(target["manifest_path"], "git-source manifest",
                                     MAX_MANIFEST_BYTES)
        if sha256_bytes(data) != target["manifest_sha256"]:
            fail("artifact_mutated", 9, "manifest SHA-256 mismatch at consumption")
        _header, entries = parse_manifest(data, target)
        present = [e["path"] for e in entries if e["state"] == "present"]
        deleted = [e["path"] for e in entries if e["state"] == "deleted"]
        missing = sorted(set(present) - tree_paths)[:5]
        if missing:
            fail("commit_mismatch", 15,
                 f"reviewed files are absent from the commit (e.g. {missing})")
        resurrected = sorted(set(deleted) & tree_paths)[:5]
        if resurrected:
            fail("commit_mismatch", 15,
                 f"reviewed deletions are present in the commit (e.g. {resurrected})")
        tree_fp = manifest_tree_fingerprint(pairs)
        if tree_fp != target["tree_fingerprint"]:
            fail("commit_mismatch", 15,
                 f"independent commit tree fingerprint {tree_fp[:12]}… does not equal the "
                 f"reviewed candidate-tree fingerprint {target['tree_fingerprint'][:12]}…")
        detail.update({"tree_fingerprint": tree_fp, "manifest_sha256": target["manifest_sha256"],
                       "coverage": "full-tree"})
    else:
        oid_by_path = {path: oid for _mode, oid, path in pairs}
        for entry in norm["changed_paths"]:
            if entry["status"] == "D":
                if entry["path"] in tree_paths:
                    fail("commit_mismatch", 15,
                         f"reviewed deletion is present in the commit: {entry['path']}")
                continue
            if entry["path"] not in tree_paths:
                fail("commit_mismatch", 15,
                     f"reviewed file is absent from the commit: {entry['path']}")
        present = [e["path"] for e in norm["changed_paths"] if e["status"] != "D"]
        oids = git_blob_oids(root, present) if present else {}
        for path in present:
            if oids.get(path) != oid_by_path.get(path):
                fail("commit_mismatch", 15,
                     f"committed blob for {path} differs from the reviewed content")
        detail.update({"coverage": "changed-paths-only",
                       "changed_paths_verified": len(norm["changed_paths"])})
    detail["artifact_fingerprint"] = artifact_fp
    return detail


def cmd_check_closure(args):
    state_path = require_abs(args.state, "--state")
    state, state_digest, _ss = load_state(state_path)
    lineage = state["lineage"]
    required = state["required_reviewer_providers"]

    finals = {}
    for provider in required:
        record = None
        for revision in (2, 1):
            candidate = reviewer_record(state, provider, revision)
            if candidate is not None and candidate["phase"] == "recorded":
                record = candidate
                record_revision = revision
                break
        if record is None:
            fail("not_terminal", 13,
                 f"no recorded review result for required reviewer provider {provider}")
        if not record["terminal"]:
            fail("not_terminal", 13,
                 f"reviewer provider {provider} is not terminal (revision {record_revision} "
                 f"{record['verdict']}); one correction wave is still open")
        if not record["accepted"]:
            fail("not_accepted", 13,
                 f"reviewer provider {provider} terminal verdict is {record['verdict']}; "
                 "closure is not accepted")
        finals[provider] = {
            "revision": record_revision,
            "ordinal": record["ordinal"],
            "verdict": record["verdict"],
            "risk_summary": record.get("risk_summary"),
            "reviewer_identity": state["reviewers"][provider]["reviewer_identity"],
            "result_digest": record["result_digest"],
            "profile_evidence": record.get("profile_evidence"),
            "mutation_check": record.get("mutation_check"),
            "recorded_utc": record.get("recorded_utc"),
        }
    if not lineage.get("terminal") or not lineage.get("accepted"):
        fail("not_terminal", 13,
             "closure state lineage is not recorded as terminal and accepted")

    revision = max(int(k) for k in state["revisions"])
    frozen = state["revisions"][str(revision)]
    bundle_path = frozen["bundle_path"]
    _bundle, digest, size, norm = parse_bundle(bundle_path)
    if digest != frozen["bundle_digest"]:
        fail("artifact_mutated", 9,
             "the terminal evidence bundle changed on disk; closure is invalidated")
    artifact_fp, artifact_info = recompute_artifact_fingerprint(
        norm, "consumption", dirty_candidate=args.commit is None)
    if artifact_fp != frozen["artifact_fingerprint"]:
        fail("artifact_mutated", 9,
             "the reviewed artifact changed on disk; closure is invalidated")

    commit_detail = None
    if args.commit is not None:
        commit_detail = commit_check(state, norm, args.commit, artifact_fp)

    return emit(
        "check-closure",
        review_id=state["review_id"],
        revision=revision,
        terminal=True,
        accepted=True,
        terminal_verdict=lineage.get("terminal_verdict"),
        terminal_utc=lineage.get("terminal_utc"),
        controller_identity=state["controller_identity"],
        producer_provider=state["producer_provider"],
        producer_identity=state["producer_identity"],
        required_reviewer_providers=required,
        reviewers=finals,
        bundle_path=bundle_path,
        bundle_digest=digest,
        bundle_bytes=size,
        artifact_schema=norm["schema"],
        artifact_fingerprint=artifact_fp,
        artifact_info=artifact_info,
        state_digest=state_digest,
        commit_verification=commit_detail,
        consumable=True,
    )


SCHEMA_DOC = {
    "tool_version": TOOL_VERSION,
    "bounds": {
        "bundle_bytes": MAX_BUNDLE_BYTES,
        "reviewer_input_bytes": MAX_REVIEWER_INPUT_BYTES,
        "changed_paths": MAX_CHANGED_PATHS,
        "invariants": MAX_INVARIANTS,
        "commands": MAX_COMMANDS,
        "command_timeout_s": MAX_COMMAND_TIMEOUT_S,
        "manifest_bytes": MAX_MANIFEST_BYTES,
        "manifest_entries": MAX_MANIFEST_ENTRIES,
        "result_bytes": MAX_RESULT_BYTES,
        "state_bytes": MAX_STATE_BYTES,
        "risk_summary_chars": MAX_RISK_SUMMARY_CHARS,
    },
    "file_modes": {
        "read": "owner-only, non-executable, regular, O_NOFOLLOW, uid == invoking uid",
        "write": "0600",
    },
    "evidence_bundle": {
        "schema": list(BUNDLE_SCHEMAS),
        "review_id": "lineage identity, [0-9A-Za-z][0-9A-Za-z._:@+/-]*",
        "revision": "1 or 2",
        "producer_provider": list(PRODUCER_PROVIDERS),
        "producer_identity": "concrete producing agent identity",
        "purpose": "<=400 chars",
        "created_utc": "ISO-8601 UTC",
        "candidate": {
            "mode": list(CANDIDATE_MODES),
            "root": "absolute repo root (repo mode only)",
            "base_head": ("full git oid (repo mode only); must equal the live HEAD at "
                          "validate-bundle and authorize-launch"),
        },
        "changed_paths": (
            "v2: required, <=40, sorted by path bytes, "
            "{status:A|M|D|T|R, path, sha256 (null for D), from_path (R only)}; "
            "repo mode paths are repo-relative, files mode paths are absolute. "
            "v3: optional advisory summary, no sha256 required"
        ),
        "invariants": "<=12 exact invariant strings",
        "commands": "<=20 {cmd, timeout_s<=600, result, exit_code?}",
        "fingerprints": "<=20 name -> lowercase hex scoped fingerprints",
        "known_limits": "required, non-empty (use [\"none\"])",
        "host_readbacks": "optional consolidated per-host readbacks, <=20",
        "artifact_fingerprint": (
            "v2: sha256 over \"<status>\\t<sha256|->\\t<path>\\n\" records in path byte order, "
            "recomputed from live files. v3: equals artifact_target.manifest_sha256"
        ),
        "artifact_target": {
            "type": MANIFEST_KIND,
            "manifest_path": "absolute, mode 0600, OUTSIDE the reviewed repo",
            "manifest_sha256": "sha256 of the manifest bytes == artifact_fingerprint",
            "entry_count": "manifest entry lines",
            "root": "absolute repo root",
            "root_identity": "<st_dev>:<st_ino>",
            "base_head": "full git oid",
            "object_format": "sha1|sha256",
            "dirty_fingerprint": "verifier dirty-candidate fingerprint (explicit, not the identity)",
            "tree_fingerprint": "verifier candidate-tree fingerprint (explicit, not the identity)",
            "retained_inventory_tsv": "optional {path, sha256, entry_count, branch}",
            "retained_source_fingerprint": "optional {path, sha256}",
        },
        "delta": (
            "required iff revision == 2: {failed_revision:1, failed_evidence_digest, "
            "failed_artifact_fingerprint, failed_results:[{reviewer_provider, "
            "reviewer_identity, result_digest, verdict:FAIL}]}"
        ),
    },
    "git_source_manifest_v1": {
        "format": "UTF-8 JSONL, LF-terminated, header line then entries sorted by path bytes",
        "header": ("{manifest, root, root_identity, base_head, object_format, entry_count, "
                   "dirty_fingerprint, tree_fingerprint}"),
        "entry_present": "{path, state:present, source:index|untracked, mode, size, sha256, blob}",
        "entry_deleted": "{path, state:deleted, source:index, mode, size:0, sha256:null, blob:null}",
        "dirty_fingerprint": "sha256 of \"<state>\\t<source>\\t<mode>\\t<sha256|->\\t<path>\\n\"*",
        "tree_fingerprint": "sha256 of \"<mode>\\t<blob>\\t<path>\\n\" over present entries",
        "fails_closed_on": ["unsafe/control/non-UTF-8/bidi paths", "duplicates", ".git paths",
                            "ignored-only injection", "symlinks", "special files", "submodules",
                            "unmerged index", "HEAD movement", "inventory drift"],
    },
    "review_result": {
        "schema": RESULT_SCHEMA,
        "required": ["review_id", "revision", "ordinal", "capability_id", "bundle_digest",
                     "artifact_fingerprint", "controller_identity", "producer_provider",
                     "reviewer_provider", "reviewer_identity", "verdict", "risk_summary",
                     "profile_evidence", "mutation_check", "completed_utc"],
        "verdict": list(VERDICTS),
        "risk_summary": "\"none\" iff PASS; otherwise a bounded non-\"none\" summary",
        "profile_evidence": {"vehicle": "str", "model": "gpt-5.6-sol for current reviews; "
                                                          "legacy Claude result schemas remain parseable",
                              "canonical_model": "v3 Claude: canonical of the model that ran "
                                                 "(claude-fable-5 or claude-opus-5)",
                              "active_canonical_models":
                                  "v3 Claude: required exact [<canonical of the model that ran>]",
                              "zero_token_model_usage":
                                  "v3 Claude: required list of {label, canonical_model, "
                                  "token_counts:{inputTokens,outputTokens,"
                                  "cacheCreationInputTokens,cacheReadInputTokens}}, all zero",
                              "effort": "gpt: exactly xhigh; legacy Claude fields remain parseable",
                              "selection": list(SELECTION_CLAIMS),
                              "detail": "optional"},
        "legacy_result_schema": "tier2-review-result-v2 remains valid for historical results; "
                                "v3 canonical evidence is not retrofitted",
        "victor_authorized_effort": "current GPT reviews: must be true for xhigh",
        "mutation_check": {"status": "must be \"unchanged\"", "before": "hex", "after": "hex",
                            "method": "str"},
        "risks": "optional <=20 {severity:low|medium|high, summary}",
    },
    "closure_state": {
        "schema": STATE_SCHEMA,
        "note": "created by authorize-launch; mode 0600; mutations serialize on <state>.lock",
        "capability_secret": "ephemeral HMAC key for capability binding (never printed)",
    },
    "launch_capability": {
        "schema": CAPABILITY_SCHEMA,
        "single_use": "claim-launch consumes it exactly once; replay is rejected",
        "identity_binding": "unbound on first authorization, bound at claim; retries reuse it",
    },
    "launcher_cli": {
        "claim-launch": ("--state --capability --reviewer-identity [--reviewer-provider] "
                          "[--reviewer-input-bytes N]; consumes the capability once and echoes "
                          "the exact fields the review result must carry"),
        "void-launch": ("--state --capability --reviewer-identity --reason <slug>; only after a "
                         "post-claim failure that left no recorded result, at most once per "
                         "reviewer per revision"),
        "capability_ttl_seconds": {"default": DEFAULT_CAPABILITY_TTL_S, "min": 1,
                                    "max": MAX_CAPABILITY_TTL_S},
        "claim_to_record_seconds": {"default": DEFAULT_MAX_REVIEW_S, "max": MAX_MAX_REVIEW_S},
    },
    "check_closure_commit_mode": (
        "without --commit the reviewed candidate must still be the live dirty candidate "
        "(HEAD == reviewed base, exact inventory equality). With --commit the dirty inventory "
        "is expected to be gone, so the same facts are proven from the commit: clean "
        "git-visible state, HEAD == the full oid, exactly one parent equal to the reviewed "
        "base, reviewed files present and reviewed deletions absent, and an independent "
        "Git-blob tree fingerprint equal to the reviewed candidate-tree fingerprint (v3 "
        "full-tree; v2 covers only the bundle's changed paths)"),
    "terminal_closure": {
        "revision_1_pass": "terminal, forbids revision or another review",
        "revision_1_fail": "authorizes exactly one producer correction wave (revision 2)",
        "revision_2": "terminal for any verdict; no third review in a lineage",
        "void": "at most one per reviewer per revision, claimed phase only",
        "mutation": "any later mutation invalidates closure at consumption",
    },
    "void_reasons": list(VOID_REASONS),
    "exit_codes": {
        "0": "ok", "2": "usage", "3": "missing/unreadable", "4": "mode/ownership/symlink",
        "5": "schema/parse", "6": "bound exceeded", "7": "capability",
        "8": "state (stale/phase/terminal)", "9": "artifact mutation", "10": "result contract",
        "11": "git-source-manifest", "12": "void", "13": "not terminal/accepted",
        "14": "lock/concurrency", "15": "commit verification",
    },
}


def cmd_schema(_args):
    sys.stdout.write(json.dumps(SCHEMA_DOC, sort_keys=True, indent=2, ensure_ascii=False) + "\n")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="tier2_evidence.py",
        description="Sats Tier 2 evidence + closure engine (tooling only, stdlib only).",
        epilog=("Order per Tier 2 transport: validate-bundle -> authorize-launch (controller) "
                "-> claim-launch (launcher) -> [void-launch on post-claim failure] -> "
                "validate-closure -> check-closure. Every rejection prints one JSON line on "
                "stderr and exits nonzero; run `schema` for the full field contract."),
    )
    parser.add_argument("--version", action="version",
                        version=f"tier2_evidence.py {TOOL_VERSION}")
    sub = parser.add_subparsers(dest="subcommand", required=True, metavar="SUBCOMMAND")

    p = sub.add_parser("validate-bundle",
                       help="validate an evidence bundle and recompute its artifact fingerprint")
    p.add_argument("--bundle", required=True, help="absolute path to the mode-0600 bundle JSON")
    p.add_argument("--producer", required=True, choices=PRODUCER_PROVIDERS,
                   help="expected producer provider; must match the bundle")
    p.add_argument("--extra-input-bytes", type=int, default=0,
                   help="declared additional reviewer input bytes (default 0)")
    p.set_defaults(func=cmd_validate_bundle)

    p = sub.add_parser("authorize-launch",
                       help="controller-only: freeze state and mint one single-use capability")
    p.add_argument("--bundle", required=True)
    p.add_argument("--state", required=True, help="absolute closure-state path (created if absent)")
    p.add_argument("--capability", required=True,
                   help="absolute path to write; must not already exist")
    p.add_argument("--controller-identity", required=True)
    p.add_argument("--reviewer-provider", required=True, choices=REVIEWER_PROVIDERS)
    p.add_argument("--reviewer-identity", default=None,
                   help="optional on first authorization; REQUIRED and identity-bound on a "
                        "post-void retry")
    p.add_argument("--ttl-seconds", type=int, default=DEFAULT_CAPABILITY_TTL_S,
                   help=f"capability lifetime (default {DEFAULT_CAPABILITY_TTL_S})")
    p.set_defaults(func=cmd_authorize_launch)

    p = sub.add_parser("claim-launch",
                       help="launcher-only: consume the capability once and bind the reviewer")
    p.add_argument("--state", required=True)
    p.add_argument("--capability", required=True)
    p.add_argument("--reviewer-identity", required=True)
    p.add_argument("--reviewer-provider", default=None, choices=REVIEWER_PROVIDERS,
                   help="optional cross-check against the capability")
    p.add_argument("--reviewer-input-bytes", type=int, default=None,
                   help="declared total reviewer input for the bounded-input preflight")
    p.set_defaults(func=cmd_claim_launch)

    p = sub.add_parser("void-launch",
                       help="launcher-only: void a claimed launch that left no recorded result")
    p.add_argument("--state", required=True)
    p.add_argument("--capability", required=True)
    p.add_argument("--reviewer-identity", required=True,
                   help="the claimed reviewer identity")
    p.add_argument("--reason", required=True, choices=VOID_REASONS)
    p.set_defaults(func=cmd_void_launch)

    p = sub.add_parser("validate-closure",
                       help="validate and record a review result against the frozen state")
    p.add_argument("--bundle", required=True)
    p.add_argument("--result", required=True)
    p.add_argument("--state", required=True)
    p.add_argument("--max-review-seconds", type=int, default=DEFAULT_MAX_REVIEW_S,
                   help=f"claim-to-record staleness bound (default {DEFAULT_MAX_REVIEW_S})")
    p.set_defaults(func=cmd_validate_closure)

    p = sub.add_parser("check-closure",
                       help="consumption gate: terminal accepted closure, revalidated live")
    p.add_argument("--state", required=True)
    p.add_argument("--commit", default=None,
                   help="full git oid: additionally verify clean HEAD, sole reviewed parent and "
                        "an independent tree fingerprint")
    p.set_defaults(func=cmd_check_closure)

    p = sub.add_parser("schema", help="print the full field contract as JSON")
    p.set_defaults(func=cmd_schema)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except Tier2Error as exc:
        payload = {"ok": False, "subcommand": args.subcommand, "error": exc.slug,
                   "exit": exc.code, "detail": exc.detail, "tool_version": TOOL_VERSION}
        payload.update(exc.extra)
        sys.stderr.write(json.dumps(payload, sort_keys=True, ensure_ascii=False) + "\n")
        return exc.code
    except BrokenPipeError:
        return 3
    except KeyboardInterrupt:
        sys.stderr.write(json.dumps({"ok": False, "error": "interrupted", "exit": 8}) + "\n")
        return 8


if __name__ == "__main__":
    sys.exit(main())

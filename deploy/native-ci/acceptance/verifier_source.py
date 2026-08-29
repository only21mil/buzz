"""Bind the receipt verifier's tracked source and installed-file contract."""

from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path

SOURCE_RELATIVE = Path("deploy/native-ci/acceptance/verify-receipt.py")
SOURCE_GIT_MODE = 0o100755
INSTALL_PATH = Path("/usr/libexec/buzz-ci-verify-acceptance-receipt")
INSTALL_MODE = 0o755
MAX_SOURCE_BYTES = 1024 * 1024

_PACKAGE_SOURCE_PATH = Path(__file__).resolve().parents[1] / "package_source.py"
_SPEC = importlib.util.spec_from_file_location(
    "buzz_ci_package_source", _PACKAGE_SOURCE_PATH
)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("shared package source validator is unavailable")
_PACKAGE_SOURCE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_PACKAGE_SOURCE)


def tracked_verifier(source_root: Path) -> tuple[bytes, os.stat_result]:
    """Read the verifier only when Git and filesystem metadata both match."""

    return _PACKAGE_SOURCE.tracked_payload(
        source_root,
        SOURCE_RELATIVE,
        expected_git_mode=SOURCE_GIT_MODE,
        max_bytes=MAX_SOURCE_BYTES,
    )


def source_contract(source_root: Path) -> dict[str, str]:
    """Return the digest and fixed install contract for central packaging."""

    payload, metadata = tracked_verifier(source_root)
    return {
        "install_mode": f"{INSTALL_MODE:04o}",
        "install_path": str(INSTALL_PATH),
        "materialized_source_mode": f"{metadata.st_mode & 0o7777:04o}",
        "sha256": hashlib.sha256(payload).hexdigest(),
        "source_git_mode": f"{SOURCE_GIT_MODE:o}",
        "source_path": str(SOURCE_RELATIVE),
    }

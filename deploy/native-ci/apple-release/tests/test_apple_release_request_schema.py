"""Shape checks for the Apple release request profile schema and its fixtures.

The Rust validator in crates/buzz-relay/src/api/ci/apple_release.rs consumes
the same fixture files, so a fixture that drifts from the schema fails here
before it fails there.
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import unittest

APPLE_RELEASE_DIR = Path(__file__).resolve().parents[1]
SCHEMA = APPLE_RELEASE_DIR / "apple-release-request.schema.json"
FIXTURES = APPLE_RELEASE_DIR / "fixtures"

ACCEPTED = (
    "accepted-macos-notarized.json",
    "accepted-ios-testflight.json",
)
REFUSED = (
    "refused-unknown-target.json",
    "refused-unpinned-commit.json",
    "refused-secret-material.json",
    "refused-malformed-profile.json",
)

SECRET_MARKERS = ("-----BEGIN", "AuthKey_")


def check(fixture: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["check-jsonschema", "--schemafile", str(SCHEMA), str(fixture)],
        capture_output=True,
        text=True,
        check=False,
    )


class AppleReleaseRequestSchemaTests(unittest.TestCase):
    def test_schema_is_a_valid_draft_2020_12_document(self) -> None:
        result = subprocess.run(
            ["check-jsonschema", "--check-metaschema", str(SCHEMA)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        document = json.loads(SCHEMA.read_text(encoding="utf-8"))
        self.assertEqual(document["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertFalse(document["additionalProperties"])
        self.assertEqual(document["properties"]["target"]["enum"], ["macos-notarized", "ios-testflight"])
        self.assertEqual(document["properties"]["executor_class"]["const"], "apple-mbp")

    def test_fixture_inventory_is_exact(self) -> None:
        present = sorted(path.name for path in FIXTURES.glob("*.json"))
        self.assertEqual(present, sorted(ACCEPTED + REFUSED))

    def test_accepted_fixtures_validate(self) -> None:
        for name in ACCEPTED:
            with self.subTest(fixture=name):
                result = check(FIXTURES / name)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_refused_fixtures_fail_validation(self) -> None:
        for name in REFUSED:
            with self.subTest(fixture=name):
                result = check(FIXTURES / name)
                self.assertNotEqual(result.returncode, 0, f"{name} must not validate")

    def test_accepted_fixtures_carry_no_secret_material(self) -> None:
        for name in ACCEPTED:
            text = (FIXTURES / name).read_text(encoding="utf-8")
            for marker in SECRET_MARKERS:
                self.assertNotIn(marker, text, f"{name} carries {marker}")

    def test_accepted_fixtures_reference_credentials_by_name_only(self) -> None:
        for name in ACCEPTED:
            document = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
            self.assertRegex(document["signing_identity_ref"], r"^[a-z0-9][a-z0-9-]{0,63}$")
            for block in ("notarization", "testflight"):
                if block in document:
                    self.assertRegex(document[block]["credential_ref"], r"^[a-z0-9][a-z0-9-]{0,63}$")


if __name__ == "__main__":
    unittest.main()

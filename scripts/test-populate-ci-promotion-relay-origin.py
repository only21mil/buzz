#!/usr/bin/env python3
"""Focused tests for promotion-template annotation removal."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).with_name("populate-ci-promotion-relay-origin.py")
SPEC = importlib.util.spec_from_file_location("populate_ci_promotion_relay_origin", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PopulatePromotionEvidenceTests(unittest.TestCase):
    def test_documented_template_annotations_are_removed_recursively(self) -> None:
        bundle = {
            "_usage": ["guide only"],
            "staging": {"event_evidence": {"relay_url": None, "events": []}},
            "production_canary": {
                "event_evidence": {
                    "relay_url": None,
                    "requests": [{"_role": "initial", "id": "wire-id"}],
                }
            },
            "deliberate_red": {
                "event_evidence": {
                    "relay_url": None,
                    "events": [{"_role": "terminal", "content": "raw"}],
                }
            },
        }

        populated = MODULE.populate_promotion_evidence(bundle, "wss://relay.example")

        self.assertNotIn("_usage", populated)
        self.assertEqual(
            populated["production_canary"]["event_evidence"]["requests"],
            [{"id": "wire-id"}],
        )
        self.assertEqual(
            populated["deliberate_red"]["event_evidence"]["events"],
            [{"content": "raw"}],
        )
        self.assertTrue(all(
            section["event_evidence"]["relay_url"] == "https://relay.example"
            for section in (
                populated["staging"],
                populated["production_canary"],
                populated["deliberate_red"],
            )
        ))

    def test_unknown_annotation_field_is_rejected(self) -> None:
        with self.assertRaisesRegex(MODULE.EvidenceError, "unknown annotation fields"):
            MODULE.remove_template_annotations({"_typo": "must not disappear"})


if __name__ == "__main__":
    unittest.main()

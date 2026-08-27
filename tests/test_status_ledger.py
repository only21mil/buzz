from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from status_ledger import LedgerError, load_ledger, render_taskboard, validate_ledger  # noqa: E402


class StatusLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ledger = load_ledger(ROOT / "BUZZ_CI_FULL_MIGRATION_STATUS.yaml")

    def assert_rejected(self, ledger: dict, message: str) -> None:
        with self.assertRaisesRegex(LedgerError, message):
            validate_ledger(ledger)

    def test_repository_ledger_and_generated_board_are_current(self) -> None:
        validate_ledger(self.ledger)
        expected = render_taskboard(self.ledger)
        self.assertEqual(expected, (ROOT / "TASKBOARD.md").read_text(encoding="utf-8"))
        self.assertEqual(expected, render_taskboard(self.ledger))

    def test_rejects_malformed_or_short_sha(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        ledger["work_items"][0]["candidate_sha"] = "d24ab5b4"
        self.assert_rejected(ledger, "exactly 40 lowercase hexadecimal")

    def test_rejects_landed_without_ancestry_evidence(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        item = ledger["work_items"][0]
        item["program_state"] = "LANDED"
        item["landing_sha"] = "a" * 40
        self.assert_rejected(ledger, "ancestry")

    def test_rejects_review_closed_without_terminal_state(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        item = ledger["work_items"][0]
        item["review_state"] = "REVIEW_CLOSED"
        item["review_receipt"] = {
            "terminal_state": "",
            "source_sha": item["candidate_sha"],
            "check_receipt": {"result": "OK", "source_sha": item["candidate_sha"]},
        }
        self.assert_rejected(ledger, "terminal review state")

    def test_rejects_review_closed_without_check_receipt(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        item = ledger["work_items"][0]
        item["review_state"] = "REVIEW_CLOSED"
        item["review_receipt"] = {
            "terminal_state": "PASS",
            "source_sha": item["candidate_sha"],
        }
        self.assert_rejected(ledger, "check_receipt")

    def test_rejects_deployed_without_source_bound_receipt(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        ledger["authoritative_truth"]["deployment"].pop("receipt")
        self.assert_rejected(ledger, "receipt")

        ledger = copy.deepcopy(self.ledger)
        ledger["authoritative_truth"]["deployment"]["receipt"]["source_sha"] = "f" * 40
        self.assert_rejected(ledger, "not bound to deployed_sha")

    def test_rejects_active_work_under_owner_stop(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        ledger["work_items"][0]["program_state"] = "INTEGRATING"
        self.assert_rejected(ledger, "cannot be active under FROZEN_OWNER_STOP without exact scoped authority")

    def test_rejects_active_review_under_owner_stop(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        ledger["work_items"][0]["review_state"] = "REVIEWING"
        self.assert_rejected(ledger, "cannot have an active review under FROZEN_OWNER_STOP")

    def test_rejects_started_downstream_gate(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        ledger["execution_checkpoint"]["downstream_states"]["merge"]["state"] = "RUNNING"
        self.assert_rejected(ledger, "invalid state or approval record")

    def test_rejects_active_web_work_without_exact_scope(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        item = next(item for item in ledger["work_items"] if item["id"] == "BCI-WEB-PARITY-01")
        item["scoped_active"]["owner_agent"] = "/root/someone_else"
        self.assert_rejected(ledger, "without exact scoped authority")

    def test_rejects_repository_ref_sha_drift(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        ledger["repository_delivery"]["github_mirror"]["ref_sha"] = "f" * 40
        self.assert_rejected(ledger, "not bound to source_sha")

    def test_checkpoint_candidate_must_match_work_item(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        ledger["execution_checkpoint"]["source_candidates"][0]["candidate_sha"] = "f" * 40
        self.assert_rejected(ledger, "does not match its work item")

    def test_rejects_unqualified_legacy_label(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        ledger["work_items"][0]["title"] = "Unqualified B1 work"
        self.assert_rejected(ledger, "unqualified B1")

    def test_requires_exactly_two_qualified_aliases(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        ledger["aliases"]["legacy_b1"]["B1"] = "BCI-P1-EXEC-01"
        self.assert_rejected(ledger, "exactly the two qualified aliases")

    def test_contradictions_must_be_unknown(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        item = ledger["work_items"][0]
        item["contradictions"] = [{"field": "candidate_sha", "claims": [item["candidate_sha"], "f" * 40]}]
        self.assert_rejected(ledger, "contradictions must resolve to UNKNOWN")

    def test_rejects_short_sha_inside_contradiction(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        item = ledger["work_items"][16]
        item["contradictions"][0]["claims"][0] = "81fc41a9"
        self.assert_rejected(ledger, "exactly 40 lowercase hexadecimal")

    def test_rejects_lower_precedence_resolution(self) -> None:
        ledger = copy.deepcopy(self.ledger)
        item = ledger["work_items"][11]
        item["resolution"]["selected_evidence_ref"] = "recovery-plan-normal-execution"
        self.assert_rejected(ledger, "violates evidence precedence")


if __name__ == "__main__":
    unittest.main()

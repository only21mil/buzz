#!/usr/bin/env python3
"""Validate the Buzz CI status ledger and render its frozen task board."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any, Iterable

import yaml


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
EVENT_ID_RE = re.compile(r"^[0-9a-f]{64}$")
STATE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
WORK_ID_RE = re.compile(r"^BCI-[A-Z0-9]+(?:-[A-Z0-9]+)+$")
UNQUALIFIED_B1_RE = re.compile(r"(?<![A-Z0-9/-])B1(?![A-Z0-9/-])")
ALLOWED_STATES = {
    "FROZEN",
    "INTEGRATING",
    "READY_FOR_CI",
    "CI_GREEN",
    "REVIEWING",
    "REVIEW_CLOSED",
    "LANDED",
    "DEPLOYED",
    "BLOCKED",
    "SUPERSEDED",
    "UNKNOWN",
}
ACTIVE_STATES = {"INTEGRATING", "READY_FOR_CI", "CI_GREEN", "REVIEWING"}
TERMINAL_REVIEW_STATES = {"PASS", "PASS_WITH_RISKS", "FAIL"}
EXPECTED_ALIASES = {
    "P0-RELAY/B1": "BCI-P0-RELAY-01",
    "P1-EXEC/B1": "BCI-P1-EXEC-01",
}
EXPECTED_ROSTER_MIGRATIONS = [
    {"from": "DSV4F", "to": "Knots", "model": "qwen/qwen3.8-flash", "reasoning": "inherited"},
    {"from": "GSV4F.2", "to": "Segwit", "model": "z-ai/glm-5.3-flash", "reasoning": "inherited"},
    {"from": "GLM5.2", "to": "Ledger", "model": "z-ai/glm-5.3-flash", "reasoning": "inherited"},
    {"from": "Codex-2", "to": "UTXO", "model": "preserve-current", "reasoning": "preserve-current"},
]
REQUIRED_DOWNSTREAM_GATES = {
    "tier2_review",
    "install",
    "push",
    "pr",
    "ci",
    "merge",
    "credentials_and_signing",
    "docker_sudo_services",
    "deployment",
    "mgact_activation",
    "live_parity",
}
EXPECTED_DOWNSTREAM_STATES = {
    "tier2_review": "NOT_STARTED",
    "install": "NOT_STARTED",
    "push": "COMPLETE",
    "pr": "DRAFT_OPEN",
    "ci": "RUNNING",
    "merge": "NOT_STARTED",
    "credentials_and_signing": "NOT_STARTED",
    "docker_sudo_services": "NOT_STARTED",
    "deployment": "NOT_STARTED",
    "mgact_activation": "NOT_STARTED",
    "live_parity": "NOT_STARTED",
}
REQUIRED_ITEM_FIELDS = {
    "id",
    "title",
    "lane",
    "program_state",
    "owner_event",
    "observed_at",
    "evidence_ref",
    "branch",
    "candidate_sha",
    "review_state",
    "promotion_sha",
    "landing_sha",
    "deployed_sha",
    "blockers",
    "dependencies",
    "verification_state",
    "evidence",
    "resolution",
    "contradictions",
}


class LedgerError(ValueError):
    pass


def load_ledger(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise LedgerError(f"cannot load ledger: {exc}") from exc
    if not isinstance(data, dict):
        raise LedgerError("ledger root must be a mapping")
    return data


def _require_mapping(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise LedgerError(f"{where} must be a mapping")
    return value


def _require_full_sha(value: Any, where: str, *, nullable: bool = False) -> None:
    if value is None and nullable:
        return
    if not isinstance(value, str) or SHA_RE.fullmatch(value) is None:
        suffix = " or null" if nullable else ""
        raise LedgerError(f"{where} must be exactly 40 lowercase hexadecimal characters{suffix}")


def _require_event_id(value: Any, where: str) -> None:
    if not isinstance(value, str) or EVENT_ID_RE.fullmatch(value) is None:
        raise LedgerError(f"{where} must be exactly 64 lowercase hexadecimal characters")


def _require_state_id(value: Any, where: str) -> None:
    if not isinstance(value, str) or STATE_ID_RE.fullmatch(value) is None:
        raise LedgerError(f"{where} must be exactly 32 lowercase hexadecimal characters")


def _require_url(value: Any, where: str, schemes: tuple[str, ...]) -> None:
    if not isinstance(value, str) or not value.startswith(schemes):
        raise LedgerError(f"{where} must use one of these URL schemes: {', '.join(schemes)}")


def _walk_sha_fields(value: Any, path: str = "ledger") -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if key.endswith("_sha"):
                yield child_path, child
            yield from _walk_sha_fields(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_sha_fields(child, f"{path}[{index}]")


def _walk_strings(value: Any, path: str = "ledger") -> Iterable[tuple[str, str]]:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if isinstance(key, str):
                yield f"{path}.<key>", key
            yield from _walk_strings(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_strings(child, f"{path}[{index}]")
    elif isinstance(value, str):
        yield path, value


def _validate_deployment(deployment: dict[str, Any], where: str) -> None:
    deployed_sha = deployment.get("deployed_sha")
    _require_full_sha(deployed_sha, f"{where}.deployed_sha")
    receipt = _require_mapping(deployment.get("receipt"), f"{where}.receipt")
    if receipt.get("result") != "PASS":
        raise LedgerError(f"{where}.receipt.result must be PASS")
    _require_full_sha(receipt.get("source_sha"), f"{where}.receipt.source_sha")
    if receipt.get("source_sha") != deployed_sha:
        raise LedgerError(f"{where} deployment receipt is not bound to deployed_sha")
    for field in ("artifact_ref", "observed_at"):
        if not isinstance(receipt.get(field), str) or not receipt[field].strip():
            raise LedgerError(f"{where}.receipt.{field} must be non-empty")


def _validate_review(item: dict[str, Any], where: str) -> None:
    if item["review_state"] != "REVIEW_CLOSED":
        return
    receipt = _require_mapping(item.get("review_receipt"), f"{where}.review_receipt")
    if receipt.get("terminal_state") not in TERMINAL_REVIEW_STATES:
        raise LedgerError(f"{where} review closure requires a terminal review state")
    source_sha = receipt.get("source_sha")
    _require_full_sha(source_sha, f"{where}.review_receipt.source_sha")
    eligible = item.get("promotion_sha") or item.get("candidate_sha")
    if source_sha != eligible:
        raise LedgerError(f"{where} review receipt is not bound to the eligible candidate")
    check = _require_mapping(receipt.get("check_receipt"), f"{where}.review_receipt.check_receipt")
    if check.get("result") != "OK":
        raise LedgerError(f"{where} review closure requires an OK check receipt")
    _require_full_sha(check.get("source_sha"), f"{where}.review_receipt.check_receipt.source_sha")
    if check.get("source_sha") != source_sha:
        raise LedgerError(f"{where} check receipt is not bound to the reviewed candidate")


def _validate_landing(item: dict[str, Any], where: str) -> None:
    if item["program_state"] not in {"LANDED", "DEPLOYED"} and item.get("landing_sha") is None:
        return
    landing_sha = item.get("landing_sha")
    _require_full_sha(landing_sha, f"{where}.landing_sha")
    ancestry = _require_mapping(item.get("ancestry"), f"{where}.ancestry")
    if ancestry.get("result") != "PASS":
        raise LedgerError(f"{where} landed state requires PASS ancestry evidence")
    expected_ancestor = item.get("promotion_sha") or item.get("candidate_sha")
    _require_full_sha(ancestry.get("ancestor_sha"), f"{where}.ancestry.ancestor_sha")
    _require_full_sha(ancestry.get("descendant_sha"), f"{where}.ancestry.descendant_sha")
    if ancestry.get("ancestor_sha") != expected_ancestor or ancestry.get("descendant_sha") != landing_sha:
        raise LedgerError(f"{where} ancestry evidence is not bound to candidate and landing SHAs")
    if not isinstance(ancestry.get("evidence_ref"), str) or not ancestry["evidence_ref"].strip():
        raise LedgerError(f"{where}.ancestry.evidence_ref must be non-empty")


def _validate_item_deploy(item: dict[str, Any], where: str) -> None:
    if item["program_state"] != "DEPLOYED" and item.get("deployed_sha") is None:
        return
    receipt = item.get("deployment_receipt")
    _validate_deployment(
        {"deployed_sha": item.get("deployed_sha"), "receipt": receipt},
        f"{where}.deployment",
    )


def _validate_evidence(item: dict[str, Any], where: str) -> None:
    evidence = item["evidence"]
    if not isinstance(evidence, list) or not evidence:
        raise LedgerError(f"{where}.evidence must be a non-empty list")
    refs: set[str] = set()
    tiers: dict[str, int] = {}
    for index, entry in enumerate(evidence):
        entry = _require_mapping(entry, f"{where}.evidence[{index}]")
        tier = entry.get("tier")
        ref = entry.get("ref")
        if not isinstance(tier, int) or tier not in range(1, 6):
            raise LedgerError(f"{where}.evidence[{index}].tier must be 1 through 5")
        if not isinstance(ref, str) or not ref.strip() or ref in refs:
            raise LedgerError(f"{where}.evidence[{index}].ref must be non-empty and unique")
        if not isinstance(entry.get("claim"), str) or not entry["claim"].strip():
            raise LedgerError(f"{where}.evidence[{index}].claim must be non-empty")
        refs.add(ref)
        tiers[ref] = tier
    resolution = _require_mapping(item["resolution"], f"{where}.resolution")
    selected = resolution.get("selected_evidence_ref")
    if selected not in refs:
        raise LedgerError(f"{where} resolution must select one listed evidence ref")
    if tiers[selected] != min(tiers.values()):
        raise LedgerError(f"{where} resolution violates evidence precedence")


def validate_ledger(data: dict[str, Any]) -> None:
    if data.get("schema_version") != 1:
        raise LedgerError("schema_version must be 1")

    metadata = _require_mapping(data.get("metadata"), "metadata")
    global_state = metadata.get("global_state")
    if global_state != "FROZEN_OWNER_STOP":
        raise LedgerError("metadata.global_state must remain FROZEN_OWNER_STOP")
    stop = _require_mapping(metadata.get("stop"), "metadata.stop")
    _require_event_id(stop.get("owner_event"), "metadata.stop.owner_event")
    _require_event_id(stop.get("thread_event"), "metadata.stop.thread_event")

    precedence = data.get("evidence_precedence")
    if not isinstance(precedence, list) or [entry.get("tier") for entry in precedence] != [1, 2, 3, 4, 5]:
        raise LedgerError("evidence_precedence must define tiers 1 through 5 in order")

    aliases = _require_mapping(data.get("aliases"), "aliases")
    if aliases.get("legacy_b1") != EXPECTED_ALIASES:
        raise LedgerError("aliases.legacy_b1 must contain exactly the two qualified aliases")

    truth = _require_mapping(data.get("authoritative_truth"), "authoritative_truth")
    main = _require_mapping(truth.get("main"), "authoritative_truth.main")
    _require_full_sha(main.get("authoritative_sha"), "authoritative_truth.main.authoritative_sha")
    _validate_deployment(
        _require_mapping(truth.get("deployment"), "authoritative_truth.deployment"),
        "authoritative_truth.deployment",
    )
    mgact = _require_mapping(truth.get("mgact"), "authoritative_truth.mgact")
    if mgact.get("activation_state") != "INACTIVE" or mgact.get("program_state") != "FROZEN":
        raise LedgerError("authoritative_truth.mgact must be INACTIVE and FROZEN")

    checkpoint = _require_mapping(data.get("execution_checkpoint"), "execution_checkpoint")
    if checkpoint.get("scope") != "SOURCE_ONLY":
        raise LedgerError("execution_checkpoint.scope must be SOURCE_ONLY")
    checkpoint_candidates = checkpoint.get("source_candidates")
    if not isinstance(checkpoint_candidates, list) or not checkpoint_candidates:
        raise LedgerError("execution_checkpoint.source_candidates must be a non-empty list")
    checkpoint_ids: set[str] = set()
    for index, candidate in enumerate(checkpoint_candidates):
        candidate = _require_mapping(candidate, f"execution_checkpoint.source_candidates[{index}]")
        candidate_id = candidate.get("id")
        if not isinstance(candidate_id, str) or WORK_ID_RE.fullmatch(candidate_id) is None or candidate_id in checkpoint_ids:
            raise LedgerError("execution checkpoint candidate IDs must be unique stable work IDs")
        checkpoint_ids.add(candidate_id)
        _require_full_sha(candidate.get("candidate_sha"), f"execution_checkpoint.source_candidates[{index}].candidate_sha")
        if candidate.get("verification") != "VERIFIED_SOURCE_ONLY":
            raise LedgerError("execution checkpoint candidates must be VERIFIED_SOURCE_ONLY")
        if not isinstance(candidate.get("includes"), str) or not candidate["includes"].strip():
            raise LedgerError("execution checkpoint candidate includes text must be non-empty")
    downstream = _require_mapping(checkpoint.get("downstream_states"), "execution_checkpoint.downstream_states")
    if set(downstream) != REQUIRED_DOWNSTREAM_GATES:
        raise LedgerError("execution checkpoint must define every required downstream gate exactly once")
    for gate, raw_state in downstream.items():
        state = _require_mapping(raw_state, f"execution_checkpoint.downstream_states.{gate}")
        if state.get("state") != EXPECTED_DOWNSTREAM_STATES[gate] or state.get("approval_required") is not True:
            raise LedgerError(f"execution checkpoint gate {gate} has an invalid state or approval record")
        if state["state"] != "NOT_STARTED" and (
            not isinstance(state.get("authority"), str) or not state["authority"].strip()
        ):
            raise LedgerError(f"execution checkpoint gate {gate} requires recorded authority")
    host_contracts = checkpoint.get("remaining_host_contracts")
    if not isinstance(host_contracts, list) or not host_contracts or not all(
        isinstance(contract, str) and contract.strip() for contract in host_contracts
    ):
        raise LedgerError("execution_checkpoint.remaining_host_contracts must be non-empty strings")

    delivery = _require_mapping(data.get("repository_delivery"), "repository_delivery")
    source_sha = delivery.get("source_sha")
    base_sha = delivery.get("base_sha")
    _require_full_sha(source_sha, "repository_delivery.source_sha")
    _require_full_sha(base_sha, "repository_delivery.base_sha")
    branch = delivery.get("branch")
    if not isinstance(branch, str) or not branch.startswith("sats/"):
        raise LedgerError("repository_delivery.branch must be a qualified sats branch")
    expected_ref = f"refs/heads/{branch}"
    for name, expected_status in (("relay", "PUBLISHED"), ("github_mirror", "MIRRORED")):
        ref_record = _require_mapping(delivery.get(name), f"repository_delivery.{name}")
        if ref_record.get("status") != expected_status or ref_record.get("ref") != expected_ref:
            raise LedgerError(f"repository_delivery.{name} status or ref is invalid")
        _require_full_sha(ref_record.get("ref_sha"), f"repository_delivery.{name}.ref_sha")
        if ref_record["ref_sha"] != source_sha:
            raise LedgerError(f"repository_delivery.{name} is not bound to source_sha")
        _require_url(ref_record.get("ref_url"), f"repository_delivery.{name}.ref_url", ("https://",))
    _require_url(delivery["relay"].get("clone_url"), "repository_delivery.relay.clone_url", ("https://",))

    issue = _require_mapping(delivery.get("buzz_issue"), "repository_delivery.buzz_issue")
    if issue.get("status") != "OPEN":
        raise LedgerError("repository_delivery.buzz_issue.status must be OPEN")
    _require_event_id(issue.get("event_id"), "repository_delivery.buzz_issue.event_id")
    _require_url(issue.get("url"), "repository_delivery.buzz_issue.url", ("buzz://issue",))
    if not isinstance(issue.get("external_id"), str) or not issue["external_id"].strip():
        raise LedgerError("repository_delivery.buzz_issue.external_id must be non-empty")

    buzz_pr = _require_mapping(delivery.get("buzz_pr"), "repository_delivery.buzz_pr")
    if buzz_pr.get("status") != "DRAFT":
        raise LedgerError("repository_delivery.buzz_pr.status must be DRAFT")
    _require_event_id(buzz_pr.get("event_id"), "repository_delivery.buzz_pr.event_id")
    _require_event_id(
        buzz_pr.get("draft_status_event_id"),
        "repository_delivery.buzz_pr.draft_status_event_id",
    )
    _require_event_id(
        buzz_pr.get("checklist_update_event_id"),
        "repository_delivery.buzz_pr.checklist_update_event_id",
    )
    _require_event_id(
        buzz_pr.get("tier2_install_update_event_id"),
        "repository_delivery.buzz_pr.tier2_install_update_event_id",
    )
    _require_event_id(
        buzz_pr.get("c1_review_update_event_id"),
        "repository_delivery.buzz_pr.c1_review_update_event_id",
    )
    _require_event_id(
        buzz_pr.get("ci_auth_c1_closure_update_event_id"),
        "repository_delivery.buzz_pr.ci_auth_c1_closure_update_event_id",
    )
    _require_event_id(
        buzz_pr.get("simplelift_remediation_update_event_id"),
        "repository_delivery.buzz_pr.simplelift_remediation_update_event_id",
    )
    _require_url(buzz_pr.get("url"), "repository_delivery.buzz_pr.url", ("buzz://pr",))
    if not isinstance(buzz_pr.get("external_id"), str) or not buzz_pr["external_id"].strip():
        raise LedgerError("repository_delivery.buzz_pr.external_id must be non-empty")

    github_pr = _require_mapping(delivery.get("github_pr"), "repository_delivery.github_pr")
    if github_pr.get("status") != "OPEN" or github_pr.get("draft") is not True:
        raise LedgerError("repository_delivery.github_pr must be an open draft")
    if not isinstance(github_pr.get("number"), int) or github_pr["number"] <= 0:
        raise LedgerError("repository_delivery.github_pr.number must be positive")
    _require_url(github_pr.get("url"), "repository_delivery.github_pr.url", ("https://github.com/",))
    _require_full_sha(github_pr.get("head_sha"), "repository_delivery.github_pr.head_sha")
    _require_full_sha(github_pr.get("base_sha"), "repository_delivery.github_pr.base_sha")
    if (
        github_pr["head_sha"] != source_sha
        or github_pr["base_sha"] != base_sha
        or github_pr.get("head_ref") != branch
        or github_pr.get("base_ref") != "main"
        or github_pr.get("ci_state") != "PR_CHECKS_COMPLETE"
    ):
        raise LedgerError("repository_delivery.github_pr is not bound to the exact source/base state")
    snapshot = _require_mapping(github_pr.get("check_snapshot"), "repository_delivery.github_pr.check_snapshot")
    if not isinstance(github_pr.get("ci_observed_at"), str) or not github_pr["ci_observed_at"].strip():
        raise LedgerError("repository_delivery.github_pr.ci_observed_at must be non-empty")
    counts = [snapshot.get(key) for key in ("total", "success", "skipped", "pending", "failed")]
    if not all(isinstance(value, int) and value >= 0 for value in counts):
        raise LedgerError("repository_delivery.github_pr.check_snapshot counts must be nonnegative integers")
    if snapshot["total"] != snapshot["success"] + snapshot["skipped"] + snapshot["pending"] + snapshot["failed"]:
        raise LedgerError("repository_delivery.github_pr.check_snapshot counts do not sum to total")
    if snapshot["pending"] != 0 or snapshot["failed"] != 0:
        raise LedgerError("completed cumulative PR checks cannot be pending or failed")

    workflows = _require_mapping(delivery.get("required_workflows"), "repository_delivery.required_workflows")
    jobs = workflows.get("ci_jobs")
    if not isinstance(jobs, list) or len(jobs) != 17 or len(set(jobs)) != 17:
        raise LedgerError("repository_delivery.required_workflows.ci_jobs must contain 17 unique jobs")
    pr_workflows = workflows.get("applicable_pr_workflows")
    if not isinstance(pr_workflows, list) or not pr_workflows:
        raise LedgerError("repository_delivery.required_workflows.applicable_pr_workflows must be non-empty")
    if workflows.get("github_main_protection") != "UNPROTECTED":
        raise LedgerError("repository_delivery.required_workflows.github_main_protection must match readback")
    missing_gates = delivery.get("missing_gates")
    if not isinstance(missing_gates, list) or not missing_gates:
        raise LedgerError("repository_delivery.missing_gates must be non-empty")

    web_delivery = _require_mapping(
        delivery.get("dependent_web_parity"),
        "repository_delivery.dependent_web_parity",
    )
    web_source_sha = web_delivery.get("source_sha")
    web_tree_sha = web_delivery.get("tree_sha")
    web_base_sha = web_delivery.get("base_sha")
    _require_full_sha(web_source_sha, "repository_delivery.dependent_web_parity.source_sha")
    _require_full_sha(web_tree_sha, "repository_delivery.dependent_web_parity.tree_sha")
    _require_full_sha(web_base_sha, "repository_delivery.dependent_web_parity.base_sha")
    if web_base_sha != source_sha:
        raise LedgerError("dependent web parity base is not the cumulative source")
    web_branch = web_delivery.get("branch")
    if web_branch != "sats/web-app-parity-20260827":
        raise LedgerError("dependent web parity branch is not the qualified delivery branch")
    web_ref = f"refs/heads/{web_branch}"
    for name, expected_status in (("relay", "PUBLISHED"), ("github_mirror", "MIRRORED")):
        ref_record = _require_mapping(
            web_delivery.get(name),
            f"repository_delivery.dependent_web_parity.{name}",
        )
        if ref_record.get("status") != expected_status or ref_record.get("ref") != web_ref:
            raise LedgerError(f"dependent web parity {name} status or ref is invalid")
        _require_full_sha(
            ref_record.get("ref_sha"),
            f"repository_delivery.dependent_web_parity.{name}.ref_sha",
        )
        if ref_record["ref_sha"] != web_source_sha:
            raise LedgerError(f"dependent web parity {name} is not bound to source_sha")
        _require_url(
            ref_record.get("ref_url"),
            f"repository_delivery.dependent_web_parity.{name}.ref_url",
            ("https://",),
        )

    issue_link = _require_mapping(
        web_delivery.get("issue_link"),
        "repository_delivery.dependent_web_parity.issue_link",
    )
    _require_event_id(
        issue_link.get("issue_event_id"),
        "repository_delivery.dependent_web_parity.issue_link.issue_event_id",
    )
    _require_event_id(
        issue_link.get("status_event_id"),
        "repository_delivery.dependent_web_parity.issue_link.status_event_id",
    )
    _require_event_id(
        issue_link.get("roster_status_event_id"),
        "repository_delivery.dependent_web_parity.issue_link.roster_status_event_id",
    )
    _require_event_id(
        issue_link.get("tier2_install_status_event_id"),
        "repository_delivery.dependent_web_parity.issue_link.tier2_install_status_event_id",
    )
    _require_event_id(
        issue_link.get("c1_review_status_event_id"),
        "repository_delivery.dependent_web_parity.issue_link.c1_review_status_event_id",
    )
    _require_event_id(
        issue_link.get("ci_auth_c1_closure_status_event_id"),
        "repository_delivery.dependent_web_parity.issue_link.ci_auth_c1_closure_status_event_id",
    )
    _require_event_id(
        issue_link.get("simplelift_remediation_status_event_id"),
        "repository_delivery.dependent_web_parity.issue_link.simplelift_remediation_status_event_id",
    )
    if issue_link.get("status") != "OPEN" or issue_link["issue_event_id"] != issue["event_id"]:
        raise LedgerError("dependent web parity issue link does not match the open primary issue")

    web_buzz_pr = _require_mapping(
        web_delivery.get("buzz_pr"),
        "repository_delivery.dependent_web_parity.buzz_pr",
    )
    if web_buzz_pr.get("status") != "DRAFT":
        raise LedgerError("dependent web parity Buzz PR must be DRAFT")
    _require_event_id(
        web_buzz_pr.get("event_id"),
        "repository_delivery.dependent_web_parity.buzz_pr.event_id",
    )
    _require_event_id(
        web_buzz_pr.get("draft_status_event_id"),
        "repository_delivery.dependent_web_parity.buzz_pr.draft_status_event_id",
    )
    _require_event_id(
        web_buzz_pr.get("checklist_update_event_id"),
        "repository_delivery.dependent_web_parity.buzz_pr.checklist_update_event_id",
    )
    _require_event_id(
        web_buzz_pr.get("tier2_install_update_event_id"),
        "repository_delivery.dependent_web_parity.buzz_pr.tier2_install_update_event_id",
    )
    _require_event_id(
        web_buzz_pr.get("c1_review_update_event_id"),
        "repository_delivery.dependent_web_parity.buzz_pr.c1_review_update_event_id",
    )
    _require_event_id(
        web_buzz_pr.get("ci_auth_c1_closure_update_event_id"),
        "repository_delivery.dependent_web_parity.buzz_pr.ci_auth_c1_closure_update_event_id",
    )
    _require_event_id(
        web_buzz_pr.get("simplelift_remediation_update_event_id"),
        "repository_delivery.dependent_web_parity.buzz_pr.simplelift_remediation_update_event_id",
    )
    _require_url(
        web_buzz_pr.get("url"),
        "repository_delivery.dependent_web_parity.buzz_pr.url",
        ("buzz://pr",),
    )
    if not isinstance(web_buzz_pr.get("external_id"), str) or not web_buzz_pr["external_id"].strip():
        raise LedgerError("dependent web parity Buzz PR external_id must be non-empty")

    web_github_pr = _require_mapping(
        web_delivery.get("github_pr"),
        "repository_delivery.dependent_web_parity.github_pr",
    )
    if web_github_pr.get("status") != "OPEN" or web_github_pr.get("draft") is not True:
        raise LedgerError("dependent web parity GitHub PR must be an open draft")
    if web_github_pr.get("number") != 108:
        raise LedgerError("dependent web parity GitHub PR number must match readback")
    _require_url(
        web_github_pr.get("url"),
        "repository_delivery.dependent_web_parity.github_pr.url",
        ("https://github.com/",),
    )
    if (
        web_github_pr.get("head_ref") != web_branch
        or web_github_pr.get("head_sha") != web_source_sha
        or web_github_pr.get("base_ref") != branch
        or web_github_pr.get("base_sha") != web_base_sha
        or web_github_pr.get("ci_state") != "PR_CHECKS_COMPLETE"
    ):
        raise LedgerError("dependent web parity GitHub PR is not bound to the exact source/base state")
    web_snapshot = _require_mapping(
        web_github_pr.get("check_snapshot"),
        "repository_delivery.dependent_web_parity.github_pr.check_snapshot",
    )
    if not isinstance(web_github_pr.get("ci_observed_at"), str) or not web_github_pr["ci_observed_at"].strip():
        raise LedgerError("dependent web parity GitHub PR ci_observed_at must be non-empty")
    web_counts = [web_snapshot.get(key) for key in ("total", "success", "skipped", "pending", "failed")]
    if not all(isinstance(value, int) and value >= 0 for value in web_counts):
        raise LedgerError("dependent web parity check snapshot counts must be nonnegative integers")
    if web_snapshot["total"] != sum(web_counts[1:]):
        raise LedgerError("dependent web parity check snapshot counts do not sum to total")
    if web_snapshot["pending"] != 0 or web_snapshot["failed"] != 0:
        raise LedgerError("completed web PR checks cannot be pending or failed")

    parent_pr = _require_mapping(
        web_delivery.get("parent_github_pr"),
        "repository_delivery.dependent_web_parity.parent_github_pr",
    )
    if (
        parent_pr.get("status") != "OPEN"
        or parent_pr.get("draft") is not True
        or parent_pr.get("number") != github_pr["number"]
        or parent_pr.get("head_sha") != source_sha
        or parent_pr.get("dependency_checklist_updated") is not True
    ):
        raise LedgerError("dependent web parity parent PR link does not match updated cumulative draft")
    _require_url(
        parent_pr.get("url"),
        "repository_delivery.dependent_web_parity.parent_github_pr.url",
        ("https://github.com/",),
    )
    web_missing_gates = web_delivery.get("missing_gates")
    if not isinstance(web_missing_gates, list) or not web_missing_gates or not all(
        isinstance(gate, str) and gate.strip() for gate in web_missing_gates
    ):
        raise LedgerError("dependent web parity missing_gates must be non-empty strings")

    roster = _require_mapping(data.get("roster_migration_inventory"), "roster_migration_inventory")
    if roster.get("state") != "ACTIVE" or roster.get("live_changes") != "NOT_APPLIED":
        raise LedgerError("roster migration inventory must remain ACTIVE with live changes NOT_APPLIED")
    if roster.get("migrations") != EXPECTED_ROSTER_MIGRATIONS:
        raise LedgerError("roster migration inventory does not match the authorized mappings")
    removal = _require_mapping(roster.get("removal"), "roster_migration_inventory.removal")
    if removal != {
        "identity": "Sat Hermes",
        "method": "tombstone plus service, configuration, and membership cleanup",
        "rollback_receipt_required": True,
    }:
        raise LedgerError("roster migration removal must preserve the authorized Sat Hermes contract")
    tracking = _require_mapping(roster.get("tracking"), "roster_migration_inventory.tracking")
    for field in (
        "primary_issue_event_id",
        "issue_status_event_id",
        "cumulative_buzz_pr_update_event_id",
        "web_buzz_pr_update_event_id",
    ):
        _require_event_id(tracking.get(field), f"roster_migration_inventory.tracking.{field}")
    if (
        tracking["primary_issue_event_id"] != issue["event_id"]
        or tracking["issue_status_event_id"] != issue_link["roster_status_event_id"]
        or tracking["cumulative_buzz_pr_update_event_id"] != buzz_pr["checklist_update_event_id"]
        or tracking["web_buzz_pr_update_event_id"] != web_buzz_pr["checklist_update_event_id"]
        or tracking.get("github_draft_prs_updated") != [107, 108]
    ):
        raise LedgerError("roster migration tracking does not match repository delivery receipts")
    receipts = roster.get("required_receipts")
    if not isinstance(receipts, list) or not receipts or not all(
        isinstance(receipt, str) and receipt.strip() for receipt in receipts
    ):
        raise LedgerError("roster migration required_receipts must be non-empty strings")

    tier2_install = _require_mapping(data.get("tier2_fleet_installation"), "tier2_fleet_installation")
    if tier2_install.get("status") != "COMPLETE" or tier2_install.get("verdict") != "PASS_WITH_RISKS":
        raise LedgerError("Tier 2 fleet installation must be COMPLETE with PASS_WITH_RISKS")
    reviewed_commit = tier2_install.get("reviewed_commit_sha")
    reviewed_tree = tier2_install.get("reviewed_tree_sha")
    _require_full_sha(reviewed_commit, "tier2_fleet_installation.reviewed_commit_sha")
    _require_full_sha(reviewed_tree, "tier2_fleet_installation.reviewed_tree_sha")
    _require_state_id(tier2_install.get("state_id"), "tier2_fleet_installation.state_id")
    _require_state_id(tier2_install.get("lineage_id"), "tier2_fleet_installation.lineage_id")
    commit_check = _require_mapping(tier2_install.get("commit_check"), "tier2_fleet_installation.commit_check")
    if commit_check != {"result": "OK", "source_sha": reviewed_commit}:
        raise LedgerError("Tier 2 fleet installation exact commit check is not bound to reviewed commit")
    if (
        tier2_install.get("installed_paths") != 7
        or tier2_install.get("host_identity_result") != "BYTE_MODE_OWNER_IDENTICAL"
        or tier2_install.get("live_canaries") != {"passed": 5, "total": 5}
        or tier2_install.get("c1_reopen_state") != "COMPLETE"
    ):
        raise LedgerError("Tier 2 fleet installation host, canary, or C1 state is invalid")
    expected_receipts = {
        "framework": "/home/victor/work/tier2-promotion-install-4efbf03-framework-20260827-r2",
        "yoga": "/home/victorv/work/tier2-promotion-install-4efbf03-yoga-20260827-r2",
    }
    for host, receipt_dir in expected_receipts.items():
        record = _require_mapping(tier2_install.get(host), f"tier2_fleet_installation.{host}")
        if record != {"status": "INSTALLED", "receipt_dir": receipt_dir}:
            raise LedgerError(f"Tier 2 fleet installation {host} receipt does not match readback")
    if tier2_install.get("attempts") != [
        {"revision": 1, "result": "ROLLED_BACK", "cause": "mode drift", "rollback": "COMPLETE"},
        {"revision": 2, "result": "PASS"},
    ]:
        raise LedgerError("Tier 2 fleet installation attempt history is invalid")
    tier2_tracking = _require_mapping(tier2_install.get("tracking"), "tier2_fleet_installation.tracking")
    for field in (
        "primary_issue_status_event_id",
        "cumulative_buzz_pr_update_event_id",
        "web_buzz_pr_update_event_id",
    ):
        _require_event_id(tier2_tracking.get(field), f"tier2_fleet_installation.tracking.{field}")
    if (
        tier2_tracking["primary_issue_status_event_id"] != issue_link["tier2_install_status_event_id"]
        or tier2_tracking["cumulative_buzz_pr_update_event_id"] != buzz_pr["tier2_install_update_event_id"]
        or tier2_tracking["web_buzz_pr_update_event_id"] != web_buzz_pr["tier2_install_update_event_id"]
        or tier2_tracking.get("github_draft_prs_updated") != [107, 108]
    ):
        raise LedgerError("Tier 2 fleet installation tracking does not match repository delivery receipts")

    c1_review = _require_mapping(data.get("c1_recovery_review"), "c1_recovery_review")
    if c1_review.get("status") != "COMPLETE":
        raise LedgerError("C1 closure must remain COMPLETE")
    c1_source = c1_review.get("source_candidate_sha")
    c1_correction = c1_review.get("correction_sha")
    _require_full_sha(c1_source, "c1_recovery_review.source_candidate_sha")
    _require_full_sha(c1_correction, "c1_recovery_review.correction_sha")
    _require_full_sha(c1_review.get("correction_tree_sha"), "c1_recovery_review.correction_tree_sha")
    _require_full_sha(c1_review.get("observed_parent_sha"), "c1_recovery_review.observed_parent_sha")
    if (
        c1_source != "c9229b6e7202c22ea5bd4f99161aedef5bc68f1f"
        or c1_correction != "5ac44f9ff2d16d61f562e4de16f012ae0be9fd47"
        or c1_review.get("correction_tree_sha") != "58630357d1fc0040b42d9e849b2f1bd2d43932a6"
        or c1_review.get("observed_parent_sha") != "c7cdd80c0cb410929a5b984d21b36ccde9d1a586"
    ):
        raise LedgerError("C1 corrected source, commit, tree, or sole parent does not match readback")
    if (
        c1_review.get("reviewer") != "claude:6502c19de9be662396c3b1cf46858d6e"
        or c1_review.get("terminal_verdict") != "PASS"
        or c1_review.get("findings") != []
    ):
        raise LedgerError("C1 corrected reviewer, verdict, or findings do not match the terminal record")
    c1_check = _require_mapping(c1_review.get("commit_check"), "c1_recovery_review.commit_check")
    if c1_check != {"result": "OK", "source_sha": c1_correction}:
        raise LedgerError("C1 exact commit check must be OK and source-bound to the corrected commit")
    superseded = _require_mapping(c1_review.get("superseded_attempt"), "c1_recovery_review.superseded_attempt")
    expected_superseded = {
        "correction_sha": "afe030a4b66b21bb8d3458acc32c29228316a733",
        "correction_tree_sha": "7288b7d04c46c40d90c6003d2962bf0426d4be3f",
        "observed_parent_sha": "5f55fe7f068a8fae14cb427a6d08355cac510bbc",
        "reviewer": "claude:da444cc9797c933d99b4c8f31b94f829",
        "terminal_verdict": "PASS_WITH_RISKS",
        "findings": [
            {"severity": "LOW", "finding": "archive and transport body caps do not match"},
            {"severity": "LOW", "finding": "archive-query unreachable path must fail closed"},
        ],
        "commit_check": {
            "result": "FAIL",
            "source_sha": "afe030a4b66b21bb8d3458acc32c29228316a733",
            "reason": "correction does not have reviewed base HEAD as its sole parent",
        },
    }
    if superseded != expected_superseded:
        raise LedgerError("C1 superseded parent-shape failure history does not match the terminal record")
    c1_tracking = _require_mapping(c1_review.get("tracking"), "c1_recovery_review.tracking")
    for field in (
        "primary_issue_status_event_id",
        "cumulative_buzz_pr_update_event_id",
        "web_buzz_pr_update_event_id",
    ):
        _require_event_id(c1_tracking.get(field), f"c1_recovery_review.tracking.{field}")
    if (
        c1_tracking["primary_issue_status_event_id"] != issue_link["ci_auth_c1_closure_status_event_id"]
        or c1_tracking["cumulative_buzz_pr_update_event_id"] != buzz_pr["ci_auth_c1_closure_update_event_id"]
        or c1_tracking["web_buzz_pr_update_event_id"] != web_buzz_pr["ci_auth_c1_closure_update_event_id"]
        or c1_tracking.get("github_draft_prs_updated") != [107, 108]
    ):
        raise LedgerError("C1 review tracking does not match repository delivery receipts")

    ci_authority = _require_mapping(data.get("standing_ci_authorization"), "standing_ci_authorization")
    if (
        ci_authority.get("state") != "ACTIVE"
        or ci_authority.get("applies_to") != ["GitHub Actions CI", "Buzz-native CI"]
        or ci_authority.get("on_failure") != "Diagnose, fix, create a new exact SHA, and rerun until green"
        or ci_authority.get("attempt_limit") != "NONE"
        or ci_authority.get("required_tracking")
        != "Every attempted SHA and result in the primary issue, relevant draft PR, and status ledger"
    ):
        raise LedgerError("standing CI authorization must permit tracked repair and reruns without an attempt limit")
    expected_ci_exclusions = [
        "Tier 2 independent-review transport retry law is unchanged",
        "Tier 2 reviewer identity, lineage, correction, and exact-commit check limits are unchanged",
        "No merge, deployment, activation, credential, signing, service, or destructive authority",
    ]
    if ci_authority.get("exclusions") != expected_ci_exclusions:
        raise LedgerError("standing CI authorization must not alter Tier 2 review law or downstream authority")
    ci_tracking = _require_mapping(ci_authority.get("tracking"), "standing_ci_authorization.tracking")
    for field in (
        "primary_issue_status_event_id",
        "cumulative_buzz_pr_update_event_id",
        "web_buzz_pr_update_event_id",
    ):
        _require_event_id(ci_tracking.get(field), f"standing_ci_authorization.tracking.{field}")
    if (
        ci_tracking["primary_issue_status_event_id"] != issue_link["ci_auth_c1_closure_status_event_id"]
        or ci_tracking["cumulative_buzz_pr_update_event_id"] != buzz_pr["ci_auth_c1_closure_update_event_id"]
        or ci_tracking["web_buzz_pr_update_event_id"] != web_buzz_pr["ci_auth_c1_closure_update_event_id"]
        or ci_tracking.get("github_draft_prs_updated") != [107, 108]
    ):
        raise LedgerError("standing CI authorization tracking does not match repository delivery receipts")

    timing = _require_mapping(data.get("program_timing_authorization"), "program_timing_authorization")
    if (
        timing.get("state") != "ACTIVE"
        or timing.get("plan_level_90_minute_stop") != "REMOVED"
        or timing.get("continue_until") != "DONE"
        or timing.get("applies_to") != ["Work", "CI fixes and reruns", "audits", "authorized delivery"]
    ):
        raise LedgerError("program timing authorization must remove the plan-level 90-minute stop until done")
    if timing.get("tier2_state_law") != {
        "deadline_source": "Installed controller deadline and freshness invariant",
        "expired_state": "Rerun as a fresh exact-candidate state",
        "stale_acceptance": "FORBIDDEN",
    }:
        raise LedgerError("program timing authorization must preserve each Tier 2 state deadline and freshness law")
    if timing.get("non_authorities") != [
        "Merge",
        "deployment",
        "activation",
        "credentials",
        "signing",
        "services",
        "destructive actions",
    ]:
        raise LedgerError("program timing authorization must not expand downstream authority")
    timing_tracking = _require_mapping(timing.get("tracking"), "program_timing_authorization.tracking")
    for field in (
        "primary_issue_status_event_id",
        "cumulative_buzz_pr_update_event_id",
        "web_buzz_pr_update_event_id",
    ):
        _require_event_id(timing_tracking.get(field), f"program_timing_authorization.tracking.{field}")
    if (
        timing_tracking["primary_issue_status_event_id"] != issue_link["simplelift_remediation_status_event_id"]
        or timing_tracking["cumulative_buzz_pr_update_event_id"] != buzz_pr["simplelift_remediation_update_event_id"]
        or timing_tracking["web_buzz_pr_update_event_id"] != web_buzz_pr["simplelift_remediation_update_event_id"]
        or timing_tracking.get("github_draft_prs_updated") != [107, 108]
    ):
        raise LedgerError("program timing authorization tracking does not match repository delivery receipts")

    remediation = _require_mapping(
        data.get("simplelift_overlap_remediation"),
        "simplelift_overlap_remediation",
    )
    if (
        remediation.get("state") != "ACTIVE"
        or remediation.get("scope") != "PLANNING_AND_TRACKING_ONLY"
        or remediation.get("live_mutation_state") != "NOT_APPLIED_BY_THIS_WAVE"
        or remediation.get("identity_direction")
        != {"simplelift": "App and repository", "framework": "Host"}
    ):
        raise LedgerError("Simplelift remediation must preserve app/repository and Framework host identity")
    audit = _require_mapping(remediation.get("audit"), "simplelift_overlap_remediation.audit")
    expected_pr = {
        "repository": "only21mil/simplelift",
        "number": 24,
        "url": "https://github.com/only21mil/simplelift/pull/24",
        "head_sha": "bbae6a383727325e83b7480e7c8cbb323de2be20",
        "state": "CLOSED",
        "merged": False,
        "branch_preserved": True,
    }
    if (
        audit.get("repository_path") != "/home/victor/projects"
        or audit.get("main_state") != "CLEAN"
        or audit.get("dev_sha") != "bbae6a383727325e83b7480e7c8cbb323de2be20"
        or audit.get("pull_request") != expected_pr
        or audit.get("overlap")
        != {"buzz_files": 101, "includes": ["LUKS header", "rescue bundle", "broken budget gitlink"]}
        or audit.get("live_dependencies")
        != {"buzz_seats": 9, "desktop_launcher": True, "source_checkout": "/home/victor/projects"}
        or audit.get("roster_commits")
        != {"repository_state": "WRONG_REPOSITORY", "publish_state": "UNPUBLISHED"}
        or audit.get("buzz_draft_prs")
        != [
            {"number": 107, "state": "CLEAN", "head_sha": "d7677e177b9e3732bf92962e00b5d7ba161ce03c"},
            {"number": 108, "state": "CLEAN", "head_sha": "e627ff05edc57990982687669e3e47326857d1ab"},
        ]
        or audit.get("desktop_pin") != "STALE"
        or audit.get("sweep") != {"state": "FAILED", "binding": "UNBOUND"}
        or audit.get("directory_sync") != {"state": "FAILED", "binding": "UNBOUND"}
        or audit.get("deploy_checkouts")
        != {"state": "DUPLICATE_AND_DIRTY", "canonical_selection": "NOT_STARTED"}
        or audit.get("cross_scope_archimedes_prompts") != "OWNER_LANE_REQUIRED"
    ):
        raise LedgerError("Simplelift remediation audit truth does not match the completed audit")
    expected_actions = [
        (1, "Close Simplelift PR 24 without merge and initially preserve its branch", "COMPLETE"),
        (2, "Finish reviewed Buzz-owned stable install roots and receipt-bound systemd and desktop cutover", "NOT_STARTED"),
        (3, "Complete all active in-scope prompts", "NOT_STARTED"),
        (4, "Execute roster model and Sat Hermes cutover with rollback receipts", "NOT_STARTED"),
        (5, "Correct MGACT policy and helper behavior", "NOT_STARTED"),
        (6, "Fix the sweep and directory sync with exact binding", "NOT_STARTED"),
        (7, "Move desktop to the current reviewed pin", "NOT_STARTED"),
        (8, "Select one canonical deploy checkout", "NOT_STARTED"),
        (9, "Preserve legitimate Simplelift dev history through 40985fbe5adb3a1aad08ca3223c744b47b8f425e", "NOT_STARTED"),
        (10, "Relocate private recovery material and complete history and security handling", "NOT_STARTED"),
        (11, "Remove contaminated refs and local branches only after readback", "NOT_STARTED"),
        (12, "Add a Simplelift repository-root CI guard", "NOT_STARTED"),
    ]
    actions = remediation.get("ordered_actions")
    if (
        not isinstance(actions, list)
        or len(actions) != len(expected_actions)
        or not all(isinstance(action, dict) for action in actions)
        or [
        (action.get("order"), action.get("action"), action.get("state"))
        for action in actions
        ]
        != expected_actions
    ):
        raise LedgerError("Simplelift remediation actions must preserve the audited dependency order")
    if remediation.get("cross_scope_rule") != "Archimedes prompts are handled only by their owner lane":
        raise LedgerError("Simplelift remediation must preserve the Archimedes owner-lane boundary")
    remediation_tracking = _require_mapping(remediation.get("tracking"), "simplelift_overlap_remediation.tracking")
    for field in (
        "primary_issue_status_event_id",
        "cumulative_buzz_pr_update_event_id",
        "web_buzz_pr_update_event_id",
    ):
        _require_event_id(remediation_tracking.get(field), f"simplelift_overlap_remediation.tracking.{field}")
    if (
        remediation_tracking != timing_tracking
        or remediation_tracking["primary_issue_status_event_id"]
        != issue_link["simplelift_remediation_status_event_id"]
        or remediation_tracking["cumulative_buzz_pr_update_event_id"]
        != buzz_pr["simplelift_remediation_update_event_id"]
        or remediation_tracking["web_buzz_pr_update_event_id"]
        != web_buzz_pr["simplelift_remediation_update_event_id"]
    ):
        raise LedgerError("Simplelift remediation tracking does not match repository delivery receipts")

    for path, value in _walk_sha_fields(data):
        _require_full_sha(value, path, nullable=True)

    for path, value in _walk_strings({key: value for key, value in data.items() if key != "aliases"}):
        if UNQUALIFIED_B1_RE.search(value):
            raise LedgerError(f"unqualified B1 is forbidden at {path}")

    items = data.get("work_items")
    if not isinstance(items, list) or not items:
        raise LedgerError("work_items must be a non-empty list")
    ids: set[str] = set()
    for index, raw_item in enumerate(items):
        where = f"work_items[{index}]"
        item = _require_mapping(raw_item, where)
        missing = REQUIRED_ITEM_FIELDS - item.keys()
        if missing:
            raise LedgerError(f"{where} missing required fields: {', '.join(sorted(missing))}")
        work_id = item["id"]
        if not isinstance(work_id, str) or WORK_ID_RE.fullmatch(work_id) is None or work_id in ids:
            raise LedgerError(f"{where}.id must be a unique stable work ID")
        ids.add(work_id)
        if item["program_state"] not in ALLOWED_STATES:
            raise LedgerError(f"{where}.program_state is invalid")
        if global_state == "FROZEN_OWNER_STOP" and item["program_state"] in ACTIVE_STATES:
            scoped = item.get("scoped_active")
            if scoped != {
                "authority": "controller assignment under standing full authorization",
                "owner_agent": "/root/web_app_parity",
                "model": "gpt-5.6-sol",
                "effort": "high",
            }:
                raise LedgerError(f"{where} cannot be active under FROZEN_OWNER_STOP without exact scoped authority")
            candidate_sha = item.get("candidate_sha")
            if candidate_sha is None:
                if item.get("verification_state") != "UNKNOWN":
                    raise LedgerError(f"{where} scoped active work must remain UNKNOWN until exact candidate evidence")
            elif (
                item.get("id") != "BCI-WEB-PARITY-01"
                or item.get("program_state") != "READY_FOR_CI"
                or candidate_sha != web_source_sha
                or item.get("branch") != web_branch
            ):
                raise LedgerError(f"{where} scoped active candidate is not bound to dependent web delivery")
            requirements = item.get("requirements")
            if not isinstance(requirements, list) or not requirements or not all(
                isinstance(requirement, str) and requirement.strip() for requirement in requirements
            ):
                raise LedgerError(f"{where}.requirements must be non-empty strings")
        if item["review_state"] not in {"NOT_STARTED", "UNKNOWN", "REVIEWING", "VERDICT_RECORDED", "REVIEW_CLOSED"}:
            raise LedgerError(f"{where}.review_state is invalid")
        if global_state == "FROZEN_OWNER_STOP" and item["review_state"] == "REVIEWING":
            raise LedgerError(f"{where} cannot have an active review under FROZEN_OWNER_STOP")
        _require_event_id(item["owner_event"], f"{where}.owner_event")
        for field in ("title", "lane", "observed_at", "evidence_ref"):
            if not isinstance(item[field], str) or not item[field].strip():
                raise LedgerError(f"{where}.{field} must be non-empty")
        for field in ("blockers", "dependencies"):
            if not isinstance(item[field], list) or not all(
                isinstance(entry, str) and entry.strip() for entry in item[field]
            ):
                raise LedgerError(f"{where}.{field} must be a list of non-empty strings")
        if any(item[field] is None for field in ("candidate_sha", "promotion_sha", "landing_sha", "deployed_sha")):
            if item["verification_state"] != "UNKNOWN":
                raise LedgerError(f"{where} has null SHA fields and must be UNKNOWN")
        contradictions = item["contradictions"]
        if not isinstance(contradictions, list):
            raise LedgerError(f"{where}.contradictions must be a list")
        if contradictions and (item["program_state"] != "UNKNOWN" or item["verification_state"] != "UNKNOWN"):
            raise LedgerError(f"{where} contradictions must resolve to UNKNOWN")
        for contradiction_index, contradiction in enumerate(contradictions):
            contradiction = _require_mapping(
                contradiction,
                f"{where}.contradictions[{contradiction_index}]",
            )
            if contradiction.get("field", "").endswith("_sha"):
                claims = contradiction.get("claims")
                if not isinstance(claims, list) or len(claims) < 2:
                    raise LedgerError(f"{where} SHA contradiction requires at least two claims")
                for claim_index, claim in enumerate(claims):
                    _require_full_sha(
                        claim,
                        f"{where}.contradictions[{contradiction_index}].claims[{claim_index}]",
                    )
        _validate_evidence(item, where)
        _validate_review(item, where)
        _validate_landing(item, where)
        _validate_item_deploy(item, where)

    for index, item in enumerate(items):
        unknown = sorted(set(item["dependencies"]) - ids)
        if unknown:
            raise LedgerError(f"work_items[{index}] has unknown dependencies: {', '.join(unknown)}")
    item_by_id = {item["id"]: item for item in items}
    for index, candidate in enumerate(checkpoint_candidates):
        item = item_by_id.get(candidate["id"])
        if item is None or item.get("candidate_sha") != candidate["candidate_sha"]:
            raise LedgerError(f"execution checkpoint candidate {index} does not match its work item")
    cumulative = item_by_id.get("BCI-BUZZ-CUMULATIVE-01")
    if cumulative is None or cumulative.get("candidate_sha") != source_sha:
        raise LedgerError("repository delivery source does not match the cumulative work item")
    web_item = item_by_id.get("BCI-WEB-PARITY-01")
    if web_item is None or web_item.get("candidate_sha") != web_source_sha:
        raise LedgerError("dependent web delivery source does not match the web parity work item")
    roster_item = item_by_id.get("BCI-ROSTER-MIGRATION-01")
    if roster_item is None or roster_item.get("inventory") != {
        "state": "ACTIVE",
        "live_changes": "NOT_APPLIED",
        "record_ref": "roster_migration_inventory",
    }:
        raise LedgerError("roster migration work item must remain active inventory with no live changes")
    engine_item = item_by_id.get("BCI-REVIEW-ENGINE-01")
    if (
        engine_item is None
        or engine_item.get("promotion_sha") != reviewed_commit
        or engine_item.get("review_state") != "REVIEW_CLOSED"
        or engine_item.get("review_receipt", {}).get("state_id") != tier2_install["state_id"]
        or engine_item.get("review_receipt", {}).get("lineage_id") != tier2_install["lineage_id"]
    ):
        raise LedgerError("Tier 2 engine work item does not match the fleet installation receipt")
    c1_item = item_by_id.get("BCI-REVIEW-C1-RECOVERY-01")
    if (
        c1_item is None
        or c1_item.get("candidate_sha") != c1_source
        or c1_item.get("correction_sha") != c1_correction
        or c1_item.get("correction_tree_sha") != c1_review["correction_tree_sha"]
        or c1_item.get("observed_parent_sha") != c1_review["observed_parent_sha"]
        or c1_item.get("reopen_state") != "COMPLETE"
        or c1_item.get("review_state") != "REVIEW_CLOSED"
        or c1_item.get("program_state") != "REVIEW_CLOSED"
        or c1_item.get("promotion_sha") != c1_correction
    ):
        raise LedgerError("C1 work item must remain complete with the corrected terminal review receipt")


def _sha_display(value: Any) -> str:
    if value is None:
        return "UNKNOWN"
    return str(value)


def _cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_taskboard(data: dict[str, Any]) -> str:
    validate_ledger(data)
    metadata = data["metadata"]
    truth = data["authoritative_truth"]
    lines = [
        "# Buzz CI migration task board",
        "",
        f"Generated from `BUZZ_CI_FULL_MIGRATION_STATUS.yaml` at `{metadata['observed_at']}`.",
        "",
        "## Routing state",
        "",
        f"`{metadata['global_state']}`. {metadata['stop']['effect']}",
        "",
        "| Truth | Value | Evidence |",
        "|---|---|---|",
        f"| Authoritative main | `{truth['main']['authoritative_sha']}` | {_cell(truth['main']['evidence_ref'])} |",
        f"| Last proven deployed source | `{truth['deployment']['deployed_sha']}` | {_cell(truth['deployment']['evidence_ref'])} |",
        f"| Production migration | `{truth['deployment']['migration']}` | source-bound deployment receipt |",
        f"| Mempool and Genesis | `{truth['mgact']['activation_state']}` | {_cell(truth['mgact']['note'])} |",
        "",
        "## Qualified legacy aliases",
        "",
        "| Alias | Stable work ID |",
        "|---|---|",
    ]
    for alias, work_id in sorted(data["aliases"]["legacy_b1"].items()):
        lines.append(f"| `{alias}` | `{work_id}` |")
    lines.extend(
        [
            "",
            "## Source-only execution checkpoint",
            "",
            "These candidates are frozen and locally checked. No downstream authority is implied.",
            "",
            "| Stable work ID | Source candidate | Verified scope | Includes |",
            "|---|---|---|---|",
        ]
    )
    for candidate in data["execution_checkpoint"]["source_candidates"]:
        lines.append(
            f"| `{candidate['id']}` | `{candidate['candidate_sha']}` | `{candidate['verification']}` | {_cell(candidate['includes'])} |"
        )
    lines.extend(
        [
            "",
            "## Downstream delivery states",
            "",
            "| Gate | State | Approval required |",
            "|---|---|---|",
        ]
    )
    for gate, state in data["execution_checkpoint"]["downstream_states"].items():
        lines.append(f"| `{gate}` | `{state['state']}` | `yes` |")
    delivery = data["repository_delivery"]
    web_delivery = delivery["dependent_web_parity"]
    roster = data["roster_migration_inventory"]
    tier2_install = data["tier2_fleet_installation"]
    c1_review = data["c1_recovery_review"]
    ci_authority = data["standing_ci_authorization"]
    timing = data["program_timing_authorization"]
    remediation = data["simplelift_overlap_remediation"]
    lines.extend(
        [
            "",
            "## Repository delivery tracking",
            "",
            "| Record | Status | Exact target |",
            "|---|---|---|",
            f"| Relay feature ref | `{delivery['relay']['status']}` | `{delivery['relay']['ref_url']}` at `{delivery['relay']['ref_sha']}` |",
            f"| GitHub mirror ref | `{delivery['github_mirror']['status']}` | [{delivery['branch']}]({delivery['github_mirror']['ref_url']}) at `{delivery['github_mirror']['ref_sha']}` |",
            f"| Buzz issue | `{delivery['buzz_issue']['status']}` | `{delivery['buzz_issue']['url']}` |",
            f"| Buzz PR | `{delivery['buzz_pr']['status']}` | `{delivery['buzz_pr']['url']}` |",
            f"| GitHub PR #{delivery['github_pr']['number']} | `DRAFT / {delivery['github_pr']['ci_state']}` | [PR #{delivery['github_pr']['number']}]({delivery['github_pr']['url']}) at `{delivery['github_pr']['head_sha']}` |",
            f"| Web relay feature ref | `{web_delivery['relay']['status']}` | `{web_delivery['relay']['ref_url']}` at `{web_delivery['relay']['ref_sha']}` |",
            f"| Web GitHub mirror ref | `{web_delivery['github_mirror']['status']}` | [{web_delivery['branch']}]({web_delivery['github_mirror']['ref_url']}) at `{web_delivery['github_mirror']['ref_sha']}` |",
            f"| Web Buzz PR | `{web_delivery['buzz_pr']['status']}` | `{web_delivery['buzz_pr']['url']}` |",
            f"| GitHub PR #{web_delivery['github_pr']['number']} | `DRAFT / {web_delivery['github_pr']['ci_state']}` | [PR #{web_delivery['github_pr']['number']}]({web_delivery['github_pr']['url']}) at `{web_delivery['github_pr']['head_sha']}` on base `{web_delivery['github_pr']['base_sha']}` |",
            "",
            "## Active roster migration inventory",
            "",
            f"`{roster['state']}` inventory. Live changes are `{roster['live_changes']}`.",
            "",
            "| Current label | Planned label | Planned model/profile |",
            "|---|---|---|",
        ]
    )
    for migration in roster["migrations"]:
        profile = migration["model"]
        if migration["reasoning"] == "preserve-current":
            profile = "preserve current model and reasoning"
        lines.append(f"| `{migration['from']}` | `{migration['to']}` | `{profile}` |")
    lines.extend(
        [
            f"| `{roster['removal']['identity']}` | `REMOVE` | {_cell(roster['removal']['method'])}; rollback receipt required |",
            "",
            "## Tier 2 fleet installation",
            "",
            "| Receipt | Value |",
            "|---|---|",
            f"| Reviewed commit | `{tier2_install['reviewed_commit_sha']}` |",
            f"| Reviewed tree | `{tier2_install['reviewed_tree_sha']}` |",
            f"| State / lineage | `{tier2_install['state_id']}` / `{tier2_install['lineage_id']}` |",
            f"| Verdict / commit check | `{tier2_install['verdict']}` / `{tier2_install['commit_check']['result']}` |",
            f"| Fleet install | `{tier2_install['installed_paths']}` byte/mode/owner-identical paths on Framework and Yoga |",
            f"| Live canaries | `{tier2_install['live_canaries']['passed']}/{tier2_install['live_canaries']['total']} PASS` |",
            f"| C1 reopen | `{tier2_install['c1_reopen_state']}` |",
            "",
            "## C1 recovery review",
            "",
            "| Receipt | Value |",
            "|---|---|",
            f"| Source candidate | `{c1_review['source_candidate_sha']}` |",
            f"| Reviewed correction | `{c1_review['correction_sha']}` / tree `{c1_review['correction_tree_sha']}` |",
            f"| Reviewer / verdict | `{c1_review['reviewer']}` / `{c1_review['terminal_verdict']}` |",
            f"| Findings | `{len(c1_review['findings'])}` |",
            f"| Exact commit check | `{c1_review['commit_check']['result']}` at `{c1_review['commit_check']['source_sha']}` |",
            f"| Closure state | `{c1_review['status']}` |",
            "",
            "The earlier correction "
            f"`{c1_review['superseded_attempt']['correction_sha']}` remains recorded as a superseded "
            "`PASS_WITH_RISKS` attempt whose exact commit check failed the sole-parent requirement.",
            "",
            "## Standing CI authorization",
            "",
            f"`{ci_authority['state']}` for GitHub Actions CI and Buzz-native CI across the current Buzz plan. "
            "On failure, agents may diagnose, fix, record each new exact SHA and result, and rerun until green; "
            "there is no CI attempt limit.",
            "",
            "This authority does not change Tier 2 independent-review transport retry law or grant merge, "
            "deployment, activation, credential, signing, service, or destructive authority.",
            "",
            "## Program timing authorization",
            "",
            f"`{timing['state']}`. The plan-level 90-minute stop is `{timing['plan_level_90_minute_stop']}`; "
            "authorized work, CI fixes and reruns, audits, and delivery continue until `DONE`.",
            "",
            "Each individual Tier 2 state still obeys the installed controller deadline and freshness invariant. "
            "An expired state is rerun as a fresh exact-candidate state and stale acceptance is forbidden.",
            "",
            "## Simplelift overlap remediation",
            "",
            "`ACTIVE / PLANNING_AND_TRACKING_ONLY`. Simplelift is the app and repository; Framework is the host. "
            "This wave made no source or live mutation.",
            "",
            "| Audit fact | Current truth |",
            "|---|---|",
            f"| Simplelift checkout | `{remediation['audit']['repository_path']}`; main `{remediation['audit']['main_state']}` |",
            f"| Simplelift dev / PR #24 | `{remediation['audit']['dev_sha']}`; `CLOSED / NOT_MERGED / BRANCH_PRESERVED` |",
            f"| Overlap | `{remediation['audit']['overlap']['buzz_files']}` Buzz files plus LUKS header, rescue bundle, and broken budget gitlink |",
            f"| Live dependency | `{remediation['audit']['live_dependencies']['buzz_seats']}` Buzz seats and desktop launcher depend on the checkout |",
            "| Roster commits | `WRONG_REPOSITORY / UNPUBLISHED` |",
            "| Buzz draft PRs | `#107 CLEAN / #108 CLEAN` |",
            "| Desktop / sweep / directory | `STALE_PIN / FAILED_UNBOUND / FAILED_UNBOUND` |",
            "| Deploy checkouts | `DUPLICATE_AND_DIRTY`; canonical selection not started |",
            "| Cross-scope prompts | Archimedes owner lane required |",
            "",
            "### Ordered remediation actions",
            "",
            "| Order | State | Action |",
            "|---|---|---|",
        ]
    )
    for action in remediation["ordered_actions"]:
        lines.append(f"| `{action['order']}` | `{action['state']}` | {_cell(action['action'])} |")
    lines.extend(
        [
            "",
            "## Active workstreams",
            "",
            "| Stable work ID | Owner | Profile | State | Candidate |",
            "|---|---|---|---|---|",
        ]
    )
    for item in data["work_items"]:
        scoped = item.get("scoped_active")
        if scoped:
            lines.append(
                f"| `{item['id']}` | `{scoped['owner_agent']}` | `{scoped['model']} · {scoped['effort']}` | `{item['program_state']}` | `{_sha_display(item['candidate_sha'])}` |"
            )
    lines.extend(
        [
            "",
            "## Current candidates",
            "",
            "Every row is non-routable while the owner stop remains in force.",
            "",
            "| Stable work ID | Item | State | Candidate | Promotion | Review | Blockers |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    for item in data["work_items"]:
        blockers = "; ".join(item["blockers"]) or "None recorded"
        if item["contradictions"]:
            claims = ", ".join(item["contradictions"][0]["claims"])
            blockers = f"CONTRADICTED candidate evidence: {claims}; {blockers}"
        lines.append(
            "| `{id}` | {title} | `{state}` | `{candidate}` | `{promotion}` | `{review}` | {blockers} |".format(
                id=item["id"],
                title=_cell(item["title"]),
                state=item["program_state"],
                candidate=_sha_display(item["candidate_sha"]),
                promotion=_sha_display(item["promotion_sha"]),
                review=item["review_state"],
                blockers=_cell(blockers),
            )
        )
    lines.extend(["", "## Evidence precedence", ""])
    for entry in data["evidence_precedence"]:
        lines.append(f"{entry['tier']}. {entry['source']}.")
    lines.extend(
        [
            "",
            "A lower-precedence source cannot override a higher one. Unresolved contradictions remain `UNKNOWN`.",
            "",
            "Regenerate and check with `python3 tools/status_ledger.py check`.",
            "",
        ]
    )
    return "\n".join(lines)


def _default_paths() -> tuple[Path, Path]:
    root = Path(__file__).resolve().parents[1]
    return root / "BUZZ_CI_FULL_MIGRATION_STATUS.yaml", root / "TASKBOARD.md"


def main(argv: list[str] | None = None) -> int:
    default_ledger, default_board = _default_paths()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate", "render", "check"))
    parser.add_argument("--ledger", type=Path, default=default_ledger)
    parser.add_argument("--taskboard", type=Path, default=default_board)
    args = parser.parse_args(argv)
    try:
        data = load_ledger(args.ledger)
        rendered = render_taskboard(data)
        if args.command == "render":
            args.taskboard.write_text(rendered, encoding="utf-8")
        elif args.command == "check":
            try:
                current = args.taskboard.read_text(encoding="utf-8")
            except OSError as exc:
                raise LedgerError(f"cannot read generated task board: {exc}") from exc
            if current != rendered:
                raise LedgerError("TASKBOARD.md is stale; run the render command")
    except LedgerError as exc:
        print(f"status-ledger: ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"status-ledger: {args.command} OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

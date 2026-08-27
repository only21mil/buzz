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
        or github_pr.get("ci_state") != "RUNNING"
    ):
        raise LedgerError("repository_delivery.github_pr is not bound to the exact source/base state")
    snapshot = _require_mapping(github_pr.get("check_snapshot"), "repository_delivery.github_pr.check_snapshot")
    counts = [snapshot.get(key) for key in ("total", "success", "skipped", "pending", "failed")]
    if not all(isinstance(value, int) and value >= 0 for value in counts):
        raise LedgerError("repository_delivery.github_pr.check_snapshot counts must be nonnegative integers")
    if snapshot["total"] != snapshot["success"] + snapshot["skipped"] + snapshot["pending"] + snapshot["failed"]:
        raise LedgerError("repository_delivery.github_pr.check_snapshot counts do not sum to total")

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
            if item.get("candidate_sha") is not None or item.get("verification_state") != "UNKNOWN":
                raise LedgerError(f"{where} scoped active work must remain UNKNOWN until exact candidate evidence")
            requirements = item.get("requirements")
            if not isinstance(requirements, list) or not requirements or not all(
                isinstance(requirement, str) and requirement.strip() for requirement in requirements
            ):
                raise LedgerError(f"{where}.requirements must be non-empty strings")
        if item["review_state"] not in {"NOT_STARTED", "UNKNOWN", "REVIEWING", "REVIEW_CLOSED"}:
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

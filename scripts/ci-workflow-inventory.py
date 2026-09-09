#!/usr/bin/env python3
"""Generate or verify docs/ci/workflow-inventory.md from .github/workflows/*.yml.

One row per job: triggers, runner labels, gate, permissions, secrets, cost
class, required-check status on protected main, and the recorded cutover
disposition. The main ruleset is read through gh (read only) and cached in a
committed snapshot so --offline runs and --check stay deterministic.

This inventory records facts. It grants no authority to change a workflow,
a ruleset, or a required check.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import itertools
import json
import math
import os
from pathlib import Path
import re
import subprocess
import tempfile

REPO = "only21mil/buzz"
RULES_ENDPOINT = f"/repos/{REPO}/rules/branches/main"
ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
DOC = ROOT / "docs" / "ci" / "workflow-inventory.md"
DISPOSITIONS = ROOT / "docs" / "ci" / "workflow-inventory.dispositions.json"
SNAPSHOT = ROOT / "docs" / "ci" / "workflow-inventory.required-checks.json"
NATIVE_WORKFLOW = "ci.yml"
DEFAULT_TIMEOUT = 360
ALLOWED_DISPOSITIONS = ("native", "retained-github", "disabled-for-fork")
MULTIPLIERS = (("macos", 10), ("windows", 2), ("ubuntu", 1), ("linux", 1))
COST_BUCKETS = ((15, "S"), (60, "M"), (300, "L"))
MATRIX_REF = re.compile(r"\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}")
SECRET_REF = re.compile(r"secrets\.([A-Za-z0-9_]+)")
VARS_REF = re.compile(r"vars\.([A-Za-z0-9_]+)")
REPO_GATE = re.compile(r"github\.repository\s*==\s*'([^']+)'")


class InventoryError(Exception):
    pass


def load_yaml(text):
    try:
        import yaml
        return yaml.safe_load(text)
    except ImportError:
        pass
    try:
        from ruamel.yaml import YAML
    except ImportError as error:
        raise InventoryError("PyYAML or ruamel.yaml is required") from error
    return YAML(typ="safe", pure=True).load(text)


def rel(path):
    return str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path)


def dump(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def sha256(value):
    return hashlib.sha256(dump(value).encode()).hexdigest()


def triggers(document):
    on = document.get("on", document.get(True))
    if isinstance(on, str):
        on = {on: None}
    if isinstance(on, list):
        on = {event: None for event in on}
    if not isinstance(on, dict):
        raise InventoryError("workflow without an on: block")
    rows = []
    for event in sorted(on):
        detail = on[event] or {}
        qualifiers = []
        for key in ("branches", "tags", "types"):
            if key in detail:
                qualifiers.append(f"{key}={','.join(map(str, detail[key]))}")
        if "paths" in detail:
            qualifiers.append(f"paths={len(detail['paths'])}")
        rows.append(event + (f"[{'; '.join(qualifiers)}]" if qualifiers else ""))
    return rows


def matrix_combos(strategy):
    matrix = (strategy or {}).get("matrix")
    if not isinstance(matrix, dict):
        return [{}]
    lists = {key: value for key, value in matrix.items()
             if key not in ("include", "exclude") and isinstance(value, list)}
    combos = [dict(zip(lists, values)) for values in itertools.product(*lists.values())] if lists else []
    for extra in matrix.get("include") or []:
        matched = [combo for combo in combos if all(combo.get(k) == v for k, v in extra.items() if k in combo)]
        if matched and lists:
            for combo in matched:
                combo.update(extra)
        else:
            combos.append(dict(extra))
    excluded = matrix.get("exclude") or []
    combos = [combo for combo in combos
              if not any(all(combo.get(k) == v for k, v in rule.items()) for rule in excluded)]
    return combos or [{}]


def expand(template, combo):
    def replace(match):
        key = match.group(1)
        if key not in combo:
            raise InventoryError(f"matrix.{key} is not defined by the job matrix")
        return str(combo[key])
    return MATRIX_REF.sub(replace, str(template))


def runner_labels(runs_on, combo):
    if isinstance(runs_on, dict):
        runs_on = runs_on.get("labels", runs_on.get("group", ""))
    labels = runs_on if isinstance(runs_on, list) else [runs_on]
    out = []
    for label in labels:
        label = str(label)
        if MATRIX_REF.search(label):
            label = expand(label, combo)
        if "${{" in label:
            names = VARS_REF.findall(label)
            label = "vars:" + ",".join(names) if names else "expr:" + label
        out.append(label)
    return out


def multiplier(labels):
    for label in labels:
        for prefix, factor in MULTIPLIERS:
            if label.lower().startswith(prefix):
                return factor
    return None


def cost_class(rows_minutes):
    if rows_minutes is None:
        return "self-hosted"
    for limit, letter in COST_BUCKETS:
        if rows_minutes <= limit:
            return f"{letter}/{rows_minutes}"
    return f"XL/{rows_minutes}"


def gate(condition):
    if not condition:
        return "-"
    text = " ".join(str(condition).split())
    repos = REPO_GATE.findall(text)
    parts = []
    if repos and REPO not in repos:
        parts.append("disabled-for-fork")
    elif repos:
        parts.append("fork-only" if len(repos) == 1 else "block-or-fork")
    if VARS_REF.search(text):
        parts.append("vars:" + ",".join(sorted(set(VARS_REF.findall(text)))))
    if "github.base_ref == 'main'" in text:
        parts.append("main-pr")
    if "needs.changes.outputs" in text:
        parts.append("path-filtered")
    if text in ("false", "${{ false }}"):
        parts.append("always-false")
    return ", ".join(parts) if parts else "conditional"


def permissions(document, job):
    merged = {}
    for scope in (document.get("permissions"), job.get("permissions")):
        if isinstance(scope, dict):
            merged = dict(scope)
        elif isinstance(scope, str):
            merged = {"*": scope}
    writes = sorted(f"{key}:{value}" for key, value in merged.items() if value == "write")
    return writes or ["read-only"]


def effects(perms, secrets, environment):
    out = []
    if any(perm.startswith(("packages:", "contents:")) for perm in perms):
        out.append("publish")
    if any(perm.startswith(("id-token:", "attestations:")) for perm in perms) or any(
            token in name for name in secrets for token in ("SIGN", "CODESIGN", "KEYSTORE")):
        out.append("sign")
    if environment:
        out.append(f"environment:{environment}")
    return out or ["none"]


def parse_workflow(path):
    document = load_yaml(path.read_text())
    if not isinstance(document, dict) or not isinstance(document.get("jobs"), dict):
        raise InventoryError(f"{path.name}: no jobs block")
    workflow_triggers = triggers(document)
    concurrency = document.get("concurrency")
    concurrency = concurrency.get("group") if isinstance(concurrency, dict) else concurrency
    rows = []
    for job_id, job in document["jobs"].items():
        if "uses" in job:
            raise InventoryError(f"{path.name}:{job_id}: reusable workflow calls are not inventoried")
        combos = matrix_combos(job.get("strategy"))
        names, labels = [], []
        for combo in combos:
            names.append(expand(job.get("name") or job_id, combo))
            labels.append(runner_labels(job.get("runs-on", ""), combo))
        flat_labels = sorted({label for group in labels for label in group})
        factor = multiplier(flat_labels)
        timeout = job.get("timeout-minutes")
        minutes = None if factor is None else math.ceil(
            (timeout if isinstance(timeout, (int, float)) else DEFAULT_TIMEOUT) * factor * len(combos))
        secrets = sorted(set(SECRET_REF.findall(dump(job))))
        environment = job.get("environment")
        environment = environment.get("name") if isinstance(environment, dict) else environment
        needs = job.get("needs") or []
        perms = permissions(document, job)
        rows.append({
            "workflow": path.name,
            "workflow_name": document.get("name") or path.stem,
            "job_id": job_id,
            "names": names,
            "triggers": workflow_triggers,
            "runners": flat_labels,
            "gate": gate(job.get("if")),
            "needs": needs if isinstance(needs, list) else [needs],
            "timeout": timeout if isinstance(timeout, (int, float)) else f"default {DEFAULT_TIMEOUT}",
            "permissions": perms,
            "secrets": secrets,
            "effects": effects(perms, secrets, environment),
            "concurrency": concurrency or "-",
            "cost": cost_class(minutes),
        })
    return rows


def parse_all(directory):
    files = sorted(p for p in directory.iterdir() if p.suffix in (".yml", ".yaml"))
    if not files:
        raise InventoryError(f"no workflows under {directory}")
    return [row for path in files for row in parse_workflow(path)]


def fetch_required_checks():
    """Read the main ruleset through gh. Same source as desktop-release-required-checks.jq."""
    env = {key: value for key, value in os.environ.items()
           if key in ("PATH", "HOME", "GH_TOKEN", "SSL_CERT_FILE", "SSL_CERT_DIR")}
    with tempfile.TemporaryDirectory(prefix="buzz-ci-inventory-gh-") as config:
        env.update(GH_HOST="github.com", GH_PROMPT_DISABLED="1", GH_CONFIG_DIR=config)
        result = subprocess.run(["gh", "api", "--hostname", "github.com", "--method", "GET",
                                 "-H", "X-GitHub-Api-Version: 2022-11-28", "--paginate", "--slurp",
                                 RULES_ENDPOINT], env=env, capture_output=True, text=True, timeout=60,
                                check=False)
    if result.returncode != 0:
        raise InventoryError("GitHub ruleset unavailable; use --offline with the committed snapshot")
    pages = json.loads(result.stdout)
    checks = []
    for page in pages:
        for rule in page:
            if rule.get("type") != "required_status_checks":
                continue
            params = rule.get("parameters") or {}
            if params.get("strict_required_status_checks_policy") is not True:
                raise InventoryError("main ruleset is not strict; refusing to snapshot")
            checks.extend({"context": c["context"], "integration_id": c["integration_id"]}
                          for c in params.get("required_status_checks", []))
    if not checks:
        raise InventoryError("main ruleset names no required status checks")
    unique = {(c["context"], c["integration_id"]): c for c in checks}
    return sorted(unique.values(), key=lambda c: c["context"])


def load_snapshot():
    if not SNAPSHOT.exists():
        raise InventoryError(f"missing snapshot {rel(SNAPSHOT)}; run without --offline --check first")
    body = json.loads(SNAPSHOT.read_text())
    if body.get("source") != RULES_ENDPOINT or not isinstance(body.get("checks"), list):
        raise InventoryError("snapshot does not describe the main ruleset")
    return body["checks"]


def load_dispositions(path):
    body = json.loads(path.read_text())
    if not isinstance(body, dict):
        raise InventoryError("dispositions must be an object keyed by workflow:job")
    for key, entry in body.items():
        if entry.get("disposition") not in ALLOWED_DISPOSITIONS:
            raise InventoryError(f"{key}: disposition must be one of {', '.join(ALLOWED_DISPOSITIONS)}")
        if entry["disposition"] == "retained-github" and not (entry.get("owner") and entry.get("exit")):
            raise InventoryError(f"{key}: retained-github needs owner and exit")
        if entry["disposition"] == "native" and not entry.get("native"):
            raise InventoryError(f"{key}: native disposition needs a native job id")
    return body


def annotate(rows, checks, dispositions):
    contexts = {c["context"]: c["integration_id"] for c in checks}
    produced = {}
    for row in rows:
        key = f"{row['workflow']}:{row['job_id']}"
        row["required"] = sorted(name for name in row["names"] if name in contexts)
        for name in row["required"]:
            produced.setdefault(name, []).append(key)
        if key not in dispositions:
            raise InventoryError(f"{key}: no disposition recorded in {rel(DISPOSITIONS)}")
        entry = dispositions[key]
        if entry["disposition"] == "native" and row["workflow"] != NATIVE_WORKFLOW:
            raise InventoryError(f"{key}: native execution covers only {NATIVE_WORKFLOW}")
        row["disposition"] = entry["disposition"]
        row["native"] = entry.get("native") or "-"
        row["owner"] = entry.get("owner") or "-"
        row["exit"] = entry.get("exit") or "-"
        row["note"] = entry.get("note") or ""
    stale = sorted(set(dispositions) - {f"{r['workflow']}:{r['job_id']}" for r in rows})
    if stale:
        raise InventoryError("dispositions for removed jobs: " + ", ".join(stale))
    orphaned = sorted(set(contexts) - set(produced))
    if orphaned:
        raise InventoryError("required checks no workflow produces: " + ", ".join(orphaned))
    ambiguous = sorted(name for name, keys in produced.items() if len(keys) > 1)
    if ambiguous:
        raise InventoryError("required checks produced by more than one job: " + ", ".join(ambiguous))
    return produced


def cell(value):
    if isinstance(value, list):
        value = ", ".join(map(str, value)) if value else "-"
    return str(value).replace("|", "\\|").replace("\n", " ")


def render(rows, checks, produced):
    counts = {name: sum(r["disposition"] == name for r in rows) for name in ALLOWED_DISPOSITIONS}
    required_rows = [r for r in rows if r["required"]]
    workflows = sorted({r["workflow"] for r in rows})
    out = [
        "# GitHub workflow inventory",
        "",
        "Generated by `scripts/ci-workflow-inventory.py`. Do not edit by hand; run",
        "`python3 scripts/ci-workflow-inventory.py --write` (or `--offline --write`)",
        "and commit the result. `--check` fails when this file, the dispositions, or",
        "the required-check snapshot drift from `.github/workflows/`.",
        "",
        "Part of the native CI cutover, GitHub issue #184 (Buzz root",
        "`4e64ca92a4abaaba45e414420cc91835ddf23fea6254711cbf5de9fc93f3fc35`).",
        "",
        "## Summary",
        "",
        f"- Workflows: {len(workflows)}; jobs: {len(rows)}; job executions after matrix expansion: "
        f"{sum(len(r['names']) for r in rows)}.",
        f"- Required checks on protected `main`: {len(checks)}, produced by {len(required_rows)} jobs, "
        f"{len({r['workflow'] for r in required_rows})} workflows.",
        f"- Dispositions: native {counts['native']}, retained-github {counts['retained-github']}, "
        f"disabled-for-fork {counts['disabled-for-fork']}.",
        f"- Required-check snapshot: `docs/ci/{SNAPSHOT.name}`, sha256 `{sha256(checks)}`.",
        "",
        "## Required checks on main",
        "",
        "Source: `gh api " + RULES_ENDPOINT + "` (strict policy), the same rule",
        "`scripts/desktop-release-required-checks.jq` reads. Integration id 15368 is GitHub Actions.",
        "",
        "| Check context | App | Producing job | Disposition | Native job |",
        "|---|---|---|---|---|",
    ]
    by_key = {f"{r['workflow']}:{r['job_id']}": r for r in rows}
    for check in checks:
        key = produced[check["context"]][0]
        row = by_key[key]
        out.append(f"| {cell(check['context'])} | {check['integration_id']} | `{key}` | "
                   f"{row['disposition']} | {cell(row['native'])} |")
    out += [
        "",
        "## Jobs",
        "",
        "Columns: `names` are check-run names after matrix expansion. `gate` condenses the job",
        "`if`: `disabled-for-fork` means the job requires `github.repository == 'block/buzz'`,",
        "`fork-only` requires `only21mil/buzz`, `main-pr` runs on every PR to main, `path-filtered`",
        "consults `Detect Changed Paths`. `cost` is bucket/minutes where minutes =",
        f"timeout (default {DEFAULT_TIMEOUT}) x GitHub-hosted multiplier (ubuntu 1, windows 2, macos 10)",
        "x matrix size; S <= 15, M <= 60, L <= 300, XL above; `self-hosted` when labels come",
        "from `vars`. `permissions` lists write scopes only. `required` names the main",
        "ruleset contexts this job produces.",
        "",
    ]
    for workflow in workflows:
        group = [r for r in rows if r["workflow"] == workflow]
        out += [
            f"### {workflow} ({cell(group[0]['workflow_name'])})",
            "",
            f"Triggers: {cell(group[0]['triggers'])}. Concurrency: `{cell(group[0]['concurrency'])}`.",
            "",
            "| Job | Names | Runners | Gate | Needs | Timeout | Permissions | Secrets | Effects | Cost | Required | Disposition | Native job | Owner | Exit condition |",
            "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|",
        ]
        for r in group:
            out.append("| " + " | ".join(cell(v) for v in (
                f"`{r['job_id']}`", r["names"], r["runners"], r["gate"], r["needs"], r["timeout"],
                r["permissions"], r["secrets"], r["effects"], r["cost"], r["required"],
                r["disposition"], r["native"], r["owner"], r["exit"])) + " |")
        notes = [f"- `{r['job_id']}`: {r['note']}" for r in group if r["note"]]
        out += [""] + (notes + [""] if notes else [])
    gaps = [r for r in rows if r["disposition"] == "retained-github"]
    out += [
        "## Gaps: jobs retained on GitHub",
        "",
        "Each row stays on GitHub Actions until its exit condition holds. Required checks in",
        "this list block the cutover; the rest are release or publication paths.",
        "",
        "| Job | Required | Owner | Exit condition |",
        "|---|---|---|---|",
    ]
    for r in gaps:
        out.append(f"| `{r['workflow']}:{r['job_id']}` | {cell(r['required'])} | {cell(r['owner'])} | {cell(r['exit'])} |")
    out += [
        "",
        "## Disposition vocabulary",
        "",
        "- `native`: the Buzz native executor runs this `ci.yml` job by id (`workflow_id: \"ci\"`,",
        "  kind 46100 `job_ids`; see `docs/ci/BUZZ_CI_PROTOCOL_CONTRACT.md`). Until the executor",
        "  is active this is a target, not a claim that native execution already happens.",
        "- `retained-github`: stays on GitHub Actions; `owner` and `exit` name who retires it and when.",
        "- `disabled-for-fork`: gated on `block/buzz`; it never runs in `only21mil/buzz` and needs",
        "  no native equivalent unless the fork adopts it.",
        "",
    ]
    return "\n".join(out)


def build(offline, workflows_dir=None, dispositions_path=None):
    rows = parse_all(workflows_dir or WORKFLOWS)
    checks = load_snapshot() if offline else fetch_required_checks()
    produced = annotate(rows, checks, load_dispositions(dispositions_path or DISPOSITIONS))
    return rows, checks, render(rows, checks, produced)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="exit 1 when the committed inventory is stale")
    mode.add_argument("--write", action="store_true", help="write the inventory (and snapshot when online)")
    parser.add_argument("--offline", action="store_true", help="use the committed required-check snapshot")
    args = parser.parse_args(argv)
    try:
        rows, checks, text = build(args.offline)
        if not args.offline:
            committed = load_snapshot() if SNAPSHOT.exists() else None
            if committed != checks:
                if args.write:
                    SNAPSHOT.write_text(json.dumps({
                        "source": RULES_ENDPOINT, "repository": REPO,
                        "fetched_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                        "checks": checks}, indent=2) + "\n")
                    print(f"updated {rel(SNAPSHOT)}")
                else:
                    raise InventoryError("required-check snapshot differs from the live main ruleset")
        text += "" if text.endswith("\n") else "\n"
        if args.write:
            DOC.write_text(text)
            print(f"wrote {rel(DOC)}: {len(rows)} jobs, {len(checks)} required checks")
        elif args.check:
            if not DOC.exists() or DOC.read_text() != text:
                raise InventoryError(f"{rel(DOC)} is stale; run --write")
            print(f"{rel(DOC)} is current: {len(rows)} jobs, {len(checks)} required checks")
        else:
            print(text, end="")
    except InventoryError as error:
        raise SystemExit(f"ci-workflow-inventory: {error}") from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

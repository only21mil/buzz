#!/usr/bin/env bash
set -euo pipefail

execute=false
if [[ ${1-} == "--execute" ]]; then
  execute=true
  shift
fi

if [[ $# -ne 5 ]]; then
  printf 'Usage: %s [--execute] VERDICT.json ISSUE_EVENT_ID REPO_OWNER REPO_ID EUC\n' "${0##*/}" >&2
  exit 2
fi

verdict_path=$1
issue_event_id=$2
repo_owner=$3
repo_id=$4
euc=$5

[[ -f $verdict_path && -r $verdict_path ]] || { printf 'Unreadable verdict: %s\n' "$verdict_path" >&2; exit 2; }
if ! jq -e '
  type == "object" and
  (.candidate_sha == null or (.candidate_sha | type == "string" and test("^([0-9a-f]{40}|[0-9a-f]{64})$"))) and
  (.green | type == "boolean") and
  (.security.total == 17) and (.probes.total_runs == 12) and
  (.missing | type == "array") and (.failed | type == "array") and (.sha_conflicts | type == "array")
' "$verdict_path" >/dev/null; then
  printf 'Malformed verdict: %s\n' "$verdict_path" >&2
  exit 2
fi

status=$(jq -r 'if .green then "resolved" else "open" end' "$verdict_path")
verdict_json=$(jq -cS '.' "$verdict_path")
content=$(printf 'Buzz CI Wave 1 acceptance evidence\n\n```json\n%s\n```\n' "$verdict_json")

if [[ $execute == true ]]; then
  printf '%s\n' "$content" | buzz issues status \
    --issue "$issue_event_id" \
    --status "$status" \
    --content - \
    --repo-owner "$repo_owner" \
    --repo-id "$repo_id" \
    --euc "$euc"
  exit 0
fi

printf "cat <<'BUZZ_ACCEPTANCE_EVIDENCE' | buzz issues status --issue %q --status %q --content - --repo-owner %q --repo-id %q --euc %q\n" \
  "$issue_event_id" "$status" "$repo_owner" "$repo_id" "$euc"
printf '%s\n' "$content"
printf 'BUZZ_ACCEPTANCE_EVIDENCE\n'

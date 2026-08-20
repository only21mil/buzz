#!/usr/bin/env bash
set -euo pipefail

script_path=${BASH_SOURCE[0]}
script_parent=.
if [[ $script_path == */* ]]; then
  script_parent=${script_path%/*}
fi
script_dir=$(cd -- "$script_parent" && pwd)
output_path="verdict.json"

usage() {
  printf 'Usage: %s [--output VERDICT.json] EVIDENCE.jsonl [EVIDENCE.jsonl ...]\n' "${0##*/}" >&2
}

emit_malformed() {
  local reason=$1
  local malformed_json
  malformed_json=$(jq -n --arg reason "$reason" '{
    candidate_sha: null,
    security: {passed: 0, total: 17},
    probes: {passed_runs: 0, total_runs: 12},
    green: false,
    missing: [],
    failed: [("MALFORMED_INPUT: " + $reason)],
    sha_conflicts: []
  }')
  if [[ $output_path == "-" ]]; then
    printf '%s\n' "$malformed_json"
  else
    printf '%s\n' "$malformed_json" >"$output_path"
  fi
  exit 2
}

if [[ ${1-} == "--output" ]]; then
  [[ $# -ge 3 ]] || { usage; exit 2; }
  output_path=$2
  shift 2
fi

[[ $# -ge 1 ]] || { usage; exit 2; }
for input_path in "$@"; do
  [[ -f $input_path && -r $input_path ]] || emit_malformed "unreadable input: $input_path"
done

security_ids=$(jq -c '[.tests[].test_id]' "$script_dir/tm_tests.json") \
  || emit_malformed "cannot read canonical TM test list"
[[ $(jq -r 'length' <<<"$security_ids") == 17 ]] \
  || emit_malformed "canonical TM test list does not contain 17 entries"

probe_ids='["P-i","P-ii","P-iii","P-iv","P-v","P-vi"]'
if ! records_json=$(jq -s '.' "$@"); then
  emit_malformed "invalid JSONL"
fi

if ! jq -e \
  --argjson security_ids "$security_ids" \
  --argjson probe_ids "$probe_ids" '
  def nonempty_string: type == "string" and length > 0;
  def integer: type == "number" and floor == .;
  def valid_record:
    type == "object" and
    ([keys[]] - ["suite","test_id","title","candidate_sha","pass","run","evidence_ref","executor","host","started_at","finished_at"] | length == 0) and
    (has("suite") and has("test_id") and has("title") and has("candidate_sha") and
     has("pass") and has("evidence_ref") and has("executor") and has("host") and
     has("started_at") and has("finished_at")) and
    (.suite == "security" or .suite == "probe") and
    (.test_id | nonempty_string) and
    (.title | nonempty_string) and
    (.candidate_sha | type == "string" and test("^([0-9a-f]{40}|[0-9a-f]{64})$")) and
    (.pass | type == "boolean") and
    (.evidence_ref | nonempty_string) and
    (.executor | nonempty_string) and
    (.host | nonempty_string) and
    (.started_at | integer and . >= 0) and
    (.finished_at | integer and . >= 0) and
    (.finished_at >= .started_at) and
    (.test_id as $id |
     if .suite == "probe"
     then has("run") and (.run == 1 or .run == 2) and ($probe_ids | index($id) != null)
     else (has("run") | not) and ($security_ids | index($id) != null)
     end);
  type == "array" and all(.[]; valid_record) and
  ([.[] | if .suite == "probe" then "probe/" + .test_id + "/" + (.run|tostring) else "security/" + .test_id end]
   | length == (unique | length))
' <<<"$records_json" >/dev/null; then
  emit_malformed "record schema, canonical ID, timestamp, or uniqueness violation"
fi

verdict_json=$(jq -n \
  --argjson records "$records_json" \
  --argjson security_ids "$security_ids" \
  --argjson probe_ids "$probe_ids" '
  def probe_key($id; $run): $id + "/run-" + ($run | tostring);
  ($records | map(select(.suite == "security"))) as $security |
  ($records | map(select(.suite == "probe"))) as $probes |
  ($records | map(.candidate_sha) | unique) as $shas |
  ([$security_ids[] | select(. as $id | ($security | any(.test_id == $id)) | not)]) as $missing_security |
  ([range(0; $probe_ids|length) as $i | [1,2][] as $run |
    select(($probes | any(.test_id == $probe_ids[$i] and .run == $run)) | not) |
    probe_key($probe_ids[$i]; $run)]) as $missing_probes |
  ([$security[] | select(.pass == false) | .test_id] +
   [$probes[] | select(.pass == false) | probe_key(.test_id; .run)]) as $failed |
  ($missing_security + $missing_probes) as $missing |
  (if ($shas|length) > 1 then $shas else [] end) as $sha_conflicts |
  ($security | map(select(.pass)) | length) as $security_passed |
  ($probes | map(select(.pass)) | length) as $probe_runs_passed |
  {
    candidate_sha: (if ($shas|length) == 1 then $shas[0] else null end),
    security: {passed: $security_passed, total: 17},
    probes: {passed_runs: $probe_runs_passed, total_runs: 12},
    green: (($missing|length) == 0 and ($failed|length) == 0 and
            ($sha_conflicts|length) == 0 and $security_passed == 17 and $probe_runs_passed == 12),
    missing: $missing,
    failed: $failed,
    sha_conflicts: $sha_conflicts
  }
')

if [[ $output_path == "-" ]]; then
  printf '%s\n' "$verdict_json"
else
  printf '%s\n' "$verdict_json" >"$output_path"
fi

if jq -e '.green == true' <<<"$verdict_json" >/dev/null; then
  exit 0
fi
exit 1

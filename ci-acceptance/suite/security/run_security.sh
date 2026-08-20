#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=../lib.sh
source "$SCRIPT_DIR/../lib.sh"

usage() {
  printf 'Usage: %s --candidate SHA --candidate-dir DIR --evidence-dir DIR [--output JSONL] [--plan]\n' \
    "${0##*/}" >&2
}

candidate=''
candidate_dir=''
evidence_dir=''
output_path='-'
plan=false
plan_output=''
security_dir="${SUITE_SECURITY_DIR:-$SCRIPT_DIR}"
executor="${SUITE_EXECUTOR:-$(id -un)@$(hostname)}"
host="${SUITE_HOST:-$(hostname)}"

while (($# > 0)); do
  case "$1" in
    --candidate)
      (($# >= 2)) || { usage; exit 4; }
      candidate=$2
      shift 2
      ;;
    --candidate-dir)
      (($# >= 2)) || { usage; exit 4; }
      candidate_dir=$2
      shift 2
      ;;
    --evidence-dir)
      (($# >= 2)) || { usage; exit 4; }
      evidence_dir=$2
      shift 2
      ;;
    --output)
      (($# >= 2)) || { usage; exit 4; }
      output_path=$2
      shift 2
      ;;
    --security-dir)
      (($# >= 2)) || { usage; exit 4; }
      security_dir=$2
      shift 2
      ;;
    --plan)
      plan=true
      shift
      ;;
    --plan-output)
      (($# >= 2)) || { usage; exit 4; }
      plan_output=$2
      shift 2
      ;;
    --executor)
      (($# >= 2)) || { usage; exit 4; }
      executor=$2
      shift 2
      ;;
    --host)
      (($# >= 2)) || { usage; exit 4; }
      host=$2
      shift 2
      ;;
    *)
      usage
      exit 4
      ;;
  esac
done

if ! suite_require_full_oid "$candidate" \
  || [[ -z "$candidate_dir" || ! -d "$candidate_dir" || -z "$evidence_dir" ]]; then
  printf 'candidate-dir must be an existing directory\n' >&2
  exit 4
fi
[[ -d "$security_dir" ]] || {
  printf 'security runner directory does not exist: %s\n' "$security_dir" >&2
  exit 4
}

if ! canonical_tests=$(jq -ce '.tests' "$SUITE_TM_TESTS"); then
  printf 'cannot read canonical security test list: %s\n' "$SUITE_TM_TESTS" >&2
  exit 2
fi
if [[ $(jq -r 'length' <<<"$canonical_tests") != 17 ]]; then
  printf 'canonical security test list does not contain 17 entries\n' >&2
  exit 2
fi
mapfile -t test_ids < <(jq -r '.[].test_id' <<<"$canonical_tests")
mapfile -t test_titles < <(jq -r '.[].title' <<<"$canonical_tests")

suite_detect_sudo
mkdir -p -- "$evidence_dir"

find_runners() {
  local test_id=$1
  local number=${test_id#TM-}
  mapfile -d '' -t FOUND_RUNNERS < <(
    find "$security_dir" -maxdepth 1 -type f -name "tm-${number}_*.sh" -print0 | sort -z
  )
}

write_paths_file() {
  local test_dir=$1
  local path_file=$2
  local parsed=${3-}
  local evidence_file

  {
    printf '%s\n' runner.stdout runner.stderr
    if [[ -n "$parsed" ]] && jq -e 'type == "object" and (.evidence_files | type == "array")' <<<"$parsed" >/dev/null 2>&1; then
      while IFS= read -r evidence_file; do
        [[ -n "$evidence_file" ]] && printf '%s\n' "$evidence_file"
      done < <(jq -r '.evidence_files[]?' <<<"$parsed")
    fi
    [[ -f "$test_dir/missing_runner.txt" ]] && printf '%s\n' missing_runner.txt
    [[ -f "$test_dir/validation_error.txt" ]] && printf '%s\n' validation_error.txt
  } | sort -u >"$path_file"
}

ensure_manifest() {
  local test_dir=$1
  local parsed=${2-}
  local paths_file="$test_dir/.manifest-paths"
  local manifest="$test_dir/MANIFEST.sha256"
  write_paths_file "$test_dir" "$paths_file" "$parsed"
  if ! suite_write_manifest "$test_dir" "$paths_file" "$manifest"; then
    printf 'manifest could not include one or more declared evidence files\n' \
      >"$test_dir/validation_error.txt"
    printf '%s\n' runner.stdout runner.stderr validation_error.txt \
      | sort -u >"$paths_file"
    suite_write_manifest "$test_dir" "$paths_file" "$manifest" || return 1
  fi
  rm -f -- "$paths_file"
  suite_hash_reference "$manifest"
}

append_record() {
  local line
  line=$(suite_emit_record "$@")
  printf '%s\n' "$line" >>"$record_file"
}

plan_mode() {
  local plan_file=${plan_output:-$evidence_dir/plan.json}
  local entries_file="$evidence_dir/.security-plan.$$.jsonl"
  local index test_id title test_dir runner parsed rc
  : >"$entries_file"
  for index in "${!test_ids[@]}"; do
    test_id=${test_ids[$index]}
    title=${test_titles[$index]}
    find_runners "$test_id"
    if ((${#FOUND_RUNNERS[@]} > 1)); then
      printf 'multiple runners found for %s\n' "$test_id" >&2
      rm -f -- "$entries_file"
      return 2
    fi
    if ((${#FOUND_RUNNERS[@]} == 0)); then
      jq -cn --arg id "$test_id" --arg title "$title" \
        '{test_id:$id,title:$title,status:"not_runnable",runner:null,preconditions:["one executable tm-NN runner must exist"]}' \
        >>"$entries_file"
      continue
    fi

    runner=${FOUND_RUNNERS[0]}
    test_dir="$evidence_dir/$test_id"
    mkdir -p -- "$test_dir"
    suite_run_bounded "$SUITE_TIMEOUT_SECONDS" "$test_dir/plan.stdout" "$test_dir/plan.stderr" \
      "$runner" --candidate "$candidate" --candidate-dir "$candidate_dir" \
      --evidence-dir "$test_dir" --plan
    rc=$SUITE_LAST_RC
    parsed=''
    if parsed=$(jq -s -c 'if (length == 1 and (.[0] | type == "object")) then .[0] else empty end' \
      "$test_dir/plan.stdout" 2>/dev/null) && [[ -n "$parsed" ]] && ((rc == 0)); then
      jq -cn --arg id "$test_id" --arg title "$title" --arg runner "$runner" \
        --argjson plan "$parsed" --argjson exit_code "$rc" \
        '{test_id:$id,title:$title,status:"plan",runner:$runner,exit:$exit_code,runner_plan:$plan}' \
        >>"$entries_file"
    else
      jq -cn --arg id "$test_id" --arg title "$title" --arg runner "$runner" \
        --argjson exit_code "$rc" \
        '{test_id:$id,title:$title,status:"malformed",runner:$runner,exit:$exit_code,preconditions:["runner --plan must emit one JSON object"]}' \
        >>"$entries_file"
    fi
  done

  mkdir -p -- "$(dirname -- "$plan_file")"
  jq -cn --arg candidate "$candidate" --arg runner_dir "$security_dir" \
    --arg executor "$executor" --arg host "$host" \
    --slurpfile tests "$entries_file" \
    '{suite:"security",mode:"plan",candidate_sha:$candidate,runner_dir:$runner_dir,executor:$executor,host:$host,tests:$tests}' \
    >"$plan_file"
  rm -f -- "$entries_file"
  printf '%s\n' "$plan_file" >&2
  return 0
}

if [[ "$plan" == true ]]; then
  plan_mode
  exit $?
fi

if [[ "$output_path" == - ]]; then
  record_file=$(mktemp "$evidence_dir/.security-records.XXXXXX")
  cleanup_record_file=true
else
  mkdir -p -- "$(dirname -- "$output_path")"
  record_file=$output_path
  cleanup_record_file=false
fi
: >"$record_file"
trap 'if [[ "${cleanup_record_file:-false}" == true ]]; then rm -f -- "$record_file"; fi' EXIT

for index in "${!test_ids[@]}"; do
  test_id=${test_ids[$index]}
  title=${test_titles[$index]}
  test_dir="$evidence_dir/$test_id"
  mkdir -p -- "$test_dir"
  : >"$test_dir/runner.stdout"
  : >"$test_dir/runner.stderr"
  find_runners "$test_id"
  if ((${#FOUND_RUNNERS[@]} > 1)); then
    printf 'multiple runners found for %s\n' "$test_id" >&2
    exit 2
  fi

  started=$(suite_now)
  if ((${#FOUND_RUNNERS[@]} == 0)); then
    printf 'missing_runner: %s\n' "$test_id" >"$test_dir/missing_runner.txt"
    finished=$(suite_now)
    evidence_ref=$(ensure_manifest "$test_dir" '') || {
      printf 'could not create evidence manifest for %s\n' "$test_id" >&2
      exit 4
    }
    append_record security "$test_id" "$title" "$candidate" false "$evidence_ref" \
      "$executor" "$host" "$started" "$finished"
    continue
  fi

  runner=${FOUND_RUNNERS[0]}
  suite_run_bounded "$SUITE_TIMEOUT_SECONDS" "$test_dir/runner.stdout" "$test_dir/runner.stderr" \
    "$runner" --candidate "$candidate" --candidate-dir "$candidate_dir" --evidence-dir "$test_dir"
  runner_rc=$SUITE_LAST_RC
  finished=$(suite_now)
  parsed=''
  parsed_ok=false
  validation_error=''

  if parsed=$(jq -s -c 'if (length == 1 and (.[0] | type == "object")) then .[0] else empty end' \
    "$test_dir/runner.stdout" 2>/dev/null) && [[ -n "$parsed" ]]; then
    parsed_ok=true
    printf '%s\n' "$parsed" >"$test_dir/runner.json"
    if ! jq -e \
      --arg id "$test_id" --arg title "$title" --arg candidate "$candidate" '
        .test_id == $id and .title == $title and
        (.status | type == "string" and (IN("pass","fail","not_runnable"))) and
        (.pass | type == "boolean") and
        (.summary | type == "string") and
        (.checks | type == "array" and all(.[];
          type == "object" and (.name | type == "string" and length > 0) and
          (.status | type == "string" and (IN("pass","fail","not_runnable","plan"))) and
          (.detail | type == "string"))) and
        (.evidence_files | type == "array" and all(.[]; type == "string")) and
        (.preconditions | type == "array" and all(.[]; type == "string")) and
        ((has("candidate_sha") | not) or
          (.candidate_sha | type == "string" and test("^([0-9a-f]{40}|[0-9a-f]{64})$") and . == $candidate))
      ' <<<"$parsed" >/dev/null; then
      validation_error='runner JSON failed the suite contract'
    fi

    if [[ -z "$validation_error" ]]; then
      while IFS= read -r evidence_file; do
        [[ -n "$evidence_file" ]] || continue
        if ! suite_is_safe_relative_path "$evidence_file" \
          || [[ ! -f "$test_dir/$evidence_file" ]] \
          || ! suite_path_is_under "$test_dir" "$test_dir/$evidence_file"; then
          validation_error="runner evidence file is missing or escapes TM directory: $evidence_file"
          break
        fi
      done < <(jq -r '.evidence_files[]' <<<"$parsed")
    fi

    if [[ -z "$validation_error" ]] \
      && ! jq -e '.status == "pass" and (.checks | all(.[]; .status == "pass")) and .pass == true' \
      <<<"$parsed" >/dev/null; then
      validation_error='runner marked pass without all checks passing'
    fi
  else
    validation_error='runner stdout was not exactly one JSON object'
  fi

  if [[ -n "$validation_error" ]]; then
    printf '%s\n' "$validation_error" >"$test_dir/validation_error.txt"
  fi

  pass=false
  if [[ "$parsed_ok" == true && -z "$validation_error" && "$runner_rc" == 0 ]] \
    && jq -e '.status == "pass" and .pass == true' <<<"$parsed" >/dev/null 2>&1; then
    pass=true
  fi
  evidence_ref=$(ensure_manifest "$test_dir" "$parsed") || {
    printf 'could not create evidence manifest for %s\n' "$test_id" >&2
    exit 4
  }
  append_record security "$test_id" "$title" "$candidate" "$pass" "$evidence_ref" \
    "$executor" "$host" "$started" "$finished"
done

if [[ "$output_path" == - ]]; then
  cat "$record_file"
fi

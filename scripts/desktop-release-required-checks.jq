# Input is gh api --paginate --slurp for rules/branches/main. Preserve producer
# binding and strict main freshness. Empty/unbound/ambiguous policies refuse.
[.[][] | select(.type == "required_status_checks") | .parameters] as $rules
| if ($rules | length) == 0 or any($rules[]; .strict_required_status_checks_policy != true)
  then error("desktop release needs strict required status checks") else . end
| [$rules[].required_status_checks[]] as $checks
| if ($checks | length) == 0 or any($checks[];
    (.context | type) != "string" or (.context | length) == 0 or
    (.context | test("[\\t\\r\\n]")) or
    (.integration_id | type) != "number" or .integration_id <= 0 or
    (.integration_id | floor) != .integration_id)
  then error("desktop release checks must bind a name and GitHub App") else . end
| if any($checks | group_by(.context)[]; (map(.integration_id) | unique | length) != 1)
  then error("desktop release check has ambiguous producers") else . end
| if any($checks[]; .context == "Desktop Release Candidate" and .integration_id == 15368) | not
  then error("Desktop Release Candidate must be required from GitHub Actions") else . end
| $checks | unique_by([.context, .integration_id]) | sort_by(.context)[]
| "\(.context):\(.integration_id)"

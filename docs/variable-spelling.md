# Workflow variable spelling

Workflow YAML uses dotted template variables inside `{{...}}`. Conditions use
the same values as flat evalexpr names with underscores.

| Value | Template spelling | Condition spelling |
| --- | --- | --- |
| Trigger author | `{{trigger.author}}` | `trigger_author` |
| Trigger text | `{{trigger.text}}` | `trigger_text` |
| Step output | `{{steps.<step_id>.output.<field>}}` | `steps_<step_id>_output_<field>` |

For webhook keys containing dots, both templates and `body_path(...)` check
the exact flattened top-level key first. They walk the nested JSON body only
when that literal key is absent.

Step IDs may contain only ASCII letters, digits, and underscores. This keeps
their condition names unambiguous.

## Workflow state actions

`read_state` reads a key scoped to the workflow:

```yaml
- id: load_counter
  action: read_state
  key: counters/{{trigger.author}}
```

`write_state` requires an expiry. The key, value, expiry, and optional expected
revision may use template variables:

```yaml
- id: save_counter
  action: write_state
  key: counters/{{trigger.author}}
  value: '{{steps.load_counter.output.value}}'
  expires_in: 24h
  expected_revision: '{{steps.load_counter.output.revision}}'
```

Set `expected_revision: '0'` for a create-only write. Any other expected
revision performs compare-and-swap. A compare-and-swap conflict completes the
step with `written: false`; it does not fail the workflow. Missing reads and
conflicts on an absent key return revision `0`.

Definition validation rejects blank keys, expiries, and supplied revisions. An
empty string remains a valid state value. The runtime checks resolved key and
value byte sizes and duration bounds after template expansion. Binary joins are
outside the current state-action contract.

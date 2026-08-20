# Probe mock limits

The acceptance scripts keep the §3 assertions intact, but the local fixture
cannot exercise relay or runner-host behavior literally:

- P-v uses MOCK_CI_INFRASTRUCTURE_FAILURE=1 when BUZZ_CI_BIN is the shipped
  mock. That models an owner-killed runner by making the persisted run enter
  infrastructure_failure; the probe still validates terminal watch JSONL and
  the reason. A live run requires the owner to drop the runner service.
- The mock log bodies are already deterministic, scrubbed text. The probes
  assert the C-command shape, cap flag, byte size, full hash, and per-attempt
  retention, while production broker quota/rate/control-character enforcement
  remains a relay implementation concern.
- P-vi uses a local dead URL and the mock's bounded retry loop. It proves the
  exit-2/no-fall-through contract and stderr attempt accounting, not a real
  network outage.
- The mock advances jobs on status/watch calls instead of executing the YAML
  workflow. The checked-in job scripts remain the source of the attempt-1
  failure, attempt-2 success, five-second job, and timeout fixtures.


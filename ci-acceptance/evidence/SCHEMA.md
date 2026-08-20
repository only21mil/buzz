# Buzz CI acceptance evidence record

Each input file is JSON Lines: one `record.schema.json` object per line. Producers must emit one record per security test and one record per probe/run pair. The aggregate gate accepts only the exact canonical sets at one candidate SHA.

Required fields:

- `suite`: `security` or `probe`.
- `test_id`: `TM-01` through `TM-17` for security; `P-i` through `P-vi` for probes.
- `title`: non-empty human-readable test title.
- `candidate_sha`: the complete lowercase 40-hex Git SHA-1 or 64-hex Git SHA-256 object ID. Truncated or uppercase IDs are invalid.
- `pass`: boolean result.
- `run`: required only for probes, and exactly `1` or `2`. Security records must omit it.
- `evidence_ref`: non-empty path or SHA-256 reference for the retained log/output.
- `executor`, `host`: non-empty execution identity and hostname.
- `started_at`, `finished_at`: non-negative integer Unix UTC seconds. The aggregator additionally requires `finished_at >= started_at`.

Unknown fields, unknown test IDs, duplicate suite/test/run keys, malformed JSON, and schema violations are malformed input (exit 2). Valid but incomplete, failed, or mixed-SHA evidence is not green (exit 1). Only all 17 passing security records and all 12 passing probe/run records at one exact SHA are green (exit 0).

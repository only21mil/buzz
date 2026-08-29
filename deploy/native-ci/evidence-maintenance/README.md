# Buzz CI evidence maintenance package

This package installs a dormant one-shot service and timer for CI evidence
retention. Installation does not reload systemd, create the service account,
enable the timer, start the service, or install object-storage credentials.

The maintainer lists only the `_ci/v2/` prefix and processes keys ending in
`.receipt.json`. It validates each receipt against the key derived from its
embedded immutable attempt binding. A blob is deleted only after its full size
and SHA-256 match that binding. Receipt-free blobs and malformed receipts never
authorize deletion.

After `retain_until`, the service removes the blob and leaves the receipt as a
tombstone. After `tombstone_until`, it confirms the blob is absent and removes
the receipt. A stopped run replays its last incomplete page. All transitions are
idempotent.

The operator must separately create
`/etc/buzzci/evidence-maintenance.env`, readable by the dedicated service user,
with `BUZZ_S3_ENDPOINT`, `BUZZ_S3_BUCKET`, and either workload identity or the
least-privilege `BUZZ_S3_ACCESS_KEY` and `BUZZ_S3_SECRET_KEY`. The credentials
must allow list on `_ci/v2/` and get, head, and delete only within that prefix.

Activation is a separate approval-gated operation. The checked-in timer has an
`[Install]` target but the package installer never enables it.

## Checks

```bash
python3 -m unittest discover -s deploy/native-ci/evidence-maintenance/tests -v
cargo test -p buzz-media ci_evidence
cargo test -p buzz-relay --bin buzz-ci-evidence-maintenance
```

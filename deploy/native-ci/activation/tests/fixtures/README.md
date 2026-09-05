# Retained rollback manifest

`rollback-manifest-009d2f06.json` is the unchanged public manifest retained in
`/var/lib/buzzci/activation-controller/rollback-cleanup-v1.json` on Framework
Desktop after the completed rollback of source
`009d2f06d373d0e2d4960db2306ba9144c105052`. It contains public package metadata,
public event templates and file hashes, with no credentials or receipt payloads.

The canonical manifest SHA-256 is
`302e600cf5c729c125551c781a7d11ffe4402fce1c9c4b0b28c2ebc61eff12ab`.
Its package digest is
`71bdc8878f8c887bd4c79533063c981e5bdd69aaff51c0b4ccde00feda7963e2`.
At readback, the complete cleanup marker SHA-256 was
`1ef0f8607316c783953281109c2cc224f3545bfc476fdc718eb5280eb3101f54`.
The installed historical package validator had SHA-256
`9ef19fb93342d19c4e5bd57d636ec3547e7ab956674cf7a14ab370b617db1e39`
and accepted this exact manifest. Its bytes matched `package.py` at the recorded
source commit. The retained controller had SHA-256
`b32b8ec63017f6771684a0bc32b221dda672397fe36e5f96a9c0c33ec475273c`.

The old template has exactly `actor`, `time_reference`, `run_event`,
`grant_event`, `rerun_event` and `tombstone_event`. That source's fixed fixture
script digest is `d081e43ebfde3ee67c3cd8d852d58410a79ad799bbfa2cf98d5e2ef7b8bed3b1`;
its receipt verifier expected-stage digest is
`c8addbb42bace522e99fc8fe00603c9245db61ac8a599ef5762c2744267189cd`.
All of these old values are bound by the full canonical manifest hash.

M15 source `5d9e277ebfa19bf949721768f50859787626dbd1` added five required
acceptance fields and changed those two fixed digests. Its candidate package
loaded successfully, then `check_current` rejected the retained old manifest
inside `_read_rollback_cleanup`, before staging. The controller now recognizes
only this exact historical record when reading cleanup and retirement markers.
Current package loading and acceptance validation remain strict. Other old
packages or any change to this record need a separately reviewed migration.
The normal controller lifecycle preserves the old marker in its bound archive;
operators must not edit or delete it to retry activation.

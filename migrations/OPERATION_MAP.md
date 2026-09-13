# Migration operation map

Every applied migration stays byte-identical forever. This directory holds the
map that proves it: `operation-map.json` is the machine-readable ledger, this
file is the explanation. The checker is `scripts/check-frozen-migrations.py`.

## Frozen prefix

Migrations `0001` through `0042` are frozen. Two manifests pin their SHA-256:

- `scripts/migrations-0001-0035.sha256` (original ledger, untouched)
- `scripts/migrations-0036-0042.sha256` (audited extension)

The checker fails if any of those 42 files changes, goes missing, or shares a
number with another file. It also fails a new migration that re-applies a
frozen semantic operation (same `create-table:`/`alter-table:`/etc id) unless
the admission entry names it in `supersedes`.

`operation-map.json` records both hashes per file: `sha256` over the raw bytes
and `sqlx_sha384`, the checksum SQLx 0.9 records in `_sqlx_migrations`
(SHA-384 of the same bytes). The Rust tests in
`crates/buzz-db/src/migration.rs` recompute the SQLx checksums from the
embedded files, so a silent byte edit fails in `cargo test` too.

## The 0040 header correction

`0040_agent_drafts.sql` line 1 says it depends on a "reserved 0039 relay
authorization migration". That comment is stale: the file only touches the
`0001` base (`communities`, `events`, `search_tsv`). It never reads or writes
anything `0039` creates, and `0039` only replaces a CHECK constraint on
`moderation_actions`.

The file bytes stay frozen, so the correction lives here and in
`operation-map.json`, which lists `0040` with `prerequisites: [1]`. Do not
"fix" the comment by editing the SQL. That would change its checksum and break
every database that already applied it.

## Fork vs upstream, versions 0029 and up

Compared against upstream `block/buzz` at
`4cd82f513214aad11c2b742ce7cc7c681e8e32a0`. Fork `0001`-`0028` are
byte-identical to upstream. From `0029` on the numbers diverge, but three
operations are shared blobs that must execute exactly once:

| Fork | Upstream | Bytes |
| --- | --- | --- |
| 0036 workflow run error codes | 0031 | identical |
| 0037 push message kinds | 0040 | identical |
| 0038 push gateway dogfood profile | 0043 | identical |

They run under the fork numbers. A merge must never schedule the upstream
numbers alongside them.

Fork-only operations with no upstream equivalent: `0029`-`0035` (workflow
snapshots/state/approvals, CI event storage, resume recovery, effect claims,
CI grants), `0039` (channel admin audit actions), `0040` (agent drafts),
`0041` (CI check storage), `0042` (CI merge gate).

Upstream-only operations and their dispositions (details in
`operation-map.json`):

- `0029`/`0030` community deletion: deferred. Revisit only if the product
  ships community deletion.
- `0032` channel roster snapshot fence: candidate for the P08 tail. It guards
  kind 39002 snapshots during rolling deploys and pairs with the complete
  roster port. Append byte-identical above the verified maximum after
  confirming the fork 39002 emission path takes the same lock order.
- `0033` private managed-agent FTS exclusion: inapplicable unless kind 30179
  lands. The fork has no 30179 producer.
- `0034` heartbeat vacuum truncation: candidate for the P08 tail. Fork `0026`
  is byte-identical to upstream `0026`, so the ALTER applies cleanly. Needs a
  heartbeat concurrency test on fresh and upgrade paths.
- `0035`-`0039` relay admin bundle: deferred to the P04 admin protocol
  decision. Adopt as one unit or not at all. Note `0035` amends
  `moderation_actions`, `moderation_reports`, and `product_feedback`, which
  overlaps fork `0039`'s CHECK vocabulary. Any adoption lands after fork
  `0039` and preserves it.
- `0041`/`0042`/`0044` NIP-FI: excluded. Upstream retracted the ledger itself
  in `0044`. The fork never had these tables, so there is nothing to drop and
  `0041`/`0042` absence is not a gap.

## Appending a migration

New migrations append above the verified maximum (today `0042`), in
dependency order. Each needs an admission-map entry with `source_commit`,
`source_path`, `source_sha256`, `adapted_sql_sha256`, `prerequisites` (a
list; empty is fine for independent operations, missing is not),
`operations` (non-empty op ids in this map's vocabulary), and
`desired_schema_delta`. A later change to an existing object gets a new
operation id and names the old one in `supersedes`. Final tail admission
happens in P08 after reconciliation; pre-merge admission lists do not qualify
the merged tree.

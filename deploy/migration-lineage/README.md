# Migration lineage cutover

Victor must approve running either SQL script and the production deployment.
These files prepare candidate A; committing them does not authorize execution.
Run neither script automatically from relay startup or the deployment script.

The merged baseline is upstream 0001-0046 at commit 5511b56fc, eleven fork
migrations moved by +1000 without changing their bytes, 1043 for write fences,
and pending fork 0050 adopted as 1044 for draft soft deletes. There are 59
migrations, ending at 1044. New fork migrations start at 1045. Upstream numbers
remain reserved for upstream. The three historical ledger filenames are kept
for CI compatibility; together they now pin all 59 files. operation-map.json's
legacy `fork` array lists the complete merged lineage. admission-map.json is
empty because the entire baseline is frozen.

## Before production approval

Dry-run the exact merged candidate on an isolated restore of the last backup.
The September 10 backup starts at 38; advance it with the old production
candidate to 42 first. Verify the listing, run forward.sql, then migrate with
the merged candidate. Also migrate an empty database. Compare normalized
schema dumps and fence coverage. The events.search_tsv wrapper nesting may
differ, but both must exclude 30179, 14201 and 14202. Record migration 0033's
heap rewrite time and prove the gate sees 42 < 59. Test forward followed by
reverse before new migrations; it must reproduce all original ledger rows.
This PR does not claim that backup rehearsal has run.

schema/schema.sql was hand-merged because the repository has no generator.
It retains fork objects and adds upstream desired-state changes, the eleven
fork fence attachments, and the 1044 draft trigger function.

## Production steps still requiring Victor's approval

1. Read the full `_sqlx_migrations` listing with the existing read-only helper.
   Require exactly versions 1-42, all successful, with the descriptions and
   SHA-384 checksums embedded in forward.sql. Stop on any difference.
2. Take a new nonempty `pg_dump -Fc` backup in the approved deploy directory.
3. Run `psql -X -v ON_ERROR_STOP=1 -f forward.sql` as the authorized database
   role. It locks the ledger and checks every identity before changing 14
   version numbers. Checksums, descriptions and execution metadata stay intact.
4. Read back the ledger. Require 42 successful rows: 1-28, 31, 40, 43,
   1029-1035 and 1039-1042, with all original checksums unchanged.
5. Deploy the reviewed merged image through deploy-local.sh. Its count gate
   must invoke `buzz-admin migrate`, applying 17 migrations: 29, 30, 32, 33,
   34, 35, 36, 37, 38, 39, 41, 42, 44, 45, 46, 1043 and 1044, before relay swap.
6. Require 59 successful rows, max version 1044, healthy relay probes, and the
   same community fence coverage as the fresh rehearsal database.

## Rollback

Before step 5 has applied any new migration, reverse.sql restores the original
42 identities. It refuses a changed ledger or any extra row. Run it with
`psql -X -v ON_ERROR_STOP=1 -f reverse.sql` only with Victor's approval.
After any new migration applies, use the approved backup restore and prior
image rollback procedure under separate production approval. Never reverse
only the ledger after the schema has advanced.

The scripts deliberately reject dev databases carrying fork 0043-0049 or
0050. Those databases need a separately reviewed tail rewrite or an authorized
reset. The push gateway's independent migration lineage is outside this change.

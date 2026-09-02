# Buzz Docker Compose deployment

This is the single-node/VPS deployment bundle. It is intentionally separate from
the root `docker-compose.yml`, which remains local development infrastructure.

## Quick start

```bash
cd deploy/compose
cp .env.example .env
$EDITOR .env       # replace every CHANGE_ME value
./run.sh start
```

For a public VPS with automatic Let's Encrypt certificates:

```bash
cd deploy/compose
BUZZ_COMPOSE_TLS=true ./run.sh start
```

The bootstrap script should eventually replace manual `.env` editing for normal
users. It is responsible for generating stable secrets and, optionally, an owner
keypair.

## Production notes

- Requires Docker Compose v2.24.4 or newer; the TLS override uses Compose's
  `!reset` tag to remove the direct relay port when Caddy terminates HTTPS.
- Default `BUZZ_IMAGE` tracks `ghcr.io/block/buzz:main` for early testing. Pin it to `ghcr.io/block/buzz:sha-<7>` or a semver release tag for production once available.
- Keep `BUZZ_RELAY_PRIVATE_KEY`, `BUZZ_GIT_HOOK_HMAC_SECRET`, database/Redis,
  and S3 secrets stable across restarts.
- `RELAY_OWNER_PUBKEY` is intentionally not prefixed with `BUZZ_`; it must be a
  64-character hex Nostr pubkey when closed relay mode is enabled.
- `BUZZ_AUTO_MIGRATE` is opt-in. Set `BUZZ_AUTO_MIGRATE=true` or run
  `buzz-admin migrate` before starting the relay when bootstrapping a fresh
  database. Auto-migration requires an image that includes embedded SQLx
  migrations.
- The stack uses Postgres, Redis, MinIO, and a git data volume because
  those are real Buzz dependencies today. Minimal mode can simplify this later.
- The bundled Compose stack fixes the relay endpoint to `http://minio:9000` and
  `BUZZ_S3_ADDRESSING_STYLE=path`: Docker DNS resolves `minio`, not
  `<bucket>.minio`. It is not configurable for an external S3 provider through
  `.env`; use the Helm chart or a custom Compose configuration for providers
  such as new Railway Storage Buckets that require `virtual` addressing.

Run `./run.sh backup-hint` for the backup checklist.

## Framework desktop production deploy

The localhost production override keeps the Compose project name `buzz-prod`,
binds the relay to `127.0.0.1:3000`, and disables startup migrations. Supply the
non-secret Compose settings file separately from the mode-`0600` secret file:

```bash
export BUZZ_COMPOSE_ENV_FILE=/path/to/compose.env
export BUZZ_SECRET_ENV_FILE="$HOME/.config/sats/secrets.env"
export BUZZ_PRE_FREEZE_RECEIPT=/path/to/pre-freeze-receipt.json
evidence_dir=/absolute/private/evidence-directory # caller-owned mode 0700
../../scripts/protected-ci-receipt.py acquire-main \
  --repository only21mil/buzz \
  --head 0123456789abcdef0123456789abcdef01234567 \
  --branch main --output "$evidence_dir/protected-ci-main.json"
../../scripts/protected-ci-receipt.py validate \
  --receipt "$evidence_dir/protected-ci-main.json" \
  --repository only21mil/buzz \
  --head 0123456789abcdef0123456789abcdef01234567 \
  --scope main --max-age-seconds 86400 --reverify
export BUZZ_PROTECTED_CI_RECEIPT="$evidence_dir/protected-ci-main.json"
./deploy-local.sh 0123456789abcdef0123456789abcdef01234567
```

`deploy-local.sh` accepts one full commit ID. It builds that exact clean commit,
dumps Postgres, compares the image migration set with `_sqlx_migrations`, and
runs the new image's `buzz-admin migrate` before swapping only `relay`. It then
checks readiness, NIP-11, the running image ID, and the relay binary hash. A
failed post-swap check restores the prior image and verifies it before exiting
nonzero. Deploy records default to `$HOME/.local/state/buzz-relay/deploys`.

The checked-out `HEAD`, `BUZZ_DEPLOY_SOURCE_REF` (default
`refs/remotes/origin/main`), pre-freeze receipt, and protected-CI receipt must
all name the requested full commit. Both receipts must be mode-safe JSON from
`only21mil/buzz`, record `overall: "PASS"`, contain at least one passing check,
and be no older than `BUZZ_DEPLOY_RECEIPT_MAX_AGE_SECONDS` (default 86400).
The pre-freeze receipt comes from `scripts/pre-freeze.sh`. The protected-CI
receipt must be the canonical `main`-scope receipt acquired for the landed
commit: operator-acquired, with the exact GitHub repository, `main` ref,
branch-rule, ruleset, and check-run bodies retained and hash-bound. GitHub does
not sign those bodies, so the deploy runs `validate --reverify`, which requires
the live GitHub authority to match the receipt binding through the pinned `gh`
and the live `refs/heads/main` head to equal the landed commit; `GH_TOKEN` must
be in the environment. `BUZZ_PROTECTED_CI_RECEIPT` is mandatory and absolute; its
immediate parent must be caller-owned mode `0700`, and the receipt must be mode
`0600`. Pull-request-scoped receipts, legacy JSON that merely asserts
`protected: true` or `full_exact_head: true`, hand-edited receipts, and
receipts GitHub no longer backs are refused. Reacquire after any rerun or
ruleset change.

`run-local.sh` carries an expected deployment image through `sudo` with an
explicit non-secret environment assignment, asks Compose for its resolved image
list, and refuses missing, default, or mismatched images before a migration or
swap. Secrets remain in inherited environment variables; their values are not
placed in command arguments or logs.

If the prior image lacks an accurate migration label, an operator may set
`BUZZ_PRIOR_MIGRATION_OVERRIDE` only to the exact
`<prior-image-id>@<current-database-migration>` binding printed by a refused
run. The override never permits rollback after the database advances beyond
that recorded migration.

Do not use `run-local.sh up` as an upgrade command. Use `deploy-local.sh` so the
backup, migration check, and rollback path cannot be skipped.

## Validation

Before sharing an install link publicly, verify a fresh install with:

```bash
cd deploy/compose
cp .env.example .env
$EDITOR .env
./run.sh config
./run.sh start
curl -fsS "http://127.0.0.1:$(grep -E '^BUZZ_HTTP_PORT=' .env | cut -d= -f2-)/_liveness"
./run.sh status
```

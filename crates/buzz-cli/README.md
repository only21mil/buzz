# Buzz CLI

Agent-first command-line interface for Buzz relay. JSON in, JSON out.

## Install

```bash
cargo install --path crates/buzz-cli
```

## Authentication

| Env Var | Mode | Use Case |
|---------|------|----------|
| `BUZZ_PRIVATE_KEY` | NIP-98 Schnorr signature | Agents with a keypair |

```bash
# Private key identity (NIP-98 signed requests)
export BUZZ_PRIVATE_KEY="nsec1..."
buzz channels list
```

## Usage

All output is JSON on stdout. Errors are JSON on stderr. Exit codes: 0=ok, 1=user error, 2=network, 3=auth, 4=other, 5=write conflict.

```bash
# Set relay URL (defaults to http://localhost:3000)
export BUZZ_RELAY_URL="https://relay.example.com"

# Messages
buzz messages send --channel <uuid> --content "Hello"
buzz messages send --channel <uuid> --content "Reply" --reply-to <event-id> --broadcast
buzz messages send --channel <uuid> --content - < message.md   # read body from stdin
buzz messages get --channel <uuid> --limit 20
buzz messages thread --channel <uuid> --event <event-id>
buzz messages search --query "architecture"
buzz messages search --author <pubkey|npub|name> --since <unix-ts>
buzz messages edit --event <event-id> --content "Updated text"
buzz messages delete --event <event-id>

# Diffs
buzz messages send-diff --channel <uuid> --diff - --repo https://github.com/org/repo --commit abc123 < diff.patch

# Channels
buzz channels list
buzz channels create --name "my-channel" --type stream --visibility open
buzz channels join --channel <uuid>
buzz channels topic --channel <uuid> --topic "New topic"

# Reactions
buzz reactions add --event <event-id> --emoji "👍"
buzz reactions get --event <event-id>

# Users & Presence
buzz users get                          # your own profile
buzz users get --pubkey <hex>           # single user
buzz users get --pubkey <hex> --pubkey <hex>  # batch (max 200)
buzz users get --name Honey --owner me  # exact-name lookup in your managed agents
buzz users set-presence --status online
buzz users set-status --text "heads down on the CLI" --emoji "🚀"
buzz users set-status --clear                 # remove your status

# DMs
buzz dms open --pubkey <hex>
buzz dms list

# Workflows
buzz workflows list --channel <uuid>
buzz workflows trigger --workflow <uuid>
buzz workflows approve --token <uuid>
buzz workflows approve --token <uuid> --approved false --note "needs revision"

# Forum
buzz messages vote --event <event-id> --direction up

# Canvas
buzz canvas get --channel <uuid>
buzz canvas set --channel <uuid> --content "# Welcome"

# Agent Memory (NIP-AE)
buzz mem ls
buzz mem get <slug>
buzz mem set <slug> "my-value"
buzz mem patch <slug> --base-hash <hex> < diff.patch  # or --no-base-hash
buzz mem rm <slug>

# Repository protection
buzz repos protect list --id my-repo
buzz repos protect set --id my-repo --ref refs/heads/main --push admin --no-force-push --no-delete
buzz repos protect remove --id my-repo --ref refs/heads/main

# Buzz-authoritative GitHub CI mirroring
buzz repos status --id my-repo
buzz repos stage-ci --id my-repo --source-ref refs/heads/pr/9 --commit <H> --expected-github-ci absent
buzz repos promote --id my-repo --base <B> --head <H> --source-ref refs/heads/pr/9 --ci-ref refs/heads/buzz-ci/<H> --required-check test

# Bootstrap only; never use this as the ongoing synchronization direction
buzz repos import-main --id my-repo --commit <exact-40-hex-GitHub-main>

# Pipe to jq
buzz channels list | jq '.[].name'
```

`protect set` replaces every existing rule for the exact ref pattern. Any
constraint omitted from the command is removed. `protect list` reports malformed
stored rules in `validation_error` so an owner can remove and repair them.

## Buzz-first delivery lifecycle

Buzz owns branches, pull requests, and the only `main` transition. GitHub is an
exact-ref CI mirror. It receives commits already fetched from Buzz, runs checks
at those exact commits, and mirrors Buzz main only after the Buzz CAS succeeds.
GitHub drift is never imported by the ongoing operator flow.

`repos stage-ci` verifies a Buzz source ref at exact `H`, fetches it from Buzz,
pushes that object to deterministic `refs/heads/buzz-ci/H` under an explicit
absent-or-old lease, and reads the CI ref back. The thin GitHub PR targets this
ref solely to run CI; the CLI does not poll.

`repos promote` requires exact `B` and `H`, revalidates both Buzz refs and the
GitHub CI ref, proves `B` is an ancestor of `H` from the Buzz-fetched graph, and
requires each named GitHub Actions check (app id 15368) uniquely
completed+success at `H`. It then CAS-updates
Buzz main `B -> H`, followed by leased GitHub main `B -> H`, and reads both back.
No squash or merge commit is created: exact tested `H` becomes both mains.

If Buzz reaches `H` but the GitHub mirror push or readback fails, run
`repos status`. If GitHub main remains `B`, rerun the same `promote` invocation
with the same `B` and `H`; the command repeats every proof before completing the
mirror. GitHub main at `H` means the dual state is already exact. Any other drift
fails closed.

`repos import-main` is only a one-time bootstrap for an absent Buzz main. It is
not the ongoing synchronization direction and cannot update an existing Buzz
main. GitHub Git and checks require `GH_TOKEN` or `GITHUB_TOKEN`; credentials
stay in environment-backed askpass/API headers and never enter arguments or
URLs.

The recipe below uses the intended issue `--channel`/`--external-id` and PR
`--channel`/`--issue`/`--external-id` flags. Choose opaque, stable external IDs
before the first write. Never correlate records by title.

```bash
set -euo pipefail

export CHANNEL_ID="<exact-channel-uuid>"
export REPO_OWNER="<exact-64-hex-owner-pubkey>"
export REPO_ID="<exact-repository-d-tag>"
export WORK_EXTERNAL_ID="<stable-caller-issued-work-id>"
export PR_EXTERNAL_ID="<stable-caller-issued-review-id>"
export GH_REPO="<owner/repository>"
export GH_CLONE_URL="<exact-GitHub-clone-url-for-origin>"
export BUZZ_CLONE_URL="<canonical-Buzz-clone-url>"

WORK_STATE_KEY="$(printf '%s' "$WORK_EXTERNAL_ID" | sha256sum | cut -d' ' -f1)"
state_dir="${XDG_STATE_HOME:-$HOME/.local/state}/buzz/lifecycles/$WORK_STATE_KEY"
install -d -m 700 "$state_dir"
umask 077

buzz issues create \
  --repo-owner "$REPO_OWNER" --repo-id "$REPO_ID" \
  --channel "$CHANNEL_ID" --external-id "$WORK_EXTERNAL_ID" \
  --title "Fix the specific failure" --content - \
  < issue.md | tee "$state_dir/issue-create.json"
ISSUE_EVENT_ID="$(jq -er '.event_id | select(test("^[0-9a-f]{64}$"))' \
  "$state_dir/issue-create.json")"
printf '%s\n' "$ISSUE_EVENT_ID"

git fetch buzz main
BASE_SHA="$(git rev-parse 'buzz/main^{commit}')"
HEAD_SHA="$(git rev-parse 'HEAD^{commit}')"
HEAD_BRANCH="buzz/$ISSUE_EVENT_ID"
SOURCE_REF="refs/heads/$HEAD_BRANCH"
CI_REF="refs/heads/buzz-ci/$HEAD_SHA"
test "$(git branch --show-current)" != main
test "$(git remote get-url buzz)" = "$BUZZ_CLONE_URL"
git push buzz "HEAD:$SOURCE_REF"
REMOTE_HEAD_SHA="$(git ls-remote buzz "$SOURCE_REF" | awk '{print $1}')"
test "$REMOTE_HEAD_SHA" = "$HEAD_SHA"

buzz pr open \
  --repo-owner "$REPO_OWNER" --repo-id "$REPO_ID" \
  --channel "$CHANNEL_ID" --issue "$ISSUE_EVENT_ID" \
  --external-id "$PR_EXTERNAL_ID" \
  --subject "Fix the specific failure" --body-file pr.md \
  --commit "$HEAD_SHA" --merge-base "$BASE_SHA" \
  --clone "$GH_CLONE_URL" --branch-name "$HEAD_BRANCH" \
  | tee "$state_dir/pr-open.json"
PR_EVENT_ID="$(jq -er '.event_id | select(test("^[0-9a-f]{64}$"))' \
  "$state_dir/pr-open.json")"
printf '%s\n' "$PR_EVENT_ID"

buzz repos stage-ci --id "$REPO_ID" --source-ref "$SOURCE_REF" \
  --commit "$HEAD_SHA" --expected-github-ci absent \
  | tee "$state_dir/repo-stage.json"

# github-pr.md contains an exact machine-readable marker block with
# ISSUE_EVENT_ID, PR_EVENT_ID, both external IDs, BASE_SHA, and HEAD_SHA.
gh pr create --repo "$GH_REPO" --base main \
  --head "buzz-ci/$HEAD_SHA" --title "Fix the specific failure" \
  --body-file github-pr.md | tee "$state_dir/github-pr-url"
GH_PR_URL="$(cat "$state_dir/github-pr-url")"
GH_PR_NUMBER="$(gh pr view "$GH_PR_URL" --json number --jq .number)"
printf '%s\n' "$GH_PR_URL" "$GH_PR_NUMBER"
```

Create the GitHub PR only after the Buzz PR ID is durable. Put the exact Buzz
issue ID, Buzz PR ID, external IDs, base SHA, and head SHA in a machine-readable
marker block in its body. Persist the returned GitHub PR number and URL; address
it by number or URL thereafter, never by title. Keep review discussion and
status decisions on the Buzz PR. GitHub supplies CI results only; do not merge
the GitHub PR or treat GitHub refs as an import source.

After every named GitHub check completes at exact `H`, promote that same commit
through Buzz main first and GitHub main second. Only the successful dual
readback authorizes marking the Buzz PR merged and its issue resolved.

Sign both Buzz status events as the corresponding root author or the repository
owner. Other signers may reach the relay, but trusted clients ignore their
status assertions.

```bash
set -euo pipefail

buzz repos status --id "$REPO_ID" | tee "$state_dir/repo-status-before.json"
buzz repos promote --id "$REPO_ID" --base "$BASE_SHA" --head "$HEAD_SHA" \
  --source-ref "$SOURCE_REF" --ci-ref "$CI_REF" \
  --required-check test --required-check lint \
  | tee "$state_dir/repo-promote.json"
jq -e --arg sha "$HEAD_SHA" \
  '.github_main == $sha and .buzz_main == $sha and .buzz_head == $sha' \
  "$state_dir/repo-promote.json"

buzz pr status --pr "$PR_EVENT_ID" --status merged \
  --repo-owner "$REPO_OWNER" --repo-id "$REPO_ID" \
  --merge-commit "$HEAD_SHA" \
  | tee "$state_dir/pr-merged.json"
PR_STATUS_EVENT_ID="$(jq -er '.event_id | select(test("^[0-9a-f]{64}$"))' \
  "$state_dir/pr-merged.json")"
printf '%s\n' "$PR_STATUS_EVENT_ID"

printf 'Resolved by exact tested Buzz commit %s\n' "$HEAD_SHA" \
  | buzz issues status --issue "$ISSUE_EVENT_ID" --status resolved \
      --repo-owner "$REPO_OWNER" --repo-id "$REPO_ID" --content - \
  | tee "$state_dir/issue-resolved.json"
ISSUE_STATUS_EVENT_ID="$(jq -er '.event_id | select(test("^[0-9a-f]{64}$"))' \
  "$state_dir/issue-resolved.json")"
printf '%s\n' "$ISSUE_STATUS_EVENT_ID"
```

Each relay write, Git push, GitHub PR write, promotion, and Buzz status write
is a separate transaction. Print and persist every returned event ID privately
before continuing. To resume, read the private checkpoint, fetch by exact event
ID, PR number, or SHA, and verify the stable external-ID marker and links. If a
retry finds a duplicate marker, missing link, or ID/SHA mismatch, stop without
writing and reconcile it; do not create a second record. There is no lifecycle
sync command and no cross-system rollback.

## Commands

| Group | Subcommand | Description |
|-------|-----------|-------------|
| `messages` | `send` | Send a message to a channel |
| | `send-diff` | Send a code diff with metadata |
| | `edit` | Edit a message you sent |
| | `delete` | Delete a message |
| | `get` | List messages in a channel |
| | `thread` | Get a message thread |
| | `search` | Full-text search, filterable by author |
| | `vote` | Vote on a forum post |
| `channels` | `list` | List channels |
| | `get` | Get channel details |
| | `create` | Create a channel |
| | `update` | Update channel name/description |
| | `topic` | Set channel topic |
| | `purpose` | Set channel purpose |
| | `join` | Join a channel |
| | `leave` | Leave a channel |
| | `archive` | Archive a channel |
| | `unarchive` | Unarchive a channel |
| | `delete` | Delete a channel |
| | `members` | List channel members |
| | `add-member` | Add a member |
| | `remove-member` | Remove a member |
| `canvas` | `get` | Get channel canvas |
| | `set` | Set channel canvas |
| `reactions` | `add` | React to a message |
| | `remove` | Remove a reaction |
| | `get` | List reactions |
| `dms` | `list` | List DM conversations |
| | `open` | Open a DM (1–8 pubkeys) |
| | `add-member` | Add member to DM group |
| `users` | `get` | Get user profile(s) |
| | `set-profile` | Update your profile |
| | `presence` | Get presence status |
| | `set-presence` | Set presence status |
| | `set-status` | Set or clear your NIP-38 profile status |
| `workflows` | `list` | List workflows |
| | `get` | Get workflow definition |
| | `create` | Create a workflow |
| | `update` | Update a workflow |
| | `delete` | Delete a workflow |
| | `trigger` | Trigger a workflow |
| | `runs` | Get workflow run history |
| | `approve` | Approve/deny a workflow step |
| `feed` | `get` | Get your activity feed |
| `social` | `publish` | Publish a NIP-01 note |
| | `set-contacts` | Set NIP-02 contact list |
| | `event` | Get a Nostr event |
| | `notes` | Get notes for a user |
| | `contacts` | Get NIP-02 contact list |
| `repos` | `create` | Announce a git repository (NIP-34) |
| | `get` | Get a repository announcement |
| | `list` | List repository announcements |
| | `protect list` | List branch and tag protection rules |
| | `protect set` | Create or replace a protection rule |
| | `protect remove` | Remove a protection rule |
| `issues` | `create` | Create a repository issue |
| | `get` | Get an issue by exact event ID |
| | `list` | List repository issues |
| | `status` | Publish issue status |
| `pr` | `open` | Open a repository pull request |
| | `update` | Publish a new PR tip |
| | `get` | Get a PR by exact event ID |
| | `list` | List repository PRs |
| | `status` | Publish PR status |
| `upload` | `file` | Upload a file to the Blossom store |
| `pack` | `validate` | Validate a persona pack (local, no relay) |
| | `inspect` | Inspect a persona pack (local, no relay) |
| `mem` | `ls` | List non-tombstoned memories |
| | `get` | Print memory value to stdout |
| | `hash` | Print SHA-256 hex of memory value |
| | `set` | Write a memory value (use `-` for stdin) |
| | `patch` | Apply unified diff to memory value |
| | `rm` | Publish a tombstone to delete memory |

## Architecture

```
buzz <group> <subcommand> [flags]
    │
    ├─ main.rs ──▶ commands/*.rs ──▶ client.rs ──▶ Buzz Relay REST API
    │  (clap)       (handlers)       (reqwest)
    │
    ├─ validate.rs   (UUID, hex, content size, percent-encode)
    └─ error.rs      (CliError → JSON stderr + exit code)

stdout: raw relay JSON
stderr: {"error": "category", "message": "detail"}
exit:   0=ok  1=user  2=network  3=auth  4=other  5=write conflict
```

# Desktop releases from the fork

`only21mil/buzz` publishes source refs to the Buzz relay first. GitHub mirrors
those refs and runs CI. The desktop auto-tagger skips this fork's
`version-bump/` merges, so it needs no upstream release-tagger GitHub App and
cannot create a GitHub-only desktop tag that the mirror would prune.

## Prepare the candidate

Use a fresh clone of the authoritative relay with `git clone --no-tags`, on a
non-default release preparation branch. Worktrees share tags with their parent
repository, so an upstream checkout's worktree can contain unrelated desktop
release history. The preparation script refuses a local desktop tag inventory
that differs from the selected remote. It never force-replaces release tags.

Fork candidates must use `Victor Vogel
<263261067+only21mil@users.noreply.github.com>` as their Git author and carry
his matching `Signed-off-by` trailer. Preparation checks the effective author
and committer before fetching or changing branches and uses that configured
identity without overriding it. Upstream candidates retain the Wes identity.

Activate Hermit and use the repository package manager. Set both the
authoritative remote and the GitHub CI repository explicitly:

```bash
export RELEASE_REMOTE=buzz
export RELEASE_REPOSITORY=only21mil/buzz
scripts/prepare-desktop-release.sh VERSION validate-only
```

The command creates and validates a local version-only preview. Replace
`VERSION` with the selected increasing semantic version. Inspect the generated
changelog. With publication approval, run in `publish` mode. That regenerates
the candidate from the current remote main and pushes it to the selected relay
remote before creating the GitHub PR. Review and qualify that exact published
head, which can differ from the preview. The mirror must expose that same
branch head before PR creation can succeed. Retain the published candidate,
frozen base and tag name in the delivery record.

## Verify and publish the immutable tag

Complete [the delivery lifecycle](delivery-lifecycle.md), including exact-head
CI, review, approval, relay-first landing and mirror readback. The release tag
points to the reviewed PR head, whose version-only commit is immutable. It does
not point to a later main commit.

In a separate clean verification checkout, set `RELEASE_REMOTE=buzz` and
`GITHUB_REPOSITORY=only21mil/buzz`. Supply `GH_TOKEN` through the approved secret
store without output. Read the merged PR from GitHub and bind `PR_NUMBER`,
`PR_HEAD_SHA`, `PR_HEAD_REF`, `PR_HEAD_REPO`, `PR_BASE_REF`, `MERGE_SHA`,
`MERGED_AT`, and the bare semantic `VERSION` to that exact response. Run:

```bash
scripts/verify-desktop-release-merge.sh
```

The verifier changes the checkout to the candidate. It loads candidate
validation and check filters from the candidate's protected base, checks the
merged PR identity, and requires every app-bound strict main check to have
passed by merge. Its policy inventory must still match at the final readback.
The immutable Desktop Release Candidate gate remains required from GitHub
Actions. Upstream-only DCO and Windows jobs are required only where the live
repository rules require them. The existing handling of skipped or neutral
required checks and the bounded DCO completion exception remain unchanged.

After this gate and explicit publication approval, create one annotated
`desktop-v<VERSION>` tag at `PR_HEAD_SHA`, push its exact ref to the relay, and
read back the tag object and peeled commit on both relay and GitHub. Refuse a
pre-existing tag unless both identities match. Never move or delete a release
tag to retry a build. Retain the gate output and both remote identities.

## Signing and update delivery

The existing `release.yml` and `signed-macos-canary.yml` remain upstream-only.
They depend on Block's Apple signing OIDC role. A fork tag alone does not build
or publish signed desktop packages. Do not remove those guards to imply that
Block's credential route is available to the fork.

A distributable fork release needs a verified Developer ID Application identity
with its private-key access and an approved Apple notarization route. It also
needs a retained Tauri updater signing key and its independently recorded public
key. Bind those routes to the reviewed candidate before adding a fork publisher
or invoking a local signer. Credentials belong in the approved store, not
repository files, command arguments, candidate archives or logs.

Generate the existing release config with `BUZZ_UPDATER_PUBLIC_KEY` set to that
approved public key and `BUZZ_UPDATER_ENDPOINT` set to
`https://github.com/only21mil/buzz/releases/download/buzz-desktop-latest/latest.json`.
The checked-in base config has no updater key and has an empty endpoint list;
it does not pin Block's updater. Upstream `release.yml` injects its own key and
endpoint only at release build time.

A complete release must bind the tag, source commit, artifact hashes, Apple
signature identity, notarization acceptance and updater signatures. Verify the
Mac app with `codesign --verify --deep --strict`, Gatekeeper assessment and the
maintained entitlement check. Build the updater archive from that final signed
app, then sign the archive. For Linux, sign the final AppImage after its runtime
repair step. A `.deb` is a manual-install artifact. Publish the matching assets
and updater manifest only after the artifact review and publication gates pass,
then verify their downloaded hashes, signatures and update behavior.

`linux-canary.yml` produces unsigned, canary-versioned packages without updater
artifacts. Installed private canaries with the base config need a deliberate
installation of a release-configured build before they can use the updater.
A private canary, an annotated source tag or an uploaded installer alone does
not complete this signed-release gate. Record missing signing credentials as a
release blocker and keep the rollout issue open until actual release proof
exists.

# Isolated clean-host activation acceptance

This harness runs candidate code only inside a disposable KVM guest. Privileged
containers are rejected: they are not a security boundary. QEMU runs beneath
Bubblewrap with a private mount namespace, no host home, no network namespace,
no NIC, no shared filesystem, no USB, and only `/dev/kvm`. The guest receives
immutable read-only ISO media and writes only its ephemeral qcow2 overlay plus
a fixed 8 MiB raw transfer device. Bubblewrap mounts the prepared state
read-only, then exposes only the current overlay, the candidate's transfer
device, and the verifier's pre-created evidence destination as writable files.
Only the trusted verifier boot receives the bounded virtio-serial evidence
channel. Every boot gives only the qcow2 operating-system disk a firmware boot
index. The raw transfer disk remains data-only even when QEMU enumerates it
before the operating-system disk.

The flow has two user-visible phases and three isolated boots:

1. `prepare` copies and hashes a pinned cloud image into a private state
   directory, boots a key-ceremony guest, generates four signing keys and a
   loopback-relay TLS identity, encrypts the runtime keys with guest-local
   `systemd-creds`, destroys every raw key, proves their absence, and exports
   only a challenge-bound public binding. The harness then flattens the
   ceremony overlay into a backing-free trusted image, validates its qcow2
   metadata, rehashes it, and deletes the source image and ceremony overlay.
2. External package freezers consume `public-binding.json`. They never receive
   the state directory or any credential bytes.
3. The candidate boot uses its own overlay over the frozen ceremony image. It
   snapshots the exact Git commit with `git archive`, copies and rehashes the
   five frozen packages and scenario into a private ISO. The guest rehashes
   every input, validates candidate/package/
   scenario/public-key cross-bindings, installs the packages, and runs real
   systemd principals through staged-zero, closed qualification, fixed
   capacity-one, the frozen fixture, all 13 acceptance stages, finalize/prove
   zero, strict installed verification, and rollback. It can write only a
   digest-framed pending record to the fixed-capacity raw transfer device.
   A second virtio-serial port carries only digest-framed progress records with
   a fixed boot, phase, event, sequence, and elapsed-millisecond schema. The
   stream contains no guest output and cannot make a failed run pass. After a
   zero QEMU exit, the host requires valid role-specific progress with exactly
   one final `complete` record and no timeout record. Missing, malformed, stale,
   oversized, truncated, or incomplete progress fails with sanitized phase
   detail before evidence parsing or the next boot.
   Candidate install progress advances only after these completed boundaries:
   `relay_ready`, `preinstall_units_clean`, `package_units_validated`,
   `principals_created`, `seccomp_ready`, `runner_installed`,
   `controld_installed`, `keyholder_installed`, `execd_installed`, and
   `installed_units_verified`. Controller phases follow in execution order.
   A failure may jump forward to `rollback` or `cleanup`. `cleanup_return`
   appears only after cleanup and its dormant-state check return without an
   error. On failure, the host reports the last completed operational phase
   before rollback/cleanup and records `cleanup_returned` as an authenticated
   boolean. An absent `cleanup_return` is reported as `false`; it remains a
   failure and does not expose guest exception text.
   During `controller_stage`, a separate nonblocking close-on-exec FIFO carries
   only the fixed `BSP\x02` header, a contiguous sequence of ordinal/complement
   pairs, and one final branch code/complement pair. A new stage authenticates
   ordinals 1 through 46 followed by code `0x80`; an idempotent unchanged stage
   authenticates ordinals 1 through 6 followed by code `0x81`, without claiming
   the skipped mutation operations. A failed or timed-out stage may authenticate
   only the last valid unterminated subphase; malformed, missing, early,
   duplicated, or trailing terminal bytes remain the generic `controller_stage`
   phase. A successful controller exit requires its exact 98-byte or 18-byte
   branch stream and matching canonical status output. These diagnostic records
   cannot satisfy terminal progress completion.
   The host kills and reaps the QEMU process group, proves it absent, and
   deletes the candidate overlay before continuing.
4. A fresh verifier overlay over the same frozen ceremony image receives the
   transfer device read-only, no candidate archive, and the only final evidence
   device in the flow. The host rehashes and validates the trusted ceremony
   image and every frozen harness asset after the candidate exits, before
   verifier staging, and again before verifier boot. A verifier frozen before
   candidate execution validates the receipt's closed schema and all strict
   acceptance checks. Guest code
   reconstructs canonical receipt and verdict objects from allowlisted fields
   and emits only those objects in a bounded digest-framed receipt. The host
   revalidates the frame and writes the receipt, verifier
   output, and exact input/evidence manifest. The VM overlay, encrypted test
   credentials, staging media, and QEMU process are then destroyed and their
   absence is checked.

The relay is guest-loopback only. It verifies the complete NIP-98 event ID,
BIP-340 signature, method, exact URL, payload digest, timestamp, and replay,
then applies the production relay's admission rules from `crates/buzz-relay`:
a published event's `pubkey` must equal the token pubkey and its `created_at`
must be within 900 seconds; an `h`-tagged event needs channel membership (the
channel is private); a kind-46107 grant needs the owner or admin role and adds
its signer for its repository and window; kinds 46101 to 46106 need a static or
granted CI signer equal to `relay_signer`; a kind-5 tombstone must target the
author's own stored event; the accepted read and evidence writes need a static
or granted CI signer for the request's repository. The guest rosters the
acceptance actor as channel admin, the ci-event key as member, and the nip98
key as the static signer (`guest_entry.relay_public_config`), the same three
facts production must hold for its channel.
The host records every staged ISO path with Rock Ridge owner and group `0:0`
while retaining each frozen file and directory mode. Package manifests,
payload bytes, and tree digests are unchanged, so the guest's strict root-owned
package validation applies directly to the read-only staging media.

## Commands

First bind an immutable, locally present qcow2 cloud image and the exact QEMU
tools. The image must boot systemd/cloud-init and contain Python 3, OpenSSL,
systemd credential/account/tmpfiles tools, CA trust tooling, `pgrep`, and
`swapoff`. Every guest phase disables swap and reads `/proc/swaps` back before
handling key or credential material; command capture files live on `/run`.

```bash
HARNESS=deploy/native-ci/activation/tests/clean_host_e2e/harness.py
STATE="$PWD/.clean-host-vm-state"

python3 "$HARNESS" capabilities

python3 "$HARNESS" prepare \
  --state "$STATE" \
  --image /protected/systemd-cloud.qcow2 \
  --image-sha256 FULL64 \
  --qemu-sha256 FULL64 \
  --qemu-img-sha256 FULL64 \
  --controld-uid 1201 --controld-gid 1201

# Freeze packages against $STATE/public-binding.json.
python3 "$HARNESS" preflight --contract /protected/e2e-contract.json
python3 "$HARNESS" run \
  --contract /protected/e2e-contract.json \
  --results /protected/e2e-results
```

The closed v3 contract includes `harness_sha256`, `timing_asset_sha256`,
`timing`, `timing_sha256`, and the exact `platform_systemd` binding copied from
the validated activation package. The maintained final renderer derives the
harness and timing values from the exact candidate Git object. For a manually
assembled contract, copy the harness and timing values from `capabilities` and
the platform value from the validated activation manifest. `prepare` records
the harness and timing values in `state.json`.
Preflight rejects a state prepared by any other `harness.py`, a contract with
another timing asset or timing table, or a candidate commit whose tracked
harness bytes do not match. Any harness change makes an unused older prepared
state stale by design.

Before it extracts candidate code or installs a package, the run guest opens
the bound Fedora global service drop-in without following symlinks and hashes
its exact bytes. A missing, relocated, replaced, or byte-drifted file stops the
clean-host run. This means a pinned cloud image that differs from the
production platform binding is a qualification blocker. The harness does not
ignore the mismatch or inject production's file into the image.

The exact `timing-contract.json` blob has a separate SHA-256 binding in the
prepare result, state, run contract, candidate stage descriptor, final evidence,
and terminal outcome. Preflight reads that path from the candidate Git object,
then requires both its byte digest and decoded closed object to equal the frozen
asset before any VM can start. The guest repeats the same check against the
candidate archive and its staged frozen timing asset.

The frozen `timing-contract.json` is the single timing source. It records leaf
command limits and an exact per-phase command inventory; the guest derives phase deadlines
and the host derives each QEMU watchdog from those terms. The 5,712-second
candidate watchdog covers a 220-second boot/cloud-init envelope, 1,452 seconds
for install, 100 for controller check, 680 for controller stage and its 13-unit
readback, 160 for activation, 1,870 for the canary's maximum 15 sequential
120-second driver operations, 100 for receipt verification, 100 for rollback,
990 for cleanup and dormant proof, 30 for guest poweroff, and 10 for host reap.
Ceremony is 1,130 seconds (including all 21 bounded ceremony commands) and the
verifier is 320 seconds. Every command count includes its 10-second process-
group reap allowance, and command-heavy phases add a 30-second local
orchestration margin. The run scenario's driver timeout must equal the frozen
120-second leaf; a different scenario cannot silently invalidate the budget.
Every guest command records its leaf category and reap term. A successful phase
transition requires the observed inventory to equal the frozen plan, so adding
a ceremony, install, controller-stage, or cleanup command without updating the
bound fails closed. The relay readiness probe is the sole exemption because its
repeated calls are bounded as one fixed window plus one probe-and-reap tail.
A terminal error names the boot and last
validated fixed-enum phase, for example `candidate canary watchdog timeout` or
`candidate cleanup watchdog timeout`. The diagnostic summary contains no guest
output, paths, credentials, or caller-provided fields, and the host emits it
only after terminal state cleanup.

The run contract also supplies the external `/usr/share/containers/seccomp.json`
source with the fixed SHA-256
`2598b3b98e6970f37f917e210202fa8976aefcd99abf8955803a6e35bba17eb4`.
The host copies those exact bytes into the immutable ISO; the guest rehashes
them before provisioning the clean host and the sealed execd installer checks
the resulting root-owned mode-`0644` source independently.

`capabilities` is read-only. `prepare`, `preflight`, and `run` fail before any
candidate execution when KVM, Bubblewrap, offline QEMU arguments, image/tool
digests, guest prerequisites, package bindings, or immutable staging differ.
`preflight` never consumes prepared state. A successful `prepare` also retains
that state for package freezing and preflight. At `run`, the harness validates
the contract envelope and the prepared-state marker, then atomically moves that
exact directory to a run-owned name. Cleanup holds directory descriptors,
moves a selected directory to an unpredictable private tombstone with an atomic
no-replace rename, and checks its device/inode identity immediately after the
move. Cleanup then truncates regular-file payloads and removes permissions
through held descriptors. It never calls path-based unlink or rmdir for a
selected object. Linux has no atomic identity-bound delete for these names, so
the harness retains at most one mode-`000` sanitized tombstone tree per selected
directory and one zero-byte mode-`000` tombstone per selected private record.
Retries do not create more tombstones. Every later validation and setup exit
has terminal cleanup ownership. A symbolic, unrecognized, replaced, or
filesystem-identity-mismatched path is never deleted; a replacement displaced
by the atomic quarantine move remains intact.
All subprocesses have fixed time and output bounds. Guest commands also use
the remaining bound for their current frozen phase. Every process group is
unconditionally killed, reaped, and checked for absence on success, failure,
timeout, and interruption. The private state is removed on every terminal
`run` path, including setup failure. Results are retained only after successful
state cleanup. The harness writes all three evidence files to one private
sibling directory, revalidates their receipt, verifier, manifest, and contract
bindings, including the exact host harness and timing table, and replays the
exact digest-bound frozen receipt verifier against
the scenario and receipt. The publication journal binds the staging
directory's device/inode identity. After sanitizing selected VM state, the
harness holds the result-staging directory descriptor through a quarantine
move, validation, and atomic no-replace rename to the requested results path,
with immediate destination identity readback. The public
path therefore exposes either the exact three-file set or nothing. A retry uses
the contract-bound ownership and publication records to remove an interrupted
partial set, finish a ready publication after cleanup, or return the already
published exact result. Cleanup or publication mismatch fails the run without
removing an unrelated path.

The authoritative base `d9360cc3203681797902cb0cf48bba6a152a0e82` does not
yet contain the sealed execd installer. A runnable final candidate must include
`deploy/native-ci/execd/install.py` with the agreed
`install --package PACKAGE` ABI and a matching frozen execd package.

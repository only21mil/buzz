# Isolated clean-host activation acceptance

This harness runs candidate code only inside a disposable KVM guest. Privileged
containers are rejected: they are not a security boundary. QEMU runs beneath
Bubblewrap with a private mount namespace, no host home, no network namespace,
no NIC, no shared filesystem, no USB, and only `/dev/kvm`. The guest receives
immutable read-only ISO media and writes only its ephemeral qcow2 overlay plus
a fixed 8 MiB raw transfer device. Only the trusted verifier boot receives the
bounded virtio-serial evidence channel.

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
   The host kills and reaps the QEMU process group, proves it absent, and
   deletes the candidate overlay before continuing.
4. A fresh verifier overlay over the same frozen ceremony image receives the
   transfer device read-only, no candidate archive, and the only final evidence
   device in the flow. A verifier frozen before candidate execution validates
   the receipt's closed schema and all strict acceptance checks. Guest code
   reconstructs canonical receipt and verdict objects from allowlisted fields
   and emits only those objects in a bounded digest-framed receipt. The host
   revalidates the frame and writes the receipt, verifier
   output, and exact input/evidence manifest. The VM overlay, encrypted test
   credentials, staging media, and QEMU process are then destroyed and their
   absence is checked.

The relay is guest-loopback only. It verifies the complete NIP-98 event ID,
BIP-340 signature, public key, method, exact URL, payload digest, and timestamp.
Published Nostr events receive the same event-ID and signature verification.

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

The run contract also supplies the external `/usr/share/containers/seccomp.json`
source with the fixed SHA-256
`2598b3b98e6970f37f917e210202fa8976aefcd99abf8955803a6e35bba17eb4`.
The host copies those exact bytes into the immutable ISO; the guest rehashes
them before provisioning the clean host and the sealed execd installer checks
the resulting root-owned mode-`0644` source independently.

`capabilities` is read-only. `prepare`, `preflight`, and `run` fail before any
candidate execution when KVM, Bubblewrap, offline QEMU arguments, image/tool
digests, guest prerequisites, package bindings, or immutable staging differ.
All subprocesses have fixed time and output bounds. Every process group is
unconditionally killed, reaped, and checked for absence on success, failure,
timeout, and interruption. The private state is removed on every terminal
`run` path.

The authoritative base `d9360cc3203681797902cb0cf48bba6a152a0e82` does not
yet contain the sealed execd installer. A runnable final candidate must include
`deploy/native-ci/execd/install.py` with the agreed
`install --package PACKAGE` ABI and a matching frozen execd package.

# Native macOS CI runner

The fixed broker runs the `desktop-build-macos-unsigned` qualification workload on Victor's
MBP. The Framework controller admits jobs and publishes signed Buzz terminal
events. The MBP holds no CI signing key and is reached through the existing
authenticated SSH operator connection. There is no GitHub runner or launchd
service to register.

## Trust and input

`broker.py run` consumes exactly one 992-byte broker v2 `RegisterJobIntent` frame on
stdin. It invokes `buzz-ci-admission-verifier` against a root-owned policy and
requires the embedded existing BIP-340 detached admission signature.
The registration frame digest and canonical JobIntentV2 digest are recomputed,
so the authenticated job preimage can change per run while the installed job
policy remains fixed. The verifier uses
the shared protocol decoder and canonical `admission_signature_message`; this
is the same admission signature as the Linux native plane. It rejects a wrong
key, actor, audience, base, workflow, job intent, isolation profile, lane, epoch,
key generation, deadline, or malformed frame.

The public policy contains `admission_pubkey`, `actor_pubkey`, `audience_digest`,
`lane_manifest_digest`, `lane_epoch`, `admission_key_generation`, `not_before`,
`expires_at`, `max_wall_timeout_seconds`, `workflow_digest`, `workflow_id`,
`job_id`, `artifacts`, `isolation_profile_digest`, `trusted_base_oid`,
`workflow_file_sha256`, `workflow_path`, and `driver_file_sha256`. Populate these
from the reviewed native job/lane authority, never from candidate input. The
Mac identity is workflow `native-macos`, job `desktop-build-macos-unsigned`,
path `.buzz/workflows/native-macos.yml`. The one declared `result.json` artifact
is the root-generated terminal build metadata receipt, maximum 32768 bytes.
The raw app is not exported by this qualification.

The trusted-base workflow and driver are both fetched and hash-checked before
candidate code runs. The installer also requires the policy's driver hash to
equal the installed driver bytes. Policy changes require a reviewed package
update; new signed run/attempt/source coordinates do not.

The source fetch uses the fixed public Buzz mirror and exact signed `tip_oid`.
The base workflow is fetched and hash-checked before any candidate program
runs. The fixed driver stays outside the checkout. Git fetch, checkout, package
scripts, and compilation all run as `buzzbuild` under Seatbelt, with an explicit
environment and no inherited credentials. Neither caller paths nor commands
exist in the admission frame.

## Existing host boundary

The candidate reuses the MBP's root-owned Apple supervisor at
`/usr/local/libexec/buzz-macos-build`. Its code and installation-manifest SHA-256 hashes are pinned in the broker
and installer. That manifest validates the existing helper files and
sandbox policy on every invocation. The old Apple files remain untouched.
The shared `supervisor.lock` serializes all use of UID/GID 590. The broker
refuses an occupied account, a nonempty registered HOME, or any prior admission
without a receipt proving cleanup. Under the lock it
uses the existing inode-attested HOME and Darwin scratch lifecycle, then kills
all source descendants before deleting owned job state. Failed cleanup cannot
produce success. A hard-killed broker leaves the next run closed for operator
recovery; it must never silently clear another lane's active work.

The sandbox permits public dependency downloads over HTTP/TLS and DNS. It
denies operator HOME reads and keychain access. No sleep settings, signing
credentials, existing apps, or persistent services are changed.

## Build and install after review

Build the portable verifier from the frozen candidate on the MBP with the
repository Hermit toolchain:

```sh
source bin/activate-hermit
cargo build --locked --release -p buzz-ci-admission-verifier
```

Prepare a package directory with `broker.py`, `payload.py`, `desktop-build.sh`,
the `buzz-ci-admission-verifier` binary, and the authority's public `policy.json`.
`installation.json` is an object with `schema_version: 1` and `files` mapping
those five exact basenames to their SHA-256 hashes. Freeze and review this
inventory along with the installer; use its independently retained SHA-256:

```sh
sudo -n /usr/bin/python3 -I /reviewed/source/install.py \
  --package /reviewed/package \
  --expected-inventory-sha256 REVIEWED_INVENTORY_SHA256
```

The installer refuses replacement of a prior installation, creates separate
root-owned installation/state directories, and starts no service. It reuses
the existing hidden no-login `buzzbuild` account without modifying it. The
operator invokes only this fixed command over SSH, supplying the v2 frame on
stdin:

```sh
sudo -n /usr/bin/python3 -I \
  /usr/local/libexec/buzz-native-macos-ci/broker.py run
```

`cancel` and `status` accept the same verified frame to identify a retained
attempt. They require the existing authenticated operator transport as well as
an exact match with the root-retained admission. They are local operation
selectors, not alternative v2 wire operations. Cancel creates a root-owned
marker checked every 250 ms. Every completed operation returns JSON; arbitrary
job output is bounded data in a separate root-owned `.log` file.

## Framework admission and publication adapter

`submit.py` is the on-demand Framework transport adapter. The trusted controller
first validates the public request and source pin, selects the root-owned
`desktop-build-macos-unsigned` job intent and lane, and obtains the existing
keyholder's detached v2 admission signature. It serializes the actual
`RegisterJobIntentRequest`, which embeds the signed admission, with
`v2::encode_request`, then pipes the frame into:

```sh
python3 submit.py --operation run \
  --verifier /trusted/buzz-ci-admission-verifier --policy /trusted/macos-policy.json
```

The adapter verifies the same signed frame locally, submits it over the fixed
SSH route, and rejects a returned receipt whose admission fields, job identity,
exit status, or cleanup assertion do not match. The controller then passes
verified terminal evidence to its existing reducer/keyholder publication path.
This candidate supplies the executable transport adapter; installing it does
not itself register the job with controld or claim that signed terminal
publication has been wired. The owning integration lane must register the
distinct job and exercise this path using a real native admission before
calling the runner live. It must not alias success to `desktop-build-macos`.

## Verification and limits

Run the verifier tests, Python broker tests, and shell syntax check before
review. After installation, prove an altered signature is refused, then run a
real signed exact-candidate admission. Retain the v2 admission, root terminal
receipt, log hash, source/base hashes, and cleanup evidence. Exercise a real
failing workload and cancellation while a workload runs. Confirm the shared
lock refuses overlap with an existing Apple build and the operator's private
files remain inaccessible to the build UID. Verify old installed helper hashes
again afterward.

The receipt carries the v2 canonical admission-message digest,
`signed_request_digest`, source pin, candidate/base, workflow/job/profile/lane
digests, run/attempt, terminal conclusion, exit code, and cleanup status. Only
the Framework authority can bind this receipt to and publish a Buzz terminal
event. A local successful receipt alone is not a signed required-check event.

The fixed driver compiles the desktop app with Metal and the same dependency
and sidecar preparation as the trusted macOS CI job. It creates an unsigned
`.app`, omitting DMG automation, updater packages, GitHub cache/artifact actions,
and GitHub qualification JSON. This is a native build mapping that must be
explicitly recorded in job authority. Keep the existing GitHub required check
until that mapping and terminal publication pass the broader parity gate.
Signing, notarization, TestFlight, and release issue 185 remain separate work.

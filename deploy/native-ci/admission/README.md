# Native runner admission operator

`native_admission_operator` prepares one v2 `RegisterJobIntent` frame for the
Linux or Mac native runner. The 992-byte frame embeds the signed v2
admission and the canonical job-intent preimage. The tool
uses the existing `prepare_signed_admission`, registration encoder and
`UnixKeyholderClient`. It creates no keys, publishes no events and starts no
runner. The installed keyholder at source `5bfe6d48` already supports this
`SignManifest(JobIntentV2)` operation.

The operator validates a genuinely signed kind 46100 request with
`buzz_core::ci::validate_signed_ci_event` before any socket connection. It also
verifies the signed kind 1618 source event, its exact independently reviewed ID,
repository, author, commit, branch and clone URL. This initial operator accepts
a fresh PR root and a Run attempt 1 only. Updated PRs and reruns are refused.
Create a fresh validation PR for each qualification. The reusable runner
policy does not pin a per-attempt job-intent digest.

Cryptographic validation is not relay acceptance. Before using this tool,
root must retain the canonical source event and the accepted request from the
relay, including authoritative preflight and event readback. Locally signing a
source event or asserting a JSON receipt does not establish canonical state.
The helper does not claim to prove relay storage, latest PR selection, protected
check parity or terminal publication.

## Trusted source registration

The Linux job is `dead-token-guard`, workflow ID `CI`, at
`.github/workflows/ci.yml`. The current trusted base
`aa81a7d266bc509ee8c9af450bc3a26f9da763e9` has workflow SHA256
`cf3bdf62e87ed4793073581bc13eb901603c37991fa23224217374fee2eafb80`.

The Mac job is `desktop-build-macos-unsigned`, workflow ID `native-macos`, at
`.buzz/workflows/native-macos.yml`. The explicit fixed selector extension and
this workflow definition must land on authoritative main before preflight can
select them. A fresh validation PR then supplies the genuine source event and
candidate. Recalculate both workflow/base bindings after this landing.
Never invent a source event for a merge commit that has no effective PR pin.

The relay preflight resolves an authorized effective PR at the exact candidate,
uses the published repository symbolic HEAD as trusted base, reads workflow
bytes from that base and derives the job list. It also requires all five
operator CI policy bounds: minimum and maximum timeout, maximum expiry,
acknowledgement timeout and maximum attempts. A client-supplied job list cannot
add a job missing from trusted-base workflow bytes.

## Public authority

The tool consumes a reviewed public `Authority` JSON document. The exact schema
is the `Authority` and `Lane` declarations in
`crates/buzz-ci-controld/examples/native_admission_operator.rs`; unknown fields
are refused. An independently retained SHA256 is mandatory for every command.
For signing, the file must also be root:root 0444 with one link, under a
canonical root-owned directory chain that nobody else can write.

Populate these fields from their independent authority:

| Field | Authority |
| --- | --- |
| `actor_pubkey` | Approved Sats Codex owner `73c705675d848ad38a919a5fa07687f55b4f0863c21969941c216b44f9e7a812` |
| `channel_id` | Buzz channel `46bba699-8251-43c7-943e-66be58376585` |
| `target_repo_a`, `source_clone_url`, `source_pin_event_id`, `candidate_oid` | Canonical PR event plus authoritative preflight/readback; pin exact values after the validation PR exists |
| `trusted_base_oid`, `workflow_digest` | Authoritative main and exact trusted-base workflow bytes, independently compared with preflight |
| `workflow_id`, `job_id` | One of the two fixed mappings above |
| `driver_file_sha256` | Mac requires SHA256 of the reviewed trusted-base `deploy/native-ci/macos/desktop-build.sh`, equal to the installed driver; Linux omits it |
| `audience_digest` | Existing reviewed deployment audience `5ee37a56e37eb01bc04be0dcc0deca7c89b2998c9688ef668609288ded369098` |
| `lane.lane_id` | SHA256 of UTF-8 `buzz-ci-native:framework-linux:dead-token-guard:v1` or `buzz-ci-native:mbp:desktop-build-macos-unsigned:v1`, no newline |
| `lane.lane_epoch` | New native lane epoch 1; increment on policy replacement |
| `lane.broker_build_identity` | SHA256 of a reviewed exact-file SHA256 inventory of the native broker/worker, fixed driver and verifier, excluding generated policy to avoid a cycle |
| `lane.host_profile_digest` | SHA256 of exact reviewed host public profile bytes with measured host, toolchain, UID and sandbox/runtime facts |
| `lane.suite_identity` | SHA256 of the exact trusted workflow bytes, equal to `workflow_digest` |
| `lane.isolation_profile_digest` | SHA256 of exact reviewed semantic runner profile bytes |
| `lane.not_before`, `lane.expires_at` | Actual reviewed activation time in Unix seconds and exactly 30 days later; do not start the window while source or CI is pending |
| `lane.max_wall_timeout_seconds` | Linux 300; Mac 2700 |

Linux semantic profile is supplied by the Linux package at
`deploy/native-ci/linux-runner/profile.semantic.json`. Its current hash is
`002b0dfc5001683362ce7da4c2248d25ead169dc11c125d2696662bd6c51ac61`.
Any profile change requires recalculation and review; this historical hash is
not an exemption. The Mac producer supplies its measured public host profile.
The helper uses the maintained `LaneActivationManifestV1::digest` method to
calculate the final lane digest. It never hashes caller assertions into proof
of live host measurements. The reviewer must compare these preimages to the
actual reviewed packages and independently retained host readback.

The keyholder client fields were read from the installed root-owned public
configuration. Use the fixed `/run/buzzci/keyholder.sock`, server UID/GID 1202,
timeout 5000 ms and one transport attempt. Public selectors at generation 1:

| Selector | Public key |
| --- | --- |
| `manifest` | `c69b62382140b5724a83eb9b09bd3947933c4ae670b5d34ad0064cd26df5a305` |
| `ci_event` | `56eb458760971c6c789fe91374d116f817a81fb3ad5fd22c34dee98bd9222da9` |
| `nip98` | `b3d0147fe649f5277ced0c32e77e277bca0d5fcfcb694e741008cdc987f6933e` |

The caller runs as the already-authorized controld UID/GID 1201. Neither
keyholder configuration, peer authorization nor credentials change. Confirm
these public fields still match before live signing. The existing keyholder
allows this authorized peer to sign structurally valid v2 admissions; the
operator's reviewed input checks therefore matter. The fixture controller is
not a source of authority for these new jobs.

The artifact declaration is exactly `result`, `result.json`,
`application/json`, `result.json`, maximum 32768 bytes. It describes native
terminal metadata. It does not claim to export a raw Mac `.app`.

## Reviewable installation and signing operation

Build only from the reviewed frozen integration source with its Hermit tools:

```sh
. ./bin/activate-hermit
cargo build --locked --release -p buzz-ci-controld --example native_admission_operator
```

Retain the executable SHA256 and review it with the public authority preimages,
runner package inventories and this operation. After root's review, install
the binary root:root 0755 at `/usr/local/libexec/buzz-ci-native-admission`.
Install each reviewed public authority root:root 0444 in a fresh directory
under `/var/lib/buzzci/native-admission/`. Stage the public signed request and
source event root:root 0444 beside the authority. Use root:root 0755 directories
so UID/GID 1201 can traverse and read these public inputs. All directory
ancestors must be root-owned and deny group/other writes. Never pass the
private Victor mode-0700 evidence directory directly to that UID. Reusing the keyholder's existing peer
UID/GID needs no service restart, credential export or policy expansion.

Before generating runner installation packages, derive each reusable public
policy from the same authority bytes:

```sh
/usr/local/libexec/buzz-ci-native-admission policy \
  /var/lib/buzzci/native-admission/ATTEMPT/authority.json REVIEWED_AUTHORITY_SHA256
```

Save stdout as `policy.json` in the corresponding runner package and review its
inventory. Do not install an old static per-attempt `job_intent_digest` policy.
Issue the owner-signed request at or after the lane activation time, within
the unchanged live relay request bounds. After acceptance and exact readback,
validate before signing:

```sh
/usr/local/libexec/buzz-ci-native-admission check \
  /var/lib/buzzci/native-admission/ATTEMPT/authority.json REVIEWED_AUTHORITY_SHA256 \
  /var/lib/buzzci/native-admission/ATTEMPT/request.event.json \
  /var/lib/buzzci/native-admission/ATTEMPT/source.event.json
```

After signing approval, invoke exactly once under the existing peer identity:

```sh
sudo -n -u '#1201' -g '#1201' /usr/local/libexec/buzz-ci-native-admission sign \
  /var/lib/buzzci/native-admission/ATTEMPT/authority.json REVIEWED_AUTHORITY_SHA256 \
  /var/lib/buzzci/native-admission/ATTEMPT/request.event.json \
  /var/lib/buzzci/native-admission/ATTEMPT/source.event.json
```

Capture stdout to a fresh mode-0600 file using the operation owner's create-only
publisher. A successful exit plus exactly 992 bytes is necessary, but verify
that frame through the installed portable verifier before runner submission.
Do not retry by changing any bound request field. The runner reuses the same
signed frame for replay/readback. Retain the actual manifest signature and
canonical request/source events as public evidence. No test-key frame counts
as a live qualification.

Lane expiry closes new admission. Renew only through reviewed policy replacement;
source or profile changes require recalculation and review. Do not widen relay
expiry/timeout policy just to make a qualification pass.

The first live attempt remains held until the real validation PR, request,
final integrated workflow/base, measured profiles, package inventories and
root review are complete. This source package contains no fabricated live
policy, source pin, signature or successful execution receipt.

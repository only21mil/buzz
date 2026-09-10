# Native Linux shell runner

This package executes the supported shell workload from the trusted-base Buzz
workflow against the exact accepted candidate. It is an operator-submitted
native runner. The currently installed `controld` fixture path does not dispatch
to it, and its local receipt alone is not a signed Buzz CI completion.

## Admission and source authority

`worker.py run` consumes exactly one existing 992-byte v2 `RegisterJobIntent`
frame on stdin. That frame contains the signed admission. The root-installed
`buzz-ci-admission-verifier` validates its canonical request digest, derives the
job-intent digest, verifies the existing BIP-340 admission signature and enforces
the installed actor, audience, lane, epoch, key generation, workflow/job,
trusted-base and isolation profile. No test key or unsigned JSON may authorize a
production execution.

The worker reads the verifier output, matches the selected job, signed isolation
profile and sole `result.json` artifact declaration to its installed profile,
then claims a persistent `(run_id, job_id, attempt)` directory under a global
capacity-one lock. Replaying a logical attempt refuses execution even if its
signing window or admission signature changes. Before claiming any new run or
attempt, the root supervisor checks every retained root claim while holding its
own capacity lock. Missing, malformed, mismatched or unclean
`supervisor.json` evidence quarantines the entire slot, including after a
supervisor crash. Only a complete root receipt with independently measured
container absence, recursive cgroup emptiness and unit inactivity permits a
new attempt. A worker receipt cannot release quarantine. Recovery requires
root investigation and retained evidence; deleting a claim is not recovery.

The fixed GitHub URL supplies content-addressed objects only. Its branch heads
and refs confer no authority. The signed candidate/base and canonical source-pin
verification by the admission producer are required first. Fetch uses no
credentials, user config, hooks, redirects, tags, submodules or checkout filters.
Raw tree entries and blobs are read directly; every blob object hash is verified.
Gitlinks, unsafe paths, escaping symlinks, symlink ancestors and resource overruns
are rejected. In-tree symlinks are necessary for Buzz's Hermit package files.
Workflow bytes come from the signed trusted base and must match the installed
SHA-256 digest, independently of the candidate's workflow file.

## Supported workload and evidence mapping

The first profile selects `.github/workflows/ci.yml:dead-token-guard`. The
compiler executes the actual literal shell workload from step 1. The fixed
checkout action in step 0 maps to verified source materialization. Only the exact
final `protected-ci-landing.py capture` command and pinned qualification-upload
action map to native provenance and evidence retention. The native receipt
records executed step indices `[1]`, native step indices `[0,2,3]`, workflow and
script digests, source commit/tree, output hashes and terminal outcome. A changed
qualification command or action is not silently omitted.

The exact existing workflow-wide environment maps to native values. Cargo color
and the public test password remain literal. `github.workspace` is `/workspace`;
`BUZZ_CI_REUSE_EPOCH` is empty because this profile performs fresh execution and
never reuses GitHub qualification. Other workflow environments, defaults, job
conditions, dependencies, services, matrix expansion, dynamic expressions,
other actions, non-Bash shells and failure-masking step controls are refused.
This package does not implement an Actions interpreter or claim full CI parity.

Podman uses a digest-pinned Ubuntu 24.04 amd64 image, `--pull=never`, private
namespaces, a fresh subordinate-ID user namespace, container user 1000, no
capabilities, no new privileges and no network. Source and script mounts are
read-only. A private tmpfs workspace receives a copy; no runtime socket, host
home, credentials or mutable host workspace reaches the container. The signed
semantic profile caps memory at 2 GiB, swap at zero, CPU at two cores, processes
at 256 and execution at 300 seconds. The supervising host unit must bound the
materializer/runtime as well and reserve resources for the relay.

Stdout and stderr are drained with separate 32 KiB retained limits. The worker
waits for the actual Podman process and then removes the exact invocation
container. Only `podman container exists` exit 1 proves absence; daemon errors
and timeouts do not. Cancellation and deadline expiry stop the client before
removal. Success requires exit zero and proven container/source cleanup.
`stdout.log` and `stderr.log` retain exact bounded bytes; the sole declared
`result.json` artifact is a bounded metadata receipt with hashes, counts and
truncation flags. Root must independently read the finished systemd unit and its
empty recursive cgroup before translating the receipt into trusted native events.

## Reviewed installation inputs

Install root-owned, non-group/world-writable files:

- `/usr/libexec/buzzci/linux-runner/submit.py`
- `/usr/libexec/buzzci/linux-runner/worker.py`
- `/usr/libexec/buzzci/linux-runner/workflow_source.py`
- `/usr/libexec/buzzci/linux-runner/container_runtime.py`
- `/usr/libexec/buzz-ci-admission-verifier`, shared portable verifier from the Mac lane
- `/etc/buzzci/linux-runner/admission.json`, the reviewed reusable public signing policy
- `/etc/buzzci/linux-runner/profile.semantic.json`, exact bytes from this package
- `/etc/buzzci/linux-runner/profile.json`, deployment binding described below

Python 3, system PyYAML, Git and rootless Podman with private SELinux bind
relabeling support are required. Both read-only mounts use `relabel=private`
on the fresh `source` tree and `workflow.sh` inside the runtime-owned private
job directory. Shared checkouts and external script paths are refused before
Podman starts; SELinux labeling remains enabled. The host preflight reported
SELinux enforcing on 2026-09-10. Label application and container access still
require the authorized live acceptance run. The dedicated locked-login
`buzzci-linux` account must have its
own home/container storage at `/var/lib/buzzci/linux-runner/home`, a non-overlapping subordinate UID/GID range, a
private `/run/user/UID`, and delegated cgroup v2 controllers. The account must
not read other principals' homes or signing state. Preload the exact pinned
image into this account's storage during the reviewed installation. Neither
worker execution nor qualification pulls an image or installs dependencies.

`profile.json` has exactly these fields:

```json
{
  "schema_version": 1,
  "runtime_uid": 1234,
  "verifier_sha256": "<SHA-256 of installed verifier>",
  "admission_policy_sha256": "<SHA-256 of exact admission.json bytes>",
  "semantic_profile_sha256": "380c42ed223751205db5bd8c68b8924d4d7067aca0788db94a55383a0508c698",
  "workflow_path": ".github/workflows/ci.yml",
  "workflow_id": "CI",
  "job_id": "dead-token-guard",
  "image": "docker.io/library/ubuntu@sha256:a61567bd31828687156d735ea8eb01ba4e37636e225dd6a48ba94136a70d9d61",
  "memory_mib": 2048,
  "cpus": 2,
  "pids_limit": 256,
  "maximum_wall_seconds": 300
}
```

`runtime_uid` above is illustrative, not an allocated host UID. Authority paths
and ancestors must be root-owned without write access for other users. Public
policy files can be mode 0644. Create `/var/lib/buzzci/linux-runner/jobs` as the
runtime account, mode 0700. Create `/var/lib/buzzci/linux-runner/supervisor` as
root, mode 0700. Keep the existing fixture services and their
hardening untouched.

The operator submits the genuine signed registration to the installed
`submit.py run` as root. The supervisor launches `/usr/bin/python3` with the installed
worker path and `run`, under the dedicated account in a capacity-one transient
systemd unit, and pipes the binary frame through stdin. Recommended outer
bounds for this profile are `MemoryMax=3G`, `MemorySwapMax=0`, `CPUQuota=200%`,
`TasksMax=512`, a bounded wall deadline and `KillMode=control-group`, with the
Podman-required user namespace and cgroup delegation. The supervisor must
capture the actual unit invocation identity, exit status and final recursive
cgroup emptiness. A surviving runtime process or container quarantines the slot.
No persistent self-hosted GitHub runner or root Docker socket is involved.

The genuine admission producer and native signed publication remain integration dependencies.
`submit.py` supplies the root supervisor and retains a create-once supervisor receipt.
The existing fixture-only keyholder/controld policy cannot be relabelled as this
profile. Install a reviewed genuine signing policy and retain the request,
source-pin, registration/admission bytes and native evidence before publishing
any native completion. Keep GitHub required CI until native completion and
required-check semantic equivalence are independently established.

Rollback stops and proves the new unit/cgroup empty, removes only its exact
container if present, restores the previous public policy/package files and
leaves all unrelated fixture services and relay state unchanged. Never delete a
pending attempt claim as a retry mechanism; retain its evidence for recovery.

## Checks and live acceptance

```sh
python3 -m unittest discover -s deploy/native-ci/linux-runner/tests -v
python3 -m unittest discover -s deploy/native-ci/tests -p test_linux_container_runtime.py -v
```

The tests run the actual guard command on clean and deliberate-failure input,
exercise source/workflow refusal paths, and check mocked Podman success,
failure, cancellation, timeout, bounded output and cleanup failures. Supervisor
regressions cover a process exiting without cleanup, successor
run and attempt refusal, invalid prior evidence and clean completion followed
by replay refusal. They do not prove that Podman, subordinate mappings, cgroups or SELinux work on a host.
Before claiming live readiness, run a genuine signed supported job, deliberate
failure, cancel, timeout, replay and cleanup qualification through the installed
supervisor, then verify the native signed completion against the exact receipt.


The root supervisor uses `RemainAfterExit=yes` to retain the exact unit identity
and actual main exit status until readback. It opens the cgroup directory while
the unit is owned, proves its recursive `populated` counter is zero, then stops
the unit and proves it inactive. Partial start failure still triggers exact-unit
cleanup and container-absence readback. Refusal paths also attempt recursive
cgroup readback, but never publish a successful supervisor receipt. Unavailable
readback retains quarantine even if stopping the unit succeeds. An existing
invocation unit is never reused or removed. The supervisor itself does not
publish events or sign anything.

Outer `NoNewPrivileges=yes` would prevent the installed `newuidmap` and
`newgidmap` helpers from creating the subordinate-ID mapping. The host helper
unit therefore permits that standard rootless-Podman transition; the container
itself always enforces no-new-privileges. No setuid helper is added by this
package. Filesystem-limit coverage is a per-file 2 GiB outer limit plus explicit
materialized-tree limits; it is not a quota-backed total download-volume proof.

The pinned official Ubuntu image has not been run during source preparation.
The reviewed host operation must first verify `/bin/bash`, `cp`, `grep` and the
shell builtins required by the actual workload. Python and `rg` are not needed
inside this profile because qualification bookkeeping becomes native evidence.

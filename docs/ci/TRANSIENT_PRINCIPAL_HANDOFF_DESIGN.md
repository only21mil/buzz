# Transient principal process handoff

Status: implementation design for the materializer principal

## Decision

Use a long-lived, broker-started exec shim inside each principal service. The
broker sends typed phase commands over a private Unix socket and transfers any
required open descriptors with the request. This is option (b), socket handoff
into a small shim whose unit is created before repository-derived code can run.

The first implementation covers the materializer. Its transient service starts
only the fixed `/usr/libexec/buzz-ci-execd --materializer-handoff` entry point.
The service retains the existing unit name, UID, lease slice, DNS bind mounts,
and materializer network policy. Its private runtime directory holds the
handoff socket. Executor and runtime handoff remain separate follow-up work.

For each Git phase, the broker validates the materializer `CommandSpec` against
the unit and the retained lease before sending it. The exact
`required_uid`, `lease_id`, `cgroup_token`, and `netns_token` must match the
root-owned handoff binding. The executable remains the fixed `/usr/bin/git`,
the environment starts empty, and the argument vector is never interpreted by
a shell. The workspace directory is identified by the already-open descriptor
in `MaterializationSlot`. The socket transport passes that descriptor with
`SCM_RIGHTS`; the shim verifies its device, inode, type, and owner before
reconstructing the local `/proc/self/fd/<n>` description.

This split matches `AttemptLeaseBinding::validate_phase1()`. The binding already
proves that the materializer UID owns the workspace and that the cgroup and
network namespace tokens are distinct broker capabilities. Handoff validation
keeps those values together at the last boundary before exec.

`DnsLeaseLifecycle` remains the owner of the unit, namespace, nft state, DNS
receipt, and cleanup token. It creates and reads back the confined shim before
returning a released lease. Reconciliation stops the lease slice, so it also
kills the shim and every command descendant before capacity can return.

## Alternatives

### Real phase argv in `systemd-run`

Passing Git directly to `systemd-run` is attractive because systemd applies
the unit properties before `execve`. It does not, however, carry the broker's
workspace directory descriptor into a service. `CommandSpec.current_dir` is a
description of that open capability, not a pathname that the system manager may
resolve again. `--working-directory` or `--same-dir` would turn a descriptor
binding into a path lookup and reopen the rename/symlink race that the
materializer contract rejects. Recreating the same transient unit for every Git
operation also complicates exact cgroup readback and crash recovery.

### Dormant unit plus scope attachment

Attaching a process later with `systemd-run --scope` does not provide the same
execution context as a service. In particular, the service manager does not
apply the service's `User`, bind mounts, network namespace, or future seccomp
settings to a process before it starts. Any stop-and-move scheme leaves a race
in which repository-derived code exists outside the final confinement. That
conflicts with the threat model and is rejected.

## Security and lifecycle rules

- The unit executable and mode are fixed by execd. Requests cannot select a
  program, unit, socket, UID, cgroup, or namespace.
- The private runtime directory is mode `0700`. The socket is mode `0600`; the
  shim requires the exact root broker UID and the broker requires the exact
  materializer service UID through `SO_PEERCRED`.
- Requests use a versioned, typed, length-bounded frame and exactly one
  close-on-exec `SCM_RIGHTS` descriptor. Malformed, oversized, partial,
  disconnected, or timed-out requests are refused before exec.
- The first valid request locks the shim to one UID/lease/cgroup/netns
  capability tuple. Later requests must match it exactly.
- The shim must clear its inherited environment and apply only the
  broker-derived environment in `CommandSpec`.
- A command must not start after lease expiry. Timeout, disconnect, malformed
  input, capability mismatch, output overflow, or failed descendant readback
  fails the command and leaves cleanup evidence non-green.
- The materializer unit is active before it accepts a command, so its UID,
  slice, DNS mounts, and network policy precede every Git exec. Later executor
  and runtime shims must preserve the same ordering.

This candidate adds the fixed unit, command-plan boundary, bounded transport,
descriptor receipt, and persistent materializer service loop. Production
composition remains closed; the later normal execution backend only needs to
join this handoff result with its root-owned nft/cgroup observations.

## Normal execution successor closure

The normal backend does not recreate the DNS-owned executor unit. Its current
direct `systemd-run --unit=<executor>` implementation now returns
`ExecutorUnitHandoffRequired` from preflight and repeats that guard in `spawn`.
This closes the collision before the DNS lifecycle creates a slice, service,
namespace, socket, or proxy listener. A later executor shim must accept the
pinned Act launch through an authenticated descriptor and command handoff inside
the already read-back executor service.

The runtime service remains a dormant DNS-owned placeholder too. An
`ActRuntimeDescriptorSource` must now prove readiness for the exact launch plan
and validated attempt binding before proxy inputs are opened, then return a
fresh one-shot Podman descriptor for each exchange. The proxy path retains its
4,096-exchange ceiling, fixed transport caps, signed expected-exec population,
and C2 ledger ownership.

Every injected source now participates in ordinary preflight before host
mutation. The exact remaining construction seams are
`NormalMaterializationSource`, `BrokerProxyInputSource`,
`ActRuntimeDescriptorSource`, `NormalTerminalCollector`, and
`NormalTeardownCollector` in `crates/buzz-ci-execd/src/normal_backend.rs`.
The first two already had exact-plan preflights; the runtime, terminal, and
teardown sources now have the same fail-closed requirement. No canonical
provider exists for these seams, and `ProductionAdapters::canonical()` in
`crates/buzz-ci-execd/src/production_composition.rs` continues to return
`HostBackendsMissing`.

The B4 revision-2 response deadline and typed command-planning behavior remain
in `crates/buzz-ci-execd/src/materializer_handoff.rs` and `dns_exec.rs`. The B5
qualification backend is still a separate dependency in
`crates/buzz-ci-execd/src/normal_qualification.rs`; this successor does not copy
that candidate or invent its `NormalQualificationPrimitiveSet` bridge. Final
all-or-closed composition must add that bridge with the five host providers
above before canonical discovery can change.

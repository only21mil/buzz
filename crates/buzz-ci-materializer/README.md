# buzz-ci-materializer

This crate is the unprivileged, credential-free source-materialization core for
Buzz CI. It resolves only broker-allowlisted repository coordinates, constructs
hardened raw-object Git operations, verifies exact commit/tree/workflow/input
digests, rejects symlinks, gitlinks, LFS pointers, non-UTF-8 paths, traversal,
case collisions, and resource overruns, then atomically publishes a read-only
tree for broker sealing.

The only public slot constructor consumes a validated
`buzz-ci-isolation-contract` lease and checks the broker-created workspace's
already-open directory plus owner/device/inode identity. All local paths and
Git cwd state remain rooted at that descriptor; the backend receives the same
File capability explicitly. The materializer rechecks identity, mode,
emptiness, and live lease expiry before executing. It refuses any mismatch in
the accepted request event, repository coordinate, run, source tip, trusted
base, workflow ID/digest, job, attempt, or lease ID. The receipt carries the
same provenance so it cannot be joined to another request or lease.

Publication opens the renamed tree immediately, rehashes the exact pinned
directory, rejects extra files/directories, and returns that File and identity
inside `PendingSeal`. No receipt is returned after expiry, and post-rename
failures remove the published tree.

It is not a sandbox and does not authorize a run. The root-owned broker remains
responsible for the materializer UID, process-group/cgroup deadline, narrow
egress namespace, quota-backed slot, signature/role/expiry checks, and sealing
the verified output under an identity the materializer cannot modify.
The production materializer process/watchdog and real Git backend remain
required before this library can satisfy the frozen hard wall-clock gate.

Phase 1 is an accepted-commit verifier only. This crate does not make current
hosts safe for unaccepted PR code.

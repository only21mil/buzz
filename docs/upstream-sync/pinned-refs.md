# Pinned refs

Four SHAs anchor every later claim. Short forms are nicknames. Full forms are
the actual pins. Anything that cites a pin must use the full SHA.

## The pins

- Fork HEAD: 1e05fce27c658bf09a2c45fbebd1d8388d33bb15. The audited source.
  This worktree sits exactly here.
- Adoption snapshot: 3c7f288c60d67df78577b237e27c3dfc8831aaa1. The upstream
  point the September 6-7 adoption worked from. It is a planning input, not an
  ancestor of main, and must read as one until reconciliation lands.
- Upstream target: 4cd82f513214aad11c2b742ce7cc7c681e8e32a0. The audited
  upstream tip. Refresh and re-pin one target at implementation time if
  upstream moved.
- Common ancestor: 5bf78671f45178f8de02ba18d3d321cbbf19cd1f, dated 2026-08-08.
  A true integration followed around August 9. No upstream commit after this
  base is an ancestor of the fork.

## Local resolution, 2026-09-13

Checked in this checkout before writing:

- 1e05fce2 resolves, commit, and equals local main and origin/main.
- 5bf78671 resolves, commit (`fix(agent): retry LLM completion on malformed
  2xx JSON body (#5351)`).
- 3c7f288c does not resolve locally. Expected: the snapshot lives in
  upstream history the local clone never fetched.
- 4cd82f51 does not resolve locally. Same reason.
- The local clone has one remote, origin, pointing at only21mil/buzz.
  Upstream block/buzz is not configured as a remote here.

Nobody should treat the two unresolved pins as missing or wrong. They are
upstream objects. Fetch them without tags when reconciliation starts, on the
canonical relay side, never by mirroring upstream tags into canonical
authority.

## Verification commands

Read-only. Run them again at P08 kickoff and paste the output into the
integration record.

```bash
git merge-base 1e05fce2 4cd82f51
git rev-list --count 5bf78671..4cd82f51
git rev-list --count 3c7f288c..4cd82f51
git merge-base --is-ancestor 3c7f288c 1e05fce2; echo $?
```

Expected today: the first three print ancestry data once upstream is fetched,
and the last returns nonzero. After an accepted reconciliation, the recorded
sync SHA must be an ancestor of canonical main, and that check must pass.

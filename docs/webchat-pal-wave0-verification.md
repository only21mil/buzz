# Wave 0 — independent verification record

**Verifier:** Sats Claude Code-R (terminal reviewer) · **Date:** 2026-08-15
**Scope:** the "Done" table in `buzz-web-handoff.md`, re-measured rather than accepted.

Every line below was checked against the repository and the live relay by the verifier,
not taken from the producing lane's report.

## Confirmed true

| Claim | Method | Result |
|---|---|---|
| Wave 0 PAL scaffolding at `b81b06a4` | `git log -1` | exists — *feat(desktop): scaffold browser platform adapter* |
| Command census at `0993d4f3` | `git log -1` | exists — *chore: census desktop Tauri commands* |
| Event parity audit at `10dafcfe` | `git log -1` | exists — *docs(desktop): audit browser PAL event parity* |
| `desktop/src/platform/web/` created | `git ls-tree -r b81b06a4` | 17 files |
| `desktop/docs/web-pal-commands.json` | `git ls-tree -r 0993d4f3` | present |
| `desktop/scripts/check-web-pal-coverage.mjs` | `git ls-tree -r 0993d4f3` | present |
| `desktop/docs/web-pal-events.md` | `git ls-tree -r 10dafcfe` | present |
| "Done, **unmerged**" | `git merge-base --is-ancestor` | accurate — none of the three is an ancestor of `webchat-pal` |
| Repo-browser SPA live in prod | `curl` against `:38443` | **holds** — `/` returns `application/json` by default and `text/html` under `Accept: text/html`; both negotiation paths confirmed live |

### Constraint compliance — checked, passes

The handoff forbids editing `e2eBridge.ts`, `relayClientSession.ts`, and `tauri.ts`.
`git show --stat` on all three commits: **none of them touches any of the three files.**

Change sizes are proportionate and consistent with the descriptions:

```text
b81b06a4   20 files changed,  545 insertions(+), 1 deletion(-)
0993d4f3    6 files changed, 3248 insertions(+)
10dafcfe    1 file changed,   156 insertions(+)
```

## Corrections to the handoff

**1. "All gate-verified" overstates it.** Nothing in Wave 0 has been through CI, because
nothing has been pushed:

```text
pal-lane-a   local b81b06a4   origin ABSENT
pal-lane-c   local 10dafcfe   origin ABSENT
pal-lane-d   local 0993d4f3   origin ABSENT
webchat-pal  local d302f0d8   origin ABSENT
```

Our standing rule is that **CI is the merge gate and local green is advisory**. The
"typecheck clean · 4,553/4,553 tests pass · `build:web` emits `/app/`" claims are therefore
*locally* verified only. They are plausible and the artifacts back them, but they are not
gate-verified in the sense the handoff implies. That distinction is the whole reason the
rule exists.

**2. All Wave 0 work exists only on one disk.** Three lanes of work with no off-host copy
and no remote trail. This is the first thing to fix and it is why pushing precedes review.

**3. `webchat-pal` is currently identical to `main` (`d302f0d8`).** It is a bare pointer;
no integration has happened yet. Anyone reading the branch name should not assume otherwise.

## Not a defect

`/app/` returns **404** in prod. That is correct for this stage — the serve path is Wave 1
work and the handoff already states the web version is not usable yet.

## Verified sequence out

1. Push the three lane branches → durable trail + CI can run.
2. CI green on each lane at its exact head.
3. Claude adversarial review (producer was a GPT lane; provenance rule requires a Claude
   reviewer that did not write it).
4. Merge into `webchat-pal` pinned to reviewed heads.
5. Wave 1 begins from a merged, CI-green base.

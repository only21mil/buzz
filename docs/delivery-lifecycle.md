## Delivery lifecycle
1. File the Buzz issue(s) before work starts. Use one issue, or a few tightly related issues, per branch.
2. Work on an isolated branch/worktree. Commits are inert snapshots; they do not merge, deploy, or activate anything.
3. Open the PR when the work is ready for its gates.
4. Run gates on that PR: delta CI for corrections, then the full exact-head matrix once at the landing head, plus Tier 2 at that same frozen SHA. LOW-only is PASS WITH RISKS; FAIL starts at MEDIUM.
5. Merge only the SHA that passed. Any new commit invalidates the gates and reruns them.
6. Deploy or activate in a separate gated step. Merge alone changes no live system.
7. Close the issues and PR with receipts: merge SHA, CI result, review verdict, and deployed SHA.

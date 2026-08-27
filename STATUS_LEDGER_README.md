# Buzz CI status ledger candidate

This isolated candidate replaces the stale hand-maintained task board with one validated YAML ledger and a generated frozen board.

Run the focused gate:

```sh
python3 -m unittest discover -s tests -v
python3 tools/status_ledger.py check
```

Regenerate the board after an authorized ledger edit:

```sh
python3 tools/status_ledger.py render
python3 tools/status_ledger.py check
```

The checker fails closed on malformed SHAs, missing landing ancestry, incomplete review closure, unbound deployment receipts, active routing under the owner stop, unresolved contradictions represented as facts, and unqualified legacy lane labels.

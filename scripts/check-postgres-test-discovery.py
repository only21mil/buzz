#!/usr/bin/env python3
"""Require explicit classification for every ignored Rust test in crates/."""
from collections import Counter
from postgres_test_inventory import validate

if __name__ == '__main__':
    try:
        rows = validate()
        print(f'Ignored source inventory: {dict(Counter(r["mode"] for r in rows))}')
        for row in rows:
            print('\t'.join(row.values()))
    except ValueError as error:
        raise SystemExit(str(error)) from error

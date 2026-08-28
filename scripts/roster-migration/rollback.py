#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

from migration import MigrationError, restore


def main() -> int:
    parser = argparse.ArgumentParser(description="Restore a Sats roster migration receipt")
    parser.add_argument("--receipt-dir", required=True, type=Path)
    parser.add_argument("--execute-external", action="store_true")
    args = parser.parse_args()
    try:
        restore(args.receipt_dir, args.execute_external)
    except MigrationError as error:
        parser.error(str(error))
    print(json.dumps({"status": "rolled_back", "raw_secrets": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

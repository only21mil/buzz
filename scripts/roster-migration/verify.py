#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

from migration import MigrationError, verify


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify the Sats roster migration")
    parser.add_argument("--root", type=Path, default=Path("/"))
    parser.add_argument("--activation-manifest", required=True, type=Path)
    parser.add_argument("--activation-manifest-sha256", required=True)
    args = parser.parse_args()
    try:
        result = verify(
            args.root, args.activation_manifest, args.activation_manifest_sha256,
        )
    except MigrationError as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

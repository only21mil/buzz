#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

from migration import MigrationError, apply, load_manifest, preflight_public_host


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply the reviewed Sats roster migration")
    parser.add_argument("--root", type=Path, default=Path("/"))
    parser.add_argument("--receipt-dir", type=Path)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--execute-external", action="store_true")
    parser.add_argument("--activation-manifest", type=Path)
    parser.add_argument("--activation-manifest-sha256")
    args = parser.parse_args()
    if args.apply and args.check:
        parser.error("--apply and --check are mutually exclusive")
    if args.check:
        if args.root != Path("/"):
            parser.error("--check requires the live root")
        try:
            result = preflight_public_host(
                load_manifest(), args.activation_manifest, args.activation_manifest_sha256,
            )
        except MigrationError as error:
            parser.error(str(error))
        print(json.dumps(result, sort_keys=True))
        return 0
    if not args.apply:
        manifest = load_manifest()
        print(json.dumps({
            "status": "plan",
            "targets": [{"slug": item["slug"], "display_name": item["display_name"], "model": item["model"]} for item in manifest["targets"]],
            "hermes_memberships": len(manifest["hermes_retirement"]["memberships"]),
            "raw_secrets": False,
        }, sort_keys=True))
        return 0
    if args.receipt_dir is None:
        parser.error("--receipt-dir is required with --apply")
    if args.root == Path("/") and not args.execute_external:
        parser.error("live apply requires --execute-external")
    try:
        receipt = apply(
            args.root,
            args.receipt_dir,
            args.execute_external,
            args.activation_manifest,
            args.activation_manifest_sha256,
        )
    except MigrationError as error:
        parser.error(str(error))
    print(json.dumps({"status": "complete", "receipt": str(receipt), "raw_secrets": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

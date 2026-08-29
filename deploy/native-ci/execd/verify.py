#!/usr/bin/env python3
"""Verify the checked-in dormant execd package contract without host effects."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


EXPECTED = {
    "templates/buzz-ci-execd.socket": (
        "ListenStream=/run/buzzci/execd.sock",
        "SocketUser=root",
        "SocketGroup=buzzci-execd",
        "SocketMode=0620",
    ),
    "templates/buzz-ci-execd.service": (
        "ExecStart=/usr/libexec/buzz-ci-execd --socket-activation",
        "ReadWritePaths=/var/lib/buzzci/execd-v2",
        "RestrictAddressFamilies=AF_UNIX",
    ),
    "templates/buzz-ci-executor.service": (
        "User=buzzci-job",
        "Group=buzzci-job",
        "SupplementaryGroups=",
        "StandardOutput=null",
        "StandardError=null",
    ),
    "templates/buzz-ci-executor.socket": (
        "ListenStream=/run/buzzci/executor.sock",
        "SocketUser=root",
        "SocketGroup=root",
        "SocketMode=0600",
    ),
    "templates/buzzci-execd.sysusers.in": (
        "g buzzci-execd @EXECD_ACCESS_GID@",
        "g buzzci-job @JOB_GID@",
        'u buzzci-job @JOB_UID@:buzzci-job "Buzz CI isolated job" /var/empty /usr/sbin/nologin',
        "m buzzci-runner buzzci-execd",
        "m buzzci-ctl buzzci-execd",
    ),
}


def verify(source_root: Path) -> None:
    root = source_root.resolve(strict=True) / "deploy/native-ci/execd"
    schema = json.loads((root / "execd-config.schema.json").read_bytes())
    if schema["properties"]["capacity"] != {"const": 1}:
        raise ValueError("capacity-one schema drift")
    members = schema["$defs"]["identities"]["properties"]["access_group_members"]
    if members != {"const": ["buzzci-ctl", "buzzci-runner"]}:
        raise ValueError("execd access group drift")
    program = schema["$defs"]["program"]["properties"]
    if program["path"] != {"const": "/usr/libexec/buzz-ci-executor"} or program["mode"] != {"const": 493}:
        raise ValueError("executor provenance schema drift")
    for relative, required in EXPECTED.items():
        lines = (root / relative).read_text().splitlines()
        missing = [line for line in required if line not in lines]
        if missing:
            raise ValueError(f"{relative} misses {missing}")
    tmpfiles = (root / "templates/buzzci-execd.tmpfiles").read_text().splitlines()
    if len(tmpfiles) != 5 or any(" 0700 root root " not in line for line in tmpfiles):
        raise ValueError("execd state roots are not exact root-owned 0700 directories")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    args = parser.parse_args()
    verify(args.source_root)
    print('{"status":"ok","capacity":1,"executor":"buzzci-job"}')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

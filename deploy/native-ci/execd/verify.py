#!/usr/bin/env python3
"""Verify the checked-in dormant execd package contract without host effects."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import stat


EXPECTED = {
    "templates/buzz-ci-execd.socket": (
        "ListenStream=/run/buzzci/execd.sock",
        "SocketUser=root",
        "SocketGroup=buzzci-execd",
        "SocketMode=0620",
    ),
    "templates/buzz-ci-execd.service": (
        "ExecStart=/usr/libexec/buzz-ci-execd --socket-activation",
        "ReadOnlyPaths=/etc/buzzci/execd-v2.json /usr/libexec/buzz-ci-executor /usr/libexec/buzz-ci-capacity-one-fixture /usr/share/buzzci/execd-v2/fixture /usr/share/containers/seccomp.json",
        "ReadWritePaths=/var/lib/buzzci/execd-v2 /var/lib/buzzci/seccomp /var/lib/buzzci/activation/receipts",
        "RestrictAddressFamilies=AF_UNIX",
        "PrivateDevices=yes",
        "DevicePolicy=closed",
        "RestrictNamespaces=yes",
        "CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER",
        "AmbientCapabilities=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER",
        "SystemCallFilter=~@clock @cpu-emulation @debug @module @mount @obsolete @raw-io @reboot @swap",
    ),
    "templates/buzz-ci-executor.service": (
        "User=buzzci-job",
        "Group=buzzci-job",
        "SupplementaryGroups=",
        "DevicePolicy=closed",
        "ProtectProc=invisible",
        "ProcSubset=pid",
        "ReadOnlyPaths=/usr/libexec/buzz-ci-executor /var/lib/buzzci/seccomp/v1/sha256/2598b3b98e6970f37f917e210202fa8976aefcd99abf8955803a6e35bba17eb4.json",
        "ReadWritePaths=/var/lib/buzzci/execd-v2/attempts",
        "RestrictAddressFamilies=AF_UNIX",
        "RestrictNamespaces=yes",
        "CapabilityBoundingSet=",
        "AmbientCapabilities=",
        "SystemCallArchitectures=native",
        "SystemCallFilter=~@clock @cpu-emulation @debug @module @mount @obsolete @privileged @raw-io @reboot @resources @swap",
        "MemoryMax=134217728",
        "TasksMax=16",
        "LimitNPROC=16",
        "LimitNOFILE=64",
        "LimitFSIZE=65536",
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
    package_schema = json.loads((root / "package-manifest.schema.json").read_bytes())
    if (
        package_schema["properties"]["schema"]
        != {"const": "buzz-ci-execd-install-package-v1"}
        or package_schema["properties"]["runtime_contract"]
        != {"const": {"binary": "/usr/libexec/buzz-ci-execd", "gid": 0, "mode": "0755", "uid": 0}}
        or package_schema["properties"]["seccomp_contract"]["const"]["packaged_bytes"] is not False
        or package_schema["properties"]["install_receipt"]["const"]["path"]
        != "/var/lib/buzzci/execd-v2/package/receipt-v1.json"
    ):
        raise ValueError("execd binary package manifest ABI drift")
    for executable in ("freeze_package.py", "install.py", "verify.py"):
        metadata = (root / executable).stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not metadata.st_mode & stat.S_IXUSR
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise ValueError(f"execd package helper mode drift: {executable}")
    package_helpers = (root / "freeze_package.py").read_text() + (root / "install.py").read_text()
    for required in (
        'SCHEMA = "buzz-ci-execd-install-package-v1"',
        '"binary": "/usr/libexec/buzz-ci-execd"',
        '"packaged_bytes": False',
        '"path": "/var/lib/buzzci/execd-v2/package/receipt-v1.json"',
        '"activation_owned_targets"',
        '"central activation receipt binding differs"',
        '"external seccomp source provenance differs"',
        '"installed execd binary readback differs"',
    ):
        if required not in package_helpers:
            raise ValueError(f"execd package helper contract misses {required}")
    if schema["properties"]["capacity"] != {"enum": [0, 1]}:
        raise ValueError("closed/active capacity schema drift")
    members = schema["$defs"]["identities"]["properties"]["access_group_members"]
    if members != {"const": ["buzzci-ctl", "buzzci-runner"]}:
        raise ValueError("execd access group drift")
    identities = schema["$defs"]["identities"]["properties"]
    expected_control = {
        "control_uid": {"const": 961},
        "control_gid": {"const": 961},
        "control_user": {"const": "buzzci-ctl"},
        "control_group": {"const": "buzzci-ctl"},
        "control_home": {"const": "/var/lib/buzzci/principals/ctl"},
        "control_shell": {"const": "/usr/sbin/nologin"},
        "control_supplementary_groups": {"const": ["buzzci-execd"]},
    }
    if any(identities.get(name) != value for name, value in expected_control.items()):
        raise ValueError("qualification principal schema drift")
    program = schema["$defs"]["program"]["properties"]
    if program["path"] != {"const": "/usr/libexec/buzz-ci-executor"} or program["mode"] != {"const": 493}:
        raise ValueError("executor provenance schema drift")
    execution = schema["$defs"]["execution"]
    expected_execution = {
        "schema_version": {"const": 1},
        "job_id": {"const": "capacity-one-fixture"},
        "fixture_manifest_sha256": {"const": "f204b8fba64e972408f5a0ea1c0bb3140cfa696289903d96a8cb07d602af6b23"},
        "fixture_input_sha256": {"const": "967723f42ed249ff3c4b81884d8fc3b9601a426dead66a5925bb9c7d4cb136f6"},
        "fixture_script_sha256": {"const": "8b2c335883399ad34033953d381a34519fc030577b875dcebe22f42843745ebf"},
        "failure_selector": {"$ref": "#/$defs/fixtureSelector"},
        "max_stdout_bytes": {"const": 32768},
        "max_stderr_bytes": {"const": 32768},
        "max_memory_bytes": {"const": 134217728},
        "max_processes": {"const": 16},
        "max_wall_seconds": {"const": 120},
    }
    if schema["properties"].get("execution") != {"$ref": "#/$defs/execution"}:
        raise ValueError("static execution schema is not required")
    if "execution" not in schema["required"]:
        raise ValueError("static execution config is optional")
    if any(execution["properties"].get(name) != value for name, value in expected_execution.items()):
        raise ValueError("static execution limits or fixture provenance drift")
    selector = schema["$defs"]["fixtureSelector"]
    if (
        selector["properties"].get("schema_version") != {"const": "buzz-ci-capacity-one-fixture-selector/v1"}
        or selector["properties"].get("selector") != {"const": "deterministic-failure"}
        or selector["properties"].get("job_id") != {"const": "capacity-one-fixture"}
        or selector["properties"].get("attempt") != {"const": 1}
        or set(selector["required"]) != set(selector["properties"])
    ):
        raise ValueError("static failure selector schema drift")
    expected_artifact = {
        "artifact_id": {"const": "result"},
        "name": {"const": "result.json"},
        "media_type": {"const": "application/json"},
        "relative_name": {"const": "result.json"},
        "max_bytes": {"const": 32768},
    }
    artifact = execution["properties"]["artifact"]
    if any(artifact["properties"].get(name) != value for name, value in expected_artifact.items()):
        raise ValueError("static artifact declaration drift")
    for relative, required in EXPECTED.items():
        lines = (root / relative).read_text().splitlines()
        missing = [line for line in required if line not in lines]
        if missing:
            raise ValueError(f"{relative} misses {missing}")
    tmpfiles = (root / "templates/buzzci-execd.tmpfiles").read_text().splitlines()
    retained = [
        "d /var/lib/buzzci 0711 root root - -",
        "d /var/lib/buzzci/seccomp 0711 root root - -",
        "d /var/lib/buzzci/activation 0700 root root - -",
        "d /var/lib/buzzci/activation/receipts 0700 root root - -",
        "d /var/lib/buzzci/execd-v2 0711 root root - -",
        "d /var/lib/buzzci/execd-v2/intents 0700 root root - -",
        "d /var/lib/buzzci/execd-v2/bindings 0700 root root - -",
        "d /var/lib/buzzci/execd-v2/evidence 0700 root root - -",
        "d /var/lib/buzzci/execd-v2/teardown 0700 root root - -",
        "d /var/lib/buzzci/execd-v2/attempts 0711 root root - -",
        "d /var/lib/buzzci/execd-v2/qualification 0700 root root - -",
    ]
    for line in tmpfiles:
        fields = line.split()
        if (
            len(fields) >= 2
            and Path(fields[1]).parent == Path("/var/lib/buzzci")
            and fields[0] != "d"
        ):
            raise ValueError("regular files are forbidden directly under the shared state ancestor")
    if tmpfiles != retained:
        raise ValueError("execd shared ancestor or private state root drift")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    args = parser.parse_args()
    verify(args.source_root)
    print('{"status":"ok","capacity":"0_or_1","executor":"buzzci-job","production_protocol":2}')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

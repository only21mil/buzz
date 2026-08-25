from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).parents[1] / "install-static-system.py"
SPEC = importlib.util.spec_from_file_location("install_static_system", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class StaticManifestTests(unittest.TestCase):
    def make_package(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        package = Path(temporary.name)
        package.chmod(0o700)
        entries = []
        for target, (source_name, mode) in MODULE.TARGETS.items():
            source = package / source_name
            source.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            source.write_bytes(target.encode())
            source.chmod(mode)
            entries.append(
                {
                    "source": source_name,
                    "target": target,
                    "mode": f"{mode:04o}",
                    "sha256": hashlib.sha256(target.encode()).hexdigest(),
                }
            )
        manifest = package / "manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "schema": MODULE.SCHEMA,
                    "package_id": "mempool-genesis-static-test",
                    "entries": entries,
                }
            )
        )
        manifest.chmod(0o600)
        return temporary, package

    def test_accepts_exact_manifest(self) -> None:
        temporary, package = self.make_package()
        self.addCleanup(temporary.cleanup)
        package_id, entries = MODULE.exact_manifest(package)
        self.assertEqual(package_id, "mempool-genesis-static-test")
        self.assertEqual(len(entries), len(MODULE.TARGETS))

    def test_rejects_duplicate_json_keys(self) -> None:
        with self.assertRaises(ValueError):
            json.loads('{"schema":"one","schema":"two"}', object_pairs_hook=MODULE.reject_duplicates)

    def test_rejects_manifest_target_drift(self) -> None:
        temporary, package = self.make_package()
        self.addCleanup(temporary.cleanup)
        manifest = json.loads((package / "manifest.json").read_text())
        manifest["entries"][0]["target"] = "/etc/passwd"
        (package / "manifest.json").write_text(json.dumps(manifest))
        (package / "manifest.json").chmod(0o600)
        with self.assertRaises(ValueError):
            MODULE.exact_manifest(package)


if __name__ == "__main__":
    unittest.main()

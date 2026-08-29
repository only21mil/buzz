from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[4]
VERIFY_PATH = ROOT / "deploy/native-ci/execd/verify.py"
SPEC = importlib.util.spec_from_file_location("execd_verify", VERIFY_PATH)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class ExecdPackageTests(unittest.TestCase):
    def test_checked_in_contract(self) -> None:
        VERIFY.verify(ROOT)

    def test_fake_root_service_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory)
            target = fake / "deploy/native-ci/execd"
            target.mkdir(parents=True)
            for source in (ROOT / "deploy/native-ci/execd").rglob("*"):
                if source.is_file() and "__pycache__" not in source.parts:
                    destination = target / source.relative_to(ROOT / "deploy/native-ci/execd")
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(source.read_bytes())
            service = target / "templates/buzz-ci-executor.service"
            service.write_text(service.read_text().replace("User=buzzci-job", "User=buzzci-runner"))
            with self.assertRaisesRegex(ValueError, "misses"):
                VERIFY.verify(fake)


if __name__ == "__main__":
    unittest.main()

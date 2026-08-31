from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest

NATIVE_CI_DIR = Path(__file__).resolve().parents[1]
COMPONENTS = ("controld", "keyholder", "runner")


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PACKAGE_SOURCE = load("package_source", NATIVE_CI_DIR / "package_source.py")


class PackageSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.seed = self.base / "seed"
        for component in COMPONENTS:
            destination = self.seed / "deploy/native-ci" / component
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(
                NATIVE_CI_DIR / component,
                destination,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
        shutil.copy2(NATIVE_CI_DIR / "package_source.py", self.seed / "deploy/native-ci/package_source.py")
        subprocess.run(["git", "init", "-q", str(self.seed)], check=True)
        subprocess.run(["git", "-C", str(self.seed), "config", "user.name", "Package source test"], check=True)
        subprocess.run(["git", "-C", str(self.seed), "config", "user.email", "package-source@test.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.seed), "add", "deploy/native-ci"], check=True)
        subprocess.run(["git", "-C", str(self.seed), "commit", "-qm", "fixture"], check=True)
        self.commit = PACKAGE_SOURCE.git_output(self.seed, "rev-parse", "HEAD")

    def private_checkout(self, name: str = "private-checkout") -> Path:
        checkout = self.base / name
        prior_umask = os.umask(0o077)
        try:
            subprocess.run(["git", "clone", "-q", str(self.seed), str(checkout)], check=True)
        finally:
            os.umask(prior_umask)
        return checkout

    def test_umask_0077_checkout_preserves_git_executable_class_for_all_components(self) -> None:
        checkout = self.private_checkout()
        for component in COMPONENTS:
            relative = Path("deploy/native-ci") / component
            PACKAGE_SOURCE.verify_checkout(checkout, self.commit, relative)
            for source in PACKAGE_SOURCE.tracked_files(checkout, relative):
                git_mode = PACKAGE_SOURCE._git_file_mode(checkout, source)
                materialized = stat.S_IMODE((checkout / source).lstat().st_mode)
                self.assertEqual(materialized, 0o700 if git_mode == 0o100755 else 0o600)

    def test_unsafe_and_ambiguous_materialized_modes_are_rejected(self) -> None:
        cases = (
            ("group-writable", "deploy/native-ci/keyholder/README.md", 0o620, "unsafe permissions"),
            ("safe-but-ambiguous", "deploy/native-ci/keyholder/README.md", 0o640, "materialized mode differs"),
            ("nonexec-execute", "deploy/native-ci/keyholder/README.md", 0o700, "executable class"),
            ("exec-no-execute", "deploy/native-ci/keyholder/freeze_package.py", 0o600, "executable class"),
        )
        for name, relative, mode, message in cases:
            with self.subTest(name=name):
                checkout = self.private_checkout(name)
                (checkout / relative).chmod(mode)
                with self.assertRaisesRegex(ValueError, message):
                    PACKAGE_SOURCE.verify_checkout(
                        checkout,
                        self.commit,
                        Path(relative).parent,
                    )

    def test_symbolic_and_hard_link_source_drift_are_rejected(self) -> None:
        symbolic = self.private_checkout("symbolic")
        relative = Path("deploy/native-ci/keyholder/README.md")
        target = symbolic / "replacement"
        target.write_bytes((symbolic / relative).read_bytes())
        (symbolic / relative).unlink()
        (symbolic / relative).symlink_to(target)
        with self.assertRaisesRegex(ValueError, "symbolic links"):
            PACKAGE_SOURCE.verify_checkout(symbolic, self.commit, Path("deploy/native-ci/keyholder"))

        linked = self.private_checkout("hard-linked")
        source = linked / "deploy/native-ci/keyholder/README.md"
        second_name = linked / "second-link"
        os.link(source, second_name)
        with self.assertRaisesRegex(ValueError, "single regular file"):
            PACKAGE_SOURCE.verify_checkout(
                linked,
                self.commit,
                Path("deploy/native-ci/keyholder"),
            )

    def test_owner_readable_and_owner_owned_are_required(self) -> None:
        checkout = self.private_checkout()
        source = checkout / "deploy/native-ci/keyholder/README.md"
        metadata = source.stat()
        with self.assertRaisesRegex(ValueError, "owner access differs"):
            PACKAGE_SOURCE.validate_metadata(metadata, 0o100644, metadata.st_uid + 1, str(source))
        source.chmod(0o200)
        with self.assertRaisesRegex(ValueError, "owner access differs"):
            PACKAGE_SOURCE.validate_metadata(source.stat(), 0o100644, source.stat().st_uid, str(source))


if __name__ == "__main__":
    unittest.main()

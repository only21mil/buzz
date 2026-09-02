from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
NATIVE_CI_ROOT = REPO_ROOT / "deploy/native-ci"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_keyholder_installer():
    keyholder_root = NATIVE_CI_ROOT / "keyholder"
    prior_path = list(sys.path)
    displaced = {
        name: sys.modules.pop(name, None)
        for name in ("freeze_package", "render_keyholder_config")
    }
    sys.path.insert(0, str(keyholder_root))
    try:
        return load_module("shared_state_keyholder_installer", keyholder_root / "install.py")
    finally:
        sys.path[:] = prior_path
        for name in ("freeze_package", "render_keyholder_config"):
            sys.modules.pop(name, None)
            if displaced[name] is not None:
                sys.modules[name] = displaced[name]


RUNNER_INSTALLER = load_module(
    "shared_state_runner_installer", NATIVE_CI_ROOT / "runner/install.py",
)
CONTROLD_INSTALLER = load_module(
    "shared_state_controld_installer", NATIVE_CI_ROOT / "controld/install.py",
)
KEYHOLDER_INSTALLER = load_keyholder_installer()


class SharedStateCompositionTests(unittest.TestCase):
    def make_root(self, parent: Path, name: str) -> Path:
        root = parent / name
        (root / "var/lib").mkdir(mode=0o755, parents=True)
        root.chmod(0o700)
        (root / "var").chmod(0o755)
        (root / "var/lib").chmod(0o755)
        return root

    def assert_mode(self, path: Path, expected: int) -> None:
        self.assertEqual(stat.S_IMODE(path.lstat().st_mode), expected, path)

    def keyholder_receipt_preflight(self, root: Path) -> None:
        root_fd = os.open(
            root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        receipt_fd = -1
        try:
            receipt_fd = KEYHOLDER_INSTALLER._receipt_directory(
                root_fd, root, create=True, created=[],
            )
        finally:
            if receipt_fd >= 0:
                os.close(receipt_fd)
            os.close(root_fd)

    def test_runner_and_controld_first_clean_compositions_reach_keyholder(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            for first, second in (
                (RUNNER_INSTALLER, CONTROLD_INSTALLER),
                (CONTROLD_INSTALLER, RUNNER_INSTALLER),
            ):
                root = self.make_root(parent, f"{first.__name__}-first")
                previous_umask = os.umask(0o077)
                try:
                    for installer in (first, second):
                        installer.ensure_private_tree(
                            root,
                            installer.backup_root_path(root, installer.DEFAULT_BACKUP_ROOT),
                        )
                    self.keyholder_receipt_preflight(root)
                finally:
                    os.umask(previous_umask)

                shared = root / "var/lib/buzzci"
                self.assert_mode(shared, 0o711)
                self.assert_mode(shared / "install-backups", 0o700)
                self.assert_mode(shared / "install-backups/runner", 0o700)
                self.assert_mode(shared / "install-backups/controld", 0o700)
                self.assert_mode(shared / "keyholder-package", 0o700)

    def test_all_installer_and_tmpfiles_declarations_agree_on_shared_mode(self) -> None:
        self.assertEqual(RUNNER_INSTALLER.SHARED_STATE_ROOT, Path("/var/lib/buzzci"))
        self.assertEqual(CONTROLD_INSTALLER.SHARED_STATE_ROOT, Path("/var/lib/buzzci"))
        for relative in (
            "activation/templates/buzzci-activation.tmpfiles",
            "execd/templates/buzzci-execd.tmpfiles",
        ):
            declarations = (NATIVE_CI_ROOT / relative).read_text().splitlines()
            self.assertIn("d /var/lib/buzzci 0711 root root - -", declarations)


if __name__ == "__main__":
    unittest.main()

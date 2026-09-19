"""Filesystem boundary tests shared by the controller and runner installers."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
from unittest import mock
import unittest

SPEC = importlib.util.spec_from_file_location(
    "native_ci_common",
    Path(__file__).resolve().parents[1] / "_common.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load shared installer helpers")
COMMON = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMMON)


class InstallerFilesystemTests(unittest.TestCase):
    def test_parent_chain_rejects_writable_and_symbolic_ancestors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = root / "parent"
            parent.mkdir(mode=0o700)
            COMMON.validate_parent_chain(root, parent)
            parent.chmod(0o777)  # noqa: S103 - hostile permissions are the test input
            with self.assertRaisesRegex(ValueError, "unsafe target directory chain"):
                COMMON.validate_parent_chain(root, parent)
            parent.chmod(0o700)
            link = root / "link"
            link.symlink_to(parent, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "unsafe target directory chain"):
                COMMON.validate_parent_chain(root, link)
            with self.assertRaisesRegex(ValueError, "symbolic path"):
                COMMON.validate_parent_chain(link, link)

    def test_package_tree_requires_private_assets_with_matching_ownership(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "package"
            package.mkdir(mode=0o700)
            assets = package / "assets"
            assets.mkdir(mode=0o700)
            self.assertEqual(
                COMMON.require_package_tree(package, root), (os.geteuid(), os.getegid())
            )
            assets.chmod(0o755)
            with self.assertRaisesRegex(ValueError, "unsafe directory metadata"):
                COMMON.require_package_tree(package, root)
            assets.chmod(0o700)
            with self.assertRaisesRegex(ValueError, "unsafe directory metadata"):
                COMMON.require_directory(assets, os.geteuid() + 1, os.getegid(), 0o700)

    def test_targets_cannot_escape_the_installation_root(self):
        root = Path("/fake-root")
        self.assertEqual(COMMON.rooted(root, "/etc/buzzci"), root / "etc/buzzci")
        for target in ("etc/buzzci", "/etc/../outside"):
            with (
                self.subTest(target=target),
                self.assertRaisesRegex(ValueError, "unsafe target"),
            ):
                COMMON.rooted(root, target)


class AssetWriterTests(unittest.TestCase):
    def test_partial_writes_preserve_payload_and_exact_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "asset"
            real_write = os.write
            with mock.patch.object(COMMON.os, "write", side_effect=lambda fd, data: real_write(fd, data[:2])):
                COMMON.write_asset(path, b"asset payload", 0o400)
            self.assertEqual(path.read_bytes(), b"asset payload")
            self.assertEqual(path.stat().st_mode & 0o777, 0o400)
            with self.assertRaises(FileExistsError):
                COMMON.write_asset(path, b"replacement", 0o600)
            self.assertEqual(path.read_bytes(), b"asset payload")
            link = Path(directory) / "link"
            link.symlink_to(path)
            with self.assertRaises(FileExistsError):
                COMMON.write_asset(link, b"replacement", 0o600)
            self.assertEqual(path.read_bytes(), b"asset payload")

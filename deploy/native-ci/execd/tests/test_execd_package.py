from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[4]
VERIFY_PATH = ROOT / "deploy/native-ci/execd/verify.py"
SPEC = importlib.util.spec_from_file_location("execd_verify", VERIFY_PATH)
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)

EXECD_TMPFILES = ROOT / "deploy/native-ci/execd/templates/buzzci-execd.tmpfiles"
SHARED_ANCESTOR = "d /var/lib/buzzci 0711 root root - -"
# Frozen from activation package commit 7c6d9fa6db0d92c9e33714868cbe928f19e16764.
ACTIVATION_DIRECTORY_PLAN = (
    SHARED_ANCESTOR,
    "d /var/lib/buzzci/activation-controller 0711 root root -",
    "d /var/lib/buzzci/seccomp 0700 root root - -",
    "d /var/lib/buzzci/activation 0700 root root - -",
    "d /var/lib/buzzci/activation/receipts 0700 root root - -",
    "d /var/lib/buzzci/execd-v2 0700 root root - -",
    "d /var/lib/buzzci/execd-v2/intents 0700 root root - -",
    "d /var/lib/buzzci/execd-v2/bindings 0700 root root - -",
    "d /var/lib/buzzci/execd-v2/evidence 0700 root root - -",
    "d /var/lib/buzzci/execd-v2/teardown 0700 root root - -",
    "d /var/lib/buzzci/execd-v2/attempts 0711 root root - -",
    "d /var/lib/buzzci/execd-v2/qualification 0700 root root - -",
)


def _copy_execd_package(fake: Path) -> Path:
    target = fake / "deploy/native-ci/execd"
    target.mkdir(parents=True)
    for source in (ROOT / "deploy/native-ci/execd").rglob("*"):
        if source.is_file() and "__pycache__" not in source.parts:
            destination = target / source.relative_to(ROOT / "deploy/native-ci/execd")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
    return target


def _apply_directory_plan(root: Path, lines: tuple[str, ...] | list[str]) -> None:
    for line in lines:
        fields = line.split()
        if len(fields) not in (6, 7):
            raise AssertionError(f"unsupported fake-root tmpfiles entry: {line}")
        kind, absolute, mode, user, group, age = fields[:6]
        if (
            kind != "d"
            or user != "root"
            or group != "root"
            or age != "-"
            or (len(fields) == 7 and fields[6] != "-")
        ):
            raise AssertionError(f"unsupported fake-root tmpfiles entry: {line}")
        target = root / absolute.removeprefix("/")
        target.mkdir(parents=True, exist_ok=True)
        target.chmod(int(mode, 8))


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat(follow_symlinks=False).st_mode)


class ExecdPackageTests(unittest.TestCase):
    def test_checked_in_contract(self) -> None:
        VERIFY.verify(ROOT)

    def test_fake_root_service_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory)
            target = _copy_execd_package(fake)
            service = target / "templates/buzz-ci-executor.service"
            service.write_text(service.read_text().replace("User=buzzci-job", "User=buzzci-runner"))
            with self.assertRaisesRegex(ValueError, "misses"):
                VERIFY.verify(fake)

    def test_execd_and_activation_directory_plans_converge_in_either_order_and_umask(self) -> None:
        execd = tuple(EXECD_TMPFILES.read_text().splitlines())
        orders = (
            ("execd-first", (execd, ACTIVATION_DIRECTORY_PLAN)),
            ("activation-first", (ACTIVATION_DIRECTORY_PLAN, execd)),
        )
        for umask in (0o000, 0o077):
            for label, order in orders:
                with self.subTest(umask=oct(umask), order=label):
                    with tempfile.TemporaryDirectory() as directory:
                        previous = os.umask(umask)
                        try:
                            for plan in order:
                                _apply_directory_plan(Path(directory), plan)
                        finally:
                            os.umask(previous)
                        state = Path(directory) / "var/lib/buzzci"
                        self.assertEqual(_mode(state), 0o711)
                        self.assertEqual(_mode(state / "activation-controller"), 0o711)
                        for private in (
                            "seccomp",
                            "activation",
                            "activation/receipts",
                            "execd-v2",
                            "execd-v2/intents",
                            "execd-v2/bindings",
                            "execd-v2/evidence",
                            "execd-v2/teardown",
                            "execd-v2/qualification",
                        ):
                            self.assertEqual(_mode(state / private), 0o700, private)

    def test_shared_traversal_exposes_only_the_explicit_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _apply_directory_plan(root, tuple(EXECD_TMPFILES.read_text().splitlines()))
            _apply_directory_plan(root, ACTIVATION_DIRECTORY_PLAN)
            shared = root / "var/lib/buzzci"
            receipt_root = shared / "activation-controller"
            receipt = receipt_root / "controld-acceptance-v1.json"
            receipt.write_bytes(b'{"schema_version":1}\n')
            receipt.chmod(0o444)
            private_state = receipt_root / "controller-state-v1.json"
            private_state.write_bytes(b'{"private":true}\n')
            private_state.chmod(0o600)

            self.assertTrue(_mode(shared) & stat.S_IXOTH)
            self.assertFalse(_mode(shared) & stat.S_IROTH)
            self.assertTrue(_mode(receipt_root) & stat.S_IXOTH)
            self.assertFalse(_mode(receipt_root) & stat.S_IROTH)
            self.assertTrue(_mode(receipt) & stat.S_IROTH)
            self.assertFalse(_mode(receipt) & stat.S_IWOTH)
            self.assertFalse(_mode(private_state) & stat.S_IROTH)
            self.assertFalse(_mode(shared / "execd-v2") & stat.S_IXOTH)
            self.assertFalse(_mode(shared / "activation") & stat.S_IXOTH)

    def test_all_packaged_direct_children_are_directories(self) -> None:
        templates = ROOT.glob("deploy/native-ci/*/templates/*tmpfiles*")
        for template in templates:
            for line in template.read_text().splitlines():
                fields = line.split()
                if len(fields) >= 2 and Path(fields[1]).parent == Path("/var/lib/buzzci"):
                    self.assertEqual(fields[0], "d", f"direct-child file in {template}: {line}")

    def test_unsafe_ancestor_private_root_and_direct_file_drift_are_rejected(self) -> None:
        mutations = (
            (SHARED_ANCESTOR, "d /var/lib/buzzci 0700 root root - -"),
            (SHARED_ANCESTOR, "d /var/lib/buzzci 0755 root root - -"),
            (
                "d /var/lib/buzzci/execd-v2 0700 root root - -",
                "d /var/lib/buzzci/execd-v2 0711 root root - -",
            ),
            (SHARED_ANCESTOR, "f /var/lib/buzzci/leaked-secret 0600 root root - payload"),
        )
        for original, replacement in mutations:
            with self.subTest(replacement=replacement):
                with tempfile.TemporaryDirectory() as directory:
                    fake = Path(directory)
                    target = _copy_execd_package(fake)
                    tmpfiles = target / "templates/buzzci-execd.tmpfiles"
                    tmpfiles.write_text(tmpfiles.read_text().replace(original, replacement))
                    with self.assertRaises(ValueError):
                        VERIFY.verify(fake)


if __name__ == "__main__":
    unittest.main()

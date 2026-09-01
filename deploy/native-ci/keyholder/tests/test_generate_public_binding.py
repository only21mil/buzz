from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

KEYHOLDER_DIR = Path(__file__).resolve().parents[1]
SOURCE_ROOT = KEYHOLDER_DIR.parents[2]
ACTIVATION_RENDERER_PATH = (
    SOURCE_ROOT / "deploy/native-ci/activation/render_inputs/render_inputs.py"
)


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


GENERATOR = load_module(
    "generate_keyholder_public_binding",
    KEYHOLDER_DIR / "generate_public_binding.py",
)
FREEZER = sys.modules["freeze_package"]
ACTIVATION_RENDERER = load_module(
    "activation_render_inputs_for_public_binding",
    ACTIVATION_RENDERER_PATH,
)

VALID_KEYS = {
    "ci_event": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "nip98": "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    "manifest": "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    "acceptance_actor": "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
}


class ProductionPublicBindingGeneratorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=SOURCE_ROOT)
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.base.chmod(0o700)
        self.keys: dict[str, Path] = {}
        for role, public_key in VALID_KEYS.items():
            path = self.base / f"{role}.pub"
            path.write_bytes(public_key.encode() + b"\n")
            path.chmod(0o600)
            self.keys[role] = path

    def arguments(self) -> dict[str, object]:
        return {
            "relay_url": "wss://relay.example.test:443",
            "relay_http_origin": "https://relay.example.test:443",
            "controld_uid": 1201,
            "controld_gid": 1201,
            "ci_event_public_key": self.keys["ci_event"],
            "ci_event_generation": 1,
            "nip98_public_key": self.keys["nip98"],
            "nip98_generation": 1,
            "manifest_public_key": self.keys["manifest"],
            "manifest_generation": 1,
            "acceptance_actor_public_key": self.keys["acceptance_actor"],
            "acceptance_actor_generation": 1,
        }

    def test_emits_exact_v3_bytes_accepted_by_both_consumers(self) -> None:
        output = self.base / "public-binding.json"
        GENERATOR.generate(output, **self.arguments())
        metadata = output.lstat()
        self.assertTrue(stat.S_ISREG(metadata.st_mode))
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
        self.assertEqual(metadata.st_nlink, 1)
        self.assertEqual(metadata.st_uid, os.geteuid())
        raw = output.read_bytes()
        self.assertTrue(raw.endswith(b"\n"))
        self.assertNotIn(b" ", raw)
        binding = json.loads(raw)
        self.assertEqual(
            binding["schema_version"],
            "buzz-ci-clean-host-e2e-public-binding/v3",
        )
        FREEZER.project_public_binding_bytes(raw)
        ACTIVATION_RENDERER.validate_public_binding(binding)
        self.assertEqual(ACTIVATION_RENDERER.canonical_public_binding(binding), raw)

    def test_same_public_inputs_produce_identical_bytes(self) -> None:
        first = GENERATOR.binding_bytes(**self.arguments())
        second = GENERATOR.binding_bytes(**self.arguments())
        self.assertEqual(first, second)

    def test_rejects_invalid_x_only_public_key_encodings(self) -> None:
        invalid = {
            "uppercase": VALID_KEYS["ci_event"].upper().encode() + b"\n",
            "zero": ("0" * 64).encode() + b"\n",
            "not-on-curve": ("0" * 63 + "5").encode() + b"\n",
            "missing-lf": VALID_KEYS["ci_event"].encode() + b"x",
            "short": VALID_KEYS["ci_event"][:-1].encode() + b"\n\n",
            "non-ascii": b"\xff" * 64 + b"\n",
        }
        for label, raw in invalid.items():
            with self.subTest(label=label):
                path = self.keys["ci_event"]
                path.write_bytes(raw)
                path.chmod(0o600)
                with self.assertRaises(ValueError):
                    GENERATOR.binding_bytes(**self.arguments())
                path.write_bytes(VALID_KEYS["ci_event"].encode() + b"\n")
                path.chmod(0o600)

    def test_rejects_colliding_roles_and_non_v3_generations(self) -> None:
        self.keys["acceptance_actor"].write_bytes(
            VALID_KEYS["ci_event"].encode() + b"\n",
        )
        with self.assertRaisesRegex(ValueError, "distinct"):
            GENERATOR.binding_bytes(**self.arguments())
        self.keys["acceptance_actor"].write_bytes(
            VALID_KEYS["acceptance_actor"].encode() + b"\n",
        )
        for field, value in (
            ("ci_event_generation", 0),
            ("nip98_generation", 2),
            ("manifest_generation", True),
            ("acceptance_actor_generation", (1 << 64)),
        ):
            with self.subTest(field=field):
                arguments = self.arguments()
                arguments[field] = value
                with self.assertRaisesRegex(ValueError, "generation"):
                    GENERATOR.binding_bytes(**arguments)

    def test_rejects_noncanonical_or_mismatched_origins(self) -> None:
        invalid = (
            ("ws://relay.example.test:443", "https://relay.example.test:443"),
            ("wss://relay.example.test:443/", "https://relay.example.test:443"),
            ("wss://Relay.example.test:443", "https://relay.example.test:443"),
            ("wss://relay.example.test:443", "https://other.example.test:443"),
            ("wss://relay.example.test:443?q=1", "https://relay.example.test:443"),
            ("wss://user@relay.example.test:443", "https://relay.example.test:443"),
            ("wss://relay.example.test:70000", "https://relay.example.test:70000"),
        )
        for relay_url, relay_http_origin in invalid:
            with self.subTest(relay_url=relay_url):
                arguments = self.arguments()
                arguments.update({
                    "relay_url": relay_url,
                    "relay_http_origin": relay_http_origin,
                })
                with self.assertRaises(ValueError):
                    GENERATOR.binding_bytes(**arguments)

    def test_rejects_unsafe_public_key_nodes_and_modes(self) -> None:
        original = self.keys["ci_event"]
        alias = self.base / "alias.pub"
        alias.symlink_to(original)
        arguments = self.arguments()
        arguments["ci_event_public_key"] = alias
        with self.assertRaisesRegex(ValueError, "symbolic"):
            GENERATOR.binding_bytes(**arguments)
        alias.unlink()

        alias.hardlink_to(original)
        with self.assertRaisesRegex(ValueError, "metadata"):
            GENERATOR.binding_bytes(**self.arguments())
        alias.unlink()

        original.chmod(0o666)
        with self.assertRaisesRegex(ValueError, "metadata"):
            GENERATOR.binding_bytes(**self.arguments())
        original.chmod(0o600)

        directory = self.base / "directory.pub"
        directory.mkdir(mode=0o700)
        arguments["ci_event_public_key"] = directory
        with self.assertRaisesRegex(ValueError, "metadata"):
            GENERATOR.binding_bytes(**arguments)

        fifo = self.base / "fifo.pub"
        os.mkfifo(fifo, 0o600)
        arguments["ci_event_public_key"] = fifo
        with self.assertRaisesRegex(ValueError, "metadata"):
            GENERATOR.binding_bytes(**arguments)

    def test_output_is_create_once_in_private_real_directory(self) -> None:
        output = self.base / "public-binding.json"
        output.write_bytes(b"existing\n")
        output.chmod(0o600)
        with self.assertRaises(FileExistsError):
            GENERATOR.generate(output, **self.arguments())
        self.assertEqual(output.read_bytes(), b"existing\n")

        loose = self.base / "loose"
        loose.mkdir(mode=0o755)
        loose.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "mode-0700"):
            GENERATOR.generate(loose / "binding.json", **self.arguments())

        private = self.base / "private"
        private.mkdir(mode=0o700)
        link = self.base / "private-link"
        link.symlink_to(private, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symbolic"):
            GENERATOR.generate(link / "binding.json", **self.arguments())

    def test_cli_writes_no_public_or_secret_value_to_stdout(self) -> None:
        output = self.base / "cli-binding.json"
        command = [
            sys.executable,
            str(KEYHOLDER_DIR / "generate_public_binding.py"),
            "--relay-url", "wss://relay.example.test:443",
            "--relay-http-origin", "https://relay.example.test:443",
            "--controld-uid", "1201",
            "--controld-gid", "1201",
        ]
        for option, role in (
            ("ci-event", "ci_event"),
            ("nip98", "nip98"),
            ("manifest", "manifest"),
            ("acceptance-actor", "acceptance_actor"),
        ):
            command.extend([
                f"--{option}-public-key", str(self.keys[role]),
                f"--{option}-generation", "1",
            ])
        command.extend(["--output", str(output)])
        result = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")
        self.assertTrue(output.is_file())


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Deterministic checks for the disposable clean-host harness."""

from __future__ import annotations

import hashlib
import http.client
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest

HERE = Path(__file__).resolve().parent


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, HERE / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


harness = load("harness")
relay = load("local_tls_relay")


class HarnessTests(unittest.TestCase):
    def test_prepare_creates_distinct_public_bindings_and_private_raw_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            result = harness.prepare(state, 1201, 1201)
            self.assertEqual(result["status"], "prepared")
            binding = json.loads((state / "public-binding.json").read_bytes())
            spec = binding["keyholder_public_spec"]
            public = [spec["selectors"][name]["public_key"] for name in ("ci_event", "nip98", "manifest")]
            public.append(binding["acceptance_actor"]["public_key"])
            self.assertEqual(len(set(public)), 4)
            self.assertTrue(all(len(value) == 64 for value in public))
            for name in harness.KEY_NAMES:
                key = state / "private" / f"{name}.key"
                self.assertEqual(key.stat().st_mode & 0o777, 0o400)
                self.assertEqual(key.stat().st_size, 32)

    def test_tree_digest_binds_relative_name_mode_and_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            item = root / "asset"
            item.write_bytes(b"one")
            item.chmod(0o400)
            first = harness.sha256_tree(root)
            item.chmod(0o600)
            second = harness.sha256_tree(root)
            item.write_bytes(b"two")
            third = harness.sha256_tree(root)
            self.assertEqual(len({first, second, third}), 3)

    def test_authoritative_parent_contains_complete_execd_package(self) -> None:
        candidate = HERE.parents[4]
        missing = [relative for relative in harness.REQUIRED_CANDIDATE_FILES if not (candidate / relative).is_file()]
        self.assertEqual(missing, [])

    def test_package_binding_rejects_activation_actor_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            harness.prepare(state, 1201, 1201)
            binding = json.loads((state / "public-binding.json").read_bytes())
            keyholder = root / "keyholder"
            activation = root / "activation"
            (keyholder / "assets").mkdir(parents=True)
            (activation / "assets").mkdir(parents=True)
            keyholder_config = harness.canonical(binding["keyholder_public_spec"])
            active_config = harness.canonical({
                "relay_url": binding["relay_url"],
                "relay_http_origin": binding["relay_http_origin"],
                "keyholder_selectors": binding["keyholder_public_spec"]["selectors"],
                "keyholder_uid": 1201,
                "keyholder_gid": 1201,
            })
            (keyholder / "assets/config.json").write_bytes(keyholder_config)
            (activation / "assets/active.json").write_bytes(active_config)
            keyholder_manifest = {"entries": [{
                "role": "config", "source": "assets/config.json",
                "sha256": hashlib.sha256(keyholder_config).hexdigest(),
            }]}
            activation_manifest = {
                "acceptance_template": {"actor": binding["acceptance_actor"]},
                "entries": [{
                    "role": "controld_config", "active_source": "assets/active.json",
                    "active_sha256": hashlib.sha256(active_config).hexdigest(),
                }],
            }
            (keyholder / "package-manifest.json").write_bytes(harness.canonical(keyholder_manifest))
            (activation / "activation-manifest.json").write_bytes(harness.canonical(activation_manifest))
            harness.validate_package_binding(keyholder, activation, binding)
            activation_manifest["acceptance_template"]["actor"] = {"public_key": "f" * 64, "generation": 1}
            (activation / "activation-manifest.json").write_bytes(harness.canonical(activation_manifest))
            with self.assertRaisesRegex(harness.HarnessError, "activation actor"):
                harness.validate_package_binding(keyholder, activation, binding)


class RelayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        state = relay.RelayState(Path(self.temporary.name))
        self.server = relay.RelayServer(("127.0.0.1", 0), state)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.connection = http.client.HTTPConnection(*self.server.server_address, timeout=2)
        self.headers = {"Authorization": "Nostr " + "A" * 32, "Content-Type": "application/json"}

    def tearDown(self) -> None:
        self.connection.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def request_json(self, method: str, path: str, body: bytes | None = None) -> tuple[int, dict[str, object]]:
        headers = dict(self.headers)
        if body is not None:
            headers["Content-Length"] = str(len(body))
        self.connection.request(method, path, body=body, headers=headers)
        response = self.connection.getresponse()
        return response.status, json.loads(response.read())

    def test_publish_poll_and_exact_object_store(self) -> None:
        event_id = "1" * 64
        event = {"id": event_id, "kind": 46100, "tags": [["h", "channel"]], "content": "{}"}
        status, published = self.request_json("POST", "/events", json.dumps(event).encode())
        self.assertEqual((status, published["event_id"], published["accepted"]), (200, event_id, True))
        status, accepted = self.request_json("GET", "/ci/control/accepted?channel_id=channel&after_cursor=0&limit=1")
        self.assertEqual(status, 200)
        self.assertEqual(accepted["accepted"]["event"], event)
        body = b"fixture evidence"
        digest = hashlib.sha256(body).hexdigest()
        status, stored = self.request_json("PUT", f"/ci/logs/event/run/job/1/{digest}", body)
        self.assertEqual((status, stored["sha256"], stored["byte_length"]), (200, digest, len(body)))
        self.assertEqual((Path(self.temporary.name) / digest).read_bytes(), body)

    def test_rejects_unbound_object_digest(self) -> None:
        status, _ = self.request_json("PUT", f"/ci/artifacts/event/run/job/1/a/{'0' * 64}", b"different")
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()

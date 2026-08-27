from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ACTIVATION_DIR = Path(__file__).resolve().parents[1]


def load_module():
    path = ACTIVATION_DIR / "capability-parity.py"
    spec = importlib.util.spec_from_file_location("mgact_capability_parity", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


PARITY = load_module()
POLICY = PARITY.validate_policy(
    json.loads((ACTIVATION_DIR / "capability-parity-policy.json").read_text())
)


def descriptor(path: str, owner: str, marker: int) -> dict[str, object]:
    return {
        "path": path,
        "present": True,
        "file_type": "regular",
        "character_class": "lowercase-hex-or-json",
        "length": 64 + marker,
        "mode": "0600",
        "owner": owner,
        "group": owner,
        "nlink": 1,
        "device": marker,
        "inode": 1000 + marker,
        "sha256_prefix": f"{marker:012x}",
    }


def manifest(role: str) -> dict[str, object]:
    markers = {"reference": 10, "mempool": 20, "genesis": 30}
    marker = markers[role]
    slug = {"reference": "codex-r", "mempool": "mempool", "genesis": "genesis"}[role]
    display = {"reference": "Sats Codex-R", "mempool": "Mempool", "genesis": "Genesis"}[role]
    pubkey = f"{marker:064x}"
    user = "victor" if role == "reference" else f"buzz-{slug}"
    home = "/home/victor" if role == "reference" else f"/home/{user}"
    runtime_root = "/run/user/1000" if role == "reference" else f"/run/buzz-agents-{slug}"
    roots = {
        "home": home,
        "codex_home": f"{home}/.codex",
        "xdg_config": f"{home}/.config",
        "xdg_cache": f"{home}/.cache",
        "xdg_state": f"{home}/.local/state",
        "temporary": f"{home}/.tmp",
        "runtime": runtime_root,
        "state": f"{home}/.local/state/buzz-acp",
        "environment": f"/etc/buzz-agents/{slug}.env",
        "prompt": f"/etc/buzz-agents/prompts/{slug}.md",
        "credential": f"/etc/buzz-agents/credentials/{slug}.key",
        "profile_event": f"{home}/.local/state/buzz/profile-event.json",
        "directory_event": f"{home}/.local/state/buzz/directory-event.json",
        "acceptance": f"{home}/.local/state/buzz/acceptance.json",
        "claim": f"{home}/.local/state/buzz/claim.json",
        "install_receipt": f"{home}/.local/state/buzz/install.json",
        "rollback_receipt": f"{home}/.local/state/buzz/rollback.json",
        "backup": f"{home}/.local/state/buzz/backup",
        "activation_receipt": f"{home}/.local/state/buzz/activation.json",
    }
    shared_hashes = {name: f"{index:064x}" for index, name in enumerate(sorted(PARITY.COMMON_CLOSURE), 100)}
    closure = {
        name: {
            "path": PARITY.EXPECTED_CANDIDATE_CLOSURE_PATHS[name],
            "sha256": shared_hashes[name],
            "mode": "0755",
            "owner": "root",
            "group": "root",
        }
        for name in PARITY.COMMON_CLOSURE
    }
    closure["service_unit"] = {
        "path": f"/etc/systemd/system/buzz-agent@{slug}.service",
        "sha256": f"{marker + 100:064x}",
        "mode": "0644",
        "owner": "root",
        "group": "root",
    }
    channels = [
        {"channel_id": "open-a", "visibility": "open", "scope": "open", "role": "member", "archived": False, "eligible": True},
        {"channel_id": "private-a", "visibility": "private", "scope": "sats-victor-private", "role": "member", "archived": False, "eligible": True},
        {"channel_id": "archived-a", "visibility": "open", "scope": "open", "role": "member", "archived": True, "eligible": False},
    ]
    hardening = copy.deepcopy(PARITY.REQUIRED_HARDENING)
    hardening.update({"User": user, "Group": user, "WorkingDirectory": home})
    host_access = copy.deepcopy(POLICY["approved_exceptions"].get(slug, {"host_access": []})["host_access"])
    private_descriptor = descriptor(roots["credential"], "root" if role != "reference" else user, marker)
    if role != "reference":
        private_descriptor.update(
            {"length": 64, "character_class": "lowercase-hex", "group": "root"}
        )
    writable = (
        list(roots.values())[:8]
        if role == "reference"
        else [
            roots["codex_home"], roots["xdg_config"], roots["xdg_cache"], roots["xdg_state"],
            roots["temporary"], roots["runtime"], roots["state"],
        ]
    )
    return {
        "schema": PARITY.MANIFEST_SCHEMA,
        "captured_at": f"2026-08-27T00:00:{marker:02d}Z",
        "slug": slug,
        "display_name": display,
        "identity": {
            "pubkey": pubkey,
            "owner_pubkey": POLICY["owner_pubkey"],
            "unix_user": user,
            "unix_group": user,
            "profile_author_pubkey": pubkey,
            "auth_tag": {
                "present": True,
                "type": "nip-oa",
                "owner_pubkey": POLICY["owner_pubkey"],
                "subject_pubkey": pubkey,
                "character_class": "bech32-or-json",
                "length": 200 + marker,
                "sha256_prefix": f"{marker + 1000:012x}",
            },
        },
        "roots": roots,
        "runtime": {
            "model": "gpt-5.6-sol",
            "reasoning_effort": "high",
            "agent_command": "/usr/local/libexec/buzz/codex-acp",
            "mcp_command": "/usr/local/libexec/buzz/buzz-dev-mcp",
            "codex_config": "managed",
            "memory": True,
            "agents": 1,
            "subscribe": "mentions",
            "multiple_event_handling": "steer",
            "context_message_limit": 12,
            "idle_timeout": 620,
            "max_turn_duration": 7200,
            "turn_liveness_secs": 10,
            "permission_mode": "bypass-permissions",
            "environment_keys": ["BUZZ_ACP_AGENT_COMMAND", "BUZZ_ACP_ALLOWED_RESPOND_TO", "BUZZ_ACP_RESPOND_TO", "BUZZ_ACP_STATE_DIR", "CODEX_PATH"],
            "closure": closure,
        },
        "response_policy": {"respond_to": "owner-only", "allowed_respond_to": "owner-only", "responder_allowlist": [], "owner_pubkey": POLICY["owner_pubkey"]},
        "channels": channels,
        "directory": {
            "self_published": True,
            "author_pubkey": pubkey,
            "agent_type": "codex",
            "respond_to": "owner-only",
            "allowed_respond_to": "owner-only",
            "responder_allowlist": [],
            "channel_ids": ["open-a", "private-a"],
            "auth_owner_pubkey": POLICY["owner_pubkey"],
            "auth_subject_pubkey": pubkey,
            "event_id": f"{marker + 2000:064x}",
        },
        "systemd": {
            "properties": hardening,
            "read_write_paths": writable,
            "read_only_paths": [],
            "address_families": ["AF_UNIX", "AF_INET", "AF_INET6"],
            "executable_paths": ["/usr/local/libexec/buzz/codex-acp", "/usr/local/libexec/buzz/codex"],
            "host_access": host_access,
        },
        "secret_files": {
            "buzz_private_key": private_descriptor,
            "codex_auth": descriptor(f"{roots['codex_home']}/auth.json", user, marker + 1),
        },
        "prompt": {
            "sha256": f"{marker + 3000:064x}",
            "policy_sha256": f"{9999:064x}",
            "identity": display,
            "mission": f"{display} mission",
            "session_title": f"{display} GPT-5.6 Sol high",
        },
        "receipts": [
            roots["acceptance"], roots["claim"], roots["install_receipt"], roots["rollback_receipt"],
            roots["backup"], roots["activation_receipt"],
        ],
    }


class CapabilityParityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.reference = manifest("reference")
        self.mempool = manifest("mempool")
        self.genesis = manifest("genesis")

    def compare(self):
        return PARITY.compare_set(self.reference, self.mempool, self.genesis, POLICY)

    def test_three_redacted_manifests_have_empty_unexplained_diff(self) -> None:
        receipt = self.compare()
        self.assertEqual(receipt["status"], "PASS")
        self.assertEqual(receipt["unexplained_differences"], {"mempool": [], "genesis": []})
        self.assertTrue(all(receipt["checks"].values()))

    def test_owner_only_policy_and_directory_are_required(self) -> None:
        self.mempool["response_policy"]["respond_to"] = "allowlist"
        self.mempool["response_policy"]["responder_allowlist"] = [POLICY["owner_pubkey"]]
        with self.assertRaisesRegex(PARITY.ParityError, "owner-only"):
            self.compare()

    def test_shared_pubkey_auth_tag_inode_path_or_material_fails(self) -> None:
        mutations = (
            ("pubkey", lambda: self.genesis["identity"].__setitem__("pubkey", self.mempool["identity"]["pubkey"])),
            ("auth tags", lambda: self.genesis["identity"]["auth_tag"].__setitem__("sha256_prefix", self.mempool["identity"]["auth_tag"]["sha256_prefix"])),
            ("inode", lambda: self.genesis["secret_files"]["codex_auth"].update({"device": self.mempool["secret_files"]["codex_auth"]["device"], "inode": self.mempool["secret_files"]["codex_auth"]["inode"]})),
            ("descriptor mismatch", lambda: self.genesis["secret_files"]["codex_auth"].__setitem__("path", self.mempool["secret_files"]["codex_auth"]["path"])),
            ("material", lambda: self.genesis["secret_files"]["codex_auth"].__setitem__("sha256_prefix", self.mempool["secret_files"]["codex_auth"]["sha256_prefix"])),
        )
        for expected, mutate in mutations:
            with self.subTest(expected=expected):
                self.setUp()
                mutate()
                with self.assertRaisesRegex(PARITY.ParityError, expected):
                    self.compare()

    def test_runtime_channel_role_and_directory_drift_fail_closed(self) -> None:
        self.mempool["runtime"]["closure"]["codex_cli"]["sha256"] = "f" * 64
        receipt = self.compare()
        self.assertEqual(receipt["status"], "BLOCKED")
        self.assertIn("/runtime/closure/codex_cli/sha256", receipt["unexplained_differences"]["mempool"])
        self.setUp()
        self.genesis["channels"][1]["role"] = "admin"
        with self.assertRaisesRegex(PARITY.ParityError, "role is not member"):
            self.compare()
        self.setUp()
        self.genesis["directory"]["channel_ids"] = ["open-a"]
        with self.assertRaisesRegex(PARITY.ParityError, "directory channels"):
            self.compare()

    def test_broad_host_access_and_unapproved_netlink_fail(self) -> None:
        self.genesis["systemd"]["read_write_paths"].append("/home/victor")
        with self.assertRaisesRegex(PARITY.ParityError, "unapproved writable path"):
            self.compare()
        self.setUp()
        self.genesis["systemd"]["address_families"].append("AF_NETLINK")
        with self.assertRaisesRegex(PARITY.ParityError, "AF_NETLINK"):
            self.compare()

    def test_observation_builder_rejects_secret_bearing_fields(self) -> None:
        observation = copy.deepcopy(self.mempool)
        observation["schema"] = PARITY.OBSERVATION_SCHEMA
        observation["private_key"] = "1" * 64
        with self.assertRaisesRegex(PARITY.ParityError, "secret-bearing field"):
            PARITY.build_manifest(observation, "mempool", POLICY)


if __name__ == "__main__":
    unittest.main()

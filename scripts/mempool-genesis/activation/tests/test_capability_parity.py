from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

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
REPO_ROOT = ACTIVATION_DIR.parents[2]


def descriptor(path: str, owner: str, marker: int) -> dict[str, object]:
    return {
        "path_class": path,
        "present": True,
        "file_type": "regular",
        "character_class": "utf8-json",
        "length": 64 + marker,
        "mode": "0600",
        "owner": owner,
        "group": owner,
        "nlink": 1,
        "device": marker,
        "inode": 1000 + marker,
        "sha256_prefix": f"{marker:012x}",
    }


def ops_manifest(signer: Path, verifier: Path) -> dict[str, object]:
    records = []
    for path, scope in (
        (signer, "owner Schnorr parity receipt signing from a sanctioned private file"),
        (verifier, "owner Schnorr parity receipt verification from standard input"),
    ):
        sha256, metadata = PARITY.regular_sha256(path)
        records.append(
            {
                "target": str(path),
                "source": f"synthetic/{path.name}",
                "mode": "0700",
                "uid": metadata.st_uid,
                "gid": metadata.st_gid,
                "sha256": sha256,
                "scope": scope,
            }
        )
    return {
        "source_commit": "a" * 40,
        "source_tree": "b" * 40,
        "package_digest": "c" * 64,
        "runtime_artifact_fingerprint": "d" * 64,
        "capability_parity": {
            "canonical_json_contract": PARITY.CANONICAL_JSON_CONTRACT,
            "reference_channels_sha256": PARITY.digest(POLICY["reference_channels"]),
            "eligible_channels_sha256": PARITY.digest(POLICY["eligible_channels"]),
            "authority_exclusions_sha256": PARITY.digest(POLICY["authority_exclusions"]),
        },
        "runtime_targets": [
            {
                "target": PARITY.ROOT_VERIFIER_TARGET,
                "source": "synthetic/root-verifier",
                "mode": "0755",
                "uid": 0,
                "gid": 0,
                "sha256": "e" * 64,
            }
        ],
        "ops_targets": records,
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
    reviewed_channels = POLICY["reference_channels"] if role == "reference" else POLICY["eligible_channels"]
    channels = [
        {**channel, "archived": False, "eligible": True}
        for channel in reviewed_channels
    ] + [
        {"channel_id": "archived-a", "visibility": "open", "scope": "open", "role": "member", "archived": True, "eligible": False},
    ]
    hardening = copy.deepcopy(PARITY.REQUIRED_HARDENING)
    hardening.update({"User": user, "Group": user, "WorkingDirectory": home})
    host_access = copy.deepcopy(POLICY["approved_exceptions"].get(slug, {"host_access": []})["host_access"])
    private_descriptor = descriptor(f"{slug}:buzz-private-key", "root" if role != "reference" else user, marker)
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
            "environment_keys": ["BUZZ_ACP_AGENT_COMMAND", "BUZZ_ACP_ALLOWED_RESPOND_TO", "BUZZ_ACP_RESPOND_TO", "BUZZ_ACP_RESPOND_TO_ALLOWLIST", "BUZZ_ACP_STATE_DIR", "CODEX_PATH"],
            "closure": closure,
        },
        "response_policy": copy.deepcopy(POLICY["response_policy"]),
        "channels": channels,
        "profile": {
            "author_pubkey": pubkey,
            "display_name": display,
            "event_id": f"{marker + 1500:064x}",
            "auth_owner_pubkey": POLICY["owner_pubkey"],
            "auth_subject_pubkey": pubkey,
        },
        "directory": {
            "self_published": True,
            "author_pubkey": pubkey,
            "agent_type": "codex",
            "respond_to": "allowlist",
            "allowed_respond_to": "allowlist",
            "responder_allowlist": [POLICY["owner_pubkey"]],
            "channel_ids": [channel["channel_id"] for channel in reviewed_channels],
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
            "codex_auth": descriptor(f"{slug}:codex-auth", user, marker + 1),
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
        self.authority = self.authority_receipt()

    def authority_receipt(self) -> dict[str, object]:
        now = int(time.time())
        exclusion = POLICY["authority_exclusions"][0]
        value = {
            "schema": PARITY.AUTHORITY_RECEIPT_SCHEMA,
            "canonical_json_contract": PARITY.CANONICAL_JSON_CONTRACT,
            "captured_at": now,
            "expires_at": now + 300,
            "relay": "wss://relay.example.test",
            "source_commit": "a" * 40,
            "source_tree": "b" * 40,
            "package_digest": "c" * 64,
            "policy_sha256": PARITY.digest(POLICY),
            "reference_channels": POLICY["reference_channels"],
            "reference_channels_sha256": PARITY.digest(POLICY["reference_channels"]),
            "eligible_channels": POLICY["eligible_channels"],
            "eligible_channels_sha256": PARITY.digest(POLICY["eligible_channels"]),
            "authority_exclusions": POLICY["authority_exclusions"],
            "authority_exclusions_sha256": PARITY.digest(POLICY["authority_exclusions"]),
            "candidate_pubkeys": {
                "mempool": self.mempool["identity"]["pubkey"],
                "genesis": self.genesis["identity"]["pubkey"],
            },
            "observations": [{
                "channel_id": exclusion["channel_id"],
                "visibility": exclusion["visibility"],
                "archived": exclusion["archived"],
                "actor_role": exclusion["expected_actor_role"],
                "reference_present": exclusion["expected_reference_present"],
                "reference_role": exclusion["expected_reference_role"],
                "candidate_presence": {"genesis": "absent", "mempool": "absent"},
            }],
        }
        value["payload_sha256"] = PARITY.digest(value)
        return value

    def compare(self):
        return PARITY.compare_set(
            self.reference, self.mempool, self.genesis, POLICY, self.authority
        )

    def test_shared_canonical_json_contract_vectors(self) -> None:
        fixture = json.loads(
            (REPO_ROOT / "crates/buzz-agent-key-handoff/tests/fixtures/parity-canonical-json-v1.json").read_text()
        )
        self.assertEqual(fixture["contract"], PARITY.CANONICAL_JSON_CONTRACT)
        for case in fixture["positive"]:
            with self.subTest(case=case["name"]):
                self.assertEqual(PARITY.canonical_json(case["value"]).decode(), case["canonical"])
        for case in fixture["negative"]:
            with self.subTest(case=case["name"]), self.assertRaises(PARITY.ParityError):
                PARITY.canonical_json(json.loads(case["json"]))

    def test_policy_v2_partition_is_exact_sorted_unique_and_disjoint(self) -> None:
        reference_ids = [item["channel_id"] for item in POLICY["reference_channels"]]
        eligible_ids = [item["channel_id"] for item in POLICY["eligible_channels"]]
        exclusion_ids = [item["channel_id"] for item in POLICY["authority_exclusions"]]
        self.assertEqual(reference_ids, sorted(reference_ids))
        self.assertEqual(eligible_ids, sorted(eligible_ids))
        self.assertEqual(exclusion_ids, sorted(exclusion_ids))
        self.assertEqual(len(reference_ids), len(set(reference_ids)))
        self.assertEqual(len(eligible_ids), len(set(eligible_ids)))
        self.assertTrue(set(eligible_ids).isdisjoint(exclusion_ids))
        self.assertEqual(set(reference_ids), set(eligible_ids) | set(exclusion_ids))

        for label, mutate in (
            (
                "overlap",
                lambda value: value["eligible_channels"].append(
                    copy.deepcopy(value["reference_channels"][-1])
                ),
            ),
            ("missing", lambda value: value["reference_channels"].pop()),
            (
                "unsorted",
                lambda value: value["eligible_channels"].reverse(),
            ),
        ):
            drifted = copy.deepcopy(POLICY)
            mutate(drifted)
            with self.subTest(label=label), self.assertRaises(PARITY.ParityError):
                PARITY.validate_policy(drifted)

    def test_authority_receipt_drift_matrix_fails_closed(self) -> None:
        cases = {
            "stale": lambda value: value.update(captured_at=0, expires_at=1),
            "unbound candidate": lambda value: value["candidate_pubkeys"].update(mempool="f" * 64),
            "visibility": lambda value: value["observations"][0].update(visibility="private"),
            "archived": lambda value: value["observations"][0].update(archived=True),
            "actor role": lambda value: value["observations"][0].update(actor_role="owner"),
            "Codex-R absent": lambda value: value["observations"][0].update(reference_present=False),
            "Codex-R role": lambda value: value["observations"][0].update(reference_role="member"),
            "candidate present": lambda value: value["observations"][0]["candidate_presence"].update(mempool="present"),
        }
        for label, mutate in cases.items():
            drifted = copy.deepcopy(self.authority)
            mutate(drifted)
            drifted["payload_sha256"] = PARITY.digest({
                key: value for key, value in drifted.items() if key != "payload_sha256"
            })
            with self.subTest(label=label), self.assertRaises(PARITY.ParityError):
                PARITY.compare_set(
                    self.reference, self.mempool, self.genesis, POLICY, drifted
                )

        tampered = copy.deepcopy(self.authority)
        tampered["relay"] = "wss://tampered.example.test"
        with self.assertRaisesRegex(PARITY.ParityError, "payload digest"):
            PARITY.compare_set(
                self.reference, self.mempool, self.genesis, POLICY, tampered
            )

    def capture_fixture(self, root: Path) -> tuple[dict[str, object], tuple[str, str, str]]:
        reference = manifest("reference")
        pubkey = reference["identity"]["pubkey"]
        auth_tag = "owner1syntheticcaptureauth"
        private_key = "a" * 64
        codex_auth = '{"session":"synthetic-capture"}'
        environment = {
            "BUZZ_ACP_MODEL": "gpt-5.6-sol[high]",
            "BUZZ_ACP_AGENT_COMMAND": "/usr/local/libexec/buzz/codex-acp",
            "BUZZ_ACP_MCP_COMMAND": "/usr/local/libexec/buzz/buzz-dev-mcp",
            "BUZZ_ACP_MEMORY": "true",
            "BUZZ_ACP_AGENTS": "1",
            "BUZZ_ACP_SUBSCRIBE": "mentions",
            "BUZZ_ACP_MULTIPLE_EVENT_HANDLING": "steer",
            "BUZZ_ACP_CONTEXT_MESSAGE_LIMIT": "12",
            "BUZZ_ACP_IDLE_TIMEOUT": "620",
            "BUZZ_ACP_MAX_TURN_DURATION": "7200",
            "BUZZ_ACP_TURN_LIVENESS_SECS": "10",
            "BUZZ_ACP_PERMISSION_MODE": "bypass-permissions",
            "BUZZ_ACP_RESPOND_TO": "allowlist",
            "BUZZ_ACP_ALLOWED_RESPOND_TO": "allowlist",
            "BUZZ_ACP_RESPOND_TO_ALLOWLIST": POLICY["owner_pubkey"],
            "BUZZ_ACP_AGENT_OWNER": POLICY["owner_pubkey"],
            "BUZZ_ACP_AUTH_TAG": auth_tag,
        }

        def write(name: str, payload: str, mode: int = 0o600) -> Path:
            path = root / name
            path.write_text(payload)
            path.chmod(mode)
            return path

        environment_path = write(
            "reference.env", "".join(f"{key}={value}\n" for key, value in environment.items())
        )
        prompt_path = write("prompt.md", "Synthetic reference prompt\n")
        prompt_policy_path = write("prompt-policy.md", "Owner-only response policy\n")
        config_path = write("config.toml", 'model = "gpt-5.6-sol"\nreasoning_effort = "high"\n')
        key_path = write("reference.key", private_key)
        auth_path = write("auth.json", codex_auth)
        channels_path = write("channels.json", json.dumps(reference["channels"]))
        profile_path = write("profile.json", json.dumps(reference["profile"]))
        directory_path = write("directory.json", json.dumps(reference["directory"]))
        systemd_path = write(
            "systemd.json",
            json.dumps(
                {
                    key: reference["systemd"][key]
                    for key in (
                        "properties", "read_write_paths", "read_only_paths",
                        "address_families", "executable_paths",
                    )
                }
            ),
        )
        closure_paths = {
            name: str(write(f"closure-{name}", name, 0o755 if name != "service_unit" else 0o644))
            for name in PARITY.CLOSURE_KEYS
        }
        environment["BUZZ_ACP_AGENT_COMMAND"] = closure_paths["codex_acp"]
        environment["BUZZ_ACP_MCP_COMMAND"] = closure_paths["mcp"]
        environment_path.write_text(
            "".join(f"{key}={value}\n" for key, value in environment.items())
        )
        spec = {
            "schema": PARITY.CAPTURE_SCHEMA,
            "role": "reference",
            "captured_at": reference["captured_at"],
            "slug": reference["slug"],
            "display_name": reference["display_name"],
            "identity": {
                key: reference["identity"][key]
                for key in ("pubkey", "owner_pubkey", "unix_user", "unix_group", "profile_author_pubkey")
            },
            "roots": reference["roots"],
            "sources": {
                "environment_file": str(environment_path),
                "prompt_file": str(prompt_path),
                "prompt_policy_file": str(prompt_policy_path),
                "codex_config_file": str(config_path),
                "buzz_private_key": {"path": str(key_path), "path_class": "codex-r:buzz-private-key"},
                "codex_auth": {"path": str(auth_path), "path_class": "codex-r:codex-auth"},
                "auth_tag": {"kind": "environment", "path": str(environment_path), "key": "BUZZ_ACP_AUTH_TAG"},
                "systemd": {"kind": "file", "path": str(systemd_path)},
                "channels": {"kind": "file", "path": str(channels_path)},
                "profile": {"kind": "file", "path": str(profile_path)},
                "directory": {"kind": "file", "path": str(directory_path)},
                "closure": closure_paths,
            },
            "prompt": {
                key: reference["prompt"][key] for key in ("identity", "mission", "session_title")
            },
            "receipts": reference["receipts"],
        }
        return spec, (auth_tag, private_key, codex_auth)

    def test_three_redacted_manifests_have_empty_unexplained_diff(self) -> None:
        receipt = self.compare()
        self.assertEqual(receipt["status"], "PASS")
        self.assertEqual(receipt["unexplained_differences"], {"mempool": [], "genesis": []})
        self.assertTrue(all(receipt["checks"].values()))

    def test_codex_r_allowlist_policy_and_directory_are_required(self) -> None:
        self.mempool["response_policy"]["respond_to"] = "owner-only"
        self.mempool["response_policy"]["responder_allowlist"] = []
        with self.assertRaisesRegex(PARITY.ParityError, "Codex-R"):
            self.compare()

    def test_shared_pubkey_auth_tag_inode_path_or_material_fails(self) -> None:
        mutations = (
            ("pubkey", lambda: self.genesis["identity"].__setitem__("pubkey", self.mempool["identity"]["pubkey"])),
            ("auth tags", lambda: self.genesis["identity"]["auth_tag"].__setitem__("sha256_prefix", self.mempool["identity"]["auth_tag"]["sha256_prefix"])),
            ("inode", lambda: self.genesis["secret_files"]["codex_auth"].update({"device": self.mempool["secret_files"]["codex_auth"]["device"], "inode": self.mempool["secret_files"]["codex_auth"]["inode"]})),
            ("descriptor mismatch", lambda: self.genesis["secret_files"]["codex_auth"].__setitem__("path_class", self.mempool["secret_files"]["codex_auth"]["path_class"])),
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
        self.genesis["directory"]["channel_ids"] = [POLICY["eligible_channels"][0]["channel_id"]]
        with self.assertRaisesRegex(PARITY.ParityError, "directory channels"):
            self.compare()

    def test_identity_local_state_prompt_and_events_are_unique(self) -> None:
        mutations = (
            ("Unix users", lambda: self.reference["identity"].__setitem__("unix_user", self.mempool["identity"]["unix_user"])),
            ("homes", lambda: self.reference["roots"].__setitem__("home", self.mempool["roots"]["home"])),
            ("state roots", lambda: self.reference["roots"].__setitem__("state", self.mempool["roots"]["state"])),
            ("prompt paths", lambda: self.reference["roots"].__setitem__("prompt", self.mempool["roots"]["prompt"])),
            ("prompts", lambda: self.reference["prompt"].__setitem__("sha256", self.mempool["prompt"]["sha256"])),
            ("directory events", lambda: self.reference["directory"].__setitem__("event_id", self.mempool["directory"]["event_id"])),
            ("profile events", lambda: self.reference["profile"].__setitem__("event_id", self.mempool["profile"]["event_id"])),
            ("receipt", lambda: self.reference["receipts"].__setitem__(0, self.mempool["receipts"][0])),
        )
        for expected, mutate in mutations:
            with self.subTest(expected=expected):
                self.setUp()
                mutate()
                with self.assertRaisesRegex(PARITY.ParityError, expected):
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

    def test_secret_scanner_allows_benign_token_limits_and_rejects_secrets(self) -> None:
        PARITY.reject_secret_values(
            {"tool_output_token_limit": 4000, "max_output_tokens": 1000, "token_budget": 25}
        )
        for field in (
            "access_token", "api_key", "private_key", "signing_key", "client_secret",
            "oauth_token", "cookie",
        ):
            with self.subTest(field=field), self.assertRaisesRegex(
                PARITY.ParityError, "secret-bearing field"
            ):
                PARITY.reject_secret_values({field: "redacted"})
        for field in (
            "private_key_tool_output_token_limit",
            "tool_output_token_limit_private_key",
            "access_token_tool_output_token_limit",
        ):
            with self.subTest(bypass=field), self.assertRaisesRegex(
                PARITY.ParityError, "secret-bearing field"
            ):
                PARITY.reject_secret_values({field: "a" * 64})

    def test_candidate_closure_hashes_physical_source_but_reports_logical_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sources = {}
            for component in PARITY.CLOSURE_KEYS:
                source = root / component
                source.write_text(component)
                source.chmod(0o644 if component == "service_unit" else 0o755)
                sources[component] = str(source)
            closure = PARITY.capture_closure(sources, "mempool")
        self.assertEqual(
            closure["buzz_acp"]["path"], PARITY.EXPECTED_CANDIDATE_CLOSURE_PATHS["buzz_acp"]
        )
        self.assertRegex(closure["buzz_acp"]["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(closure["service_unit"]["path"], str(root / "service_unit"))

    def test_capture_fixture_is_deterministic_and_secret_safe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            spec, secret_values = self.capture_fixture(Path(temporary))
            first = PARITY.capture_manifest(spec, POLICY)
            second = PARITY.capture_manifest(spec, POLICY)
        self.assertEqual(PARITY.canonical_json(first), PARITY.canonical_json(second))
        serialized = PARITY.canonical_json(first).decode()
        for secret in secret_values:
            self.assertNotIn(secret, serialized)
        self.assertEqual(first["secret_files"]["buzz_private_key"]["path_class"], "codex-r:buzz-private-key")
        self.assertNotIn("path", first["secret_files"]["buzz_private_key"])
        self.assertEqual(
            first["response_policy"]["responder_allowlist"], [POLICY["owner_pubkey"]]
        )

    def test_capture_rejects_archimedes_rachel_private_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            spec, _secret_values = self.capture_fixture(Path(temporary))
            channels_path = Path(spec["sources"]["channels"]["path"])
            channels = json.loads(channels_path.read_text())
            channels.append(
                {
                    "channel_id": "foreign-private",
                    "visibility": "private",
                    "scope": "archimedes-rachel-private",
                    "role": "member",
                    "archived": False,
                    "eligible": True,
                }
            )
            channels_path.write_text(json.dumps(channels))
            with self.assertRaisesRegex(PARITY.ParityError, "ineligible private-channel"):
                PARITY.capture_manifest(spec, POLICY)

    def test_live_systemd_adapter_never_requests_environment(self) -> None:
        calls: list[list[str]] = []

        def observe(argv, _stdin_payload=None):
            calls.append(argv)
            property_name = next(item for item in argv if item.startswith("--property=")).removeprefix(
                "--property="
            )
            values = {
                "CapabilityBoundingSet": "",
                "AmbientCapabilities": "",
                "ReadWritePaths": "/run/fixture",
                "ReadOnlyPaths": "/usr/local/libexec/buzz",
                "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6",
            }
            return f"{values.get(property_name, 'yes')}\n".encode()

        with mock.patch.object(PARITY, "safe_command", side_effect=observe):
            result = PARITY.systemd_capture(
                {
                    "kind": "live", "scope": "system",
                    "unit": "buzz-agent@mempool.service", "executable_paths": [],
                }
            )
        self.assertEqual(result["address_families"], ["AF_UNIX", "AF_INET", "AF_INET6"])
        self.assertTrue(calls)
        self.assertNotIn("Environment", " ".join(argument for call in calls for argument in call))
        calls.clear()
        with mock.patch.object(PARITY, "safe_command", side_effect=observe):
            PARITY.systemd_capture(
                {
                    "kind": "live", "scope": "user",
                    "unit": "buzz-sats-agent@sats-codex-r.service", "executable_paths": [],
                }
            )
        self.assertTrue(all("--user" in call for call in calls))

    def test_command_json_adapter_and_signed_receipt_contract(self) -> None:
        command_value = [{"channel_id": "open-a"}]
        command = PARITY.json_source(
            {"kind": "command", "argv": ["/usr/bin/printf", "%s", json.dumps(command_value)]},
            "fixture command",
        )
        self.assertEqual(command, command_value)
        receipt = self.compare()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            signer = root / "buzz-parity-owner-signer"
            verifier = root / "buzz-parity-owner-verifier"
            signer.write_text(
                "#!/usr/bin/python3\n"
                "import json,sys\n"
                "value=sys.stdin.read().strip()\n"
                f"print(json.dumps({{'schema':'{PARITY.SIGNATURE_SCHEMA}',"
                "'algorithm':'schnorr-secp256k1',"
                f"'signer_pubkey':'{POLICY['owner_pubkey']}',"
                "'payload_sha256':value,'signature':'0'*128,'signed_at':'2026-08-27T00:00:00Z'}))\n"
            )
            verifier.write_text(
                "#!/usr/bin/python3\n"
                "import json,sys\n"
                "value=json.load(sys.stdin)\n"
                "raise SystemExit(0 if value['verified'] in (False,True) else 1)\n"
            )
            signer.chmod(0o700)
            verifier.chmod(0o700)
            manifest = ops_manifest(signer, verifier)
            sealed = PARITY.seal_receipt(
                receipt, POLICY, [str(signer)], [str(verifier)], manifest
            )
            verifier.chmod(0o000)
            with mock.patch.object(PARITY, "run_runtime_verifier") as runtime_verifier:
                verified = PARITY.verify_sealed_receipt(
                    sealed, POLICY, manifest, Path(PARITY.ROOT_VERIFIER_TARGET)
                )
            runtime_verifier.assert_called_once()
            self.assertEqual(
                verified["receipt"]["activation_binding"],
                PARITY.activation_binding(manifest),
            )
            wrong = copy.deepcopy(manifest)
            wrong["ops_targets"][0]["sha256"] = "f" * 64
            with self.assertRaisesRegex(PARITY.ParityError, "manifest-bound"):
                PARITY.seal_receipt(
                    receipt, POLICY, [str(signer)], [str(verifier)], wrong
                )
            stub = root / "buzz-parity-owner-signer-stub"
            stub.write_bytes(signer.read_bytes())
            stub.chmod(0o700)
            with self.assertRaisesRegex(PARITY.ParityError, "no unique|manifest-bound"):
                PARITY.seal_receipt(
                    receipt, POLICY, [str(stub)], [str(verifier)], manifest
                )
            rebound = copy.deepcopy(manifest)
            rebound["package_digest"] = "e" * 64
            with self.assertRaisesRegex(PARITY.ParityError, "source/package binding mismatch"):
                PARITY.verify_sealed_receipt(
                    sealed, POLICY, rebound, Path(PARITY.ROOT_VERIFIER_TARGET)
                )
        self.assertTrue(sealed["verified"])
        self.assertRegex(sealed["sealed_sha256"], r"^[0-9a-f]{64}$")
        tampered = copy.deepcopy(receipt)
        tampered["checks"]["runtime_closure"] = False
        with self.assertRaisesRegex(PARITY.ParityError, "digest mismatch"):
            PARITY.validate_receipt_digest(tampered)

    def test_open_sealed_runtime_verifier_rejects_drift_and_freezes_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            verifier = root / PARITY.ROOT_VERIFIER_TARGET.lstrip("/")
            verifier.parent.mkdir(parents=True)
            original = b"#!/bin/sh\nexit 0\n"
            verifier.write_bytes(original)
            verifier.chmod(0o755)
            sha256, _metadata = PARITY.regular_sha256(verifier)
            record = {
                "target": PARITY.ROOT_VERIFIER_TARGET,
                "source": "install-root/usr/local/libexec/buzz/buzz-agent-key-handoff",
                "mode": "0755",
                "uid": 0,
                "gid": 0,
                "sha256": sha256,
            }
            manifest = {"runtime_targets": [record]}
            real_fstat = PARITY.os.fstat

            def metadata(*, uid=0, gid=0):
                def observe(descriptor):
                    fields = list(real_fstat(descriptor))
                    fields[4] = uid
                    fields[5] = gid
                    return os.stat_result(fields)

                return observe

            with mock.patch.object(PARITY.os, "fstat", side_effect=metadata()):
                descriptor = PARITY.open_sealed_runtime_verifier(verifier, manifest, root)
            try:
                verifier.write_bytes(b"mutated after freeze\n")
                os.lseek(descriptor, 0, os.SEEK_SET)
                self.assertEqual(os.read(descriptor, len(original) + 32), original)
                with self.assertRaises(OSError):
                    os.write(descriptor, b"x")
            finally:
                os.close(descriptor)
            verifier.write_bytes(original)
            verifier.chmod(0o755)

            with self.assertRaisesRegex(PARITY.ParityError, "reviewed runtime target"):
                PARITY.open_sealed_runtime_verifier(root / "wrong", manifest, root)
            with self.assertRaisesRegex(PARITY.ParityError, "inventory is absent"):
                PARITY.open_sealed_runtime_verifier(verifier, {}, root)
            with self.assertRaisesRegex(PARITY.ParityError, "no unique"):
                PARITY.open_sealed_runtime_verifier(verifier, {"runtime_targets": []}, root)
            wrong_target = copy.deepcopy(record)
            wrong_target["target"] = f"{PARITY.ROOT_VERIFIER_TARGET}.other"
            with self.assertRaisesRegex(PARITY.ParityError, "no unique"):
                PARITY.open_sealed_runtime_verifier(
                    verifier, {"runtime_targets": [wrong_target]}, root
                )
            with self.assertRaisesRegex(PARITY.ParityError, "no unique"):
                PARITY.open_sealed_runtime_verifier(
                    verifier, {"runtime_targets": [record, copy.deepcopy(record)]}, root
                )

            for field, value in (("mode", "0700"), ("uid", 1000), ("gid", 1000)):
                drifted = copy.deepcopy(record)
                drifted[field] = value
                with self.subTest(record_field=field), self.assertRaisesRegex(
                    PARITY.ParityError, "manifest ownership, mode, or digest is unsafe"
                ):
                    PARITY.open_sealed_runtime_verifier(
                        verifier, {"runtime_targets": [drifted]}, root
                    )

            with mock.patch.object(PARITY.os, "fstat", side_effect=metadata(uid=1000)):
                with self.assertRaisesRegex(PARITY.ParityError, "metadata is unsafe"):
                    PARITY.open_sealed_runtime_verifier(verifier, manifest, root)
            with mock.patch.object(PARITY.os, "fstat", side_effect=metadata(gid=1000)):
                with self.assertRaisesRegex(PARITY.ParityError, "metadata is unsafe"):
                    PARITY.open_sealed_runtime_verifier(verifier, manifest, root)
            verifier.chmod(0o700)
            with mock.patch.object(PARITY.os, "fstat", side_effect=metadata()):
                with self.assertRaisesRegex(PARITY.ParityError, "metadata is unsafe"):
                    PARITY.open_sealed_runtime_verifier(verifier, manifest, root)
            verifier.chmod(0o755)
            hardlink = root / "runtime-verifier-hardlink"
            os.link(verifier, hardlink)
            with mock.patch.object(PARITY.os, "fstat", side_effect=metadata()):
                with self.assertRaisesRegex(PARITY.ParityError, "metadata is unsafe"):
                    PARITY.open_sealed_runtime_verifier(verifier, manifest, root)
            hardlink.unlink()

            wrong_digest = copy.deepcopy(record)
            wrong_digest["sha256"] = "f" * 64
            with mock.patch.object(PARITY.os, "fstat", side_effect=metadata()):
                with self.assertRaisesRegex(PARITY.ParityError, "digest is not manifest-bound"):
                    PARITY.open_sealed_runtime_verifier(
                        verifier, {"runtime_targets": [wrong_digest]}, root
                    )

    def test_maintained_owner_tools_seal_synthetic_private_safe_receipt(self) -> None:
        synthetic_owner = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        synthetic_secret = "0" * 63 + "1"
        policy = copy.deepcopy(POLICY)
        policy["reserved_pubkeys"][0] = synthetic_owner
        policy["owner_pubkey"] = synthetic_owner
        policy["response_policy"]["owner_pubkey"] = synthetic_owner
        policy["response_policy"]["responder_allowlist"] = [synthetic_owner]
        policy = PARITY.validate_policy(policy)

        def replace_owner(value):
            if isinstance(value, dict):
                return {key: replace_owner(child) for key, child in value.items()}
            if isinstance(value, list):
                return [replace_owner(child) for child in value]
            return synthetic_owner if value == POLICY["owner_pubkey"] else value

        authority = replace_owner(self.authority)
        authority["policy_sha256"] = PARITY.digest(policy)
        authority["payload_sha256"] = PARITY.digest({
            key: value for key, value in authority.items() if key != "payload_sha256"
        })
        receipt = PARITY.compare_set(
            replace_owner(self.reference),
            replace_owner(self.mempool),
            replace_owner(self.genesis),
            policy,
            authority,
        )
        self.assertEqual(receipt["status"], "PASS")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            secret_file = root / "secrets.env"
            secret_file.write_text(f"BUZZ_OWNER_PRIVATE_KEY={synthetic_secret}\n")
            secret_file.chmod(0o600)
            signer = root / "buzz-parity-owner-signer"
            verifier = root / "buzz-parity-owner-verifier"
            signer.write_bytes((REPO_ROOT / "target/release/buzz-parity-owner-signer").read_bytes())
            verifier.write_bytes((REPO_ROOT / "target/release/buzz-parity-owner-verifier").read_bytes())
            signer.chmod(0o700)
            verifier.chmod(0o700)
            tool_manifest = ops_manifest(signer, verifier)
            sealed = PARITY.seal_receipt(
                receipt,
                policy,
                [
                    str(signer), "--secrets-file", str(secret_file),
                    "--owner-pubkey", synthetic_owner,
                    "--signed-at", "2026-08-27T00:00:00Z",
                ],
                [str(verifier), "--owner-pubkey", synthetic_owner],
                tool_manifest,
            )
            runtime_root = root / "runtime-root"
            runtime_verifier = runtime_root / PARITY.ROOT_VERIFIER_TARGET.lstrip("/")
            runtime_verifier.parent.mkdir(parents=True)
            runtime_verifier.write_bytes(
                (REPO_ROOT / "target/release/buzz-agent-key-handoff").read_bytes()
            )
            runtime_verifier.chmod(0o755)
            runtime_sha256, _runtime_metadata = PARITY.regular_sha256(runtime_verifier)
            tool_manifest["runtime_targets"][0]["sha256"] = runtime_sha256
            real_fstat = PARITY.os.fstat

            def root_owned_fstat(descriptor):
                observed = real_fstat(descriptor)
                fields = list(observed)
                fields[4] = 0
                fields[5] = 0
                return os.stat_result(fields)

            with mock.patch.object(PARITY.os, "fstat", side_effect=root_owned_fstat):
                PARITY.run_runtime_verifier(
                    runtime_verifier,
                    tool_manifest,
                    synthetic_owner,
                    sealed,
                    runtime_root,
                )
            PARITY.safe_command(
                [str(verifier), "--owner-pubkey", synthetic_owner],
                PARITY.canonical_json(sealed),
            )
            persisted_tamper = copy.deepcopy(sealed)
            persisted_tamper["receipt"]["status"] = "BLOCKED"
            with self.assertRaisesRegex(PARITY.ParityError, "failed"):
                PARITY.safe_command(
                    [str(verifier), "--owner-pubkey", synthetic_owner],
                    PARITY.canonical_json(persisted_tamper),
                )
        self.assertTrue(sealed["verified"])
        self.assertNotIn(synthetic_secret, PARITY.canonical_json(sealed).decode())


if __name__ == "__main__":
    unittest.main()

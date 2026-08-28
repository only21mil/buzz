import hashlib
import importlib.util
import json
import os
from pathlib import Path
import grp
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from migration import (
    BUZZ_CLI,
    Executor,
    MigrationError,
    SYSTEMCTL,
    apply,
    backup_paths,
    execute_apply,
    execute_restore_external,
    load_manifest,
    managed_units,
    parse_channel_members,
    preflight_external_dependencies,
    preflight_install_roots,
    preflight_public_host,
    preflight_restore_memberships,
    preflight_unit_states,
    require_member_role,
    retained_runtime_units,
    restore,
    snapshot_hermes_memberships,
    snapshot_kind0_names,
    validate_manifest,
    validate_hermes_secret_assignments,
    validate_membership_sweep_dependency,
    validate_unit_states,
    verify,
    wait_for_member_role,
)


PRIVATE_SENTINEL = "a" * 64
AUTH_SENTINEL = (
    '["auth","4a34c131ec5cb5dd9a200bac619bbd103c0793e068fad278d1de59203d05b97d",'
    '"kind=1","' + "b" * 128 + '"]'
)
OWNER_SENTINEL = "c" * 64
PROXY_SENTINEL = "proxy-credential-sentinel-do-not-print"


def membership_payload(manifest, *, hermes_present, hermes_role="member"):
    members = [{"pubkey": manifest["owner_pubkey"], "role": "owner"}]
    if hermes_present:
        members.append({
            "pubkey": manifest["hermes_retirement"]["pubkey"],
            "role": hermes_role,
        })
    return json.dumps(members, separators=(",", ":")).encode()


class RosterMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "root"
        self.root.mkdir()
        self.receipt = Path(self.temp.name) / "receipt"
        self.manifest = load_manifest()
        self.original: dict[str, bytes] = {}
        self._make_fixture()

    def tearDown(self):
        self.temp.cleanup()

    def path(self, absolute):
        return self.root / absolute.lstrip("/")

    def kind0_snapshots(self):
        return {
            target["slug"]: {
                "name": {"present": True, "value": f"username-{target['slug']}"},
                "display_name": {"present": True, "value": target["previous_display_name"]},
            }
            for target in self.manifest["targets"]
        }

    def write(self, absolute, data, mode=0o600):
        path = self.path(absolute)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)
        self.original[str(path)] = data
        return path

    def desktop_launcher_fixture(self):
        fixture = Path(tempfile.mkdtemp(prefix="desktop-launcher-", dir=self.temp.name))
        fixture.chmod(0o700)
        artifact_dir = fixture / "work" / "buzz-client"
        artifact_dir.mkdir(parents=True)
        (fixture / "work").chmod(0o700)
        artifact_dir.chmod(0o700)
        cache = fixture / "cache"
        runtime = fixture / "run" / "user" / str(os.getuid())
        secret_dir = fixture / "config" / "sats"
        for directory in (
            cache,
            cache / "tmp",
            cache / "huggingface",
            cache / "huggingface" / "hub",
            cache / "huggingface" / "xet",
            cache / "mesh-llm",
            cache / "mesh-llm" / "native-runtimes",
            runtime,
            runtime / "gdm",
            secret_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o700)

        output = fixture / "environment.json"
        appimage = artifact_dir / "Buzz.AppImage"
        appimage.write_text(
            "#!/usr/bin/python3\n"
            "import json, os\n"
            "from pathlib import Path\n"
            f"Path({str(output)!r}).write_text(json.dumps(dict(os.environ), sort_keys=True))\n"
        )
        appimage.chmod(0o700)
        appimage_manifest = artifact_dir / "Buzz.AppImage.manifest.json"
        appimage_manifest.write_text("{}\n")
        appimage_manifest.chmod(0o600)
        secret_file = secret_dir / "secrets.env"
        secret_file.write_text(f"BUZZ_OWNER_PRIVATE_KEY={PRIVATE_SENTINEL}\n")
        secret_file.chmod(0o600)
        xauthority = runtime / "gdm" / "Xauthority"
        xauthority.write_bytes(b"fixture-xauthority\n")
        xauthority.chmod(0o600)
        fallback_xauthority = fixture / ".Xauthority"
        fallback_xauthority.write_bytes(b"fixture-fallback-xauthority\n")
        fallback_xauthority.chmod(0o600)

        owner = pwd.getpwuid(os.getuid()).pw_name
        group = grp.getgrgid(os.getgid()).gr_name
        source = (HERE.parent / "payloads" / "launch_buzz_desktop.sh").read_text()
        replacements = (
            ("/home/victor/.cache", str(cache)),
            ("/home/victor/work/buzz-client/Buzz_0.5.9-test.11_amd64.AppImage.manifest.json", str(appimage_manifest)),
            ("/home/victor/work/buzz-client/Buzz_0.5.9-test.11_amd64.AppImage", str(appimage)),
            ("b18b3b5185da563a267df2f31336ac26138d39b6808616c6735bf76d6f611168", hashlib.sha256(appimage_manifest.read_bytes()).hexdigest()),
            ("404829a7fba15a9887e847c3b0fbf5b208f6759e097367bba51ca044437f2009", hashlib.sha256(appimage.read_bytes()).hexdigest()),
            ("/home/victor/.config/sats", str(secret_dir)),
            ("readonly trusted_home=/home/victor", f"readonly trusted_home={fixture}"),
            ("readonly trusted_owner=victor", f"readonly trusted_owner={owner}"),
            ("readonly runtime_dir=/run/user/1000", f"readonly runtime_dir={runtime}"),
            ("readonly fallback_xauthority=/home/victor/.Xauthority", f"readonly fallback_xauthority={fallback_xauthority}"),
            ("victor:victor", f"{owner}:{group}"),
            ("== victor ]]", f"== {owner} ]]"),
            ("HOME=/home/victor", f"HOME={fixture}"),
            ("USER=victor", f"USER={owner}"),
            ("LOGNAME=victor", f"LOGNAME={owner}"),
        )
        for old, new in replacements:
            source = source.replace(old, new)
        secret_declaration = next(
            line for line in source.splitlines() if line.startswith("readonly secret_dir=")
        )
        self.assertEqual(secret_declaration, f"readonly secret_dir={secret_dir}")
        self.assertTrue(secret_dir.is_dir())
        launcher = fixture / "launch-buzz-desktop"
        launcher.write_text(source)
        launcher.chmod(0o700)
        return launcher, output, xauthority, fallback_xauthority, fixture

    def run_desktop_launcher(
        self,
        *,
        display,
        wayland_display,
        xauthority=None,
        fallback="safe",
        hostile=False,
        preopened_fd=False,
        inherited_desktop_xauthority=False,
        inherited_readonly_export=False,
        appimage_state="safe",
    ):
        launcher, output, default_xauthority, fallback_xauthority, fixture = self.desktop_launcher_fixture()
        environment = {
            "DISPLAY": display,
            "WAYLAND_DISPLAY": wayland_display,
            "LEAK_ME": "must-not-survive",
        }
        if inherited_desktop_xauthority:
            environment["desktop_xauthority"] = "inherited-export-must-not-survive"
        if inherited_readonly_export:
            environment["session_display"] = "inherited-readonly-must-not-survive"
        if xauthority == "default":
            environment["XAUTHORITY"] = str(default_xauthority)
        elif xauthority == "group-writable":
            default_xauthority.chmod(0o620)
            environment["XAUTHORITY"] = str(default_xauthority)
        elif xauthority == "symlink":
            link = fixture / "linked-Xauthority"
            link.symlink_to(default_xauthority)
            environment["XAUTHORITY"] = str(link)
        elif xauthority is not None:
            environment["XAUTHORITY"] = str(xauthority)
        sentinel = fixture / "hostile-function-ran"
        if hostile:
            body = f"() {{ /usr/bin/touch {sentinel}; }}"
            for name in ("assert_exact_exported_environment", "builtin", "compgen", "export", "unset"):
                environment[f"BASH_FUNC_{name}%%"] = body
            bash_env = fixture / "hostile-bash-env"
            bash_env.write_text(f"/usr/bin/touch {sentinel}\nexport BASH_ENV_INJECTED=1\n")
            environment["BASH_ENV"] = str(bash_env)
        if fallback == "missing":
            fallback_xauthority.unlink()
        elif fallback == "group-writable":
            fallback_xauthority.chmod(0o620)
        elif fallback == "symlink":
            fallback_xauthority.unlink()
            fallback_xauthority.symlink_to(default_xauthority)
        appimage = fixture / "work" / "buzz-client" / "Buzz.AppImage"
        if appimage_state == "group-writable":
            appimage.chmod(0o720)
        elif appimage_state == "symlink":
            target = fixture / "Buzz.AppImage.target"
            appimage.rename(target)
            appimage.symlink_to(target)
        elif appimage_state == "directory-group-writable":
            appimage.parent.chmod(0o720)
        elif appimage_state == "intermediate-directory-group-writable":
            appimage.parent.parent.chmod(0o720)

        saved_fd = None
        pass_fds = ()
        if preopened_fd:
            try:
                saved_fd = os.dup(247)
            except OSError:
                saved_fd = -1
            source_fd = os.open(launcher, os.O_RDONLY)
            try:
                os.dup2(source_fd, 247, inheritable=True)
            finally:
                os.close(source_fd)
            pass_fds = (247,)
        try:
            result = subprocess.run(
                [str(launcher)],
                env=environment,
                pass_fds=pass_fds,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        finally:
            if preopened_fd:
                if saved_fd == -1:
                    os.close(247)
                else:
                    os.dup2(saved_fd, 247, inheritable=True)
                    os.close(saved_fd)
        exported = json.loads(output.read_text()) if output.exists() else None
        return result, exported, sentinel, default_xauthority, fallback_xauthority

    def apply_migration(self, root, receipt, execute_external=False):
        return apply(
            root,
            receipt,
            execute_external,
            self.activation_manifest,
            self.activation_manifest_sha256,
        )

    def verify_migration(self, root):
        return verify(
            root, self.activation_manifest, self.activation_manifest_sha256,
        )

    def _make_fixture(self):
        live = self.manifest["live_files"]
        self.write(live["launcher"], b"old-launcher\n", 0o755)
        self.write(live["desktop_launcher"], b"old-desktop-launcher\n", 0o700)
        self.write(live["desktop_entry"], b"[Desktop Entry]\nExec=/home/victor/projects/buzz/old\n", 0o644)
        self.write(live["directory_sync"], b"old-directory\n", 0o755)
        self.write(live["directory_sync_compat"], b"old-directory-compat\n", 0o755)
        sweep = b"#!/usr/bin/env bash\nexit 0\n"
        service = (
            b"[Unit]\n"
            b"Description=Reconcile Sats agents and authority in Buzz channels\n"
            b"After=network-online.target\n"
            b"Wants=network-online.target\n\n"
            b"[Service]\n"
            b"Type=oneshot\n"
            b"ExecStart=/home/victor/.local/libexec/buzz/buzz-sats-channel-sweep\n"
        )
        self.write(live["membership_sweep"], sweep, 0o700)
        self.write(live["membership_sweep_service"], service, 0o600)
        package = Path(self.temp.name) / "activation-package"
        sweep_source = package / "ops-root/home/victor/.local/libexec/buzz/buzz-sats-channel-sweep"
        service_source = package / "ops-root/home/victor/.config/systemd/user/buzz-sats-channel-sweep.service"
        for path, payload, mode in ((sweep_source, sweep, 0o700), (service_source, service, 0o600)):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            path.chmod(mode)
        dependency = self.manifest["membership_sweep_dependency"]
        activation = {
            "schema": dependency["activation_manifest_schema"],
            "source_commit": dependency["source_commit"],
            "source_tree": dependency["source_tree"],
            "package_digest": "9" * 64,
            "generator_sources": [
                {"path": path, "sha256": sha256, "mode": "0755"}
                for path, sha256 in dependency["generator_sources"].items()
            ],
            "ops_targets": [
                {
                    **record,
                    "sha256": hashlib.sha256(sweep if name == "membership_sweep" else service).hexdigest(),
                    "scope": "fixture",
                }
                for name, record in dependency["ops_targets"].items()
            ],
        }
        self.activation_manifest = package / "bundle-manifest.json"
        self.activation_manifest.write_text(json.dumps(activation, sort_keys=True))
        self.activation_manifest.chmod(0o600)
        self.activation_manifest_sha256 = hashlib.sha256(self.activation_manifest.read_bytes()).hexdigest()
        self.write(
            live["agent_service"],
            b"[Service]\nExecStart=/home/victor/projects/buzz/scripts/launch_buzz_agent.sh %i\n",
            0o644,
        )
        env = ["KEEP_ME=unchanged", f"{self.manifest['owner_private_key_var']}={OWNER_SENTINEL}"]
        for target in self.manifest["targets"]:
            env.extend([
                f"{target['private_key_var']}={PRIVATE_SENTINEL}",
                f"{target['auth_tag_var']}={AUTH_SENTINEL}",
            ])
            if target.get("proxy_token_var"):
                env.append(f"{target['proxy_token_var']}=loopback-token")
            if target.get("proxy_config"):
                proxy = {
                    "host": "127.0.0.1",
                    "port": target["port"],
                    "api-keys": ["loopback-token"],
                    "openai-compatibility": [{
                        "name": "openrouter-dsv4f",
                        "base-url": "https://openrouter.ai/api/v1",
                        "api-key-entries": [{"api-key": PROXY_SENTINEL}],
                        "models": [{"name": "deepseek/deepseek-v4-flash-0731", "alias": "dsv4f-max", "display-name": "old", "force-mapping": True}],
                    }],
                    "payload": {
                        "filter": [{"models": [{"name": "dsv4f-max"}], "params": ["reasoning_effort"]}],
                        "override": [{"models": [{"name": "dsv4f-max"}], "params": {"reasoning.effort": "max"}}],
                    },
                }
                self.write(target["proxy_config"], yaml.safe_dump(proxy).encode())
        for prompt in self.manifest["fleet_prompts"]:
            self.write(prompt["path"], f"old prompt {prompt['name']}\n".encode(), 0o600)
        hermes = self.manifest["hermes_retirement"]
        env.extend([
            f"{hermes['secret_variables'][0]}={PRIVATE_SENTINEL}",
            f"{hermes['secret_variables'][1]}={AUTH_SENTINEL}",
        ])
        self.write(live["secrets"], ("\n".join(env) + "\n").encode())
        self.write(hermes["launcher_prompt"], b"old Hermes prompt\n", 0o644)

    def test_manifest_exact_inventory_and_stable_identity(self):
        expected = {
            "sats-dsv4f": ("3b1293bdf1f3885417eb1df302b5f31401fb740ad6e25b83a7aab210abc549bb", 8328),
            "sats-glm": ("b7d2ebed4d4f15a28c71b8a83f3a717770a37bd65bd29e95aea4faa6106c445a", 8327),
            "sats-glm52": ("d0abfb7c343012552a44009b2f33bb6a6ada54b4e6d408fffeed58d388d1f2af", 8329),
            "sats-codex-2": ("aefa6783cdf2f33f9aa3705b41e5ae3ec214318c64db48f1410fc77db015f2ec", None),
        }
        self.assertEqual({item["slug"]: (item["pubkey"], item.get("port")) for item in self.manifest["targets"]}, expected)
        self.assertEqual(self.manifest["install_root"], "/home/victor/.local/libexec/buzz/fleet/roster-5ac44f9f-v1")
        self.assertEqual(self.manifest["config_root"], "/home/victor/.config/buzz/agents")
        self.assertNotIn("/home/victor/projects", json.dumps(self.manifest, sort_keys=True))
        hermes = self.manifest["hermes_retirement"]
        self.assertEqual(hermes["slug"], "sats-hermes")
        self.assertEqual(hermes["pubkey"], "fc2cd7a09dfebfc20cd9ee4cc9ec03536d7ad4ef5d0e2d961e9fdb064511e6ba")
        self.assertEqual(len(hermes["memberships"]), 27)

    def test_apply_verify_receipt_and_rollback(self):
        receipt_path = self.apply_migration(self.root, self.receipt)
        result = self.verify_migration(self.root)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["relay_memberships"]["status"], "not_checked")
        self.assertEqual(result["relay_memberships"]["pending"], "live_post_readback")
        self.assertNotIn("hermes_memberships_removed", result)
        secrets = self.path(self.manifest["live_files"]["secrets"]).read_text()
        self.assertIn("KEEP_ME=unchanged", secrets)
        self.assertNotIn("BUZZ_SATS_HERMES_", secrets)
        service = self.path(self.manifest["live_files"]["agent_service"]).read_text()
        self.assertIn("/home/victor/.local/libexec/buzz/fleet/roster-5ac44f9f-v1/launch-buzz-agent %i", service)
        self.assertNotIn("/home/victor/projects", service)
        compatibility = self.path(self.manifest["live_files"]["directory_sync_compat"]).read_text()
        self.assertIn(self.manifest["live_files"]["directory_sync"], compatibility)
        for target in self.manifest["targets"]:
            if target.get("proxy_config"):
                proxy = yaml.safe_load(self.path(target["proxy_config"]).read_bytes())
                self.assertEqual(proxy["openai-compatibility"][0]["api-key-entries"][0]["api-key"], PROXY_SENTINEL)
        receipt_raw = receipt_path.read_text()
        self.assertNotIn(PRIVATE_SENTINEL, receipt_raw)
        self.assertNotIn(AUTH_SENTINEL, receipt_raw)
        self.assertNotIn(PROXY_SENTINEL, receipt_raw)
        self.assertEqual(stat.S_IMODE(self.receipt.stat().st_mode), 0o700)
        for backup in (self.receipt / "files").iterdir():
            self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
        operations = json.loads(receipt_raw)["operations"]
        self.assertEqual(json.loads(receipt_raw)["relay_memberships"]["status"], "not_checked")
        leaves = [item for item in operations if item[1:3] == ["channels", "leave"]]
        members = [item for item in operations if item[1:3] == ["channels", "members"]]
        self.assertEqual(len(leaves), 27)
        self.assertEqual(len(members), 54)
        disable = [item for item in operations if item[:3] == [str(SYSTEMCTL), "--user", "disable"]]
        self.assertEqual(disable[0][-2:], ["buzz-sats-agent@sats-hermes.service", "agent-child-reaper@sats-hermes.timer"])
        restore(self.receipt, execute_external=False)
        for path_text, raw in self.original.items():
            self.assertEqual(Path(path_text).read_bytes(), raw)

    def test_reasoning_and_context_contracts(self):
        self.apply_migration(self.root, self.receipt)
        by_slug = {item["slug"]: item for item in self.manifest["targets"]}
        qwen = by_slug["sats-dsv4f"]
        self.assertEqual(qwen["display_name"], "Knots")
        self.assertEqual(qwen["model"], "qwen/qwen3.8-flash")
        self.assertEqual(qwen["context_tokens"], 1_000_000)
        self.assertTrue(qwen["reasoning"]["enabled"])
        self.assertIsNone(qwen["reasoning"]["effort"])
        for slug in ("sats-glm", "sats-glm52"):
            self.assertEqual(by_slug[slug]["model"], "z-ai/glm-5.3-flash")
            self.assertEqual(by_slug[slug]["context_tokens"], 1_048_576)
            self.assertEqual(by_slug[slug]["reasoning"]["effort"], "max")
        utxo = by_slug["sats-codex-2"]
        self.assertEqual(utxo["display_name"], "UTXO")
        self.assertEqual(utxo["model"], "gpt-5.6-sol")
        self.assertEqual(utxo["reasoning"], {"enabled": True, "effort": "high"})
        launcher = self.path(self.manifest["live_files"]["launcher"]).read_text()
        self.assertNotIn("1250000", launcher)
        self.assertNotIn("sats-hermes)", launcher)
        self.assertNotIn("/home/victor/projects", launcher)

    def test_verifier_rejects_stale_prompt_digest_pin(self):
        self.apply_migration(self.root, self.receipt)
        target = self.manifest["targets"][0]
        prompt = self.path(target["prompt"])
        prompt.write_bytes(prompt.read_bytes() + b"changed after launcher pin\n")
        with self.assertRaisesRegex(MigrationError, "launcher prompt digest mismatch"):
            self.verify_migration(self.root)

    def test_fail_closed_on_scope_expansion(self):
        broken = json.loads(json.dumps(self.manifest))
        broken["targets"][0]["context_tokens"] += 1
        with self.assertRaises(MigrationError):
            validate_manifest(broken)
        broken = json.loads(json.dumps(self.manifest))
        broken["targets"][0]["auth_tag_var"] = "BUZZ_WRONG_AUTH_TAG"
        with self.assertRaises(MigrationError):
            validate_manifest(broken)
        with self.assertRaises(MigrationError):
            self.apply_migration(self.root, self.receipt, execute_external=True)

    def test_external_plan_has_exact_service_and_publish_scope(self):
        secrets = {}
        for target in self.manifest["targets"]:
            secrets[target["private_key_var"]] = PRIVATE_SENTINEL
            secrets[target["auth_tag_var"]] = AUTH_SENTINEL
        hermes = self.manifest["hermes_retirement"]
        secrets[hermes["secret_variables"][0]] = PRIVATE_SENTINEL
        secrets[hermes["secret_variables"][1]] = AUTH_SENTINEL
        executor = Executor(self.manifest, secrets, dry_run=True)
        with mock.patch("migration.write_files"):
            execute_apply(self.manifest, executor, Path("/"))
        restarts = [item[-1] for item in executor.operations if item[:3] == [str(SYSTEMCTL), "--user", "restart"]]
        self.assertEqual(
            set(restarts),
            set(retained_runtime_units(self.manifest)) | {
                "buzz-sats-channel-sweep.service",
                "buzz-sats-channel-sweep.timer",
            },
        )
        operations = " ".join(" ".join(item) for item in executor.operations)
        self.assertNotIn("hermes-gateway.service", operations)
        self.assertNotIn("/home/victor/.hermes", operations)
        self.assertNotIn("hermes-acp", operations)
        self.assertFalse(any(item[1:3] == ["users", "set-profile"] for item in executor.operations))
        stop_index = executor.operations.index([
            str(SYSTEMCTL), "--user", "stop",
            "buzz-sats-channel-sweep.timer", "buzz-sats-channel-sweep.service",
        ])
        disable_index = next(index for index, item in enumerate(executor.operations) if item[:3] == [str(SYSTEMCTL), "--user", "disable"] and "--now" in item)
        archive_index = next(index for index, item in enumerate(executor.operations) if item[1:3] == ["agents", "archive"])
        leave_index = next(index for index, item in enumerate(executor.operations) if item[1:3] == ["channels", "leave"])
        publisher_index = next(index for index, item in enumerate(executor.operations) if "--sync-kind0" in item)
        sweep_restart_index = max(index for index, item in enumerate(executor.operations) if item == [str(SYSTEMCTL), "--user", "restart", "buzz-sats-channel-sweep.timer"])
        self.assertLess(stop_index, disable_index)
        self.assertLess(disable_index, archive_index)
        self.assertLess(archive_index, leave_index)
        self.assertLess(publisher_index, sweep_restart_index)

    def test_channel_removal_is_readback_driven_and_idempotent(self):
        hermes = self.manifest["hermes_retirement"]

        class FakeExecutor(Executor):
            def __init__(self, manifest):
                super().__init__(manifest, {}, dry_run=False)
                self.memberships = set(hermes["memberships"])
                self.archived = False
                self.states = {
                    unit: {"is-enabled": "enabled", "is-active": "active"}
                    for unit in managed_units(manifest)
                }

            def command(self, argv, identity=None, allowed_returncodes=(0,)):
                self.operations.append(argv)
                if argv[:2] == [str(SYSTEMCTL), "--user"]:
                    verb = argv[2]
                    if verb == "stop":
                        for unit in argv[3:]:
                            self.states[unit]["is-active"] = "inactive"
                    elif verb == "disable" and "--now" in argv:
                        for unit in argv[4:]:
                            self.states[unit] = {"is-enabled": "disabled", "is-active": "inactive"}
                    elif verb in {"enable", "disable"}:
                        self.states[argv[-1]]["is-enabled"] = "enabled" if verb == "enable" else "disabled"
                    elif verb == "restart":
                        self.states[argv[-1]]["is-active"] = "active"
                    elif verb == "is-enabled":
                        return self.states[argv[-1]]["is-enabled"].encode()
                    elif verb == "is-active":
                        return self.states[argv[-1]]["is-active"].encode()
                    return b""
                if argv[1:3] == ["agents", "archive"]:
                    self.archived = True
                if argv[1:3] == ["agents", "archived"]:
                    return hermes["pubkey"].encode() if self.archived else b"[]"
                if argv[1:3] == ["channels", "members"]:
                    channel = argv[-1]
                    return membership_payload(
                        self.manifest, hermes_present=channel in self.memberships,
                    )
                if argv[1:3] == ["channels", "leave"]:
                    self.memberships.discard(argv[-1])
                if argv[1:3] == ["users", "get"]:
                    return argv[-1].encode() + b" Knots Segwit Ledger UTXO"
                return b"{}"

        executor = FakeExecutor(self.manifest)
        prior = {
            unit: {"is-enabled": "enabled", "is-active": "active"}
            for unit in managed_units(self.manifest)
        }
        completed = mock.Mock(returncode=0)
        publisher_digest = hashlib.sha256((HERE.parent / "payloads" / "buzz-sats-directory-sync.py").read_bytes()).hexdigest()
        with mock.patch("migration.write_files"), \
             mock.patch("migration.dependency_descriptor", return_value={"sha256": publisher_digest}), \
             mock.patch("migration.subprocess.run", return_value=completed):
            memberships = {channel: "member" for channel in hermes["memberships"]}
            execute_apply(self.manifest, executor, Path("/"), prior, memberships)
            first_count = len([item for item in executor.operations if item[1:3] == ["channels", "leave"]])
            absent = {channel: "absent" for channel in hermes["memberships"]}
            execute_apply(self.manifest, executor, Path("/"), prior, absent)
            second_count = len([item for item in executor.operations if item[1:3] == ["channels", "leave"]])
        self.assertEqual(first_count, 27)
        self.assertEqual(second_count, first_count)

    def test_post_leave_readback_retries_stale_membership_with_a_bound(self):
        hermes = self.manifest["hermes_retirement"]

        class StaleExecutor:
            dry_run = False

            def __init__(self):
                self.operations = []

            def command(inner_self, argv, identity=None, allowed_returncodes=(0,)):
                inner_self.operations.append(argv)
                return membership_payload(
                    self.manifest,
                    hermes_present=len(inner_self.operations) < 3,
                )

        executor = StaleExecutor()
        with mock.patch("migration.time.sleep") as sleeper:
            wait_for_member_role(
                executor,
                {"private_key_var": self.manifest["owner_private_key_var"]},
                hermes["memberships"][0],
                hermes["pubkey"],
                None,
                attempts=3,
            )
        self.assertEqual(len(executor.operations), 3)
        self.assertEqual(sleeper.call_count, 2)

    def test_member_parser_accepts_exact_buzz_cli_object_shape(self):
        raw = json.dumps([
            {"pubkey": self.manifest["owner_pubkey"], "role": "owner"},
            {"pubkey": self.manifest["hermes_retirement"]["pubkey"], "role": "member"},
        ]).encode()
        roles = parse_channel_members(raw)
        self.assertEqual(roles, {
            self.manifest["owner_pubkey"]: "owner",
            self.manifest["hermes_retirement"]["pubkey"]: "member",
        })
        require_member_role(
            roles,
            self.manifest["hermes_retirement"]["pubkey"],
            "member",
            channel=self.manifest["hermes_retirement"]["memberships"][0],
        )

    def test_member_parser_rejects_malformed_exact_shape_and_types(self):
        owner = self.manifest["owner_pubkey"]
        cases = (
            b"not-json",
            b"{}",
            json.dumps([owner]).encode(),
            json.dumps([{"pubkey": owner}]).encode(),
            json.dumps([{"pubkey": owner, "role": "owner", "extra": True}]).encode(),
            json.dumps([{"pubkey": "not-hex", "role": "owner"}]).encode(),
            json.dumps([{"pubkey": owner, "role": 1}]).encode(),
            json.dumps([{"pubkey": owner, "role": "superuser"}]).encode(),
        )
        for raw in cases:
            with self.subTest(raw=raw):
                with self.assertRaises(MigrationError):
                    parse_channel_members(raw)

    def test_member_parser_rejects_degraded_empty_and_duplicate_pubkeys(self):
        with self.assertRaisesRegex(MigrationError, "empty or degraded"):
            parse_channel_members(b"[]")
        owner = self.manifest["owner_pubkey"]
        duplicate = json.dumps([
            {"pubkey": owner, "role": "owner"},
            {"pubkey": owner.upper(), "role": "admin"},
        ]).encode()
        with self.assertRaisesRegex(MigrationError, "duplicate pubkey"):
            parse_channel_members(duplicate)

    def test_membership_preflight_rejects_degraded_empty_before_mutation(self):
        operations = []

        class DegradedExecutor:
            def command(inner_self, argv, identity=None, allowed_returncodes=(0,)):
                operations.append(argv)
                return b"[]"

        with self.assertRaisesRegex(MigrationError, "empty or degraded"):
            snapshot_hermes_memberships(self.manifest, DegradedExecutor())
        self.assertEqual(len(operations), 1)
        self.assertEqual(operations[0][1:3], ["channels", "members"])
        self.assertFalse(any(operation[1:3] == ["channels", "leave"] for operation in operations))

    def test_membership_preflight_preserves_exact_supported_role(self):
        operations = []

        class WrongRoleExecutor:
            def command(inner_self, argv, identity=None, allowed_returncodes=(0,)):
                operations.append(argv)
                return membership_payload(
                    self.manifest, hermes_present=True, hermes_role="admin",
                )

        snapshot = snapshot_hermes_memberships(self.manifest, WrongRoleExecutor())
        self.assertEqual(set(snapshot.values()), {"admin"})
        self.assertEqual(len(operations), 27)
        self.assertFalse(any(operation[1:3] == ["channels", "leave"] for operation in operations))

    def test_restore_membership_preflight_records_exact_supported_role(self):
        operations = []

        class WrongRoleExecutor:
            def command(inner_self, argv, identity=None, allowed_returncodes=(0,)):
                operations.append(argv)
                return membership_payload(
                    self.manifest, hermes_present=True, hermes_role="admin",
                )

        snapshot = preflight_restore_memberships(self.manifest, WrongRoleExecutor())
        self.assertEqual(set(snapshot.values()), {"admin"})
        self.assertEqual(len(operations), 27)
        self.assertFalse(any(
            operation[1:3] == ["channels", "add-member"] for operation in operations
        ))

    def test_apply_restarts_only_units_that_were_active(self):
        secrets = {}
        for target in self.manifest["targets"]:
            secrets[target["private_key_var"]] = PRIVATE_SENTINEL
            secrets[target["auth_tag_var"]] = AUTH_SENTINEL
        hermes = self.manifest["hermes_retirement"]
        secrets[hermes["secret_variables"][0]] = PRIVATE_SENTINEL
        secrets[hermes["secret_variables"][1]] = AUTH_SENTINEL
        prior = {
            unit: {"is-enabled": "enabled", "is-active": "inactive"}
            for unit in managed_units(self.manifest)
        }
        active = {"sats-dsv4f-proxy.service", "buzz-sats-agent@sats-codex-2.service"}
        for unit in active:
            prior[unit]["is-active"] = "active"
        executor = Executor(self.manifest, secrets, dry_run=True)
        with mock.patch("migration.write_files"):
            execute_apply(self.manifest, executor, Path("/"), prior)
        restarts = {item[-1] for item in executor.operations if item[:3] == [str(SYSTEMCTL), "--user", "restart"]}
        self.assertEqual(restarts, active)

    def test_unit_state_preflight_rejects_every_unsupported_state(self):
        valid = {
            unit: {"is-enabled": "enabled", "is-active": "active"}
            for unit in managed_units(self.manifest)
        }
        unit = managed_units(self.manifest)[0]
        for field, unsupported in (
            ("is-enabled", "static"),
            ("is-enabled", "exit-4"),
            ("is-active", "failed"),
            ("is-active", "activating"),
        ):
            with self.subTest(field=field, unsupported=unsupported):
                broken = json.loads(json.dumps(valid))
                broken[unit][field] = unsupported
                with self.assertRaises(MigrationError):
                    validate_unit_states(self.manifest, broken)
        missing = json.loads(json.dumps(valid))
        missing.pop(unit)
        with self.assertRaises(MigrationError):
            validate_unit_states(self.manifest, missing)
        valid[self.manifest["standing_sweep_service"]]["is-enabled"] = "static"
        validate_unit_states(self.manifest, valid)

    def test_unsupported_live_unit_state_prevents_backup_and_executor_creation(self):
        backup = mock.Mock()
        executor = mock.Mock()
        with mock.patch("migration.preflight_install_roots"), \
             mock.patch("migration.rooted", return_value=self.path(self.manifest["live_files"]["secrets"])), \
             mock.patch("migration.preflight_public_host", side_effect=MigrationError("unsupported state")), \
             mock.patch("migration.make_backup", backup), \
             mock.patch("migration.Executor", executor):
            with self.assertRaises(MigrationError):
                self.apply_migration(Path("/"), self.receipt, execute_external=True)
        backup.assert_not_called()
        executor.assert_not_called()
        self.assertFalse(self.receipt.exists())

    def test_dependency_preflight_failure_is_clean_and_precedes_backup_or_stop(self):
        backup = mock.Mock()
        executor = mock.Mock()
        with mock.patch("migration.preflight_install_roots"), \
             mock.patch("migration.rooted", return_value=self.path(self.manifest["live_files"]["secrets"])), \
             mock.patch("migration.preflight_public_host", return_value={"unit_states": {}}), \
             mock.patch(
                 "migration.preflight_external_dependencies",
                 side_effect=MigrationError("required dependency is missing"),
             ), \
             mock.patch("migration.make_backup", backup), \
             mock.patch("migration.Executor", executor):
            with self.assertRaisesRegex(MigrationError, "required dependency"):
                self.apply_migration(Path("/"), self.receipt, execute_external=True)
        backup.assert_not_called()
        executor.assert_not_called()
        self.assertFalse(self.receipt.exists())

    def test_external_dependency_commands_are_exact_and_oserror_is_wrapped(self):
        descriptor = {
            "path": "fixture", "resolved": "fixture", "owner_uid": os.getuid(),
            "mode": "0700", "sha256": "0" * 64,
        }
        completed = mock.Mock(returncode=0)
        with mock.patch("migration.dependency_descriptor", return_value=descriptor), \
             mock.patch("migration.subprocess.run", return_value=completed) as runner:
            state = preflight_external_dependencies(OWNER_SENTINEL)
        self.assertEqual(set(state), {"buzz", "systemctl", "python", "nostr_min", "publisher"})
        argv = [call.args[0] for call in runner.call_args_list]
        self.assertEqual(argv[0], [str(BUZZ_CLI), "--version"])
        self.assertEqual(argv[1], [str(SYSTEMCTL), "--version"])
        self.assertEqual(argv[2], ["/usr/bin/python3", "--version"])
        self.assertEqual(argv[3][-1], "--preflight-owner")
        self.assertEqual(runner.call_args_list[3].kwargs["input"], OWNER_SENTINEL.encode())
        with mock.patch("migration.dependency_descriptor", return_value=descriptor), \
             mock.patch("migration.subprocess.run", side_effect=FileNotFoundError):
            with self.assertRaisesRegex(MigrationError, "could not execute"):
                preflight_external_dependencies(OWNER_SENTINEL)

    def test_kind0_snapshot_keeps_name_distinct_from_display_name(self):
        profiles = {
            target["pubkey"]: [{
                "pubkey": target["pubkey"],
                "name": f"username-{target['slug']}",
                "display_name": target["previous_display_name"],
            }]
            for target in self.manifest["targets"]
        }

        class ProfileExecutor:
            operations = []

            def command(self, argv, identity=None, allowed_returncodes=(0,)):
                self.operations.append(argv)
                return json.dumps(profiles[argv[-1]]).encode()

        snapshots = snapshot_kind0_names(self.manifest, ProfileExecutor())
        self.assertEqual(snapshots, self.kind0_snapshots())
        self.assertTrue(all(
            state["name"]["value"] != state["display_name"]["value"]
            for state in snapshots.values()
        ))

    def test_publisher_restores_kind0_name_and_display_name_independently(self):
        publisher_path = HERE.parent / "payloads" / "buzz-sats-directory-sync.py"
        spec = importlib.util.spec_from_file_location("roster_directory_publisher", publisher_path)
        publisher = importlib.util.module_from_spec(spec)
        with mock.patch.dict(sys.modules, {"websockets": mock.Mock(), "nostr_min": mock.Mock()}):
            spec.loader.exec_module(publisher)
        profile = {"name": "stable-username", "display_name": "Knots", "about": "preserved"}
        publisher.apply_profile_field_state(profile, "name", {"present": True, "value": "old-username"})
        publisher.apply_profile_field_state(profile, "display_name", {"present": False})
        self.assertEqual(profile, {"name": "old-username", "about": "preserved"})
        self.assertEqual(
            publisher.profile_field_state(profile, "name"),
            {"present": True, "value": "old-username"},
        )

    def test_apply_transaction_recovers_after_every_mutating_boundary(self):
        boundaries = (
            "sweep_stopped", "hermes_units_stopped", "hermes_archived",
            "memberships_left", "files_written", "services_reloaded",
            "retained_units_restarted", "profiles_published", "sweep_reconciled",
        )
        hermes = self.manifest["hermes_retirement"]
        prior = {
            unit: {"is-enabled": "enabled", "is-active": "active"}
            for unit in managed_units(self.manifest)
        }

        class TransactionExecutor(Executor):
            def __init__(self, manifest, secrets, dry_run):
                super().__init__(manifest, secrets, dry_run=False)
                self.states = json.loads(json.dumps(prior))
                self.memberships = set(hermes["memberships"])
                self.archived = False

            def command(self, argv, identity=None, allowed_returncodes=(0,)):
                self.operations.append(argv)
                if argv[:2] == [str(SYSTEMCTL), "--user"]:
                    verb = argv[2]
                    if verb == "stop":
                        for unit in argv[3:]:
                            self.states[unit]["is-active"] = "inactive"
                    elif verb == "disable" and "--now" in argv:
                        for unit in argv[4:]:
                            self.states[unit] = {"is-enabled": "disabled", "is-active": "inactive"}
                    elif verb in {"enable", "disable"}:
                        self.states[argv[-1]]["is-enabled"] = "enabled" if verb == "enable" else "disabled"
                    elif verb == "restart":
                        self.states[argv[-1]]["is-active"] = "active"
                    elif verb == "is-enabled":
                        return self.states[argv[-1]]["is-enabled"].encode()
                    elif verb == "is-active":
                        return self.states[argv[-1]]["is-active"].encode()
                    return b""
                if argv[1:3] == ["agents", "archive"]:
                    self.archived = True
                if argv[1:3] == ["agents", "archived"]:
                    return hermes["pubkey"].encode() if self.archived else b"[]"
                if argv[1:3] == ["channels", "members"]:
                    return membership_payload(
                        self.manifest, hermes_present=argv[-1] in self.memberships,
                    )
                if argv[1:3] == ["channels", "leave"]:
                    self.memberships.discard(argv[-1])
                return b"{}"

        def fake_backup(_manifest, _root, receipt_dir):
            receipt_dir.mkdir(mode=0o700)
            receipt = {
                "schema_version": 1,
                "status": "backup_complete",
                "manifest_sha256": hashlib.sha256((HERE.parent / "roster.json").read_bytes()).hexdigest(),
                "root": "/",
                "files": {},
                "operations": [],
            }
            (receipt_dir / "receipt.json").write_text(json.dumps(receipt))
            return receipt

        publisher_digest = hashlib.sha256((HERE.parent / "payloads" / "buzz-sats-directory-sync.py").read_bytes()).hexdigest()
        for boundary in boundaries:
            with self.subTest(boundary=boundary):
                receipt_dir = Path(self.temp.name) / f"fault-{boundary}"
                recovery = mock.Mock()
                completed = mock.Mock(returncode=0)

                def inject(name):
                    if name == boundary:
                        raise RuntimeError(f"fault at {name}")

                with mock.patch("migration.preflight_install_roots"), \
                     mock.patch("migration.rooted", return_value=self.path(self.manifest["live_files"]["secrets"])), \
                     mock.patch("migration.preflight_public_host", return_value={"unit_states": prior}), \
                     mock.patch("migration.preflight_external_dependencies", return_value={}), \
                     mock.patch("migration.snapshot_kind0_names", return_value=self.kind0_snapshots()), \
                     mock.patch(
                         "migration.snapshot_hermes_memberships",
                         return_value={channel: "member" for channel in hermes["memberships"]},
                     ), \
                     mock.patch("migration.make_backup", side_effect=fake_backup), \
                     mock.patch("migration.Executor", TransactionExecutor), \
                     mock.patch("migration.write_files"), \
                     mock.patch("migration.restore_backed_up_files"), \
                     mock.patch("migration.execute_restore_external", recovery), \
                     mock.patch("migration.dependency_descriptor", return_value={"sha256": publisher_digest}), \
                     mock.patch("migration.subprocess.run", return_value=completed), \
                     mock.patch("migration.transaction_checkpoint", side_effect=inject):
                    with self.assertRaisesRegex(MigrationError, "automatic recovery completed"):
                        self.apply_migration(Path("/"), receipt_dir, execute_external=True)
                receipt = json.loads((receipt_dir / "receipt.json").read_text())
                self.assertEqual(receipt["status"], "apply_failed_rolled_back")
                self.assertEqual(receipt["apply_error_type"], "RuntimeError")
                recovery.assert_called_once()

    def test_apply_transaction_records_truthful_partial_recovery(self):
        def inject(name):
            if name == "files_written":
                raise RuntimeError("fixture apply failure")

        with mock.patch("migration.transaction_checkpoint", side_effect=inject), \
             mock.patch(
                 "migration.restore_backed_up_files",
                 side_effect=MigrationError("fixture recovery failure"),
             ):
            with self.assertRaisesRegex(MigrationError, "automatic recovery was partial"):
                self.apply_migration(self.root, self.receipt)
        receipt = json.loads((self.receipt / "receipt.json").read_text())
        self.assertEqual(receipt["status"], "apply_failed_partial")
        self.assertEqual(receipt["apply_error_type"], "RuntimeError")
        self.assertEqual(receipt["recovery_error_type"], "MigrationError")

    def test_hermes_secret_preflight_rejects_duplicate_and_malformed_before_backup(self):
        secrets_path = self.path(self.manifest["live_files"]["secrets"])
        original = secrets_path.read_bytes()
        hermes = self.manifest["hermes_retirement"]
        duplicate = original + f"{hermes['secret_variables'][0]}={PRIVATE_SENTINEL}\n".encode()
        hermes_auth = f"{hermes['secret_variables'][1]}={AUTH_SENTINEL}".encode()
        malformed_auth = original.replace(hermes_auth, f"{hermes['secret_variables'][1]}=not-json".encode(), 1)
        for index, raw in enumerate((duplicate, malformed_auth)):
            with self.subTest(index=index):
                secrets_path.write_bytes(raw)
                receipt = Path(self.temp.name) / f"invalid-secret-{index}"
                with self.assertRaises(MigrationError):
                    self.apply_migration(self.root, receipt)
                self.assertFalse(receipt.exists())
        secrets_path.write_bytes(original)

    def test_hermes_auth_requires_canonical_four_element_nip_oa(self):
        secrets_path = self.path(self.manifest["live_files"]["secrets"])
        valid = secrets_path.read_bytes()
        validate_hermes_secret_assignments(valid, self.manifest)
        invalid_tags = (
            '["auth","' + self.manifest["owner_pubkey"] + '"]',
            '["auth","' + self.manifest["owner_pubkey"].upper() + '","kind=1","' + "b" * 128 + '"]',
            '["auth","' + self.manifest["owner_pubkey"] + '","kind=01","' + "b" * 128 + '"]',
            '["auth","' + self.manifest["owner_pubkey"] + '","kind=1","' + "B" * 128 + '"]',
        )
        for tag in invalid_tags:
            with self.subTest(tag=tag[:80]):
                candidate = valid.replace(AUTH_SENTINEL.encode(), tag.encode())
                with self.assertRaises(MigrationError):
                    validate_hermes_secret_assignments(candidate, self.manifest)

    def test_membership_sweep_preflight_waits_for_stable_natural_state(self):
        calls = {self.manifest["standing_sweep_service"]: 0}

        def state(unit):
            if unit == self.manifest["standing_sweep_service"]:
                calls[unit] += 1
                return {
                    "is-enabled": "static",
                    "is-active": "activating" if calls[unit] < 3 else "inactive",
                }
            if unit == self.manifest["standing_sweep_timer"]:
                return {"is-enabled": "enabled", "is-active": "active"}
            return {"is-enabled": "enabled", "is-active": "active"}

        with mock.patch("migration.service_state", side_effect=state), \
             mock.patch("migration.time.sleep") as sleeper:
            states = preflight_unit_states(self.manifest)
        self.assertEqual(states[self.manifest["standing_sweep_service"]]["is-active"], "inactive")
        self.assertEqual(calls[self.manifest["standing_sweep_service"]], 3)
        self.assertEqual(sleeper.call_count, 2)

    def test_non_sweep_preflight_failure_names_unit_without_retry(self):
        unstable_unit = retained_runtime_units(self.manifest)[0]
        calls = {unit: 0 for unit in managed_units(self.manifest)}

        def state(unit):
            calls[unit] += 1
            if unit == unstable_unit:
                return {"is-enabled": "enabled", "is-active": "activating"}
            return {"is-enabled": "enabled", "is-active": "active"}

        with mock.patch("migration.service_state", side_effect=state), \
             mock.patch("migration.time.sleep") as sleeper, \
             self.assertRaisesRegex(MigrationError, unstable_unit):
            preflight_unit_states(self.manifest)
        self.assertEqual(calls[unstable_unit], 1)
        self.assertEqual(calls[self.manifest["standing_sweep_service"]], 0)
        self.assertEqual(calls[self.manifest["standing_sweep_timer"]], 0)
        sleeper.assert_not_called()

    def test_activation_manifest_pins_sweep_source_tree_targets_and_installed_bytes(self):
        state = validate_membership_sweep_dependency(
            self.manifest,
            self.root,
            self.activation_manifest,
            self.activation_manifest_sha256,
        )
        self.assertEqual(
            state["source_tree"],
            self.manifest["membership_sweep_dependency"]["source_tree"],
        )
        self.assertEqual(
            set(state["ops_targets"]), {"membership_sweep", "membership_sweep_service"},
        )
        with self.assertRaisesRegex(MigrationError, "required"):
            apply(self.root, Path(self.temp.name) / "missing-binding", execute_external=False)
        original = self.activation_manifest.read_bytes()
        activation = json.loads(original)
        mutations = (
            lambda value: value.__setitem__("source_tree", "0" * 40),
            lambda value: value["ops_targets"][0].__setitem__("target", "/wrong"),
            lambda value: value["ops_targets"][0].__setitem__("sha256", "f" * 64),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                changed = json.loads(original)
                mutate(changed)
                self.activation_manifest.write_text(json.dumps(changed, sort_keys=True))
                digest = hashlib.sha256(self.activation_manifest.read_bytes()).hexdigest()
                with self.assertRaises(MigrationError):
                    validate_membership_sweep_dependency(
                        self.manifest, self.root, self.activation_manifest, digest,
                    )
        self.activation_manifest.write_bytes(original)
        self.assertNotIn(
            self.path(self.manifest["live_files"]["membership_sweep"]),
            backup_paths(self.manifest, self.root),
        )
        self.assertNotIn(
            self.path(self.manifest["live_files"]["membership_sweep_service"]),
            backup_paths(self.manifest, self.root),
        )

    def test_library_rejects_live_byte_only_apply_and_rollback(self):
        live_receipt = Path(self.temp.name) / "live-apply"
        with self.assertRaises(MigrationError):
            self.apply_migration(Path("/"), live_receipt)
        self.assertFalse(live_receipt.exists())

        self.apply_migration(self.root, self.receipt)
        receipt_path = self.receipt / "receipt.json"
        receipt = json.loads(receipt_path.read_text())
        receipt["root"] = "/"
        receipt_path.write_text(json.dumps(receipt))
        before = json.loads(receipt_path.read_text())
        with self.assertRaises(MigrationError):
            restore(self.receipt, execute_external=False)
        self.assertEqual(json.loads(receipt_path.read_text()), before)

        receipt["root"] = str(self.root)
        receipt_path.write_text(json.dumps(receipt))
        before = json.loads(receipt_path.read_text())
        with self.assertRaises(MigrationError):
            restore(self.receipt, execute_external=True)
        self.assertEqual(json.loads(receipt_path.read_text()), before)

    def test_install_root_preflight_rejects_symlink_and_unsafe_mode(self):
        config_root = self.path(self.manifest["config_root"])
        shutil.rmtree(config_root)
        external = Path(self.temp.name) / "external-config"
        external.mkdir()
        config_root.symlink_to(external, target_is_directory=True)
        with self.assertRaises(MigrationError):
            self.apply_migration(self.root, self.receipt)
        self.assertFalse(self.receipt.exists())

    def test_install_root_preflight_rejects_group_writable_directory(self):
        config_root = self.path(self.manifest["config_root"])
        config_root.chmod(0o770)
        with self.assertRaises(MigrationError):
            self.apply_migration(self.root, self.receipt)
        self.assertFalse(self.receipt.exists())

    def test_auxiliary_write_and_import_chains_reject_unsafe_directories(self):
        applications = self.path(self.manifest["live_files"]["desktop_entry"]).parent
        tools = self.path(self.manifest["live_files"]["directory_sync_compat"]).parent
        for directory in (applications, tools):
            with self.subTest(directory=directory, condition="writable"):
                directory.chmod(0o770)
                with self.assertRaisesRegex(MigrationError, "unsafe install directory owner or mode"):
                    preflight_install_roots(self.manifest, self.root)
                directory.chmod(0o755)
        shutil.rmtree(tools)
        external = Path(self.temp.name) / "external-tools"
        external.mkdir()
        tools.symlink_to(external, target_is_directory=True)
        with self.assertRaisesRegex(MigrationError, "unsafe install directory type"):
            preflight_install_roots(self.manifest, self.root)

    def test_external_restore_restarts_runtime_and_restores_recorded_unit_state(self):
        hermes = self.manifest["hermes_retirement"]
        prior = {
            unit: {"is-enabled": "enabled", "is-active": "active"}
            for unit in managed_units(self.manifest)
        }
        prior[hermes["reaper_timer"]] = {"is-enabled": "disabled", "is-active": "inactive"}
        prior[self.manifest["standing_sweep_service"]] = {"is-enabled": "static", "is-active": "inactive"}

        class RestoreExecutor(Executor):
            def __init__(self, manifest):
                secrets = {}
                for target in manifest["targets"]:
                    secrets[target["private_key_var"]] = PRIVATE_SENTINEL
                    secrets[target["auth_tag_var"]] = AUTH_SENTINEL
                secrets[hermes["secret_variables"][0]] = PRIVATE_SENTINEL
                secrets[hermes["secret_variables"][1]] = AUTH_SENTINEL
                secrets[manifest["owner_private_key_var"]] = OWNER_SENTINEL
                super().__init__(manifest, secrets, dry_run=False)
                self.states = {
                    unit: {"is-enabled": "disabled", "is-active": "inactive"}
                    for unit in managed_units(manifest)
                }
                self.states[manifest["standing_sweep_service"]]["is-enabled"] = "static"
                self.member_roles = {hermes["memberships"][0]: "member"}
                self.identities = []

            def command(self, argv, identity=None, allowed_returncodes=(0,)):
                self.operations.append(argv)
                self.identities.append((argv, identity))
                if argv[:2] == [str(SYSTEMCTL), "--user"]:
                    verb = argv[2]
                    unit = argv[-1]
                    if verb in {"enable", "disable"}:
                        self.states[unit]["is-enabled"] = "enabled" if verb == "enable" else "disabled"
                    elif verb in {"restart", "stop"}:
                        self.states[unit]["is-active"] = "active" if verb == "restart" else "inactive"
                    elif verb == "is-enabled" and "--quiet" not in argv:
                        return self.states[unit]["is-enabled"].encode()
                    elif verb == "is-active" and "--quiet" not in argv:
                        return self.states[unit]["is-active"].encode()
                    return b""
                if argv[1:3] == ["agents", "archived"]:
                    return b"[]"
                if argv[1:3] == ["channels", "members"]:
                    return membership_payload(
                        self.manifest,
                        hermes_present=argv[-1] in self.member_roles,
                        hermes_role=self.member_roles.get(argv[-1], "member"),
                    )
                if argv[1:3] == ["channels", "add-member"]:
                    channel = argv[argv.index("--channel") + 1]
                    self.member_roles[channel] = argv[argv.index("--role") + 1]
                if argv[1:3] == ["channels", "remove-member"]:
                    self.member_roles.pop(argv[argv.index("--channel") + 1], None)
                return b"{}"

        executor = RestoreExecutor(self.manifest)
        directory_calls = []
        desired_memberships = {channel: "member" for channel in hermes["memberships"]}
        desired_memberships[hermes["memberships"][0]] = "absent"
        desired_memberships[hermes["memberships"][1]] = "admin"
        execute_restore_external(
            self.manifest,
            executor,
            prior,
            self.kind0_snapshots(),
            desired_memberships,
            directory_runner=lambda manifest, runner, snapshots: directory_calls.append((manifest, runner, snapshots)),
        )
        restarts = {item[-1] for item in executor.operations if item[:3] == [str(SYSTEMCTL), "--user", "restart"]}
        self.assertEqual(restarts, {unit for unit, state in prior.items() if state["is-active"] == "active"})
        self.assertEqual(executor.states, prior)
        operations = " ".join(" ".join(item) for item in executor.operations)
        self.assertNotIn("hermes-gateway.service", operations)
        self.assertNotIn("/home/victor/.hermes", operations)
        self.assertNotIn("hermes-acp", operations)
        self.assertEqual(len(directory_calls), 1)
        owner_adds = [
            (argv, identity) for argv, identity in executor.identities
            if argv[1:3] == ["channels", "add-member"]
        ]
        self.assertEqual(len(owner_adds), 26)
        self.assertTrue(all(
            identity == {"private_key_var": self.manifest["owner_private_key_var"]}
            for _, identity in owner_adds
        ))
        self.assertEqual(
            executor.member_roles,
            {channel: role for channel, role in desired_memberships.items() if role != "absent"},
        )

    def test_owner_membership_refusal_fails_closed_before_unit_restart(self):
        hermes = self.manifest["hermes_retirement"]
        manifest = self.manifest
        prior = {
            unit: {"is-enabled": "enabled", "is-active": "active"}
            for unit in managed_units(self.manifest)
        }
        prior[self.manifest["standing_sweep_service"]]["is-enabled"] = "static"

        class RefusingExecutor(Executor):
            def __init__(self):
                secrets = {
                    manifest["owner_private_key_var"]: OWNER_SENTINEL,
                    hermes["secret_variables"][0]: PRIVATE_SENTINEL,
                    hermes["secret_variables"][1]: AUTH_SENTINEL,
                }
                super().__init__(manifest, secrets, dry_run=False)

            def command(inner_self, argv, identity=None, allowed_returncodes=(0,)):
                inner_self.operations.append(argv)
                if argv[1:3] == ["agents", "archived"]:
                    return b"[]"
                if argv[1:3] == ["channels", "members"]:
                    return membership_payload(manifest, hermes_present=False)
                if argv[1:3] == ["channels", "add-member"]:
                    raise MigrationError("owner add-member unavailable")
                return b""

        executor = RefusingExecutor()
        with self.assertRaisesRegex(MigrationError, "owner add-member unavailable"):
            execute_restore_external(
                self.manifest,
                executor,
                prior,
                self.kind0_snapshots(),
                {channel: "member" for channel in hermes["memberships"]},
            )
        self.assertFalse(any(
            item[:3] == [str(SYSTEMCTL), "--user", "restart"]
            for item in executor.operations
        ))

    def test_external_rollback_failure_records_truthful_receipt(self):
        self.apply_migration(self.root, self.receipt)
        receipt_path = self.receipt / "receipt.json"
        receipt = json.loads(receipt_path.read_text())
        receipt["root"] = "/"
        receipt["pre_service_state"] = {
            unit: {"is-enabled": "enabled", "is-active": "active"}
            for unit in managed_units(self.manifest)
        }
        receipt["pre_kind0_names"] = self.kind0_snapshots()
        receipt["pre_memberships"] = {
            channel: "member"
            for channel in self.manifest["hermes_retirement"]["memberships"]
        }
        receipt_path.write_text(json.dumps(receipt))
        restored_secrets = {}
        for target in self.manifest["targets"]:
            restored_secrets[target["private_key_var"]] = PRIVATE_SENTINEL
            restored_secrets[target["auth_tag_var"]] = AUTH_SENTINEL
        restored_secrets[self.manifest["hermes_retirement"]["secret_variables"][0]] = PRIVATE_SENTINEL
        restored_secrets[self.manifest["hermes_retirement"]["secret_variables"][1]] = AUTH_SENTINEL
        restored_secrets[self.manifest["owner_private_key_var"]] = OWNER_SENTINEL
        fake_executor = mock.Mock()
        fake_executor.operations = []
        fake_executor.secrets = {}

        def fake_command(argv, identity=None, allowed_returncodes=(0,)):
            fake_executor.operations.append(argv)
            if argv[2:3] == ["is-enabled"]:
                return b"enabled"
            if argv[2:3] == ["is-active"]:
                return b"inactive"
            return b""

        fake_executor.command.side_effect = fake_command
        original_read_bytes = Path.read_bytes

        def fixture_read_bytes(path):
            if str(path) == self.manifest["live_files"]["secrets"]:
                return self.path(self.manifest["live_files"]["secrets"]).read_bytes()
            return original_read_bytes(path)

        with mock.patch("migration.preflight_install_roots"), \
             mock.patch("migration.validate_membership_sweep_dependency", return_value={}), \
             mock.patch("migration.validate_restore_state", return_value=receipt["pre_service_state"]), \
             mock.patch("migration.preflight_external_dependencies", return_value={}), \
             mock.patch(
                 "migration.preflight_restore_memberships",
                 return_value={channel: "absent" for channel in self.manifest["hermes_retirement"]["memberships"]},
             ), \
             mock.patch("migration.parse_env", return_value=restored_secrets), \
             mock.patch("migration.Executor", return_value=fake_executor), \
             mock.patch.object(Path, "read_bytes", fixture_read_bytes), \
             mock.patch("migration.execute_restore_external", side_effect=MigrationError("fixture failure")):
            with self.assertRaises(MigrationError):
                restore(self.receipt, execute_external=True)
        failed = json.loads(receipt_path.read_text())
        self.assertEqual(failed["status"], "rollback_failed")
        self.assertEqual(failed["rollback_error_type"], "MigrationError")

    def test_rollback_publisher_has_import_safe_tool_path(self):
        publisher = (HERE.parent / "payloads" / "buzz-sats-directory-sync.py").read_text()
        migration = (HERE.parent / "migration.py").read_text()
        self.assertIn('INSTALLED_TOOL_DIR = "/home/victor/.agents/tools"', publisher)
        self.assertIn('str(BUNDLE / "payloads" / "buzz-sats-directory-sync.py")', migration)
        self.assertIn('"--restore-kind0-stdin"', migration)

    def test_public_payloads_match_manifest(self):
        profiles = json.loads((HERE.parent / "payloads" / "profiles.json").read_text())
        self.assertEqual(
            {(item["slug"], item["pubkey"], item["kind_0"]["display_name"]) for item in profiles["events"]},
            {(item["slug"], item["pubkey"], item["display_name"]) for item in self.manifest["targets"]},
        )
        self.assertTrue(all(
            set(item["kind_0"]) == {"preserve", "display_name"}
            and item["kind_0"]["preserve"] == ["name"]
            for item in profiles["events"]
        ))
        units = json.loads((HERE.parent / "payloads" / "systemd.json").read_text())
        hermes = self.manifest["hermes_retirement"]
        self.assertEqual(units["disable_stop_exact"], [hermes["agent_unit"], hermes["reaper_timer"]])
        self.assertEqual(len(managed_units(self.manifest)), 15)
        self.assertEqual(len(retained_runtime_units(self.manifest)), 11)
        self.assertEqual(
            units["pause_restore_exact"],
            [self.manifest["standing_sweep_timer"], self.manifest["standing_sweep_service"]],
        )
        self.assertEqual(
            units["preserve_exact"],
            ["buzz-sats-agent@.service", "agent-child-reaper@.timer", *self.manifest["preserve_units"]],
        )
        self.assertEqual(units["install_template"]["path"], self.manifest["live_files"]["agent_service"])
        self.assertIn(self.manifest["install_root"], units["install_template"]["exec_start"])
        broken = json.loads(json.dumps(self.manifest))
        broken["hermes_retirement"]["memberships"].pop()
        with self.assertRaises(MigrationError):
            validate_manifest(broken)

    def test_desktop_launcher_exports_only_reviewed_environment(self):
        launcher = (HERE.parent / "payloads" / "launch_buzz_desktop.sh").read_text()
        self.assertTrue(launcher.startswith("#!/usr/bin/bash -p\n"))
        self.assertNotIn("/proc/", launcher)
        self.assertNotIn("/usr/bin/cmp", launcher)
        self.assertNotIn("/usr/bin/env -i", launcher)
        self.assertNotIn("247<", launcher)
        self.assertIn("/usr/bin/python3 -I -S -E -c", launcher)
        start = launcher.index("clear_exported_environment\nbuiltin export HOME=")
        end = launcher.index("assert_exact_exported_environment\n", start)
        export_block = launcher[start:end]
        exported = set(re.findall(r"^.*?export ([A-Z][A-Z0-9_]*)=", export_block, re.MULTILINE))
        self.assertEqual(exported, {
            "HOME", "USER", "LOGNAME", "PATH", "LANG", "LC_ALL", "TMPDIR",
            "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY",
            "BUZZ_PRIVATE_KEY", "BUZZ_SHARE_IDENTITY", "BUZZ_RELAY_URL", "HF_HUB_CACHE",
            "HF_XET_CACHE", "MESH_LLM_NATIVE_RUNTIME_CACHE_DIR",
        })
        self.assertIn("builtin unset -f", launcher)
        self.assertIn("fallback_xauthority=/home/victor/.Xauthority", launcher)
        self.assertIn("XAUTHORITY is group/world-writable", launcher)
        self.assertIn("builtin export -n desktop_xauthority", launcher)
        self.assertIn("Buzz AppImage has unsafe ownership or link count", launcher)
        self.assertIn("reviewed artifact directory is group/world-writable", launcher)
        self.assertLess(
            launcher.index("XAUTHORITY is unset and fallback is missing"),
            launcher.index('. "${secret_file}"'),
        )
        self.assertIn("inherited exported environment was not fully cleared", launcher)
        self.assertIn("unexpected exported environment name", launcher)
        self.assertNotIn("unset BUZZ_OWNER_PRIVATE_KEY", launcher)

    def test_desktop_launcher_xwayland_preserves_safe_xauthority_and_drops_functions(self):
        result, exported, sentinel, xauthority, _ = self.run_desktop_launcher(
            display=":0",
            wayland_display="wayland-0",
            xauthority="default",
            hostile=True,
            preopened_fd=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(sentinel.exists())
        self.assertNotIn("LEAK_ME", exported)
        self.assertFalse(any(name.startswith("BASH_FUNC_") for name in exported))
        self.assertEqual(exported["XAUTHORITY"], str(xauthority))
        self.assertEqual(exported["DISPLAY"], ":0")
        self.assertEqual(exported["WAYLAND_DISPLAY"], "wayland-0")
        self.assertEqual(set(exported), {
            "HOME", "USER", "LOGNAME", "PATH", "LANG", "LC_ALL", "TMPDIR",
            "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY",
            "BUZZ_PRIVATE_KEY", "BUZZ_SHARE_IDENTITY", "BUZZ_RELAY_URL", "HF_HUB_CACHE",
            "HF_XET_CACHE", "MESH_LLM_NATIVE_RUNTIME_CACHE_DIR",
        })

    def test_desktop_launcher_deexports_inherited_desktop_xauthority_before_clear(self):
        result, exported, sentinel, xauthority, _ = self.run_desktop_launcher(
            display=":0",
            wayland_display="wayland-0",
            xauthority="default",
            hostile=True,
            inherited_desktop_xauthority=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(sentinel.exists())
        self.assertEqual(exported["XAUTHORITY"], str(xauthority))
        self.assertNotIn("desktop_xauthority", exported)
        self.assertNotIn("inherited-export-must-not-survive", exported.values())

    def test_desktop_launcher_deexports_inherited_readonly_variable_after_unset_fails(self):
        probe = subprocess.run(
            [
                "/usr/bin/bash",
                "-p",
                "-c",
                """
builtin set -euo pipefail
readonly session_display=:0
is_exported() {
  builtin local name
  while IFS= read -r name; do
    [[ ${name} == session_display ]] && return 0
  done < <(builtin compgen -e)
  return 1
}
is_exported
if builtin unset -v session_display 2>/dev/null; then
  builtin exit 17
fi
builtin export -n session_display
! is_exported
[[ ${session_display} == :0 ]]
builtin printf 'readonly-export-fallback-ok\\n'
""",
            ],
            env={"session_display": "inherited-readonly-must-not-survive"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(probe.returncode, 0, probe.stderr)
        self.assertEqual(probe.stdout, "readonly-export-fallback-ok\n")

        result, exported, sentinel, xauthority, _ = self.run_desktop_launcher(
            display=":0",
            wayland_display="wayland-0",
            xauthority="default",
            inherited_readonly_export=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(sentinel.exists())
        self.assertEqual(exported["DISPLAY"], ":0")
        self.assertEqual(exported["XAUTHORITY"], str(xauthority))
        self.assertNotIn("session_display", exported)
        self.assertNotIn("inherited-readonly-must-not-survive", exported.values())

    def test_desktop_launcher_pure_wayland_omits_xauthority(self):
        result, exported, sentinel, _, _ = self.run_desktop_launcher(
            display="", wayland_display="wayland-1", hostile=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(sentinel.exists())
        self.assertNotIn("DISPLAY", exported)
        self.assertNotIn("XAUTHORITY", exported)
        self.assertEqual(exported["WAYLAND_DISPLAY"], "wayland-1")
        self.assertEqual(set(exported), {
            "HOME", "USER", "LOGNAME", "PATH", "LANG", "LC_ALL", "TMPDIR",
            "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "WAYLAND_DISPLAY",
            "BUZZ_PRIVATE_KEY", "BUZZ_SHARE_IDENTITY", "BUZZ_RELAY_URL", "HF_HUB_CACHE",
            "HF_XET_CACHE", "MESH_LLM_NATIVE_RUNTIME_CACHE_DIR",
        })

    def test_desktop_launcher_rejects_xauthority_without_display(self):
        result, exported, sentinel, _, _ = self.run_desktop_launcher(
            display="", wayland_display="wayland-1", xauthority="default", hostile=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("XAUTHORITY is set without X11 or XWayland", result.stderr)
        self.assertIsNone(exported)
        self.assertFalse(sentinel.exists())

    def test_desktop_launcher_uses_safe_default_xauthority_when_unexported(self):
        result, exported, sentinel, _, fallback = self.run_desktop_launcher(
            display=":0",
            wayland_display="wayland-0",
            hostile=True,
            preopened_fd=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(sentinel.exists())
        self.assertEqual(exported["XAUTHORITY"], str(fallback))
        self.assertEqual(exported["DISPLAY"], ":0")
        self.assertNotIn("BASH_ENV", exported)
        self.assertNotIn("BASH_ENV_INJECTED", exported)

    def test_desktop_launcher_rejects_missing_or_unsafe_xauthority(self):
        cases = (
            (Path("relative-Xauthority"), "must be an absolute path"),
            (Path(self.temp.name) / "missing-Xauthority", "XAUTHORITY is missing"),
            ("symlink", "linked or not a regular file"),
            ("group-writable", "group/world-writable"),
        )
        for xauthority, message in cases:
            with self.subTest(xauthority=xauthority):
                result, exported, sentinel, _, _ = self.run_desktop_launcher(
                    display=":0", wayland_display="wayland-0", xauthority=xauthority,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertIsNone(exported)
                self.assertFalse(sentinel.exists())

    def test_desktop_launcher_rejects_missing_or_unsafe_default_xauthority(self):
        for fallback, message in (
            ("missing", "fallback is missing"),
            ("symlink", "linked or not a regular file"),
            ("group-writable", "group/world-writable"),
        ):
            with self.subTest(fallback=fallback):
                result, exported, sentinel, _, _ = self.run_desktop_launcher(
                    display=":0",
                    wayland_display="wayland-0",
                    fallback=fallback,
                    hostile=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertIsNone(exported)
                self.assertFalse(sentinel.exists())

    def test_desktop_launcher_rejects_unsafe_appimage_or_directory(self):
        for appimage_state, message in (
            ("group-writable", "Buzz AppImage is group/world-writable"),
            ("symlink", "Buzz AppImage is missing, linked, unreadable, or not executable"),
            ("directory-group-writable", "reviewed artifact directory is group/world-writable"),
        ):
            with self.subTest(appimage_state=appimage_state):
                result, exported, sentinel, _, _ = self.run_desktop_launcher(
                    display=":0",
                    wayland_display="wayland-0",
                    xauthority="default",
                    appimage_state=appimage_state,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertIsNone(exported)
                self.assertFalse(sentinel.exists())

    def test_desktop_launcher_rejects_unsafe_intermediate_appimage_directory(self):
        result, exported, sentinel, _, _ = self.run_desktop_launcher(
            display=":0",
            wayland_display="wayland-0",
            xauthority="default",
            appimage_state="intermediate-directory-group-writable",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertRegex(
            result.stderr,
            r"reviewed artifact directory is group/world-writable: .*/work\n",
        )
        self.assertIsNone(exported)
        self.assertFalse(sentinel.exists())

    def test_bash_privileged_mode_ignores_bash_env_and_imported_functions(self):
        probe = Path(self.temp.name) / "bash-p-probe"
        probe.mkdir(mode=0o700)
        marker = probe / "bash-env-ran"
        bash_env = probe / "bash-env"
        bash_env.write_text(f"/usr/bin/touch {marker}\nexport BASH_ENV_PROBE=sourced\n")
        environment = {
            "BASH_ENV": str(bash_env),
            "BASH_FUNC_roster_probe%%": "() { return 17; }",
        }
        control = subprocess.run(
            [
                "/usr/bin/bash", "-c",
                "[[ ${BASH_ENV_PROBE:-} == sourced ]] && builtin declare -F roster_probe >/dev/null",
            ],
            env=environment,
            check=False,
        )
        self.assertEqual(control.returncode, 0)
        self.assertTrue(marker.exists())
        marker.unlink()
        privileged = subprocess.run(
            [
                "/usr/bin/bash", "-p", "-c",
                "[[ -z ${BASH_ENV_PROBE:-} ]] && ! builtin declare -F roster_probe >/dev/null",
            ],
            env=environment,
            check=False,
        )
        self.assertEqual(privileged.returncode, 0)
        self.assertFalse(marker.exists())

    def test_runtime_inventory_excludes_generic_hermes_and_system_agents(self):
        self.assertTrue(set(self.manifest["preserve_units"]).isdisjoint(managed_units(self.manifest)))
        backup_inventory = "\n".join(str(path) for path in backup_paths(self.manifest, self.root))
        for forbidden in ("hermes-gateway.service", "/home/victor/.hermes", "hermes-acp", "/home/buzz-mempool", "/home/buzz-genesis"):
            self.assertNotIn(forbidden, backup_inventory)

    def test_full_live_fleet_dependency_is_buzz_owned_and_digest_pinned(self):
        launcher = (HERE.parent / "payloads" / "launch_buzz_agent.sh").read_text()
        service = (HERE.parent / "payloads" / "buzz-sats-agent@.service").read_text()
        compatibility = (HERE.parent / "payloads" / "buzz-sats-directory-sync-wrapper.py").read_text()
        self.assertNotIn("/home/victor/projects", launcher + service)
        self.assertIn(self.manifest["install_root"], service)
        self.assertIn(self.manifest["live_files"]["directory_sync"], compatibility)
        self.assertEqual(len(self.manifest["fleet_prompts"]), 8)
        for item in self.manifest["fleet_prompts"]:
            prompt = HERE.parent / "payloads" / "prompts" / item["name"]
            self.assertEqual(hashlib.sha256(prompt.read_bytes()).hexdigest(), item["sha256"])
            self.assertIn(item["path"], launcher)
            self.assertIn(f"system_prompt_sha256={item['sha256']}", launcher)

if __name__ == "__main__":
    unittest.main()

# Mempool and Genesis credential handoff

This package adds an absent-only key handoff for the two framework-desktop
agents. It does not save Buzz identities, read the live keyring during build or
review, install credentials, start services, add memberships, open DMs, or send
messages.

The unprivileged controller creates one anonymous pipe. The exporter reads the
production Buzz Desktop keyring blob under the same advisory lock as Desktop,
selects only the requested agent entry, derives and verifies the requested
public key, and writes one lowercase secret scalar to file descriptor 3. The
root receiver reads the expected public key from a root-owned strict map,
derives the public key independently, and publishes the matching credential
under /etc/buzz-agents/credentials through O_TMPFILE and linkat. The root
receiver holds the slug lock, rejects every existing target, then signals the
controller to start the exporter. It performs no secret read before that
absent-only gate. Existing files, unsafe metadata, symlinks, and hard links all
fail closed.

The updated service unit loads that root-owned file with systemd
LoadCredential. The service user never owns the credential path. Services stay
disabled and inactive until serial identity enrollment and smoke checks finish.

Activation order is split across two reviewed promotion boundaries because the
authority-bearing enrollment map cannot exist before Buzz Desktop creates both
public identities:

1. Freeze and review the fixed Desktop artifact plus static service tools.
2. Run the reviewed static-system and Desktop installers, restart Desktop, and keep both agents
   disabled and inactive. The old closure intentionally fails against the new
   verifier until the dynamic review closes.
3. Save Mempool in the fixed Buzz Desktop, record its full pubkey, and close the
   dialog before sending the Genesis draft.
4. Save Genesis, verify distinct full pubkeys, and install the public enrollment
   map candidate once.
5. Freeze and review the exact map, full installed-runtime manifest, and final
   closure. Install the accepted map and closure last.
6. Run the controller once per slug. Never print or inspect key files.
7. Start and verify one agent at a time. Add only the approved Sats/Victor
   channels, then DMs and explicit mention/reply tests.

Freeze the static and Desktop install bytes with one manifest:

```sh
python3 scripts/mempool-genesis/freeze-install-package.py \
  --package /home/victor/.cache/tmp/mempool-genesis-install-package \
  --package-id mempool-genesis-install-050ac722 \
  --desktop-app /path/to/Buzz_0.5.8-fixed-050ac722_amd64.AppImage
```

The freezer refuses a dirty source worktree, runs
`cargo build --release -p buzz-agent-key-handoff`, and rechecks that the build
did not change Git-visible state before copying any package source.
The freezer reads the current launcher only from
`/home/victor/projects/buzz/scripts/launch_buzz_desktop.sh`. It copies neither
that file nor application data. The package owns no prompt files, so the v2
schema has exactly nine entries: seven static-system sources, the AppImage, and
the bundled launcher. `install-package.manifest.json` records each target path
and SHA-256, both launcher hashes, and a package fingerprint over sorted
`<status>\t<sha256>\t<target>\n` records. The evidence bundle must list the nine
absolute package source paths in byte order and repeat the manifest's three
named fingerprints.

`install-reviewed-desktop` never starts the GUI. It installs the pinned
AppImage and swaps only the reviewed launcher after preserving the old launcher
under `rollback-desktop-050ac722106c`. `rollback-reviewed-desktop` restores
that launcher without deleting the new AppImage or touching application data.
The installer hashes the bundled launcher at runtime. It accepts the previous
live launcher only when the terminal evidence bundle records its hash as
`desktop_previous_launcher_sha256`. Before the launcher swap, it writes both
accepted hashes to the owner-only rollback receipt. Rollback consumes that
receipt instead of source-pinned hashes.

`install-static-system.py` accepts only an evidence v2 files-mode closure whose
changed-path set and per-path hashes exactly match all nine manifest sources.
The static and Desktop installers validate that same full accepted set before
selecting their schema-owned entries. The static installer writes a complete
rollback receipt before changing system paths.
Each install uses a UTC timestamped backup ID, which the installer prints; pass
that exact ID to `rollback --backup-id ID`.

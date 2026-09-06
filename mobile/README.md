# Buzz Mobile

Flutter mobile client for Buzz.

## Setup

```bash
cd mobile
flutter pub get
```

## Run

```bash
# From repo root (recommended — starts Docker, relay, and simulator):
just mobile-dev

# Direct (requires services and relay already running):
cd mobile && flutter run
```

### Worktree-aware debug identity

Debug builds produced from a git worktree get a unique app identifier keyed
to the **worktree directory name**
(`com.buzz.buzzMobile.<slug>` on iOS,
`xyz.block.buzz.mobile.<slug>` on Android) plus a display-only branch label
in the app name (`Buzz (my-branch)`, or a short SHA when the worktree is
detached). Because the identifier follows the directory rather than the
branch, one worktree keeps exactly one installed app — and its login state —
across branch switches, and builds from multiple worktrees install side by
side, mirroring the desktop dev experience. Release and profile builds
always keep the production identity and name.

`just mobile-dev` and `just mobile-build-android` apply this automatically by
running `scripts/mobile-worktree-overrides.sh`, which writes two gitignored
files:

- `mobile/ios/Flutter/WorktreeOverrides.xcconfig` (included by Debug builds
  only; a developer's `AppOverrides.xcconfig` is included after it, so
  app-specific overrides like a personal `BUNDLE_IDENTIFIER` for device
  signing always win)
- `mobile/android/worktree.properties` (read by the debug build type only)

For direct Xcode / Android Studio / `flutter run` development, run
`./scripts/mobile-worktree-overrides.sh` from the repo root once per branch
switch to refresh the display label (the install identity never changes);
the persisted files are then picked up by any subsequent build. In the main
checkout the script is a no-op that removes stale override files, restoring
the plain `Buzz` identity.

To remove leftover worktree-suffixed installs from booted iOS simulators and
connected Android emulators, run `just mobile-clean` (add `--dry-run` via
`./scripts/mobile-worktree-clean.sh --dry-run` to preview). Production
installs are never touched.

### iOS push capability

Every iOS artifact builds and embeds the Notification Service Extension and
native push bridge. Runtime activation is fail-closed and scoped to the current
relay. After authenticated connectivity and a fully valid NIP-11 `nip-pl` push
descriptor, Buzz independently requests display permission and registers with
APNs. Display denial or request failure does not gate the device token, gateway
enrollment, or lease publication, so a later user opt-in can display pushes
without rebuilding transport authority. An absent, malformed, or unreachable
descriptor leaves push inactive without partial enrollment.

Relay rollout remains an explicit deployment opt-in. Only deployments with
`BUZZ_PUSH_ENABLED=true` advertise the descriptor and process push. See
`docs/push-gateway-deployment.md` for the canonical gateway profile contract,
manual physical-device proof, measurements, and rollback procedure.

The fork retains iOS `com.buzz.buzzMobile` and worktree-isolated Debug identities.
The Apple team remains unset until an approved iOS identity is supplied through
`mobile/ios/Flutter/AppOverrides.xcconfig`. Configure the matching gateway App
Attest app ID, APNs topic/certificate/environment, parent and extension App
Groups, Keychain groups, and provisioning profiles together. The parent requires
Communication Notifications. This packet provisions none of them and contains
only the `buzz-ios-dogfood` application profile; there is no App Store profile.
Android's separate `xyz.block.buzz.mobile` identity and local notifications are
unchanged. See [the fork adoption boundary](../docs/mobile-push-adoption.md) for
migration retirement, unsigned CI runner admission, and remaining rollout gates.

APNs and the gateway continue to carry only the constant opaque wake-up. The
extension fetches the message from the scoped relay, verifies message, sender
profile, and channel-metadata signatures, and uses a bounded App Group cache
for names and app-rendered avatar thumbnails. It never fetches an avatar URL;
missing, stale, or invalid enrichment falls back to the verified message with a
short sender pubkey, community subtitle, and no image.

## Checks

```bash
dart format --output=none --set-exit-if-changed .
flutter analyze
flutter test
```

Or from the repo root: `just mobile-check` and `just mobile-test`.

## Android release signing

Android release builds fail unless all upload-key inputs are supplied through the
environment:

- `BUZZ_ANDROID_UPLOAD_KEYSTORE_PATH`: path to a CI-vended keystore file
- `BUZZ_ANDROID_UPLOAD_KEYSTORE_PASSWORD`
- `BUZZ_ANDROID_UPLOAD_KEY_ALIAS`
- `BUZZ_ANDROID_UPLOAD_KEY_PASSWORD`

The keystore path must be absolute, and the keystore must remain outside the
repository. Development and debug builds do not require these variables.

Release pipelines that sign through the central APK Signer service instead of
a local upload keystore must set `BUZZ_ANDROID_RELEASE_SIGNING=external`. That
mode produces an unsigned release bundle and refuses to run if any
`BUZZ_ANDROID_UPLOAD_*` value is also set.

## Architecture

```
lib/
├── main.dart              # Entry point, Riverpod bootstrap
├── app.dart               # MaterialApp with theme
├── shared/
│   └── theme/             # Catppuccin light/dark, spacing tokens, extensions
└── features/
    └── home/              # Placeholder home surface
```

- **State management:** Riverpod + Hooks (`HookConsumerWidget`)
- **Theme:** Catppuccin Latte (light) / Macchiato (dark) — matches desktop
- **Spacing:** `Grid` tokens for consistent spacing
- **Linting:** `flutter_lints` + `riverpod_lint` via `custom_lint`
- **Feature isolation:** No cross-feature imports except `shared/`

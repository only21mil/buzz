# Release identity routes

Each platform has one documented user route that needs no dev checkout,
toolchain, or manual sidecar repair. Until a route meets that bar with
receipts, its platform hold stays open in known-holds.md.

## Desktop, Linux and macOS

Source version at HEAD is 0.5.20 in desktop/package.json and the Tauri
manifest. Upstream sits at 0.5.23. The verifier at
scripts/desktop_release.py:308-370 binds candidate metadata and three version
fields, so the fork identity and version fields must survive the sync
unchanged (CD-4). Version bumps go through the existing release process in
docs/desktop-fork-release.md, never as drive-by edits inside the
reconciliation.

Tags are immutable: desktop-v<VERSION> points at the reviewed PR head, never
an arbitrary later main commit. A version-only candidate may be its own
commit, and it carries its own fork release gates. Never relabel a binary or
ship different bytes under a published identity. Every receipt binds source
commit and tree, tag object and peeled commit, platform version, toolchain,
artifact hashes, signer identity, build provenance, and downloaded and
installed readback.

The MBP is the Apple build, sign, and test host. The retired Mini is
forbidden. Upstream-only guards in release.yml and signed-macos-canary.yml
stay in place; the fork needs its own reviewed publisher or approved local
route with real key custody, plus the approved Tauri public key and fork
updater endpoint in the release config. Update tests cover failure,
cancel, and restore of the last compatible signed app with data kept.

## Android

Last receipted artifact is 0.5.9-only21mil.rc.1, code 1000509001, published
and installed with the retained signer (Sep 5 canon receipt). That receipt is
newer than the release doc's proposal baseline but still needs kickoff
readback. It is not a proposal for the next release, and code 2 was never
current. Confirm the adopted signer and key custody under the authorized
workflow before building.

Physical Fold acceptance is required. Upgrades keep the same signer and a
strictly increasing version code over the canonical installed app, installed
with reviewed adb install -r on the intended profile. Never uninstall, reset
data, or downgrade to dodge a signature or version mismatch. Every build gets
manifest, compiled APK, and artifact scans for prohibited Google components
before acceptance. QR scanning stays on ZXing. The duplicate-key and ML Kit
insertion from the raw merge (MW-2) must never reach a release branch.

## iOS

No confirmed TestFlight baseline is in scope. Reconcile the Release.xcconfig
default com.buzz.buzzMobile against the candidate admission contract
com.sats21m.buzz, the actual approved ASC record, extension IDs, and effective
overrides before choosing an identity. Neither string proves an owned app
record or a valid profile. Build on the MBP under the Apple workflows,
upload, await processing, and assign only the intended testers as authorized.
No App Store review submission and no public release. For a first-ever
TestFlight distribution, record the missing baseline honestly and prove
upgrade from an earlier authorized test build.

## Browser and relay

Browser and relay deployments serve mutually compatible versions. The P03 and
P04 leads maintain an explicit version matrix before any production promotion:
old installed clients against the candidate relay, candidate clients against
the oldest supported relay, new admin-web against old and new admin API, and
previous and candidate relay binaries against each supported schema. A network
connection alone never proves compatibility. Unsupported combinations get an
intentional gate and a clear upgrade instruction.

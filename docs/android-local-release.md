# Local Android releases for only21mil

Use this route to publish fork Android APKs while keeping the retained key only
in Victor's approved local secret store. The existing GitHub signing workflow
is a separate route and remains unconfigured until its custody is separately
settled. `docs/delivery-lifecycle.md` governs review and publication.

## Signing identity adoption

This candidate proposes adopting the canonical Fold private-canary signer for
only21mil Android distribution. Adoption takes effect only when the responsible
controller closes the complete signing and publication review and promotes this
candidate. The certificate SHA-256 is
`cc25c85edae8b74a2a81f46e328c381d96af28094b2f1f92f632399e9f46d0db`.
The retained PKCS12 and password remain in the existing
`BUZZ_ANDROID_PRIVATE_CANARY_*` fields in `~/.config/sats/secrets.env`.
The historical field names and certificate subject stay unchanged. The signer
has no key-generation or secret-store mutation command.

The old GitHub `android-release` pin is
`6a31e6313a5a44134985fc74135a1912b93b4a172a1523ce4900aed1d320f59b`.
No held key has been demonstrated for it. This local adoption does not change
that environment, claim recovery of its key, or relabel the prior private APK.

The first proposed release is `only21mil-android-v0.5.9-rc.1`, version
`0.5.9-only21mil.rc.1`, code `1000509001`. It uses the same signer and package
`xyz.block.buzz.mobile` as the installed private code 2, allowing an in-place
update that preserves app data. Pairing is deferred to Victor and is independent
of this release gate.

## Prepare and freeze

1. Use a clean source worktree. Derive version name and code with
   `scripts/android-fork-release-metadata.py`. Create the annotated tag locally.
   Build unsigned with `BUZZ_ANDROID_RELEASE_SIGNING=external` and the derived
   Flutter `--build-name` and `--build-number`. Run the maintained Google-free
   dependency guard and unsigned verifier.
2. Place the unsigned APK and dependency manifest in an owned mode-0700
   directory. Write a mode-0600 `buzz-local-android-release-v1` manifest using
   the exact fields accepted by `scripts/android-local-release.py`. Include
   source root, commit, tree, annotated source tag, package, versions and both
   artifact hashes. Keep source worktree and artifacts fixed through signing.
3. Have the controller bind the helper commit, source, manifest hash, approved
   signer fingerprint, secret-store preimage and actual promotion actions.
   Signing, authoritative tag publication, public release assets and device
   installation each need current review coverage and standing authorization.

## Sign and publish

1. Run `android-local-release.py sign` as Victor inside an isolated network
   namespace. When `sudo`, `unshare` and `setpriv` switch to the operator UID,
   explicitly set `HOME` to that operator's home, `HOME=/home/victor` for Victor.
   The helper uses `Path.home()` to locate the approved store. Changing UID
   alone does not set `HOME`. Supply the captured host namespace through
   `HOST_NETWORK_NAMESPACE`, and explicit `--candidate-manifest`,
   `--manifest-sha256`, `--store-preimage-sha256`, `--cert` and `--build-tools`.
   The helper verifies the clean source, official tag/version and unsigned
   artifact before reading the retained key. Keystore and separate password
   readers are sealed anonymous memory files. The final APK verifier checks the
   expected signer, package, version and Google-free dependency manifest.
2. Write provenance with `scripts/write-android-fork-release-provenance.py`.
   Freeze the signed APK hash and exact release notes before publication.
3. Publish the annotated tag to the authoritative Buzz relay first, using the
   existing owner credential through the credential helper. Read back the tag
   object and peeled source commit on both Buzz and GitHub after mirror sync.
   Run `scripts/verify-android-fork-release-ref.sh` from trusted main.
4. Create the GitHub prerelease for that existing tag with `--verify-tag` and
   explicit `--latest=false`. Publish the hash-named APK, `provenance.json`, and
   `buzz-runtime-dependencies.tsv`. Download published assets and compare all
   bytes to the frozen local artifacts. Preserve the exact URLs and readbacks.

## Updates and rollback

Install a reviewed release with `adb install -r` only on the intended existing
canonical user profile. Verify the installed APK hash, signer, version and code,
then cold launch without pairing. Preserve the installed app and its data if a
check fails. Recovery uses a corrected APK signed by the same key with a higher
version code. An immutable release tag stays fixed; a withdrawal marks release
notes and removes the defective download only under the controller's bound
rollback action. Never use uninstall or data reset to bypass signer mismatch.

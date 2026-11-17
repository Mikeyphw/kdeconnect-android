# KDE Connect community fork — final acceptance evidence

The source of truth for delivery is `Mikeyphw/kdeconnect-android`, pull request #1,
`feature/community-quit-updater-shizuku-audit-final-20261116`. The review was
started at PR HEAD `f93acda33549fe41202e3c865278c237ab24d571`; always
revalidate **the resulting** PR HEAD and required hosted checks after applying
new changes. The upstream master and this fork's feature branch must not be
reset/rebased/force-pushed or merged automatically.

## Qualified versus unqualified evidence

- Previous PR HEAD `f93acda...`: hosted Android debug/release unit tests,
  `lintDebug`, `lintRelease`, optimized release build, debug build, and unsigned
  community package identity passed (Actions run `43973329983`). This is
  **source/build evidence only**; a fresh run is mandatory for every subsequent
  commit.
- Reviewed source uses HTTPS GitHub release discovery; enforces expected
  repository/tag/asset, file SHA-256 and size, release package/version and the
  installed signing certificate before attempting to install. The new code
  validates *every* HTTPS redirect hop before connecting, instead of validating
  only the final landing host; bounded redirects and negative URL tests are
  included in the same acceptance overlay.
- Release signing key identity, root, Shizuku, Sui, app permissions, and Android
  16 device behavior are **not qualified** by a green PR workflow.
- No stable community release was published when this plan was prepared.
  No same-signer upgrade pair was available, so updater end-to-end or production
  installation cannot truthfully be marked passed at this stage.
- `lint-baseline.xml` has an existing fixed **444-issue localization-only**
  backlog (424 MissingTranslation; 20 ExtraTranslation). It is not a claim of
  complete localization, and all other lint errors remain blocking.

## 1. Real-device test run (Termux, no automatic installation)

Use the exact green PR debug APK downloaded from GitHub Actions (run `43973329983`
artifact name `kdeconnect-community-debug-733f12df36a8da8dda59fe5e43b92669f36c1287`)
for Quit, tile, boot persistence, and update-check failure paths. That APK's
package is **`org.kde.kdeconnect_tp.debug`**, not the production package.

On a device that you control, inspect the APK and explicitly install it through
Android's installation UI or a separate approved ADB command. **Do not** install
an untrusted or unverified APK. Installing into `.debug` may coexist with
`org.kde.kdeconnect_tp.mikey`; choose a test device and back up pairing data first.
The QA script never installs apps, reboots, requests root, or changes settings.

```sh
# Run from a checkout containing tools/community_acceptance.py.
# Wireless debugging must be paired if using ADB from on-device Termux.
python3 -B tools/community_acceptance.py device \
  --transport adb \
  --package org.kde.kdeconnect_tp.debug \
  --source-commit "$(git rev-parse HEAD)" \
  --receipt "$HOME/.local/state/kdeconnect-qa/device-debug.json"

# If ADB is unavailable and you explicitly permit read-only su queries:
python3 -B tools/community_acceptance.py device \
  --transport root \
  --package org.kde.kdeconnect_tp.debug \
  --source-commit "$(git rev-parse HEAD)" \
  --receipt "$HOME/.local/state/kdeconnect-qa/device-root-observation.json"
```

The script captures Android SDK, device fingerprint, installed package and
versionCode **locally** (receipt mode 0600) and prompts for observed outcomes:
Quit (service/network inactivity), reboot persistence, QS tile state transition,
and updater's safe behavior without a published release. Explicitly mark a
failure or blocked case when it cannot be observed. These are **operator
observations**, not automated device instrumentation evidence.

`--noninteractive` only snapshots device metadata: all functional cases remain
`BLOCKED`. Cases for Android installation, Shizuku permission-granted/denied,
Sui, and root permitted/denied remain `BLOCKED` until there are stable,
independently verified same-signer upgrade APKs. `--published-signed-update`
removes that *prerequisite gate* only after the operator has established the
required published upgrade; it is not signing or proof of success.

For each privileged installation path, independently compare the **installed**
package/version and signer before and after, and capture PackageInstaller
status, Android confirmation UI, cancellation and permission-denial behavior.
Use separate device states or dedicated test devices for repeated upgrades;
never silently downgrade a user's production installation just to replay a
mode. Running Shizuku and Sui is not the same as proving both paths.

## 2. Independent signed community APK verification

The release workflow on `master` requires explicit manual dispatch, a private
stable signing keystore, a pinned signing certificate SHA-256 secret, and a
monotonically increasing version code. **Never provide or commit a keystore,
password, private key or raw signing secret to this tooling.**

After an authorized signed build exists, download its `kdeconnect-community.apk`
and `update.json` from the *same* published release. Separately obtain the
expected signing certificate fingerprint from a trusted offline key record
(not `update.json`). Check the actual signed release source commit/HEAD and tag.

```sh
python3 -B tools/community_acceptance.py verify-release \
  --apk /secure/location/kdeconnect-community.apk \
  --manifest /secure/location/update.json \
  --expected-cert YOUR_INDEPENDENT_64_HEX_CERT_FINGERPRINT \
  --expected-source ACTUAL_RELEASE_SOURCE_COMMIT_SHA40 \
  --expected-tag community-vX.Y.Z-N \
  --receipt "$HOME/.local/state/kdeconnect-qa/release-check.json"
```

Use `--previous-manifest /secure/location/prior-update.json` to independently
check monotonicity against a predecessor. The publishing workflow separately
checks *all* prior releases, not just one. Requires the **real** `apksigner`
and `aapt` Android SDK tools; no output from `jarsigner`, an unsigned APK, or a
faked test stub is accepted for a real release. The verifier checks:

- Exact APK size, SHA-256, metadata schema and release tag/source commit.
- `apksigner verify --min-sdk-version 24 --verbose --print-certs`, exactly
  **one** signer and a match with the independently trusted certificate.
- APK `aapt dump badging` package, versionCode, versionName match manifest,
  with package `org.kde.kdeconnect_tp.mikey` and versionCode >13703.
- Optional predecessor versionCode strictly less than the proposed release.

The receipt has status `VERIFIED_OFFLINE`; it deliberately sets
`device_qualified=false` and `published_release_qualified=false` because
checking local files is not evidence they were actually installed or served by
GitHub Releases. To qualify production update behavior, **first** install a
trusted earlier same-signer production build, then publish a later verified
build through the authorized workflow, exercise the in-app updater and verify
that installation/confirmation/cancellation and version transition behave as
expected on the device. Debug APKs cannot substitute: they use `.debug`.

## 3. Security review and PR decision

### Reviewed controls

- GitHub release URL allowlist, exact tag/asset, bounded metadata/APK size,
  SHA-256 and APK identity/signer check; new per-hop HTTPS redirect enforcement.
- Installer modes are explicit; auto does not initiate Shizuku authorization,
  and privilege denial should not trigger silent fallback.
- Shizuku UserService enforces app package and size; `InstallResultReceiver`
  is not exported. Android and root paths are separate.
- CI keeps `testDebugUnitTest`, `testReleaseUnitTest`, `lintDebug`, `lintRelease`,
  both APK builds, and unsigned community package check in **one** PR workflow.
- Signing secrets are absent from PR CI. Signed release workflow is manually
  dispatched on master and compares the pinned certificate, package, source
  commit, rollback history and release/tag uniqueness.

### Remaining mandatory acceptance / risks

1. **No production signing or device proof yet.** Pending identity from an
   offline trust record, actual signed candidate, version upgrade, Shizuku/Sui
   permission confirmation and explicit root denial/confirmation tests.
2. **No approved merge yet.** Keep PR #1 draft until the new hosted HEAD is
   green and device sign-off is recorded. Request independent code review;
   GitHub typically does not allow self-approval. Do not force-merge, auto-merge,
   or publish from the PR.
3. **Known localization debt** remains visible and fixed in the separate lint
   baseline, not silently removed or expanded.
4. **Sensitive QA evidence stays local.** Device fingerprint, system logs and
   signer data should be redacted before posting publicly. Do not send
   keystore/passwords, private package data or full device dumps to PR comments.

Approval/merge is a separate human action **after** these gates pass. Release
publication is later and still requires a different explicit authorization.
The two cannot be truthfully conflated.

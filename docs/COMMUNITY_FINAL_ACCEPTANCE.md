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
The default QA mode never installs apps, reboots, requests root, or changes settings; the explicit `--install-debug-apk` mode is the only installation exception.

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

### Optional explicit, automatic debug APK installation

For the PR HEAD `4955804df3fa19ff671456c7d8797020f9cf478d`, the green
GitHub Actions run `44001383455` has an independently obtained debug APK
artifact `kdeconnect-community-debug-9fdedad56c19e66378f90e2a80f5d55382267bd1`.
The APK SHA-256 is `9635b2ce4471d26224d904c9ebc9651e8fa58b0812994a95761647cc282e3a01`.
The following **explicit opt-in** installs this exact APK through ADB *before*
the interactive QA questions. Check `adb -s localhost:5555 get-state` first.
On-device Termux ADB must be paired/authorized; multiple ADB devices require
choosing the serial explicitly. Android's package signature conflict is never
silently solved by uninstalling an existing app.

```sh
python3 -B tools/community_acceptance.py device \
  --transport adb --serial localhost:5555 \
  --package org.kde.kdeconnect_tp.debug \
  --source-commit 4955804df3fa19ff671456c7d8797020f9cf478d \
  --install-debug-apk /trusted/path/kdeconnect-android-debug.apk \
  --expected-apk-sha256 9635b2ce4471d26224d904c9ebc9651e8fa58b0812994a95761647cc282e3a01 \
  --receipt "$HOME/.local/state/kdeconnect-qa/device-debug.json"
```

This mode checks a strict SHA-256 and APK ZIP structure before invoking
`adb -s SERIAL install -r APK` (without `-g`, root or uninstall), verifies the
selected device reports `device`, and requires an explicit `Success`. The new
`debug_install` receipt distinguishes an ADB install from manual QA observations;
neither proves a production signing certificate or production updater behavior.
The bundled opt-in QA runner can include the exact artifact and avoid an
additional download/extraction step. It is **not** a signed release.

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


## Consolidated pre-merge, signed QA qualification (new)

The new `.github/workflows/signed-qa.yml` is **not** a release workflow. It
runs only on an explicitly pushed `kde-qa-<40-character-PR-HEAD>` Git tag,
requires the owner actor and an exact-match green PR source commit before it
reads the signing secrets, and targets the `community-signing-qa` GitHub
Environment. **Configure required reviewers before triggering the QA tag:**
merely naming an environment does not create a reviewer-approval gate.
Without configured protection, the owner-created tag is the only explicit
signing authorization.
It generates *signed, QA-only* APKs with versionCodes **13704–13708**, all
signed with the existing trusted community key, and posts them only to
short-retention Actions artifacts. No tag is created automatically. No GitHub
Release, production `update.json`, secret, or private keystore is published.

The QA-only APKs use package `org.kde.kdeconnect_tp.mikey` and versionName
`1.37.3-community-qa`, with a compile-time gated local APK picker. The picker
is **absent in production builds**, accepts only explicit user-selected
`content://` APK documents, copies them with a byte-size limit into private
cache, and applies the *same* PackageManager package/version/signer identity
check as the normal updater before using the selected installer mode. The
normal updater still only checks published stable GitHub Releases.

**Important:** These QA APKs have real production-package signing identity.
Use a disposable test state (back up application data) before installing the
first one. To test Android, Shizuku, Sui and root in sequence without resetting
app data, install code 13704, then use the QA-only picker to advance to 13705,
13706, 13707 and 13708 with the selected installation modes. For denial tests,
try denied permissions without consuming a versionCode. The QA tool does not
automatically root, uninstall, or bypass a system confirmation UI.

After the signed QA tag run succeeds, download the five workflow artifacts
with `gh run download <RUN_ID> -R Mikeyphw/kdeconnect-android --dir <PRIVATE_DIR>`.
Verify each candidate using `tools/signed_qa.py verify` against the
independently trusted fingerprint (not solely against a GitHub-hosted value),
and compare device-installed certificate/version before and after the tests.
The QA artifacts must never be published as a stable release.

**Reserved QA version codes: 13704–13708.** The first production release
must have `versionCode >= 13709`, or an existing QA installation could prevent
an in-place update. `test_signed_qa_contract.py` ensures that QA mode is
opt-in and separate from production/release signing.

This workflow cannot be dispatched with `workflow_dispatch` pre-merge because
the workflow is absent from `master`. A deliberately created *lightweight*
Git tag at the verified feature HEAD is the supported trigger. The official
release workflow still publishes only after an explicit approved dispatch on
`master`, and the actual end-to-end in-app updater can only be qualified once
a stable release exists. No signed-QA green check substitutes for human PR
approval, device observations or release evidence.

### Signed-QA verifier and dependency reliability (2026-11-17)

Android `apksigner` may identify the same verified certificate as either
`Signer #1` or `Signer (minSdkVersion=24, maxSdkVersion=32)`, with repeated
SDK-range rows. The shared verifier accepts these report formats **only** if
signature verification succeeds and the reported signer SHA-256 identities all
agree with the independently pinned certificate. Missing/malformed, mixed
certificate or multiple-signer output remains a blocking failure. The
production release uses the same strict verifier, not a divergent regex.

The signed candidate matrix now limits simultaneous Gradle resolutions to two
and retries **only** Maven HTTP 429 up to three logged attempts; test, build,
lint, signing and all other errors remain fatal. This does not weaken any gate.

**Important tag semantics:** The previously created `kde-qa-2f8a19a...`
ref is immutable and retains the failed source revision. After a native fix is
committed and the NEW PR HEAD CI is green, create a distinct explicit
`kde-qa-<NEW_PR_HEAD>` tag as in the signed-QA procedure. Do not rewrite or
delete the old tag, and do not rerun its outdated source to qualify a new commit.

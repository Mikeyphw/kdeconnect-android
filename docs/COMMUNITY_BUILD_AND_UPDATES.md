# KDE Connect community fork — signed APK and updater contract

Source baseline `Mikeyphw/kdeconnect-android` `master@1a5692f379dfb433d875f55320f27eb2393e0c81`.
Contributor adaptation: Rohit Ghosh (`jendermine`), KDE GitLab MR !790 commit `1ded6bc1a2fcd9a5191be24afe6d917843446123`.
MR !789 head `56a0b2f28512696e600eaadbcbfd0a6dfe618aa4` is formatting only; relevant callback cleanup already exists on the current baseline. This is not an attempt to cherry-pick either MR unchanged, which would regress newer upstream code.

## Build variants

- `assembleDebug`: `org.kde.kdeconnect_tp.debug` (upstream debug package/signing behavior).
- `assembleRelease`: `org.kde.kdeconnect_tp.mikey` (separate package; never overwrites F-Droid/Google Play or KDE official APK). Production releases **require a stable secret keystore**. Every update must reuse the exact original signing key. Pairing data does not transfer automatically between distinct packages.
- Source is GPL; attribution remains in the contributor's original tile source and in the adapted service comment.

## Android compatibility for Shizuku builds

- **Minimum API: 24 (Android 7.0)** for the community fork. The official KDE Connect baseline still supports API 23 (Android 6.0); **this is an intentional support change**, not an upstream KDE requirement.
- The shipped `dev.rikka.shizuku:api:13.1.5` and `:provider:13.1.5` libraries require API 24. The PR's original API-23 setting failed `processDebugMainManifest` in hosted CI; a one-off `tools:overrideLibrary` would suppress the diagnostic without demonstrating runtime compatibility, so it is explicitly forbidden.
- Shizuku is still optional **at runtime** (normal Android APK installation does not require Shizuku), but the APK embeds its library and therefore cannot be installed below API 24. A future API-23 build would need a separately validated flavor/module that excludes the incompatible libraries, not a silent manifest override.
- CI must compile the actual debug variant and run the required source compatibility tests; neither static checks nor successful AIDL generation count as proof that the full Android build passes.

## Release requirements

Configure repository Actions secrets `KDE_FORK_KEYSTORE_BASE64`, `KDE_FORK_STORE_PASSWORD`, `KDE_FORK_KEY_ALIAS`, `KDE_FORK_KEY_PASSWORD`, `KDE_FORK_SIGNING_CERT_SHA256` privately. Do not commit keystores, passwords or private keys. Back up the keystore offline; losing it makes all future in-place updates impossible.

Before first publishing, record the SHA-256 fingerprint of the signing certificate in `KDE_FORK_SIGNING_CERT_SHA256` and verify it independently. Signed publishing refuses a mismatched fingerprint and requires every release `versionCode` to be greater than the upstream baseline and **all** previously published community release version codes (paginated discovery, not only the last few). Metadata `version_name` is read from the built APK rather than inferred from the release tag.

Dispatch **Signed community APK release** from `master`, with a new `community-vX.Y.Z-N` tag and a positive, monotonically increasing `version_code`. This is a **manual** approval: upstream synchronization and PR tests never create a release. Both `lintDebug` and `lintRelease` are required to pass; an error is not silently ignored. Publishing is blocked if tests, lint, signing or APK signature verification fails, if signing credentials are missing, or if the tag/release is already present.

A release publishes two assets: `kdeconnect-community.apk` and `update.json` (schema 1). `update.json` contains package, version, tag, APK byte size, SHA-256, and source commit. GitHub Actions computes all metadata from the built APK; no user-supplied APK URL enters the app.

## In-app updater

Updates > Check for updates accesses only `Mikeyphw/kdeconnect-android` stable GitHub Releases over HTTPS. A unique `update.json` and APK asset are required. The app checks versions, expected package, exact release-tag asset URL/length and SHA-256; **after download**, it independently parses the APK and requires the candidate APK versionName and signing certificates to match the release metadata and its own installed signing identity. Downgrades, wrong-package APKs, stale or mismatched assets, and untrusted hosts are refused. The app only downloads after explicit user action; automatic checks are limited to app opening (no background scheduler), at most daily, and can be disabled. Notifications require Android permission when applicable.

Installer modes: Android (PackageInstaller confirmation), Shizuku/Sui (authorized UserService, shell/root identity, official API 13.1.5), root (explicit `su -c pm install -S` stream), auto (only use **already-authorized** Shizuku; otherwise Android). There is no hidden privilege escalation, silent permission prompt in Auto mode or automatic APK installation. If a user-service install returns `STATUS_PENDING_USER_ACTION`, Android may still require confirmation. Never claim silent installation capability without physical-device evidence.

Quit KDE Connect turns off background networking and remains stopped across system broadcasts until explicit app launch, sharing or tile toggle. Update checks do not reactivate KDE networking. Android may start the process to serve other exported components; the intended guarantee is background service/link inactivity, **not** complete OS-level process prohibition.

## CI and limitations

- `android-ci.yml` runs once per pull request, on pushes to `master`, and on explicit `workflow_dispatch`. Pushes to `feature/**` and `sync/**` do not automatically start a second build. Before opening a PR, use manual dispatch if a branch build is needed.
- `upstream-sync.yml` opens a **review PR** from an immutable per-upstream-commit branch; no auto-merge or force-push. Conflicts fail closed.
- `community-release.yml` requires private signing secrets and explicit manual dispatch. Android tests/lint/build and installed-device validation are distinct gates.
- The hosted debug build, unit tests and lint passed for PR #1 at commit `68ed2b0498f538d92c5690adf79015ea79a04d6f` (run 43964580671). The subsequent unsigned release-variant qualification is **not accepted** until its own hosted run passes.
- Current limitations: no Android 16 device acceptance or signed production-release validation has been performed. Shizuku PackageInstaller UserService must be tested with real Shizuku and Sui (including failure/cancellation/confirmation), and release signatures and versionCode monotonicity must be validated end to end before production release.


## Unsigned pre-release CI qualification

Before a signed release is requested, the **single** PR workflow now runs
`testDebugUnitTest`, `lintDebug`, `assembleDebug`, `testReleaseUnitTest`,
`lintRelease`, and `assembleRelease` against the same exact PR revision.
Android Gradle Plugin 9.5.1 enables unit-test components only for the tested
(default debug) build type unless `android.onlyEnableUnitTestForTheTestedBuildType=false`
is set. `gradle.properties` opts into both **real** test variants. PR run
`43969732157` failed before test execution because `testReleaseUnitTest` was
absent. Do not replace release tests with an empty Gradle task or remove them
from required CI. The corrected PR needs a fresh hosted run before release
variant acceptance can be claimed.
It then inspects the unsigned release APK with `aapt`, requiring the distinct
`org.kde.kdeconnect_tp.mikey` package identity; it refuses an unexpectedly
signed release APK. No release keystore or signing secrets are available to PR
jobs; the unsigned release APK is **never uploaded or published**. Only the
debug APK is uploaded after all checks pass. Debug and release lint and test
reports are retained on failures. Both lint tasks retain `abortOnError`.

This qualifies the release build **variant**, not the actual signing identity,
real-device functionality, PackageInstaller/Shizuku/root behavior, permission
prompts or the manual signed release pipeline. The separate release workflow
still requires explicit authorization, the stable private signing key, APK
certificate and metadata verification, and rollback protection. Do not
interpret a green PR run as permission to publish an untested signed APK.

## Hosted CI lint artifact retention

The GitHub PR CI job runs mandatory debug and release variant tests, lint and assembly.
A failure is **not** treated as success. A separate `if: always()` upload step
retains debug/release Lint XML/HTML/SARIF, Lint text and test XML reports (when
produced), so existing upstream debt and community-fork regressions can be
classified before choosing fixes. No lint severity, security diagnostic,
`abortOnError` or gate is disabled. A non-green run remains unqualified and
must not be merged or released. Diagnostics are retained for 14 days.


## Localization-debt baseline and safety repairs (2026-11-16)

Hosted PR run 43953522627, commit d2fe47a388152715cf9465ea5211b64840a487cc,
reported 454 blocking lint findings: 424 MissingTranslation, 20 ExtraTranslation,
and 10 compatibility/thread/resource/Android TV findings. Only the 444
translation findings are recorded in `lint-baseline.xml` as a **fixed,
reviewed, incomplete-localization backlog**. Four settings strings newly added
by this fork are included explicitly; English fallback remains available but
full localization is **not** qualified. Do not treat the baseline as proof of
translation completeness or a release acceptance gate. These entries must
be reduced as translators provide equivalents; tests refuse silent growth,
new issue families or safety/compatibility baselining.

`lintDebug` and `lintRelease` retain `abortOnError = true`. All other lint
finding types remain live, including API compatibility, exported components,
threading and unsafe TLS. Runtime changes additionally gate the Android-30
Controls provider with version-qualified bool resources, guard Process APIs
on Android 7 and earlier, use NIO desugaring for API24, and read preferences
on an I/O dispatcher. The category `LEANBACK_LAUNCHER` is present for Android TV.

The translation backlog is an exception to full localization acceptance, not
permission to ignore newly introduced lint issues. Unit tests, functional
Shizuku/Sui/root validation, signed release and device acceptance remain
independent and not automatically qualified by this source repair.

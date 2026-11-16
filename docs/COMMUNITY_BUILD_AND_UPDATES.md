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
- Current limitation: no hosted Gradle build or Android 16 device test was executed in the artifact preparation environment. Shizuku PackageInstaller UserService must be tested with real Shizuku and Sui (including failure/cancellation/confirmation), and release signatures and versionCode monotonicity must be validated end to end before production release.


## Hosted CI lint artifact retention

The GitHub PR CI job runs mandatory `testDebugUnitTest lintDebug assembleDebug`.
A failure is **not** treated as success. A separate `if: always()` upload step
retains complete Lint XML/HTML/SARIF, Lint text and test XML reports (when
produced), so existing upstream debt and community-fork regressions can be
classified before choosing fixes. No lint severity, security diagnostic,
`abortOnError` or gate is disabled. A non-green run remains unqualified and
must not be merged or released. Diagnostics are retained for 14 days.

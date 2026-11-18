#!/usr/bin/env python3
"""Device acceptance recorder and independent signed-APK verifier.

Read-only by default; optional --install-debug-apk explicitly authorizes a
SHA-256-bound ADB install onto one named device. No root, production install,
release signing, publishing, clipboard access, key import, or Git writes.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import zipfile

PACKAGE_RELEASE = "org.kde.kdeconnect_tp.mikey"
PACKAGE_DEBUG = "org.kde.kdeconnect_tp.debug"
SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")
SHA40 = re.compile(r"[0-9a-fA-F]{40}\Z")
TAG = re.compile(r"community-v\d+\.\d+\.\d+-\d+\Z")
MAX_APK = 250 * 1024 * 1024

# Tests requiring a published stable update and a pre-installed APK signed with
# the same trusted key cannot be certified with the unsigned PR release build.
CASES = (
    ("quit_persistent", "Open app, Settings > Quit. Confirm devices disconnect and the service stays stopped.", False),
    ("reboot_stopped", "With Quit still active, reboot manually. Confirm networking remains off until explicit app launch.", False),
    ("tile_off_on", "Add KDE Connect Quick Settings tile; stop and restart. Confirm tile and service agree.", False),
    ("updater_no_release", "Open Updates > Check. With no stable releases, expect a safe failure and no install action.", False),
    ("android_confirmation", "With a newer signed community release published, select Android installer; confirm system approval UI and installed version.", True),
    ("shizuku_authorized", "With a newer signed community release, test authorized Shizuku UserService upgrade, including confirmation if Android requires it.", True),
    ("shizuku_denied", "Deny Shizuku permission; verify explicit failure with no privileged fallback or APK install.", True),
    ("sui_authorized", "Independently qualify Sui root-mode UserService using a signed upgrade; confirm resulting package/version.", True),
    ("root_explicit", "Select Root explicitly and install a trusted signed upgrade; confirm su authorization and version.", True),
    ("root_denied", "Deny su; confirm failure, no silent alternative installer, and no version change.", True),
)


def fail(message: str) -> None:
    raise ValueError(message)


def iso_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def private_json_write(path: Path, document: dict) -> None:
    path = path.expanduser()
    if path.is_symlink():
        fail("Refusing symlink receipt")
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    fd, temp = tempfile.mkstemp(prefix=".acceptance-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as dest:
            dest.write(data)
            dest.flush()
            os.fsync(dest.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def safe_read_json(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 128 * 1024:
        fail("Missing, symlinked or oversized release metadata")
    result = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(result, dict):
        fail("Release metadata must be an object")
    return result


def digest_file(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as src:
        for b in iter(lambda: src.read(1024 * 1024), b""):
            sha.update(b)
    return sha.hexdigest()


def tool(name: str, explicit: str | None = None) -> str:
    if explicit:
        if not Path(explicit).is_file():
            fail("Required Android tool not found: " + name)
        return explicit
    cmd = shutil.which(name)
    if cmd:
        return cmd
    for home in filter(None, (os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT"))):
        builds = Path(home, "build-tools")
        for candidate in sorted(builds.glob("*/" + name), reverse=True):
            if candidate.is_file():
                return str(candidate)
    fail("Required Android SDK tool unavailable: " + name)


def command_output(argv: list[str], timeout: int = 45) -> str:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        fail("Required verification command unavailable: " + type(exc).__name__)
    if proc.returncode:
        detail = (proc.stderr or proc.stdout).strip()[:230]
        if not detail:
            # ADB may exit nonzero without a diagnostic. Identify the failing
            # subcommand instead of printing just `adb:` and hiding the stage.
            detail = "no stderr/stdout; args=" + repr(argv[1:5])[:160]
        fail("Verification command failed (no bypass): " + Path(argv[0]).name +
             " rc=" + str(proc.returncode) + ": " + detail)
    return proc.stdout


def checked_version(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0 or value > 2147483647:
        fail("Invalid " + field)
    return value


def validated_manifest(meta: dict, expected_source: str, expected_tag: str) -> None:
    if meta.get("schema") != 1 or type(meta.get("schema")) is not int:
        fail("Unsupported release metadata schema")
    if not SHA40.fullmatch(expected_source) or meta.get("source_commit") != expected_source:
        fail("Release source commit does not match independently reviewed source")
    if not TAG.fullmatch(expected_tag) or meta.get("tag") != expected_tag:
        fail("Release tag mismatch")
    if meta.get("apk_name") != "kdeconnect-community.apk" or meta.get("package_name") != PACKAGE_RELEASE:
        fail("Unexpected community release package or APK asset")
    checked_version(meta.get("version_code"), "version_code")
    if meta["version_code"] <= 13703:
        fail("Release versionCode must exceed upstream baseline")
    if not isinstance(meta.get("version_name"), str) or not meta["version_name"].strip():
        fail("Missing versionName")
    size = meta.get("apk_size")
    if type(size) is not int or not 1024 <= size <= MAX_APK:
        fail("Invalid APK size")
    if not isinstance(meta.get("apk_sha256"), str) or not SHA256.fullmatch(meta["apk_sha256"]):
        fail("Invalid APK SHA-256")


def parse_badging(report: str) -> tuple[str, int, str]:
    row = next((line for line in report.splitlines() if line.startswith("package: ")), "")
    # aapt may append compileSdkVersionCodename and platformBuildVersionName;
    # partial suffix matches are unsafe for independently verified package IDs.
    fields = re.findall(r"(?:^|\s)(name|versionCode|versionName)='([^']*)'", row)
    values = dict(fields)
    if len(fields) != 3 or set(values) != {"name", "versionCode", "versionName"}:
        fail("Cannot independently parse APK package identity")
    try:
        code = int(values["versionCode"])
    except ValueError:
        fail("APK versionCode is not numeric")
    return values["name"], code, values["versionName"]


def parse_signer(report: str) -> str:
    digests = re.findall(r"Signer #\d+ certificate SHA-256 digest:\s*([0-9a-fA-F]{64})", report)
    if len(digests) != 1:
        fail("APK must have one independently verified signing certificate")
    return digests[0].lower()


def verify_release(apk: Path, manifest: Path, independent_cert: str,
                   source: str, tag: str, previous_manifest: Path | None = None,
                   aapt_path: str | None = None, apksigner_path: str | None = None) -> dict:
    """Verification only; never reads signing private keys or installs the APK."""
    if not SHA256.fullmatch(independent_cert):
        fail("An independent 64-hex trusted signer certificate SHA-256 is required")
    if apk.is_symlink() or not apk.is_file() or not 1024 <= apk.stat().st_size <= MAX_APK:
        fail("Invalid, symlinked or oversized APK")
    meta = safe_read_json(manifest)
    validated_manifest(meta, source, tag)
    if apk.name != meta["apk_name"] or apk.stat().st_size != meta["apk_size"]:
        fail("APK name/byte-size differs from release metadata")
    actual_sha = digest_file(apk)
    if actual_sha != meta["apk_sha256"].lower():
        fail("APK file SHA-256 differs from published metadata")
    if previous_manifest:
        old = safe_read_json(previous_manifest)
        older_code = checked_version(old.get("version_code"), "previous version_code")
        if meta["version_code"] <= older_code:
            fail("VersionCode rollback against predecessor refused")
    signer_report = command_output([
        tool("apksigner", apksigner_path), "verify", "--min-sdk-version", "24",
        "--verbose", "--print-certs", str(apk)
    ])
    signer = parse_signer(signer_report)
    if signer != independent_cert.lower():
        fail("Signer differs from independently trusted certificate fingerprint")
    pkg, code, name = parse_badging(command_output([tool("aapt", aapt_path), "dump", "badging", str(apk)]))
    if (pkg, code, name) != (PACKAGE_RELEASE, meta["version_code"], meta["version_name"]):
        fail("Signed APK manifest differs from expected package or version")
    return {
        "schema": "kdeconnect.signed-release-verification.v1",
        "status": "VERIFIED_OFFLINE",
        "verified_at": iso_now(),
        "source_commit": source,
        "release_tag": tag,
        "apk_sha256": actual_sha,
        "apk_size": apk.stat().st_size,
        "signing_certificate_sha256": signer,
        "package_name": pkg,
        "version_code": code,
        "version_name": name,
        "previous_version_checked": previous_manifest is not None,
        "device_qualified": False,
        "published_release_qualified": False,
    }



def install_verified_debug_apk(args: argparse.Namespace) -> dict:
    """Explicit, hash-bound ADB install. Never install the unsigned release variant.

    The expected digest must be independently obtained from a reviewed, green
    GitHub Actions build of this precise source revision. This function does
    not fetch mutable URLs or trust the APK filename as package identity.
    """
    if args.transport != "adb" or args.package != PACKAGE_DEBUG or args.published_signed_update:
        fail("Automatic installation is restricted to the community debug package over ADB")
    if not args.serial or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", args.serial):
        fail("Automatic installation requires an explicit, valid --serial")
    expected = args.expected_apk_sha256
    if not isinstance(expected, str) or not SHA256.fullmatch(expected):
        fail("Automatic installation requires an independent --expected-apk-sha256")
    apk = args.install_debug_apk
    if apk is None or apk.is_symlink() or not apk.is_file():
        fail("Missing or symlinked debug APK")
    length = apk.stat().st_size
    if not 1024 <= length <= MAX_APK:
        fail("Debug APK outside allowed size range")
    actual = digest_file(apk)
    if actual != expected.lower():
        fail("Debug APK does not match the pinned green-CI SHA-256; installation refused")
    try:
        with zipfile.ZipFile(apk) as archive:
            names = set(archive.namelist())
            if not {"AndroidManifest.xml", "classes.dex"}.issubset(names):
                fail("APK missing Android manifest or executable classes")
    except zipfile.BadZipFile:
        fail("Debug APK is not a valid APK ZIP")
    adb = tool("adb")
    state = command_output([adb, "-s", args.serial, "get-state"], timeout=15).strip()
    if state != "device":
        fail("Selected ADB serial is not in device state")
    # No -g, no uninstall, no root, no permission auto-grant, no arbitrary pm.
    # Android's Package Manager refuses signature conflicts on replacement.
    output = command_output([adb, "-s", args.serial, "install", "-r", str(apk)], timeout=180)
    if not any(line.strip() == "Success" for line in output.splitlines()):
        fail("ADB did not confirm a successful APK installation")
    print("KDECOMMUNITY_ADB_INSTALL_VERIFIED " + output.strip() +
          " serial=" + args.serial, flush=True)
    return {
        "mode": "explicit-adb-debug-install",
        "status": "INSTALLED_VIA_ADB",
        "device_serial": args.serial,
        "artifact_sha256": actual,
        "artifact_size": length,
        "source_commit_operator_asserted": args.source_commit,
        "signer_independently_qualified": False,
        "production_release_qualified": False,
    }


class DeviceProbe:
    def __init__(self, transport: str, serial: str | None):
        if transport not in ("adb", "root"):
            fail("Unsupported device transport")
        self.transport = transport
        self.serial = serial

    def read(self, *argv: str) -> str:
        if self.transport == "adb":
            prefix = [tool("adb")]
            if self.serial:
                prefix.extend(["-s", self.serial])
            return command_output(prefix + ["shell", *argv], timeout=25)
        # --transport=root is an explicit opt-in. All commands here are read-only.
        return command_output([tool("su"), "-c", shlex.join(argv)], timeout=25)


def snapshot(probe: DeviceProbe, package: str) -> dict:
    if package not in (PACKAGE_DEBUG, PACKAGE_RELEASE):
        fail("Only KDE Connect community debug or release package IDs may be inspected")
    sdk = probe.read("getprop", "ro.build.version.sdk").strip()
    fingerprint = probe.read("getprop", "ro.build.fingerprint").strip()
    installed = probe.read("pm", "path", package).strip()
    if not installed.startswith("package:"):
        fail("Target package is not installed on the connected device")
    details = probe.read("dumpsys", "package", package)
    match = re.search(r"\bversionCode=(\d+)\b", details)
    if not match:
        fail("Cannot read installed APK versionCode")
    return {
        "observed_at": iso_now(),
        "sdk": sdk,
        "fingerprint": fingerprint,
        "package_name": package,
        "version_code": int(match.group(1)),
        "transport": probe.transport,
        "serial_used": bool(probe.serial),
        "app_installed": True,
    }


def run_device(args: argparse.Namespace) -> dict:
    has_signed_update = bool(args.published_signed_update) and args.package == PACKAGE_RELEASE
    has_qa_candidates = bool(getattr(args, "qa_signed_candidates", False)) and args.package == PACKAGE_RELEASE
    if has_signed_update and has_qa_candidates:
        fail("Choose published release acceptance OR QA candidate testing, not both")
    probe = DeviceProbe(args.transport, args.serial)
    before = snapshot(probe, args.package)
    results = []
    print("Device verified as installed:", before["package_name"], "v", before["version_code"])
    print("QA observations never change settings; optional explicit debug ADB install is recorded separately.")
    for key, description, requires_signed_update in CASES:
        if has_qa_candidates and requires_signed_update:
            description = description.replace("newer signed community release published", "newer signed QA-only APK")
            description = description.replace("newer signed community release", "newer signed QA-only APK")
        entry = {"id": key, "instruction": description,
                 "requires_published_signed_update": requires_signed_update and not has_qa_candidates,
                 "requires_qa_signed_candidate": requires_signed_update and has_qa_candidates,
                 "status": "BLOCKED", "evidence": ""}
        if requires_signed_update and not (has_signed_update or has_qa_candidates):
            entry["evidence"] = "Requires an independently verified same-signer signed upgrade pair"
        elif args.noninteractive:
            entry["evidence"] = "No real-device operator observation recorded"
        else:
            print("\nTEST:", description)
            while True:
                value = input("Result [p=observed pass, f=fail, b=blocked]: ").strip().lower()
                if value in {"p", "f", "b"}:
                    break
            entry["status"] = {"p": "OPERATOR_OBSERVED", "f": "FAIL", "b": "BLOCKED"}[value]
            entry["evidence"] = input("Concise observation / limitation (no secrets): ").strip()[:500]
        results.append(entry)
    after = snapshot(probe, args.package)
    return {
        "schema": "kdeconnect.device-acceptance.v1",
        "qa_signed_candidates_operator_asserted": has_qa_candidates,
        "qa_only": has_qa_candidates,
        "published_release_evidence": has_signed_update,
        "created_at": iso_now(),
        "source_commit": args.source_commit,
        "package": args.package,
        "before": before,
        "after": after,
        "tests": results,
        "operator_observed_count": sum(r["status"] == "OPERATOR_OBSERVED" for r in results),
        "failed_count": sum(r["status"] == "FAIL" for r in results),
        "blocked_count": sum(r["status"] == "BLOCKED" for r in results),
        # Observation is valuable but is not independent/device-instrumented proof.
        "fully_device_qualified": False,
        "signed_release_qualified": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    release = sub.add_parser("verify-release", help="Independently verify an existing signed community APK")
    release.add_argument("--apk", required=True, type=Path)
    release.add_argument("--manifest", required=True, type=Path)
    release.add_argument("--expected-cert", required=True)
    release.add_argument("--expected-source", required=True)
    release.add_argument("--expected-tag", required=True)
    release.add_argument("--previous-manifest", type=Path)
    release.add_argument("--aapt")
    release.add_argument("--apksigner")
    release.add_argument("--receipt", type=Path)
    device = sub.add_parser("device", help="Record explicit real-device observations without installing")
    device.add_argument("--transport", choices=["adb", "root"], default="adb")
    device.add_argument("--serial")
    device.add_argument("--package", choices=[PACKAGE_DEBUG, PACKAGE_RELEASE], default=PACKAGE_DEBUG)
    device.add_argument("--source-commit", required=True)
    device.add_argument("--qa-signed-candidates", action="store_true",
                        help="Operator asserts independently verified QA-only signed candidates; NOT a published release")
    device.add_argument("--published-signed-update", action="store_true",
                        help="Operator asserts two independently verified same-signer releases exist")
    device.add_argument("--install-debug-apk", type=Path,
                        help="Explicit ADB -s SERIAL install -r of reviewed debug APK before QA")
    device.add_argument("--expected-apk-sha256",
                        help="Independent exact green-CI APK SHA-256; required with --install-debug-apk")
    device.add_argument("--noninteractive", action="store_true")
    device.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.mode == "verify-release":
            receipt = verify_release(args.apk, args.manifest, args.expected_cert,
                                     args.expected_source, args.expected_tag,
                                     args.previous_manifest, args.aapt, args.apksigner)
        else:
            if not SHA40.fullmatch(args.source_commit):
                fail("Source commit must be an exact 40-character SHA-1")
            if args.install_debug_apk is None and args.expected_apk_sha256 is not None:
                fail("--expected-apk-sha256 requires --install-debug-apk")
            install_record = install_verified_debug_apk(args) if args.install_debug_apk else None
            receipt = run_device(args)
            if install_record is not None:
                receipt["debug_install"] = install_record
        if args.receipt:
            private_json_write(args.receipt, receipt)
        print(json.dumps(receipt, indent=2, sort_keys=True))
        return 0
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print("KDECOMMUNITY_ACCEPTANCE_REFUSED " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

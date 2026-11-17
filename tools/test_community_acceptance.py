"""Offline/negative qualification of community device and release acceptance tools."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import community_acceptance as qa

CERT = 'a' * 64
SOURCE = '1' * 40
TAG = 'community-v1.37.3-2'
APK_BYTES = b'qualifying fixture payload' * 100


class SignedReleaseVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.apk = self.base/'kdeconnect-community.apk'
        self.apk.write_bytes(APK_BYTES)
        self.meta = {
            'schema': 1, 'tag': TAG, 'source_commit': SOURCE,
            'apk_name': self.apk.name, 'package_name': qa.PACKAGE_RELEASE,
            'apk_size': len(APK_BYTES), 'apk_sha256': hashlib.sha256(APK_BYTES).hexdigest(),
            'version_code': 137040, 'version_name': '1.37.3-community',
        }
        self.manifest = self.base/'update.json'
        self.write_meta()
        self.signer = 'Signer #1 certificate SHA-256 digest: '+CERT+'\nVerified using v2 scheme: true\n'
        self.badging = "package: name='org.kde.kdeconnect_tp.mikey' versionCode='137040' versionName='1.37.3-community'\n"

    def write_meta(self):
        self.manifest.write_text(json.dumps(self.meta))

    def verify(self, manifest=None, previous=None):
        with patch.object(qa, 'tool', side_effect=lambda name, explicit: name), \
             patch.object(qa, 'command_output', side_effect=[self.signer, self.badging]):
            return qa.verify_release(self.apk, manifest or self.manifest, CERT,
                                     SOURCE, TAG, previous)

    def test_good_signed_release_checked_offline(self):
        receipt = self.verify()
        self.assertEqual(receipt['status'], 'VERIFIED_OFFLINE')
        self.assertEqual(receipt['signing_certificate_sha256'], CERT)
        self.assertFalse(receipt['device_qualified'])
        self.assertFalse(receipt['published_release_qualified'])

    def test_refuses_changed_apk_size_or_sha(self):
        self.meta['apk_size'] += 1
        self.write_meta()
        with self.assertRaises(ValueError): self.verify()
        self.meta['apk_size'] -= 1
        self.meta['apk_sha256'] = '0' * 64
        self.write_meta()
        with self.assertRaises(ValueError): self.verify()

    def test_refuses_wrong_package_source_tag_and_version(self):
        for field, value in (
            ('package_name','org.kde.kdeconnect_tp.debug'),
            ('source_commit','2'*40), ('tag', 'community-v1.37.3-3'),
            ('version_code',13703), ('version_name',''), ('schema',2),
            ('apk_name','other.apk'),
        ):
            with self.subTest(field=field):
                original=self.meta[field]
                self.meta[field]=value
                self.write_meta()
                with self.assertRaises(ValueError): self.verify()
                self.meta[field]=original
        self.write_meta()

    def test_bad_signer_rejected_without_weaker_fallback(self):
        self.signer = 'Signer #1 certificate SHA-256 digest: '+('b'*64)
        with self.assertRaisesRegex(ValueError, 'Signer differs'):
            self.verify()

    def test_duplicate_signer_rejected(self):
        self.signer += 'Signer #2 certificate SHA-256 digest: '+CERT+'\n'
        with self.assertRaisesRegex(ValueError, 'one independently'):
            self.verify()

    def test_unsigned_apk_or_missing_android_tools_is_not_accepted(self):
        with patch.object(qa, 'tool', side_effect=ValueError('apksigner unavailable')):
            with self.assertRaises(ValueError): qa.verify_release(self.apk, self.manifest, CERT, SOURCE, TAG)
        with patch.object(qa, 'tool', side_effect=lambda name, explicit: name), \
             patch.object(qa, 'command_output', side_effect=ValueError('unsigned')):
            with self.assertRaises(ValueError): qa.verify_release(self.apk, self.manifest, CERT, SOURCE, TAG)

    def test_wrong_installed_package_badging_rejected(self):
        self.badging = "package: name='org.kde.kdeconnect_tp.debug' versionCode='137040' versionName='1.37.3-community'"
        with self.assertRaisesRegex(ValueError, 'Signed APK manifest'):
            self.verify()

    def test_malformed_badging_rejected(self):
        self.badging = 'this does not contain Android package metadata'
        with self.assertRaisesRegex(ValueError, 'Cannot independently parse'):
            self.verify()

    def test_rejects_version_rollback(self):
        previous=self.base/'prior.json'
        previous.write_text(json.dumps({'version_code':137041}))
        with self.assertRaisesRegex(ValueError, 'rollback'):
            self.verify(previous=previous)
        previous.write_text(json.dumps({'version_code':137039}))
        self.assertTrue(self.verify(previous=previous)['previous_version_checked'])

    def test_manifest_boolean_code_rejected(self):
        self.meta['version_code'] = True
        self.write_meta()
        with self.assertRaises(ValueError):self.verify()

    def test_independent_certificate_is_mandatory(self):
        with self.assertRaisesRegex(ValueError, 'independent'):
            qa.verify_release(self.apk, self.manifest, '', SOURCE, TAG)

    def test_symlinked_apk_refused(self):
        fake=self.base/'fake.apk'
        fake.symlink_to(self.apk)
        with self.assertRaises(ValueError):
            qa.verify_release(fake, self.manifest, CERT, SOURCE, TAG)

    def test_refuse_symlink_receipt(self):
        original=self.base/'original.json'
        original.write_text('{"intact":true}')
        link=self.base/'link.json'
        link.symlink_to(original)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            qa.private_json_write(link, {'status':'VERIFIED'})
        self.assertEqual(original.read_text(), '{"intact":true}')

    def test_receipts_are_private_not_clipboard(self):
        receipt_path=self.base/'nested'/'receipt.json'
        qa.private_json_write(receipt_path, {'status':'BLOCKED'})
        self.assertEqual(receipt_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(receipt_path.read_text())['status'],'BLOCKED')


class DeviceEvidenceTests(unittest.TestCase):
    def test_noninteractive_never_claims_device_acceptance(self):
        args=argparse.Namespace(transport='adb',serial=None,
            package=qa.PACKAGE_DEBUG,source_commit=SOURCE,
            published_signed_update=False,noninteractive=True)
        fixture={'sdk':'36','fingerprint':'device/fingerprint','package_name':qa.PACKAGE_DEBUG,
                 'version_code':13703,'app_installed':True}
        with patch.object(qa,'snapshot',return_value=fixture):
            result=qa.run_device(args)
        self.assertFalse(result['fully_device_qualified'])
        self.assertEqual(result['operator_observed_count'],0)
        self.assertEqual(result['blocked_count'],len(qa.CASES))

    def test_privileged_cases_blocked_without_published_signed_upgrade(self):
        for key, description, signed in qa.CASES:
            if key.startswith(('shizuku','sui','root','android_confirmation')):
                self.assertTrue(signed, key)

    def test_disallow_unknown_packages_and_transports(self):
        with self.assertRaises(ValueError):qa.DeviceProbe('usb-patch',None)
        with patch.object(qa.DeviceProbe,'read',return_value=''):
            with self.assertRaisesRegex(ValueError, 'Only KDE'):
                qa.snapshot(qa.DeviceProbe('adb',None),'com.other.app')

    def test_probing_uses_only_read_only_shell_commands(self):
        calls=[]
        probe=qa.DeviceProbe('adb','localhost:5555')
        probe.read=lambda *argv: (calls.append(argv) or {
            'getprop': '36', 'pm': 'package:/data/app/base.apk',
            'dumpsys': 'versionCode=13703 targetSdk=37',
        }[argv[0]])
        qa.snapshot(probe,qa.PACKAGE_DEBUG)
        self.assertEqual([x[0] for x in calls],['getprop','getprop','pm','dumpsys'])
        self.assertNotIn('install',repr(calls))


class RepositorySafetyContracts(unittest.TestCase):
    ROOT=Path(__file__).resolve().parents[1]

    def test_explicit_bounded_redirects_no_implicit_follow(self):
        source=(self.ROOT/'src/main/java/org/kde/kdeconnect/updates/ReleaseUpdater.kt').read_text()
        for keyword in ('conn.instanceFollowRedirects = false','validateDownloadHop(resolved)',
                        'validateDownloadHop(next)','repeat(5)',
                        'Untrusted update redirect','Update redirect limit exceeded'):
            self.assertIn(keyword,source)
        self.assertNotIn('conn.instanceFollowRedirects = true',source)

    def test_native_pr_build_still_checks_both_variants_and_tooling(self):
        source=(self.ROOT/'.github/workflows/android-ci.yml').read_text()
        for keyword in ('testDebugUnitTest','testReleaseUnitTest','lintDebug','lintRelease',
                        'assembleDebug','assembleRelease','test_community_actions_contract.py',
                        'test_community_acceptance.py'):
            self.assertIn(keyword,source)
        self.assertNotIn('continue-on-error:',source)
        self.assertNotIn('gh release create',source)

    def test_release_key_does_not_enter_pr_job(self):
        source=(self.ROOT/'.github/workflows/android-ci.yml').read_text()
        for field in ('KDE_FORK_KEYSTORE_BASE64','KDE_FORK_STORE_PASSWORD','KDE_FORK_KEYSTORE='):
            self.assertNotIn(field,source)


if __name__ == '__main__':
    unittest.main()

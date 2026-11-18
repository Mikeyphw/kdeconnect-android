"""Independent regression/negative assurance for signed-QA workflow and verifier."""
import json
import sys
from pathlib import Path
import tempfile
import unittest
import os
import subprocess
import textwrap
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import signed_qa as qa
import signed_qa_pair as pair

SOURCE='a'*40
CERT='f'*64

class SignedQaVerification(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.apk=Path(self.tmp.name)/qa.QA_NAME
        self.apk.write_bytes(b'A'*2048)
        self.code=13704
        self.signer=patch.object(qa,'inspected_signer',return_value=CERT)
        self.badging=patch.object(qa,'inspected_identity',return_value=(qa.QA_PACKAGE,self.code,qa.QA_VERSION))
        self.signer.start();self.badging.start();self.addCleanup(self.signer.stop);self.addCleanup(self.badging.stop)

    def test_valid_qa_attestation(self):
        receipt=qa.verify(self.apk,None,CERT,SOURCE,self.code)
        self.assertTrue(receipt['qualification_only'])
        self.assertFalse(receipt['publishable_release'])
        self.assertEqual(receipt['version_code'],self.code)
        self.assertEqual(receipt['apk_sha256'],qa.apk_hash(self.apk))
        self.assertEqual(receipt,qa.verify(self.apk,receipt,CERT,SOURCE,self.code))

    def test_rejects_wrong_cert_code_signer_package_version_and_metadata(self):
        good=qa.verify(self.apk,None,CERT,SOURCE,self.code)
        mutations=[dict(good,qualification_only=False),dict(good,publishable_release=True),
                   dict(good,apk_sha256='0'*64),dict(good,source_commit='b'*40),
                   dict(good,version_code=13705),dict(good,qa_tag='community-v1.37.3-1')]
        for altered in mutations:
            with self.subTest(mutation=altered),self.assertRaises(qa.Rejected):
                qa.verify(self.apk,altered,CERT,SOURCE,self.code)
        with self.assertRaises(qa.Rejected): qa.verify(self.apk,None,'0'*64,SOURCE,self.code)
        with self.assertRaises(qa.Rejected): qa.verify(self.apk,None,CERT,SOURCE,13709)
        with patch.object(qa,'inspected_signer',return_value='0'*64),self.assertRaises(qa.Rejected):
            qa.verify(self.apk,None,CERT,SOURCE,self.code)
        for x in [('org.kde.kdeconnect_tp',self.code,qa.QA_VERSION),
                  (qa.QA_PACKAGE,self.code,'1.37.3-community')]:
            with patch.object(qa,'inspected_identity',return_value=x),self.assertRaises(qa.Rejected):
                qa.verify(self.apk,None,CERT,SOURCE,self.code)
        self.apk.write_bytes(b'bad')
        with self.assertRaises(qa.Rejected):qa.verify(self.apk,None,CERT,SOURCE,self.code)

    def test_manifest_symlink_and_unsafe_main_modes_refused(self):
        md=Path(self.tmp.name)/'qa.json'
        self.assertEqual(qa.main(['verify','--apk',str(self.apk),'--metadata',str(md),
                                  '--expected-cert',CERT,'--expected-source',SOURCE,'--expected-code','13704']),2)
        self.assertEqual(qa.main(['attest','--apk',str(self.apk),'--metadata',str(md),
                                  '--expected-cert',CERT,'--expected-source',SOURCE,'--expected-code','13704']),0)
        self.assertEqual(qa.main(['verify','--apk',str(self.apk),'--metadata',str(md),
                                  '--expected-cert',CERT,'--expected-source',SOURCE,'--expected-code','13704']),0)
        self.assertEqual(qa.main(['attest','--apk',str(self.apk),'--metadata',str(md),
                                  '--expected-cert',CERT,'--expected-source',SOURCE,'--expected-code','13704']),2)

class AndroidSignerReportCompatibility(unittest.TestCase):
    """Signed APK verification must cover both modern SDK-range and legacy rows."""
    def test_valid_single_signer_legacy_and_sdk_ranges(self):
        for report in (
            'Verifies\nNumber of signers: 1\nSigner #1 certificate SHA-256 digest: '+CERT+'\n',
            'Verifies\nSigner (minSdkVersion=24, maxSdkVersion=32) certificate SHA-256 digest: '+CERT+'\n'
            'Signer (minSdkVersion=33) certificate SHA-256 digest: '+CERT+'\n',
            'Signer (minSdkVersion=24, maxSdkVersion=32) certificate SHA-256 digest: '+CERT.upper()+'\n'
            'Signer (minSdkVersion=33, maxSdkVersion=36) certificate SHA-256 digest: '+CERT+'\n',
        ):
            with self.subTest(report=report):
                self.assertEqual(qa.parse_verified_signer_report(report),CERT)

    def test_rejects_ambiguous_or_missing_certificate(self):
        for report in (
            '', 'Verifies\n',
            'Signer #1 certificate SHA-1 digest: '+CERT[:40]+'\n',
            'Signer #1 certificate SHA-256 digest: '+CERT[:-1]+'\n',
            'Signer #1 certificate SHA-256 digest: '+CERT+'\n'
            'Signer #2 certificate SHA-256 digest: '+'a'*64+'\n',
            'Signer (minSdkVersion=24, maxSdkVersion=32) certificate SHA-256 digest: '+CERT+'\n'
            'Signer (minSdkVersion=33) certificate SHA-256 digest: '+'a'*64+'\n',
            'Number of signers: 2\nSigner #1 certificate SHA-256 digest: '+CERT+'\n',
            'Signer unexpected certificate SHA-256 digest: '+CERT+'\n',
            'Signer #1 certificate SHA-256 digest: '+CERT+'\n'
            'Signer odd-version certificate SHA-256 digest: '+CERT+'\n',
        ):
            with self.subTest(report=report), self.assertRaises(qa.Rejected):
                qa.parse_verified_signer_report(report)

    def test_verified_report_variants_and_colon_digest(self):
        colon = ':'.join(CERT[i:i+2] for i in range(0, 64, 2))
        for report in (
            'Verifies\nSigner #1 (minSdkVersion=24, maxSdkVersion=35) '
            'certificate SHA-256 digest: '+CERT+'\n',
            'Verifies\nSigner #1 certificate SHA-256 digest: '+colon+'\n',
            'Signer #1 certificate SHA-256 digest: '+CERT+'\n'
            'Signer (minSdkVersion=24, maxSdkVersion=35) certificate SHA-256 digest: '+CERT+'\n',
        ):
            with self.subTest(report_kind=report.splitlines()[1].split(' certificate')[0]):
                self.assertEqual(qa.parse_verified_signer_report(report), CERT)

    def test_same_certificate_from_a_second_numbered_signer_is_rejected(self):
        for report in (
            'Signer #1 certificate SHA-256 digest: '+CERT+'\n'
            'Signer #2 certificate SHA-256 digest: '+CERT+'\n',
            'Signer #1 certificate SHA-256 digest: '+CERT+'\n'
            'Signer #2 certificate SHA-1 digest: '+'a'*40+'\n',
            'Signer #1 certificate SHA-256 digest: '+CERT+'\nNumber of signers: 2\n',
        ):
            with self.subTest(report=report), self.assertRaises(qa.Rejected):
                qa.parse_verified_signer_report(report)

    def test_diagnostic_never_discloses_certificate_or_dn(self):
        sensitive = 'Private signing DN secret'
        report = ('Signer unfamiliar certificate SHA-256 digest: '+CERT+'\n'
                  'Signer #1 certificate DN: '+sensitive+'\n')
        with patch.object(qa, 'inspect_tool', return_value=report):
            with self.assertRaises(qa.Rejected) as caught:
                qa.inspected_signer(Path('/tmp/irrelevant.apk'))
        message = str(caught.exception)
        self.assertIn('apksigner_report_shape=', message)
        self.assertNotIn(CERT, message)
        self.assertNotIn(sensitive, message)
        self.assertNotIn('unfamiliar', message)

    def test_invalid_or_unrecognized_digest_refused(self):
        for report in (
            'Signer #1 certificate SHA-256 digest: not-a-sha\n',
            'Signer #1 certificate SHA-256 digest: '+CERT[:-1]+'\n',
            'Signer unknown certificate SHA-256 digest: '+CERT+'\n',
            'Signer #0 certificate SHA-256 digest: '+CERT+'\n',
        ):
            with self.subTest(report=report), self.assertRaises(qa.Rejected):
                qa.parse_verified_signer_report(report)

    def test_fallback_uses_verified_pem_certificate(self):
        import base64, hashlib
        der=b'\x30\x12' + b'X'*18
        pem='-----BEGIN CERTIFICATE-----\n'+base64.b64encode(der).decode()+'\n-----END CERTIFICATE-----\n'
        signer=hashlib.sha256(der).hexdigest()
        with patch.object(qa,'inspect_tool',side_effect=['Verifies\n','Verifies\n'+pem]) as tool:
            self.assertEqual(qa.inspected_signer(Path('/tmp/qa.apk')),signer)
            self.assertEqual(tool.call_count,2)
            self.assertIn('--print-certs',tool.call_args_list[0].args[1])
            self.assertIn('--print-certs-pem',tool.call_args_list[1].args[1])

    def test_fallback_requires_exactly_one_certificate(self):
        import base64
        der=b'\x30\x12' + b'X'*18
        pem='-----BEGIN CERTIFICATE-----\n'+base64.b64encode(der).decode()+'\n-----END CERTIFICATE-----\n'
        for report in ('',pem+pem,'Number of signers: 2\n'+pem,
                       'Signer #2 certificate DN: private\n'+pem,
                       '-----BEGIN CERTIFICATE-----\ninvalid!\n-----END CERTIFICATE-----\n'):
            with self.subTest(length=len(report)),self.assertRaises(qa.Rejected):
                qa.parse_verified_pem_report(report)

    def test_malformed_digest_never_falls_back_to_pem(self):
        with patch.object(qa,'inspect_tool',return_value='Signer #1 certificate SHA-256 digest: BAD\n') as tool:
            with self.assertRaises(qa.Rejected):
                qa.inspected_signer(Path('/tmp/qa.apk'))
            self.assertEqual(tool.call_count,1)

    def test_apksigner_stream_merge_and_failure_refusal(self):
        from unittest.mock import Mock
        completed=Mock(returncode=0,stdout='Verifies\n',stderr='Signer #1 certificate SHA-256 digest: '+CERT+'\n')
        with patch('shutil.which',return_value='/fake/apksigner'), \
             patch.object(qa.subprocess,'run',return_value=completed):
            with patch.dict(qa.os.environ,{'ANDROID_HOME':'/nonexistent','ANDROID_SDK_ROOT':'/nonexistent'}):
                actual=qa.inspect_tool('apksigner',['verify','--print-certs','/fake.apk'])
            self.assertEqual(qa.parse_verified_signer_report(actual),CERT)
        completed.returncode=2
        with patch('shutil.which',return_value='/fake/apksigner'), \
             patch.object(qa.subprocess,'run',return_value=completed):
            with patch.dict(qa.os.environ,{'ANDROID_HOME':'/nonexistent','ANDROID_SDK_ROOT':'/nonexistent'}):
                with self.assertRaises(qa.Rejected):
                    qa.inspect_tool('apksigner',['verify','/fake.apk'])

    def test_fallback_error_does_not_disclose_pem_or_dn(self):
        secret='Private signing DN secret'
        report='Signer #2 certificate DN: '+secret+'\n'
        with patch.object(qa,'inspect_tool',return_value=report):
            with self.assertRaises(qa.Rejected) as caught:
                qa.inspected_signer(Path('/tmp/qa.apk'))
        self.assertNotIn(secret,str(caught.exception))

    def test_inspected_signer_requires_real_successful_apksigner_verify(self):
        report='Signer (minSdkVersion=24, maxSdkVersion=32) certificate SHA-256 digest: '+CERT+'\n'
        with patch.object(qa,'inspect_tool',return_value=report) as call:
            self.assertEqual(qa.inspected_signer(Path('/tmp/fake.apk')),CERT)
            self.assertEqual(call.call_args.args[0], 'apksigner')
            self.assertIn('verify',call.call_args.args[1])
            self.assertIn('--min-sdk-version',call.call_args.args[1])
        with patch.object(qa,'inspect_tool',side_effect=qa.Rejected('Invalid APK signature')):
            with self.assertRaises(qa.Rejected):qa.inspected_signer(Path('/tmp/fake.apk'))

    def test_production_uses_same_real_signature_verifier(self):
        workflow=(ROOT/'.github/workflows/community-release.yml').read_text(encoding='utf8')
        self.assertIn('from tools.signed_qa import inspected_signer',workflow)
        self.assertIn("inspected_signer(Path('release/kdeconnect-community.apk'))",workflow)
        self.assertIn('if actual != pinned:',workflow)
        self.assertNotIn('re.findall(',workflow)

    def test_bounded_maven_429_retries_only(self):
        workflow=(ROOT/'.github/workflows/signed-qa.yml').read_text(encoding='utf8')
        required=('max-parallel: 2', 'for attempt in 1 2 3',
                  'Received status code 429', 'Too Many Requests',
                  'result=${PIPESTATUS[0]}', 'tee "$RUNNER_TEMP/kde-qa-gradle.log"',
                  'exit "$result"', 'testReleaseUnitTest lintRelease assembleRelease')
        for x in required:self.assertIn(x,workflow)
        self.assertNotIn('continue-on-error:',workflow)
        self.assertNotIn('|| true',workflow)

class Maven429HostedShellRegression(unittest.TestCase):
    """Execute the actual hosted bash step with fake Gradle; never waive errors."""

    @staticmethod
    def shell_step() -> str:
        workflow=(ROOT/'.github/workflows/signed-qa.yml').read_text(encoding='utf8')
        step=workflow.split('      - name: Build signed, isolated QA release candidate\n',1)[1]
        step=step.split('      - name: Verify signer, APK package/version and create QA-only receipt\n',1)[0]
        body=step.split('        run: |\n',1)[1]
        return textwrap.dedent(body)

    @staticmethod
    def execute(scenario: str) -> tuple[int, int, str]:
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            gradlew=root/'gradlew'
            gradlew.write_text("""#!/usr/bin/env bash
set -euo pipefail
counter="$RUNNER_TEMP/attempt-count"
count=0
if [[ -s "$counter" ]]; then count=$(cat "$counter"); fi
count=$((count + 1))
printf '%s' "$count" > "$counter"
case "$QA_TEST_SCENARIO" in
  success) echo 'BUILD SUCCESSFUL'; exit 0;;
  429-then-success)
    if ((count == 1)); then echo 'Could not GET ... Received status code 429 from server: Too Many Requests'; exit 1; fi
    echo 'BUILD SUCCESSFUL'; exit 0;;
  fail-compile) echo 'Compilation error: Kotlin type mismatch'; exit 7;;
  persistent-429) echo 'Could not GET ... Received status code 429 from server: Too Many Requests'; exit 1;;
esac
exit 99
""")
            gradlew.chmod(0o755)
            binpath=root/'bin';binpath.mkdir()
            sleeper=binpath/'sleep';sleeper.write_text('#!/bin/sh\nexit 0\n');sleeper.chmod(0o755)
            env=os.environ.copy()
            env.update(RUNNER_TEMP=temp, QA_TEST_SCENARIO=scenario,
                       PATH=str(binpath)+os.pathsep+env.get('PATH',''))
            result=subprocess.run(['bash','-c',Maven429HostedShellRegression.shell_step()],
                                  cwd=root,env=env,capture_output=True,text=True,timeout=15)
            return result.returncode,int((root/'attempt-count').read_text()),result.stdout+result.stderr

    def test_successful_gradle_not_repeated(self):
        rc,n,_=self.execute('success');self.assertEqual((rc,n),(0,1))

    def test_maven_429_only_retried_and_then_passes(self):
        rc,n,logs=self.execute('429-then-success')
        self.assertEqual((rc,n),(0,2));self.assertIn('KDE_QA_MAVEN_429_RETRY',logs)

    def test_compilation_error_never_retried_or_waived(self):
        rc,n,logs=self.execute('fail-compile')
        self.assertEqual((rc,n),(7,1));self.assertIn('Compilation error',logs)

    def test_repeated_maven_429_remains_failed(self):
        rc,n,logs=self.execute('persistent-429')
        self.assertEqual((rc,n),(1,3));self.assertIn('KDE_QA_GRADLE_FAILURE',logs)

class SignedQaChain(unittest.TestCase):
    def test_require_all_five_same_signer_and_monotonic(self):
        with tempfile.TemporaryDirectory() as path:
            root=Path(path)
            for code in qa.QA_CODES:
                d=root/f'kdeconnect-signed-qa-{SOURCE}-{code}'
                d.mkdir()
                b=d/qa.QA_NAME
                b.write_bytes(b'A'*2048)
                (d/'qa.json').write_text(json.dumps({'signing_certificate_sha256':CERT}))
            with patch.object(qa,'verify',side_effect=lambda apk,meta,cert,src,code: {'apk_sha256':'1'*64}):
                result=pair.inspect_chain(root,SOURCE)
                self.assertEqual([x['version_code'] for x in result['candidates']],list(qa.QA_CODES))
                self.assertFalse(result['production_release_qualified'])
                (root/f'kdeconnect-signed-qa-{SOURCE}-13708'/'qa.json').unlink()
                with self.assertRaises(qa.Rejected): pair.inspect_chain(root,SOURCE)

class SignedQaSourceContract(unittest.TestCase):
    def read(self,path):return (ROOT/path).read_text(encoding='utf8')

    @staticmethod
    def inspect(workflow,gradle,updater,release,ci):
        must=lambda condition: (_ for _ in ()).throw(ValueError('Signed QA contract drift')) if not condition else None
        for token in ('on:\n  push:\n    tags:',"'kde-qa-*'",'environment: community-signing-qa',
                      'GITHUB_ACTOR',"'Mikeyphw'",'GITHUB_SHA', 'pulls/1', 'head_sha=$GITHUB_SHA',
                      'KDE_FORK_SIGNING_CERT_SHA256', 'testReleaseUnitTest lintRelease assembleRelease',
                      'signed_qa.py attest','signed_qa_pair.py','retention-days: 3',
                      '13704, 13705, 13706, 13707, 13708'):
            must(token in workflow)
        for forbidden in ('gh release create','workflow_dispatch:','pull_request:','push:\n    branches:',
                          'KDE_FORK_KEYSTORE_BASE64: ${{ github.event'):
            must(forbidden not in workflow)
        must('buildConfigField("boolean", "KDE_SIGNED_QA_INSTALL"' in gradle)
        must('storeType = "pkcs12"' in gradle)
        must('if (System.getenv("KDE_FORK_SIGNED_QA") == "1") "true" else "false"' in gradle)
        must('require(forkVersionCode != null && forkVersionCode in 13704..13708)' in gradle)
        must('versionName = if (signedQaVariant) "1.37.3-community-qa" else "1.37.3"' in gradle)
        must('versionNameSuffix = if (signedQaVariant) "" else "-community"' in gradle)
        must('if (BuildConfig.KDE_SIGNED_QA_INSTALL)' in updater)
        must('if (uri == null || !BuildConfig.KDE_SIGNED_QA_INSTALL)' in updater)
        must('check(BuildConfig.KDE_SIGNED_QA_INSTALL)' in release)
        must('verifyApkIdentity(context, partial, identity)' in release)
        must('Only signed QA-to-QA upgrades are allowed' in release)
        must('test_signed_qa_contract.py' in ci)
        must('KDE_FORK_KEYSTORE_BASE64' not in ci)

    def test_signed_qa_isolation(self):
        self.inspect(self.read('.github/workflows/signed-qa.yml'),self.read('build.gradle.kts'),
                     self.read('src/main/java/org/kde/kdeconnect/updates/UpdaterActivity.kt'),
                     self.read('src/main/java/org/kde/kdeconnect/updates/ReleaseUpdater.kt'),
                     self.read('.github/workflows/android-ci.yml'))

    def test_production_release_minimum_and_QA_recording(self):
        wf=self.read('.github/workflows/community-release.yml')
        self.assertIn('10#$KDE_FORK_VERSION_CODE > 13708',wf)
        self.assertIn("KDE_FORK_SIGNED_QA: '0'",wf)
        accept=self.read('tools/community_acceptance.py')
        self.assertIn('has_qa_candidates',accept)
        kotlin=self.read('src/test/java/org/kde/kdeconnect/updates/QaSignedInstallerGuardTest.kt')
        self.assertIn('productionAndDebugBuildsRejectLocalQaImports',kotlin)
        self.assertIn('QA_SIGNED',kotlin.replace('KDE_SIGNED_QA','QA_SIGNED'))
        self.assertIn('"qa_only": has_qa_candidates',accept)
        self.assertIn('"fully_device_qualified": False',accept)
        self.assertIn('"signed_release_qualified": False',accept)

    def test_negative_contract_mutations(self):
        files=[self.read('.github/workflows/signed-qa.yml'),self.read('build.gradle.kts'),
               self.read('src/main/java/org/kde/kdeconnect/updates/UpdaterActivity.kt'),
               self.read('src/main/java/org/kde/kdeconnect/updates/ReleaseUpdater.kt'),
               self.read('.github/workflows/android-ci.yml')]
        cases=[(0,"'kde-qa-*'", "'*'"),
               (0,'environment: community-signing-qa','environment: default'),
               (0,"'Mikeyphw'","'anyone'"),
               (0,'signed_qa.py attest','echo done'),
               (1,'versionName = if (signedQaVariant) "1.37.3-community-qa" else "1.37.3"',
                  'versionName = "1.37.3"'),
               (1,'forkVersionCode in 13704..13708','forkVersionCode in 13703..13708'),
               (1,'versionNameSuffix = if (signedQaVariant) "" else "-community"',
                  'versionNameSuffix = "-community"'),
               (2,'if (BuildConfig.KDE_SIGNED_QA_INSTALL)','if (true)'),
               (3,'verifyApkIdentity(context, partial, identity)','// bypassed identity'),
               (4,'test_signed_qa_contract.py','missing_qa_contract.py')]
        for index,a,b in cases:
            self.assertIn(a,files[index])
            altered=files.copy();altered[index]=altered[index].replace(a,b,1)
            with self.subTest(case=(index,a)),self.assertRaises(ValueError):self.inspect(*altered)



class ModernApksignerSchemeCompatibility(unittest.TestCase):
    """Build-tools 37 scheme-prefixed certificate report; still fail closed."""

    def test_verified_v3_scheme_rows_match_original_certificate_pin(self):
        for row in (
            'V3.0 Signer: certificate SHA-256 digest: '+CERT,
            'V3.0 Signer: (minSdkVersion=24, maxSdkVersion=32) certificate SHA-256 digest: '+CERT,
            'V3.1 Signer: (minSdkVersion=33, maxSdkVersion=36) certificate SHA-256 digest: '+CERT,
            'V2.0 Signer: certificate SHA-256 digest: '+CERT,
            'V2 Signer: certificate SHA-256 digest: '+CERT,
            'V3.2 Signer: certificate SHA-256 digest: '+CERT,
        ):
            report='Verifies\nNumber of signers: 1\n'+row+'\n'
            with self.subTest(row=row[:15]):
                self.assertEqual(qa.parse_verified_signer_report(report),CERT)
                self.assertIn('sha256_rows=1',qa.report_shape(report))

    def test_real_verifier_path_uses_only_successful_apksigner_verify(self):
        report=('Verifies\nNumber of signers: 1\n'
                'V3.0 Signer: certificate SHA-256 digest: '+CERT+'\n')
        with patch.object(qa,'inspect_tool',return_value=report) as call:
            self.assertEqual(qa.inspected_signer(Path('/irrelevant.apk')),CERT)
            self.assertEqual(call.call_count,1)
            self.assertIn('verify',call.call_args.args[1])
        with patch.object(qa,'inspect_tool',side_effect=qa.Rejected('bad signature')):
            with self.assertRaises(qa.Rejected):
                qa.inspected_signer(Path('/irrelevant.apk'))

    def test_conflicting_or_malformed_scheme_signers_refused_without_fallback(self):
        base='Verifies\nNumber of signers: 1\n'
        good='V3.0 Signer: certificate SHA-256 digest: '+CERT+'\n'
        bad='V3.1 Signer: certificate SHA-256 digest: '+'a'*64+'\n'
        inputs=(
            base+good+bad,
            'Verifies\nNumber of signers: 2\n'+good,
            base+'V3.0 Signer #2 certificate SHA-256 digest: '+CERT+'\n',
            base+'V4.0 Signer: certificate SHA-256 digest: '+CERT+'\n',
            base+'V3.0 Signer: certificate SHA-256 digest: '+CERT[:-1]+'\n',
            base+good+good,
            base+'V3.1 Signer: (minSdkVersion=abc) certificate SHA-256 digest: '+CERT+'\n',
        )
        for report in inputs:
            with self.subTest(shape=qa.report_shape(report)), self.assertRaises(qa.Rejected):
                qa.parse_verified_signer_report(report)
            with patch.object(qa,'inspect_tool',return_value=report) as call:
                with self.assertRaises(qa.Rejected):
                    qa.inspected_signer(Path('/irrelevant.apk'))
                self.assertEqual(call.call_count,1)

    def test_scheme_report_diagnostics_dont_disclose_fingerprint(self):
        report='V3.0 Signer: certificate SHA-256 digest: '+CERT+'\n'
        self.assertIn('scheme-v3.0',qa.report_shape(report))
        self.assertNotIn(CERT,qa.report_shape(report))


class SignedQaManifestIdentityDiagnostics(unittest.TestCase):
    """Reject mismatched package, code, or QA name; report only safe metadata."""
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.apk=Path(self.tmp.name)/qa.QA_NAME
        self.apk.write_bytes(b'A'*2048)
        self.signer=patch.object(qa,'inspected_signer',return_value=CERT)
        self.signer.start()
        self.addCleanup(self.signer.stop)

    def test_canonical_manifest_identity_is_accepted(self):
        with patch.object(qa,'inspected_identity',return_value=(qa.QA_PACKAGE,13704,qa.QA_VERSION)):
            result=qa.verify(self.apk,None,CERT,SOURCE,13704)
        self.assertEqual(result['version_name'],qa.QA_VERSION)

    def test_each_identity_mismatch_still_refused_and_identified(self):
        rows=[
            (('org.kde.invalid',13704,qa.QA_VERSION),'package'),
            ((qa.QA_PACKAGE,13703,qa.QA_VERSION),'versionCode'),
            ((qa.QA_PACKAGE,13704,'1.37.3-community'),'versionName'),
        ]
        for actual,field in rows:
            with self.subTest(field=field),patch.object(qa,'inspected_identity',return_value=actual):
                with self.assertRaises(qa.Rejected) as caught:
                    qa.verify(self.apk,None,CERT,SOURCE,13704)
                self.assertIn('fields='+field,str(caught.exception))
                self.assertIn('Wrong QA APK',str(caught.exception))

    def test_untrusted_manifest_text_does_not_escape_to_logs(self):
        evil='bad\n##[error]fake-runner-command'
        with patch.object(qa,'inspected_identity',return_value=(qa.QA_PACKAGE,13704,evil)):
            with self.assertRaises(qa.Rejected) as caught:
                qa.verify(self.apk,None,CERT,SOURCE,13704)
        msg=str(caught.exception)
        self.assertIn('observed_version=<redacted>',msg)
        self.assertNotIn(evil,msg)
        self.assertNotIn(CERT,msg)

    def test_release_qa_gradle_config_gates_are_current_and_strict(self):
        gradle=(ROOT/'build.gradle.kts').read_text(encoding='utf8')
        self.assertIn('versionName = if (signedQaVariant) "1.37.3-community-qa" else "1.37.3"',gradle)
        self.assertIn('require(forkVersionCode != null && forkVersionCode in 13704..13708)',gradle)
        self.assertIn('versionNameSuffix = if (signedQaVariant) "" else "-community"',gradle)
        self.assertIn('applicationIdSuffix = ".mikey"',gradle)

if __name__=='__main__':unittest.main()

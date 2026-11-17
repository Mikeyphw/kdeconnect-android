"""Independent regression/negative assurance for signed-QA workflow and verifier."""
import json
import sys
from pathlib import Path
import tempfile
import unittest
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
        must('"-community-qa" else "-community"' in gradle)
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
               (1,'"-community-qa" else "-community"','"-community" else "-community"'),
               (2,'if (BuildConfig.KDE_SIGNED_QA_INSTALL)','if (true)'),
               (3,'verifyApkIdentity(context, partial, identity)','// bypassed identity'),
               (4,'test_signed_qa_contract.py','missing_qa_contract.py')]
        for index,a,b in cases:
            self.assertIn(a,files[index])
            altered=files.copy();altered[index]=altered[index].replace(a,b,1)
            with self.subTest(case=(index,a)),self.assertRaises(ValueError):self.inspect(*altered)

if __name__=='__main__':unittest.main()

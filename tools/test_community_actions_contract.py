"""Regression checks for community Android CI and release workflow safety.

Run without third-party modules: python3 -m unittest discover -s tools -p test_community_actions_contract.py
"""
from pathlib import Path
import copy
import json
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SDK_ACTION_COMMIT = "be39fa834029ff78f1a44aa3bb0819b8fc2bd8fd"  # v4.0.4
REQUIRED_WORKFLOW_ID = 420422186  # GitHub verified numeric workflow identity


class CommunityWorkflowContractTests(unittest.TestCase):
    def workflows(self):
        return (
            ROOT / ".github/workflows/android-ci.yml",
            ROOT / ".github/workflows/community-release.yml",
        )

    def test_sdk_setup_exact_supported_commit(self):
        for file in self.workflows():
            with self.subTest(file=file.name):
                source = file.read_text(encoding="utf-8")
                refs = re.findall(
                    r"(?m)^\s*- uses: android-actions/setup-android@([^\s#]+)", source
                )
                self.assertEqual(refs, [SDK_ACTION_COMMIT])
                self.assertNotRegex(source, r"(?m)^\s*[-]?\s*run:\s*sdkmanager\s+tools\s*$")
                self.assertRegex(source, r"(?m)^\s*packages: 'platform-tools'\s*$")

    def test_ci_still_builds_and_tests_on_pull_request(self):
        source = self.workflows()[0].read_text(encoding="utf-8")
        for marker in ("  pull_request:", "  push:", "testDebugUnitTest", "lintDebug", "assembleDebug",
                       "testReleaseUnitTest", "lintRelease", "assembleRelease"):
            with self.subTest(marker=marker):
                self.assertIn(marker, source)
        self.assertIn("if: success()", source)

    def test_release_still_requires_explicit_manual_authorization(self):
        source = self.workflows()[1].read_text(encoding="utf-8")
        for marker in (
            "  workflow_dispatch:",
            "if: github.ref == 'refs/heads/master'",
            "KDE_FORK_KEYSTORE_BASE64",
            "KDE_FORK_SIGNING_CERT_SHA256",
            "gh release create",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, source)
        self.assertNotIn("  push:", source)
        self.assertNotIn("  pull_request:", source)


    @staticmethod
    def check_single_event_trigger_contract(workflow):
        """Each feature/sync PR HEAD gets one run; master and manual builds remain."""
        expected = (
            "on:\n"
            "  push:\n"
            "    branches: [master]\n"
            "  pull_request:\n"
            "  workflow_dispatch:\n"
        )
        if workflow.count(expected) != 1:
            raise ValueError("A PR branch must not run for both push and pull_request")
        # Do not weaken PR coverage by filtering paths, target branches or actions.
        if re.search(r"(?m)^  pull_request:\n    (?:types|branches|paths|paths-ignore):", workflow):
            raise ValueError("Pull-request CI may not be filtered")
        if "continue-on-error:" in workflow:
            raise ValueError("CI failures must remain blocking")

    def test_no_duplicate_runs_per_feature_pr(self):
        workflow = self.workflows()[0].read_text(encoding="utf-8")
        self.check_single_event_trigger_contract(workflow)
        cases = (
            workflow.replace("branches: [master]", "branches: [master, 'feature/**']", 1),
            workflow.replace("branches: [master]", "branches: [master, 'sync/**']", 1),
            workflow.replace("  pull_request:\n", "", 1),
            workflow.replace("  workflow_dispatch:\n", "", 1),
            workflow.replace("  pull_request:\n", "  pull_request:\n    paths: ['src/**']\n", 1),
            workflow.replace("  push:\n    branches: [master]", "  push:\n    branches: ['feature/**']", 1),
            workflow + "\n  continue-on-error: true\n",
        )
        for case in cases:
            with self.subTest(case=case[:130]):
                with self.assertRaises(ValueError):
                    self.check_single_event_trigger_contract(case)

    @staticmethod
    def check_required_ci_contract(policy, workflow):
        """Fail closed when the committed CI authority drifts from the PR workflow."""
        expected = {
            "schema_version": 1,
            "repository": "Mikeyphw/kdeconnect-android",
            "base_branch": "master",
            "event": "pull_request",
            "release_qualification": "separate",
            "required_workflows": [
                {"name": "Android community build", "workflow_id": REQUIRED_WORKFLOW_ID}
            ],
        }
        if policy != expected:
            raise ValueError("Required-CI policy differs from reviewed GitHub identity")
        if not re.search(r"(?m)^name: Android community build\s*$", workflow):
            raise ValueError("Required workflow name missing or changed")
        if not re.search(r"(?m)^  pull_request:[ \t]*(?:\n  [a-z_]+:|\npermissions:)", workflow):
            raise ValueError("Pull-request trigger missing or filtered")
        CommunityWorkflowContractTests.check_single_event_trigger_contract(workflow)
        if not re.search(r"(?m)^  workflow_dispatch:\s*$", workflow):
            raise ValueError("Manual build trigger was removed")
        if not re.search(r"(?m)^      - name: Validate community workflow contracts\s*$", workflow):
            raise ValueError("Community workflow contract gate not executed")

    def test_committed_required_ci_policy_matches_hosted_workflow(self):
        policy = json.loads((ROOT / "config/delivery-required-ci.json").read_text(encoding="utf-8"))
        workflow = self.workflows()[0].read_text(encoding="utf-8")
        self.check_required_ci_contract(policy, workflow)

    def test_required_ci_policy_negative_drift(self):
        policy = json.loads((ROOT / "config/delivery-required-ci.json").read_text(encoding="utf-8"))
        workflow = self.workflows()[0].read_text(encoding="utf-8")
        for key, value in (
            ("repository", "OtherUser/kdeconnect-android"),
            ("base_branch", "main"),
            ("event", "push"),
            ("release_qualification", "automatic"),
        ):
            with self.subTest(key=key):
                wrong = copy.deepcopy(policy)
                wrong[key] = value
                with self.assertRaises(ValueError):
                    self.check_required_ci_contract(wrong, workflow)
        for mismatch in ({"name": "Wrong CI", "workflow_id": REQUIRED_WORKFLOW_ID},
                         {"name": "Android community build", "workflow_id": REQUIRED_WORKFLOW_ID + 1}):
            with self.subTest(mismatch=mismatch):
                wrong = copy.deepcopy(policy)
                wrong["required_workflows"] = [mismatch]
                with self.assertRaises(ValueError):
                    self.check_required_ci_contract(wrong, workflow)
        with self.assertRaises(ValueError):
            self.check_required_ci_contract(policy, workflow.replace("  pull_request:", "  pull_request:\n    paths: ['*.md']"))

    @staticmethod
    def check_installer_aidl(source):
        rows = re.findall(r"(?m)^\s*void\s+(\w+)\([^;]*\)\s*=\s*(\d+)\s*;\s*$", source)
        expected = [
            ("begin", "1"), ("chunk", "2"), ("commit", "3"),
            ("abort", "4"), ("destroy", "16777114"),
        ]
        if rows != expected or len(re.findall(r"(?m)^\s*void\s+", source)) != len(expected):
            raise ValueError("AIDL methods require unique explicit IDs; preserve Shizuku destroy transaction ID")

    def test_privileged_installer_aidl_compiles_with_explicit_ids(self):
        file = ROOT / "src/main/aidl/org/kde/kdeconnect/updates/IPrivilegedInstaller.aidl"
        source = file.read_text(encoding="utf-8")
        self.check_installer_aidl(source)

    def test_privileged_installer_aidl_negative_missing_id(self):
        file = ROOT / "src/main/aidl/org/kde/kdeconnect/updates/IPrivilegedInstaller.aidl"
        source = file.read_text(encoding="utf-8")
        for original, replacement in (
            ("void abort() = 4;", "void abort();"),
            ("void destroy() = 16777114;", "void destroy() = 4;"),
            ("void chunk(in byte[] bytes) = 2;", "void chunk(in byte[] bytes) = 1;"),
        ):
            with self.subTest(replacement=replacement):
                self.assertIn(original, source)
                with self.assertRaises(ValueError):
                    self.check_installer_aidl(source.replace(original, replacement))


    @staticmethod
    def check_shizuku_min_sdk_contract(gradle):
        """The 13.1.5 AARs require API 24; keep Shizuku and AIDL build-time contracts explicit."""
        matches = re.findall(r"(?m)^\s*minSdk\s*=\s*(\d+)\s*$", gradle)
        if matches != ["24"]:
            raise ValueError("Community APK must declare minSdk 24 for Shizuku API 13.1.5")
        for artifact in ("api", "provider"):
            needle = f'implementation("dev.rikka.shizuku:{artifact}:13.1.5")'
            if gradle.count(needle) != 1:
                raise ValueError(f"Missing or changed official Shizuku {artifact} dependency")
        if len(re.findall(r"(?m)^\s*aidl\s*=\s*true\s*$", gradle)) != 1:
            raise ValueError("Exactly one enabled AIDL setting is required")
        if "tools:overrideLibrary" in re.sub(r"(?m)^\s*//.*$", "", gradle):
            raise ValueError("Unsafe Android minSdk override is forbidden")

    def test_shizuku_min_sdk_and_aidl_contract(self):
        source = (ROOT / "build.gradle.kts").read_text(encoding="utf-8")
        self.check_shizuku_min_sdk_contract(source)
        docs = (ROOT / "docs/COMMUNITY_BUILD_AND_UPDATES.md").read_text(encoding="utf-8")
        self.assertIn("Minimum API: 24 (Android 7.0)", docs)
        self.assertIn("API 23 (Android 6.0)", docs)

    def test_shizuku_min_sdk_negative_regressions(self):
        source = (ROOT / "build.gradle.kts").read_text(encoding="utf-8")
        cases = (
            source.replace("minSdk = 24", "minSdk = 23", 1),
            source.replace('implementation("dev.rikka.shizuku:api:13.1.5")',
                           'implementation("dev.rikka.shizuku:api:13.1.4")', 1),
            source.replace('implementation("dev.rikka.shizuku:provider:13.1.5")', "", 1),
            source.replace("aidl = true", "aidl = true\n        aidl = true", 1),
            source.replace("aidl = true", "aidl = false", 1),
            source + '\nandroid { tools:overrideLibrary="rikka.shizuku.api" }\n',
        )
        for case in cases:
            with self.subTest(case=case[-100:]):
                with self.assertRaises(ValueError):
                    self.check_shizuku_min_sdk_contract(case)

if __name__ == "__main__":
    unittest.main()


class FullLintDiagnosticsContractTests(unittest.TestCase):
    """Mandatory lint remains failing; its complete diagnostics are preserved."""

    def test_failed_lint_report_is_uploaded_without_suppressing_failure(self):
        workflow=(ROOT / '.github/workflows/android-ci.yml').read_text(encoding='utf-8')
        self.check_contract(workflow)

    @staticmethod
    def check_contract(workflow):
        marker='      - name: Upload full lint and test diagnostics\n'
        if workflow.count(marker)!=1:
            raise ValueError('Missing diagnostic-artifact step')
        suffix=workflow.split(marker,1)[1].split('      - name: Upload debug APK',1)[0]
        needed=('if: always()', 'actions/upload-artifact@v4',
                'build/reports/lint-results-debug.xml',
                'build/reports/lint-results-debug.sarif',
                'build/reports/lint-results-release.xml',
                'build/reports/lint-results-release.sarif',
                'build/intermediates/lint_intermediate_text_report/**/lint-results-debug.txt',
                'build/intermediates/lint_intermediate_text_report/**/lint-results-release.txt',
                'build/test-results/testDebugUnitTest/**/*.xml',
                'build/test-results/testReleaseUnitTest/**/*.xml',
                'if-no-files-found: warn')
        for token in needed:
            if token not in suffix:raise ValueError('Missing mandatory evidence token '+token)
        if ('-Pci testDebugUnitTest lintDebug assembleDebug testReleaseUnitTest lintRelease assembleRelease' not in workflow or
                'continue-on-error:' in workflow or
                'lintDebug --continue' in workflow):
            raise ValueError('CI must still fail when lint or tests fail')
        if 'if: success()' not in workflow.split('      - name: Upload debug APK',1)[1]:
            raise ValueError('Debug artifact must remain gated by successful build')

    def test_diagnostic_step_negative_tampering_refused(self):
        workflow=(ROOT / '.github/workflows/android-ci.yml').read_text(encoding='utf-8')
        for mutated in (workflow.replace('if: always()', 'if: success()',1),
                        workflow.replace('lintDebug ', '',1),
                        workflow.replace('if-no-files-found: warn', 'if-no-files-found: ignore',1),
                        workflow+'\n      continue-on-error: true\n'):
            with self.subTest(mutated=mutated[-80:]):
                with self.assertRaises(ValueError):self.check_contract(mutated)


class ReviewedLocalizationBaselineAndApiSafetyTests(unittest.TestCase):
    """Translation backlog is a fixed inventory, never a blanket lint bypass."""

    @staticmethod
    def check_reviewed_baseline(xml_bytes):
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml_bytes)
        if root.tag != 'issues' or root.get('type') != 'baseline' or root.get('format') != '6':
            raise ValueError('Unexpected Android lint baseline format')
        issues = root.findall('issue')
        if len(issues) != 444:
            raise ValueError('Localization backlog inventory changed; review new/deleted findings')
        counts = {id: sum(i.get('id') == id for i in issues)
                  for id in ('MissingTranslation','ExtraTranslation')}
        if counts != {'MissingTranslation':424,'ExtraTranslation':20}:
            raise ValueError('Only the reviewed translation backlog may be baselined')
        for issue in issues:
            if issue.get('id') not in counts or not issue.get('message'):
                raise ValueError('Security/compatibility lint may not be baselined')
            locs=issue.findall('location')
            if not locs or any(not l.get('file','').startswith(('src/main/res/','src/debug/res/'))
                               or l.get('file','').startswith('/') for l in locs):
                raise ValueError('Baseline may only cover source resource localization')

    @staticmethod
    def check_api_and_lint_safety(gradle,manifest,privileged,saf,ui,default_bools,api30_bools):
        if 'baseline = file("lint-baseline.xml")' not in gradle:
            raise ValueError('Required source-bound translation baseline missing')
        for token in ('abortOnError = true','coreLibraryDesugaring(libs.android.desugarJdkLibsNio)',
                      'isCoreLibraryDesugaringEnabled = true'):
            if token not in gradle:
                raise ValueError('Android compatibility or blocking lint contract removed')
        if 'android.intent.category.LEANBACK_LAUNCHER' not in manifest:
            raise ValueError('Android TV launcher category missing')
        for token in ('tools:targetApi="30"','android:enabled="@bool/kde_controls_provider_enabled"',
                      'RunCommandControlsProviderService'):
            if token not in manifest: raise ValueError('API 30 Controls provider guard absent')
        if 'kde_controls_provider_enabled">false' not in default_bools or \
           'kde_controls_provider_enabled">true' not in api30_bools or \
           'config_materialPreferenceIconSpaceReserved">true' not in default_bools:
            raise ValueError('Required safe default and API30-only resource values absent')
        if ('Build.VERSION.SDK_INT >= Build.VERSION_CODES.O' not in privileged or
             'if (proc.isAlive) proc.destroyForcibly()' not in privileged or
             'proc.destroy()' not in privileged):
            raise ValueError('API24-safe Process cleanup missing')
        if ('@SuppressLint("NewApi")' not in saf or
            'coreLibraryDesugaring(desugar_jdk_libs_nio)' not in saf):
            raise ValueError('NIO desugared API contract changed')
        if ('withContext(Dispatchers.IO)' not in ui or
            '!device.isPluginEnabled(pluginKey)' not in ui):
            raise ValueError('Preference read must leave the UI thread')

    def test_reviewed_translation_baseline_only(self):
        self.check_reviewed_baseline((ROOT/'lint-baseline.xml').read_bytes())

    def test_baseline_rejects_nontranslation_and_growth(self):
        import xml.etree.ElementTree as ET
        baseline=(ROOT/'lint-baseline.xml').read_bytes()
        root=ET.fromstring(baseline)
        ET.SubElement(root,'issue',{'id':'NewApi','message':'Must not baseline safety'})
        with self.assertRaises(ValueError):
            self.check_reviewed_baseline(ET.tostring(root))
        root=ET.fromstring(baseline)
        root.remove(root.findall('issue')[0])
        with self.assertRaises(ValueError):
            self.check_reviewed_baseline(ET.tostring(root))

    def files(self):
        def read(path): return (ROOT/path).read_text(encoding='utf-8')
        return (read('build.gradle.kts'),read('src/main/AndroidManifest.xml'),
                read('src/main/java/org/kde/kdeconnect/updates/PrivilegedUpdateInstall.kt'),
                read('src/main/java/org/kde/kdeconnect/plugins/sftp/saf/SafFileSystemProvider.kt'),
                read('src/main/java/org/kde/kdeconnect/ui/PluginPreference.kt'),
                read('src/main/res/values/bools.xml'),read('src/main/res/values-v30/bools.xml'))

    def test_api_compatibility_and_blocking_lint_contract(self):
        self.check_api_and_lint_safety(*self.files())

    def test_api_safety_negative_mutations(self):
        originals=self.files()
        cases={0:('abortOnError = true','abortOnError = false'),
               1:('android:enabled="@bool/kde_controls_provider_enabled"','android:enabled="true"'),
               2:('Build.VERSION.SDK_INT >= Build.VERSION_CODES.O','Build.VERSION.SDK_INT >= 35'),
               3:('coreLibraryDesugaring(desugar_jdk_libs_nio)','NIO not desugared'),
               4:('withContext(Dispatchers.IO)','withContext(Dispatchers.Main)')}
        for index,(old,new) in cases.items():
            copy=list(originals)
            self.assertIn(old,copy[index])
            copy[index]=copy[index].replace(old,new,1)
            with self.subTest(file=index), self.assertRaises(ValueError):
                self.check_api_and_lint_safety(*copy)


class PluginPreferenceThreadBoundaryTests(unittest.TestCase):
    """No UI access or preference writes on the wrong dispatcher."""

    @staticmethod
    def check_source(source: str):
        worker = source.partition('    @WorkerThread\n    private fun togglePluginOnWorker()')[2].partition('\n    }')[0]
        ui = source.partition('    @MainThread\n    private fun updateBoundToggle(')[2].partition('\n    }')[0]
        if not worker or not ui:
            raise ValueError('Explicit Main/Worker annotated functions required')
        if ('!device.isPluginEnabled(pluginKey)' not in worker or
                'device.setPluginEnabled(pluginKey, newState)' not in worker):
            raise ValueError('Both preference read and write must remain on Worker')
        if any(word in worker for word in ('itemView', 'onStateChanged(', 'isChecked =', '.isEnabled =')):
            raise ValueError('Worker implementation must not touch Android views')
        if 'withContext(Dispatchers.IO) {\n        togglePluginOnWorker()' not in source:
            raise ValueError('Preference transaction must dispatch onto IO')
        if ('withContext(Dispatchers.Main.immediate) {\n                        updateBoundToggle(' not in source or
                'withContext(kotlinx.coroutines.NonCancellable + Dispatchers.Main.immediate)' not in source):
            raise ValueError('UI updates and cancellation cleanup must dispatch onto Main')
        if not all(part in ui for part in ('itemView.isAttachedToWindow',
                                         'isChecked = newState', 'onStateChanged(holder, newState)')):
            raise ValueError('Bound UI state must be updated on Main only')
        if ('itemView.isEnabled = false' not in source or
                'itemView.isEnabled = true' not in source):
            raise ValueError('Item must be re-enabled after preference transaction')

    def test_plugin_preference_thread_boundary(self):
        file = ROOT/'src/main/java/org/kde/kdeconnect/ui/PluginPreference.kt'
        self.check_source(file.read_text(encoding='utf-8'))

    def test_negative_wrong_dispatcher_and_ui_calls(self):
        source = (ROOT/'src/main/java/org/kde/kdeconnect/ui/PluginPreference.kt').read_text(encoding='utf-8')
        mutations = (
            source.replace('withContext(Dispatchers.IO) {\n        togglePluginOnWorker()',
                           'withContext(Dispatchers.Main) {\n        togglePluginOnWorker()',1),
            source.replace('withContext(Dispatchers.Main.immediate) {\n                        updateBoundToggle(',
                           'withContext(Dispatchers.IO) {\n                        updateBoundToggle(',1),
            source.replace('withContext(kotlinx.coroutines.NonCancellable + Dispatchers.Main.immediate)',
                           'withContext(Dispatchers.IO)',1),
            source.replace('device.setPluginEnabled(pluginKey, newState)',
                           'itemView.isEnabled = true',1),
        )
        for altered in mutations:
            with self.subTest(altered=altered[-60:]), self.assertRaises(ValueError):
                self.check_source(altered)


class UnsignedReleaseVariantQualificationTests(unittest.TestCase):
    """PR CI qualifies both variants without signing, publishing or distributing release APKs."""

    @staticmethod
    def check_workflow(source):
        required = (
            'run: ./gradlew --no-daemon --console=plain -Pci testDebugUnitTest lintDebug assembleDebug testReleaseUnitTest lintRelease assembleRelease',
            '- name: Verify unsigned community release package identity',
            'set -euo pipefail',
            'find build/outputs/apk/release -maxdepth 1 -type f -name',
            '[[ ${#apks[@]} -eq 1 ]]',
            'badging=$("$aapt" dump badging "${apks[0]}")',
            "package: name='org.kde.kdeconnect_tp.mikey'",
            '"$apksigner" verify "${apks[0]}" >/dev/null 2>&1',
            "Unexpectedly signed release APK in PR CI; refusing",
            'build/reports/lint-results-release.sarif',
            'build/test-results/testReleaseUnitTest/**/*.xml',
        )
        for term in required:
            if term not in source:
                raise ValueError('Missing release-variant CI qualification: '+term)
        if source.count('- name: Verify unsigned community release package identity') != 1:
            raise ValueError('Release artifact identity verification must run exactly once')
        if ('if "$apksigner" verify "${apks[0]}" >/dev/null 2>&1; then' not in source or
                'exit 1' not in source.split('if "$apksigner" verify',1)[1].split('fi',1)[0]):
            raise ValueError('Signed release artifacts must be refused in PR CI')
        if any(term in source for term in ('gh release create','KDE_FORK_STORE_PASSWORD',
                                          'KDE_FORK_KEYSTORE_BASE64','KDE_FORK_KEYSTORE=',
                                          'continue-on-error:','|| true')):
            raise ValueError('PR CI must never publish, use signing secrets, or bypass errors')
        upload_section = source.split('- name: Upload debug APK',1)[1]
        if 'build/outputs/apk/debug/*.apk' not in upload_section or 'if: success()' not in upload_section:
            raise ValueError('PR debug artifact must remain successful-build-only')
        if 'build/outputs/apk/release/*.apk' in source or 'release/kdeconnect-community.apk' in source:
            raise ValueError('Unsigned release APKs must not be uploaded for distribution')
        if 'timeout-minutes: 55' not in source:
            raise ValueError('CI job must retain explicit watchdog timeout')

    def test_release_variant_qualification_contract(self):
        source=(ROOT/'.github/workflows/android-ci.yml').read_text(encoding='utf-8')
        self.check_workflow(source)

    def test_release_variant_qualification_negative_drift(self):
        source=(ROOT/'.github/workflows/android-ci.yml').read_text(encoding='utf-8')
        cases=(
            source.replace('testReleaseUnitTest','testDebugUnitTest',1),
            source.replace('lintRelease','lintDebug',1),
            source.replace('assembleRelease','assembleDebug',1),
            source.replace("package: name='org.kde.kdeconnect_tp.mikey'","package: name='org.kde.kdeconnect_tp'",1),
            source.replace('if "$apksigner" verify', 'if false && "$apksigner" verify',1),
            source.replace('exit 1\n          fi','exit 0\n          fi',1),
            source+'\n      - run: gh release create v1\n',
            source+'\n      continue-on-error: true\n',
            source.replace('build/outputs/apk/debug/*.apk','build/outputs/apk/release/*.apk',1),
        )
        for case in cases:
            with self.subTest(case=case[-90:]),self.assertRaises(ValueError):
                self.check_workflow(case)


class Agp9DualVariantUnitTestRegistrationTests(unittest.TestCase):
    """AGP 9 defaults to debug-only units; both real variants are required in CI."""

    @staticmethod
    def check_registration(props: str, workflow: str, gradle: str):
        import re
        lines = re.findall(r'(?m)^\s*android\.onlyEnableUnitTestForTheTestedBuildType\s*=\s*(\S+)\s*$', props)
        if lines != ['false']:
            raise ValueError('AGP9 must register actual debug and release unit-test components')
        expected = 'testDebugUnitTest lintDebug assembleDebug testReleaseUnitTest lintRelease assembleRelease'
        if workflow.count(expected) != 1:
            raise ValueError('Both variants, lint checks and APK builds must run in mandatory CI')
        if any(t in workflow for t in ('continue-on-error:', '|| true', '--dry-run', 'testReleaseUnitTest SKIPPED')):
            raise ValueError('CI must not skip, simulate, or ignore failures from release unit tests')
        if not re.search(r'(?m)^androidGradlePlugin\s*=\s*"9\.[0-9]+\.[0-9]+"\s*$', gradle):
            raise ValueError('AGP9 dual-variant setting must remain aligned with the version catalog')

    def inputs(self):
        return ((ROOT/'gradle.properties').read_text(encoding='utf-8'),
                (ROOT/'.github/workflows/android-ci.yml').read_text(encoding='utf-8'),
                (ROOT/'gradle/libs.versions.toml').read_text(encoding='utf-8'))

    def test_real_debug_and_release_unit_tests_registered(self):
        self.check_registration(*self.inputs())

    def test_negative_agp9_registration_and_ci_drift(self):
        props, workflow, gradle = self.inputs()
        cases = (
            ('props', props.replace('android.onlyEnableUnitTestForTheTestedBuildType=false',
                                    'android.onlyEnableUnitTestForTheTestedBuildType=true'), workflow, gradle),
            ('props', props.replace('android.onlyEnableUnitTestForTheTestedBuildType=false', ''), workflow, gradle),
            ('props', props + '\nandroid.onlyEnableUnitTestForTheTestedBuildType=true\n', workflow, gradle),
            ('ci', props, workflow.replace('testReleaseUnitTest ', ''), gradle),
            ('ci', props, workflow.replace('lintRelease ', ''), gradle),
            ('ci', props, workflow.replace('assembleRelease', 'assembleDebug', 1), gradle),
            ('ci', props, workflow+'\ncontinue-on-error: true\n', gradle),
            ('ci', props, workflow.replace('testReleaseUnitTest', 'testDebugUnitTest', 1), gradle),
            ('catalog', props, workflow, gradle.replace('androidGradlePlugin = "9.5.1"', 'androidGradlePlugin = "8.0.0"', 1)),
        )
        for kind, p, w, g in cases:
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.check_registration(p, w, g)

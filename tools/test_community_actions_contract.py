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
        for marker in ("  pull_request:", "  push:", "testDebugUnitTest", "lintDebug", "assembleDebug"):
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
        if not re.search(r"(?m)^  push:\s*$", workflow):
            raise ValueError("Expected push trigger was removed")
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
                'build/intermediates/lint_intermediate_text_report/**/lint-results-debug.txt',
                'build/test-results/testDebugUnitTest/**/*.xml',
                'if-no-files-found: warn')
        for token in needed:
            if token not in suffix:raise ValueError('Missing mandatory evidence token '+token)
        if ('-Pci testDebugUnitTest lintDebug assembleDebug' not in workflow or
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

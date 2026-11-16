"""Regression checks for community Android CI and release workflow safety.

Run without third-party modules: python3 -m unittest discover -s tools -p test_community_actions_contract.py
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SDK_ACTION_COMMIT = "be39fa834029ff78f1a44aa3bb0819b8fc2bd8fd"  # v4.0.4


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


if __name__ == "__main__":
    unittest.main()

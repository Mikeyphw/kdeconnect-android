/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
package org.kde.kdeconnect.updates

import android.net.Uri
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.kde.kdeconnect_tp.BuildConfig
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class QaSignedInstallerGuardTest {
    @Test fun qaFlagMatchesExplicitlyBrandedVariantOnly() {
        if (BuildConfig.KDE_SIGNED_QA_INSTALL) {
            assertTrue(BuildConfig.VERSION_NAME.endsWith("-community-qa"))
            assertTrue(BuildConfig.APPLICATION_ID.endsWith(".mikey"))
        } else {
            assertFalse(BuildConfig.VERSION_NAME.endsWith("-community-qa"))
        }
    }

    @Test fun productionAndDebugBuildsRejectLocalQaImports() {
        if (!BuildConfig.KDE_SIGNED_QA_INSTALL) {
            val app = RuntimeEnvironment.getApplication()
            try {
                ReleaseUpdater.importSignedQaCandidate(app, Uri.parse("content://local-test/candidate.apk"))
                throw AssertionError("Non-QA variant accepted local candidate")
            } catch (_: IllegalStateException) {
                // Required compile-time build flag prevents access to local APK path.
            }
        }
    }
}

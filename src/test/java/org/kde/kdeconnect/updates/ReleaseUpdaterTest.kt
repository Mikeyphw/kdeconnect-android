/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
package org.kde.kdeconnect.updates

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.kde.kdeconnect_tp.BuildConfig

@RunWith(RobolectricTestRunner::class)
class ReleaseUpdaterTest {
    private fun fixture(url: String = "https://github.com/Mikeyphw/kdeconnect-android/releases/download/community-v1.37.3-1/kdeconnect-community.apk"):
        Pair<JSONObject, JSONObject> {
        val r = JSONObject()
            .put("tag_name", "community-v1.37.3-1")
            .put("body", "Release notes")
            .put("assets", JSONArray().put(JSONObject()
                .put("name", "kdeconnect-community.apk")
                .put("size", 4096)
                .put("browser_download_url", url)))
        val metadata = JSONObject()
            .put("tag", "community-v1.37.3-1")
            .put("apk_name", "kdeconnect-community.apk")
            .put("apk_size", 4096)
            .put("version_code", 137040)
            .put("version_name", "1.37.4-community")
            .put("package_name", BuildConfig.APPLICATION_ID)
            .put("apk_sha256", "a".repeat(64))
        return r to metadata
    }

    @Test fun acceptsVerifiedMetadataShape() {
        val (release, manifest) = fixture()
        val result = ReleaseUpdater.parseRelease(release, manifest)
        assertEquals(137040L, result.versionCode)
        assertEquals(4096L, result.declaredSize)
    }

    private inline fun rejects(mutator: (JSONObject, JSONObject) -> Unit) {
        val (r, meta) = fixture()
        mutator(r, meta)
        try { ReleaseUpdater.parseRelease(r, meta); throw AssertionError("unexpected acceptance") }
        catch (_: IllegalArgumentException) { }
    }

    @Test fun rejectsUntrustedHost() {
        val (r, m) = fixture("https://evil.invalid/kdeconnect-community.apk")
        try { ReleaseUpdater.parseRelease(r, m); throw AssertionError("accepted untrusted host") }
        catch (_: IllegalArgumentException) { }
    }

    @Test fun rejectsWrongPackage() = rejects { _, m -> m.put("package_name", "org.kde.kdeconnect_tp") }

    @Test fun rejectsWrongTag() = rejects { _, m -> m.put("tag", "different-tag") }

    @Test fun rejectsOversizedRelease() = rejects { r, m ->
        m.put("apk_size", 251L * 1024 * 1024)
        r.getJSONArray("assets").getJSONObject(0).put("size", 251L * 1024 * 1024)
    }

    @Test fun rejectsShaMismatchFormatting() = rejects { _, m -> m.put("apk_sha256", "not-sha256") }

    @Test fun rejectsAssetFromDifferentReleaseTag() {
        val (r, m) = fixture("https://github.com/Mikeyphw/kdeconnect-android/releases/download/community-v1.37.3-0/kdeconnect-community.apk")
        try { ReleaseUpdater.parseRelease(r, m); throw AssertionError("accepted wrong release tag") }
        catch (_: IllegalArgumentException) { }
    }

    @Test fun rejectsAssetWithQueryOrFragment() {
        for (suffix in listOf("?source=untrusted", "#fragment")) {
            val (r, m) = fixture("https://github.com/Mikeyphw/kdeconnect-android/releases/download/community-v1.37.3-1/kdeconnect-community.apk$suffix")
            try { ReleaseUpdater.parseRelease(r, m); throw AssertionError("accepted additional URL components") }
            catch (_: IllegalArgumentException) { }
        }
    }

    @Test fun rejectsUnexpectedReleaseTagPattern() = rejects { r, m ->
        r.put("tag_name", "latest")
        m.put("tag", "latest")
    }

    @Test fun rejectsMissingApkAsset() = rejects { r, _ ->
        r.put("assets", JSONArray())
    }

    @Test fun rejectsInvalidVersionCode() = rejects { _, m ->
        m.put("version_code", 0)
    }

    @Test fun rejectsEmptyVersionName() = rejects { _, m ->
        m.put("version_name", "")
    }

    @Test fun rejectsAssetSizeMismatch() = rejects { r, _ ->
        r.getJSONArray("assets").getJSONObject(0).put("size", 3)
    }

    @Test fun rejectsDuplicateApk() = rejects { r, _ ->
        val asset = r.getJSONArray("assets").getJSONObject(0)
        r.getJSONArray("assets").put(JSONObject(asset.toString()))
    }
}

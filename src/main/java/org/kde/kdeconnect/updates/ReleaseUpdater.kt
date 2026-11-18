/*
 * SPDX-FileCopyrightText: 2026 KDE Connect community fork contributors
 * SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only
 */
package org.kde.kdeconnect.updates

import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import androidx.core.content.FileProvider
import org.json.JSONObject
import org.kde.kdeconnect_tp.BuildConfig
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/** Strictly trust GitHub Release metadata only as a discovery hint, never as an APK signature. */
data class AvailableUpdate(
    val versionCode: Long,
    val versionName: String,
    val tag: String,
    val notes: String,
    val sha256: String,
    val apkUrl: URL,
    val declaredSize: Long,
)

object ReleaseUpdater {
    private const val REPO = "Mikeyphw/kdeconnect-android"
    private const val API = "https://api.github.com/repos/$REPO/releases/latest"
    private const val MAX_APK_SIZE = 250L * 1024 * 1024
    private const val MAX_METADATA_BYTES = 128 * 1024
    private const val APK = "kdeconnect-community.apk"

    fun parseRelease(release: JSONObject, metadata: JSONObject): AvailableUpdate {
        val tag = release.getString("tag_name")
        val name = metadata.getString("apk_name")
        val versionCode = metadata.getLong("version_code")
        val versionName = metadata.getString("version_name")
        val packageName = metadata.getString("package_name")
        val size = metadata.getLong("apk_size")
        val sha256 = metadata.getString("apk_sha256").lowercase()
        require(tag.matches(Regex("community-v[0-9]+\\.[0-9]+\\.[0-9]+-[0-9]+")) &&
            tag == metadata.getString("tag")) { "Release tag mismatch" }
        require(name == APK && packageName == BuildConfig.APPLICATION_ID) { "Wrong APK package or asset" }
        require(versionCode in 1..2147483647L && versionName.isNotBlank()) { "Invalid version" }
        require(size in 1024..MAX_APK_SIZE) { "Invalid APK size" }
        require(Regex("[0-9a-f]{64}").matches(sha256)) { "Invalid SHA-256" }
        val assets = release.getJSONArray("assets")
        var found: URL? = null
        for (i in 0 until assets.length()) {
            val asset = assets.getJSONObject(i)
            if (asset.getString("name") == APK) {
                require(found == null) { "Duplicate APK assets" }
                require(asset.getLong("size") == size) { "Asset size mismatch" }
                found = URL(asset.getString("browser_download_url"))
            }
        }
        val url = requireNotNull(found) { "Release APK not found" }
        require(url.protocol == "https" && url.host == "github.com" &&
            url.query == null && url.ref == null &&
            url.path == "/$REPO/releases/download/$tag/$APK") { "Untrusted asset location" }
        return AvailableUpdate(versionCode, versionName, tag,
            release.optString("body", ""), sha256, url, size)
    }

    fun checkLatest(): AvailableUpdate? {
        val release = JSONObject(readHttps(URL(API), MAX_METADATA_BYTES).toString(Charsets.UTF_8))
        require(!release.optBoolean("draft") && !release.optBoolean("prerelease")) { "Release is not stable" }
        val assets = release.getJSONArray("assets")
        val manifest = (0 until assets.length()).map { assets.getJSONObject(it) }
            .filter { it.getString("name") == "update.json" }.singleOrNull()
            ?: throw IOException("A unique update.json release asset is required")
        val tag = release.getString("tag_name")
        require(manifest.getLong("size") in 2..MAX_METADATA_BYTES.toLong()) { "Invalid manifest size" }
        val raw = URL(manifest.getString("browser_download_url"))
        require(raw.protocol == "https" && raw.host == "github.com" &&
            raw.query == null && raw.ref == null &&
            raw.path == "/$REPO/releases/download/$tag/update.json") { "Untrusted manifest location" }
        val info = JSONObject(readHttps(raw, MAX_METADATA_BYTES).toString(Charsets.UTF_8))
        return parseRelease(release, info).takeIf { it.versionCode > BuildConfig.VERSION_CODE.toLong() }
    }

    fun downloadVerified(context: Context, release: AvailableUpdate,
                         onProgress: ((Long, Long) -> Unit)? = null): File {
        require(release.versionCode > BuildConfig.VERSION_CODE.toLong()) { "Downgrade refused" }
        val dir = File(context.cacheDir, "updates")
        require((dir.exists() || dir.mkdirs()) && dir.isDirectory) { "Cannot create update cache" }
        val temp = File(dir, "download.partial.apk")
        val verified = File(dir, "verified-${release.versionCode}.apk")
        temp.delete()
        try {
            val digest = MessageDigest.getInstance("SHA-256")
            val connection = openHttps(release.apkUrl)
            try {
                var total = 0L
                var lastReportedPercent = -1
                connection.inputStream.use { input ->
                    temp.outputStream().use { output ->
                        val buffer = ByteArray(64 * 1024)
                        while (true) {
                            val n = input.read(buffer)
                            if (n < 0) break
                            total += n
                            require(total <= MAX_APK_SIZE && total <= release.declaredSize) { "Oversized APK" }
                            digest.update(buffer, 0, n)
                            output.write(buffer, 0, n)
                            val percent = (total * 100L / release.declaredSize).toInt()
                            if (percent != lastReportedPercent) {
                                lastReportedPercent = percent
                                onProgress?.invoke(total, release.declaredSize)
                            }
                        }
                        output.fd.sync()
                    }
                }
                require(total == release.declaredSize) { "Incomplete APK" }
                require(digest.digest().joinToString("") { "%02x".format(it) } == release.sha256) {
                    "APK SHA-256 mismatch"
                }
            } finally {
                connection.disconnect()
            }
            verifyApkIdentity(context, temp, release)
            if (verified.exists() && !verified.delete()) throw IOException("Unable to replace old update")
            if (!temp.renameTo(verified)) throw IOException("Unable to finalize verified APK")
            return verified
        } finally {
            temp.delete()
        }
    }

    @Suppress("DEPRECATION")
    private fun getArchive(context: Context, file: File): PackageInfo? {
        val flags = if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES
        return context.packageManager.getPackageArchiveInfo(file.absolutePath, flags)
    }

    @Suppress("DEPRECATION")
    private fun signatures(info: PackageInfo): Set<String> {
        val certs = if (Build.VERSION.SDK_INT >= 28) {
            info.signingInfo?.apkContentsSigners?.toList().orEmpty()
        } else {
            info.signatures?.toList().orEmpty()
        }
        return certs.map { cert ->
            MessageDigest.getInstance("SHA-256").digest(cert.toByteArray())
                .joinToString("") { "%02x".format(it) }
        }.toSet()
    }

    @Suppress("DEPRECATION")
    fun verifyApkIdentity(context: Context, apk: File, release: AvailableUpdate) {
        val archive = requireNotNull(getArchive(context, apk)) { "Invalid APK archive" }
        require(archive.packageName == context.packageName) { "APK package identity mismatch" }
        val candidateCode = if (Build.VERSION.SDK_INT >= 28) archive.longVersionCode else archive.versionCode.toLong()
        require(candidateCode == release.versionCode && candidateCode > BuildConfig.VERSION_CODE.toLong()) {
            "APK version mismatch or downgrade"
        }
        require(archive.versionName == release.versionName) { "APK version name mismatch" }
        val flags = if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES
        val installed = context.packageManager.getPackageInfo(context.packageName, flags)
        val candidateSigners = signatures(archive)
        require(candidateSigners.isNotEmpty() && candidateSigners == signatures(installed)) {
            "APK signing certificate differs from installed application"
        }
    }

    /** Import a user-picked QA APK ONLY in signed, explicitly gated QA builds.
     *  The copied file is size-bounded, and the archive must match the current
     *  installed signing identity, package, and strictly newer versionCode.
     */
    fun importSignedQaCandidate(context: Context, uri: Uri): File {
        check(BuildConfig.KDE_SIGNED_QA_INSTALL) { "Local APK imports are not available in production" }
        require(uri.scheme == "content") { "Only content-provider APK selection is supported" }
        val dir = File(context.cacheDir, "updates")
        require((dir.exists() || dir.mkdirs()) && dir.isDirectory) { "Cannot prepare QA update cache" }
        val partial = File(dir, "qa-import.partial.apk")
        partial.delete()
        try {
            val input = requireNotNull(context.contentResolver.openInputStream(uri)) { "Unable to read selected APK" }
            var total = 0L
            input.use { source ->
                partial.outputStream().use { output ->
                    val buf = ByteArray(65536)
                    while (true) {
                        val n = source.read(buf)
                        if (n < 0) break
                        total += n
                        require(total <= MAX_APK_SIZE) { "QA APK exceeds safe size limit" }
                        output.write(buf, 0, n)
                    }
                    output.fd.sync()
                }
            }
            require(total >= 1024) { "QA APK is too small" }
            val archive = requireNotNull(getArchive(context, partial)) { "Invalid QA APK" }
            val code = if (Build.VERSION.SDK_INT >= 28) archive.longVersionCode else archive.versionCode.toLong()
            val name = requireNotNull(archive.versionName) { "QA APK version name missing" }
            require(name.endsWith("-community-qa")) { "Only signed QA-to-QA upgrades are allowed" }
            val digest = MessageDigest.getInstance("SHA-256")
            partial.inputStream().use { stream ->
                val buf = ByteArray(65536)
                while (true) {
                    val n = stream.read(buf)
                    if (n < 0) break
                    digest.update(buf, 0, n)
                }
            }
            val sha = digest.digest().joinToString("") { "%02x".format(it) }
            val identity = AvailableUpdate(
                code, name, "qa-local", "Explicit local QA candidate", sha,
                URL("https://github.com/$REPO"), total
            )
            verifyApkIdentity(context, partial, identity)
            val verified = File(dir, "qa-verified-$code.apk")
            if (verified.exists() && !verified.delete()) throw IOException("Cannot replace cached QA APK")
            if (!partial.renameTo(verified)) throw IOException("Cannot finalize signed QA APK")
            return verified
        } finally {
            partial.delete()
        }
    }

    fun installWithAndroid(context: Context, verifiedApk: File) {
        val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", verifiedApk)
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, "application/vnd.android.package-archive")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        context.startActivity(intent)
    }

    private fun readHttps(url: URL, maxBytes: Int): ByteArray {
        val conn = openHttps(url)
        try {
            conn.inputStream.use { input ->
                val output = java.io.ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                while (true) {
                    val n = input.read(buffer)
                    if (n < 0) break
                    require(output.size() + n <= maxBytes) { "Oversized metadata" }
                    output.write(buffer, 0, n)
                }
                return output.toByteArray()
            }
        } finally {
            conn.disconnect()
        }
    }

    /** Check each redirect *before* connecting; never trust only the final landing URL. */
    internal fun validateDownloadHop(url: URL) {
        require(url.protocol == "https" && (url.port == -1 || url.port == 443) &&
            url.userInfo == null && url.ref == null &&
            url.host.lowercase() in setOf(
                "api.github.com", "github.com", "release-assets.githubusercontent.com",
                "objects.githubusercontent.com"
            )) { "Untrusted update redirect" }
    }

    private fun openHttps(url: URL): HttpURLConnection {
        var next = url
        // GitHub release assets normally use one CDN hop. Bound the chain in case
        // an API response or release redirect is malformed or compromised.
        repeat(5) {
            validateDownloadHop(next)
            val conn = next.openConnection() as HttpURLConnection
            conn.connectTimeout = 12000
            conn.readTimeout = 30000
            conn.setRequestProperty("User-Agent", "KDEConnect-Community-Updater")
            conn.setRequestProperty("Accept", "application/vnd.github+json")
            conn.instanceFollowRedirects = false
            val status = try { conn.responseCode } catch (e: Exception) {
                conn.disconnect()
                throw e
            }
            if (status in listOf(301, 302, 303, 307, 308)) {
                val location = conn.getHeaderField("Location")
                conn.disconnect()
                require(!location.isNullOrBlank()) { "Missing update redirect Location" }
                val resolved = URL(next, location)
                validateDownloadHop(resolved) // BEFORE any network connection to this hop
                next = resolved
            } else {
                if (status != 200) {
                    conn.disconnect()
                    throw IOException("Release HTTP $status")
                }
                return conn
            }
        }
        throw IOException("Update redirect limit exceeded")
    }
}

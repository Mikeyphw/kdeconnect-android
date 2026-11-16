/*
 * SPDX-FileCopyrightText: 2026 KDE Connect community fork contributors
 * SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only
 */
package org.kde.kdeconnect.updates

import android.content.Context
import android.content.IntentSender
import android.content.pm.PackageInstaller
import androidx.annotation.Keep
import org.kde.kdeconnect_tp.BuildConfig
import java.io.OutputStream
import kotlin.system.exitProcess

/** Shizuku UserService. It runs as shell/root, not as an ordinary Android Service. */
@Keep
class PrivilegedInstallerService @Keep constructor(private val context: Context) : IPrivilegedInstaller.Stub() {
    // UserService v13 supplies an application Context, but not every Context API works.
    // PackageInstaller APIs are invoked with the UserService's caller UID (shell/root).
    private var installer: PackageInstaller? = null
    private var session: PackageInstaller.Session? = null
    private var stream: OutputStream? = null
    private var sessionId: Int = -1
    private var expected = 0L
    private var written = 0L

    @Synchronized
    override fun begin(packageName: String, size: Long) {
        require(session == null) { "Installation already running" }
        require(packageName == BuildConfig.APPLICATION_ID) { "Package mismatch" }
        require(size in 1024..(250L * 1024 * 1024)) { "Bad size" }
        val pi = context.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
            setAppPackageName(packageName)
            setSize(size)
        }
        val id = pi.createSession(params)
        try {
            val s = pi.openSession(id)
            val out = s.openWrite("base.apk", 0, size)
            installer = pi
            sessionId = id
            session = s
            stream = out
            expected = size
            written = 0
        } catch (e: Exception) {
            pi.abandonSession(id)
            throw e
        }
    }

    @Synchronized
    override fun chunk(bytes: ByteArray) {
        require(bytes.size in 1..65536) { "Bad chunk" }
        require(session != null && stream != null && written + bytes.size <= expected) { "Bad session state" }
        stream!!.write(bytes)
        written += bytes.size
    }

    @Synchronized
    override fun commit(receiver: IntentSender) {
        require(session != null && stream != null && written == expected) { "Incomplete APK" }
        val s = session!!
        val out = stream!!
        s.fsync(out)
        out.close()
        stream = null
        s.commit(receiver)
        s.close()
        session = null
        sessionId = -1
    }

    @Synchronized
    override fun abort() {
        try { stream?.close() } catch (_: Exception) { }
        try { session?.close() } catch (_: Exception) { }
        if (sessionId != -1) {
            try { installer?.abandonSession(sessionId) } catch (_: Exception) { }
        }
        stream = null
        session = null
        sessionId = -1
    }

    override fun destroy() {
        abort()
        exitProcess(0)
    }
}

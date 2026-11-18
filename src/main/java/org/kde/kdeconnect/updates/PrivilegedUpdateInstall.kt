/*
 * SPDX-FileCopyrightText: 2026 KDE Connect community fork contributors
 * SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only
 */
package org.kde.kdeconnect.updates

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.os.Build
import android.os.IBinder
import android.util.Log
import android.widget.Toast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import rikka.shizuku.Shizuku
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

object PrivilegedUpdateInstall {
    private const val REQUEST = 61017
    private const val TAG = "KDE/PrivilegedUpdate"

    fun isShizukuAuthorized(): Boolean = try {
        Shizuku.pingBinder() && Shizuku.getVersion() >= 13 &&
            Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED
    } catch (_: Exception) { false }

    fun requestShizukuPermission(): Boolean {
        if (isShizukuAuthorized()) return true
        if (!Shizuku.pingBinder()) return false
        Shizuku.requestPermission(REQUEST)
        return false
    }

    private fun installerStatusSender(context: Context): android.content.IntentSender {
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or
            (if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) PendingIntent.FLAG_MUTABLE else 0)
        val intent = Intent(context, InstallResultReceiver::class.java)
        return PendingIntent.getBroadcast(context, REQUEST, intent, flags).intentSender
    }

    suspend fun installViaShizuku(context: Context, apk: File) {
        require(isShizukuAuthorized()) { "Shizuku not running or not authorized" }
        require(apk.isFile && apk.length() in 1024..(250L * 1024 * 1024)) { "Invalid verified APK" }
        val args = Shizuku.UserServiceArgs(
            ComponentName(context.packageName, PrivilegedInstallerService::class.java.name)
        ).processNameSuffix("kde_updater").daemon(false).version(1).tag("kde-update-install")
        val connection = withTimeout(15000) { suspendCancellableCoroutine<Pair<ServiceConnection, IPrivilegedInstaller>> { cont ->
            val delivered = AtomicBoolean(false)
            val listener = object : ServiceConnection {
                override fun onServiceConnected(name: ComponentName, binder: IBinder) {
                    if (delivered.compareAndSet(false, true) && cont.isActive) {
                        cont.resume(this to IPrivilegedInstaller.Stub.asInterface(binder))
                    }
                }
                override fun onServiceDisconnected(name: ComponentName) {
                    if (delivered.compareAndSet(false, true) && cont.isActive) {
                        cont.resumeWithException(IllegalStateException("Shizuku UserService disconnected"))
                    }
                }
            }
            cont.invokeOnCancellation {
                try { Shizuku.unbindUserService(args, listener, true) } catch (_: Exception) { }
            }
            try { Shizuku.bindUserService(args, listener) }
            catch (e: Exception) { if (delivered.compareAndSet(false,true) && cont.isActive) cont.resumeWithException(e) }
        } }
        val (listener, remote) = connection
        try {
            withContext(Dispatchers.IO) {
                remote.begin(context.packageName, apk.length())
                try {
                    apk.inputStream().use { file ->
                        val buffer = ByteArray(65536)
                        while (true) {
                            val n = file.read(buffer)
                            if (n < 0) break
                            remote.chunk(if (n == buffer.size) buffer else buffer.copyOf(n))
                        }
                    }
                    remote.commit(installerStatusSender(context))
                } catch (e: Exception) {
                    try { remote.abort() } catch (_: Exception) { }
                    throw e
                }
            }
        } finally {
            try { Shizuku.unbindUserService(args, listener, true) } catch (e: Exception) {
                Log.w(TAG, "Failed to unbind user service", e)
            }
        }
    }

    /** Explicit root mode only; no silent automatic root privilege requests. */
    suspend fun installViaRoot(apk: File, onProgress: ((Long, Long) -> Unit)? = null) = withContext(Dispatchers.IO) {
        require(apk.isFile && apk.length() in 1024..(250L * 1024 * 1024))
        val proc = ProcessBuilder("su", "-c", "pm install -r -S ${apk.length()} -")
            .redirectErrorStream(true).start()
        try {
            proc.outputStream.use { dest ->
                apk.inputStream().use { source ->
                    val buffer = ByteArray(65536)
                    var written = 0L
                    var prevPercent = -1
                    while (true) {
                        val n = source.read(buffer)
                        if (n < 0) break
                        dest.write(buffer, 0, n)
                        written += n
                        val pct = (written * 100L / apk.length()).toInt()
                        if (pct != prevPercent) {
                            prevPercent = pct
                            onProgress?.invoke(written, apk.length())
                        }
                    }
                }
            }
            val result = proc.inputStream.bufferedReader().use { it.readText().trim() }
            val code = proc.waitFor()
            require(code == 0 && result.lines().any { it.trim() == "Success" }) {
                "Root installer failed (status $code): ${result.take(400)}"
            }
        } finally {
            // API 24-25 lack Process.isAlive()/destroyForcibly().
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                if (proc.isAlive) proc.destroyForcibly()
            } else {
                proc.destroy()
            }
        }
    }
}

/** Result is reported asynchronously by PackageInstaller, including user-confirmation requirements. */
class InstallResultReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
        if (status == PackageInstaller.STATUS_PENDING_USER_ACTION) {
            @Suppress("DEPRECATION")
            val confirm = if (Build.VERSION.SDK_INT >= 33) {
                intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
            } else {
                intent.getParcelableExtra(Intent.EXTRA_INTENT)
            }
            if (confirm != null) {
                // Android owns the confirmation; never impersonate system installation UI.
                confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                try { context.startActivity(confirm) } catch (e: Exception) {
                    Log.e("KDE/UpdateInstall", "Unable to launch confirmation", e)
                }
            }
            return
        }
        val msg = if (status == PackageInstaller.STATUS_SUCCESS) "KDE Connect update installed" else
            "KDE Connect update failed: " + intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE).orEmpty()
        Log.i("KDE/UpdateInstall", msg)
        Toast.makeText(context, msg, Toast.LENGTH_LONG).show()
    }
}

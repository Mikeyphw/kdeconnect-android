/*
 * SPDX-FileCopyrightText: 2026 KDE Connect community fork contributors
 * SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only
 */
package org.kde.kdeconnect.updates

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.content.getSystemService
import androidx.preference.PreferenceManager
import androidx.core.content.edit
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.kde.kdeconnect_tp.R

/** On-open only; an explicit Quit never schedules or wakes the network service. */
object AutomaticUpdateCheck {
    private const val LAST = "community_updates_last_check"
    private const val NOTIFICATION_ID = 37011
    private const val CHANNEL = "community_updates"
    fun onOpened(context: Context) {
        val prefs = PreferenceManager.getDefaultSharedPreferences(context)
        if (!prefs.getBoolean(UpdaterActivity.KEY_AUTO_CHECK, true)) return
        val now = System.currentTimeMillis()
        val last = prefs.getLong(LAST, 0)
        if (last in 1..now && now - last < 24L * 60 * 60 * 1000) return
        prefs.edit { putLong(LAST, now) }
        val app = context.applicationContext
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val release = ReleaseUpdater.checkLatest() ?: return@launch
                val manager = app.getSystemService<NotificationManager>() ?: return@launch
                if (Build.VERSION.SDK_INT >= 26) {
                    manager.createNotificationChannel(NotificationChannel(CHANNEL, "KDE Connect updates", NotificationManager.IMPORTANCE_DEFAULT))
                }
                val intent = Intent(app, UpdaterActivity::class.java)
                val pending = PendingIntent.getActivity(app, NOTIFICATION_ID, intent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
                val notification = NotificationCompat.Builder(app, CHANNEL)
                    .setSmallIcon(R.drawable.ic_notification)
                    .setContentTitle("KDE Connect update available")
                    .setContentText(release.versionName)
                    .setContentIntent(pending)
                    .setAutoCancel(true)
                    .build()
                // Notification permission may be absent on Android 13+. An update check never asks for it.
                manager.notify(NOTIFICATION_ID, notification)
            } catch (_: Exception) {
                // A failed check is not an update, and never starts the background service.
            }
        }
    }
}

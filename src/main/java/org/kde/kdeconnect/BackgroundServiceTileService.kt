/*
 * SPDX-FileCopyrightText: 2026 Rohit Ghosh <jendermine@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only OR LicenseRef-KDE-Accepted-GPL
 */

package org.kde.kdeconnect

import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.core.service.quicksettings.PendingIntentActivityWrapper
import androidx.core.service.quicksettings.TileServiceCompat
import org.kde.kdeconnect.ui.MainActivity

@RequiresApi(Build.VERSION_CODES.N)
class BackgroundServiceTileService : TileService() {
    override fun onStartListening() {
        super.onStartListening()
        updateTile()
    }

    override fun onClick() {
        super.onClick()
        if (BackgroundService.isStoppedByUser(this)) {
            try {
                BackgroundService.Start(this)
            } catch (e: IllegalStateException) { // To catch ForegroundServiceStartNotAllowedException
                Log.w(TAG, "Couldn't start the foreground service, opening the app instead", e)
                TileServiceCompat.startActivityAndCollapse(this, PendingIntentActivityWrapper(
                    this, 0, Intent(this, MainActivity::class.java).apply {
                        flags = Intent.FLAG_ACTIVITY_NEW_TASK
                    }, PendingIntent.FLAG_ONE_SHOT, true
                ))
            }
        } else {
            BackgroundService.Stop(this)
        }
        updateTile()
    }

    private fun updateTile() {
        qsTile?.let { tile ->
            tile.state = if (BackgroundService.isStoppedByUser(this)) Tile.STATE_INACTIVE else Tile.STATE_ACTIVE
            tile.updateTile()
        }
    }

    companion object {
        private const val TAG = "KDE/ServiceTileService"
    }
}

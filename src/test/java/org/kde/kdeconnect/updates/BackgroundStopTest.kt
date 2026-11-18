/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
package org.kde.kdeconnect.updates

import androidx.preference.PreferenceManager
import org.junit.After
import android.content.Intent
import android.net.ConnectivityManager
import android.net.wifi.WifiManager
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.kde.kdeconnect.BackgroundService
import org.kde.kdeconnect.KdeConnectBroadcastReceiver
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class BackgroundStopTest {
    @After fun clean() {
        PreferenceManager.getDefaultSharedPreferences(RuntimeEnvironment.getApplication())
            .edit().remove("backgroundServiceStoppedByUser").commit()
    }

    @Test fun explicitStopPersistsEvenIfBackgroundServiceNotRunning() {
        val app = RuntimeEnvironment.getApplication()
        BackgroundService.Stop(app)
        assertTrue(BackgroundService.isStoppedByUser(app))
    }

    @Test fun automaticStartDoesNotClearStoppedState() {
        val app = RuntimeEnvironment.getApplication()
        BackgroundService.Stop(app)
        BackgroundService.StartAutomatically(app)
        BackgroundService.RefreshAutomatically(app)
        assertTrue(BackgroundService.isStoppedByUser(app))
    }
    @Test fun systemBroadcastsDoNotClearStoppedState() {
        val app = RuntimeEnvironment.getApplication()
        BackgroundService.Stop(app)
        val receiver = KdeConnectBroadcastReceiver()
        for (action in listOf(Intent.ACTION_BOOT_COMPLETED, Intent.ACTION_MY_PACKAGE_REPLACED,
                Intent.ACTION_SCREEN_ON, WifiManager.WIFI_STATE_CHANGED_ACTION,
                ConnectivityManager.CONNECTIVITY_ACTION)) {
            receiver.onReceive(app, Intent(action))
            assertTrue("Stopped flag changed by broadcast: $action", BackgroundService.isStoppedByUser(app))
        }
    }

}

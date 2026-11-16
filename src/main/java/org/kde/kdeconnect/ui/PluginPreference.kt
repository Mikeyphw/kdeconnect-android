/*
 * SPDX-FileCopyrightText: 2023 Albert Vaca Cintora <albertvaka@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only OR LicenseRef-KDE-Accepted-GPL
 */
package org.kde.kdeconnect.ui

import android.content.Context
import android.util.TypedValue
import android.view.View
import androidx.annotation.MainThread
import androidx.annotation.WorkerThread
import androidx.preference.PreferenceViewHolder
import androidx.preference.SwitchPreference
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.kde.kdeconnect.Device
import org.kde.kdeconnect.plugins.Plugin
import org.kde.kdeconnect.plugins.PluginFactory.getPluginInfo
import org.kde.kdeconnect_tp.R

class PluginPreference : SwitchPreference {
    private val device: Device
    private val pluginKey: String
    private val listener: View.OnClickListener?

    constructor(context: Context, pluginKey: String, device: Device, callback: PluginPreferenceCallback) : super(context) {
        layoutResource = R.layout.preference_with_button
        this.device = device
        this.pluginKey = pluginKey

        val info = getPluginInfo(pluginKey)
        title = info.displayName
        summary = info.description
        isChecked = device.isPluginEnabled(pluginKey)

        fun createClickListener() = View.OnClickListener {
            val plugin = device.getPluginIncludingWithoutPermissions(pluginKey)
            if (plugin != null) {
                callback.onStartPluginSettingsFragment(plugin)
            }
            else { // Could happen if the device is not connected anymore
                callback.onFinish()
            }
        }
        this.listener = if (info.hasSettings) createClickListener() else null
    }

    /** Read/modify/write the preference on the same worker dispatcher. */
    private suspend fun togglePluginOnIo(): Boolean = withContext(Dispatchers.IO) {
        togglePluginOnWorker()
    }

    @WorkerThread
    private fun togglePluginOnWorker(): Boolean {
        val newState = !device.isPluginEnabled(pluginKey)
        device.setPluginEnabled(pluginKey, newState)
        return newState
    }

    /** Android view properties must only be inspected and updated on Main. */
    @MainThread
    private fun updateBoundToggle(holder: PreferenceViewHolder, itemView: View, newState: Boolean) {
        if (itemView.isAttachedToWindow) {
            isChecked = newState
            onStateChanged(holder, newState)
        }
    }

    override fun onBindViewHolder(holder: PreferenceViewHolder) {
        super.onBindViewHolder(holder)

        val toggleListener = View.OnClickListener {
            // SharedPreferences can touch disk. Do not read it on the UI thread.
            val itemView = holder.itemView
            itemView.isEnabled = false
            CoroutineScope(Dispatchers.Main.immediate).launch {
                try {
                    // Keep the disk-backed setting transaction separate from UI work.
                    val newState = togglePluginOnIo()
                    withContext(Dispatchers.Main.immediate) {
                        updateBoundToggle(holder, itemView, newState)
                    }
                } finally {
                    withContext(kotlinx.coroutines.NonCancellable + Dispatchers.Main.immediate) {
                        itemView.isEnabled = true
                    }
                }
            }
        }

        val content = holder.findViewById(R.id.content)
        val widget = holder.findViewById(android.R.id.widget_frame)
        val parent = holder.itemView
        content.setOnClickListener(listener)
        widget.setOnClickListener(toggleListener)
        parent.setOnClickListener(toggleListener)

        // Disable child backgrounds when known to be unneeded to prevent duplicate ripples
        fun getSelectableItemBackgroundResource(): Int {
            val value = TypedValue()
            context.theme.resolveAttribute(android.R.attr.selectableItemBackground, value, true)
            return value.resourceId
        }
        val selectableItemBackground: Int = if (listener == null) 0 else getSelectableItemBackgroundResource()
        content.setBackgroundResource(selectableItemBackground)
        widget.setBackgroundResource(selectableItemBackground)

        onStateChanged(holder, isChecked)
    }

    private fun onStateChanged(holder: PreferenceViewHolder, isEnabled: Boolean) {
        val content = holder.findViewById(R.id.content)
        val divider = holder.findViewById(R.id.divider)
        val widget = holder.findViewById(android.R.id.widget_frame)
        val parent = holder.itemView

        val hasDetails = isEnabled && listener != null && device.isReachable && device.isPaired

        divider.visibility = if (hasDetails) View.VISIBLE else View.GONE
        content.isClickable = hasDetails
        widget.isClickable = hasDetails
        parent.isClickable = !hasDetails

        if (hasDetails) {
            // Cancel duplicate ripple caused by pressed state of parent propagating down
            content.isPressed = false
            content.background.jumpToCurrentState()
            widget.isPressed = false
            widget.background.jumpToCurrentState()
        }
    }

    interface PluginPreferenceCallback {
        fun onStartPluginSettingsFragment(plugin: Plugin)
        fun onFinish()
    }
}

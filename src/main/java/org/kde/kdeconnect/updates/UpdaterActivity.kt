/*
 * SPDX-FileCopyrightText: 2026 KDE Connect community fork contributors
 * SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only
 */
package org.kde.kdeconnect.updates

import android.os.Bundle
import java.io.File
import androidx.activity.result.contract.ActivityResultContracts
import android.widget.Button
import android.widget.CheckBox
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.ArrayAdapter
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.edit
import androidx.preference.PreferenceManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.kde.kdeconnect_tp.BuildConfig

/** Update checks and privileged installations are initiated here; never by the network service. */
class UpdaterActivity : AppCompatActivity() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var available: AvailableUpdate? = null
    private lateinit var status: TextView
    private lateinit var installButton: Button
    private lateinit var shizukuButton: Button

    private val preferences by lazy { PreferenceManager.getDefaultSharedPreferences(this) }

    private val signedQaPicker = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null || !BuildConfig.KDE_SIGNED_QA_INSTALL) return@registerForActivityResult
        status.text = "Importing and verifying selected QA APK…"
        scope.launch {
            try {
                val apk = withContext(Dispatchers.IO) {
                    ReleaseUpdater.importSignedQaCandidate(this@UpdaterActivity, uri)
                }
                status.text = "Selected QA APK verified; invoking explicitly selected installer…"
                installSelectedMode(apk)
                status.append("\nInstaller submitted; check system confirmation / result.")
            } catch (e: Exception) {
                status.text = "QA install refused: ${e.message}"
            }
        }
    }

    private suspend fun installSelectedMode(apk: File) {
        when (preferences.getInt(KEY_INSTALLER, 0)) {
            2 -> PrivilegedUpdateInstall.installViaShizuku(this, apk)
            3 -> PrivilegedUpdateInstall.installViaRoot(apk) { count, length ->
                runOnUiThread { status.text = "Streaming QA APK to root: ${count * 100L / length}%" }
            }
            0 -> if (PrivilegedUpdateInstall.isShizukuAuthorized()) {
                PrivilegedUpdateInstall.installViaShizuku(this, apk)
            } else ReleaseUpdater.installWithAndroid(this, apk)
            else -> ReleaseUpdater.installWithAndroid(this, apk)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        title = "KDE Connect updates"
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 32, 32, 32)
        }
        fun label(value: String) = TextView(this).apply { text = value; textSize = 16f }
        val scroll = ScrollView(this).apply { addView(root) }
        setContentView(scroll)
        root.addView(label("Installed: ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})"))
        status = label("Updates are checked against GitHub Releases. Installation requires the same package and signing certificate as this app.")
        root.addView(status)
        val auto = CheckBox(this).apply {
            text = "Check for updates when opening KDE Connect (once per day)"
            isChecked = preferences.getBoolean(KEY_AUTO_CHECK, true)
            setOnCheckedChangeListener { _, checked -> preferences.edit { putBoolean(KEY_AUTO_CHECK, checked) } }
        }
        root.addView(auto)
        val modes = listOf("Auto (authorized Shizuku; otherwise Android)", "Android installer", "Shizuku / Sui", "Root")
        val spinner = Spinner(this).apply {
            adapter = ArrayAdapter(this@UpdaterActivity, android.R.layout.simple_spinner_dropdown_item, modes)
            setSelection(preferences.getInt(KEY_INSTALLER, 0).coerceIn(0, 3))
            onItemSelectedListener = object : android.widget.AdapterView.OnItemSelectedListener {
                override fun onNothingSelected(parent: android.widget.AdapterView<*>?) = Unit
                override fun onItemSelected(parent: android.widget.AdapterView<*>?, view: android.view.View?, position: Int, id: Long) {
                    preferences.edit { putInt(KEY_INSTALLER, position) }
                }
            }
        }
        root.addView(label("Installation mode"))
        root.addView(spinner)
        shizukuButton = Button(this).apply {
            text = "Authorize Shizuku / Sui"
            setOnClickListener {
                if (PrivilegedUpdateInstall.isShizukuAuthorized()) {
                    status.text = "Shizuku already authorized."
                } else {
                    val requested = try { PrivilegedUpdateInstall.requestShizukuPermission() }
                        catch (e: Exception) { status.text = "Shizuku unavailable: ${e.message}"; false }
                    if (requested) status.text = "Shizuku authorized."
                    else status.append("\nAuthorize in Shizuku if it is running; otherwise select Android installer.")
                }
            }
        }
        root.addView(shizukuButton)
        root.addView(Button(this).apply {
            text = "Check for updates"
            setOnClickListener {
                status.text = "Checking stable releases…"
                scope.launch {
                    try {
                        available = withContext(Dispatchers.IO) { ReleaseUpdater.checkLatest() }
                        val update = available
                        status.text = if (update == null) "Up to date." else
                            "Available ${update.versionName} (${update.versionCode})\n${update.notes.take(1200)}"
                        installButton.isEnabled = update != null
                    } catch (e: Exception) {
                        status.text = "Update check failed: ${e.message}"
                        available = null
                        installButton.isEnabled = false
                    }
                }
            }
        })
        installButton = Button(this).apply {
            text = "Download, verify and install"
            isEnabled = false
            setOnClickListener {
                val release = available ?: return@setOnClickListener
                isEnabled = false
                status.text = "Downloading and verifying APK…"
                scope.launch {
                    try {
                        val apk = withContext(Dispatchers.IO) {
                            ReleaseUpdater.downloadVerified(this@UpdaterActivity, release) { count, length ->
                                val pct = (count * 100 / length).toInt()
                                runOnUiThread { status.text = "Downloading APK: $pct% ($count / $length bytes)" }
                            }
                        }
                        status.text = "APK verified: SHA-256, package, version and installed signing certificate."
                        installSelectedMode(apk)
                        status.append("\nInstaller started; check system confirmation or result.")
                    } catch (e: Exception) {
                        status.text = "Install failed or refused: ${e.message}"
                        // Failure never triggers a silent privileged-to-unprivileged retry.
                    } finally {
                        installButton.isEnabled = available != null
                    }
                }
            }
        }
        root.addView(installButton)
        if (BuildConfig.KDE_SIGNED_QA_INSTALL) {
            root.addView(Button(this).apply {
                text = "QA ONLY · Install local same-signer test APK"
                setOnClickListener {
                    // Explicit user action; picker grants read access for one candidate.
                    signedQaPicker.launch(arrayOf("application/vnd.android.package-archive", "application/octet-stream"))
                }
            })
        }
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    companion object {
        const val KEY_AUTO_CHECK = "community_updates_check_on_open"
        const val KEY_INSTALLER = "community_updates_installer_mode"
    }
}

package com.notcvnt.rknhardering

import android.content.SharedPreferences
import android.os.Bundle
import android.view.View
import androidx.core.content.edit
import androidx.fragment.app.Fragment
import com.google.android.material.materialswitch.MaterialSwitch

internal class SettingsDebugFragment : Fragment(R.layout.fragment_settings_debug) {

    private lateinit var prefs: SharedPreferences
    private lateinit var switchTunProbeDebug: MaterialSwitch

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        prefs = AppUiSettings.prefs(requireContext())
        switchTunProbeDebug = view.findViewById(R.id.switchTunProbeDebug)
        switchTunProbeDebug.isChecked = prefs.getBoolean(SettingsPrefs.PREF_TUN_PROBE_DEBUG_ENABLED, false)
        switchTunProbeDebug.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit { putBoolean(SettingsPrefs.PREF_TUN_PROBE_DEBUG_ENABLED, isChecked) }
        }
    }
}

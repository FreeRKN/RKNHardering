package com.notcvnt.rknhardering

import android.os.Bundle
import android.view.View
import android.widget.ImageView
import android.widget.TextView
import androidx.annotation.DrawableRes
import androidx.annotation.StringRes
import androidx.fragment.app.Fragment

internal class SettingsCategoriesFragment : Fragment(R.layout.fragment_settings_categories) {

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        val activity = requireActivity() as SettingsActivity

        bindRow(
            view, R.id.rowSplitTunnel,
            iconRes = R.drawable.ic_split,
            titleRes = R.string.settings_cat_split_tunnel,
            valueRes = R.string.settings_cat_split_tunnel_desc,
        ) { activity.navigateTo(SettingsSplitTunnelFragment(), R.string.settings_cat_split_tunnel) }

        bindRow(
            view, R.id.rowNetwork,
            iconRes = R.drawable.ic_network,
            titleRes = R.string.settings_cat_network,
            valueRes = R.string.settings_cat_network_desc,
        ) { activity.navigateTo(SettingsNetworkFragment(), R.string.settings_cat_network) }

        bindRow(
            view, R.id.rowDns,
            iconRes = R.drawable.ic_globe,
            titleRes = R.string.settings_cat_dns,
            valueRes = R.string.settings_cat_dns_desc,
        ) { activity.navigateTo(SettingsDnsFragment(), R.string.settings_cat_dns) }

        bindRow(
            view, R.id.rowPrivacy,
            iconRes = R.drawable.ic_lock,
            titleRes = R.string.settings_cat_privacy,
            valueRes = R.string.settings_cat_privacy_desc,
        ) { activity.navigateTo(SettingsPrivacyFragment(), R.string.settings_cat_privacy) }

        bindRow(
            view, R.id.rowAppearance,
            iconRes = R.drawable.ic_settings,
            titleRes = R.string.settings_cat_appearance,
            valueRes = R.string.settings_cat_appearance_desc,
        ) { activity.navigateTo(SettingsAppearanceFragment(), R.string.settings_cat_appearance) }

        bindRow(
            view, R.id.rowDebug,
            iconRes = R.drawable.ic_shield,
            titleRes = R.string.settings_cat_debug,
            valueRes = R.string.settings_cat_debug_desc,
        ) { activity.navigateTo(SettingsDebugFragment(), R.string.settings_cat_debug) }

        bindRow(
            view, R.id.rowAbout,
            iconRes = R.drawable.ic_help,
            titleRes = R.string.settings_cat_about,
            valueRes = R.string.settings_cat_about_desc,
        ) { activity.navigateTo(SettingsAboutFragment(), R.string.settings_cat_about) }
    }

    private fun bindRow(
        root: View,
        rowId: Int,
        @DrawableRes iconRes: Int,
        @StringRes titleRes: Int,
        @StringRes valueRes: Int,
        onClick: () -> Unit,
    ) {
        val row = root.findViewById<View>(rowId)
        row.findViewById<ImageView>(R.id.rowIcon).setImageResource(iconRes)
        row.findViewById<TextView>(R.id.rowTitle).setText(titleRes)
        row.findViewById<TextView>(R.id.rowValue).setText(valueRes)
        row.setOnClickListener { onClick() }
    }
}

package com.notcvnt.rknhardering

import android.content.Context
import com.notcvnt.rknhardering.checker.CheckSettings
import com.notcvnt.rknhardering.network.DnsResolverMode
import com.notcvnt.rknhardering.probe.PublicIpProbeMode
import com.notcvnt.rknhardering.probe.PublicIpProbeStatus
import com.notcvnt.rknhardering.probe.TunEndpointAttempt
import com.notcvnt.rknhardering.probe.TunProbeAttemptDiagnostics
import com.notcvnt.rknhardering.probe.TunProbeDiagnostics
import com.notcvnt.rknhardering.probe.TunProbeModeOverride
import com.notcvnt.rknhardering.probe.TunProbePathDiagnostics
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object TunProbeDiagnosticsFormatter {

    fun format(
        diagnostics: TunProbeDiagnostics,
        settings: CheckSettings,
        timestampMillis: Long = System.currentTimeMillis(),
        appVersionName: String = BuildConfig.VERSION_NAME,
        buildType: String = BuildConfig.BUILD_TYPE,
    ): String {
        val builder = StringBuilder()
        builder.appendLine("timestamp: ${formatTimestamp(timestampMillis)}")
        builder.appendLine("app: $appVersionName ($buildType)")
        builder.append(formatSection(diagnostics, settings))
        return builder.toString().trimEnd()
    }

    fun formatSection(
        diagnostics: TunProbeDiagnostics,
        settings: CheckSettings,
    ): String {
        val builder = StringBuilder()
        builder.appendLine("debugDiagnosticsEnabled: ${diagnostics.enabled}")
        builder.appendLine("tunProbeModeOverride: ${diagnostics.modeOverride.name}")
        builder.appendLine("resolver: ${describeResolver(settings)}")
        builder.appendLine("activeNetworkIsVpn: ${diagnostics.activeNetworkIsVpn}")
        builder.appendLine("vpnNetworkPresent: ${diagnostics.vpnNetworkPresent}")
        builder.appendLine("underlyingNetworkPresent: ${diagnostics.underlyingNetworkPresent}")
        appendPath(builder, "vpn path", diagnostics.vpnPath)
        appendPath(builder, "underlying path", diagnostics.underlyingPath)
        return builder.toString().trimEnd()
    }

    fun formatUiSummary(
        context: Context,
        pathLabel: String,
        modeOverride: TunProbeModeOverride,
        path: TunProbePathDiagnostics,
    ): String {
        return context.getString(
            R.string.checker_tun_probe_debug_summary,
            pathLabel,
            effectiveModeLabel(context, modeOverride, path),
            selectedModeLabel(context, path.selectedMode),
            statusLabel(context, path.strict.status),
            statusLabel(context, path.curlCompatible.status),
            path.dnsPathMismatch.toString(),
        )
    }

    fun effectiveModeLabel(
        context: Context,
        modeOverride: TunProbeModeOverride,
        path: TunProbePathDiagnostics,
    ): String {
        return when (modeOverride) {
            TunProbeModeOverride.AUTO -> selectedModeLabel(context, path.selectedMode)
            TunProbeModeOverride.STRICT_SAME_PATH -> context.getString(R.string.settings_tun_probe_mode_strict)
            TunProbeModeOverride.CURL_COMPATIBLE -> context.getString(R.string.settings_tun_probe_mode_curl)
        }
    }

    fun selectedModeLabel(context: Context, mode: PublicIpProbeMode?): String {
        return when (mode) {
            PublicIpProbeMode.STRICT_SAME_PATH -> context.getString(R.string.settings_tun_probe_mode_strict)
            PublicIpProbeMode.CURL_COMPATIBLE -> context.getString(R.string.settings_tun_probe_mode_curl)
            null -> context.getString(R.string.checker_tun_probe_mode_none)
        }
    }

    fun statusLabel(context: Context, status: PublicIpProbeStatus): String {
        return when (status) {
            PublicIpProbeStatus.SUCCEEDED -> context.getString(R.string.checker_tun_probe_status_succeeded)
            PublicIpProbeStatus.FAILED -> context.getString(R.string.checker_tun_probe_status_failed)
            PublicIpProbeStatus.SKIPPED -> context.getString(R.string.checker_tun_probe_status_skipped)
        }
    }

    private fun appendPath(
        builder: StringBuilder,
        label: String,
        path: TunProbePathDiagnostics?,
    ) {
        builder.appendLine()
        builder.appendLine("[$label]")
        if (path == null) {
            builder.appendLine("available: false")
            return
        }

        builder.appendLine("available: true")
        builder.appendLine("interfaceName: ${path.interfaceName ?: "<missing>"}")
        builder.appendLine("selectedMode: ${path.selectedMode?.name ?: "NONE"}")
        builder.appendLine("selectedIp: ${path.selectedIp?.let(::maskIp) ?: "<none>"}")
        builder.appendLine("selectedError: ${path.selectedError?.let(::maskIpsInText) ?: "<none>"}")
        builder.appendLine("dnsPathMismatch: ${path.dnsPathMismatch}")
        appendAttempt(builder, "strict", path.strict)
        appendAttempt(builder, "curl-compatible", path.curlCompatible)
    }

    private fun appendAttempt(
        builder: StringBuilder,
        label: String,
        attempt: TunProbeAttemptDiagnostics,
    ) {
        builder.appendLine("$label.status: ${attempt.status}")
        builder.appendLine("$label.ip: ${attempt.ip?.let(::maskIp) ?: "<none>"}")
        builder.appendLine("$label.error: ${attempt.error?.let(::maskIpsInText) ?: "<none>"}")
        builder.appendLine("$label.endpoints:")
        if (attempt.endpointAttempts.isEmpty()) {
            builder.appendLine("- <none>")
            return
        }

        attempt.endpointAttempts.forEach { endpointAttempt ->
            builder.appendLine("- ${formatEndpointAttempt(endpointAttempt)}")
        }
    }

    private fun formatEndpointAttempt(attempt: TunEndpointAttempt): String {
        val result = when (attempt.status) {
            PublicIpProbeStatus.SUCCEEDED -> "ip=${attempt.ip?.let(::maskIp) ?: "<none>"}"
            PublicIpProbeStatus.FAILED,
            PublicIpProbeStatus.SKIPPED -> "error=${attempt.error?.let(::maskIpsInText) ?: "<none>"}"
        }
        return "${attempt.endpoint} [${attempt.familyHint}] -> ${attempt.status} ($result)"
    }

    private fun describeResolver(settings: CheckSettings): String {
        return when (settings.resolverConfig.mode) {
            DnsResolverMode.SYSTEM -> "SYSTEM"
            DnsResolverMode.DIRECT -> {
                val servers = settings.resolverConfig.effectiveDirectServers()
                    .joinToString(", ") { maskIp(it) }
                    .ifBlank { "<none>" }
                "DIRECT preset=${settings.resolverConfig.preset.name} servers=$servers"
            }
            DnsResolverMode.DOH -> {
                val bootstrap = settings.resolverConfig.effectiveDohBootstrapHosts()
                    .joinToString(", ") { maskIp(it) }
                    .ifBlank { "<none>" }
                "DOH preset=${settings.resolverConfig.preset.name} url=${settings.resolverConfig.effectiveDohUrl() ?: "<none>"} bootstrap=$bootstrap"
            }
        }
    }

    private fun formatTimestamp(timestampMillis: Long): String {
        return SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.US).format(Date(timestampMillis))
    }
}

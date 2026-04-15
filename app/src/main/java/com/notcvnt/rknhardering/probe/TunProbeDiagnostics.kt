package com.notcvnt.rknhardering.probe

enum class TunProbeModeOverride(val prefValue: String) {
    AUTO("auto"),
    STRICT_SAME_PATH("strict_same_path"),
    CURL_COMPATIBLE("curl_compatible");

    companion object {
        fun fromPref(value: String?): TunProbeModeOverride {
            return entries.firstOrNull { it.prefValue == value } ?: AUTO
        }
    }
}

data class TunEndpointAttempt(
    val endpoint: String,
    val familyHint: String,
    val status: PublicIpProbeStatus,
    val ip: String? = null,
    val error: String? = null,
)

data class TunProbeAttemptDiagnostics(
    val mode: PublicIpProbeMode,
    val status: PublicIpProbeStatus,
    val ip: String? = null,
    val error: String? = null,
    val endpointAttempts: List<TunEndpointAttempt> = emptyList(),
)

data class TunProbePathDiagnostics(
    val interfaceName: String? = null,
    val selectedMode: PublicIpProbeMode? = null,
    val selectedIp: String? = null,
    val selectedError: String? = null,
    val dnsPathMismatch: Boolean = false,
    val strict: TunProbeAttemptDiagnostics,
    val curlCompatible: TunProbeAttemptDiagnostics,
)

data class TunProbeDiagnostics(
    val enabled: Boolean,
    val modeOverride: TunProbeModeOverride,
    val activeNetworkIsVpn: Boolean? = null,
    val vpnNetworkPresent: Boolean = false,
    val underlyingNetworkPresent: Boolean = false,
    val vpnPath: TunProbePathDiagnostics? = null,
    val underlyingPath: TunProbePathDiagnostics? = null,
)

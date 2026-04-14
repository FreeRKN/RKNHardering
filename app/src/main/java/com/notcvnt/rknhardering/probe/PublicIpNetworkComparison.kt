package com.notcvnt.rknhardering.probe

import java.io.IOException

enum class PublicIpProbeMode {
    STRICT_SAME_PATH,
    CURL_COMPATIBLE,
}

enum class PublicIpProbeStatus {
    SUCCEEDED,
    FAILED,
    SKIPPED,
}

data class PublicIpModeProbeResult(
    val mode: PublicIpProbeMode,
    val status: PublicIpProbeStatus,
    val ip: String? = null,
    val error: String? = null,
)

data class PublicIpNetworkComparison(
    val strict: PublicIpModeProbeResult,
    val curlCompatible: PublicIpModeProbeResult,
    val selectedMode: PublicIpProbeMode? = null,
    val selectedIp: String? = null,
    val selectedError: String? = null,
    val dnsPathMismatch: Boolean = false,
) {
    fun asResult(): Result<String> {
        return selectedIp?.let(Result.Companion::success)
            ?: Result.failure(IOException(selectedError ?: "Public IP probe failed"))
    }
}

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
    val endpointAttempts: List<TunEndpointAttempt> = emptyList(),
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

    fun usedCurlCompatibleFallback(): Boolean {
        return selectedMode == PublicIpProbeMode.CURL_COMPATIBLE &&
            strict.status == PublicIpProbeStatus.FAILED
    }

    fun toPathDiagnostics(interfaceName: String?): TunProbePathDiagnostics {
        return TunProbePathDiagnostics(
            interfaceName = interfaceName,
            selectedMode = selectedMode,
            selectedIp = selectedIp,
            selectedError = selectedError,
            dnsPathMismatch = dnsPathMismatch,
            strict = TunProbeAttemptDiagnostics(
                mode = strict.mode,
                status = strict.status,
                ip = strict.ip,
                error = strict.error,
                endpointAttempts = strict.endpointAttempts,
            ),
            curlCompatible = TunProbeAttemptDiagnostics(
                mode = curlCompatible.mode,
                status = curlCompatible.status,
                ip = curlCompatible.ip,
                error = curlCompatible.error,
                endpointAttempts = curlCompatible.endpointAttempts,
            ),
        )
    }
}

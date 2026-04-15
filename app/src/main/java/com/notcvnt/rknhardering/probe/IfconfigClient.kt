package com.notcvnt.rknhardering.probe

import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.ResolverBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Proxy

object IfconfigClient {
    private const val CURL_COMPATIBLE_UNAVAILABLE_MESSAGE =
        "OS device bind fallback is unavailable because interfaceName is missing"
    private const val DISABLED_BY_OVERRIDE_MESSAGE = "Disabled by override"

    private val ENDPOINTS = listOf(
        IpEndpointSpec("https://ifconfig.me/ip"),
        IpEndpointSpec("https://checkip.amazonaws.com"),
        IpEndpointSpec("https://ip.mail.ru"),
        IpEndpointSpec("https://api4.ipify.org"),
        IpEndpointSpec("https://api6.ipify.org", IpEndpointFamilyHint.IPV6),
    )

    suspend fun fetchDirectIp(
        timeoutMs: Int = 7000,
        resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
    ): Result<String> = fetchIpWithFallback(
        timeoutMs = timeoutMs,
        resolverConfig = resolverConfig,
    )

    suspend fun fetchIpViaProxy(
        endpoint: ProxyEndpoint,
        timeoutMs: Int = 7000,
        resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
    ): Result<String> = fetchIpWithFallback(
        timeoutMs = timeoutMs,
        resolverConfig = resolverConfig,
        proxy = Proxy(
            when (endpoint.type) {
                ProxyType.SOCKS5 -> Proxy.Type.SOCKS
                ProxyType.HTTP -> Proxy.Type.HTTP
            },
            InetSocketAddress(endpoint.host, endpoint.port),
        ),
    )

    suspend fun fetchIpViaNetwork(
        primaryBinding: ResolverBinding.AndroidNetworkBinding,
        fallbackBinding: ResolverBinding.OsDeviceBinding? = null,
        timeoutMs: Int = 7000,
        resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
        modeOverride: TunProbeModeOverride = TunProbeModeOverride.AUTO,
    ): Result<String> = fetchIpViaNetworkComparison(
        primaryBinding = primaryBinding,
        fallbackBinding = fallbackBinding,
        timeoutMs = timeoutMs,
        resolverConfig = resolverConfig,
        modeOverride = modeOverride,
    ).asResult()

    suspend fun fetchIpViaNetworkComparison(
        primaryBinding: ResolverBinding.AndroidNetworkBinding,
        fallbackBinding: ResolverBinding.OsDeviceBinding? = null,
        timeoutMs: Int = 7000,
        resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
        modeOverride: TunProbeModeOverride = TunProbeModeOverride.AUTO,
        collectTrace: Boolean = false,
    ): PublicIpNetworkComparison = withContext(Dispatchers.IO) {
        val strict = if (modeOverride == TunProbeModeOverride.CURL_COMPATIBLE) {
            PublicIpModeProbeResult(
                mode = PublicIpProbeMode.STRICT_SAME_PATH,
                status = PublicIpProbeStatus.SKIPPED,
                error = DISABLED_BY_OVERRIDE_MESSAGE,
            )
        } else {
            fetchModeProbeResult(
                mode = PublicIpProbeMode.STRICT_SAME_PATH,
                timeoutMs = timeoutMs,
                resolverConfig = resolverConfig,
                binding = primaryBinding,
                collectTrace = collectTrace,
            )
        }
        val curlCompatible = when {
            modeOverride == TunProbeModeOverride.STRICT_SAME_PATH -> PublicIpModeProbeResult(
                mode = PublicIpProbeMode.CURL_COMPATIBLE,
                status = PublicIpProbeStatus.SKIPPED,
                error = DISABLED_BY_OVERRIDE_MESSAGE,
            )
            fallbackBinding != null -> fetchModeProbeResult(
                mode = PublicIpProbeMode.CURL_COMPATIBLE,
                timeoutMs = timeoutMs,
                resolverConfig = resolverConfig,
                binding = fallbackBinding,
                collectTrace = collectTrace,
            )
            else -> PublicIpModeProbeResult(
                mode = PublicIpProbeMode.CURL_COMPATIBLE,
                status = PublicIpProbeStatus.SKIPPED,
                error = CURL_COMPATIBLE_UNAVAILABLE_MESSAGE,
            )
        }

        val selectedMode = when (modeOverride) {
            TunProbeModeOverride.AUTO -> when {
                strict.status == PublicIpProbeStatus.SUCCEEDED -> PublicIpProbeMode.STRICT_SAME_PATH
                strict.status == PublicIpProbeStatus.FAILED &&
                    curlCompatible.status == PublicIpProbeStatus.SUCCEEDED -> PublicIpProbeMode.CURL_COMPATIBLE
                else -> null
            }
            TunProbeModeOverride.STRICT_SAME_PATH ->
                PublicIpProbeMode.STRICT_SAME_PATH.takeIf { strict.status == PublicIpProbeStatus.SUCCEEDED }
            TunProbeModeOverride.CURL_COMPATIBLE ->
                PublicIpProbeMode.CURL_COMPATIBLE.takeIf { curlCompatible.status == PublicIpProbeStatus.SUCCEEDED }
        }
        val selectedIp = when (selectedMode) {
            PublicIpProbeMode.STRICT_SAME_PATH -> strict.ip
            PublicIpProbeMode.CURL_COMPATIBLE -> curlCompatible.ip
            null -> null
        }
        val selectedError = if (selectedIp != null) {
            null
        } else {
            when (modeOverride) {
                TunProbeModeOverride.AUTO -> mergeNetworkProbeFailure(
                    strict = strict,
                    curlCompatible = curlCompatible,
                    fallbackBinding = fallbackBinding,
                )
                TunProbeModeOverride.STRICT_SAME_PATH -> strict.error ?: "Public IP probe failed"
                TunProbeModeOverride.CURL_COMPATIBLE -> curlCompatible.error ?: CURL_COMPATIBLE_UNAVAILABLE_MESSAGE
            }
        }

        PublicIpNetworkComparison(
            strict = strict,
            curlCompatible = curlCompatible,
            selectedMode = selectedMode,
            selectedIp = selectedIp,
            selectedError = selectedError,
            dnsPathMismatch = modeOverride == TunProbeModeOverride.AUTO &&
                strict.status == PublicIpProbeStatus.FAILED &&
                curlCompatible.status == PublicIpProbeStatus.SUCCEEDED,
        )
    }

    private suspend fun fetchIpWithFallback(
        timeoutMs: Int,
        resolverConfig: DnsResolverConfig,
        proxy: Proxy? = null,
        binding: ResolverBinding? = null,
        fallbackBinding: ResolverBinding.OsDeviceBinding? = null,
    ): Result<String> = withContext(Dispatchers.IO) {
        val primaryResult = fetchIpForBinding(
            timeoutMs = timeoutMs,
            resolverConfig = resolverConfig,
            proxy = proxy,
            binding = binding,
        )

        if (primaryResult.isSuccess || fallbackBinding == null) {
            return@withContext primaryResult
        }

        val fallbackResult = fetchIpForBinding(
            timeoutMs = timeoutMs,
            resolverConfig = resolverConfig,
            proxy = proxy,
            binding = fallbackBinding,
        )

        if (fallbackResult.isSuccess) {
            return@withContext fallbackResult
        }

        return@withContext Result.failure(
            composeDualBindingFailure(
                primaryError = primaryResult.exceptionOrNull(),
                fallbackError = fallbackResult.exceptionOrNull(),
                fallbackBinding = fallbackBinding,
            ),
        )
    }

    private fun composeDualBindingFailure(
        primaryError: Throwable?,
        fallbackError: Throwable?,
        fallbackBinding: ResolverBinding.OsDeviceBinding,
    ): IOException {
        val primaryMessage = primaryError.renderMessage()
        val fallbackMessage = fallbackError.renderMessage()
        return IOException(
            "Android Network binding failed: $primaryMessage; " +
                "SO_BINDTODEVICE(${fallbackBinding.interfaceName}) failed: $fallbackMessage",
        )
    }

    private suspend fun fetchIpForBinding(
        timeoutMs: Int,
        resolverConfig: DnsResolverConfig,
        proxy: Proxy? = null,
        binding: ResolverBinding? = null,
        onEndpointResult: ((IpEndpointSpec, Result<String>) -> Unit)? = null,
    ): Result<String> = fetchFirstSuccessfulIp(ENDPOINTS) { endpoint ->
        val result = PublicIpClient.fetchIp(
            endpoint = endpoint.url,
            timeoutMs = timeoutMs,
            proxy = proxy,
            resolverConfig = resolverConfig,
            binding = binding,
        )
        onEndpointResult?.invoke(endpoint, result)
        result
    }

    private suspend fun fetchModeProbeResult(
        mode: PublicIpProbeMode,
        timeoutMs: Int,
        resolverConfig: DnsResolverConfig,
        binding: ResolverBinding,
        collectTrace: Boolean = false,
    ): PublicIpModeProbeResult {
        val endpointAttempts = if (collectTrace) mutableListOf<TunEndpointAttempt>() else null
        val result = fetchIpForBinding(
            timeoutMs = timeoutMs,
            resolverConfig = resolverConfig,
            binding = binding,
            onEndpointResult = endpointAttempts?.let { attempts ->
                { endpoint, endpointResult ->
                    attempts += TunEndpointAttempt(
                        endpoint = endpoint.url,
                        familyHint = endpoint.familyHint.name,
                        status = if (endpointResult.isSuccess) {
                            PublicIpProbeStatus.SUCCEEDED
                        } else {
                            PublicIpProbeStatus.FAILED
                        },
                        ip = endpointResult.getOrNull(),
                        error = endpointResult.exceptionOrNull().renderMessage(),
                    )
                }
            },
        )
        return if (result.isSuccess) {
            PublicIpModeProbeResult(
                mode = mode,
                status = PublicIpProbeStatus.SUCCEEDED,
                ip = result.getOrNull(),
                endpointAttempts = endpointAttempts.orEmpty(),
            )
        } else {
            PublicIpModeProbeResult(
                mode = mode,
                status = PublicIpProbeStatus.FAILED,
                error = result.exceptionOrNull().renderMessage(),
                endpointAttempts = endpointAttempts.orEmpty(),
            )
        }
    }

    private fun mergeNetworkProbeFailure(
        strict: PublicIpModeProbeResult,
        curlCompatible: PublicIpModeProbeResult,
        fallbackBinding: ResolverBinding.OsDeviceBinding?,
    ): String {
        return when (curlCompatible.status) {
            PublicIpProbeStatus.FAILED -> composeDualBindingFailure(
                primaryError = strict.error,
                fallbackError = curlCompatible.error,
                fallbackBinding = fallbackBinding,
            ).message ?: "Public IP probe failed"
            PublicIpProbeStatus.SKIPPED -> {
                val strictMessage = strict.error ?: "unknown error"
                "$strictMessage; ${curlCompatible.error ?: CURL_COMPATIBLE_UNAVAILABLE_MESSAGE}"
            }
            PublicIpProbeStatus.SUCCEEDED -> strict.error ?: "Public IP probe failed"
        }
    }

    private fun composeDualBindingFailure(
        primaryError: String?,
        fallbackError: String?,
        fallbackBinding: ResolverBinding.OsDeviceBinding?,
    ): IOException {
        val interfaceName = fallbackBinding?.interfaceName ?: "unknown"
        return IOException(
            "Android Network binding failed: ${primaryError ?: "unknown error"}; " +
                "SO_BINDTODEVICE($interfaceName) failed: ${fallbackError ?: "unknown error"}",
        )
    }

    private fun Throwable?.renderMessage(): String {
        return this?.message
            ?: this?.javaClass?.simpleName
            ?: "unknown error"
    }
}

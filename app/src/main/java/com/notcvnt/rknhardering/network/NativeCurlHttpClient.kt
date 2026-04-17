package com.notcvnt.rknhardering.network

import com.notcvnt.rknhardering.probe.NativeCurlBridge
import com.notcvnt.rknhardering.probe.NativeCurlProxyType
import com.notcvnt.rknhardering.probe.NativeCurlRequest
import com.notcvnt.rknhardering.probe.NativeCurlResolveRule
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL

internal object NativeCurlHttpClient {

    fun canExecute(request: ResolverHttpRequest): Boolean {
        if (request.binding is ResolverBinding.AndroidNetworkBinding) return false
        val scheme = runCatching { URL(request.url).protocol.lowercase() }.getOrNull()
        if (scheme != "http" && scheme != "https") return false
        return NativeCurlBridge.canExecute()
    }

    fun execute(request: ResolverHttpRequest): ResolverHttpResponse {
        val nativeResponse = NativeCurlBridge.execute(buildRequest(request))
        nativeResponse.localError?.takeIf { it.isNotBlank() }?.let { throw IOException(it) }
        nativeResponse.errorBuffer?.takeIf { it.isNotBlank() }?.let { throw IOException(it) }

        return ResolverHttpResponse(
            code = nativeResponse.httpCode ?: 0,
            body = nativeResponse.body,
        )
    }

    private fun buildRequest(request: ResolverHttpRequest): NativeCurlRequest {
        val url = URL(request.url)
        val defaultPort = when {
            url.port > 0 -> url.port
            url.defaultPort > 0 -> url.defaultPort
            url.protocol.equals("https", ignoreCase = true) -> 443
            else -> 80
        }
        val normalizedHeaders = LinkedHashMap<String, String>().apply {
            putAll(request.headers)
            if (request.body != null && request.bodyContentType != null && keys.none { it.equals("Content-Type", ignoreCase = true) }) {
                put("Content-Type", request.bodyContentType)
            }
        }

        return NativeCurlRequest(
            url = request.url,
            interfaceName = (request.binding as? ResolverBinding.OsDeviceBinding)?.interfaceName.orEmpty(),
            resolveRules = buildResolveRules(request, url.host, defaultPort),
            timeoutMs = request.timeoutMs,
            connectTimeoutMs = request.timeoutMs,
            caBundlePath = NativeCurlBridge.caBundleInfo()?.absolutePath.orEmpty(),
            debugVerbose = false,
            method = request.method.uppercase(),
            headers = normalizedHeaders.map { (name, value) -> "$name: $value" },
            body = request.body,
            followRedirects = true,
            proxyUrl = request.proxy?.toCurlProxyUrl(),
            proxyType = request.proxy.toNativeProxyType(),
        )
    }

    private fun buildResolveRules(
        request: ResolverHttpRequest,
        host: String,
        port: Int,
    ): List<NativeCurlResolveRule> {
        if (request.proxy != null) return emptyList()
        if (request.binding is ResolverBinding.AndroidNetworkBinding) return emptyList()
        if (request.config.mode == DnsResolverMode.SYSTEM) return emptyList()

        val addresses = ResolverNetworkStack.lookup(host, request.config, request.binding)
            .mapNotNull { it.hostAddress }
            .distinct()

        if (addresses.isEmpty()) return emptyList()

        return listOf(
            NativeCurlResolveRule(
                host = host,
                port = port,
                addresses = addresses,
            ),
        )
    }

    private fun Proxy?.toCurlProxyUrl(): String? {
        if (this == null || type() == Proxy.Type.DIRECT) return null
        val address = address() as? InetSocketAddress ?: return null
        val host = address.hostString?.takeIf { it.isNotBlank() } ?: address.address?.hostAddress ?: return null
        return "$host:${address.port}"
    }

    private fun Proxy?.toNativeProxyType(): NativeCurlProxyType {
        return when (this?.type()) {
            Proxy.Type.HTTP -> NativeCurlProxyType.HTTP
            Proxy.Type.SOCKS -> NativeCurlProxyType.SOCKS5
            else -> NativeCurlProxyType.DIRECT
        }
    }
}

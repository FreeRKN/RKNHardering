package com.notcvnt.rknhardering.probe

import org.json.JSONArray
import org.json.JSONObject

internal enum class NativeCurlIpResolveMode(val wireValue: String) {
    WHATEVER("whatever"),
    V4("v4"),
    V6("v6");

    val nativeValue: Int
        get() = when (this) {
            WHATEVER -> 0
            V4 -> 1
            V6 -> 2
        }

    companion object {
        fun fromWireValue(value: String?): NativeCurlIpResolveMode {
            return entries.firstOrNull { it.wireValue == value } ?: WHATEVER
        }
    }
}

internal enum class NativeCurlProxyType(val wireValue: String) {
    DIRECT("direct"),
    HTTP("http"),
    SOCKS5("socks5");

    val nativeValue: Int
        get() = when (this) {
            DIRECT -> 0
            HTTP -> 1
            SOCKS5 -> 2
        }

    companion object {
        fun fromWireValue(value: String?): NativeCurlProxyType {
            return entries.firstOrNull { it.wireValue == value } ?: DIRECT
        }
    }
}

internal data class NativeCurlResolveRule(
    val host: String,
    val port: Int,
    val addresses: List<String>,
) {
    fun toCurlRule(): String = "$host:$port:${addresses.joinToString(",")}"

    companion object {
        fun fromJson(json: JSONObject): NativeCurlResolveRule {
            return NativeCurlResolveRule(
                host = json.getString("host"),
                port = json.optInt("port", 443),
                addresses = json.optJSONArray("addresses").toStringList(),
            )
        }
    }
}

internal data class NativeCurlRequest(
    val url: String,
    val interfaceName: String = "",
    val resolveRules: List<NativeCurlResolveRule> = emptyList(),
    val ipResolveMode: NativeCurlIpResolveMode = NativeCurlIpResolveMode.WHATEVER,
    val timeoutMs: Int,
    val connectTimeoutMs: Int,
    val caBundlePath: String,
    val debugVerbose: Boolean,
    val method: String = "GET",
    val headers: List<String> = emptyList(),
    val body: String? = null,
    val followRedirects: Boolean = true,
    val proxyUrl: String? = null,
    val proxyType: NativeCurlProxyType = NativeCurlProxyType.DIRECT,
) {
    companion object {
        fun fromJson(raw: String): NativeCurlRequest {
            val json = JSONObject(raw)
            return NativeCurlRequest(
                url = json.getString("url"),
                interfaceName = json.getString("interfaceName"),
                resolveRules = json.optJSONArray("resolveRules").toResolveRuleList(),
                ipResolveMode = NativeCurlIpResolveMode.fromWireValue(
                    json.optString("ipResolveMode").takeIf { it.isNotBlank() },
                ),
                timeoutMs = json.optInt("timeoutMs", 7_000),
                connectTimeoutMs = json.optInt("connectTimeoutMs", json.optInt("timeoutMs", 7_000)),
                caBundlePath = json.optString("caBundlePath", ""),
                debugVerbose = json.optBoolean("debugVerbose", false),
                method = json.optString("method", "GET"),
                headers = json.optJSONArray("headers").toStringList(),
                body = json.optString("body").takeIf { json.has("body") },
                followRedirects = json.optBoolean("followRedirects", true),
                proxyUrl = json.optString("proxyUrl").takeIf { json.has("proxyUrl") && it.isNotBlank() },
                proxyType = NativeCurlProxyType.fromWireValue(
                    json.optString("proxyType").takeIf { it.isNotBlank() },
                ),
            )
        }
    }

    fun toJson(): String {
        val json = JSONObject()
        json.put("url", url)
        json.put("interfaceName", interfaceName)
        json.put("ipResolveMode", ipResolveMode.wireValue)
        json.put("timeoutMs", timeoutMs)
        json.put("connectTimeoutMs", connectTimeoutMs)
        json.put("caBundlePath", caBundlePath)
        json.put("debugVerbose", debugVerbose)
        json.put("method", method)
        json.put("headers", JSONArray(headers))
        body?.let { json.put("body", it) }
        json.put("followRedirects", followRedirects)
        proxyUrl?.let { json.put("proxyUrl", it) }
        json.put("proxyType", proxyType.wireValue)
        json.put(
            "resolveRules",
            JSONArray().apply {
                resolveRules.forEach { rule ->
                    put(
                        JSONObject().apply {
                            put("host", rule.host)
                            put("port", rule.port)
                            put("addresses", JSONArray(rule.addresses))
                        },
                    )
                }
            },
        )
        return json.toString()
    }
}

internal data class NativeCurlResponse(
    val curlCode: Int? = null,
    val httpCode: Int? = null,
    val body: String = "",
    val errorBuffer: String? = null,
    val resolvedAddressesUsed: List<String> = emptyList(),
    val localError: String? = null,
) {
    companion object {
        fun fromRaw(raw: Array<String?>): NativeCurlResponse {
            val values = raw.toList()
            return NativeCurlResponse(
                curlCode = values.getOrNull(0)?.toIntOrNull(),
                httpCode = values.getOrNull(1)?.toIntOrNull(),
                body = values.getOrNull(2).orEmpty(),
                errorBuffer = values.getOrNull(3)?.takeIf { it.isNotBlank() },
                resolvedAddressesUsed = values.getOrNull(4)
                    ?.split(',')
                    ?.map(String::trim)
                    ?.filter(String::isNotEmpty)
                    .orEmpty(),
                localError = values.getOrNull(5)?.takeIf { it.isNotBlank() },
            )
        }
    }

    fun toJson(): String {
        return JSONObject().apply {
            curlCode?.let { put("curlCode", it) }
            httpCode?.let { put("httpCode", it) }
            put("body", body)
            errorBuffer?.let { put("errorBuffer", it) }
            put("resolvedAddressesUsed", JSONArray(resolvedAddressesUsed))
            localError?.let { put("localError", it) }
        }.toString()
    }
}

private fun JSONArray?.toStringList(): List<String> {
    if (this == null) return emptyList()
    return buildList(length()) {
        for (index in 0 until length()) {
            optString(index).takeIf { it.isNotBlank() }?.let(::add)
        }
    }
}

private fun JSONArray?.toResolveRuleList(): List<NativeCurlResolveRule> {
    if (this == null) return emptyList()
    return buildList(length()) {
        for (index in 0 until length()) {
            optJSONObject(index)?.let { add(NativeCurlResolveRule.fromJson(it)) }
        }
    }
}

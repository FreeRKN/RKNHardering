package com.notcvnt.rknhardering.probe

import java.io.IOException
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.Proxy
import java.net.URL
import javax.net.ssl.HttpsURLConnection

object PublicIpClient {

    data class DnsRecords(
        val ipv4Records: List<String> = emptyList(),
        val ipv6Records: List<String> = emptyList(),
    )

    private const val USER_AGENT = "curl/8.0"

    fun fetchIp(
        endpoint: String,
        timeoutMs: Int = 7000,
        proxy: Proxy? = null,
    ): Result<String> {
        val url = URL(endpoint)
        val connection = if (proxy == null) url.openConnection() else url.openConnection(proxy)
        val https = connection as? HttpsURLConnection
            ?: return Result.failure(IllegalStateException("Not an HTTPS connection"))

        return try {
            https.instanceFollowRedirects = true
            https.requestMethod = "GET"
            https.useCaches = false
            https.connectTimeout = timeoutMs
            https.readTimeout = timeoutMs
            https.setRequestProperty("User-Agent", USER_AGENT)
            https.setRequestProperty("Accept", "text/plain")

            val code = https.responseCode
            if (code !in 200..299) {
                val errorText = https.errorStream?.bufferedReader()?.use { it.readText() }?.trim()
                return Result.failure(
                    IOException(
                        buildString {
                            append("HTTP ")
                            append(code)
                            if (!errorText.isNullOrBlank()) {
                                append(": ")
                                append(errorText)
                            }
                        },
                    ),
                )
            }

            val body = https.inputStream.bufferedReader().use { it.readText() }.trim()
            if (body.isBlank()) {
                return Result.failure(IOException("Empty response body"))
            }
            val ip = extractIp(body)
                ?: return Result.failure(IOException("Response does not look like an IP: $body"))
            if (!looksLikeIp(ip)) {
                return Result.failure(IOException("Response does not look like an IP: $ip"))
            }
            Result.success(ip)
        } catch (e: Exception) {
            Result.failure(e)
        } finally {
            https.disconnect()
        }
    }

    internal fun extractIp(body: String): String? {
        val candidate = body
            .trim()
            .lineSequence()
            .map { it.trim() }
            .firstOrNull()
            ?.removeSurrounding("\"")
            ?.trim()
            .orEmpty()
        if (candidate.isBlank()) return null
        return candidate.takeIf(::looksLikeIp)
    }

    fun resolveDnsRecords(endpoint: String): DnsRecords {
        return try {
            val host = URL(endpoint).host
            val allAddresses = InetAddress.getAllByName(host)
            DnsRecords(
                ipv4Records = allAddresses
                    .filterIsInstance<Inet4Address>()
                    .mapNotNull { it.hostAddress }
                    .distinct(),
                ipv6Records = allAddresses
                    .filterIsInstance<Inet6Address>()
                    .mapNotNull { it.hostAddress }
                    .distinct(),
            )
        } catch (_: Exception) {
            DnsRecords()
        }
    }

    private fun looksLikeIp(text: String): Boolean {
        if (text.length > 45) return false
        return text.matches(Regex("""[\d.:a-fA-F]+"""))
    }
}

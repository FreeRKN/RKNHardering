package com.notcvnt.rknhardering.checker

import android.content.Context
import com.notcvnt.rknhardering.R
import com.notcvnt.rknhardering.model.CdnPullingResponse
import com.notcvnt.rknhardering.model.CdnPullingResult
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.probe.CdnPullingClient
import java.io.IOException
import java.security.cert.CertPathBuilderException
import java.security.cert.CertPathValidatorException
import java.security.cert.CertificateException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLPeerUnverifiedException

object CdnPullingChecker {

    private const val MAX_FETCH_ATTEMPTS = 1
    private const val RETRY_DELAY_MS = 250L

    internal data class EndpointSpec(
        val label: String,
        val url: String,
        val kind: CdnPullingClient.TargetKind,
    )

    internal val ENDPOINTS = listOf(
        EndpointSpec(
            label = "redirector.googlevideo.com",
            url = "https://redirector.googlevideo.com/report_mapping?di=no",
            kind = CdnPullingClient.TargetKind.GOOGLEVIDEO_REPORT_MAPPING,
        ),
        EndpointSpec(
            label = "rutracker.org",
            url = "https://rutracker.org/cdn-cgi/trace",
            kind = CdnPullingClient.TargetKind.CLOUDFLARE_TRACE,
        ),
        EndpointSpec(
            label = "meduza.io",
            url = "https://meduza.io/cdn-cgi/trace",
            kind = CdnPullingClient.TargetKind.CLOUDFLARE_TRACE,
        ),
    )

    suspend fun check(
        context: Context,
        timeoutMs: Int = 7000,
        resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
        meduzaEnabled: Boolean = true,
    ): CdnPullingResult = withContext(Dispatchers.IO) {
        coroutineScope {
            val activeEndpoints = if (meduzaEnabled) ENDPOINTS else ENDPOINTS.filter { it.label != "meduza.io" }
            val responses = activeEndpoints.map { endpoint ->
                async {
                    val bodyResult = fetchBodyWithRetries(
                        endpoint = endpoint.url,
                        timeoutMs = timeoutMs,
                        resolverConfig = resolverConfig,
                    )
                    val rawBody = bodyResult.getOrNull()
                    val parsedBody = rawBody?.let { CdnPullingClient.parseBody(endpoint.kind, it) }
                    val error = when {
                        bodyResult.isFailure -> formatError(context, bodyResult.exceptionOrNull())
                        parsedBody?.hasUsefulData == true -> null
                        else -> context.getString(R.string.checker_cdn_pulling_error_unrecognized)
                    }
                    CdnPullingResponse(
                        targetLabel = endpoint.label,
                        url = endpoint.url,
                        ip = parsedBody?.ip,
                        importantFields = parsedBody?.importantFields.orEmpty(),
                        rawBody = rawBody,
                        error = error,
                    )
                }
            }.map { it.await() }
            evaluate(context, responses)
        }
    }

    internal suspend fun fetchBodyWithRetries(
        endpoint: String,
        timeoutMs: Int,
        resolverConfig: DnsResolverConfig,
        maxAttempts: Int = MAX_FETCH_ATTEMPTS,
        retryDelayMs: Long = RETRY_DELAY_MS,
        fetcher: (String, Int, DnsResolverConfig) -> Result<String> = { url, timeout, resolver ->
            CdnPullingClient.fetchBody(url, timeoutMs = timeout, resolverConfig = resolver)
        },
    ): Result<String> {
        var lastError: Throwable? = null
        repeat(maxAttempts.coerceAtLeast(1)) { attempt ->
            val result = fetcher(endpoint, timeoutMs, resolverConfig)
            if (result.isSuccess) {
                return result
            }
            lastError = result.exceptionOrNull() ?: lastError
            if (!shouldRetry(lastError)) {
                return Result.failure(lastError ?: IOException("All CDN pulling attempts failed"))
            }
            if (attempt < maxAttempts - 1 && retryDelayMs > 0) {
                delay(retryDelayMs)
            }
        }
        return Result.failure(lastError ?: IOException("All CDN pulling attempts failed"))
    }

    internal fun evaluate(
        context: Context,
        responses: List<CdnPullingResponse>,
    ): CdnPullingResult {
        val successfulResponses = responses.filter { it.ip != null || it.importantFields.isNotEmpty() }
        val successfulCount = successfulResponses.size
        val allIps = successfulResponses.mapNotNull { it.ip }.distinct()
        val allSuccessfulResponsesExposeIp = successfulResponses.isNotEmpty() && successfulResponses.all { it.ip != null }
        val hasError = successfulCount == 0
        val detected = successfulCount > 0
        val needsReview = detected && (
            successfulCount < responses.size ||
                allIps.size > 1 ||
                !allSuccessfulResponsesExposeIp
        )

        val findings = buildFindings(successfulResponses, responses)
        val summary = when {
            hasError -> context.getString(R.string.checker_cdn_pulling_summary_error)
            allIps.size > 1 -> context.getString(
                R.string.checker_cdn_pulling_summary_mixed_ips,
                allIps.joinToString(", "),
            )
            successfulCount == responses.size && allSuccessfulResponsesExposeIp && allIps.size == 1 -> context.getString(
                R.string.checker_cdn_pulling_summary_detected_full,
                allIps.single(),
            )
            allSuccessfulResponsesExposeIp && allIps.size == 1 -> context.getString(
                R.string.checker_cdn_pulling_summary_detected_partial,
                allIps.single(),
                successfulCount,
                responses.size,
            )
            else -> context.getString(
                R.string.checker_cdn_pulling_summary_detected_no_ip,
                successfulCount,
                responses.size,
            )
        }

        return CdnPullingResult(
            detected = detected,
            needsReview = needsReview,
            hasError = hasError,
            summary = summary,
            responses = responses,
            findings = findings,
        )
    }

    private fun buildFindings(
        successfulResponses: List<CdnPullingResponse>,
        allResponses: List<CdnPullingResponse>,
    ): List<Finding> {
        val findings = mutableListOf<Finding>()
        successfulResponses.forEach { response ->
            val fieldsSummary = response.importantFields.entries
                .filterNot { response.ip != null && it.key.equals("IP", ignoreCase = true) }
                .joinToString(", ") { "${it.key}: ${it.value}" }
            val suffix = when {
                response.ip != null && fieldsSummary.isNotBlank() -> "IP: ${response.ip}, $fieldsSummary"
                response.ip != null -> "IP: ${response.ip}"
                else -> fieldsSummary
            }
            findings += Finding(
                description = "${response.targetLabel}: $suffix",
                detected = true,
                isInformational = true,
                confidence = EvidenceConfidence.MEDIUM,
            )
        }
        allResponses.filter { it.error != null }.forEach { response ->
            findings += Finding(
                description = "${response.targetLabel}: ${response.error}",
                needsReview = successfulResponses.isNotEmpty(),
                isError = successfulResponses.isEmpty(),
                confidence = EvidenceConfidence.LOW,
            )
        }
        return findings
    }

    internal fun formatError(context: Context, error: Throwable?): String {
        val message = error?.message?.trim().orEmpty()
        if (isTlsCertificateError(error)) {
            val friendlyMessage = context.getString(R.string.checker_cdn_pulling_error_tls_certificate)
            val details = tlsCertificateErrorDetails(error).ifBlank { message }
            return if (details.isBlank()) friendlyMessage else {
                "$friendlyMessage ${context.getString(R.string.checker_cdn_pulling_error_details, details)}"
            }
        }
        if (message.isNotBlank()) return message
        return when (error) {
            is IOException -> "Network error"
            null -> "Unknown error"
            else -> error::class.java.simpleName
        }
    }

    internal fun shouldRetry(error: Throwable?): Boolean {
        return error != null && !isTlsCertificateError(error)
    }

    internal fun isTlsCertificateError(error: Throwable?): Boolean {
        if (error == null) return false
        return errorCauseSequence(error).any { cause ->
            cause is CertPathValidatorException ||
                cause is CertPathBuilderException ||
                cause is CertificateException ||
                cause is SSLPeerUnverifiedException ||
                cause is SSLHandshakeException && containsTlsCertificateKeywords(cause.message) ||
                containsTlsCertificateKeywords(cause.message)
        }
    }

    private fun tlsCertificateErrorDetails(error: Throwable?): String {
        if (error == null) return ""
        return errorCauseSequence(error)
            .mapNotNull { cause ->
                cause.message
                    ?.trim()
                    ?.takeIf {
                        cause is CertPathValidatorException ||
                            cause is CertPathBuilderException ||
                            cause is CertificateException ||
                            cause is SSLPeerUnverifiedException ||
                            containsTlsCertificateKeywords(it)
                    }
            }
            .firstOrNull()
            .orEmpty()
    }

    private fun errorCauseSequence(error: Throwable): Sequence<Throwable> {
        return generateSequence(error) { current ->
            current.cause?.takeIf { it !== current }
        }
    }

    private fun containsTlsCertificateKeywords(message: String?): Boolean {
        val normalized = message?.trim()?.lowercase().orEmpty()
        if (normalized.isBlank()) return false
        return normalized.contains("trust anchor") ||
            normalized.contains("certpath") ||
            normalized.contains("certificate path") ||
            normalized.contains("path building failed") ||
            normalized.contains("peer not authenticated") ||
            normalized.contains("hostname") && normalized.contains("not verified")
    }
}

package com.notcvnt.rknhardering

import com.notcvnt.rknhardering.model.Verdict
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

internal data class CompletedExportSnapshot(
    val result: com.notcvnt.rknhardering.model.CheckResult,
    val privacyMode: Boolean,
    val finishedAtMillis: Long,
)

internal enum class ExportFormat(
    val extension: String,
    val mimeType: String,
) {
    MARKDOWN(extension = "md", mimeType = "text/markdown"),
    JSON(extension = "json", mimeType = "application/json"),
}

internal fun createCompletedExportSnapshot(
    result: com.notcvnt.rknhardering.model.CheckResult,
    privacyMode: Boolean,
    finishedAtMillis: Long = System.currentTimeMillis(),
): CompletedExportSnapshot {
    return CompletedExportSnapshot(
        result = result,
        privacyMode = privacyMode,
        finishedAtMillis = finishedAtMillis,
    )
}

internal fun buildDefaultExportFileName(format: ExportFormat, timestampMillis: Long): String {
    val timestamp = SimpleDateFormat("yyyy-MM-dd_HH-mm-ss", Locale.US).format(Date(timestampMillis))
    return "rknhardering-scan-$timestamp.${format.extension}"
}

internal fun formatExportTimestamp(timestampMillis: Long): String {
    return SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.US).format(Date(timestampMillis))
}

internal fun verdictStatusTag(verdict: Verdict): String {
    return when (verdict) {
        Verdict.NOT_DETECTED -> "[OK]"
        Verdict.NEEDS_REVIEW -> "[REVIEW]"
        Verdict.DETECTED -> "[DETECTED]"
    }
}

internal fun sectionStatusTag(
    detected: Boolean,
    needsReview: Boolean,
    hasError: Boolean = false,
): String {
    return when {
        hasError -> "[ERROR]"
        detected -> "[DETECTED]"
        needsReview -> "[REVIEW]"
        else -> "[OK]"
    }
}

internal fun maskExportValue(value: String, privacyMode: Boolean): String {
    return if (privacyMode) maskInfoValue(value, privacyMode = true) else value
}

internal fun maskExportIp(value: String?, privacyMode: Boolean): String? {
    return value?.let { if (privacyMode) maskIp(it) else it }
}

internal fun maskExportHostOrIp(value: String, privacyMode: Boolean): String {
    return if (privacyMode && isIpLiteralForExport(value)) maskIp(value) else value
}

internal fun maskExportHostPort(value: String, privacyMode: Boolean): String {
    val separatorIndex = value.lastIndexOf(':')
    if (separatorIndex <= 0 || separatorIndex == value.lastIndex) {
        return maskExportHostOrIp(value, privacyMode)
    }
    val port = value.substring(separatorIndex + 1)
    if (!port.all(Char::isDigit)) {
        return maskExportHostOrIp(value, privacyMode)
    }
    val host = value.substring(0, separatorIndex)
    return "${maskExportHostOrIp(host, privacyMode)}:$port"
}

internal fun formatExportHostPort(host: String, port: Int, privacyMode: Boolean): String {
    val renderedHost = maskExportHostOrIp(host, privacyMode)
    return if (renderedHost.contains(':') && !renderedHost.startsWith("[")) {
        "[$renderedHost]:$port"
    } else {
        "$renderedHost:$port"
    }
}

private fun isIpLiteralForExport(value: String): Boolean {
    val normalized = value.trim().removePrefix("[").removeSuffix("]").substringBefore('%')
    return normalized.matches(IPV4_LITERAL) ||
        (
            normalized.contains(':') &&
                normalized.all { char ->
                    char.isDigit() || char.lowercaseChar() in 'a'..'f' || char == ':'
                }
            )
}

private val IPV4_LITERAL = Regex("""(?:\d{1,3}\.){3}\d{1,3}""")

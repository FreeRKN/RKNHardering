package com.notcvnt.rknhardering.network

object NetworkInterfaceNameNormalizer {
    private const val STACKED_V4_PREFIX = "v4-"

    private val STANDARD_BASE_PATTERNS = listOf(
        Regex("^wlan.*"),
        Regex("^rmnet.*"),
        Regex("^eth.*"),
        Regex("^lo$"),
        Regex("^ccmni.*"),
        Regex("^ccemni.*"),
    )

    fun canonicalName(name: String?): String? {
        if (name.isNullOrBlank()) return name
        val baseName = name.removePrefix(STACKED_V4_PREFIX)
        if (baseName == name) return name
        return baseName.takeIf(::isStandardBaseInterface) ?: name
    }

    private fun isStandardBaseInterface(name: String): Boolean {
        return STANDARD_BASE_PATTERNS.any { it.matches(name) }
    }
}

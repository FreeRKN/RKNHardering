package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.IpCheckerResponse
import com.notcvnt.rknhardering.model.IpCheckerScope
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class IpComparisonCheckerTest {

    @Test
    fun `all checkers returning same ip produces clean result`() {
        val result = IpComparisonChecker.evaluate(
            listOf(
                response("Yandex", IpCheckerScope.RU, ip = "1.2.3.4"),
                response("ipify", IpCheckerScope.NON_RU, ip = "1.2.3.4"),
                response("ip.sb", IpCheckerScope.NON_RU, ip = "1.2.3.4"),
            ),
        )

        assertFalse(result.detected)
        assertFalse(result.needsReview)
        assertEquals("Есть ответ", result.ruGroup.statusLabel)
        assertEquals("Совпадает", result.nonRuGroup.statusLabel)
    }

    @Test
    fun `ru and non-ru mismatch with full data is detected`() {
        val result = IpComparisonChecker.evaluate(
            listOf(
                response("Yandex", IpCheckerScope.RU, ip = "10.0.0.1"),
                response("ipify", IpCheckerScope.NON_RU, ip = "20.0.0.1"),
                response("ip.sb", IpCheckerScope.NON_RU, ip = "20.0.0.1"),
            ),
        )

        assertTrue(result.detected)
        assertFalse(result.needsReview)
        assertTrue(result.summary.contains("10.0.0.1"))
        assertTrue(result.summary.contains("20.0.0.1"))
    }

    @Test
    fun `non-ru mismatch inside group requires attention`() {
        val result = IpComparisonChecker.evaluate(
            listOf(
                response("Yandex", IpCheckerScope.RU, ip = "1.2.3.4"),
                response("ipify", IpCheckerScope.NON_RU, ip = "5.6.7.8"),
                response("ip.sb", IpCheckerScope.NON_RU, ip = "9.9.9.9"),
            ),
        )

        assertFalse(result.detected)
        assertTrue(result.needsReview)
        assertTrue(result.nonRuGroup.detected)
        assertEquals("Разнобой", result.nonRuGroup.statusLabel)
    }

    @Test
    fun `partial non-ru response stays in review even when ip differs`() {
        val result = IpComparisonChecker.evaluate(
            listOf(
                response("Yandex", IpCheckerScope.RU, ip = "1.2.3.4"),
                response("ipify", IpCheckerScope.NON_RU, ip = "5.6.7.8"),
                response("ip.sb", IpCheckerScope.NON_RU, error = "timeout"),
            ),
        )

        assertFalse(result.detected)
        assertTrue(result.needsReview)
        assertEquals("Частично", result.nonRuGroup.statusLabel)
    }

    @Test
    fun `mixed ipv4 and ipv6 responses require review instead of detection`() {
        val result = IpComparisonChecker.evaluate(
            listOf(
                response("Yandex", IpCheckerScope.RU, ip = "37.113.42.220"),
                response("ipify", IpCheckerScope.NON_RU, ip = "37.113.42.220"),
                response("ip.sb", IpCheckerScope.NON_RU, ip = "2a01:4f9:c013:d2ba::1"),
            ),
        )

        assertFalse(result.detected)
        assertTrue(result.needsReview)
        assertEquals("IPv4/IPv6", result.nonRuGroup.statusLabel)
    }

    @Test
    fun `ignored ipv6 error does not make ru group partial`() {
        val result = IpComparisonChecker.evaluate(
            listOf(
                response("Yandex IPv4", IpCheckerScope.RU, ip = "37.113.42.220"),
                response(
                    "Yandex IPv6",
                    IpCheckerScope.RU,
                    error = "connect failed",
                    ignoredIpv6Error = true,
                    ipv6Records = listOf("2a02:6b8::"),
                ),
                response("ifconfig.me", IpCheckerScope.NON_RU, ip = "37.113.42.220"),
                response("checkip.amazonaws.com", IpCheckerScope.NON_RU, ip = "37.113.42.220"),
            ),
        )

        assertFalse(result.detected)
        assertFalse(result.needsReview)
        assertEquals("Совпадает", result.ruGroup.statusLabel)
        assertEquals(1, result.ruGroup.ignoredIpv6ErrorCount)
    }

    @Test
    fun `ignored ipv6 error does not make non ru group partial`() {
        val result = IpComparisonChecker.evaluate(
            listOf(
                response("Yandex IPv4", IpCheckerScope.RU, ip = "37.113.42.220"),
                response("2ip.ru", IpCheckerScope.RU, ip = "37.113.42.220"),
                response("ifconfig.me IPv4", IpCheckerScope.NON_RU, ip = "37.113.42.220"),
                response(
                    "ifconfig.me IPv6",
                    IpCheckerScope.NON_RU,
                    error = "connect failed",
                    ignoredIpv6Error = true,
                    ipv6Records = listOf("2600:1901:0:b2bd::"),
                ),
                response("ipify", IpCheckerScope.NON_RU, ip = "37.113.42.220"),
                response("ip.sb IPv4", IpCheckerScope.NON_RU, ip = "37.113.42.220"),
            ),
        )

        assertFalse(result.detected)
        assertFalse(result.needsReview)
        assertEquals("Ð¡Ð¾Ð²Ð¿Ð°Ð´Ð°ÐµÑ‚", result.nonRuGroup.statusLabel)
        assertEquals(1, result.nonRuGroup.ignoredIpv6ErrorCount)
    }

    private fun response(
        label: String,
        scope: IpCheckerScope,
        ip: String? = null,
        error: String? = null,
        ipv4Records: List<String> = emptyList(),
        ipv6Records: List<String> = emptyList(),
        ignoredIpv6Error: Boolean = false,
    ): IpCheckerResponse = IpCheckerResponse(
        label = label,
        url = "https://example.com/$label",
        scope = scope,
        ip = ip,
        error = error,
        ipv4Records = ipv4Records,
        ipv6Records = ipv6Records,
        ignoredIpv6Error = ignoredIpv6Error,
    )
}

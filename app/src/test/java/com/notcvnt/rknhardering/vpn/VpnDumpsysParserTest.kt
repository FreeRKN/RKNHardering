package com.notcvnt.rknhardering.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class VpnDumpsysParserTest {

    @Test
    fun `parses active package from vpn management output`() {
        val output = """
            VPNs:
              Active package name: com.v2ray.ang
              Active vpn type: legacy
        """.trimIndent()

        val records = VpnDumpsysParser.parseVpnManagement(output)

        assertEquals(1, records.count { it.packageName == "com.v2ray.ang" })
    }

    @Test
    fun `parses active vpn service record`() {
        val output = """
            ServiceRecord{12345 u0 com.v2ray.ang/com.v2ray.ang.service.VpnService}
        """.trimIndent()

        val records = VpnDumpsysParser.parseVpnServices(output)

        assertEquals("com.v2ray.ang", records.single().packageName)
        assertEquals("com.v2ray.ang.service.VpnService", records.single().serviceName)
    }

    @Test
    fun `treats permission denial as unavailable`() {
        assertTrue(VpnDumpsysParser.isUnavailable("Permission Denial: can't dump"))
        assertTrue(VpnDumpsysParser.parseVpnServices("Permission Denial: can't dump").isEmpty())
    }
}

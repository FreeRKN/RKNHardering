package com.notcvnt.rknhardering.probe

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PublicIpClientTest {

    @Test
    fun `extractIp strips quotes from quoted plain response`() {
        assertEquals("1.2.3.4", PublicIpClient.extractIp("\"1.2.3.4\""))
    }

    @Test
    fun `extractIp keeps plain ipv6 response`() {
        assertEquals("2001:db8::1", PublicIpClient.extractIp("2001:db8::1"))
    }

    @Test
    fun `extractIp parses json ip field`() {
        assertEquals("1.2.3.4", PublicIpClient.extractIp("{\"ip\":\"1.2.3.4\"}"))
    }

    @Test
    fun `extractIp parses json ip field with spaces`() {
        assertEquals("1.2.3.4", PublicIpClient.extractIp("{\"ip\": \"1.2.3.4\", \"city\": {}}"))
    }

    @Test
    fun `extractIp rejects non ip json`() {
        assertNull(PublicIpClient.extractIp("{\"country\":\"RU\",\"city\":\"Moscow\"}"))
    }
}

package com.notcvnt.rknhardering.network

import org.junit.Assert.assertEquals
import org.junit.Test

class NetworkInterfaceNameNormalizerTest {

    @Test
    fun `canonicalizes stacked clat wifi and mobile interfaces`() {
        assertEquals("wlan0", NetworkInterfaceNameNormalizer.canonicalName("v4-wlan0"))
        assertEquals("rmnet_data0", NetworkInterfaceNameNormalizer.canonicalName("v4-rmnet_data0"))
    }

    @Test
    fun `keeps unrelated v4 prefixed interfaces unchanged`() {
        assertEquals("v4-tun0", NetworkInterfaceNameNormalizer.canonicalName("v4-tun0"))
        assertEquals("tun0", NetworkInterfaceNameNormalizer.canonicalName("tun0"))
    }
}

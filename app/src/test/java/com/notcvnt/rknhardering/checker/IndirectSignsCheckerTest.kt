package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.checker.IndirectSignsChecker.DnsClassification
import org.junit.Assert.assertEquals
import org.junit.Test

class IndirectSignsCheckerTest {

    @Test
    fun `classifies loopback dns`() {
        assertEquals(DnsClassification.LOOPBACK, IndirectSignsChecker.classifyDnsAddress("127.0.0.1"))
        assertEquals(DnsClassification.LOOPBACK, IndirectSignsChecker.classifyDnsAddress("::1"))
    }

    @Test
    fun `classifies private tunnel dns`() {
        assertEquals(DnsClassification.PRIVATE_TUNNEL, IndirectSignsChecker.classifyDnsAddress("10.0.0.2"))
        assertEquals(DnsClassification.PRIVATE_TUNNEL, IndirectSignsChecker.classifyDnsAddress("172.16.0.10"))
        assertEquals(DnsClassification.PRIVATE_TUNNEL, IndirectSignsChecker.classifyDnsAddress("192.168.1.1"))
        assertEquals(DnsClassification.PRIVATE_TUNNEL, IndirectSignsChecker.classifyDnsAddress("fd00::1"))
    }

    @Test
    fun `classifies known public resolvers`() {
        assertEquals(DnsClassification.KNOWN_PUBLIC_RESOLVER, IndirectSignsChecker.classifyDnsAddress("1.1.1.1"))
        assertEquals(DnsClassification.KNOWN_PUBLIC_RESOLVER, IndirectSignsChecker.classifyDnsAddress("8.8.8.8"))
        assertEquals(DnsClassification.KNOWN_PUBLIC_RESOLVER, IndirectSignsChecker.classifyDnsAddress("2606:4700:4700::1111"))
    }

    @Test
    fun `classifies link local and other public dns`() {
        assertEquals(DnsClassification.LINK_LOCAL, IndirectSignsChecker.classifyDnsAddress("169.254.1.1"))
        assertEquals(DnsClassification.LINK_LOCAL, IndirectSignsChecker.classifyDnsAddress("fe80::1"))
        assertEquals(DnsClassification.OTHER_PUBLIC, IndirectSignsChecker.classifyDnsAddress("77.88.55.55"))
    }
}

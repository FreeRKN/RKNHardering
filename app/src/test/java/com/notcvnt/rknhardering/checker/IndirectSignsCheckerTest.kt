package com.notcvnt.rknhardering.checker

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.checker.IndirectSignsChecker.DnsClassification
import com.notcvnt.rknhardering.checker.IndirectSignsChecker.InterfaceAddressSnapshot
import com.notcvnt.rknhardering.checker.IndirectSignsChecker.NetworkSnapshot
import com.notcvnt.rknhardering.checker.IndirectSignsChecker.RouteSnapshot
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.probe.LocalSocketInspector
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class IndirectSignsCheckerTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `classifies loopback dns`() {
        assertEquals(DnsClassification.LOOPBACK, IndirectSignsChecker.classifyDnsAddress("127.0.0.1"))
        assertEquals(DnsClassification.LOOPBACK, IndirectSignsChecker.classifyDnsAddress("::1"))
    }

    @Test
    fun `classifies private network dns including carrier grade nat and ula`() {
        assertEquals(DnsClassification.PRIVATE_NETWORK, IndirectSignsChecker.classifyDnsAddress("10.0.0.2"))
        assertEquals(DnsClassification.PRIVATE_NETWORK, IndirectSignsChecker.classifyDnsAddress("172.16.0.10"))
        assertEquals(DnsClassification.PRIVATE_NETWORK, IndirectSignsChecker.classifyDnsAddress("192.168.1.1"))
        assertEquals(DnsClassification.PRIVATE_NETWORK, IndirectSignsChecker.classifyDnsAddress("100.64.0.10"))
        assertEquals(DnsClassification.PRIVATE_NETWORK, IndirectSignsChecker.classifyDnsAddress("fd00::1"))
    }

    @Test
    fun `classifies link local and public dns separately`() {
        assertEquals(DnsClassification.LINK_LOCAL, IndirectSignsChecker.classifyDnsAddress("169.254.1.1"))
        assertEquals(DnsClassification.LINK_LOCAL, IndirectSignsChecker.classifyDnsAddress("fe80::1"))
        assertEquals(DnsClassification.KNOWN_PUBLIC_RESOLVER, IndirectSignsChecker.classifyDnsAddress("8.8.8.8"))
        assertEquals(DnsClassification.OTHER_PUBLIC, IndirectSignsChecker.classifyDnsAddress("77.88.55.55"))
    }

    @Test
    fun `parses proc net listeners`() {
        val listeners = IndirectSignsChecker.parseProcNetListeners(
            lines = listOf(
                "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
                "   0: 0100007F:2382 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 0 1 0000000000000000 100 0 0 10 0",
            ),
            protocol = "tcp",
        )

        assertEquals(1, listeners.size)
        assertEquals("127.0.0.1", listeners.single().host)
        assertEquals(9090, listeners.single().port)
        assertEquals(0, listeners.single().uid)
        assertEquals(0L, listeners.single().inode)
    }

    @Test
    fun `resolves owner for a single visible package`() {
        val owner = LocalSocketInspector.resolveOwner(
            uid = 10123,
            packageNames = listOf("com.whatsapp"),
            uidName = "u0a123",
            appLabelResolver = { "WhatsApp" },
        )

        assertEquals(10123, owner.uid)
        assertEquals(listOf("com.whatsapp"), owner.packageNames)
        assertEquals(listOf("WhatsApp"), owner.appLabels)
        assertEquals(EvidenceConfidence.HIGH, owner.confidence)
    }

    @Test
    fun `resolves owner for shared uid packages`() {
        val owner = LocalSocketInspector.resolveOwner(
            uid = 10124,
            packageNames = listOf("com.example.first", "com.example.second"),
            uidName = "u0a124",
            appLabelResolver = { packageName ->
                when (packageName) {
                    "com.example.first" -> "First"
                    "com.example.second" -> "Second"
                    else -> null
                }
            },
        )

        assertEquals(listOf("com.example.first", "com.example.second"), owner.packageNames)
        assertEquals(listOf("First", "Second"), owner.appLabels)
        assertEquals(EvidenceConfidence.MEDIUM, owner.confidence)
    }

    @Test
    fun `resolves owner to uid fallback when package list is unavailable`() {
        val owner = LocalSocketInspector.resolveOwner(
            uid = 10125,
            packageNames = emptyList(),
            uidName = "u0a125",
            appLabelResolver = { null },
        )

        assertEquals(emptyList<String>(), owner.packageNames)
        assertEquals(listOf("u0a125"), owner.appLabels)
        assertEquals(EvidenceConfidence.LOW, owner.confidence)
    }

    @Test
    fun `loopback dns on active vpn is detected`() {
        val evaluation = IndirectSignsChecker.checkDns(
            context,
            listOf(
                snapshot(
                    isActive = true,
                    isVpn = true,
                    interfaceName = "tun0",
                    routes = listOf(route("0.0.0.0/0", "tun0", isDefault = true)),
                    dnsServers = listOf("127.0.0.1"),
                ),
                snapshot(
                    isActive = false,
                    isVpn = false,
                    interfaceName = "wlan0",
                    routes = listOf(route("0.0.0.0/0", "wlan0", isDefault = true)),
                    dnsServers = listOf("192.168.1.1"),
                    interfaceAddresses = listOf(linkAddress("192.168.1.2", 24)),
                ),
            ),
        )

        assertTrue(evaluation.detected)
        assertFalse(evaluation.needsReview)
        assertTrue(evaluation.evidence.any { it.source == EvidenceSource.DNS && it.detected })
    }

    @Test
    fun `vpn replacing public dns yields needs review`() {
        val evaluation = IndirectSignsChecker.checkDns(
            context,
            listOf(
                snapshot(
                    isActive = true,
                    isVpn = true,
                    interfaceName = "tun0",
                    routes = listOf(route("0.0.0.0/0", "tun0", isDefault = true)),
                    dnsServers = listOf("8.8.8.8"),
                ),
                snapshot(
                    isActive = false,
                    isVpn = false,
                    interfaceName = "wlan0",
                    routes = listOf(route("0.0.0.0/0", "wlan0", isDefault = true)),
                    dnsServers = listOf("192.168.1.1"),
                    interfaceAddresses = listOf(linkAddress("192.168.1.2", 24)),
                ),
            ),
        )

        assertFalse(evaluation.detected)
        assertTrue(evaluation.needsReview)
        assertTrue(evaluation.evidence.any { it.source == EvidenceSource.DNS && it.detected })
    }

    @Test
    fun `shared ula dns across vpn and underlying prefixes stays clear`() {
        val evaluation = IndirectSignsChecker.checkDns(
            context,
            listOf(
                snapshot(
                    isActive = true,
                    isVpn = true,
                    interfaceName = "tun0",
                    routes = listOf(route("0.0.0.0/0", "tun0", isDefault = true)),
                    dnsServers = listOf("fd12:3456:789a::53"),
                    interfaceAddresses = listOf(linkAddress("fd12:3456:789a::2", 64)),
                ),
                snapshot(
                    isActive = false,
                    isVpn = false,
                    interfaceName = "wlan0",
                    routes = listOf(route("0.0.0.0/0", "wlan0", isDefault = true)),
                    dnsServers = listOf("fd12:3456:789a::1"),
                    interfaceAddresses = listOf(linkAddress("fd12:3456:789a::10", 64)),
                ),
            ),
        )

        assertFalse(evaluation.detected)
        assertFalse(evaluation.needsReview)
        assertTrue(evaluation.evidence.isEmpty())
    }

    @Test
    fun `shared carrier grade nat dns across vpn and underlying prefixes stays clear`() {
        val evaluation = IndirectSignsChecker.checkDns(
            context,
            listOf(
                snapshot(
                    isActive = true,
                    isVpn = true,
                    interfaceName = "tun0",
                    routes = listOf(route("0.0.0.0/0", "tun0", isDefault = true)),
                    dnsServers = listOf("100.64.10.53"),
                    interfaceAddresses = listOf(linkAddress("100.64.10.2", 24)),
                ),
                snapshot(
                    isActive = false,
                    isVpn = false,
                    interfaceName = "rmnet0",
                    routes = listOf(route("0.0.0.0/0", "rmnet0", isDefault = true)),
                    dnsServers = listOf("100.64.10.1"),
                    interfaceAddresses = listOf(linkAddress("100.64.10.9", 24)),
                ),
            ),
        )

        assertFalse(evaluation.detected)
        assertFalse(evaluation.needsReview)
        assertTrue(evaluation.evidence.isEmpty())
    }

    @Test
    fun `private dns on local non vpn prefix stays clear`() {
        val evaluation = IndirectSignsChecker.checkDns(
            context,
            listOf(
                snapshot(
                    isActive = true,
                    isVpn = false,
                    interfaceName = "rmnet0",
                    routes = listOf(route("0.0.0.0/0", "rmnet0", isDefault = true)),
                    dnsServers = listOf("100.64.10.53"),
                    interfaceAddresses = listOf(linkAddress("100.64.10.2", 24)),
                ),
            ),
        )

        assertFalse(evaluation.detected)
        assertFalse(evaluation.needsReview)
        assertTrue(evaluation.evidence.isEmpty())
    }

    @Test
    fun `private dns on different underlying prefix stays detected on active vpn`() {
        val evaluation = IndirectSignsChecker.checkDns(
            context,
            listOf(
                snapshot(
                    isActive = true,
                    isVpn = true,
                    interfaceName = "tun0",
                    routes = listOf(route("0.0.0.0/0", "tun0", isDefault = true)),
                    dnsServers = listOf("fd12:3456:789a::53"),
                    interfaceAddresses = listOf(linkAddress("fd12:3456:789a::2", 64)),
                ),
                snapshot(
                    isActive = false,
                    isVpn = false,
                    interfaceName = "wlan0",
                    routes = listOf(route("0.0.0.0/0", "wlan0", isDefault = true)),
                    dnsServers = listOf("fd98:7654:3210::1"),
                    interfaceAddresses = listOf(linkAddress("fd98:7654:3210::10", 64)),
                ),
            ),
        )

        assertTrue(evaluation.detected)
        assertFalse(evaluation.needsReview)
        assertTrue(evaluation.evidence.any { it.source == EvidenceSource.DNS && it.detected })
    }

    @Test
    fun `default route on non standard interface is detected`() {
        val evaluation = IndirectSignsChecker.checkRoutingTable(
            context,
            listOf(
                snapshot(
                    isActive = true,
                    isVpn = false,
                    interfaceName = "tun0",
                    routes = listOf(route("0.0.0.0/0", "tun0", isDefault = true)),
                ),
            ),
        )

        assertTrue(evaluation.detected)
        assertTrue(evaluation.evidence.any { it.source == EvidenceSource.ROUTING && it.detected })
    }

    @Test
    fun `default route on stacked clat interface stays clear`() {
        val evaluation = IndirectSignsChecker.checkRoutingTable(
            context,
            listOf(
                snapshot(
                    isActive = true,
                    isVpn = false,
                    interfaceName = "wlan0",
                    routes = listOf(route("0.0.0.0/0", "v4-wlan0", isDefault = true)),
                ),
            ),
        )

        assertFalse(evaluation.detected)
        assertTrue(evaluation.findings.any { !it.detected && it.description.contains("wlan0") })
    }

    @Test
    fun `split tunneling route pattern is detected`() {
        val evaluation = IndirectSignsChecker.checkRoutingTable(
            context,
            listOf(
                snapshot(
                    isActive = true,
                    isVpn = true,
                    interfaceName = "tun0",
                    routes = listOf(route("10.0.0.0/8", "tun0", isDefault = false)),
                ),
                snapshot(
                    isActive = false,
                    isVpn = false,
                    interfaceName = "wlan0",
                    routes = listOf(route("0.0.0.0/0", "wlan0", isDefault = true)),
                ),
            ),
        )

        assertTrue(evaluation.detected)
        assertTrue(evaluation.evidence.any { it.description.contains("Split-tunneling") })
    }

    private fun snapshot(
        isActive: Boolean,
        isVpn: Boolean,
        interfaceName: String?,
        routes: List<RouteSnapshot>,
        dnsServers: List<String> = emptyList(),
        interfaceAddresses: List<InterfaceAddressSnapshot> = emptyList(),
    ): NetworkSnapshot {
        return NetworkSnapshot(
            label = interfaceName ?: "network",
            isActive = isActive,
            isVpn = isVpn,
            interfaceName = interfaceName,
            routes = routes,
            dnsServers = dnsServers,
            interfaceAddresses = interfaceAddresses,
        )
    }

    private fun linkAddress(address: String, prefixLength: Int): InterfaceAddressSnapshot {
        return InterfaceAddressSnapshot(
            address = address,
            prefixLength = prefixLength,
        )
    }

    private fun route(
        destination: String,
        interfaceName: String?,
        isDefault: Boolean,
        gateway: String? = "192.0.2.1",
    ): RouteSnapshot {
        return RouteSnapshot(
            destination = destination,
            gateway = gateway,
            interfaceName = interfaceName,
            isDefault = isDefault,
        )
    }
}

package com.notcvnt.rknhardering.probe

import android.net.Network
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.ResolverBinding
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.IOException

@RunWith(RobolectricTestRunner::class)
class IfconfigClientTest {

    @After
    fun tearDown() {
        PublicIpClient.resetForTests()
    }

    @Test
    fun `fetch ip via network keeps primary then fallback order`() {
        val observedBindings = mutableListOf<ResolverBinding?>()
        PublicIpClient.fetchIpOverride = { _, _, _, _, binding ->
            observedBindings += binding
            when (binding) {
                is ResolverBinding.AndroidNetworkBinding -> Result.failure(IOException("primary path failed"))
                is ResolverBinding.OsDeviceBinding -> Result.success("203.0.113.20")
                null -> Result.failure(IOException("unexpected unbound path"))
            }
        }

        val result = kotlinx.coroutines.runBlocking {
            IfconfigClient.fetchIpViaNetwork(
                primaryBinding = ResolverBinding.AndroidNetworkBinding(newNetwork(202)),
                fallbackBinding = ResolverBinding.OsDeviceBinding(
                    interfaceName = "tun0",
                    dnsMode = ResolverBinding.DnsMode.SYSTEM,
                ),
                resolverConfig = DnsResolverConfig.system(),
            )
        }

        assertTrue(result.isSuccess)
        assertEquals("203.0.113.20", result.getOrNull())
        assertTrue(observedBindings.first() is ResolverBinding.AndroidNetworkBinding)
        val fallbackIndex = observedBindings.indexOfFirst { it is ResolverBinding.OsDeviceBinding }
        assertTrue(fallbackIndex > 0)
        assertTrue(observedBindings.take(fallbackIndex).all { it is ResolverBinding.AndroidNetworkBinding })
        val fallbackBinding = observedBindings[fallbackIndex] as ResolverBinding.OsDeviceBinding
        assertEquals("tun0", fallbackBinding.interfaceName)
        assertEquals(ResolverBinding.DnsMode.SYSTEM, fallbackBinding.dnsMode)
    }

    @Test
    fun `fetch ip via network combines primary and fallback errors when both bindings fail`() {
        PublicIpClient.fetchIpOverride = { _, _, _, _, binding ->
            when (binding) {
                is ResolverBinding.AndroidNetworkBinding -> Result.failure(IOException("primary path failed"))
                is ResolverBinding.OsDeviceBinding -> Result.failure(IOException("device path failed"))
                null -> Result.failure(IOException("unexpected unbound path"))
            }
        }

        val result = kotlinx.coroutines.runBlocking {
            IfconfigClient.fetchIpViaNetwork(
                primaryBinding = ResolverBinding.AndroidNetworkBinding(newNetwork(203)),
                fallbackBinding = ResolverBinding.OsDeviceBinding(
                    interfaceName = "tun0",
                    dnsMode = ResolverBinding.DnsMode.SYSTEM,
                ),
                resolverConfig = DnsResolverConfig.system(),
            )
        }

        assertTrue(result.isFailure)
        assertEquals(
            "Android Network binding failed: primary path failed; SO_BINDTODEVICE(tun0) failed: device path failed",
            result.exceptionOrNull()?.message,
        )
    }

    @Test
    fun `network comparison marks dns path mismatch when curl compatible succeeds after strict failure`() {
        val observedBindings = mutableListOf<ResolverBinding?>()
        PublicIpClient.fetchIpOverride = { _, _, _, _, binding ->
            observedBindings += binding
            when (binding) {
                is ResolverBinding.AndroidNetworkBinding -> Result.failure(IOException("strict failed"))
                is ResolverBinding.OsDeviceBinding -> Result.success("203.0.113.21")
                null -> Result.failure(IOException("unexpected unbound path"))
            }
        }

        val comparison = kotlinx.coroutines.runBlocking {
            IfconfigClient.fetchIpViaNetworkComparison(
                primaryBinding = ResolverBinding.AndroidNetworkBinding(newNetwork(204)),
                fallbackBinding = ResolverBinding.OsDeviceBinding(
                    interfaceName = "tun0",
                    dnsMode = ResolverBinding.DnsMode.SYSTEM,
                ),
                resolverConfig = DnsResolverConfig.system(),
                collectTrace = true,
            )
        }

        assertEquals(PublicIpProbeStatus.FAILED, comparison.strict.status)
        assertEquals(PublicIpProbeStatus.SUCCEEDED, comparison.curlCompatible.status)
        assertEquals(PublicIpProbeMode.CURL_COMPATIBLE, comparison.selectedMode)
        assertEquals("203.0.113.21", comparison.selectedIp)
        assertTrue(comparison.dnsPathMismatch)
        assertFalse(comparison.strict.endpointAttempts.isEmpty())
        assertFalse(comparison.curlCompatible.endpointAttempts.isEmpty())
        assertTrue(observedBindings.any { it is ResolverBinding.AndroidNetworkBinding })
        assertTrue(observedBindings.any { it is ResolverBinding.OsDeviceBinding })
    }

    @Test
    fun `network comparison still runs curl compatible branch after strict success`() {
        val observedBindings = mutableListOf<ResolverBinding?>()
        PublicIpClient.fetchIpOverride = { _, _, _, _, binding ->
            observedBindings += binding
            when (binding) {
                is ResolverBinding.AndroidNetworkBinding -> Result.success("198.51.100.10")
                is ResolverBinding.OsDeviceBinding -> Result.success("203.0.113.22")
                null -> Result.failure(IOException("unexpected unbound path"))
            }
        }

        val comparison = kotlinx.coroutines.runBlocking {
            IfconfigClient.fetchIpViaNetworkComparison(
                primaryBinding = ResolverBinding.AndroidNetworkBinding(newNetwork(205)),
                fallbackBinding = ResolverBinding.OsDeviceBinding(
                    interfaceName = "tun0",
                    dnsMode = ResolverBinding.DnsMode.SYSTEM,
                ),
                resolverConfig = DnsResolverConfig.system(),
                collectTrace = true,
            )
        }

        assertEquals(PublicIpProbeMode.STRICT_SAME_PATH, comparison.selectedMode)
        assertEquals("198.51.100.10", comparison.selectedIp)
        assertEquals(PublicIpProbeStatus.SUCCEEDED, comparison.curlCompatible.status)
        assertTrue(observedBindings.any { it is ResolverBinding.AndroidNetworkBinding })
        assertTrue(observedBindings.any { it is ResolverBinding.OsDeviceBinding })
    }

    @Test
    fun `strict override skips curl compatible branch`() {
        val observedBindings = mutableListOf<ResolverBinding?>()
        PublicIpClient.fetchIpOverride = { _, _, _, _, binding ->
            observedBindings += binding
            when (binding) {
                is ResolverBinding.AndroidNetworkBinding -> Result.success("198.51.100.11")
                is ResolverBinding.OsDeviceBinding -> Result.success("203.0.113.31")
                null -> Result.failure(IOException("unexpected unbound path"))
            }
        }

        val comparison = kotlinx.coroutines.runBlocking {
            IfconfigClient.fetchIpViaNetworkComparison(
                primaryBinding = ResolverBinding.AndroidNetworkBinding(newNetwork(207)),
                fallbackBinding = ResolverBinding.OsDeviceBinding(
                    interfaceName = "tun0",
                    dnsMode = ResolverBinding.DnsMode.SYSTEM,
                ),
                resolverConfig = DnsResolverConfig.system(),
                modeOverride = TunProbeModeOverride.STRICT_SAME_PATH,
            )
        }

        assertEquals(PublicIpProbeMode.STRICT_SAME_PATH, comparison.selectedMode)
        assertEquals(PublicIpProbeStatus.SKIPPED, comparison.curlCompatible.status)
        assertEquals("Disabled by override", comparison.curlCompatible.error)
        assertTrue(observedBindings.all { it is ResolverBinding.AndroidNetworkBinding })
    }

    @Test
    fun `curl compatible override skips strict branch`() {
        val observedBindings = mutableListOf<ResolverBinding?>()
        PublicIpClient.fetchIpOverride = { _, _, _, _, binding ->
            observedBindings += binding
            when (binding) {
                is ResolverBinding.OsDeviceBinding -> Result.success("203.0.113.32")
                is ResolverBinding.AndroidNetworkBinding -> Result.failure(IOException("strict should not run"))
                null -> Result.failure(IOException("unexpected unbound path"))
            }
        }

        val comparison = kotlinx.coroutines.runBlocking {
            IfconfigClient.fetchIpViaNetworkComparison(
                primaryBinding = ResolverBinding.AndroidNetworkBinding(newNetwork(208)),
                fallbackBinding = ResolverBinding.OsDeviceBinding(
                    interfaceName = "tun0",
                    dnsMode = ResolverBinding.DnsMode.SYSTEM,
                ),
                resolverConfig = DnsResolverConfig.system(),
                modeOverride = TunProbeModeOverride.CURL_COMPATIBLE,
            )
        }

        assertEquals(PublicIpProbeMode.CURL_COMPATIBLE, comparison.selectedMode)
        assertEquals(PublicIpProbeStatus.SKIPPED, comparison.strict.status)
        assertEquals("Disabled by override", comparison.strict.error)
        assertTrue(observedBindings.all { it is ResolverBinding.OsDeviceBinding })
    }

    @Test
    fun `forced curl compatible reports missing interface clearly`() {
        val comparison = kotlinx.coroutines.runBlocking {
            IfconfigClient.fetchIpViaNetworkComparison(
                primaryBinding = ResolverBinding.AndroidNetworkBinding(newNetwork(209)),
                fallbackBinding = null,
                resolverConfig = DnsResolverConfig.system(),
                modeOverride = TunProbeModeOverride.CURL_COMPATIBLE,
            )
        }

        assertEquals(PublicIpProbeStatus.SKIPPED, comparison.curlCompatible.status)
        assertEquals(null, comparison.selectedMode)
        assertEquals(
            "OS device bind fallback is unavailable because interfaceName is missing",
            comparison.selectedError,
        )
    }

    @Test
    fun `network comparison marks curl compatible branch as skipped when interface is missing`() {
        PublicIpClient.fetchIpOverride = { _, _, _, _, binding ->
            when (binding) {
                is ResolverBinding.AndroidNetworkBinding -> Result.failure(IOException("strict failed"))
                else -> Result.failure(IOException("unexpected binding"))
            }
        }

        val comparison = kotlinx.coroutines.runBlocking {
            IfconfigClient.fetchIpViaNetworkComparison(
                primaryBinding = ResolverBinding.AndroidNetworkBinding(newNetwork(206)),
                fallbackBinding = null,
                resolverConfig = DnsResolverConfig.system(),
            )
        }

        assertEquals(PublicIpProbeStatus.SKIPPED, comparison.curlCompatible.status)
        assertEquals(
            "OS device bind fallback is unavailable because interfaceName is missing",
            comparison.curlCompatible.error,
        )
        assertEquals("strict failed; OS device bind fallback is unavailable because interfaceName is missing", comparison.selectedError)
        assertEquals(null, comparison.selectedMode)
        assertFalse(comparison.dnsPathMismatch)
    }

    @Test
    fun `fetch direct ip prefers generic or ipv4 error over trailing ipv6-only failure`() {
        PublicIpClient.fetchIpOverride = { endpoint, _, _, _, _ ->
            when {
                endpoint.contains("api6.ipify.org") ->
                    Result.failure(IOException("Unable to resolve host \"api6.ipify.org\""))
                else ->
                    Result.failure(IOException("generic timeout"))
            }
        }

        val result = kotlinx.coroutines.runBlocking {
            IfconfigClient.fetchDirectIp(
                resolverConfig = DnsResolverConfig.system(),
            )
        }

        assertTrue(result.isFailure)
        assertEquals("generic timeout", result.exceptionOrNull()?.message)
    }

    @Test
    fun `ipv6 endpoints are tried after all ipv4 and generic endpoints`() {
        val calledEndpoints = mutableListOf<String>()
        PublicIpClient.fetchIpOverride = { endpoint, _, _, _, _ ->
            calledEndpoints += endpoint
            Result.failure(IOException("fail"))
        }

        kotlinx.coroutines.runBlocking {
            IfconfigClient.fetchDirectIp(
                resolverConfig = DnsResolverConfig.system(),
            )
        }

        val ipv6Index = calledEndpoints.indexOfFirst { it.contains("api6.ipify.org") }
        assertTrue("IPv6 endpoint should be present", ipv6Index >= 0)
        // All endpoints before IPv6 should be non-IPv6
        for (i in 0 until ipv6Index) {
            assertTrue(
                "Non-IPv6 endpoint should come before IPv6: ${calledEndpoints[i]}",
                !calledEndpoints[i].contains("api6.ipify.org"),
            )
        }
        // IPv6 endpoint should be last
        assertEquals(calledEndpoints.lastIndex, ipv6Index)
    }

    private fun newNetwork(netId: Int): Network {
        val constructor = Network::class.java.getDeclaredConstructor(Int::class.javaPrimitiveType)
        constructor.isAccessible = true
        return constructor.newInstance(netId)
    }
}

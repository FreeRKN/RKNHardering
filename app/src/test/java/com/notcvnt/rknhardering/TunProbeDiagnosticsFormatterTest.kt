package com.notcvnt.rknhardering

import com.notcvnt.rknhardering.checker.CheckSettings
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.DnsResolverMode
import com.notcvnt.rknhardering.probe.PublicIpProbeMode
import com.notcvnt.rknhardering.probe.PublicIpProbeStatus
import com.notcvnt.rknhardering.probe.TunEndpointAttempt
import com.notcvnt.rknhardering.probe.TunProbeAttemptDiagnostics
import com.notcvnt.rknhardering.probe.TunProbeDiagnostics
import com.notcvnt.rknhardering.probe.TunProbeModeOverride
import com.notcvnt.rknhardering.probe.TunProbePathDiagnostics
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TunProbeDiagnosticsFormatterTest {

    @Test
    fun `formatter masks public IPs and keeps local addresses`() {
        val diagnostics = TunProbeDiagnostics(
            enabled = true,
            modeOverride = TunProbeModeOverride.AUTO,
            activeNetworkIsVpn = true,
            vpnNetworkPresent = true,
            underlyingNetworkPresent = true,
            vpnPath = TunProbePathDiagnostics(
                interfaceName = "tun0",
                selectedMode = PublicIpProbeMode.CURL_COMPATIBLE,
                selectedIp = "203.0.113.64",
                selectedError = "strict failed for 203.0.113.64",
                dnsPathMismatch = true,
                strict = TunProbeAttemptDiagnostics(
                    mode = PublicIpProbeMode.STRICT_SAME_PATH,
                    status = PublicIpProbeStatus.FAILED,
                    error = "timeout via 203.0.113.64",
                    endpointAttempts = listOf(
                        TunEndpointAttempt(
                            endpoint = "https://ifconfig.me/ip",
                            familyHint = "GENERIC",
                            status = PublicIpProbeStatus.FAILED,
                            error = "timeout from 203.0.113.64",
                        ),
                    ),
                ),
                curlCompatible = TunProbeAttemptDiagnostics(
                    mode = PublicIpProbeMode.CURL_COMPATIBLE,
                    status = PublicIpProbeStatus.SUCCEEDED,
                    ip = "203.0.113.64",
                ),
            ),
            underlyingPath = TunProbePathDiagnostics(
                interfaceName = "wlan0",
                selectedMode = PublicIpProbeMode.STRICT_SAME_PATH,
                selectedIp = "192.168.1.55",
                selectedError = null,
                dnsPathMismatch = false,
                strict = TunProbeAttemptDiagnostics(
                    mode = PublicIpProbeMode.STRICT_SAME_PATH,
                    status = PublicIpProbeStatus.SUCCEEDED,
                    ip = "192.168.1.55",
                ),
                curlCompatible = TunProbeAttemptDiagnostics(
                    mode = PublicIpProbeMode.CURL_COMPATIBLE,
                    status = PublicIpProbeStatus.SKIPPED,
                    error = "Disabled by override",
                ),
            ),
        )

        val report = TunProbeDiagnosticsFormatter.format(
            diagnostics = diagnostics,
            settings = CheckSettings(
                tunProbeDebugEnabled = true,
                tunProbeModeOverride = TunProbeModeOverride.AUTO,
                resolverConfig = DnsResolverConfig(mode = DnsResolverMode.SYSTEM),
            ),
            timestampMillis = 0L,
            appVersionName = "1.0",
            buildType = "debug",
        )

        assertTrue(report.contains("203.0.*.*"))
        assertFalse(report.contains("203.0.113.64"))
        assertTrue(report.contains("192.168.1.55"))
        assertTrue(report.contains("timestamp: 1970-01-01T"))
    }
}

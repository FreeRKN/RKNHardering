package com.notcvnt.rknhardering

import com.notcvnt.rknhardering.checker.CheckSettings
import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.CheckResult
import com.notcvnt.rknhardering.model.IpCheckerGroupResult
import com.notcvnt.rknhardering.model.IpComparisonResult
import com.notcvnt.rknhardering.model.Verdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class MainActivityStateTest {

    @Test
    fun `retain completed diagnostics snapshot keeps snapshot only when debug enabled`() {
        val result = testCheckResult()
        val settings = CheckSettings(tunProbeDebugEnabled = true)

        assertNull(retainCompletedDiagnosticsSnapshot(result, CheckSettings(tunProbeDebugEnabled = false)))

        val snapshot = retainCompletedDiagnosticsSnapshot(result, settings)
        assertSame(result, snapshot?.result)
        assertSame(settings, snapshot?.settings)
    }

    @Test
    fun `retain completed diagnostics snapshot ignores missing settings`() {
        assertNull(retainCompletedDiagnosticsSnapshot(testCheckResult(), settings = null))
    }

    @Test
    fun `create completed export snapshot keeps result privacy mode and timestamp`() {
        val result = testCheckResult()

        val snapshot = createCompletedExportSnapshot(
            result = result,
            privacyMode = true,
            finishedAtMillis = 42L,
        )

        assertSame(result, snapshot.result)
        assertTrue(snapshot.privacyMode)
        assertEquals(42L, snapshot.finishedAtMillis)
    }

    @Test
    fun `completed export snapshot does not depend on debug diagnostics setting`() {
        val result = testCheckResult()

        val exportSnapshot = createCompletedExportSnapshot(
            result = result,
            privacyMode = false,
            finishedAtMillis = 7L,
        )

        assertSame(result, exportSnapshot.result)
        assertNull(retainCompletedDiagnosticsSnapshot(result, CheckSettings(tunProbeDebugEnabled = false)))
    }

    private fun testCheckResult(): CheckResult {
        val emptyCategory = CategoryResult(
            name = "empty",
            detected = false,
            findings = emptyList(),
        )
        return CheckResult(
            geoIp = emptyCategory,
            ipComparison = IpComparisonResult(
                detected = false,
                summary = "",
                ruGroup = IpCheckerGroupResult(
                    title = "RU",
                    detected = false,
                    statusLabel = "",
                    summary = "",
                    responses = emptyList(),
                ),
                nonRuGroup = IpCheckerGroupResult(
                    title = "NON_RU",
                    detected = false,
                    statusLabel = "",
                    summary = "",
                    responses = emptyList(),
                ),
            ),
            directSigns = emptyCategory,
            indirectSigns = emptyCategory,
            locationSignals = emptyCategory,
            bypassResult = BypassResult(
                proxyEndpoint = null,
                directIp = null,
                proxyIp = null,
                xrayApiScanResult = null,
                findings = emptyList(),
                detected = false,
            ),
            verdict = Verdict.NOT_DETECTED,
        )
    }
}

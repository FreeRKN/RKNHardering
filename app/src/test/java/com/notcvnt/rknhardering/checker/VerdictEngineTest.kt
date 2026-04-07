package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.Verdict
import org.junit.Assert.assertEquals
import org.junit.Test

class VerdictEngineTest {

    @Test
    fun `bypass detection always returns detected`() {
        val verdict = VerdictEngine.evaluate(
            geoIpDetected = false,
            directDetected = false,
            indirectDetected = false,
            bypassDetected = true,
        )

        assertEquals(Verdict.DETECTED, verdict)
    }

    @Test
    fun `geoip only returns needs review`() {
        val verdict = VerdictEngine.evaluate(
            geoIpDetected = true,
            directDetected = false,
            indirectDetected = false,
        )

        assertEquals(Verdict.NEEDS_REVIEW, verdict)
    }

    @Test
    fun `geoip with direct evidence returns detected`() {
        val verdict = VerdictEngine.evaluate(
            geoIpDetected = true,
            directDetected = true,
            indirectDetected = false,
        )

        assertEquals(Verdict.DETECTED, verdict)
    }

    @Test
    fun `direct and indirect evidence without geoip returns needs review`() {
        val verdict = VerdictEngine.evaluate(
            geoIpDetected = false,
            directDetected = true,
            indirectDetected = true,
        )

        assertEquals(Verdict.NEEDS_REVIEW, verdict)
    }

    @Test
    fun `review-only direct signal returns needs review`() {
        val verdict = VerdictEngine.evaluate(
            geoIpDetected = false,
            directDetected = false,
            indirectDetected = false,
            directNeedsReview = true,
        )

        assertEquals(Verdict.NEEDS_REVIEW, verdict)
    }

    @Test
    fun `review-only indirect signal returns needs review`() {
        val verdict = VerdictEngine.evaluate(
            geoIpDetected = false,
            directDetected = false,
            indirectDetected = false,
            indirectNeedsReview = true,
        )

        assertEquals(Verdict.NEEDS_REVIEW, verdict)
    }

    @Test
    fun `direct signal alone still does not escalate to detected`() {
        val verdict = VerdictEngine.evaluate(
            geoIpDetected = false,
            directDetected = true,
            indirectDetected = false,
        )

        assertEquals(Verdict.NOT_DETECTED, verdict)
    }
}

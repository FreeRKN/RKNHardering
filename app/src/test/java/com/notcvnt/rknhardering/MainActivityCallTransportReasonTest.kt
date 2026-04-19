package com.notcvnt.rknhardering

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.model.CallTransportLeakResult
import com.notcvnt.rknhardering.model.CallTransportNetworkPath
import com.notcvnt.rknhardering.model.CallTransportProbeKind
import com.notcvnt.rknhardering.model.CallTransportService
import com.notcvnt.rknhardering.model.CallTransportStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class MainActivityCallTransportReasonTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `formatCallTransportReason localizes stun timeout`() {
        val leak = leak(
            status = CallTransportStatus.NO_SIGNAL,
            summary = "Telegram call transport via active network did not receive a STUN response: timeout",
        )

        val reason = formatCallTransportReason(context, leak, privacyMode = false)

        assertEquals(
            "${context.getString(R.string.main_card_call_transport_reason_no_response)}: timeout",
            reason,
        )
    }

    @Test
    fun `formatCallTransportReason masks ip details in privacy mode`() {
        val leak = leak(
            status = CallTransportStatus.NO_SIGNAL,
            summary = "Telegram call transport via active network did not receive a STUN response: timeout from 203.0.113.10",
        )

        val reason = formatCallTransportReason(context, leak, privacyMode = true)

        assertEquals(
            "${context.getString(R.string.main_card_call_transport_reason_no_response)}: timeout from 203.0.*.*",
            reason,
        )
    }

    @Test
    fun `formatCallTransportReason keeps needs review without extra text`() {
        val leak = leak(
            status = CallTransportStatus.BASELINE,
            summary = "Telegram call transport via active network: STUN endpoint responded",
        )

        assertNull(formatCallTransportReason(context, leak, privacyMode = false))
    }

    @Test
    fun `formatCallTransportReason keeps review status without extra text`() {
        val leak = leak(
            status = CallTransportStatus.NEEDS_REVIEW,
            summary = "Telegram call transport via active network: STUN endpoint responded",
        )

        assertNull(formatCallTransportReason(context, leak, privacyMode = false))
    }

    private fun leak(
        service: CallTransportService = CallTransportService.TELEGRAM,
        status: CallTransportStatus,
        summary: String,
    ): CallTransportLeakResult {
        return CallTransportLeakResult(
            service = service,
            probeKind = CallTransportProbeKind.DIRECT_UDP_STUN,
            networkPath = CallTransportNetworkPath.ACTIVE,
            status = status,
            summary = summary,
        )
    }
}

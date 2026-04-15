package com.notcvnt.rknhardering

import android.app.Application
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CheckViewModelTest {

    @Test
    fun `completed diagnostics retention can be consumed and reset`() {
        val viewModel = CheckViewModel(Application())

        assertTrue(viewModel.canRetainCompletedDiagnostics())

        viewModel.markCompletedDiagnosticsConsumed()
        assertFalse(viewModel.canRetainCompletedDiagnostics())

        viewModel.resetCompletedDiagnosticsRetention()
        assertTrue(viewModel.canRetainCompletedDiagnostics())
    }
}

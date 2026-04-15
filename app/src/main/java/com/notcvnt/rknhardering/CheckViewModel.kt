package com.notcvnt.rknhardering

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.notcvnt.rknhardering.checker.CheckSettings
import com.notcvnt.rknhardering.checker.CheckUpdate
import com.notcvnt.rknhardering.checker.VpnCheckRunner
import com.notcvnt.rknhardering.model.CheckResult
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

sealed interface ScanEvent {
    data class Started(val settings: CheckSettings, val privacyMode: Boolean) : ScanEvent
    data class Update(val update: CheckUpdate) : ScanEvent
    data class Completed(val result: CheckResult, val privacyMode: Boolean) : ScanEvent
    data object Cancelled : ScanEvent
}

class CheckViewModel(app: Application) : AndroidViewModel(app) {

    private val _scanEvents = MutableStateFlow<List<ScanEvent>>(emptyList())
    val scanEvents: StateFlow<List<ScanEvent>> = _scanEvents

    private val _isRunning = MutableStateFlow(false)
    val isRunning: StateFlow<Boolean> = _isRunning

    private var scanJob: Job? = null
    private var completedDiagnosticsConsumed = false

    fun startScan(settings: CheckSettings, privacyMode: Boolean) {
        if (scanJob?.isActive == true) return

        resetCompletedDiagnosticsRetention()
        _scanEvents.value = listOf(ScanEvent.Started(settings, privacyMode))
        _isRunning.value = true

        scanJob = viewModelScope.launch {
            try {
                val result = VpnCheckRunner.run(
                    context = getApplication(),
                    settings = settings,
                ) { update ->
                    _scanEvents.value = _scanEvents.value + ScanEvent.Update(update)
                }
                _scanEvents.value = _scanEvents.value + ScanEvent.Completed(result, privacyMode)
            } catch (e: kotlinx.coroutines.CancellationException) {
                _scanEvents.value = _scanEvents.value + ScanEvent.Cancelled
                throw e
            } finally {
                _isRunning.value = false
                scanJob = null
            }
        }
    }

    fun cancelScan() {
        scanJob?.cancel()
    }

    internal fun canRetainCompletedDiagnostics(): Boolean = !completedDiagnosticsConsumed

    internal fun markCompletedDiagnosticsConsumed() {
        completedDiagnosticsConsumed = true
    }

    internal fun resetCompletedDiagnosticsRetention() {
        completedDiagnosticsConsumed = false
    }
}

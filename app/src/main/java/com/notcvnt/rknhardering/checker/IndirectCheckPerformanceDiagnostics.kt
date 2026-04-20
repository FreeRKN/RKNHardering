package com.notcvnt.rknhardering.checker

import android.os.SystemClock
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.StunScope
import java.util.Collections
import java.util.WeakHashMap

internal data class DebugStepTiming(
    val name: String,
    val durationMs: Long,
    val skipped: Boolean = false,
)

internal data class StunScopeTiming(
    val scope: StunScope,
    val durationMs: Long,
    val targetCount: Int,
    val respondedCount: Int,
    val noResponseCount: Int,
)

internal data class CallTransportPerformanceDiagnostics(
    val totalDurationMs: Long,
    val steps: List<DebugStepTiming>,
    val stunScopeTimings: List<StunScopeTiming>,
) {
    val totalStunTargets: Int
        get() = stunScopeTimings.sumOf { it.targetCount }

    val respondedStunTargets: Int
        get() = stunScopeTimings.sumOf { it.respondedCount }

    val noResponseStunTargets: Int
        get() = stunScopeTimings.sumOf { it.noResponseCount }
}

internal data class IndirectCheckPerformanceDiagnostics(
    val totalDurationMs: Long,
    val steps: List<DebugStepTiming>,
    val callTransport: CallTransportPerformanceDiagnostics? = null,
) {
    val slowestStep: DebugStepTiming?
        get() = steps.maxByOrNull { it.durationMs }
}

internal data class IndirectDelaySummary(
    val label: String,
    val durationMs: Long,
)

internal object IndirectCheckPerformanceRegistry {
    private val diagnosticsByCategory =
        Collections.synchronizedMap(WeakHashMap<CategoryResult, IndirectCheckPerformanceDiagnostics>())

    fun attach(category: CategoryResult, diagnostics: IndirectCheckPerformanceDiagnostics) {
        diagnosticsByCategory[category] = diagnostics
    }

    fun find(category: CategoryResult): IndirectCheckPerformanceDiagnostics? {
        return diagnosticsByCategory[category]
    }
}

internal object IndirectCheckPerformanceSupport {
    fun monotonicNowMs(): Long = SystemClock.elapsedRealtime()

    fun elapsedSince(startedAtMs: Long): Long = (monotonicNowMs() - startedAtMs).coerceAtLeast(0L)

    inline fun <T> measureStep(
        name: String,
        collector: MutableList<DebugStepTiming>,
        block: () -> T,
    ): T {
        val startedAtMs = monotonicNowMs()
        return try {
            block()
        } finally {
            collector += DebugStepTiming(name = name, durationMs = elapsedSince(startedAtMs))
        }
    }

    suspend inline fun <T> measureSuspendStep(
        name: String,
        collector: MutableList<DebugStepTiming>,
        crossinline block: suspend () -> T,
    ): T {
        val startedAtMs = monotonicNowMs()
        return try {
            block()
        } finally {
            collector += DebugStepTiming(name = name, durationMs = elapsedSince(startedAtMs))
        }
    }

    fun markSkippedStep(
        name: String,
        collector: MutableList<DebugStepTiming>,
    ) {
        collector += DebugStepTiming(name = name, durationMs = 0L, skipped = true)
    }
}

internal fun IndirectCheckPerformanceDiagnostics.summarizeDominantDelay(): IndirectDelaySummary {
    val stunDuration = callTransport?.steps
        ?.firstOrNull { it.name == "probeStunTargets" }
        ?.durationMs
        ?: 0L
    val dumpsysDuration = steps
        .filter { it.name == "checkDumpsysVpn" || it.name == "checkDumpsysVpnService" }
        .sumOf { it.durationMs }

    return when {
        stunDuration > 0L &&
            dumpsysDuration > 0L &&
            stunDuration >= totalDurationMs / 4 &&
            dumpsysDuration >= totalDurationMs / 4 ->
            IndirectDelaySummary(label = "STUN sweep + dumpsys", durationMs = maxOf(stunDuration, dumpsysDuration))

        stunDuration >= dumpsysDuration && stunDuration > 0L ->
            IndirectDelaySummary(label = "STUN sweep", durationMs = stunDuration)

        dumpsysDuration > stunDuration && dumpsysDuration > 0L ->
            IndirectDelaySummary(label = "dumpsys", durationMs = dumpsysDuration)

        else -> {
            val slowest = slowestStep
            IndirectDelaySummary(
                label = slowest?.name ?: "other",
                durationMs = slowest?.durationMs ?: 0L,
            )
        }
    }
}

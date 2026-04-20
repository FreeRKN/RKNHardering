package com.notcvnt.rknhardering.checker

import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CallTransportNetworkPath
import com.notcvnt.rknhardering.model.CallTransportStatus
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.IpConsensusResult
import com.notcvnt.rknhardering.model.Verdict

object VerdictEngine {

    private val HARD_DETECT_BYPASS = setOf(
        EvidenceSource.SPLIT_TUNNEL_BYPASS,
        EvidenceSource.XRAY_API,
        EvidenceSource.VPN_GATEWAY_LEAK,
        EvidenceSource.VPN_NETWORK_BINDING,
    )

    private val HARD_DETECT_DIRECT = setOf(
        EvidenceSource.DIRECT_NETWORK_CAPABILITIES,
        EvidenceSource.SYSTEM_PROXY,
    )

    private val MATRIX_INDIRECT_SOURCES = setOf(
        EvidenceSource.INDIRECT_NETWORK_CAPABILITIES,
        EvidenceSource.ACTIVE_VPN,
        EvidenceSource.NETWORK_INTERFACE,
        EvidenceSource.ROUTING,
        EvidenceSource.DNS,
        EvidenceSource.PROXY_TECHNICAL_SIGNAL,
        EvidenceSource.NATIVE_INTERFACE,
        EvidenceSource.NATIVE_ROUTE,
        EvidenceSource.NATIVE_JVM_MISMATCH,
    )

    private val NATIVE_REVIEW_SOURCES = setOf(
        EvidenceSource.NATIVE_HOOK_MARKERS,
        EvidenceSource.NATIVE_LIBRARY_INTEGRITY,
    )

    fun evaluate(
        geoIp: CategoryResult,
        directSigns: CategoryResult,
        indirectSigns: CategoryResult,
        locationSignals: CategoryResult,
        bypassResult: BypassResult,
        ipConsensus: IpConsensusResult,
        nativeSigns: CategoryResult = CategoryResult(name = "", detected = false, findings = emptyList()),
        icmpSpoofing: CategoryResult = CategoryResult(name = "", detected = false, findings = emptyList()),
    ): Verdict {
        // R1
        if (bypassResult.evidence.any { it.detected && it.source in HARD_DETECT_BYPASS }) {
            return Verdict.DETECTED
        }

        // R2
        if (directSigns.evidence.any { it.detected && it.source in HARD_DETECT_DIRECT }) {
            return Verdict.DETECTED
        }

        // R3
        if (ipConsensus.probeTargetDivergence) {
            return Verdict.DETECTED
        }
        val geoAxis = ipConsensus.foreignIps.isNotEmpty() ||
            ipConsensus.geoCountryMismatch ||
            ipConsensus.warpLikeIndicator
        if (ipConsensus.probeTargetDirectDivergence && geoAxis) {
            return Verdict.DETECTED
        }
        if (ipConsensus.crossChannelMismatch && geoAxis) {
            return Verdict.DETECTED
        }

        // R4
        val locationConfirmsRussia = locationSignals.findings.any {
            it.description.contains("network_mcc_ru:true") ||
                it.description.contains("cell_country_ru:true") ||
                it.description.contains("location_country_ru:true")
        }
        val geo = geoIp.geoFacts
        val anyOtherSignal = directSigns.evidence.any { it.detected } ||
            indirectSigns.evidence.any { it.detected } ||
            ipConsensus.crossChannelMismatch ||
            ipConsensus.probeTargetDivergence ||
            ipConsensus.probeTargetDirectDivergence
        if (locationConfirmsRussia && geo?.outsideRu == true) {
            return Verdict.DETECTED
        }
        if (locationConfirmsRussia &&
            (geo?.hosting == true || geo?.proxyDb == true) &&
            geo.outsideRu != true &&
            !anyOtherSignal
        ) {
            return Verdict.NEEDS_REVIEW
        }

        // R5 — 2-bit matrix (geo x indirect)
        val geoHit = geo?.outsideRu == true
        val indirectHit = indirectSigns.evidence.any { it.detected && it.source in MATRIX_INDIRECT_SOURCES } ||
            nativeSigns.evidence.any { it.detected && it.source in MATRIX_INDIRECT_SOURCES }
        val matrix = when {
            !geoHit && !indirectHit -> Verdict.NOT_DETECTED
            !geoHit && indirectHit -> Verdict.NOT_DETECTED
            geoHit && !indirectHit -> Verdict.NEEDS_REVIEW
            else -> Verdict.DETECTED
        }

        // R6 — needs-review fallbacks
        val hasActionableCallTransportLeak = indirectSigns.callTransportLeaks.any {
            it.status == CallTransportStatus.NEEDS_REVIEW &&
                it.networkPath != CallTransportNetworkPath.LOCAL_PROXY
        }
        val nativeReviewHit = nativeSigns.evidence.any { it.detected && it.source in NATIVE_REVIEW_SOURCES }
        val tunProbeReview = directSigns.evidence.any {
            it.source == EvidenceSource.TUN_ACTIVE_PROBE && !it.detected
        }
        if (matrix == Verdict.NOT_DETECTED && (
                bypassResult.needsReview ||
                    hasActionableCallTransportLeak ||
                    icmpSpoofing.needsReview ||
                    nativeReviewHit ||
                    ipConsensus.needsReview ||
                    ipConsensus.channelConflict.isNotEmpty() ||
                    tunProbeReview
                )
        ) {
            return Verdict.NEEDS_REVIEW
        }

        return matrix
    }
}

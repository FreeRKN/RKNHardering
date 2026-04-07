package com.notcvnt.rknhardering.checker

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Proxy
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.EvidenceConfidence
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.MatchedVpnApp
import com.notcvnt.rknhardering.vpn.InstalledVpnAppDetector

object DirectSignsChecker {

    private data class SignalOutcome(
        val detected: Boolean = false,
        val needsReview: Boolean = false,
    )

    private val KNOWN_PROXY_PORTS = setOf(
        80, 443, 1080, 3127, 3128, 4080, 5555,
        7000, 7044, 8000, 8080, 8081, 8082, 8888,
        9000, 9050, 9051, 9150, 12345,
    )
    private val KNOWN_PROXY_PORT_RANGES = listOf(16000..16100)

    fun check(context: Context): CategoryResult {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()
        val matchedApps = mutableListOf<MatchedVpnApp>()
        var detected = false
        var needsReview = false

        val vpnTransportOutcome = checkVpnTransport(context, findings, evidence)
        detected = detected || vpnTransportOutcome.detected
        needsReview = needsReview || vpnTransportOutcome.needsReview

        val systemProxyOutcome = checkSystemProxy(findings, evidence)
        detected = detected || systemProxyOutcome.detected
        needsReview = needsReview || systemProxyOutcome.needsReview

        val appDetection = InstalledVpnAppDetector.detect(context)
        findings += appDetection.findings
        evidence += appDetection.evidence
        matchedApps += appDetection.matchedApps
        needsReview = needsReview || appDetection.needsReview

        return CategoryResult(
            name = "Прямые признаки",
            detected = detected,
            findings = findings,
            needsReview = needsReview,
            evidence = evidence,
            matchedApps = matchedApps,
        )
    }

    private fun checkVpnTransport(
        context: Context,
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
    ): SignalOutcome {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val activeNetwork = cm.activeNetwork
        if (activeNetwork == null) {
            findings.add(Finding("Активная сеть не найдена"))
            return SignalOutcome()
        }

        val caps = cm.getNetworkCapabilities(activeNetwork)
        if (caps == null) {
            findings.add(Finding("NetworkCapabilities недоступны"))
            return SignalOutcome()
        }

        var detected = false
        val hasVpnTransport = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        findings.add(
            Finding(
                description = "TRANSPORT_VPN: ${if (hasVpnTransport) "обнаружен" else "не обнаружен"}",
                detected = hasVpnTransport,
                source = EvidenceSource.NETWORK_CAPABILITIES,
                confidence = hasVpnTransport.takeIf { it }?.let { EvidenceConfidence.HIGH },
            ),
        )
        if (hasVpnTransport) {
            detected = true
            evidence.add(
                EvidenceItem(
                    source = EvidenceSource.NETWORK_CAPABILITIES,
                    detected = true,
                    confidence = EvidenceConfidence.HIGH,
                    description = "Active network reports TRANSPORT_VPN",
                ),
            )
        }

        val capsString = caps.toString()
        val hasIsVpn = capsString.contains("IS_VPN")
        if (hasIsVpn) {
            detected = true
            findings.add(
                Finding(
                    description = "Флаг IS_VPN обнаружен в capabilities",
                    detected = true,
                    source = EvidenceSource.NETWORK_CAPABILITIES,
                    confidence = EvidenceConfidence.HIGH,
                ),
            )
            evidence.add(
                EvidenceItem(
                    source = EvidenceSource.NETWORK_CAPABILITIES,
                    detected = true,
                    confidence = EvidenceConfidence.HIGH,
                    description = "NetworkCapabilities string contains IS_VPN",
                ),
            )
        }

        val hasVpnTransportInfo = capsString.contains("VpnTransportInfo")
        if (hasVpnTransportInfo) {
            detected = true
            findings.add(
                Finding(
                    description = "VpnTransportInfo обнаружен в транспортной информации",
                    detected = true,
                    source = EvidenceSource.NETWORK_CAPABILITIES,
                    confidence = EvidenceConfidence.HIGH,
                ),
            )
            evidence.add(
                EvidenceItem(
                    source = EvidenceSource.NETWORK_CAPABILITIES,
                    detected = true,
                    confidence = EvidenceConfidence.HIGH,
                    description = "NetworkCapabilities string contains VpnTransportInfo",
                ),
            )
        }

        return SignalOutcome(detected = detected)
    }

    @Suppress("DEPRECATION")
    private fun checkSystemProxy(
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
    ): SignalOutcome {
        val httpHost = System.getProperty("http.proxyHost") ?: Proxy.getDefaultHost()
        val httpPort = System.getProperty("http.proxyPort")
            ?: Proxy.getDefaultPort().takeIf { it > 0 }?.toString()
        val socksHost = System.getProperty("socksProxyHost")
        val socksPort = System.getProperty("socksProxyPort")
        var needsReview = false

        needsReview = addProxyFinding(
            type = "HTTP прокси",
            host = httpHost,
            port = httpPort,
            findings = findings,
            evidence = evidence,
        ) || needsReview

        needsReview = addProxyFinding(
            type = "SOCKS прокси",
            host = socksHost,
            port = socksPort,
            findings = findings,
            evidence = evidence,
        ) || needsReview

        return SignalOutcome(needsReview = needsReview)
    }

    private fun addProxyFinding(
        type: String,
        host: String?,
        port: String?,
        findings: MutableList<Finding>,
        evidence: MutableList<EvidenceItem>,
    ): Boolean {
        if (host.isNullOrBlank()) {
            findings.add(Finding("$type: не настроен"))
            return false
        }

        val knownPort = isKnownProxyPort(port)
        val confidence = if (knownPort) EvidenceConfidence.MEDIUM else EvidenceConfidence.LOW
        val description = "$type: $host:${port ?: "N/A"}"

        findings.add(
            Finding(
                description = description,
                needsReview = true,
                source = EvidenceSource.SYSTEM_PROXY,
                confidence = confidence,
            ),
        )
        evidence.add(
            EvidenceItem(
                source = EvidenceSource.SYSTEM_PROXY,
                detected = true,
                confidence = confidence,
                description = description,
            ),
        )

        if (knownPort) {
            findings.add(
                Finding(
                    description = "$type использует характерный порт $port",
                    needsReview = true,
                    source = EvidenceSource.SYSTEM_PROXY,
                    confidence = EvidenceConfidence.MEDIUM,
                ),
            )
            evidence.add(
                EvidenceItem(
                    source = EvidenceSource.SYSTEM_PROXY,
                    detected = true,
                    confidence = EvidenceConfidence.MEDIUM,
                    description = "$type uses known proxy port $port",
                ),
            )
        }

        return true
    }

    internal fun isKnownProxyPort(port: String?): Boolean {
        val value = port?.toIntOrNull() ?: return false
        return value in KNOWN_PROXY_PORTS || KNOWN_PROXY_PORT_RANGES.any { value in it }
    }
}

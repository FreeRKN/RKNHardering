package com.notcvnt.rknhardering

import com.notcvnt.rknhardering.checker.CheckSettings
import com.notcvnt.rknhardering.model.ActiveVpnApp
import com.notcvnt.rknhardering.model.BypassResult
import com.notcvnt.rknhardering.model.CallTransportLeakResult
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.CheckResult
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.model.IpCheckerGroupResult
import com.notcvnt.rknhardering.model.IpCheckerResponse
import com.notcvnt.rknhardering.model.IpComparisonResult
import com.notcvnt.rknhardering.model.LocalProxyOwner
import com.notcvnt.rknhardering.model.MatchedVpnApp
import com.notcvnt.rknhardering.probe.XrayApiScanResult
import com.notcvnt.rknhardering.probe.XrayOutboundSummary
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object DebugDiagnosticsFormatter {

    fun format(
        result: CheckResult,
        settings: CheckSettings,
        privacyMode: Boolean,
        timestampMillis: Long = System.currentTimeMillis(),
        appVersionName: String = BuildConfig.VERSION_NAME,
        buildType: String = BuildConfig.BUILD_TYPE,
    ): String {
        val builder = StringBuilder()
        builder.appendLine("timestamp: ${formatTimestamp(timestampMillis)}")
        builder.appendLine("app: $appVersionName ($buildType)")
        builder.appendLine("debugDiagnosticsEnabled: ${settings.tunProbeDebugEnabled}")
        builder.appendLine("privacyMode: $privacyMode")
        builder.appendLine("splitTunnelEnabled: ${settings.splitTunnelEnabled}")
        builder.appendLine("proxyScanEnabled: ${settings.proxyScanEnabled}")
        builder.appendLine("xrayApiScanEnabled: ${settings.xrayApiScanEnabled}")
        builder.appendLine("networkRequestsEnabled: ${settings.networkRequestsEnabled}")
        builder.appendLine("callTransportProbeEnabled: ${settings.callTransportProbeEnabled}")
        builder.appendLine("tunProbeModeOverride: ${settings.tunProbeModeOverride.name}")
        appendResolver(builder, settings)
        builder.appendLine("verdict: ${result.verdict}")

        appendCategory(builder, "geoIp", result.geoIp)
        appendIpComparison(builder, result.ipComparison)
        appendCategory(builder, "directSigns", result.directSigns)
        appendCategory(builder, "indirectSigns", result.indirectSigns)
        appendCategory(builder, "locationSignals", result.locationSignals)
        appendBypass(builder, result.bypassResult)

        builder.appendLine()
        builder.appendLine("[tunProbe]")
        val tunDiagnostics = result.tunProbeDiagnostics
        if (tunDiagnostics == null) {
            builder.appendLine("collected: false")
        } else {
            builder.appendLine("collected: true")
            builder.append(TunProbeDiagnosticsFormatter.formatSection(tunDiagnostics, settings))
            builder.appendLine()
        }
        return builder.toString().trimEnd()
    }

    private fun appendCategory(
        builder: StringBuilder,
        key: String,
        category: CategoryResult,
    ) {
        builder.appendLine()
        builder.appendLine("[$key]")
        builder.appendLine("name: ${category.name}")
        builder.appendLine("detected: ${category.detected}")
        builder.appendLine("needsReview: ${category.needsReview}")
        builder.appendLine("hasError: ${category.hasError}")
        builder.appendLine("findingsCount: ${category.findings.size}")
        builder.appendLine("evidenceCount: ${category.evidence.size}")
        builder.appendLine("matchedAppsCount: ${category.matchedApps.size}")
        builder.appendLine("activeAppsCount: ${category.activeApps.size}")
        builder.appendLine("callTransportCount: ${category.callTransportLeaks.size}")
        builder.appendLine("findings:")
        if (category.findings.isEmpty()) {
            builder.appendLine("- <none>")
        } else {
            category.findings.forEach { finding ->
                builder.appendLine("- ${formatFinding(finding)}")
            }
        }

        appendNamedCollection(builder, "evidence", category.evidence, ::formatEvidence)
        appendNamedCollection(builder, "matchedApps", category.matchedApps, ::formatMatchedVpnApp)
        appendNamedCollection(builder, "activeApps", category.activeApps, ::formatActiveVpnApp)
        appendNamedCollection(builder, "callTransport", category.callTransportLeaks, ::formatCallTransportLeak)
    }

    private fun appendIpComparison(
        builder: StringBuilder,
        ipComparison: IpComparisonResult,
    ) {
        builder.appendLine()
        builder.appendLine("[ipComparison]")
        builder.appendLine("detected: ${ipComparison.detected}")
        builder.appendLine("needsReview: ${ipComparison.needsReview}")
        builder.appendLine("summary: ${maskIpsInText(ipComparison.summary)}")
        appendIpCheckerGroup(builder, "ru", ipComparison.ruGroup)
        appendIpCheckerGroup(builder, "nonRu", ipComparison.nonRuGroup)
    }

    private fun appendBypass(
        builder: StringBuilder,
        bypass: BypassResult,
    ) {
        builder.appendLine()
        builder.appendLine("[bypass]")
        builder.appendLine("detected: ${bypass.detected}")
        builder.appendLine("needsReview: ${bypass.needsReview}")
        builder.appendLine("directIp: ${bypass.directIp?.let(::maskIp) ?: "<none>"}")
        builder.appendLine("proxyIp: ${bypass.proxyIp?.let(::maskIp) ?: "<none>"}")
        builder.appendLine("vpnNetworkIp: ${bypass.vpnNetworkIp?.let(::maskIp) ?: "<none>"}")
        builder.appendLine("underlyingIp: ${bypass.underlyingIp?.let(::maskIp) ?: "<none>"}")
        builder.appendLine("proxyEndpoint: ${formatProxyEndpoint(bypass)}")
        builder.appendLine("proxyOwner: ${formatProxyOwner(bypass.proxyOwner)}")
        builder.appendLine("xrayApi: ${formatXrayApiHeader(bypass.xrayApiScanResult)}")
        builder.appendLine("findings:")
        if (bypass.findings.isEmpty()) {
            builder.appendLine("- <none>")
        } else {
            bypass.findings.forEach { finding ->
                builder.appendLine("- ${formatFinding(finding)}")
            }
        }
        appendNamedCollection(
            builder = builder,
            label = "evidence",
            items = bypass.evidence,
            formatter = ::formatEvidence,
        )
        appendNamedCollection(
            builder = builder,
            label = "xrayOutbounds",
            items = bypass.xrayApiScanResult?.outbounds.orEmpty(),
            formatter = ::formatXrayOutbound,
        )
    }

    private fun appendResolver(
        builder: StringBuilder,
        settings: CheckSettings,
    ) {
        val resolver = settings.resolverConfig
        builder.appendLine("resolverMode: ${resolver.mode}")
        builder.appendLine("resolverPreset: ${resolver.preset}")
        builder.appendLine(
            "resolverDirectServers: ${
                resolver.effectiveDirectServers().joinToString(", ") { maskIp(it) }.ifBlank { "<none>" }
            }",
        )
        builder.appendLine("resolverDohUrl: ${resolver.effectiveDohUrl() ?: "<none>"}")
        builder.appendLine(
            "resolverDohBootstrap: ${
                resolver.effectiveDohBootstrapHosts().joinToString(", ") { maskIp(it) }.ifBlank { "<none>" }
            }",
        )
    }

    private fun appendIpCheckerGroup(
        builder: StringBuilder,
        label: String,
        group: IpCheckerGroupResult,
    ) {
        builder.appendLine("$label.title: ${group.title}")
        builder.appendLine("$label.detected: ${group.detected}")
        builder.appendLine("$label.needsReview: ${group.needsReview}")
        builder.appendLine("$label.statusLabel: ${group.statusLabel}")
        builder.appendLine("$label.summary: ${maskIpsInText(group.summary)}")
        builder.appendLine("$label.canonicalIp: ${group.canonicalIp?.let(::maskIp) ?: "<none>"}")
        builder.appendLine("$label.ignoredIpv6ErrorCount: ${group.ignoredIpv6ErrorCount}")
        builder.appendLine("$label.responses:")
        if (group.responses.isEmpty()) {
            builder.appendLine("- <none>")
            return
        }
        group.responses.forEach { response ->
            builder.appendLine("- ${formatIpCheckerResponse(response)}")
        }
    }

    private fun <T> appendNamedCollection(
        builder: StringBuilder,
        label: String,
        items: List<T>,
        formatter: (T) -> String,
    ) {
        builder.appendLine("$label:")
        if (items.isEmpty()) {
            builder.appendLine("- <none>")
            return
        }
        items.forEach { item ->
            builder.appendLine("- ${formatter(item)}")
        }
    }

    private fun formatFinding(finding: Finding): String {
        return buildList {
            add("description=${maskIpsInText(finding.description)}")
            add("detected=${finding.detected}")
            add("needsReview=${finding.needsReview}")
            add("error=${finding.isError}")
            add("informational=${finding.isInformational}")
            finding.source?.let { add("source=$it") }
            finding.confidence?.let { add("confidence=$it") }
            finding.family?.let { add("family=$it") }
            finding.packageName?.let { add("package=$it") }
        }.joinToString(" ")
    }

    private fun formatEvidence(item: EvidenceItem): String {
        return buildList {
            add("source=${item.source}")
            add("detected=${item.detected}")
            add("confidence=${item.confidence}")
            item.kind?.let { add("kind=$it") }
            item.family?.let { add("family=$it") }
            item.packageName?.let { add("package=$it") }
            add("description=${maskIpsInText(item.description)}")
        }.joinToString(" ")
    }

    private fun formatMatchedVpnApp(app: MatchedVpnApp): String {
        return buildList {
            add("appName=${app.appName}")
            add("package=${app.packageName}")
            app.family?.let { add("family=$it") }
            add("kind=${app.kind}")
            add("source=${app.source}")
            add("active=${app.active}")
            add("confidence=${app.confidence}")
        }.joinToString(" ")
    }

    private fun formatActiveVpnApp(app: ActiveVpnApp): String {
        return buildList {
            add("package=${app.packageName ?: "<none>"}")
            add("serviceName=${app.serviceName ?: "<none>"}")
            add("family=${app.family ?: "<none>"}")
            add("kind=${app.kind ?: "<none>"}")
            add("source=${app.source}")
            add("confidence=${app.confidence}")
        }.joinToString(" ")
    }

    private fun formatCallTransportLeak(leak: CallTransportLeakResult): String {
        return buildList {
            add("service=${leak.service}")
            add("probeKind=${leak.probeKind}")
            add("networkPath=${leak.networkPath}")
            add("status=${leak.status}")
            leak.targetHost?.let { add("targetHost=${maskHostOrIp(it)}") }
            leak.targetPort?.let { add("targetPort=$it") }
            add(
                "resolvedIps=${
                    leak.resolvedIps.joinToString(", ") { maskIp(it) }.ifBlank { "<none>" }
                }",
            )
            leak.mappedIp?.let { add("mappedIp=${maskIp(it)}") }
            leak.observedPublicIp?.let { add("observedPublicIp=${maskIp(it)}") }
            leak.confidence?.let { add("confidence=$it") }
            add("experimental=${leak.experimental}")
            add("summary=${maskIpsInText(leak.summary)}")
        }.joinToString(" ")
    }

    private fun formatIpCheckerResponse(response: IpCheckerResponse): String {
        return buildList {
            add("label=${response.label}")
            add("scope=${response.scope}")
            add("url=${response.url}")
            add("ip=${response.ip?.let(::maskIp) ?: "<none>"}")
            add("error=${response.error?.let(::maskIpsInText) ?: "<none>"}")
            add(
                "ipv4Records=${
                    response.ipv4Records.joinToString(", ") { maskIp(it) }.ifBlank { "<none>" }
                }",
            )
            add(
                "ipv6Records=${
                    response.ipv6Records.joinToString(", ") { maskIp(it) }.ifBlank { "<none>" }
                }",
            )
            add("ignoredIpv6Error=${response.ignoredIpv6Error}")
        }.joinToString(" ")
    }

    private fun formatProxyEndpoint(bypass: BypassResult): String {
        val proxyEndpoint = bypass.proxyEndpoint ?: return "<none>"
        return "${maskHostOrIp(proxyEndpoint.host)}:${proxyEndpoint.port} (${proxyEndpoint.type})"
    }

    private fun formatProxyOwner(owner: LocalProxyOwner?): String {
        if (owner == null) return "<none>"
        return buildList {
            add("uid=${owner.uid}")
            add("confidence=${owner.confidence}")
            add("apps=${owner.appLabels.joinToString(", ").ifBlank { "<none>" }}")
            add("packages=${owner.packageNames.joinToString(", ").ifBlank { "<none>" }}")
        }.joinToString(" ")
    }

    private fun formatXrayApiHeader(scanResult: XrayApiScanResult?): String {
        if (scanResult == null) return "<none>"
        return "endpoint=${maskHostOrIp(scanResult.endpoint.host)}:${scanResult.endpoint.port} outboundCount=${scanResult.outbounds.size}"
    }

    private fun formatXrayOutbound(outbound: XrayOutboundSummary): String {
        return buildList {
            add("tag=${outbound.tag}")
            add("protocol=${outbound.protocolName ?: "<none>"}")
            add("address=${outbound.address?.let(::maskHostOrIp) ?: "<none>"}")
            add("port=${outbound.port ?: "<none>"}")
            add("sni=${outbound.sni ?: "<none>"}")
            add("senderSettingsType=${outbound.senderSettingsType ?: "<none>"}")
            add("proxySettingsType=${outbound.proxySettingsType ?: "<none>"}")
            add("uuidPresent=${!outbound.uuid.isNullOrBlank()}")
            add("publicKeyPresent=${!outbound.publicKey.isNullOrBlank()}")
        }.joinToString(" ")
    }

    private fun maskHostOrIp(value: String): String {
        return if (isIpLiteral(value)) maskIp(value) else value
    }

    private fun isIpLiteral(value: String): Boolean {
        if (value.matches(IPV4_LITERAL)) return true
        return value.contains(':') && value.all { char ->
            char.isDigit() || char.lowercaseChar() in 'a'..'f' || char == ':' || char == '%'
        }
    }

    private fun formatTimestamp(timestampMillis: Long): String {
        return SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.US).format(Date(timestampMillis))
    }

    private val IPV4_LITERAL = Regex("""^(?:\d{1,3}\.){3}\d{1,3}$""")
}

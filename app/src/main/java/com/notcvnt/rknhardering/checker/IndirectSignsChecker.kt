package com.notcvnt.rknhardering.checker

import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.Finding
import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import java.net.NetworkInterface

object IndirectSignsChecker {

    private data class SignalOutcome(
        val detected: Boolean = false,
        val needsReview: Boolean = false,
    )

    internal enum class DnsClassification {
        LOOPBACK,
        PRIVATE_TUNNEL,
        KNOWN_PUBLIC_RESOLVER,
        LINK_LOCAL,
        OTHER_PUBLIC,
    }

    private val VPN_INTERFACE_PATTERNS = listOf(
        Regex("^tun\\d+"),
        Regex("^tap\\d+"),
        Regex("^wg\\d+"),
        Regex("^ppp\\d+"),
        Regex("^ipsec.*")
    )

    private val STANDARD_INTERFACES = listOf(
        Regex("^wlan.*"),
        Regex("^rmnet.*"),
        Regex("^eth.*"),
        Regex("^lo$")
    )

    private val KNOWN_PUBLIC_RESOLVERS = setOf(
        "1.1.1.1", "1.0.0.1",
        "8.8.8.8", "8.8.4.4",
        "9.9.9.9", "149.112.112.112",
        "208.67.222.222", "208.67.220.220",
        "94.140.14.14", "94.140.15.15",
        "77.88.8.8", "77.88.8.1",
        "76.76.19.19",
        "2606:4700:4700::1111", "2606:4700:4700::1001",
        "2001:4860:4860::8888", "2001:4860:4860::8844",
        "2620:fe::fe", "2620:fe::9",
        "2620:119:35::35", "2620:119:53::53",
        "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"
    )

    fun check(context: Context): CategoryResult {
        val findings = mutableListOf<Finding>()
        var detected = false
        var needsReview = false

        detected = checkNotVpnCapability(context, findings) || detected
        detected = checkNetworkInterfaces(findings) || detected
        detected = checkMtu(findings) || detected
        detected = checkRoutingTable(findings) || detected

        val dnsOutcome = checkDns(context, findings)
        detected = dnsOutcome.detected || detected
        needsReview = dnsOutcome.needsReview || needsReview

        detected = checkDumpsysVpn(findings) || detected
        detected = checkDumpsysVpnService(findings) || detected

        return CategoryResult(
            name = "Косвенные признаки",
            detected = detected,
            findings = findings,
            needsReview = needsReview,
        )
    }

    private fun checkNotVpnCapability(context: Context, findings: MutableList<Finding>): Boolean {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val activeNetwork = cm.activeNetwork ?: return false
        val caps = cm.getNetworkCapabilities(activeNetwork) ?: return false

        val capsString = caps.toString()
        val hasNotVpn = capsString.contains("NOT_VPN")
        findings.add(
            Finding(
                "Capability NOT_VPN: ${if (hasNotVpn) "присутствует" else "отсутствует (подозрительно)"}",
                detected = !hasNotVpn,
            )
        )
        return !hasNotVpn
    }

    private fun checkNetworkInterfaces(findings: MutableList<Finding>): Boolean {
        try {
            val interfaces = NetworkInterface.getNetworkInterfaces()?.toList() ?: emptyList()
            val vpnInterfaces = interfaces.filter { iface ->
                iface.isUp && VPN_INTERFACE_PATTERNS.any { pattern -> pattern.matches(iface.name) }
            }

            if (vpnInterfaces.isNotEmpty()) {
                for (iface in vpnInterfaces) {
                    findings.add(Finding("VPN-интерфейс обнаружен: ${iface.name}", detected = true))
                }
                return true
            }

            findings.add(Finding("VPN-интерфейсы (tun/tap/wg/ppp/ipsec): не обнаружены"))
        } catch (e: Exception) {
            findings.add(Finding("Ошибка при проверке интерфейсов: ${e.message}"))
        }

        return false
    }

    private fun checkMtu(findings: MutableList<Finding>): Boolean {
        try {
            val interfaces = NetworkInterface.getNetworkInterfaces()?.toList() ?: emptyList()
            var detected = false
            for (iface in interfaces) {
                if (!iface.isUp) continue
                val isVpnLike = VPN_INTERFACE_PATTERNS.any { it.matches(iface.name) }
                if (!isVpnLike) continue

                val mtu = iface.mtu
                if (mtu in 1..1499) {
                    findings.add(
                        Finding("MTU аномалия: ${iface.name} MTU=$mtu (< 1500)", detected = true)
                    )
                    detected = true
                }
            }

            val activeInterfaces = interfaces.filter { it.isUp && it.mtu in 1..1499 }
            val nonVpnLowMtu = activeInterfaces.filter { iface ->
                !VPN_INTERFACE_PATTERNS.any { it.matches(iface.name) } &&
                    !STANDARD_INTERFACES.any { it.matches(iface.name) }
            }
            for (iface in nonVpnLowMtu) {
                findings.add(
                    Finding(
                        "MTU аномалия: нестандартный интерфейс ${iface.name} MTU=${iface.mtu}",
                        detected = true,
                    )
                )
                detected = true
            }

            if (findings.none { it.description.startsWith("MTU") }) {
                findings.add(Finding("MTU: аномалий не обнаружено"))
            }

            return detected
        } catch (e: Exception) {
            findings.add(Finding("Ошибка при проверке MTU: ${e.message}"))
        }

        return false
    }

    private fun checkRoutingTable(findings: MutableList<Finding>): Boolean {
        try {
            val routeFile = File("/proc/net/route")
            if (!routeFile.exists()) {
                findings.add(Finding("Таблица маршрутизации: /proc/net/route недоступен"))
                return false
            }

            val lines = BufferedReader(FileReader(routeFile)).use { it.readLines() }
            val defaultRoutes = lines.drop(1).filter { line ->
                val parts = line.trim().split("\\s+".toRegex())
                parts.size >= 2 && parts[1] == "00000000"
            }

            if (defaultRoutes.isEmpty()) {
                findings.add(Finding("Маршрут по умолчанию: не найден"))
                return false
            }

            var detected = false
            for (route in defaultRoutes) {
                val parts = route.trim().split("\\s+".toRegex())
                val iface = parts[0]
                val isStandard = STANDARD_INTERFACES.any { it.matches(iface) }
                if (!isStandard) {
                    findings.add(
                        Finding(
                            "Маршрут по умолчанию через нестандартный интерфейс: $iface",
                            detected = true,
                        )
                    )
                    detected = true
                } else {
                    findings.add(Finding("Маршрут по умолчанию: $iface (стандартный)"))
                }
            }

            return detected
        } catch (e: Exception) {
            findings.add(Finding("Ошибка при проверке маршрутов: ${e.message}"))
        }

        return false
    }

    private fun checkDns(context: Context, findings: MutableList<Finding>): SignalOutcome {
        try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val activeNetwork = cm.activeNetwork
            if (activeNetwork == null) {
                findings.add(Finding("DNS: активная сеть не найдена"))
                return SignalOutcome()
            }

            val linkProperties = cm.getLinkProperties(activeNetwork)
            if (linkProperties == null) {
                findings.add(Finding("DNS: LinkProperties недоступны"))
                return SignalOutcome()
            }

            val dnsServers = linkProperties.dnsServers
            if (dnsServers.isEmpty()) {
                findings.add(Finding("DNS серверы: не обнаружены"))
                return SignalOutcome()
            }

            var detected = false
            var needsReview = false
            for (dns in dnsServers) {
                val addr = dns.hostAddress ?: continue
                when (classifyDnsAddress(addr)) {
                    DnsClassification.LOOPBACK -> {
                        findings.add(
                            Finding(
                                "DNS указывает на localhost: $addr (типично для VPN)",
                                detected = true,
                            )
                        )
                        detected = true
                    }
                    DnsClassification.PRIVATE_TUNNEL -> {
                        findings.add(
                            Finding(
                                "DNS в частной подсети: $addr (может указывать на VPN-туннель)",
                                detected = true,
                            )
                        )
                        detected = true
                    }
                    DnsClassification.KNOWN_PUBLIC_RESOLVER -> {
                        findings.add(
                            Finding(
                                description = "DNS использует публичный резолвер: $addr",
                                needsReview = true,
                            )
                        )
                        needsReview = true
                    }
                    DnsClassification.LINK_LOCAL -> {
                        findings.add(Finding("DNS: $addr (link-local)"))
                    }
                    DnsClassification.OTHER_PUBLIC -> {
                        findings.add(Finding("DNS: $addr"))
                    }
                }
            }

            return SignalOutcome(detected = detected, needsReview = needsReview)
        } catch (e: Exception) {
            findings.add(Finding("Ошибка при проверке DNS: ${e.message}"))
        }

        return SignalOutcome()
    }

    private fun checkDumpsysVpn(findings: MutableList<Finding>): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return false
        try {
            val process = Runtime.getRuntime().exec(arrayOf("dumpsys", "vpn_management"))
            val output = process.inputStream.bufferedReader().readText()
            process.waitFor()

            if (output.isBlank() || output.contains("Permission Denial") || output.contains("Can't find service")) {
                findings.add(Finding("dumpsys vpn_management: недоступен"))
                return false
            }

            val vpnLines = output.lines().filter {
                it.contains("Active package name:") || it.contains("Active vpn type:")
            }

            if (vpnLines.isNotEmpty()) {
                for (line in vpnLines) {
                    findings.add(Finding("VPN management: ${line.trim()}", detected = true))
                }
                return true
            }

            if (output.contains("VPNs:")) {
                val hasActiveVpn = output.lines().any { line ->
                    val trimmed = line.trim()
                    trimmed.matches(Regex("^\\d+:.*")) && trimmed.length > 2
                }
                if (hasActiveVpn) {
                    findings.add(Finding("dumpsys vpn_management: обнаружен активный VPN", detected = true))
                    return true
                }
            }

            findings.add(Finding("dumpsys vpn_management: активных VPN нет"))
        } catch (e: Exception) {
            findings.add(Finding("dumpsys vpn_management: ${e.message}"))
        }

        return false
    }

    private fun checkDumpsysVpnService(findings: MutableList<Finding>): Boolean {
        try {
            val process = Runtime.getRuntime().exec(arrayOf("dumpsys", "activity", "services", "android.net.VpnService"))
            val output = process.inputStream.bufferedReader().readText()
            process.waitFor()

            if (output.isBlank() || output.contains("Permission Denial")) {
                findings.add(Finding("dumpsys activity services VpnService: недоступен"))
                return false
            }

            val serviceRecords = output.lines().filter {
                it.contains("ServiceRecord") && it.contains("VpnService")
            }

            if (serviceRecords.isNotEmpty()) {
                for (line in serviceRecords) {
                    val trimmed = line.trim()
                    val packageMatch = Regex("\\{[^}]*\\s+(\\S+/\\S+)\\}").find(trimmed)
                    val serviceName = packageMatch?.groupValues?.get(1) ?: trimmed
                    findings.add(Finding("VpnService активен: $serviceName", detected = true))
                }
                return true
            }

            if (output.contains("(nothing)") || !output.contains("ServiceRecord")) {
                findings.add(Finding("Активные VpnService: не обнаружены"))
            }
        } catch (e: Exception) {
            findings.add(Finding("dumpsys activity services: ${e.message}"))
        }

        return false
    }

    private fun isPrivate172(addr: String): Boolean {
        val parts = addr.split(".")
        if (parts.size < 2) return false
        val second = parts[1].toIntOrNull() ?: return false
        return second in 16..31
    }

    internal fun classifyDnsAddress(addr: String): DnsClassification {
        val normalized = addr.lowercase()
        if (normalized == "::1" || normalized.startsWith("127.")) return DnsClassification.LOOPBACK
        if (normalized.startsWith("169.254.") || normalized.startsWith("fe80:")) {
            return DnsClassification.LINK_LOCAL
        }
        if (
            normalized.startsWith("10.") ||
            (normalized.startsWith("172.") && isPrivate172(normalized)) ||
            normalized.startsWith("192.168.") ||
            normalized.startsWith("fc") ||
            normalized.startsWith("fd")
        ) {
            return DnsClassification.PRIVATE_TUNNEL
        }
        if (normalized in KNOWN_PUBLIC_RESOLVERS) return DnsClassification.KNOWN_PUBLIC_RESOLVER
        return DnsClassification.OTHER_PUBLIC
    }
}

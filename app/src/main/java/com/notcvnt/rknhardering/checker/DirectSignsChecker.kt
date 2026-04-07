package com.notcvnt.rknhardering.checker

import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Proxy
import com.notcvnt.rknhardering.model.CategoryResult
import com.notcvnt.rknhardering.model.Finding

object DirectSignsChecker {

    private val KNOWN_PROXY_PORTS = setOf(
        80, 443, 1080, 3127, 3128, 4080, 5555,
        7000, 7044, 8000, 8080, 8081, 8082, 8888,
        9000, 9050, 9051, 9150, 12345
    )
    private val KNOWN_PROXY_PORT_RANGES = listOf(16000..16100)

    // packageId to human-readable name
    private val KNOWN_VPN_PACKAGES = mapOf(
        "com.v2ray.ang"                         to "v2rayNG",
        "io.nekohasekai.sfa"                    to "sing-box",
        "app.hiddify.com"                       to "Hiddify",
        "com.github.metacubex.clash.meta"       to "ClashMeta for Android",
        "com.github.shadowsocks"                to "Shadowsocks",
        "com.github.shadowsocks.tv"             to "Shadowsocks TV",
        "com.happproxy"                         to "HAPP VPN",
        "io.github.saeeddev94.xray"             to "XrayNG",
        "moe.nb4a"                              to "NekoBox",
        "io.github.dovecoteescapee.byedpi"      to "ByeDPI",
        "com.romanvht.byebyedpi"                to "ByeByeDPI",
        "org.outline.android.client"            to "Outline",
        "com.psiphon3"                          to "Psiphon",
        "org.getlantern.lantern"                to "Lantern",
        "com.wireguard.android"                 to "WireGuard",
        "com.strongswan.android"                to "strongSwan",
        "org.torproject.android"                to "Tor Browser",
        "info.guardianproject.orfox"            to "Orbot",
        "org.torproject.torbrowser"             to "Tor Browser (official)",
    )

    fun check(context: Context): CategoryResult {
        val findings = mutableListOf<Finding>()
        var detected = false
        var needsReview = false

        detected = checkVpnTransport(context, findings) || detected
        detected = checkSystemProxy(findings) || detected
        needsReview = checkKnownVpnApps(context, findings) || needsReview

        return CategoryResult(
            name = "Прямые признаки",
            detected = detected,
            findings = findings,
            needsReview = needsReview,
        )
    }

    private fun checkVpnTransport(context: Context, findings: MutableList<Finding>): Boolean {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val activeNetwork = cm.activeNetwork
        if (activeNetwork == null) {
            findings.add(Finding("Активная сеть не найдена", false))
            return false
        }

        val caps = cm.getNetworkCapabilities(activeNetwork)
        if (caps == null) {
            findings.add(Finding("NetworkCapabilities недоступны", false))
            return false
        }

        val hasVpnTransport = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        findings.add(
            Finding(
                "TRANSPORT_VPN: ${if (hasVpnTransport) "обнаружен" else "не обнаружен"}",
                hasVpnTransport
            )
        )

        val capsString = caps.toString()
        var detected = hasVpnTransport

        val hasIsVpn = capsString.contains("IS_VPN")
        if (hasIsVpn) {
            findings.add(Finding("Флаг IS_VPN обнаружен в capabilities", true))
            detected = true
        }

        val hasVpnTransportInfo = capsString.contains("VpnTransportInfo")
        if (hasVpnTransportInfo) {
            findings.add(Finding("VpnTransportInfo обнаружен в транспортной информации", true))
            detected = true
        }

        return detected
    }

    @Suppress("DEPRECATION")
    private fun checkSystemProxy(findings: MutableList<Finding>): Boolean {
        val httpHost = System.getProperty("http.proxyHost") ?: Proxy.getDefaultHost()
        val httpPort = System.getProperty("http.proxyPort")
            ?: Proxy.getDefaultPort().takeIf { it > 0 }?.toString()
        val socksHost = System.getProperty("socksProxyHost")
        val socksPort = System.getProperty("socksProxyPort")
        var detected = false

        val httpProxySet = !httpHost.isNullOrBlank()
        if (httpProxySet) {
            findings.add(Finding("HTTP прокси: $httpHost:${httpPort ?: "N/A"}", true))
            detected = true
            checkKnownPort(httpPort, "HTTP прокси", findings)
        } else {
            findings.add(Finding("HTTP прокси: не настроен", false))
        }

        val socksProxySet = !socksHost.isNullOrBlank()
        if (socksProxySet) {
            findings.add(Finding("SOCKS прокси: $socksHost:${socksPort ?: "N/A"}", true))
            detected = true
            checkKnownPort(socksPort, "SOCKS прокси", findings)
        } else {
            findings.add(Finding("SOCKS прокси: не настроен", false))
        }

        return detected
    }

    private fun checkKnownVpnApps(context: Context, findings: MutableList<Finding>): Boolean {
        val pm = context.packageManager
        val installed = mutableListOf<String>()

        for ((pkg, name) in KNOWN_VPN_PACKAGES) {
            try {
                pm.getPackageInfo(pkg, 0)
                installed.add(name)
                findings.add(
                    Finding(
                        description = "Установлено VPN/Proxy-приложение: $name ($pkg)",
                        needsReview = true,
                    )
                )
            } catch (_: PackageManager.NameNotFoundException) {
                // not installed
            }
        }

        if (installed.isEmpty()) {
            findings.add(Finding("Известные VPN-приложения: не обнаружены", false))
        }

        return installed.isNotEmpty()
    }

    private fun checkKnownPort(port: String?, type: String, findings: MutableList<Finding>) {
        if (isKnownProxyPort(port)) {
            findings.add(
                Finding(
                    description = "$type использует характерный порт $port",
                    needsReview = true,
                )
            )
        }
    }

    internal fun isKnownProxyPort(port: String?): Boolean {
        val value = port?.toIntOrNull() ?: return false
        return value in KNOWN_PROXY_PORTS || KNOWN_PROXY_PORT_RANGES.any { value in it }
    }
}

package com.notcvnt.rknhardering.probe

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.NetworkInterfaceNameNormalizer
import com.notcvnt.rknhardering.network.ResolverBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Detects whether a non-VPN (underlying) network is reachable from this app.
 *
 * When VPN runs in split-tunnel / per-app mode, apps excluded from the tunnel
 * (or any app that can bind to the underlying network) can reach the VPN gateway
 * and any external host directly, leaking the real IP and confirming VPN usage.
 *
 * The probe enumerates all networks, finds one without TRANSPORT_VPN, binds an
 * HTTPS request to it, and fetches the public IP. Success means split-tunnel
 * vulnerability is present.
 */
object UnderlyingNetworkProber {
    private data class BoundNetwork(
        val network: Network,
        val interfaceName: String?,
    )

    data class ProbeResult(
        val vpnActive: Boolean,
        val underlyingReachable: Boolean,
        val vpnIp: String? = null,
        val underlyingIp: String? = null,
        val vpnError: String? = null,
        val underlyingError: String? = null,
        val vpnIpComparison: PublicIpNetworkComparison? = null,
        val underlyingIpComparison: PublicIpNetworkComparison? = null,
        val dnsPathMismatch: Boolean = false,
        val vpnNetwork: Network? = null,
        val underlyingNetwork: Network? = null,
        val activeNetworkIsVpn: Boolean? = null,
        val tunProbeDiagnostics: TunProbeDiagnostics? = null,
    )

    @Suppress("DEPRECATION")
    suspend fun probe(
        context: Context,
        resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
        debugEnabled: Boolean = false,
        modeOverride: TunProbeModeOverride = TunProbeModeOverride.AUTO,
    ): ProbeResult = withContext(Dispatchers.IO) {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val activeNetwork = cm.activeNetwork
        val activeNetworkIsVpn = activeNetwork
            ?.let(cm::getNetworkCapabilities)
            ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)

        val allNetworks = cm.allNetworks
        var vpnNetwork: BoundNetwork? = null
        val nonVpnNetworks = mutableListOf<BoundNetwork>()

        for (network in allNetworks) {
            val caps = cm.getNetworkCapabilities(network) ?: continue
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
            val boundNetwork = BoundNetwork(
                network = network,
                interfaceName = NetworkInterfaceNameNormalizer.canonicalName(
                    cm.getLinkProperties(network)?.interfaceName,
                ),
            )
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                vpnNetwork = boundNetwork
            } else {
                nonVpnNetworks.add(boundNetwork)
            }
        }

        if (vpnNetwork == null) {
            return@withContext ProbeResult(
                vpnActive = false,
                underlyingReachable = false,
                activeNetworkIsVpn = activeNetworkIsVpn,
                tunProbeDiagnostics = buildTunProbeDiagnostics(
                    debugEnabled = debugEnabled,
                    modeOverride = modeOverride,
                    activeNetworkIsVpn = activeNetworkIsVpn,
                    vpnNetworkPresent = false,
                    underlyingNetworkPresent = nonVpnNetworks.isNotEmpty(),
                    vpnInterfaceName = null,
                    vpnComparison = null,
                    underlyingInterfaceName = nonVpnNetworks.firstOrNull()?.interfaceName,
                    underlyingComparison = null,
                ),
            )
        }

        val vpnComparison = fetchIpViaNetworkComparison(vpnNetwork, resolverConfig, debugEnabled, modeOverride)
        val vpnIp = vpnComparison.selectedIp
        val vpnError = vpnComparison.selectedError

        if (nonVpnNetworks.isEmpty()) {
            return@withContext ProbeResult(
                vpnActive = true,
                underlyingReachable = false,
                vpnIp = vpnIp,
                vpnError = vpnError,
                vpnIpComparison = vpnComparison,
                dnsPathMismatch = vpnComparison.dnsPathMismatch,
                vpnNetwork = vpnNetwork.network,
                activeNetworkIsVpn = activeNetworkIsVpn,
                tunProbeDiagnostics = buildTunProbeDiagnostics(
                    debugEnabled = debugEnabled,
                    modeOverride = modeOverride,
                    activeNetworkIsVpn = activeNetworkIsVpn,
                    vpnNetworkPresent = true,
                    underlyingNetworkPresent = false,
                    vpnInterfaceName = vpnNetwork.interfaceName,
                    vpnComparison = vpnComparison,
                    underlyingInterfaceName = null,
                    underlyingComparison = null,
                ),
            )
        }

        var underlyingIp: String? = null
        var underlyingError: String? = null
        var usedNetwork: Network? = null
        var usedBoundNetwork: BoundNetwork? = null
        var underlyingComparison: PublicIpNetworkComparison? = null
        var lastUnderlyingNetwork: BoundNetwork? = null

        for (network in nonVpnNetworks) {
            val result = fetchIpViaNetworkComparison(network, resolverConfig, debugEnabled, modeOverride)
            lastUnderlyingNetwork = network
            underlyingComparison = result
            underlyingIp = result.selectedIp
            if (underlyingIp != null) {
                usedNetwork = network.network
                usedBoundNetwork = network
                underlyingError = null
                break
            }
            underlyingError = result.selectedError ?: underlyingError
        }

        ProbeResult(
            vpnActive = true,
            underlyingReachable = underlyingIp != null,
            vpnIp = vpnIp,
            underlyingIp = underlyingIp,
            vpnError = vpnError,
            underlyingError = underlyingError,
            vpnIpComparison = vpnComparison,
            underlyingIpComparison = underlyingComparison,
            dnsPathMismatch = vpnComparison.dnsPathMismatch ||
                (underlyingComparison?.dnsPathMismatch == true),
            vpnNetwork = vpnNetwork.network,
            underlyingNetwork = usedNetwork,
            activeNetworkIsVpn = activeNetworkIsVpn,
            tunProbeDiagnostics = buildTunProbeDiagnostics(
                debugEnabled = debugEnabled,
                modeOverride = modeOverride,
                activeNetworkIsVpn = activeNetworkIsVpn,
                vpnNetworkPresent = true,
                underlyingNetworkPresent = true,
                vpnInterfaceName = vpnNetwork.interfaceName,
                vpnComparison = vpnComparison,
                underlyingInterfaceName = (usedBoundNetwork ?: lastUnderlyingNetwork)?.interfaceName,
                underlyingComparison = underlyingComparison,
            ),
        )
    }

    private suspend fun fetchIpViaNetworkComparison(
        boundNetwork: BoundNetwork,
        resolverConfig: DnsResolverConfig,
        debugEnabled: Boolean,
        modeOverride: TunProbeModeOverride,
    ): PublicIpNetworkComparison {
        val fallbackBinding = boundNetwork.interfaceName
            ?.takeIf { it.isNotBlank() }
            ?.let { ResolverBinding.OsDeviceBinding(it, dnsMode = ResolverBinding.DnsMode.SYSTEM) }

        return IfconfigClient.fetchIpViaNetworkComparison(
            primaryBinding = ResolverBinding.AndroidNetworkBinding(boundNetwork.network),
            fallbackBinding = fallbackBinding,
            resolverConfig = resolverConfig,
            modeOverride = modeOverride,
            collectTrace = debugEnabled,
        )
    }

    internal fun buildTunProbeDiagnostics(
        debugEnabled: Boolean,
        modeOverride: TunProbeModeOverride,
        activeNetworkIsVpn: Boolean?,
        vpnNetworkPresent: Boolean,
        underlyingNetworkPresent: Boolean,
        vpnInterfaceName: String?,
        vpnComparison: PublicIpNetworkComparison?,
        underlyingInterfaceName: String?,
        underlyingComparison: PublicIpNetworkComparison?,
    ): TunProbeDiagnostics? {
        if (!debugEnabled) return null

        return TunProbeDiagnostics(
            enabled = true,
            modeOverride = modeOverride,
            activeNetworkIsVpn = activeNetworkIsVpn,
            vpnNetworkPresent = vpnNetworkPresent,
            underlyingNetworkPresent = underlyingNetworkPresent,
            vpnPath = vpnComparison?.toPathDiagnostics(vpnInterfaceName),
            underlyingPath = underlyingComparison?.toPathDiagnostics(underlyingInterfaceName),
        )
    }
}

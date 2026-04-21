package com.notcvnt.rknhardering.probe

import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.supervisorScope
import java.io.IOException
import java.net.URL

internal enum class IpEndpointFamilyHint {
    GENERIC,
    IPV4,
    IPV6,
}

internal data class IpEndpointSpec(
    val url: String,
    val familyHint: IpEndpointFamilyHint = familyHintForUrl(url),
)

internal suspend fun fetchFirstSuccessfulIp(
    endpoints: List<IpEndpointSpec>,
    attempt: suspend (IpEndpointSpec) -> Result<String>,
): Result<String> {
    // IPv4 / GENERIC endpoints first; IPv6 only as a fallback.
    val (ipv6Endpoints, primaryEndpoints) = endpoints.partition {
        it.familyHint == IpEndpointFamilyHint.IPV6
    }

    val primaryResult = fetchFirstSuccessfulIpGroup(primaryEndpoints, attempt)
    if (primaryResult.isSuccess || ipv6Endpoints.isEmpty()) {
        return primaryResult
    }

    val ipv6Result = fetchFirstSuccessfulIpGroup(ipv6Endpoints, attempt)
    if (ipv6Result.isSuccess) {
        return ipv6Result
    }

    val primaryError = primaryResult.exceptionOrNull() as? Exception
    val ipv6Error = ipv6Result.exceptionOrNull() as? Exception
    val preferredFailure = selectPreferredFailure(
        current = primaryError?.let { EndpointFailure(IpEndpointFamilyHint.GENERIC, it) },
        candidate = ipv6Error?.let { EndpointFailure(IpEndpointFamilyHint.IPV6, it) }
            ?: return primaryResult,
    )
    return Result.failure(preferredFailure.error)
}

private suspend fun fetchFirstSuccessfulIpGroup(
    endpoints: List<IpEndpointSpec>,
    attempt: suspend (IpEndpointSpec) -> Result<String>,
): Result<String> = supervisorScope {
    if (endpoints.isEmpty()) {
        return@supervisorScope Result.failure(IOException("All IP endpoints failed"))
    }

    val completions = Channel<EndpointCompletion>(capacity = endpoints.size)
    var preferredFailure: EndpointFailure? = null

    val jobs = endpoints.map { endpoint ->
        async {
            completions.send(
                EndpointCompletion(
                    endpoint = endpoint,
                    result = attempt(endpoint),
                ),
            )
        }
    }

    try {
        repeat(endpoints.size) {
            val completion = completions.receive()
            if (completion.result.isSuccess) {
                jobs.forEach { it.cancel() }
                return@supervisorScope completion.result
            }

            val error = completion.result.exceptionOrNull() as? Exception ?: IOException("Unknown IP fetch error")
            val candidate = EndpointFailure(completion.endpoint.familyHint, error)
            preferredFailure = selectPreferredFailure(preferredFailure, candidate)
        }
    } finally {
        jobs.forEach { it.cancel() }
        completions.close()
    }

    Result.failure(preferredFailure?.error ?: IOException("All IP endpoints failed"))
}

private data class EndpointFailure(
    val familyHint: IpEndpointFamilyHint,
    val error: Exception,
)

private data class EndpointCompletion(
    val endpoint: IpEndpointSpec,
    val result: Result<String>,
)

private fun selectPreferredFailure(
    current: EndpointFailure?,
    candidate: EndpointFailure,
): EndpointFailure {
    if (current == null) return candidate
    return if (failurePriority(candidate.familyHint) > failurePriority(current.familyHint)) {
        candidate
    } else {
        current
    }
}

private fun failurePriority(familyHint: IpEndpointFamilyHint): Int {
    return when (familyHint) {
        IpEndpointFamilyHint.GENERIC -> 3
        IpEndpointFamilyHint.IPV4 -> 2
        IpEndpointFamilyHint.IPV6 -> 1
    }
}

private fun familyHintForUrl(url: String): IpEndpointFamilyHint {
    val host = runCatching { URL(url).host.lowercase() }.getOrDefault("")
    return when {
        host.startsWith("ipv4-") || host.startsWith("api-ipv4.") -> IpEndpointFamilyHint.IPV4
        host.startsWith("ipv6-") || host.startsWith("api-ipv6.") -> IpEndpointFamilyHint.IPV6
        else -> IpEndpointFamilyHint.GENERIC
    }
}

package com.notcvnt.rknhardering.probe

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test

class XrayApiScannerTest {

    @Test
    fun `custom scan range does not probe ports outside selected range`() = runBlocking {
        val probedPorts = mutableListOf<Int>()
        val scanner = XrayApiScanner(
            loopbackHosts = listOf("127.0.0.1"),
            scanRange = 50000..50002,
            maxConcurrency = 1,
            progressUpdateEvery = 1,
            isTcpPortOpenOverride = { _, port ->
                probedPorts += port
                false
            },
        )

        val result = scanner.findXrayApi(onProgress = {})

        assertNull(result)
        assertEquals(listOf(50000, 50001, 50002), probedPorts)
        assertFalse(probedPorts.contains(10085))
    }

    @Test
    fun `popular scan probes only configured xray api ports`() = runBlocking {
        val probedPorts = mutableListOf<Int>()
        val scanner = XrayApiScanner(
            loopbackHosts = listOf("127.0.0.1"),
            scanPorts = listOf(8080, 10085, 8080),
            maxConcurrency = 1,
            progressUpdateEvery = 1,
            isTcpPortOpenOverride = { _, port ->
                probedPorts += port
                false
            },
        )

        val result = scanner.findXrayApi(onProgress = {})

        assertNull(result)
        assertEquals(listOf(8080, 10085), probedPorts)
    }
}

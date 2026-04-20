package com.notcvnt.rknhardering.probe

import java.io.IOException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.After
import org.junit.Test

class SystemPingProberTest {

    @After
    fun tearDown() {
        SystemPingProber.runCommandOverride = null
    }

    @Test
    fun `parse extracts summary and rtt from standard ping output`() {
        val result = SystemPingProber.parse(
            address = "8.8.8.8",
            commandResult = SystemPingProber.CommandResult(
                exitCode = 0,
                output = """
                    PING 8.8.8.8 (8.8.8.8): 56 data bytes
                    64 bytes from 8.8.8.8: icmp_seq=0 ttl=117 time=12.3 ms
                    64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=11.1 ms
                    64 bytes from 8.8.8.8: icmp_seq=2 ttl=117 time=10.9 ms

                    --- 8.8.8.8 ping statistics ---
                    3 packets transmitted, 3 packets received, 0% packet loss
                    round-trip min/avg/max/stddev = 10.9/11.4/12.3/0.6 ms
                """.trimIndent(),
            ),
        )

        assertEquals(3, result.sent)
        assertEquals(3, result.received)
        assertEquals(10.9, result.minRttMs ?: -1.0, 0.0)
        assertEquals(11.4, result.avgRttMs ?: -1.0, 0.0)
        assertEquals(12.3, result.maxRttMs ?: -1.0, 0.0)
        assertTrue(result.hasReplies)
    }

    @Test
    fun `parse keeps zero reply summary when rtt line is absent`() {
        val result = SystemPingProber.parse(
            address = "157.240.22.174",
            commandResult = SystemPingProber.CommandResult(
                exitCode = 1,
                output = """
                    PING 157.240.22.174 (157.240.22.174): 56 data bytes

                    --- 157.240.22.174 ping statistics ---
                    3 packets transmitted, 0 packets received, 100% packet loss
                """.trimIndent(),
            ),
        )

        assertEquals(3, result.sent)
        assertEquals(0, result.received)
        assertFalse(result.hasReplies)
    }

    @Test
    fun `probe includes command exit code and output preview when parse fails`() {
        SystemPingProber.runCommandOverride = {
            SystemPingProber.CommandResult(
                exitCode = 0,
                output = """
                    PING 8.8.8.8 (8.8.8.8)
                    reply from 8.8.8.8 with unsupported timing field
                    unexpected summary format
                """.trimIndent(),
            )
        }

        val error = assertThrows(IOException::class.java) {
            runBlocking {
                SystemPingProber.probe(address = "8.8.8.8")
            }
        }

        assertTrue(error.message.orEmpty().contains("command="))
        assertTrue(error.message.orEmpty().contains("exitCode=0"))
        assertTrue(error.message.orEmpty().contains("unexpected summary format"))
    }

    @Test
    fun `probe falls back to command without force ipv4 flag when dash4 is unsupported`() {
        val attemptedCommands = mutableListOf<List<String>>()
        SystemPingProber.runCommandOverride = { command ->
            attemptedCommands += command
            if ("-4" in command) {
                SystemPingProber.CommandResult(
                    exitCode = 2,
                    output = "ping: invalid option -- 4",
                )
            } else {
                SystemPingProber.CommandResult(
                    exitCode = 0,
                    output = """
                        PING 8.8.8.8 (8.8.8.8): 56 data bytes
                        64 bytes from 8.8.8.8: icmp_seq=0 ttl=117 time=12.3 ms
                        64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=11.1 ms
                        64 bytes from 8.8.8.8: icmp_seq=2 ttl=117 time=10.9 ms

                        --- 8.8.8.8 ping statistics ---
                        3 packets transmitted, 3 packets received, 0% packet loss
                        round-trip min/avg/max/stddev = 10.9/11.4/12.3/0.6 ms
                    """.trimIndent(),
                )
            }
        }

        val result = runBlocking {
            SystemPingProber.probe(address = "8.8.8.8")
        }

        assertTrue(attemptedCommands.any { "-4" in it })
        assertTrue(attemptedCommands.any { "-4" !in it })
        assertEquals(3, result.received)
        assertTrue(result.hasReplies)
    }
}

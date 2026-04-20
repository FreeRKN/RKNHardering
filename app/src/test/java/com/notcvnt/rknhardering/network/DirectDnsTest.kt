package com.notcvnt.rknhardering.network

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress
import java.net.SocketException
import java.net.UnknownHostException
import java.util.concurrent.atomic.AtomicBoolean

class DirectDnsTest {
    @After
    fun tearDown() {
        ResolverNetworkStack.resetForTests()
    }

    @Test
    fun `direct dns resolves ipv4 and ipv6 from configured server`() {
        FakeDnsServer(
            records = mapOf(
                "resolver-test.local" to FakeDnsServer.Record(
                    ipv4 = "127.0.0.1",
                    ipv6 = "2001:db8::1",
                ),
            ),
        ).use { server ->
            val dns = DirectDns(listOf("127.0.0.1"), port = server.port, timeoutMs = 1_000)

            val resolved = dns.lookup("resolver-test.local")

            assertTrue(resolved.any { it.hostAddress == "127.0.0.1" })
            assertTrue(resolved.any { it.hostAddress == InetAddress.getByName("2001:db8::1").hostAddress })
        }
    }

    @Test(expected = UnknownHostException::class)
    fun `direct dns surfaces nxdomain from configured server`() {
        FakeDnsServer(
            records = mapOf(
                "missing.local" to FakeDnsServer.Record(nxdomain = true),
            ),
        ).use { server ->
            val dns = DirectDns(listOf("127.0.0.1"), port = server.port, timeoutMs = 1_000)
            dns.lookup("missing.local")
        }
    }

    @Test
    fun `literal ip lookup bypasses dns query`() {
        val dns = DirectDns(listOf("127.0.0.1"))

        val resolved = dns.lookup("203.0.113.5")

        assertEquals(listOf("203.0.113.5"), resolved.mapNotNull { it.hostAddress })
    }

    @Test(expected = UnknownHostException::class)
    fun `direct dns fails fast when no valid servers remain`() {
        DirectDns(listOf("not-an-ip", "999.999.999.999")).lookup("resolver-test.local")
    }

    @Test
    fun `direct dns uses os device binding for udp sockets`() {
        val boundInterfaces = mutableListOf<String>()
        ResolverSocketBinder.bindDatagramToDeviceOverride = { _, interfaceName ->
            boundInterfaces += interfaceName
        }

        FakeDnsServer(
            records = mapOf(
                "resolver-test.local" to FakeDnsServer.Record(
                    ipv4 = "127.0.0.1",
                    ipv6 = "2001:db8::1",
                ),
            ),
        ).use { server ->
            val dns = DirectDns(
                servers = listOf("127.0.0.1"),
                port = server.port,
                timeoutMs = 1_000,
                binding = ResolverBinding.OsDeviceBinding("tun0"),
            )

            dns.lookup("resolver-test.local")
        }

        assertTrue(boundInterfaces.isNotEmpty())
        assertTrue(boundInterfaces.all { it == "tun0" })
    }

    @Test
    fun `direct dns ignores responses from unexpected udp peer`() {
        DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { server ->
            DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { attacker ->
                val running = AtomicBoolean(true)
                val worker = Thread(
                    {
                        val buffer = ByteArray(1500)
                        while (running.get()) {
                            val packet = DatagramPacket(buffer, buffer.size)
                            try {
                                server.receive(packet)
                                val request = packet.data.copyOf(packet.length)
                                val query = parseQuery(request)
                                val response = when (query.type) {
                                    1 -> {
                                        val spoofed = buildResponse(request, ipv4 = "203.0.113.10")
                                        attacker.send(DatagramPacket(spoofed, spoofed.size, packet.address, packet.port))
                                        Thread.sleep(50)
                                        buildResponse(request, ipv4 = "127.0.0.1")
                                    }
                                    else -> buildResponse(request)
                                }
                                server.send(DatagramPacket(response, response.size, packet.address, packet.port))
                            } catch (error: SocketException) {
                                if (!running.get()) return@Thread
                                throw error
                            }
                        }
                    },
                    "spoofed-dns-server",
                ).apply {
                    isDaemon = true
                    start()
                }

                try {
                    val dns = DirectDns(listOf("127.0.0.1"), port = server.localPort, timeoutMs = 1_000)

                    val resolved = dns.lookup("resolver-test.local")

                    assertTrue(resolved.any { it.hostAddress == "127.0.0.1" })
                    assertFalse(resolved.any { it.hostAddress == "203.0.113.10" })
                } finally {
                    running.set(false)
                    server.close()
                    attacker.close()
                    worker.join(1_000)
                }
            }
        }
    }

    private fun parseQuery(request: ByteArray): TestDnsQuery {
        var offset = 12
        while (offset < request.size) {
            val length = request[offset].toInt() and 0xFF
            offset += 1
            if (length == 0) break
            offset += length
        }
        return TestDnsQuery(type = readUnsignedShort(request, offset))
    }

    private fun buildResponse(
        request: ByteArray,
        ipv4: String? = null,
    ): ByteArray {
        val id = readUnsignedShort(request, 0)
        val question = request.copyOfRange(12, request.size)
        val payload = ipv4?.let { InetAddress.getByName(it).address }

        return ByteArrayOutputStream().use { output ->
            DataOutputStream(output).use { stream ->
                stream.writeShort(id)
                stream.writeShort(0x8180)
                stream.writeShort(1)
                stream.writeShort(if (payload != null) 1 else 0)
                stream.writeShort(0)
                stream.writeShort(0)
                stream.write(question)
                if (payload != null) {
                    stream.writeShort(0xC00C)
                    stream.writeShort(1)
                    stream.writeShort(1)
                    stream.writeInt(60)
                    stream.writeShort(payload.size)
                    stream.write(payload)
                }
            }
            output.toByteArray()
        }
    }

    private fun readUnsignedShort(data: ByteArray, offset: Int): Int {
        return ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
    }

    private data class TestDnsQuery(
        val type: Int,
    )
}

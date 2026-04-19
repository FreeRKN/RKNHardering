package com.notcvnt.rknhardering.probe

import com.notcvnt.rknhardering.ScanCancellationSignal
import com.notcvnt.rknhardering.ScanExecutionContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress
import java.net.ServerSocket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

class XrayApiClientTest {

    @Test
    fun `cancelled grpc call shuts down channel immediately`() {
        ServerSocket(0, 50, InetAddress.getByName("127.0.0.1")).use { server ->
            val accepted = CountDownLatch(1)
            val releaseServer = CountDownLatch(1)
            val executionContext = ScanExecutionContext(cancellationSignal = ScanCancellationSignal())

            val serverWorker = thread(start = true, isDaemon = true) {
                try {
                    server.accept().use {
                        accepted.countDown()
                        releaseServer.await(2, TimeUnit.SECONDS)
                    }
                } catch (_: Exception) {
                }
            }

            var failure: Throwable? = null
            val clientWorker = thread(start = true) {
                failure = runCatching {
                    runBlocking {
                        XrayApiClient("127.0.0.1").listOutbounds(
                            port = server.localPort,
                            deadlineMs = 30_000,
                            executionContext = executionContext,
                        )
                    }
                }.exceptionOrNull()
            }

            assertTrue(accepted.await(2, TimeUnit.SECONDS))
            executionContext.cancellationSignal.cancel()
            clientWorker.join(2_000)
            releaseServer.countDown()
            serverWorker.join(2_000)

            assertFalse(clientWorker.isAlive)
            assertTrue(failure is CancellationException)
        }
    }
}

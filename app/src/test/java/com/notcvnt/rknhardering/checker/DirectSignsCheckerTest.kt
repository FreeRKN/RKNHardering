package com.notcvnt.rknhardering.checker

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DirectSignsCheckerTest {

    @Test
    fun `matches documented proxy ports`() {
        assertTrue(DirectSignsChecker.isKnownProxyPort("1080"))
        assertTrue(DirectSignsChecker.isKnownProxyPort("3128"))
        assertTrue(DirectSignsChecker.isKnownProxyPort("8081"))
        assertTrue(DirectSignsChecker.isKnownProxyPort("9051"))
        assertTrue(DirectSignsChecker.isKnownProxyPort("12345"))
    }

    @Test
    fun `matches documented proxy port ranges`() {
        assertTrue(DirectSignsChecker.isKnownProxyPort("16000"))
        assertTrue(DirectSignsChecker.isKnownProxyPort("16042"))
        assertTrue(DirectSignsChecker.isKnownProxyPort("16100"))
    }

    @Test
    fun `ignores unknown or invalid ports`() {
        assertFalse(DirectSignsChecker.isKnownProxyPort(null))
        assertFalse(DirectSignsChecker.isKnownProxyPort("abc"))
        assertFalse(DirectSignsChecker.isKnownProxyPort("53"))
        assertFalse(DirectSignsChecker.isKnownProxyPort("16101"))
    }
}

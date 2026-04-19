package com.notcvnt.rknhardering

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class CheckResultMarkdownExportFormatterTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `markdown export contains ascii summary block and major sections`() {
        val markdown = CheckResultMarkdownExportFormatter.format(
            context = context,
            snapshot = createCompletedExportSnapshot(
                result = exportRichCheckResult(),
                privacyMode = false,
                finishedAtMillis = 0L,
            ),
            appVersionName = "1.0",
            buildType = "debug",
        )

        assertTrue(markdown.contains("# RKNHardering Scan Report"))
        assertTrue(markdown.contains("```text"))
        assertTrue(markdown.contains("VERDICT      : [DETECTED]"))
        assertTrue(markdown.contains("| Section | Status | Summary |"))
        assertTrue(markdown.contains("## GeoIP"))
        assertTrue(markdown.contains("## ${context.getString(R.string.main_card_ip_comparison)}"))
        assertTrue(markdown.contains("## ${context.getString(R.string.settings_split_tunnel)}"))
        assertTrue(markdown.contains("## Footer"))
    }

    @Test
    fun `markdown export masks public ips in privacy mode`() {
        val markdown = CheckResultMarkdownExportFormatter.format(
            context = context,
            snapshot = createCompletedExportSnapshot(
                result = exportRichCheckResult(),
                privacyMode = true,
                finishedAtMillis = 0L,
            ),
            appVersionName = "1.0",
            buildType = "debug",
        )

        assertTrue(markdown.contains("203.0.*.*"))
        assertTrue(markdown.contains("198.51.*.*"))
        assertFalse(markdown.contains("203.0.113.64"))
        assertFalse(markdown.contains("198.51.100.7"))
    }

    @Test
    fun `markdown export stays readable for empty result`() {
        val markdown = CheckResultMarkdownExportFormatter.format(
            context = context,
            snapshot = createCompletedExportSnapshot(
                result = exportEmptyCheckResult(),
                privacyMode = false,
                finishedAtMillis = 0L,
            ),
            appVersionName = "1.0",
            buildType = "debug",
        )

        assertTrue(markdown.contains("### Findings"))
        assertTrue(markdown.contains("- <none>"))
        assertFalse(markdown.contains("null"))
    }
}

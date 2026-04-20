package com.notcvnt.rknhardering

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.content.edit
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * Checks for application updates by querying the GitHub Releases API.
 *
 * Behaviour:
 * - Fetches the latest release from [RELEASES_API_URL].
 * - Compares the remote `tag_name` (e.g. "v2.5.0") against [BuildConfig.VERSION_NAME].
 * - If a newer version exists **and** it has not been skipped by the user, shows a
 *   [MaterialAlertDialogBuilder] dialog with three actions:
 *     • **Download** – opens the APK download URL in the browser.
 *     • **Skip this version** – persists the remote version so the dialog won't appear again
 *       for that particular release.
 *     • **Later** – dismisses the dialog without any side-effects.
 */
internal object AppUpdateChecker {

    private const val RELEASES_API_URL =
        "https://api.github.com/repos/xtclovver/RKNHardering/releases/latest"

    private const val PREF_SKIPPED_VERSION = "update_skipped_version"

    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .build()

    /**
     * Result of a successful update check.
     */
    data class UpdateInfo(
        val latestVersion: String,
        val downloadUrl: String,
    )

    /**
     * Fetches the latest release metadata from GitHub.
     * Returns `null` when the request fails or the response cannot be parsed.
     */
    suspend fun fetchLatestRelease(): UpdateInfo? = withContext(Dispatchers.IO) {
        runCatching {
            val request = Request.Builder()
                .url(RELEASES_API_URL)
                .header("Accept", "application/vnd.github+json")
                .build()
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return@withContext null
                val body = response.body?.string() ?: return@withContext null
                val json = JSONObject(body)
                val tagName = json.optString("tag_name", "").trim()
                if (tagName.isBlank()) return@withContext null

                // Find *.apk asset download URL
                val assets = json.optJSONArray("assets")
                var apkUrl: String? = null
                if (assets != null) {
                    for (i in 0 until assets.length()) {
                        val asset = assets.getJSONObject(i)
                        val name = asset.optString("name", "")
                        if (name.endsWith(".apk")) {
                            apkUrl = asset.optString("browser_download_url", "")
                            break
                        }
                    }
                }
                // Fallback to the release page itself
                val downloadUrl = apkUrl?.takeIf { it.isNotBlank() }
                    ?: json.optString("html_url", "")

                UpdateInfo(
                    latestVersion = tagName.removePrefix("v"),
                    downloadUrl = downloadUrl,
                )
            }
        }.getOrNull()
    }

    /**
     * Returns `true` when [remoteVersion] is strictly newer than [localVersion].
     * Both strings are expected in `MAJOR.MINOR.PATCH` format.
     */
    fun isNewerVersion(localVersion: String, remoteVersion: String): Boolean {
        val local = parseVersion(localVersion) ?: return false
        val remote = parseVersion(remoteVersion) ?: return false
        return compareVersions(remote, local) > 0
    }

    /**
     * Shows the update dialog. Handles the three user actions internally.
     */
    fun showUpdateDialog(
        context: Context,
        currentVersion: String,
        updateInfo: UpdateInfo,
    ) {
        val prefs = AppUiSettings.prefs(context)
        MaterialAlertDialogBuilder(context)
            .setTitle(context.getString(R.string.update_dialog_title))
            .setMessage(
                context.getString(
                    R.string.update_dialog_message,
                    currentVersion,
                    updateInfo.latestVersion,
                ),
            )
            .setPositiveButton(R.string.update_dialog_download) { _, _ ->
                val intent = Intent(Intent.ACTION_VIEW, Uri.parse(updateInfo.downloadUrl))
                context.startActivity(intent)
            }
            .setNegativeButton(R.string.update_dialog_skip) { _, _ ->
                prefs.edit { putString(PREF_SKIPPED_VERSION, updateInfo.latestVersion) }
            }
            .setNeutralButton(R.string.update_dialog_later, null)
            .setCancelable(true)
            .show()
    }

    /**
     * Returns `true` when the user has explicitly chosen to skip [version].
     */
    fun isVersionSkipped(context: Context, version: String): Boolean {
        val skipped = AppUiSettings.prefs(context)
            .getString(PREF_SKIPPED_VERSION, null)
        return skipped == version
    }

    // ---- internal helpers ----

    private data class SemVer(val major: Int, val minor: Int, val patch: Int)

    private fun parseVersion(raw: String): SemVer? {
        val cleaned = raw.removePrefix("v").trim()
        val parts = cleaned.split(".")
        if (parts.size != 3) return null
        val major = parts[0].toIntOrNull() ?: return null
        val minor = parts[1].toIntOrNull() ?: return null
        val patch = parts[2].toIntOrNull() ?: return null
        return SemVer(major, minor, patch)
    }

    private fun compareVersions(a: SemVer, b: SemVer): Int {
        val majorCmp = a.major.compareTo(b.major)
        if (majorCmp != 0) return majorCmp
        val minorCmp = a.minor.compareTo(b.minor)
        if (minorCmp != 0) return minorCmp
        return a.patch.compareTo(b.patch)
    }
}

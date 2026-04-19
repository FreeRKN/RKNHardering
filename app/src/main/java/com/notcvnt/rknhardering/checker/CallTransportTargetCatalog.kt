package com.notcvnt.rknhardering.checker

import android.content.Context
import com.notcvnt.rknhardering.model.StunScope
import org.json.JSONArray

object CallTransportTargetCatalog {

    data class StunTarget(
        val host: String,
        val port: Int,
        val scope: StunScope,
        val enabled: Boolean,
    )

    data class Catalog(
        val stunTargets: List<StunTarget>,
    )

    fun load(context: Context): Catalog {
        val stunGlobal = readStunTargets(context, "stun_targets_global.json", StunScope.GLOBAL)
        val stunRu = readStunTargets(context, "stun_targets_ru.json", StunScope.RU)
        return Catalog(stunTargets = (stunGlobal + stunRu).filter { it.enabled })
    }

    private fun readStunTargets(
        context: Context,
        assetName: String,
        scope: StunScope,
    ): List<StunTarget> {
        val raw = runCatching {
            context.assets.open(assetName).bufferedReader(Charsets.UTF_8).use { it.readText() }
        }.getOrElse { return emptyList() }
        val json = JSONArray(raw)
        return buildList(json.length()) {
            for (index in 0 until json.length()) {
                val item = json.getJSONObject(index)
                add(
                    StunTarget(
                        host = item.getString("host").trim(),
                        port = item.optInt("port", 3478),
                        scope = scope,
                        enabled = item.optBoolean("enabled", true),
                    ),
                )
            }
        }
    }
}

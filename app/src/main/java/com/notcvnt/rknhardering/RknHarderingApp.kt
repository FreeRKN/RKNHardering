package com.notcvnt.rknhardering

import android.app.Application
import com.notcvnt.rknhardering.probe.NativeCurlBridge

class RknHarderingApp : Application() {

    override fun onCreate() {
        super.onCreate()
        NativeCurlBridge.initIfNeeded(this)
        AppUiSettings.applySavedTheme(this)
    }
}

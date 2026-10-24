package org.sovereign.mesh

import android.app.Application
import org.sovereign.mesh.core.CoreBridge

class SovereignApp : Application() {
    companion object {
        lateinit var core: CoreBridge
            private set
    }

    override fun onCreate() {
        super.onCreate()
        core = CoreBridge()
    }
}

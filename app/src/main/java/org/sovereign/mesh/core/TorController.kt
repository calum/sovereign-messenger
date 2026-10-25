package org.sovereign.mesh.core

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import uniffi.rust_core.FacadeException
import uniffi.rust_core.TorState

/** What the UI shows about Tor right now. */
data class TorSnapshot(val state: TorState, val percent: Int)

/**
 * Keeps Tor running for the app: starts it, mirrors its status into Compose state,
 * restarts it after a failure, and once the onion service is up keeps waiting for
 * contacts to call. Calls into the core block, so they all run on the IO dispatcher.
 * It holds no key and no message; those stay in rust-core.
 */
class TorController(private val core: CoreBridge, private val stateDir: File) {
    var snapshot by mutableStateOf(TorSnapshot(TorState.STOPPED, 0))
        private set

    private var job: Job? = null

    fun start(scope: CoroutineScope) {
        job?.cancel()
        job = scope.launch(Dispatchers.IO) {
            var accepting: Job? = null
            var failedSince: Long? = null
            while (isActive) {
                try {
                    val status = core.torStatus()
                    snapshot = TorSnapshot(status.state, status.percent.toInt())
                    when (status.state) {
                        TorState.NOT_BUILT -> return@launch
                        TorState.STOPPED -> core.startTor(stateDir.absolutePath)
                        TorState.READY ->
                            if (accepting?.isActive != true) accepting = launch { acceptLoop() }
                        TorState.FAILED -> {
                            // Try again after a pause; start() on a failed node makes a fresh one.
                            val since = failedSince ?: System.currentTimeMillis().also { failedSince = it }
                            if (System.currentTimeMillis() - since >= RESTART_AFTER_MS) {
                                failedSince = null
                                core.startTor(stateDir.absolutePath)
                            }
                        }
                        else -> failedSince = null
                    }
                } catch (e: FacadeException) {
                    snapshot = TorSnapshot(TorState.FAILED, 0)
                }
                delay(POLL_MS)
            }
        }
    }

    /** Stops polling and shuts Tor down. Used when the identity is deleted. */
    fun stop() {
        job?.cancel()
        job = null
        try {
            core.stopTor()
        } catch (e: FacadeException) {
            // Nothing to stop.
        }
        snapshot = TorSnapshot(TorState.STOPPED, 0)
    }

    /** Takes calls from contacts. Each core call waits up to [ACCEPT_SECONDS] and cannot be cancelled. */
    private suspend fun acceptLoop() {
        while (currentCoroutineContext().isActive) {
            try {
                core.acceptTor(ACCEPT_SECONDS)
            } catch (e: FacadeException.TorUnavailable) {
                return
            } catch (e: FacadeException) {
                // A timeout with no caller, or a refused or failed handshake: wait again.
                delay(ACCEPT_RETRY_MS)
            }
        }
    }

    private companion object {
        const val POLL_MS = 2_000L
        const val ACCEPT_SECONDS = 30
        const val ACCEPT_RETRY_MS = 500L
        const val RESTART_AFTER_MS = 30_000L
    }
}

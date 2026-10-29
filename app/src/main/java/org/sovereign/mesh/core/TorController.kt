package org.sovereign.mesh.core

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
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

    /** Recent progress lines, newest last. Fixed sentences with a time; no keys, addresses or messages. */
    val log = mutableStateListOf<TorLogLine>()

    private var job: Job? = null

    /** Adds a line to the progress log, dropping the oldest beyond [LOG_LIMIT]. */
    fun note(text: String) {
        log.add(TorLogLine(System.currentTimeMillis(), text))
        while (log.size > LOG_LIMIT) log.removeAt(0)
    }

    private fun update(next: TorSnapshot) {
        torLogEntry(snapshot, next)?.let(::note)
        snapshot = next
    }

    fun start(scope: CoroutineScope) {
        job?.cancel()
        job = scope.launch(Dispatchers.IO) {
            var accepting: Job? = null
            var failedSince: Long? = null
            while (isActive) {
                try {
                    val status = core.torStatus()
                    update(TorSnapshot(status.state, status.percent.toInt()))
                    when (status.state) {
                        TorState.NOT_BUILT -> return@launch
                        TorState.STOPPED -> core.startTor(stateDir.absolutePath)
                        TorState.READY ->
                            if (accepting?.isActive != true) {
                                // Several workers, so one caller that stalls its handshake (the onion
                                // address is not secret) cannot hold up the real contacts behind it.
                                accepting = launch { repeat(ACCEPT_WORKERS) { launch { acceptLoop() } } }
                            }
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
                    update(TorSnapshot(TorState.FAILED, 0))
                } catch (e: IllegalStateException) {
                    // The core was released by an identity delete; stop instead of polling it.
                    return@launch
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
        } catch (e: IllegalStateException) {
            // Core already released.
        }
        snapshot = TorSnapshot(TorState.STOPPED, 0)
        log.clear()
    }

    /** Takes calls from contacts. Each core call waits up to [ACCEPT_SECONDS] and cannot be cancelled. */
    private suspend fun acceptLoop() {
        while (currentCoroutineContext().isActive) {
            try {
                core.acceptTor(ACCEPT_SECONDS)
            } catch (e: FacadeException.TorUnavailable) {
                return
            } catch (e: IllegalStateException) {
                return // Core released by an identity delete.
            } catch (e: FacadeException) {
                // A timeout with no caller, or a refused or failed handshake: wait again.
                delay(ACCEPT_RETRY_MS)
            }
        }
    }

    private companion object {
        const val POLL_MS = 1_000L
        const val LOG_LIMIT = 40
        const val ACCEPT_WORKERS = 4
        const val ACCEPT_SECONDS = 30
        const val ACCEPT_RETRY_MS = 500L
        const val RESTART_AFTER_MS = 30_000L
    }
}

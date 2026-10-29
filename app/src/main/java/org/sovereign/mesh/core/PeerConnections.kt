package org.sovereign.mesh.core

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.setValue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import uniffi.rust_core.FacadeException

/**
 * Keeps every paired contact connected for as long as the app process lives, not only while
 * their chat is open. One loop per contact receives while the link is up, redials (on the
 * side the core names) when it drops, and sends queued messages as soon as the link returns.
 * Calls into the core block, so everything here runs on the IO dispatcher. It holds no key
 * and no message: those stay in rust-core.
 */
class PeerConnections(
    private val core: CoreBridge,
    private val torState: () -> TorSnapshot,
) {
    /** Bumped whenever something arrives or a link changes, so screens re-read the core at once. */
    var revision by mutableIntStateOf(0)
        private set

    /** Contacts being dialled right now. */
    val dialling = mutableStateMapOf<String, Boolean>()

    /** The last problem worth showing for a contact, such as a message that failed authentication. */
    val problems = mutableStateMapOf<String, String>()

    private var watcher: Job? = null
    private val loops = HashMap<String, Job>()

    fun start(scope: CoroutineScope) {
        watcher?.cancel()
        watcher = scope.launch(Dispatchers.IO) {
            while (isActive) {
                val paired = runCatching { core.pinnedPeers() }.getOrDefault(emptyList()).toSet()
                synchronized(loops) {
                    for (peer in paired) {
                        if (loops[peer]?.isActive != true) loops[peer] = launch { runPeer(peer) }
                    }
                    for (peer in loops.keys.toList()) {
                        if (peer !in paired) loops.remove(peer)?.cancel()
                    }
                }
                delay(WATCH_MS)
            }
        }
    }

    fun stop() {
        watcher?.cancel()
        watcher = null
        synchronized(loops) {
            loops.values.forEach { it.cancel() }
            loops.clear()
        }
        dialling.clear()
        problems.clear()
    }

    /** Asks every screen to re-read the core now, for example after the user sends a message. */
    fun refresh() {
        revision += 1
    }

    private suspend fun runPeer(peer: String) {
        val role = runCatching { core.torRole(peer) }.getOrNull()
        var lastAttempt: Long? = null
        var failures = 0
        var wasLinked = false
        while (currentCoroutineContext().isActive) {
            val linked = runCatching { peer in core.linkedPeers() }.getOrDefault(false)
            if (linked) {
                if (!wasLinked) {
                    wasLinked = true
                    failures = 0
                    lastAttempt = null
                    problems.remove(peer)
                    // Anything written while the contact was away goes out now, in order.
                    runCatching { core.flushPending(peer) }
                    refresh()
                }
                val received = runCatching { core.receiveOnce(peer) }
                val error = received.exceptionOrNull()
                when {
                    error is FacadeException.AuthFailed || error is FacadeException.Malformed -> {
                        problems[peer] = transportStatusText(error)
                        delay(RECEIVE_RETRY_MS)
                    }
                    error != null -> delay(RECEIVE_RETRY_MS)
                    received.getOrNull() == true -> refresh()
                }
                continue
            }
            if (wasLinked) {
                wasLinked = false
                refresh()
            }
            val now = System.currentTimeMillis()
            val ready = torIsReady(torState().state)
            if (shouldDial(role, ready, false, false, lastAttempt?.let { now - it }, failures)) {
                dialling[peer] = true
                lastAttempt = now
                val result = runCatching { core.connectTor(peer) }
                dialling.remove(peer)
                if (result.isSuccess) {
                    problems.remove(peer)
                } else {
                    failures += 1
                }
                refresh()
            }
            delay(DIAL_CHECK_MS)
        }
    }

    private companion object {
        const val WATCH_MS = 2_000L
        const val RECEIVE_RETRY_MS = 2_000L
        const val DIAL_CHECK_MS = 1_000L
    }
}

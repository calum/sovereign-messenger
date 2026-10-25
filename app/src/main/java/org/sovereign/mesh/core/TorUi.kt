package org.sovereign.mesh.core

import uniffi.rust_core.TorRole
import uniffi.rust_core.TorState

/**
 * One fixed sentence per Tor state, shown on the chat list and the chat screen. It
 * states what the core reports and nothing more: "ready" means the onion service is
 * up, not that the traffic is private. Pure, so it is tested on the JVM.
 */
fun torStatusText(state: TorState, percent: Int): String =
    when (state) {
        TorState.NOT_BUILT -> "Tor is not included in this build."
        TorState.STOPPED -> "Tor: off"
        TorState.STARTING -> "Tor: starting"
        TorState.BOOTSTRAPPING -> "Tor: connecting (${percent.coerceIn(0, 100)}%)"
        TorState.PUBLISHING ->
            "Tor: publishing your address. The first time this can take several minutes."
        TorState.READY -> "Tor: ready"
        TorState.FAILED -> "Tor: could not start. Check the internet connection."
    }

/** Messages can be sent over Tor only when the onion service is up. */
fun torIsReady(state: TorState): Boolean = state == TorState.READY

/** Shortest and longest wait between two automatic dial attempts. */
private const val DIAL_BACKOFF_FIRST_MS = 10_000L
private const val DIAL_BACKOFF_MAX_MS = 120_000L

/**
 * Whether this phone should start dialling its contact now. Only the side the core
 * names [TorRole.DIAL] ever dials; the other waits to be called, so the two phones
 * never both dial and replace each other's session. After a failed attempt the wait
 * doubles each time, up to two minutes, so a contact who is offline is not hammered.
 *
 * [msSinceLastAttempt] is null before the first attempt; [failures] counts failed
 * attempts since the last successful link.
 */
fun shouldDial(
    role: TorRole?,
    torReady: Boolean,
    linkAlive: Boolean,
    busy: Boolean,
    msSinceLastAttempt: Long?,
    failures: Int,
): Boolean {
    if (role != TorRole.DIAL || !torReady || linkAlive || busy) return false
    val last = msSinceLastAttempt ?: return true
    val doublings = (failures - 1).coerceIn(0, 20)
    val wait = (DIAL_BACKOFF_FIRST_MS shl doublings).coerceAtMost(DIAL_BACKOFF_MAX_MS)
    return failures == 0 || last >= wait
}

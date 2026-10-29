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

/**
 * How far along Tor start-up is. [fraction] is null when the core reports a stage with no
 * measurable progress (the bar then runs indeterminate); [active] is false once Tor is up
 * or has stopped, when no bar is shown.
 */
data class TorProgress(val fraction: Float?, val active: Boolean)

fun torProgress(state: TorState, percent: Int): TorProgress =
    when (state) {
        TorState.STARTING -> TorProgress(null, true)
        TorState.BOOTSTRAPPING -> TorProgress(percent.coerceIn(0, 100) / 100f, true)
        TorState.PUBLISHING -> TorProgress(null, true)
        TorState.NOT_BUILT, TorState.STOPPED, TorState.READY, TorState.FAILED -> TorProgress(1f, false)
    }

/** One line of the progress log. Holds only a time and a fixed sentence, never an address or key. */
data class TorLogLine(val atMillis: Long, val text: String)

/** Bootstrap progress is logged at every step of this many percent, not on every poll. */
private const val LOG_PERCENT_STEP = 10

/**
 * The log line for a status change, or null when nothing worth showing changed. A new state
 * always logs; within bootstrapping only a new 10% step does. Pure, so it is tested on the JVM.
 */
fun torLogEntry(previous: TorSnapshot?, current: TorSnapshot): String? {
    if (previous == null || previous.state != current.state) {
        return when (current.state) {
            TorState.NOT_BUILT -> "Tor is not included in this build"
            TorState.STOPPED -> "Tor stopped"
            TorState.STARTING -> "Starting Tor"
            TorState.BOOTSTRAPPING -> "Connecting to the Tor network (${current.percent.coerceIn(0, 100)}%)"
            TorState.PUBLISHING -> "Publishing your onion address. The first time this can take several minutes"
            TorState.READY -> "Tor is ready. Contacts can reach you"
            TorState.FAILED -> "Tor failed to start. Will retry"
        }
    }
    if (current.state == TorState.BOOTSTRAPPING &&
        current.percent / LOG_PERCENT_STEP != (previous?.percent ?: 0) / LOG_PERCENT_STEP
    ) {
        return "Connecting to the Tor network (${current.percent.coerceIn(0, 100)}%)"
    }
    return null
}

/**
 * What the chat screen says about the contact's side of the link. The core only learns that
 * the contact is online when a Tor connection to or from them succeeds, so "not connected"
 * means not yet reached, not that they are offline.
 */
fun contactLinkText(role: TorRole?, torReady: Boolean, linkAlive: Boolean, dialing: Boolean): String =
    when {
        linkAlive -> "Contact is connected over Tor"
        !torReady -> "Waiting for your Tor to be ready"
        dialing -> "Reaching your contact over Tor..."
        role == TorRole.DIAL -> "Contact not reached yet. Trying again shortly"
        else -> "Waiting for your contact to connect (they need Tor ready too)"
    }

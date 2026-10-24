package org.sovereign.mesh.core

/**
 * What the discreet "P2P mesh" header can say. Each value is a fact the core
 * reports: a session with a live socket, a listener waiting, a session with no
 * socket, or no session. The core has no single "secured" flag, so none of these
 * values claims security.
 */
enum class MeshLink { CONNECTED, LISTENING, NOT_CONNECTED, NO_SESSION }

data class MeshStatus(val link: MeshLink, val label: String)

/**
 * Maps the core's answers to a header state. Pure, so it is tested on the JVM.
 *
 * [sessions] is `peers()` (every open session), [linked] is `linkedPeers()`
 * (sessions with a live socket) and [listening] is `listeningPeer()`. [peer] is the
 * contact on the chat screen, or null on the chat list, where any peer counts.
 *
 * Precedence: a live connection beats a waiting listener, which beats a session
 * with no socket, which beats no session. A listener or connection for another
 * contact does not show on this chat.
 */
fun meshStatus(
    sessions: List<String>,
    linked: List<String>,
    listening: String?,
    peer: String? = null,
): MeshStatus {
    val connected = if (peer == null) linked.isNotEmpty() else peer in linked
    if (connected) return MeshStatus(MeshLink.CONNECTED, "P2P mesh: connected")

    val listeningHere = if (peer == null) listening != null else listening == peer
    if (listeningHere) return MeshStatus(MeshLink.LISTENING, "P2P mesh: waiting for contact")

    val hasSession = if (peer == null) sessions.isNotEmpty() else peer in sessions
    return if (hasSession) {
        MeshStatus(MeshLink.NOT_CONNECTED, "P2P mesh: not connected")
    } else {
        MeshStatus(MeshLink.NO_SESSION, "P2P mesh: no session")
    }
}

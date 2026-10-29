package org.sovereign.mesh.core

/**
 * The screen stack, as plain strings (contact names only). It lives in `SovereignApp`'s RAM-only
 * state, so it survives rotation and is never written to saved instance state or disk.
 * The system back gesture pops one entry; at the root it leaves the app. Pure, so it is
 * tested on the JVM.
 */
object Route {
    const val LIST = "list"
    const val PAIR = "pair"
    const val UPDATE = "update"
    const val SETTINGS = "settings"
    private const val CHAT_PREFIX = "chat:"

    fun chat(peer: String): String = CHAT_PREFIX + peer

    /** The contact a chat route is for, or null for any other route. */
    fun peerOf(route: String): String? =
        if (route.startsWith(CHAT_PREFIX)) route.removePrefix(CHAT_PREFIX) else null
}

fun initialStack(): ArrayList<String> = arrayListOf(Route.LIST)

/** Opens [route] on top of the stack. Opening the screen already on top changes nothing. */
fun push(stack: List<String>, route: String): ArrayList<String> =
    if (stack.lastOrNull() == route) ArrayList(stack) else ArrayList(stack + route)

/** Goes back one screen. The root screen stays. */
fun pop(stack: List<String>): ArrayList<String> =
    if (stack.size > 1) ArrayList(stack.dropLast(1)) else ArrayList(stack)

fun canGoBack(stack: List<String>): Boolean = stack.size > 1

/** Drops every entry for a contact who was removed, so back never lands on a dead chat. */
fun withoutPeer(stack: List<String>, peer: String): ArrayList<String> {
    val kept = stack.filter { Route.peerOf(it) != peer }
    return if (kept.isEmpty()) initialStack() else ArrayList(kept)
}

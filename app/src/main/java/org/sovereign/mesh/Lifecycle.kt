package org.sovereign.mesh

/**
 * Decides whether a stop of the activity means the user has left the app.
 *
 * Android also stops the activity on rotation and other configuration changes,
 * and recreates it straight away. `isChangingConfigurations` is true in that case,
 * so chats survive it. Every other stop wipes them, because the app may be
 * backgrounded or killed and chats must not outlive the session (CLAUDE.md rule 1).
 */
internal fun shouldWipeOnStop(isChangingConfigurations: Boolean): Boolean = !isChangingConfigurations

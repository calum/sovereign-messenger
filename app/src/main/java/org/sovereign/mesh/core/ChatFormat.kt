package org.sovereign.mesh.core

import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale
import uniffi.rust_core.ChatMessage
import uniffi.rust_core.MessageState

/**
 * Text and grouping rules for the chat screens. Pure, so they are tested on the JVM.
 * Times are this phone's own clock: when a message was sent or arrived here, and when
 * the link to a contact last was up. The contact's clock is never used.
 */

private val clock: DateTimeFormatter = DateTimeFormatter.ofPattern("HH:mm", Locale.getDefault())
private val shortDate: DateTimeFormatter = DateTimeFormatter.ofPattern("d MMM", Locale.getDefault())
private val longDate: DateTimeFormatter = DateTimeFormatter.ofPattern("EEE d MMM", Locale.getDefault())

private const val MINUTE_MS = 60_000L

fun clockTime(ms: Long, zone: ZoneId = ZoneId.systemDefault()): String =
    clock.format(Instant.ofEpochMilli(ms).atZone(zone))

private fun dayOf(ms: Long, zone: ZoneId): LocalDate = Instant.ofEpochMilli(ms).atZone(zone).toLocalDate()

/** "Today", "Yesterday" or a date, for the separators inside a chat. */
fun dayLabel(ms: Long, nowMs: Long, zone: ZoneId = ZoneId.systemDefault()): String {
    val day = dayOf(ms, zone)
    val today = dayOf(nowMs, zone)
    return when (day) {
        today -> "Today"
        today.minusDays(1) -> "Yesterday"
        else -> longDate.format(day)
    }
}

/** The short time shown on a chat list row: the clock today, then "Yesterday", then a date. */
fun listTime(ms: Long, nowMs: Long, zone: ZoneId = ZoneId.systemDefault()): String {
    val day = dayOf(ms, zone)
    val today = dayOf(nowMs, zone)
    return when (day) {
        today -> clockTime(ms, zone)
        today.minusDays(1) -> "Yesterday"
        else -> shortDate.format(day)
    }
}

/**
 * The line under a contact's name. "Online" means the link is up right now. A contact
 * who has not connected since this app started has no last-seen time to show.
 */
fun presenceText(online: Boolean, lastSeenMs: Long?, nowMs: Long, zone: ZoneId = ZoneId.systemDefault()): String {
    if (online) return "Online"
    if (lastSeenMs == null) return "Not connected yet"
    val ago = nowMs - lastSeenMs
    return when {
        ago < MINUTE_MS -> "Last seen just now"
        ago < 60 * MINUTE_MS -> "Last seen ${ago / MINUTE_MS} min ago"
        else -> {
            val day = dayOf(lastSeenMs, zone)
            val today = dayOf(nowMs, zone)
            when (day) {
                today -> "Last seen today at ${clockTime(lastSeenMs, zone)}"
                today.minusDays(1) -> "Last seen yesterday at ${clockTime(lastSeenMs, zone)}"
                else -> "Last seen ${shortDate.format(day)}"
            }
        }
    }
}

/**
 * What the chat header says while the contact is not online. It names what this phone is
 * doing about it, so a missing contact is explained and not just shown as grey.
 */
fun reachText(
    name: String,
    online: Boolean,
    lastSeenMs: Long?,
    nowMs: Long,
    dialling: Boolean,
    torReady: Boolean,
    zone: ZoneId = ZoneId.systemDefault(),
): String = when {
    online -> "Online"
    dialling -> "Connecting to $name…"
    !torReady -> "Waiting for Tor · ${presenceText(false, lastSeenMs, nowMs, zone)}"
    else -> presenceText(false, lastSeenMs, nowMs, zone)
}

/** Short mark under a sent message. Plain text so it needs no icon font. */
fun deliveryMark(state: MessageState): String = when (state) {
    MessageState.PENDING -> "Sending…"
    MessageState.SENT -> "✓"
    MessageState.DELIVERED, MessageState.READ -> "✓✓"
    MessageState.RECEIVED -> ""
}

/** Spoken form of [deliveryMark], for screen readers. */
fun deliveryDescription(state: MessageState): String = when (state) {
    MessageState.PENDING -> "Waiting to send"
    MessageState.SENT -> "Sent"
    MessageState.DELIVERED -> "Delivered"
    MessageState.READ -> "Read"
    MessageState.RECEIVED -> ""
}

/** One row of the chat: a day separator or a message. */
sealed interface ChatItem {
    val key: String

    data class Day(val label: String, val ms: Long) : ChatItem {
        override val key get() = "day-$ms"
    }

    /** [showSender] is true for the first message of a run from the same side. */
    data class Bubble(val message: ChatMessage, val showSender: Boolean) : ChatItem {
        override val key get() = "${if (message.outgoing) "o" else "i"}-${message.id}"
    }
}

/** Inserts a separator at each new day and marks the first message of each run per sender. */
fun buildChatItems(messages: List<ChatMessage>, nowMs: Long, zone: ZoneId = ZoneId.systemDefault()): List<ChatItem> {
    val items = ArrayList<ChatItem>(messages.size + 4)
    var lastDay: LocalDate? = null
    var lastOutgoing: Boolean? = null
    for (m in messages) {
        val at = m.atMs.toLong()
        val day = dayOf(at, zone)
        if (day != lastDay) {
            items += ChatItem.Day(dayLabel(at, nowMs, zone), at)
            lastDay = day
            lastOutgoing = null
        }
        items += ChatItem.Bubble(m, showSender = m.outgoing != lastOutgoing)
        lastOutgoing = m.outgoing
    }
    return items
}

/** One line for a chat list row: "You: " before our own messages, newlines flattened. */
fun previewText(message: ChatMessage, maxLength: Int = 80): String {
    val flat = message.text.replace(Regex("\\s+"), " ").trim()
    val clipped = if (flat.length > maxLength) flat.take(maxLength - 1) + "…" else flat
    return if (message.outgoing) "You: $clipped" else clipped
}

/** The letter in a contact's round avatar. */
fun initialOf(name: String): String =
    name.trim().firstOrNull { it.isLetterOrDigit() }?.uppercaseChar()?.toString() ?: "?"

/**
 * Groups a fingerprint in blocks of four so two people can read it aloud and compare it.
 * Separators already in the text are dropped first.
 */
fun groupFingerprint(fingerprint: String): String =
    fingerprint.filter { !it.isWhitespace() && it != ':' && it != '-' }
        .chunked(4)
        .joinToString(" ")

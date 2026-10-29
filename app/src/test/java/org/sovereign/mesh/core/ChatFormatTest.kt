package org.sovereign.mesh.core

import java.time.ZoneId
import java.time.ZonedDateTime
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.rust_core.ChatMessage
import uniffi.rust_core.MessageState

class ChatFormatTest {
    private val zone: ZoneId = ZoneId.of("UTC")

    private fun at(day: Int, hour: Int, minute: Int = 0): Long =
        ZonedDateTime.of(2026, 10, day, hour, minute, 0, 0, zone).toInstant().toEpochMilli()

    private fun msg(id: Long, outgoing: Boolean, atMs: Long, text: String = "hi", state: MessageState = MessageState.SENT) =
        ChatMessage(id.toULong(), outgoing, atMs.toULong(), if (outgoing) state else MessageState.RECEIVED, text)

    @Test
    fun onlineWinsOverAnyLastSeen() {
        assertEquals("Online", presenceText(true, at(29, 9), at(29, 10), zone))
    }

    @Test
    fun neverConnectedHasNoLastSeen() {
        assertEquals("Not connected yet", presenceText(false, null, at(29, 10), zone))
    }

    @Test
    fun lastSeenReadsInMinutesThenClockThenDate() {
        val now = at(29, 15)
        assertEquals("Last seen just now", presenceText(false, now - 20_000, now, zone))
        assertEquals("Last seen 5 min ago", presenceText(false, now - 5 * 60_000, now, zone))
        assertEquals("Last seen today at 11:30", presenceText(false, at(29, 11, 30), now, zone))
        assertEquals("Last seen yesterday at 23:10", presenceText(false, at(28, 23, 10), now, zone))
        assertEquals("Last seen 25 Oct", presenceText(false, at(25, 8), now, zone).replace("Oct.", "Oct"))
    }

    @Test
    fun headerExplainsWhatTheAppIsDoingAboutAMissingContact() {
        val now = at(29, 15)
        assertEquals("Online", reachText("Sam", true, null, now, dialling = false, torReady = true, zone = zone))
        assertEquals("Connecting to Sam…", reachText("Sam", false, null, now, dialling = true, torReady = true, zone = zone))
        assertTrue(reachText("Sam", false, null, now, dialling = false, torReady = false, zone = zone).startsWith("Waiting for Tor"))
        assertEquals("Not connected yet", reachText("Sam", false, null, now, dialling = false, torReady = true, zone = zone))
    }

    @Test
    fun listTimeIsClockTodayThenYesterdayThenDate() {
        val now = at(29, 15)
        assertEquals("09:05", listTime(at(29, 9, 5), now, zone))
        assertEquals("Yesterday", listTime(at(28, 9), now, zone))
        assertTrue(listTime(at(20, 9), now, zone).startsWith("20"))
    }

    @Test
    fun deliveryMarksFollowTheState() {
        assertEquals("Sending…", deliveryMark(MessageState.PENDING))
        assertEquals("✓", deliveryMark(MessageState.SENT))
        assertEquals("✓✓", deliveryMark(MessageState.DELIVERED))
        assertEquals("✓✓", deliveryMark(MessageState.READ))
        assertEquals("Read", deliveryDescription(MessageState.READ))
        assertEquals("Delivered", deliveryDescription(MessageState.DELIVERED))
    }

    @Test
    fun separatorsAndSenderLabelsFollowTheConversation() {
        val items = buildChatItems(
            listOf(
                msg(1, false, at(28, 9)),
                msg(2, false, at(28, 9, 1)),
                msg(3, true, at(28, 9, 2)),
                msg(4, true, at(29, 8)),
            ),
            nowMs = at(29, 15),
            zone = zone,
        )
        assertEquals(6, items.size)
        assertEquals("Yesterday", (items[0] as ChatItem.Day).label)
        assertTrue((items[1] as ChatItem.Bubble).showSender)
        assertEquals(false, (items[2] as ChatItem.Bubble).showSender) // same sender, same run
        assertTrue((items[3] as ChatItem.Bubble).showSender) // we answer
        assertEquals("Today", (items[4] as ChatItem.Day).label)
        assertTrue((items[5] as ChatItem.Bubble).showSender) // a new day starts a new run
    }

    @Test
    fun itemKeysAreUniqueEvenWhenBothSidesUseTheSameId() {
        val items = buildChatItems(listOf(msg(7, false, at(29, 9)), msg(7, true, at(29, 10))), at(29, 15), zone)
        assertEquals(items.size, items.map { it.key }.toSet().size)
    }

    @Test
    fun previewFlattensNewlinesAndMarksOurOwn() {
        assertEquals("You: a b", previewText(msg(1, true, 0, "a\n  b")))
        assertEquals("a b", previewText(msg(1, false, 0, "a\n  b")))
        val long = previewText(msg(1, false, 0, "x".repeat(200)), maxLength = 10)
        assertEquals(10, long.length)
        assertTrue(long.endsWith("…"))
    }

    @Test
    fun avatarInitialSkipsPunctuationAndHandlesEmpty() {
        assertEquals("S", initialOf("sam"))
        assertEquals("A", initialOf("  .ana"))
        assertEquals("?", initialOf(""))
    }

    @Test
    fun fingerprintIsGroupedInFours() {
        assertEquals("abcd 1234 ef", groupFingerprint("abcd1234ef"))
        assertEquals("abcd 1234", groupFingerprint("ab:cd 12-34"))
    }
}

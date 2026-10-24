package org.sovereign.mesh.ui

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch

private data class TourCard(val title: String, val body: String)

private val cards = listOf(
    TourCard(
        "Serverless P2P",
        "No servers, no cloud. Your phone talks directly to your friends' phones over Tor onion services.",
    ),
    TourCard(
        "RAM-only memory",
        "Nothing is written to flash storage. Chats exist only while the app is open and vanish when it closes.",
    ),
    TourCard(
        "Scan to join",
        "Meet in person and scan each other's QR code. That is how new people are verified and trusted.",
    ),
)

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun TourScreen(onFinished: () -> Unit) {
    val pagerState = rememberPagerState(pageCount = { cards.size })
    val scope = rememberCoroutineScope()

    Column(modifier = Modifier.fillMaxSize().padding(24.dp)) {
        HorizontalPager(state = pagerState, modifier = Modifier.weight(1f)) { page ->
            Column(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(cards[page].title, style = MaterialTheme.typography.headlineMedium)
                Text(
                    cards[page].body,
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.padding(top = 16.dp),
                )
            }
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text("${pagerState.currentPage + 1} / ${cards.size}")
            if (pagerState.currentPage < cards.lastIndex) {
                Button(onClick = { scope.launch { pagerState.animateScrollToPage(pagerState.currentPage + 1) } }) {
                    Text("Next")
                }
            } else {
                Button(onClick = onFinished) { Text("Get started") }
            }
        }
    }
}

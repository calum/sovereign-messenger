package org.sovereign.mesh.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch

internal data class TourCard(val title: String, val body: String)

internal val tourCards = listOf(
    TourCard(
        "No server in the middle",
        "Your phone talks to your friends' phones through Tor, with no server of ours in between. " +
            "This is experimental and has not been tested between two phones yet, so do not rely on it to hide you.",
    ),
    TourCard(
        "Kept in memory only",
        "Messages are never saved to storage. They stay in this phone's memory while the app is running " +
            "and are gone when Android closes the app or the phone restarts.",
    ),
    TourCard(
        "Scan to add people",
        "Meet in person and scan each other's QR codes. That is how new people are verified and trusted.",
    ),
)

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun TourScreen(onFinished: () -> Unit) {
    val pagerState = rememberPagerState(pageCount = { tourCards.size })
    val scope = rememberCoroutineScope()
    val page = pagerState.currentPage

    // Back steps to the previous card; on the first card it leaves the app like any other root screen.
    BackHandler(enabled = page > 0) {
        scope.launch { pagerState.animateScrollToPage(page - 1) }
    }

    Column(modifier = Modifier.fillMaxSize().padding(24.dp)) {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
            if (page < tourCards.lastIndex) TextButton(onClick = onFinished) { Text("Skip") }
        }
        HorizontalPager(state = pagerState, modifier = Modifier.weight(1f)) { index ->
            Column(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(
                    tourCards[index].title,
                    style = MaterialTheme.typography.headlineMedium,
                    textAlign = TextAlign.Center,
                )
                Text(
                    tourCards[index].body,
                    style = MaterialTheme.typography.bodyLarge,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(top = 16.dp),
                )
            }
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                tourCards.indices.forEach { index ->
                    Column(
                        modifier = Modifier
                            .size(8.dp)
                            .background(
                                if (index == page) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant,
                                CircleShape,
                            ),
                    ) {}
                }
            }
            if (page < tourCards.lastIndex) {
                Button(onClick = { scope.launch { pagerState.animateScrollToPage(page + 1) } }) { Text("Next") }
            } else {
                Button(onClick = onFinished) { Text("Get started") }
            }
        }
    }
}

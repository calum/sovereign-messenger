package org.sovereign.mesh.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.State
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import org.sovereign.mesh.core.initialOf

/** How often clock-based text such as "Last seen 3 min ago" is refreshed. */
private const val NOW_TICK_MS = 15_000L

/** The current time, refreshed every few seconds so relative text does not go stale. */
@Composable
fun rememberNow(): State<Long> = produceState(System.currentTimeMillis()) {
    while (true) {
        delay(NOW_TICK_MS)
        value = System.currentTimeMillis()
    }
}

/**
 * Top bar used by every screen. [title] is a composable so a chat can show a name with a
 * status line under it. With [onBack] set it shows the back arrow, which does what the
 * system back gesture does.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScreenBar(
    onBack: (() -> Unit)?,
    title: @Composable () -> Unit,
    actions: @Composable RowScope.() -> Unit = {},
) {
    TopAppBar(
        title = title,
        navigationIcon = {
            if (onBack != null) {
                IconButton(onClick = onBack) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                }
            }
        },
        actions = actions,
    )
}

/** Plain text title for [ScreenBar]. */
@Composable
fun BarTitle(text: String) {
    Text(text, style = MaterialTheme.typography.titleLarge)
}

/** A name with a quieter line under it, such as a contact and whether they are online. */
@Composable
fun BarTitleWithSubtitle(name: String, subtitle: String) {
    Column {
        Text(name, style = MaterialTheme.typography.titleMedium, maxLines = 1)
        Text(
            subtitle,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
        )
    }
}

/** The ⋮ button and its menu. Each entry is a label and an action. */
@Composable
fun OverflowMenu(entries: List<Pair<String, () -> Unit>>) {
    var open by remember { mutableStateOf(false) }
    Box {
        IconButton(onClick = { open = true }) {
            Icon(Icons.Default.MoreVert, contentDescription = "More options")
        }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            entries.forEach { (label, action) ->
                DropdownMenuItem(
                    text = { Text(label) },
                    onClick = {
                        open = false
                        action()
                    },
                )
            }
        }
    }
}

/** Round avatar with the contact's initial. A dot in the corner shows they are online. */
@Composable
fun Avatar(name: String, online: Boolean, size: Dp = 44.dp) {
    Box(modifier = Modifier.size(size)) {
        Box(
            modifier = Modifier
                .size(size)
                .background(MaterialTheme.colorScheme.primaryContainer, CircleShape),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                initialOf(name),
                color = MaterialTheme.colorScheme.onPrimaryContainer,
                style = MaterialTheme.typography.titleMedium,
                fontSize = (size.value * 0.4f).sp,
            )
        }
        if (online) {
            Box(
                modifier = Modifier
                    .size(size * 0.3f)
                    .align(Alignment.BottomEnd)
                    .background(MaterialTheme.colorScheme.surface, CircleShape)
                    .padding(2.dp)
                    .background(MaterialTheme.colorScheme.tertiary, CircleShape),
            )
        }
    }
}

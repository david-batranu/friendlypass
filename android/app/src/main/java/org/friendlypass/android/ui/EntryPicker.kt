package org.friendlypass.android.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import org.friendlypass.android.FriendlypassApp
import org.friendlypass.android.vault.model.EntrySummary
import org.friendlypass.android.vault.model.VaultException

/**
 * Searchable entry list used by the "Search friendlypass…" autofill chip: the caller gets one [EntrySummary]
 * back. Shown as a full-screen dialog so it can float over another app.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EntryPicker(
    onEntrySelected: (EntrySummary) -> Unit,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
    /** Only entries that can produce a one-time code (autofill picker opened for an OTP field). */
    onlyWithTotp: Boolean = false,
) {
    val context = LocalContext.current
    val app = context.applicationContext as FriendlypassApp
    var query by remember { mutableStateOf("") }
    val results = remember(query, onlyWithTotp) {
        if (query.isBlank()) {
            emptyList()
        } else {
            runCatching { app.vault.search(query) }.getOrElse { error ->
                if (error is VaultException) emptyList() else throw error
            }.filter { !onlyWithTotp || it.hasTotp }
        }
    }

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false),
    ) {
        Surface(modifier = modifier.fillMaxSize()) {
            Scaffold(
                topBar = {
                    TopAppBar(
                        title = { Text("Search friendlypass") },
                        navigationIcon = {
                            IconButton(onClick = onDismiss) {
                                Icon(Icons.Filled.Close, contentDescription = "Close")
                            }
                        },
                    )
                },
            ) { padding ->
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(padding),
                ) {
                    OutlinedTextField(
                        value = query,
                        onValueChange = { query = it },
                        singleLine = true,
                        placeholder = { Text(if (onlyWithTotp) "Search entries with a one-time code" else "Search entries") },
                        leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp)
                            .testTag("picker-search"),
                    )
                    Spacer(Modifier.height(8.dp))
                    when {
                        query.isBlank() -> Text(
                            "Type a title, username, URL or tag",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(24.dp),
                        )

                        results.isEmpty() -> Text(
                            "No entries match \"$query\"",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(24.dp),
                        )

                        else -> LazyColumn(modifier = Modifier.fillMaxSize()) {
                            items(results, key = { it.uuid }) { entry ->
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable { onEntrySelected(entry) }
                                        .padding(horizontal = 16.dp, vertical = 12.dp)
                                        .testTag("picker-entry-${entry.uuid}"),
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    EntryAvatar(title = entry.title)
                                    Spacer(Modifier.width(16.dp))
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            entry.title,
                                            style = MaterialTheme.typography.titleMedium,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis,
                                        )
                                        Text(
                                            entry.username.ifBlank { entry.url },
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                                            maxLines = 1,
                                            overflow = TextOverflow.Ellipsis,
                                        )
                                    }
                                }
                                HorizontalDivider()
                            }
                        }
                    }
                }
            }
        }
    }
}

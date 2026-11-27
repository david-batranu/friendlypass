package org.friendlypass.android.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.friendlypass.android.FriendlypassApp
import org.friendlypass.android.vault.model.EntrySummary
import org.friendlypass.android.vault.model.GroupNode
import org.friendlypass.android.vault.model.VaultState

/**
 * Group/entry browser with a search field. Search spans every entry; without a query it shows the groups and
 * entries of the current group. Groups are navigated with the back arrow.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BrowserScreen(
    onOpenEntry: (String) -> Unit,
    onOpenSettings: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val app = context.applicationContext as FriendlypassApp
    val state by app.vault.state.collectAsStateWithLifecycle()
    val revision by app.vault.revision.collectAsStateWithLifecycle()
    val unlocked = state as? VaultState.Unlocked ?: return

    val snackbar = remember { SnackbarHostState() }
    LaunchedEffect(app.vault) {
        app.vault.syncEvents.collect { message ->
            snackbar.showSnackbar(message, withDismissAction = false)
        }
    }

    val groups = remember(unlocked, revision) { app.vault.groups() }
    val rootUuid = remember(unlocked, revision) { app.vault.rootGroupUuid() }
    var currentGroupUuid by rememberSaveable(unlocked.db.uri, rootUuid) { mutableStateOf(rootUuid) }
    var query by rememberSaveable(unlocked.db.uri) { mutableStateOf("") }

    val currentGroup = groups.firstOrNull { it.uuid == currentGroupUuid } ?: groups.first { it.uuid == rootUuid }
    val childGroups = groups.filter { it.parentUuid == currentGroup.uuid }.sortedBy { it.name.lowercase() }
    val entries = remember(unlocked, revision, currentGroup.uuid, query) {
        if (query.isBlank()) {
            app.vault.entriesInGroup(currentGroup.uuid)
        } else {
            app.vault.search(query)
        }
    }

    val canGoBack = query.isNotBlank() || currentGroup.uuid != rootUuid

    Scaffold(
        modifier = modifier.fillMaxSize(),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        when {
                            query.isNotBlank() -> "Search"
                            else -> currentGroup.name
                        },
                    )
                },
                navigationIcon = {
                    if (canGoBack) {
                        IconButton(onClick = {
                            if (query.isNotBlank()) {
                                query = ""
                            } else {
                                currentGroupUuid = currentGroup.parentUuid ?: rootUuid
                            }
                        }) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                        }
                    }
                },
                actions = {
                    IconButton(onClick = onOpenSettings, modifier = Modifier.testTag("open-settings")) {
                        Icon(Icons.Filled.Settings, contentDescription = "Settings")
                    }
                },
            )
        },
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding),
        ) {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                singleLine = true,
                placeholder = { Text("Search entries") },
                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp)
                    .testTag("search"),
            )
            Text(
                text = unlocked.databaseName,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp),
            )

            if (query.isBlank() && childGroups.isNotEmpty()) {
                LazyColumn(modifier = Modifier.fillMaxSize()) {
                    items(childGroups, key = { it.uuid }) { group ->
                        GroupRow(group = group) { currentGroupUuid = group.uuid }
                        HorizontalDivider()
                    }
                    items(entries, key = { it.uuid }) { entry ->
                        EntryRow(entry = entry, onClick = { onOpenEntry(entry.uuid) })
                        HorizontalDivider()
                    }
                }
            } else if (entries.isEmpty()) {
                Text(
                    text = if (query.isBlank()) "This group has no entries" else "No entries match \"$query\"",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(24.dp),
                )
            } else {
                LazyColumn(modifier = Modifier.fillMaxSize()) {
                    items(entries, key = { it.uuid }) { entry ->
                        EntryRow(entry = entry, onClick = { onOpenEntry(entry.uuid) })
                        HorizontalDivider()
                    }
                }
            }
        }
    }
}

@Composable
private fun GroupRow(group: GroupNode, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        EntryAvatar(title = group.name)
        Spacer(Modifier.width(16.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(group.name, style = MaterialTheme.typography.titleMedium)
            Text(
                text = "${group.entryCount} ${if (group.entryCount == 1) "entry" else "entries"}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
internal fun EntryRow(entry: EntrySummary, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .testTag("entry-${entry.uuid}"),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        EntryAvatar(title = entry.title)
        Spacer(Modifier.width(16.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = entry.title,
                style = MaterialTheme.typography.titleMedium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            val subtitle = entry.username.ifBlank { entry.url }
            if (subtitle.isNotBlank()) {
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
        if (entry.hasTotp) {
            Badge("TOTP")
        }
        if (entry.hasPasskey) {
            Spacer(Modifier.width(4.dp))
            Badge("Passkey")
        }
    }
}

@Composable
private fun Badge(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(start = 8.dp),
    )
}

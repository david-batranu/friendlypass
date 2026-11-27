package org.friendlypass.android.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.launch
import org.friendlypass.android.FriendlypassApp
import org.friendlypass.android.vault.model.EntrySummary
import org.friendlypass.android.vault.model.GroupNode
import org.friendlypass.android.vault.model.VaultException
import org.friendlypass.android.vault.model.VaultState

private enum class EntryFilter(val label: String) {
    ALL("All"),
    TOTP("TOTP"),
    PASSKEYS("Passkeys"),
}

/**
 * Group/entry browser with search, quick filters (All / TOTP / Passkeys), quick-copy password,
 * group management (create/rename/delete), manual sync, quick lock, and a FAB to add entries.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BrowserScreen(
    onOpenEntry: (String) -> Unit,
    onCreateEntry: (String) -> Unit,
    onOpenSettings: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val app = context.applicationContext as FriendlypassApp
    val scope = rememberCoroutineScope()
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
    var filter by rememberSaveable(unlocked.db.uri) { mutableStateOf(EntryFilter.ALL) }
    var syncing by remember { mutableStateOf(false) }

    var showCreateGroup by remember { mutableStateOf(false) }
    var showDatabaseSwitcher by remember { mutableStateOf(false) }
    var groupToRename by remember { mutableStateOf<GroupNode?>(null) }
    var groupToDelete by remember { mutableStateOf<GroupNode?>(null) }

    val currentGroup = groups.firstOrNull { it.uuid == currentGroupUuid } ?: groups.first { it.uuid == rootUuid }
    val childGroups = remember(groups, currentGroup.uuid) {
        groups.filter { it.parentUuid == currentGroup.uuid }.sortedBy { it.name.lowercase() }
    }
    val rawEntries = remember(unlocked, revision, currentGroup.uuid, query, filter) {
        when {
            query.isNotBlank() -> app.vault.search(query)
            filter != EntryFilter.ALL -> app.vault.allEntries()
            else -> app.vault.entriesInGroup(currentGroup.uuid)
        }
    }
    val entries = remember(rawEntries, filter) {
        when (filter) {
            EntryFilter.ALL -> rawEntries
            EntryFilter.TOTP -> rawEntries.filter { it.hasTotp }
            EntryFilter.PASSKEYS -> rawEntries.filter { it.hasPasskey }
        }
    }

    val canGoBack = query.isNotBlank() || filter != EntryFilter.ALL || currentGroup.uuid != rootUuid

    fun quickCopyPassword(entry: EntrySummary) {
        val detail = runCatching { app.vault.entry(entry.uuid) }.getOrNull() ?: return
        if (detail.password.isEmpty()) {
            scope.launch { snackbar.showSnackbar("Entry has no password") }
            return
        }
        SecureClipboard.copySecret(context, "Password", detail.password)
        scope.launch { snackbar.showSnackbar("Password copied — clipboard clears in 30 s") }
    }

    if (showDatabaseSwitcher) {
        DatabaseSwitcherDialog(
            currentDb = unlocked.db,
            onDismiss = { showDatabaseSwitcher = false },
            onSelect = { chosen ->
                app.store.remember(chosen)
                app.vault.selectDatabase(chosen)
            },
            onManageDatabases = { app.vault.clearDatabase() },
        )
    }

    if (showCreateGroup) {
        GroupNameDialog(
            title = "New group",
            initialName = "",
            confirmLabel = "Create",
            onDismiss = { showCreateGroup = false },
            onConfirm = { name ->
                showCreateGroup = false
                scope.launch {
                    try {
                        app.vault.createGroup(currentGroup.uuid, name)
                        snackbar.showSnackbar("Group \"$name\" created")
                    } catch (e: VaultException) {
                        snackbar.showSnackbar(e.message ?: "Could not create group")
                    }
                }
            },
        )
    }

    groupToRename?.let { target ->
        GroupNameDialog(
            title = "Rename group",
            initialName = target.name,
            confirmLabel = "Rename",
            onDismiss = { groupToRename = null },
            onConfirm = { name ->
                groupToRename = null
                scope.launch {
                    try {
                        app.vault.renameGroup(target.uuid, name)
                        snackbar.showSnackbar("Group renamed")
                    } catch (e: VaultException) {
                        snackbar.showSnackbar(e.message ?: "Could not rename group")
                    }
                }
            },
        )
    }

    groupToDelete?.let { target ->
        AlertDialog(
            onDismissRequest = { groupToDelete = null },
            title = { Text("Delete \"${target.name}\"?") },
            text = { Text("This group and its entries will be moved to the Recycle Bin.") },
            confirmButton = {
                Button(onClick = {
                    groupToDelete = null
                    scope.launch {
                        try {
                            app.vault.deleteGroup(target.uuid)
                            if (currentGroupUuid == target.uuid) {
                                currentGroupUuid = rootUuid
                            }
                            snackbar.showSnackbar("Group deleted")
                        } catch (e: VaultException) {
                            snackbar.showSnackbar(e.message ?: "Could not delete group")
                        }
                    }
                }) { Text("Delete") }
            },
            dismissButton = {
                TextButton(onClick = { groupToDelete = null }) { Text("Cancel") }
            },
        )
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = {
                    Column(
                        modifier = Modifier
                            .clickable { showDatabaseSwitcher = true }
                            .testTag("browser-switch-database"),
                    ) {
                        Text(
                            text = when {
                                query.isNotBlank() -> "Search"
                                filter != EntryFilter.ALL -> filter.label
                                else -> currentGroup.name
                            },
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                        Text(
                            text = "${unlocked.databaseName} ▾",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.primary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                },
                navigationIcon = {
                    if (canGoBack) {
                        IconButton(onClick = {
                            when {
                                query.isNotBlank() -> query = ""
                                filter != EntryFilter.ALL -> filter = EntryFilter.ALL
                                else -> currentGroupUuid = currentGroup.parentUuid ?: rootUuid
                            }
                        }) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                        }
                    }
                },
                actions = {
                    IconButton(
                        enabled = !syncing,
                        onClick = {
                            syncing = true
                            scope.launch {
                                try {
                                    val reloaded = app.vault.syncIfChanged()
                                    if (!reloaded) {
                                        snackbar.showSnackbar("Database is up to date")
                                    }
                                } finally {
                                    syncing = false
                                }
                            }
                        },
                        modifier = Modifier.testTag("sync-now"),
                    ) {
                        if (syncing) {
                            CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                        } else {
                            Icon(Icons.Filled.Refresh, contentDescription = "Sync database")
                        }
                    }
                    IconButton(
                        onClick = { app.vault.lock() },
                        modifier = Modifier.testTag("quick-lock"),
                    ) {
                        Icon(Icons.Filled.Lock, contentDescription = "Lock database")
                    }
                    IconButton(onClick = onOpenSettings, modifier = Modifier.testTag("open-settings")) {
                        Icon(Icons.Filled.Settings, contentDescription = "Settings")
                    }
                },
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = { onCreateEntry(currentGroup.uuid) },
                modifier = Modifier.testTag("add-entry-fab"),
            ) {
                Icon(Icons.Filled.Add, contentDescription = "New entry")
            }
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
                shape = RoundedCornerShape(28.dp),
                placeholder = { Text("Search entries") },
                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                trailingIcon = {
                    if (query.isNotEmpty()) {
                        IconButton(onClick = { query = "" }) {
                            Icon(Icons.Filled.Close, contentDescription = "Clear search")
                        }
                    }
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 6.dp)
                    .testTag("search"),
            )

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 2.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                for (option in EntryFilter.entries) {
                    FilterChip(
                        selected = filter == option,
                        onClick = { filter = option },
                        label = { Text(option.label) },
                        modifier = Modifier.testTag("filter-${option.name.lowercase()}"),
                    )
                }
                Spacer(Modifier.weight(1f))
                if (query.isBlank() && filter == EntryFilter.ALL) {
                    TextButton(
                        onClick = { showCreateGroup = true },
                        modifier = Modifier.testTag("add-group"),
                    ) {
                        Text("+ Group")
                    }
                }
            }

            val showGroups = query.isBlank() && filter == EntryFilter.ALL && childGroups.isNotEmpty()

            if (!showGroups && entries.isEmpty()) {
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(32.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = when {
                            query.isNotBlank() -> "No entries match \"$query\""
                            filter == EntryFilter.TOTP -> "No entries with TOTP codes"
                            filter == EntryFilter.PASSKEYS -> "No entries with passkeys"
                            else -> "This group has no entries yet.\nTap + to create one."
                        },
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            } else {
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 6.dp, bottom = 88.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    if (showGroups) {
                        items(childGroups, key = { "group-${it.uuid}" }) { group ->
                            GroupRow(
                                group = group,
                                onClick = { currentGroupUuid = group.uuid },
                                onRename = { groupToRename = group },
                                onDelete = { groupToDelete = group },
                            )
                        }
                    }
                    items(entries, key = { it.uuid }) { entry ->
                        EntryRow(
                            entry = entry,
                            onClick = { onOpenEntry(entry.uuid) },
                            onCopyPassword = { quickCopyPassword(entry) },
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun GroupRow(
    group: GroupNode,
    onClick: () -> Unit,
    onRename: () -> Unit,
    onDelete: () -> Unit,
) {
    var menuExpanded by remember { mutableStateOf(false) }

    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 14.dp, end = 4.dp, top = 10.dp, bottom = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            EntryAvatar(title = group.name, size = 40.dp)
            Spacer(Modifier.width(14.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    group.name,
                    style = MaterialTheme.typography.titleMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = "${group.entryCount} ${if (group.entryCount == 1) "entry" else "entries"}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Box {
                IconButton(onClick = { menuExpanded = true }) {
                    Icon(Icons.Filled.MoreVert, contentDescription = "Group options")
                }
                DropdownMenu(
                    expanded = menuExpanded,
                    onDismissRequest = { menuExpanded = false },
                ) {
                    DropdownMenuItem(
                        text = { Text("Rename") },
                        onClick = {
                            menuExpanded = false
                            onRename()
                        },
                    )
                    DropdownMenuItem(
                        text = { Text("Delete") },
                        onClick = {
                            menuExpanded = false
                            onDelete()
                        },
                    )
                }
            }
        }
    }
}

@Composable
internal fun EntryRow(
    entry: EntrySummary,
    onClick: () -> Unit,
    onCopyPassword: (() -> Unit)? = null,
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLowest),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .testTag("entry-${entry.uuid}"),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            EntryAvatar(title = entry.title, size = 40.dp)
            Spacer(Modifier.width(14.dp))
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
                if (entry.hasTotp || entry.hasPasskey) {
                    Spacer(Modifier.height(4.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        if (entry.hasTotp) Badge("TOTP")
                        if (entry.hasPasskey) Badge("Passkey")
                    }
                }
            }
            if (onCopyPassword != null) {
                TextButton(
                    onClick = onCopyPassword,
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp),
                ) {
                    Text("Copy", style = MaterialTheme.typography.labelMedium)
                }
            }
        }
    }
}

@Composable
private fun Badge(text: String) {
    Surface(
        color = MaterialTheme.colorScheme.secondaryContainer,
        shape = RoundedCornerShape(6.dp),
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSecondaryContainer,
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
        )
    }
}

@Composable
private fun GroupNameDialog(
    title: String,
    initialName: String,
    confirmLabel: String,
    onDismiss: () -> Unit,
    onConfirm: (String) -> Unit,
) {
    var name by remember { mutableStateOf(initialName) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text("Group name") },
                singleLine = true,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("group-name-input"),
            )
        },
        confirmButton = {
            Button(
                enabled = name.trim().isNotEmpty(),
                onClick = { onConfirm(name.trim()) },
                modifier = Modifier.testTag("group-name-confirm"),
            ) {
                Text(confirmLabel)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}

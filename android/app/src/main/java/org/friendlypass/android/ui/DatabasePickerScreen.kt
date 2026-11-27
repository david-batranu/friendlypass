package org.friendlypass.android.ui

import android.app.Activity
import android.content.Intent
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.friendlypass.android.FriendlypassApp
import org.friendlypass.android.storage.AndroidDocumentGateway
import org.friendlypass.android.storage.SafDocuments
import org.friendlypass.android.storage.SafWrite
import org.friendlypass.android.vault.model.DatabaseRef
import uniffi.friendlypass_mobile.createDatabase

/**
 * First screen of the gate: "Open database…", "Create new database…", and the recent database list
 * (with per-item forget).
 *
 * Documents are opened with `ACTION_OPEN_DOCUMENT` using a wildcard MIME type because Drive reports
 * `.kdbx` as `application/octet-stream`; read+write access is persisted so saves survive a reboot.
 */
@Composable
fun DatabasePickerScreen(modifier: Modifier = Modifier, onCancel: (() -> Unit)? = null) {
    val context = LocalContext.current
    val app = context.applicationContext as FriendlypassApp
    val scope = rememberCoroutineScope()
    var recent by remember { mutableStateOf(app.store.recent()) }

    var showCreateDialog by remember { mutableStateOf(false) }
    var pendingNewDbName by remember { mutableStateOf("") }
    var pendingNewDbPassword by remember { mutableStateOf("") }

    val openLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            val uri = result.data?.data ?: return@rememberLauncherForActivityResult
            SafDocuments.persistPermission(context, uri)
            val db = DatabaseRef(uri.toString(), SafDocuments.displayName(context, uri))
            app.store.remember(db)
            recent = app.store.recent()
            app.vault.selectDatabase(db)
        }
    }

    val createLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        val password = pendingNewDbPassword
        val name = pendingNewDbName
        pendingNewDbPassword = ""
        pendingNewDbName = ""
        if (result.resultCode != Activity.RESULT_OK) return@rememberLauncherForActivityResult
        val uri = result.data?.data ?: return@rememberLauncherForActivityResult
        scope.launch {
            try {
                val bytes = withContext(Dispatchers.IO) {
                    createDatabase(name, password, null)
                }
                withContext(Dispatchers.IO) {
                    SafDocuments.persistPermission(context, uri)
                    SafWrite.write(AndroidDocumentGateway(context), uri.toString(), bytes)
                }
                val db = DatabaseRef(uri.toString(), SafDocuments.displayName(context, uri))
                app.store.remember(db)
                recent = app.store.recent()
                app.vault.selectDatabase(db)
                app.vault.unlock(password.toCharArray(), null)
            } catch (e: Exception) {
                Toast.makeText(
                    context,
                    e.message ?: "Could not create database",
                    Toast.LENGTH_LONG,
                ).show()
            }
        }
    }

    fun launchPicker() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            type = "*/*"
            addCategory(Intent.CATEGORY_OPENABLE)
            addFlags(
                Intent.FLAG_GRANT_READ_URI_PERMISSION or
                    Intent.FLAG_GRANT_WRITE_URI_PERMISSION or
                    Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION,
            )
        }
        openLauncher.launch(intent)
    }

    if (showCreateDialog) {
        CreateDatabaseDialog(
            onDismiss = { showCreateDialog = false },
            onConfirm = { name, password ->
                showCreateDialog = false
                pendingNewDbName = name
                pendingNewDbPassword = password
                val filename = if (name.endsWith(".kdbx", ignoreCase = true)) name else "$name.kdbx"
                val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                    type = "application/octet-stream"
                    addCategory(Intent.CATEGORY_OPENABLE)
                    putExtra(Intent.EXTRA_TITLE, filename)
                    addFlags(
                        Intent.FLAG_GRANT_READ_URI_PERMISSION or
                            Intent.FLAG_GRANT_WRITE_URI_PERMISSION or
                            Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION,
                    )
                }
                createLauncher.launch(intent)
            },
        )
    }

    Surface(
        modifier = modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.background,
    ) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .systemBarsPadding()
            .padding(horizontal = 24.dp, vertical = 20.dp),
    ) {
        Spacer(Modifier.height(28.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Surface(
                color = MaterialTheme.colorScheme.primaryContainer,
                shape = CircleShape,
                modifier = Modifier.size(48.dp),
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Icon(
                        Icons.Filled.Lock,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onPrimaryContainer,
                    )
                }
            }
            Spacer(Modifier.width(14.dp))
            Column {
                Text("friendlypass", style = MaterialTheme.typography.headlineMedium)
                Text(
                    "KeePass-compatible password manager",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        Spacer(Modifier.height(16.dp))
        Text(
            "Open an existing .kdbx database from your device or cloud storage, or create a new one.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(20.dp))
        Button(
            onClick = { launchPicker() },
            modifier = Modifier
                .fillMaxWidth()
                .testTag("open-database"),
        ) {
            Icon(Icons.Filled.Add, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Text("Open database…")
        }
        Spacer(Modifier.height(10.dp))
        OutlinedButton(
            onClick = { showCreateDialog = true },
            modifier = Modifier
                .fillMaxWidth()
                .testTag("create-database"),
        ) {
            Text("Create new database…")
        }
        Spacer(Modifier.height(24.dp))
        Text("Recent databases", style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(10.dp))
        if (recent.isEmpty()) {
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow),
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 28.dp),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Icon(
                        Icons.Filled.Lock,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        "  No databases yet",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier.weight(1f),
                contentPadding = PaddingValues(bottom = 16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                items(recent, key = { it.uri }) { db ->
                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceContainerLowest,
                        ),
                        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
                        shape = RoundedCornerShape(16.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("recent-${db.displayName}")
                            .clickable {
                                app.store.remember(db)
                                app.vault.selectDatabase(db)
                            },
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(start = 14.dp, end = 6.dp, top = 12.dp, bottom = 12.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            EntryAvatar(title = db.displayName, size = 40.dp)
                            Spacer(Modifier.width(14.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    db.displayName,
                                    style = MaterialTheme.typography.titleMedium,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                                Text(
                                    db.uri.substringBefore('/').substringAfter("://"),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                            }
                            IconButton(
                                onClick = {
                                    app.store.forget(db)
                                    recent = app.store.recent()
                                },
                            ) {
                                Icon(Icons.Filled.Delete, contentDescription = "Remove from recent")
                            }
                        }
                    }
                }
            }
        }
        if (onCancel != null) {
            TextButton(onClick = onCancel) { Text("Cancel") }
        }
    }
    }
}

/**
 * Quick database switcher dialog usable from both the unlock screen and the browser top bar.
 */
@Composable
fun DatabaseSwitcherDialog(
    currentDb: DatabaseRef?,
    onDismiss: () -> Unit,
    onSelect: (DatabaseRef) -> Unit,
    onManageDatabases: () -> Unit,
) {
    val context = LocalContext.current
    val app = context.applicationContext as FriendlypassApp
    val recent = remember { app.store.recent() }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Switch database") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (recent.isEmpty()) {
                    Text(
                        "No recent databases.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                } else {
                    for (db in recent) {
                        val isCurrent = db.uri == currentDb?.uri
                        Card(
                            colors = CardDefaults.cardColors(
                                containerColor = if (isCurrent) {
                                    MaterialTheme.colorScheme.primaryContainer
                                } else {
                                    MaterialTheme.colorScheme.surfaceContainerLow
                                },
                            ),
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    if (!isCurrent) {
                                        onSelect(db)
                                    }
                                    onDismiss()
                                },
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 12.dp, vertical = 10.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                EntryAvatar(title = db.displayName, size = 34.dp)
                                Spacer(Modifier.width(12.dp))
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = db.displayName,
                                        style = MaterialTheme.typography.titleSmall,
                                        color = if (isCurrent) {
                                            MaterialTheme.colorScheme.onPrimaryContainer
                                        } else {
                                            MaterialTheme.colorScheme.onSurface
                                        },
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                    )
                                    if (isCurrent) {
                                        Text(
                                            text = "Current",
                                            style = MaterialTheme.typography.labelSmall,
                                            color = MaterialTheme.colorScheme.onPrimaryContainer,
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    onDismiss()
                    onManageDatabases()
                },
            ) {
                Text("Open / Create…")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Close") }
        },
    )
}

@Composable
private fun CreateDatabaseDialog(
    onDismiss: () -> Unit,
    onConfirm: (name: String, password: String) -> Unit,
) {
    var name by remember { mutableStateOf("Passwords") }
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Create new database") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it; error = null },
                    label = { Text("Database name") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it; error = null },
                    label = { Text("Master password") },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = confirm,
                    onValueChange = { confirm = it; error = null },
                    label = { Text("Confirm password") },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    modifier = Modifier.fillMaxWidth(),
                )
                error?.let {
                    Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                }
            }
        },
        confirmButton = {
            Button(onClick = {
                when {
                    name.trim().isEmpty() -> error = "Enter a database name"
                    password.isEmpty() -> error = "Enter a master password"
                    password != confirm -> error = "Passwords do not match"
                    else -> onConfirm(name.trim(), password)
                }
            }) {
                Text("Choose location…")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}

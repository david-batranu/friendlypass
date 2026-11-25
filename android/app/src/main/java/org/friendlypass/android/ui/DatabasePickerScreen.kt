package org.friendlypass.android.ui

import android.app.Activity
import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import org.friendlypass.android.FriendlypassApp
import org.friendlypass.android.storage.SafDocuments
import org.friendlypass.android.vault.model.DatabaseRef

/**
 * First screen of the gate: the databases opened before plus "Open database…".
 *
 * Documents are opened with `ACTION_OPEN_DOCUMENT` using a wildcard MIME type because Drive reports
 * `.kdbx` as `application/octet-stream`; read+write access is persisted so saves survive a reboot.
 */
@Composable
fun DatabasePickerScreen(modifier: Modifier = Modifier, onCancel: (() -> Unit)? = null) {
    val context = LocalContext.current
    val app = context.applicationContext as FriendlypassApp
    var recent by remember { mutableStateOf(app.store.recent()) }

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

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(24.dp),
    ) {
        Spacer(Modifier.height(32.dp))
        Text("friendlypass", style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(8.dp))
        Text(
            "Open a KeePass database to get started. Files stay in your storage provider; friendlypass keeps " +
                "a private copy for offline access.",
            style = MaterialTheme.typography.bodyMedium,
        )
        Spacer(Modifier.height(24.dp))
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
        Spacer(Modifier.height(24.dp))
        Text("Recent", style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(8.dp))
        if (recent.isEmpty()) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 24.dp),
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
        } else {
            LazyColumn(modifier = Modifier.weight(1f)) {
                items(recent, key = { it.uri }) { db ->
                    ListItem(
                        headlineContent = { Text(db.displayName) },
                        supportingContent = { Text(db.uri.substringBefore('/').substringAfter("://")) },
                        leadingContent = { Icon(Icons.Filled.Lock, contentDescription = null) },
                        modifier = Modifier
                            .testTag("recent-${db.displayName}")
                            .clickable {
                                app.store.remember(db)
                                app.vault.selectDatabase(db)
                            },
                    )
                    HorizontalDivider()
                }
            }
        }
        if (onCancel != null) {
            TextButton(onClick = onCancel) { Text("Cancel") }
        }
    }
}

package org.friendlypass.android.ui

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
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
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.friendlypass.android.FriendlypassApp
import org.friendlypass.android.vault.model.TotpCode
import org.friendlypass.android.vault.model.VaultException

/**
 * Entry details with grouped Material 3 cards, clipboard actions, reveal toggles (including protected
 * custom fields), open-in-browser for URLs, live TOTP code, and Edit / Delete actions.
 * The hosting activity adds `FLAG_SECURE` for this route.
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun EntryDetailScreen(
    entryUuid: String,
    onEdit: () -> Unit,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val app = context.applicationContext as FriendlypassApp
    val revision by app.vault.revision.collectAsStateWithLifecycle()
    val detail = remember(entryUuid, revision) {
        runCatching { app.vault.entry(entryUuid) }.getOrElse { error ->
            if (error is VaultException) null else throw error
        }
    }
    val snackbar = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    var confirmDelete by remember { mutableStateOf(false) }

    if (detail == null) {
        Scaffold(
            topBar = {
                TopAppBar(
                    title = { Text("Entry") },
                    navigationIcon = {
                        IconButton(onClick = onBack) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                        }
                    },
                )
            },
        ) { padding ->
            Text("Entry is no longer available", modifier = Modifier.padding(padding).padding(24.dp))
        }
        return
    }

    var nowSecs by remember { mutableLongStateOf(System.currentTimeMillis() / 1000) }
    LaunchedEffect(entryUuid) {
        while (true) {
            nowSecs = System.currentTimeMillis() / 1000
            delay(1_000)
        }
    }
    val totp = remember(entryUuid, nowSecs, revision) {
        runCatching { app.vault.totp(entryUuid, nowSecs) }.getOrNull()
    }

    fun announce(message: String) {
        scope.launch { snackbar.showSnackbar(message, withDismissAction = false) }
    }

    fun copy(label: String, value: String) {
        SecureClipboard.copySecret(context, label, value)
        announce("$label copied — clipboard clears in 30 s")
    }

    fun openUrl(rawUrl: String) {
        val target = if (rawUrl.contains("://")) rawUrl else "https://$rawUrl"
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(target))
        if (runCatching { context.startActivity(intent) }.isFailure) {
            announce("Could not open link")
        }
    }

    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text("Delete \"${detail.summary.title}\"?") },
            text = { Text("This entry will be moved to the Recycle Bin.") },
            confirmButton = {
                Button(
                    onClick = {
                        confirmDelete = false
                        scope.launch {
                            try {
                                app.vault.deleteEntry(entryUuid)
                                onBack()
                            } catch (e: VaultException) {
                                announce(e.message ?: "Could not delete entry")
                            }
                        }
                    },
                    modifier = Modifier.testTag("confirm-delete-entry"),
                ) {
                    Text("Delete")
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmDelete = false }) { Text("Cancel") }
            },
        )
    }

    val visibleCustomFields = remember(detail.customFields) {
        detail.customFields.filterNot {
            it.name.startsWith("KPEX_PASSKEY_") || it.name == "AndroidApp" || it.name.startsWith("AndroidApp_")
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(detail.summary.title, maxLines = 1, overflow = TextOverflow.Ellipsis)
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(onClick = onEdit, modifier = Modifier.testTag("edit-entry")) {
                        Icon(Icons.Filled.Edit, contentDescription = "Edit entry")
                    }
                    IconButton(onClick = { confirmDelete = true }, modifier = Modifier.testTag("delete-entry")) {
                        Icon(Icons.Filled.Delete, contentDescription = "Delete entry")
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.padding(horizontal = 4.dp, vertical = 4.dp),
            ) {
                EntryAvatar(title = detail.summary.title, size = 56.dp)
                Spacer(Modifier.width(16.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(detail.summary.title, style = MaterialTheme.typography.headlineSmall)
                    Text(
                        detail.summary.groupPath,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    if (detail.summary.hasPasskey) {
                        Spacer(Modifier.height(4.dp))
                        Surface(
                            color = MaterialTheme.colorScheme.primaryContainer,
                            shape = RoundedCornerShape(6.dp),
                        ) {
                            Text(
                                "Passkey stored",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onPrimaryContainer,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                            )
                        }
                    }
                }
            }

            // Credentials card
            DetailCard {
                DetailField(
                    label = "Username",
                    value = detail.summary.username.ifBlank { "—" },
                    onCopy = detail.summary.username.takeIf { it.isNotBlank() }?.let { { copy("Username", it) } },
                )
                HorizontalDivider()
                PasswordField(
                    password = detail.password,
                    onCopy = { copy("Password", detail.password) },
                )
                if (totp != null) {
                    HorizontalDivider()
                    TotpField(totp = totp, onCopy = { copy("TOTP code", totp.code) })
                }
            }

            // Links & Android apps card
            if (detail.urls.isNotEmpty() || detail.androidApps.isNotEmpty()) {
                DetailCard {
                    detail.urls.forEachIndexed { index, url ->
                        if (index > 0) HorizontalDivider()
                        val isWeb = url.startsWith("http://") || url.startsWith("https://")
                        DetailField(
                            label = if (index == 0) "URL" else "URL ${index + 1}",
                            value = url,
                            onCopy = { copy("URL", url) },
                            secondaryActionLabel = if (isWeb) "Open" else null,
                            onSecondaryAction = if (isWeb) ({ openUrl(url) }) else null,
                        )
                    }
                    detail.androidApps.forEachIndexed { index, packageName ->
                        if (index > 0 || detail.urls.isNotEmpty()) HorizontalDivider()
                        DetailField(
                            label = "Android app",
                            value = packageName,
                            onCopy = { copy("Package name", packageName) },
                        )
                    }
                }
            }

            // Custom fields card
            if (visibleCustomFields.isNotEmpty()) {
                DetailCard {
                    visibleCustomFields.forEachIndexed { index, field ->
                        if (index > 0) HorizontalDivider()
                        if (field.protected) {
                            ProtectedCustomField(
                                label = field.name,
                                value = field.value,
                                onCopy = { copy(field.name, field.value) },
                            )
                        } else {
                            DetailField(
                                label = field.name,
                                value = field.value,
                                onCopy = { copy(field.name, field.value) },
                            )
                        }
                    }
                }
            }

            // Notes card
            if (detail.notes.isNotBlank()) {
                DetailCard {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            "Notes",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        TextButton(onClick = { copy("Notes", detail.notes) }) { Text("Copy") }
                    }
                    Text(detail.notes, style = MaterialTheme.typography.bodyMedium)
                }
            }

            // Tags
            if (detail.tags.isNotEmpty()) {
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                    modifier = Modifier.padding(horizontal = 4.dp),
                ) {
                    for (tag in detail.tags) {
                        Surface(
                            color = MaterialTheme.colorScheme.secondaryContainer,
                            shape = RoundedCornerShape(8.dp),
                        ) {
                            Text(
                                "#$tag",
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSecondaryContainer,
                                modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
                            )
                        }
                    }
                }
            }

            Spacer(Modifier.height(24.dp))
        }
    }
}

@Composable
private fun DetailCard(content: @Composable () -> Unit) {
    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLowest),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
            content()
        }
    }
}

@Composable
private fun DetailField(
    label: String,
    value: String,
    onCopy: (() -> Unit)?,
    secondaryActionLabel: String? = null,
    onSecondaryAction: (() -> Unit)? = null,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(value, style = MaterialTheme.typography.bodyLarge)
        }
        if (secondaryActionLabel != null && onSecondaryAction != null) {
            TextButton(onClick = onSecondaryAction) { Text(secondaryActionLabel) }
        }
        if (onCopy != null) {
            TextButton(onClick = onCopy) { Text("Copy") }
        }
    }
}

@Composable
private fun PasswordField(password: String, onCopy: () -> Unit) {
    var revealed by remember { mutableStateOf(false) }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                "Password",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = if (revealed) password else "••••••••••",
                style = MaterialTheme.typography.bodyLarge,
                fontFamily = if (revealed) FontFamily.Monospace else FontFamily.Default,
                modifier = Modifier.testTag("password-value"),
            )
        }
        TextButton(onClick = { revealed = !revealed }, modifier = Modifier.testTag("reveal-password")) {
            Text(if (revealed) "Hide" else "Reveal")
        }
        TextButton(onClick = onCopy) { Text("Copy") }
    }
}

@Composable
private fun ProtectedCustomField(label: String, value: String, onCopy: () -> Unit) {
    var revealed by remember { mutableStateOf(false) }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(
                text = if (revealed) value else "••••••••",
                style = MaterialTheme.typography.bodyLarge,
                fontFamily = if (revealed) FontFamily.Monospace else FontFamily.Default,
            )
        }
        TextButton(onClick = { revealed = !revealed }) {
            Text(if (revealed) "Hide" else "Reveal")
        }
        TextButton(onClick = onCopy) { Text("Copy") }
    }
}

@Composable
private fun TotpField(totp: TotpCode, onCopy: () -> Unit) {
    Column(modifier = Modifier.padding(vertical = 8.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    "One-time code",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    text = totp.code,
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.SemiBold,
                    fontFamily = FontFamily.Monospace,
                    letterSpacing = 4.sp,
                    modifier = Modifier.testTag("totp-code"),
                )
            }
            Text("${totp.remainingSecs}s", style = MaterialTheme.typography.labelLarge)
            TextButton(onClick = onCopy) { Text("Copy") }
        }
        Spacer(Modifier.height(6.dp))
        LinearProgressIndicator(
            progress = { totp.remainingSecs.toFloat() / totp.periodSecs.toFloat() },
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

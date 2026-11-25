package org.friendlypass.android.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
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
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.friendlypass.android.FriendlypassApp
import org.friendlypass.android.vault.model.EntryDetail
import org.friendlypass.android.vault.model.TotpCode
import org.friendlypass.android.vault.model.VaultException

/**
 * Entry details with clipboard actions, a reveal toggle and a live TOTP code. The hosting activity adds
 * `FLAG_SECURE` for this route.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EntryDetailScreen(entryUuid: String, onBack: () -> Unit) {
    val context = LocalContext.current
    val app = context.applicationContext as FriendlypassApp
    val detail = remember(entryUuid) {
        runCatching { app.vault.entry(entryUuid) }.getOrElse { error ->
            if (error is VaultException) null else throw error
        }
    }
    val snackbar = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()

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
    val totp = remember(entryUuid, nowSecs) {
        runCatching { app.vault.totp(entryUuid, nowSecs) }.getOrNull()
    }

    fun announce(message: String) {
        scope.launch { snackbar.showSnackbar(message, withDismissAction = false) }
    }

    fun copy(label: String, value: String) {
        SecureClipboard.copySecret(context, label, value)
        announce("$label copied — clipboard clears in 30 s")
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
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 8.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                EntryAvatar(title = detail.summary.title, size = 56.dp)
                Spacer(Modifier.width(16.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(detail.summary.title, style = MaterialTheme.typography.titleLarge)
                    Text(
                        detail.summary.groupPath,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            if (detail.summary.hasPasskey) {
                Spacer(Modifier.height(8.dp))
                Text(
                    "Passkey stored for this entry",
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
            Spacer(Modifier.height(16.dp))
            HorizontalDivider()

            DetailField(
                label = "Username",
                value = detail.summary.username.ifBlank { "—" },
                onCopy = detail.summary.username.takeIf { it.isNotBlank() }?.let { { copy("Username", it) } },
            )

            PasswordField(
                password = detail.password,
                onCopy = { copy("Password", detail.password) },
            )

            for ((index, url) in detail.urls.withIndex()) {
                DetailField(
                    label = if (index == 0) "URL" else "URL ${index + 1}",
                    value = url,
                    onCopy = { copy("URL", url) },
                )
            }

            for (packageName in detail.androidApps) {
                DetailField(
                    label = "Android app",
                    value = packageName,
                    onCopy = { copy("Package name", packageName) },
                )
            }

            if (totp != null) {
                TotpField(totp = totp, onCopy = { copy("TOTP code", totp.code) })
            }

            for (field in detail.customFields) {
                if (field.name.startsWith("KPEX_PASSKEY_")) continue
                DetailField(
                    label = field.name,
                    value = if (field.protected) "••••••••" else field.value,
                    onCopy = if (field.protected) null else ({ copy(field.name, field.value) }),
                )
            }

            if (detail.notes.isNotBlank()) {
                Spacer(Modifier.height(8.dp))
                HorizontalDivider()
                Spacer(Modifier.height(12.dp))
                Text("Notes", style = MaterialTheme.typography.labelLarge)
                Spacer(Modifier.height(4.dp))
                Text(detail.notes, style = MaterialTheme.typography.bodyMedium)
            }

            if (detail.tags.isNotEmpty()) {
                Spacer(Modifier.height(16.dp))
                Text(
                    detail.tags.joinToString("  ") { "#$it" },
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(Modifier.height(32.dp))
        }
    }
}

@Composable
private fun DetailField(label: String, value: String, onCopy: (() -> Unit)?) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(value, style = MaterialTheme.typography.bodyLarge)
        }
        if (onCopy != null) {
            TextButton(onClick = onCopy) { Text("Copy") }
        }
    }
    HorizontalDivider()
}

@Composable
private fun PasswordField(password: String, onCopy: () -> Unit) {
    var revealed by remember { mutableStateOf(false) }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
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
    HorizontalDivider()
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
        Spacer(Modifier.height(4.dp))
        LinearProgressIndicator(
            progress = { totp.remainingSecs.toFloat() / totp.periodSecs.toFloat() },
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(8.dp))
        HorizontalDivider()
    }
}

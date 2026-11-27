package org.friendlypass.android.ui

import android.content.Intent
import android.os.Build
import android.provider.Settings
import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import androidx.credentials.CredentialManager
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.launch
import org.friendlypass.android.FriendlypassApp
import org.friendlypass.android.autofill.AutofillStatus
import org.friendlypass.android.credentials.CredentialProviderStatus
import org.friendlypass.android.settings.AppSettings
import org.friendlypass.android.vault.model.DatabaseRef
import org.friendlypass.android.vault.model.VaultState

/** Scrollable Material 3 settings screen: auto-lock, biometrics, password generator, system integration, and database actions. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val app = context.applicationContext as FriendlypassApp
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    val state by app.vault.state.collectAsStateWithLifecycle()
    val db: DatabaseRef? = (state as? VaultState.Unlocked)?.db

    var timeout by remember { mutableIntStateOf(app.settings.lockTimeoutMinutes) }
    var biometricEnabled by remember { mutableStateOf(db?.let { app.biometric.isEnabled(it) } ?: false) }
    var showGenerator by remember { mutableStateOf(false) }

    fun toast(message: String) {
        Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
    }

    if (showGenerator) {
        PasswordGeneratorDialog(
            onDismiss = { showGenerator = false },
            onCopy = { generated ->
                SecureClipboard.copySecret(context, "Generated password", generated)
                scope.launch { snackbar.showSnackbar("Password copied — clipboard clears in 30 s") }
            },
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
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
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            SettingsCard(title = "Auto-lock") {
                Text(
                    "The database locks after this much inactivity, and whenever the screen turns off.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(4.dp))
                Column(modifier = Modifier.selectableGroup()) {
                    for (minutes in AppSettings.LOCK_TIMEOUT_CHOICES) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .selectable(
                                    selected = timeout == minutes,
                                    onClick = {
                                        timeout = minutes
                                        app.settings.lockTimeoutMinutes = minutes
                                    },
                                    role = Role.RadioButton,
                                )
                                .padding(vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            RadioButton(
                                selected = timeout == minutes,
                                onClick = null,
                            )
                            Text(
                                text = if (minutes == 1) "1 minute" else "$minutes minutes",
                                modifier = Modifier.padding(start = 12.dp),
                            )
                        }
                    }
                }
            }

            SettingsCard(title = "Biometric unlock") {
                Text(
                    text = when {
                        db == null -> "No database is open"
                        biometricEnabled -> "Enabled for ${db.displayName}"
                        app.biometric.canAuthenticate() ->
                            "Not set up. Enable it on the unlock screen after entering your password."
                        else -> "No biometrics are enrolled on this device."
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (db != null && biometricEnabled) {
                    TextButton(
                        onClick = {
                            app.biometric.disable(db)
                            biometricEnabled = false
                        },
                        modifier = Modifier.testTag("disable-biometric"),
                    ) {
                        Text("Disable biometric unlock")
                    }
                }
            }

            SettingsCard(title = "Tools") {
                TextButton(
                    onClick = { showGenerator = true },
                    modifier = Modifier.testTag("open-password-generator"),
                ) {
                    Text("Password generator")
                }
            }

            SettingsCard(title = "App integration") {
                Text(
                    text = AutofillStatus.statusText(context),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.testTag("autofill-status"),
                )
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                    Text(
                        text = CredentialProviderStatus.statusText(context),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.testTag("credential-provider-status"),
                    )
                }
                TextButton(
                    onClick = {
                        val intent = Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE)
                        if (runCatching { context.startActivity(intent) }.isFailure) {
                            runCatching { context.startActivity(Intent(Settings.ACTION_SETTINGS)) }
                        }
                    },
                    modifier = Modifier.testTag("autofill-settings"),
                ) {
                    Text("Choose autofill service")
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                    TextButton(
                        onClick = {
                            runCatching {
                                CredentialManager.create(context).createSettingsPendingIntent().send()
                            }.onFailure {
                                toast("Credential provider settings are not available")
                            }
                        },
                        modifier = Modifier.testTag("credential-provider-settings"),
                    ) {
                        Text("Credential provider settings")
                    }
                }
            }

            SettingsCard(title = "Database") {
                TextButton(
                    onClick = {
                        scope.launch {
                            val reloaded = app.vault.syncIfChanged()
                            snackbar.showSnackbar(
                                if (reloaded) "Reloaded external changes" else "Database is up to date",
                            )
                        }
                    },
                ) {
                    Text("Sync database now")
                }
                TextButton(
                    onClick = { app.vault.clearDatabase() },
                ) {
                    Text("Switch database")
                }
                TextButton(
                    onClick = { app.vault.lock() },
                    modifier = Modifier.testTag("lock-now"),
                ) {
                    Text("Lock database now")
                }
            }

            Spacer(Modifier.height(16.dp))
        }
    }
}

@Composable
private fun SettingsCard(
    title: String,
    content: @Composable () -> Unit,
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLowest),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(6.dp))
            content()
        }
    }
}

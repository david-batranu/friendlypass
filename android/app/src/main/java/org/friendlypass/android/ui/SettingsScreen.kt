package org.friendlypass.android.ui

import android.content.Intent
import android.os.Build
import android.provider.Settings
import android.widget.Toast
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import androidx.credentials.CredentialManager
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.friendlypass.android.FriendlypassApp
import org.friendlypass.android.autofill.AutofillStatus
import org.friendlypass.android.credentials.CredentialProviderStatus
import org.friendlypass.android.settings.AppSettings
import org.friendlypass.android.vault.model.DatabaseRef
import org.friendlypass.android.vault.model.VaultState

/** Lock timeout, biometric state, and the two system integration shortcuts. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val app = context.applicationContext as FriendlypassApp
    val state by app.vault.state.collectAsStateWithLifecycle()
    val db: DatabaseRef? = (state as? VaultState.Unlocked)?.db

    var timeout by remember { mutableIntStateOf(app.settings.lockTimeoutMinutes) }
    var biometricEnabled by remember { mutableStateOf(db?.let { app.biometric.isEnabled(it) } ?: false) }

    fun toast(message: String) {
        Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
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
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 20.dp),
        ) {
            Spacer(Modifier.height(8.dp))
            Text("Auto-lock", style = MaterialTheme.typography.titleMedium)
            Text(
                "The database locks after this much inactivity, and whenever the screen turns off.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
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

            HorizontalDivider(modifier = Modifier.padding(vertical = 12.dp))
            Text("Biometric unlock", style = MaterialTheme.typography.titleMedium)
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

            HorizontalDivider(modifier = Modifier.padding(vertical = 12.dp))
            Text("App integration", style = MaterialTheme.typography.titleMedium)
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

            HorizontalDivider(modifier = Modifier.padding(vertical = 12.dp))
            TextButton(
                onClick = { app.vault.lock() },
                modifier = Modifier.testTag("lock-now"),
            ) {
                Text("Lock database now")
            }
        }
    }
}

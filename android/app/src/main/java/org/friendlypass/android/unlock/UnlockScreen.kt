package org.friendlypass.android.unlock

import android.app.Activity
import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
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
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.launch
import org.friendlypass.android.FriendlypassApp
import org.friendlypass.android.storage.SafDocuments
import org.friendlypass.android.ui.EntryAvatar
import org.friendlypass.android.vault.model.DatabaseRef
import org.friendlypass.android.vault.model.VaultException

/**
 * Password (+ optional SAF key file, kept only in memory) unlock for one database.
 *
 * On success the credentials are handed to [onUnlocked] so the gate can offer to remember them for biometric
 * unlock; this screen never persists anything itself.
 */
@Composable
fun UnlockScreen(
    db: DatabaseRef,
    onUnlocked: (CharArray?, ByteArray?) -> Unit,
    onCancel: () -> Unit,
) {
    val context = LocalContext.current
    val app = context.applicationContext as FriendlypassApp
    val activity = context as? FragmentActivity
    val scope = rememberCoroutineScope()

    var password by rememberSaveable(db.uri) { mutableStateOf("") }
    var showPassword by remember { mutableStateOf(false) }
    var keyfile by remember { mutableStateOf<ByteArray?>(null) }
    var keyfileName by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }

    DisposableEffect(Unit) {
        onDispose { keyfile?.fill(0) }
    }

    val keyfileLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode != Activity.RESULT_OK) return@rememberLauncherForActivityResult
        val uri = result.data?.data ?: return@rememberLauncherForActivityResult
        val bytes = runCatching {
            context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
        }.getOrNull()
        if (bytes == null) {
            error = "Could not read the key file"
            return@rememberLauncherForActivityResult
        }
        keyfile?.fill(0)
        keyfile = bytes
        keyfileName = SafDocuments.displayName(context, uri)
        error = null
    }

    fun pickKeyFile() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            type = "*/*"
            addCategory(Intent.CATEGORY_OPENABLE)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        keyfileLauncher.launch(intent)
    }

    fun unlock() {
        if (busy) return
        error = null
        busy = true
        val passwordChars = password.toCharArray()
        val keyfileCopy = keyfile?.copyOf()
        scope.launch {
            try {
                app.vault.unlock(passwordChars, keyfileCopy)
                onUnlocked(password.toCharArray(), keyfile?.copyOf())
            } catch (e: VaultException.InvalidCredentials) {
                error = e.message
            } catch (e: VaultException) {
                error = e.message ?: "Could not unlock the database"
            } finally {
                busy = false
            }
        }
    }

    fun unlockWithBiometrics() {
        if (activity == null) return
        error = null
        app.biometric.authenticate(
            activity = activity,
            db = db,
            onCredentials = { passwordChars, keyfileBytes ->
                scope.launch {
                    try {
                        app.vault.unlock(passwordChars, keyfileBytes)
                        onUnlocked(null, null)
                    } catch (e: VaultException) {
                        error = e.message ?: "Could not unlock the database"
                    }
                }
            },
            onError = { message -> error = message },
        )
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .imePadding()
            .padding(horizontal = 24.dp, vertical = 40.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        EntryAvatar(title = db.displayName, size = 72.dp)
        Spacer(Modifier.height(16.dp))
        Text(db.displayName, style = MaterialTheme.typography.headlineSmall)
        Text(
            "Database is locked",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(32.dp))

        OutlinedTextField(
            value = password,
            onValueChange = {
                password = it
                error = null
            },
            label = { Text("Password") },
            singleLine = true,
            visualTransformation = if (showPassword) VisualTransformation.None else PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(
                keyboardType = KeyboardType.Password,
                imeAction = ImeAction.Done,
            ),
            keyboardActions = KeyboardActions(onDone = { unlock() }),
            trailingIcon = {
                TextButton(onClick = { showPassword = !showPassword }) {
                    Text(if (showPassword) "Hide" else "Show")
                }
            },
            modifier = Modifier
                .fillMaxWidth()
                .testTag("password"),
        )
        Spacer(Modifier.height(12.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column {
                Text("Key file (optional)", style = MaterialTheme.typography.labelLarge)
                Text(
                    keyfileName ?: "None selected",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Row {
                if (keyfile != null) {
                    TextButton(onClick = {
                        keyfile?.fill(0)
                        keyfile = null
                        keyfileName = null
                    }) { Text("Remove") }
                }
                TextButton(onClick = { pickKeyFile() }, modifier = Modifier.testTag("pick-keyfile")) {
                    Text("Choose…")
                }
            }
        }

        if (error != null) {
            Spacer(Modifier.height(8.dp))
            Text(
                text = error!!,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("unlock-error"),
            )
        }

        Spacer(Modifier.height(24.dp))
        Button(
            onClick = { unlock() },
            enabled = !busy,
            modifier = Modifier
                .fillMaxWidth()
                .testTag("unlock"),
        ) {
            if (busy) {
                CircularProgressIndicator(
                    modifier = Modifier
                        .height(18.dp)
                        .width(18.dp),
                    strokeWidth = 2.dp,
                )
                Spacer(Modifier.width(8.dp))
            }
            Text("Unlock")
        }

        if (activity != null && app.biometric.isAvailableFor(db)) {
            Spacer(Modifier.height(12.dp))
            OutlinedButton(
                onClick = { unlockWithBiometrics() },
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("biometric-unlock"),
            ) {
                Text("Unlock with biometrics")
            }
        }

        Spacer(Modifier.height(24.dp))
        TextButton(onClick = onCancel) { Text("Cancel") }
    }
}

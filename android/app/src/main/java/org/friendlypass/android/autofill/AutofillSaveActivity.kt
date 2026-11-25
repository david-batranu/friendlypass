package org.friendlypass.android.autofill

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.launch
import org.friendlypass.android.BuildConfig
import org.friendlypass.android.FriendlypassApp
import org.friendlypass.android.R
import org.friendlypass.android.ui.theme.FriendlypassTheme
import org.friendlypass.android.unlock.UnlockGate
import org.friendlypass.android.vault.model.NewLogin
import org.friendlypass.android.vault.model.VaultException
import org.friendlypass.android.vault.model.VaultState

/**
 * Save confirmation for [FriendlypassAutofillService.onSaveRequest].
 *
 * Unlocks (via [UnlockGate]) when needed, shows an editable title (default: web host or app label),
 * username and password, and calls `vault.addLogin`. Errors such as [VaultException.Conflict] are shown
 * instead of being swallowed.
 */
class AutofillSaveActivity : FragmentActivity() {

    private var webUrl: String = ""
    private var androidPackage: String = ""
    private var username: String = ""
    private var password: String = ""
    private var callingPackage: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val target = AutofillExtras.target(intent) ?: run {
            android.util.Log.d("FriendlypassAutofill", "save activity: no target in intent")
            finish()
            return
        }
        android.util.Log.d("FriendlypassAutofill", "save activity: target=$target")
        webUrl = (target as? AutofillTarget.Web)?.url.orEmpty()
        androidPackage = (target as? AutofillTarget.App)?.packageName.orEmpty()
        username = intent.getStringExtra(AutofillExtras.EXTRA_SAVE_USERNAME).orEmpty()
        password = intent.getStringExtra(AutofillExtras.EXTRA_SAVE_PASSWORD).orEmpty()
        callingPackage = intent.getStringExtra(AutofillExtras.EXTRA_TARGET_PACKAGE).orEmpty()

        if (password.isEmpty()) {
            finish()
            return
        }
        if (!BuildConfig.DEBUG) {
            // The sheet contains the password that is about to be stored.
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
        // Compose focuses the first text field when the window appears; that would send the keyboard
        // (and any typing meant for the app behind) to the name field. Keep the IME hidden until a tap.
        window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN)

        setContent {
            FriendlypassTheme {
                val app = application as FriendlypassApp
                val state by app.vault.state.collectAsStateWithLifecycle()
                if (state is VaultState.Unlocked) {
                    SaveSheet(
                        app = app,
                        initialTitle = defaultTitle(),
                        initialUsername = username,
                        initialPassword = password,
                        targetLabel = targetLabel(),
                        onDismiss = { finish() },
                    )
                } else {
                    Surface(modifier = Modifier.fillMaxSize()) {
                        UnlockGate(
                            onUnlocked = { /* recomposition shows the sheet */ },
                            onCancel = { finish() },
                        )
                    }
                }
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        password = ""
    }

    private fun defaultTitle(): String = when {
        webUrl.isNotBlank() -> AutofillTargets.hostOf(webUrl) ?: webUrl
        androidPackage.isNotBlank() -> appLabel(androidPackage)
        else -> getString(R.string.autofill_save_default_title)
    }

    private fun targetLabel(): String = when {
        webUrl.isNotBlank() -> webUrl
        androidPackage.isNotBlank() -> androidPackage
        else -> callingPackage
    }

    private fun appLabel(packageName: String): String = try {
        val info = packageManager.getApplicationInfo(packageName, 0)
        packageManager.getApplicationLabel(info).toString()
    } catch (e: Exception) {
        packageName
    }

    @Composable
    private fun SaveSheet(
        app: FriendlypassApp,
        initialTitle: String,
        initialUsername: String,
        initialPassword: String,
        targetLabel: String,
        onDismiss: () -> Unit,
    ) {
        val scope = rememberCoroutineScope()
        val focusManager = androidx.compose.ui.platform.LocalFocusManager.current
        LaunchedEffect(Unit) { focusManager.clearFocus(force = true) }
        var title by remember { mutableStateOf(initialTitle) }
        var user by remember { mutableStateOf(initialUsername) }
        var secret by remember { mutableStateOf(initialPassword) }
        var error by remember { mutableStateOf<String?>(null) }
        var busy by remember { mutableStateOf(false) }

        Box(
            modifier = Modifier
                .fillMaxSize()
                .imePadding(),
            contentAlignment = Alignment.BottomCenter,
        ) {
            Surface(
                shape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp),
                tonalElevation = 3.dp,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 24.dp, vertical = 20.dp),
                ) {
                    Text(getString(R.string.autofill_save_title), style = MaterialTheme.typography.headlineSmall)
                    Text(
                        targetLabel,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(16.dp))
                    OutlinedTextField(
                        value = title,
                        onValueChange = { title = it; error = null },
                        label = { Text(getString(R.string.autofill_save_name)) },
                        singleLine = true,
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("autofill-save-title"),
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = user,
                        onValueChange = { user = it; error = null },
                        label = { Text(getString(R.string.autofill_save_username)) },
                        singleLine = true,
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("autofill-save-username"),
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = secret,
                        onValueChange = { secret = it; error = null },
                        label = { Text(getString(R.string.autofill_save_password)) },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("autofill-save-password"),
                    )
                    error?.let { message ->
                        Spacer(Modifier.height(8.dp))
                        Text(
                            message,
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier.testTag("autofill-save-error"),
                        )
                    }
                    Spacer(Modifier.height(16.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.End,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        TextButton(
                            onClick = onDismiss,
                            enabled = !busy,
                            modifier = Modifier.testTag("autofill-save-cancel"),
                        ) {
                            Text(getString(R.string.autofill_save_not_now))
                        }
                        Spacer(Modifier.width(8.dp))
                        Button(
                            enabled = !busy,
                            onClick = {
                                if (busy) return@Button
                                busy = true
                                error = null
                                val login = NewLogin(
                                    title = title.ifBlank { defaultTitle() },
                                    username = user,
                                    password = secret,
                                    url = webUrl.takeIf { it.isNotBlank() },
                                    androidApp = androidPackage.takeIf { it.isNotBlank() },
                                )
                                scope.launch {
                                    try {
                                        app.vault.addLogin(login)
                                        finish()
                                    } catch (e: VaultException.Conflict) {
                                        error = getString(R.string.autofill_save_conflict)
                                    } catch (e: VaultException) {
                                        error = e.message ?: getString(R.string.autofill_save_failed)
                                    } finally {
                                        busy = false
                                    }
                                }
                            },
                            modifier = Modifier.testTag("autofill-save-confirm"),
                        ) {
                            if (busy) {
                                CircularProgressIndicator(
                                    modifier = Modifier
                                        .height(18.dp)
                                        .width(18.dp),
                                    strokeWidth = 2.dp,
                                )
                            } else {
                                Text(getString(R.string.autofill_save_confirm))
                            }
                        }
                    }
                }
            }
        }
    }

    companion object {
        fun newIntent(
            context: Context,
            target: AutofillTarget,
            callingPackage: String?,
            username: String,
            password: String,
        ): Intent = Intent(context, AutofillSaveActivity::class.java).apply {
            AutofillExtras.putTarget(this, target, callingPackage)
            putExtra(AutofillExtras.EXTRA_SAVE_USERNAME, username)
            putExtra(AutofillExtras.EXTRA_SAVE_PASSWORD, password)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
    }
}

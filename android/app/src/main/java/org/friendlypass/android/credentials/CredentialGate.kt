package org.friendlypass.android.credentials

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import org.friendlypass.android.FriendlypassApp
import org.friendlypass.android.unlock.UnlockGate
import org.friendlypass.android.vault.model.VaultState

/**
 * Shows [UnlockGate] until the vault is unlocked, then invokes [onReady] once. Both credentials activities use it
 * so an entry selected while the vault auto-locked still works: the user unlocks and the flow continues.
 */
@Composable
internal fun CredentialGate(onUnlocked: () -> Unit, onReady: () -> Unit) {
    val context = LocalContext.current
    val app = context.applicationContext as FriendlypassApp
    var unlocked by remember {
        mutableStateOf(app.vault.state.value is VaultState.Unlocked)
    }

    if (unlocked) {
        LaunchedEffect(Unit) { onReady() }
    } else {
        UnlockGate(
            onUnlocked = {
                onUnlocked()
                unlocked = true
            },
            onCancel = { (context as? android.app.Activity)?.finish() },
        )
    }
}

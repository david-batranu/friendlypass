package org.friendlypass.android.unlock

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.friendlypass.android.FriendlypassApp
import org.friendlypass.android.MainActivity
import org.friendlypass.android.ui.DatabasePickerScreen
import org.friendlypass.android.vault.model.DatabaseRef
import org.friendlypass.android.vault.model.VaultState

/** Credentials held only while the "Enable biometric unlock" offer is on screen. */
internal class BiometricOffer(
    val db: DatabaseRef,
    val password: CharArray?,
    val keyfile: ByteArray?,
) {
    fun wipe() {
        password?.fill('\u0000')
        keyfile?.fill(0)
    }
}

/**
 * The single entry point into the app (and, later, into autofill/credential activities): picker when no
 * database is selected, unlock when locked, [onUnlocked] immediately when already unlocked.
 */
@Composable
fun UnlockGate(onUnlocked: () -> Unit, onCancel: () -> Unit) {
    val context = LocalContext.current
    val app = context.applicationContext as FriendlypassApp
    val state by app.vault.state.collectAsStateWithLifecycle()
    val activity = context as? FragmentActivity
    var biometricOffer by remember { mutableStateOf<BiometricOffer?>(null) }

    // The enable offer belongs to the app's own screen ("...before the browser opens"). Autofill and
    // credential flows must answer the framework immediately; a modal nag there would stall the fill.
    val offersBiometric = activity is MainActivity

    when (val current = state) {
        VaultState.NoDatabase -> DatabasePickerScreen(onCancel = onCancel)

        is VaultState.Locked -> UnlockScreen(
            db = current.db,
            onUnlocked = { password, keyfile ->
                if (offersBiometric && activity != null && app.biometric.canAuthenticate() &&
                    !app.biometric.isEnabled(current.db)
                ) {
                    biometricOffer = BiometricOffer(current.db, password, keyfile)
                } else {
                    password?.fill('\u0000')
                    keyfile?.fill(0)
                    onUnlocked()
                }
            },
            onCancel = onCancel,
        )

        is VaultState.Unlocked -> {
            val offer = biometricOffer
            if (offer != null && activity != null) {
                EnableBiometricUnlockDialog(
                    offer = offer,
                    onEnable = {
                        app.biometric.enable(
                            activity = activity,
                            db = offer.db,
                            password = offer.password,
                            keyfile = offer.keyfile,
                            onEnabled = {
                                offer.wipe()
                                biometricOffer = null
                                onUnlocked()
                            },
                            onError = {
                                // Enabling is a convenience; the database is already unlocked.
                                offer.wipe()
                                biometricOffer = null
                                onUnlocked()
                            },
                        )
                    },
                    onDismiss = {
                        offer.wipe()
                        biometricOffer = null
                        onUnlocked()
                    },
                )
            } else {
                LaunchedEffect(current) { onUnlocked() }
            }
        }
    }
}

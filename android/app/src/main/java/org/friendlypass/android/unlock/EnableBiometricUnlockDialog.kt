package org.friendlypass.android.unlock

import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable

/** Offered once after a successful password unlock, before the browser opens. */
@Composable
internal fun EnableBiometricUnlockDialog(
    offer: BiometricOffer,
    onEnable: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Enable biometric unlock") },
        text = {
            Text(
                "Unlock ${offer.db.displayName} with your fingerprint or face from now on? Your password and " +
                    "key file are stored encrypted with a key that only works after biometric authentication, " +
                    "and are discarded if you enrol new biometrics.",
            )
        },
        confirmButton = {
            TextButton(onClick = onEnable) { Text("Enable") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Not now") }
        },
    )
}

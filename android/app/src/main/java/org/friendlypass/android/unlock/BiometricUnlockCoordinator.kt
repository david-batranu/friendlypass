package org.friendlypass.android.unlock

import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import org.friendlypass.android.vault.VaultRepository
import org.friendlypass.android.vault.model.VaultException

/**
 * Completes biometric unlock on a process-wide [scope].
 *
 * A `BiometricPrompt` can deliver its result after the activity that started it was recreated (the user
 * rotates the phone while the face prompt is up, the theme or locale changes, …). androidx.biometric hands
 * the success to the callback of the *old* screen, whose Compose `rememberCoroutineScope` is already
 * cancelled: launching `vault.unlock` there is dropped silently and the database stays locked with no
 * visible error. Unlocking on the application scope instead always runs, and the outcome is published in
 * [error] so whichever unlock screen instance is currently on screen shows failures. Success needs no
 * event: [VaultRepository] moves to Unlocked and the gate navigates.
 */
internal class BiometricUnlockCoordinator(
    private val scope: CoroutineScope,
    private val vault: VaultRepository,
    val error: MutableStateFlow<String?>,
) {

    /** Clears a previous failure when a new biometric attempt starts. */
    fun begin() {
        error.value = null
    }

    /**
     * Called with the credentials decrypted after a successful prompt; may come from a screen that no
     * longer exists, which is exactly why this must not use a composition scope. Never fails silently:
     * any error while unlocking is published in [error].
     */
    fun onCredentials(password: CharArray?, keyfile: ByteArray?) {
        Log.d(TAG, "biometric unlock: credentials received, unlocking on app scope")
        scope.launch {
            try {
                vault.unlock(password, keyfile)
                Log.d(TAG, "biometric unlock: vault unlocked")
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (e: VaultException) {
                Log.d(TAG, "vault unlock after biometric prompt failed: ${e::class.java.simpleName}")
                error.value = e.message ?: "Could not unlock the database"
            } catch (e: Exception) {
                Log.d(TAG, "vault unlock after biometric prompt failed: ${e::class.java.simpleName}")
                error.value = "Could not unlock the database"
            }
        }
    }

    /** Every prompt or keystore failure must become a visible message. */
    fun onError(message: String) {
        error.value = message
    }

    private companion object {
        const val TAG = "friendlypass.unlock"
    }
}

package org.friendlypass.android

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import org.friendlypass.android.autofill.AutofillRecents
import org.friendlypass.android.settings.AppSettings
import org.friendlypass.android.storage.AndroidDocumentGateway
import org.friendlypass.android.storage.DatabaseStore
import org.friendlypass.android.storage.PrefsRecentStore
import org.friendlypass.android.storage.SafDatabaseStore
import org.friendlypass.android.unlock.BiometricUnlock
import org.friendlypass.android.unlock.BiometricUnlockCoordinator
import org.friendlypass.android.vault.RustVaultRepository
import org.friendlypass.android.vault.VaultRepository

/**
 * Process-wide singletons. Wave 2 swaps [vault] for the UniFFI-backed `RustVaultRepository` in one line; nothing
 * else in the app constructs a repository or a store.
 */
class FriendlypassApp : Application() {

    lateinit var vault: VaultRepository
        private set

    lateinit var store: DatabaseStore
        private set

    lateinit var settings: AppSettings
        private set

    lateinit var autoLock: AutoLockController
        private set

    lateinit var biometric: BiometricUnlock
        private set

    /**
     * Runs the post-prompt half of a biometric unlock on [appScope]: the `BiometricPrompt` callback may
     * arrive after the unlock screen was recreated, and a composition-scoped launch would be dropped.
     */
    internal lateinit var biometricUnlocker: BiometricUnlockCoordinator
        private set

    /** Biometric unlock failures shown by whichever unlock screen instance is currently visible. */
    val biometricError = MutableStateFlow<String?>(null)

    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    private val screenOffReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == Intent.ACTION_SCREEN_OFF) {
                autoLock.onScreenOff()
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        settings = AppSettings(this)
        store = SafDatabaseStore(AndroidDocumentGateway(this), PrefsRecentStore(this))
        vault = RustVaultRepository(store, this)
        autoLock = AutoLockController(vault, timeoutMillis = { settings.lockTimeoutMillis })
        biometric = BiometricUnlock(this)
        biometricUnlocker = BiometricUnlockCoordinator(appScope, vault, biometricError)
        ContextCompat.registerReceiver(
            this,
            screenOffReceiver,
            IntentFilter(Intent.ACTION_SCREEN_OFF),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        // Autofill's "most recently used entry" memory is only valid while the vault is open.
        appScope.launch {
            vault.state.collect { state ->
                if (state !is org.friendlypass.android.vault.model.VaultState.Unlocked) {
                    AutofillRecents.clear()
                }
            }
        }
    }
}

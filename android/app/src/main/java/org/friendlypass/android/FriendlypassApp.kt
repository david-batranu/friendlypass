package org.friendlypass.android

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.core.content.ContextCompat
import org.friendlypass.android.settings.AppSettings
import org.friendlypass.android.storage.AndroidDocumentGateway
import org.friendlypass.android.storage.DatabaseStore
import org.friendlypass.android.storage.PrefsRecentStore
import org.friendlypass.android.storage.SafDatabaseStore
import org.friendlypass.android.unlock.BiometricUnlock
import org.friendlypass.android.vault.FakeVaultRepository
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
        vault = FakeVaultRepository()
        store = SafDatabaseStore(AndroidDocumentGateway(this), PrefsRecentStore(this))
        autoLock = AutoLockController(vault, timeoutMillis = { settings.lockTimeoutMillis })
        biometric = BiometricUnlock(this)
        ContextCompat.registerReceiver(
            this,
            screenOffReceiver,
            IntentFilter(Intent.ACTION_SCREEN_OFF),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
    }
}

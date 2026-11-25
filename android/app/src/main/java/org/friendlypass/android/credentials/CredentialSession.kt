package org.friendlypass.android.credentials

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import org.friendlypass.android.vault.VaultRepository
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Process-wide unlock freshness for the credential provider. Started lazily by the service and by the
 * credential activities (the provider cannot change `FriendlypassApp` to install a listener at startup).
 */
internal object CredentialSession {

    private val freshness = UnlockFreshness()
    private val started = AtomicBoolean(false)

    fun ensureStarted(vault: VaultRepository) {
        if (!started.compareAndSet(false, true)) return
        freshness.onState(vault.state.value)
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        scope.launch {
            vault.state.collect { freshness.onState(it) }
        }
    }

    fun markUnlocked() {
        freshness.markUnlocked()
    }

    fun requiresUserVerification(): Boolean = freshness.requiresVerification()

    fun hasObservedUnlock(): Boolean = freshness.hasObservedUnlock()
}

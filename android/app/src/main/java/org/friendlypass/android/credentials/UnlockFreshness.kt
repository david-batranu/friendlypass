package org.friendlypass.android.credentials

import org.friendlypass.android.vault.model.VaultState

/**
 * Tracks how long ago the vault was unlocked so passkey use can require user verification once the unlock is
 * stale. Clock is injected for JVM tests.
 *
 * Note: the vault API does not expose an unlock timestamp. This tracker observes the repository's state from the
 * moment the credential provider first runs; if it starts while the vault is already unlocked (the normal case,
 * because the service binds lazily) it treats that as "just unlocked". The unlock activity additionally calls
 * [markUnlocked] whenever it unlocks the vault itself.
 */
internal class UnlockFreshness(
    private val now: () -> Long = System::currentTimeMillis,
    private val verificationWindowMillis: Long = VERIFICATION_WINDOW_MS,
) {
    private var unlockedAtMillis: Long? = null

    @Synchronized
    fun onState(state: VaultState) {
        when (state) {
            is VaultState.Unlocked -> if (unlockedAtMillis == null) unlockedAtMillis = now()
            else -> unlockedAtMillis = null
        }
    }

    @Synchronized
    fun markUnlocked() {
        unlockedAtMillis = now()
    }

    @Synchronized
    fun hasObservedUnlock(): Boolean = unlockedAtMillis != null

    @Synchronized
    fun requiresVerification(): Boolean {
        val unlockedAt = unlockedAtMillis ?: return true
        return now() - unlockedAt >= verificationWindowMillis
    }

    companion object {
        const val VERIFICATION_WINDOW_MS: Long = 60_000L
    }
}

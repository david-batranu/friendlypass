package org.friendlypass.android

import org.friendlypass.android.vault.VaultRepository
import org.friendlypass.android.vault.model.VaultState
import java.util.concurrent.atomic.AtomicLong

/**
 * App-layer auto-lock: the vault is dropped on [android.content.Intent.ACTION_SCREEN_OFF] and after
 * [timeoutMillis] of inactivity. The UI calls [touch] from `Activity.onUserInteraction`; [checkIdle] is polled
 * while the app is in the foreground.
 *
 * The clock and the timeout are injected so this can be unit tested on the JVM.
 */
class AutoLockController(
    private val vault: VaultRepository,
    private val now: () -> Long = System::currentTimeMillis,
    private val timeoutMillis: () -> Long = { DEFAULT_TIMEOUT_MS },
) {
    private val lastInteraction = AtomicLong(now())

    /** Records user activity; used to keep the vault unlocked while the user is working. */
    fun touch() {
        lastInteraction.set(now())
    }

    /** Locks immediately (screen off, explicit "Lock now"). */
    fun onScreenOff() {
        vault.lock()
    }

    /**
     * Locks when the idle timeout elapsed. Returns true when it locked. While the vault is not unlocked the
     * activity timestamp keeps moving so a fresh unlock is never treated as long idle.
     */
    fun checkIdle(): Boolean {
        val current = now()
        if (vault.state.value !is VaultState.Unlocked) {
            lastInteraction.set(current)
            return false
        }
        val timeout = timeoutMillis()
        if (timeout <= 0L) {
            lastInteraction.set(current)
            return false
        }
        if (current - lastInteraction.get() >= timeout) {
            vault.lock()
            lastInteraction.set(current)
            return true
        }
        return false
    }

    companion object {
        const val DEFAULT_TIMEOUT_MS = 5 * 60_000L
    }
}

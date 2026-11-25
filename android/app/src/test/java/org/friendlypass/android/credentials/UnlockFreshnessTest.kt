package org.friendlypass.android.credentials

import org.friendlypass.android.vault.model.DatabaseRef
import org.friendlypass.android.vault.model.VaultState
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UnlockFreshnessTest {

    private var now = 1_000L
    private val freshness = UnlockFreshness(now = { now })

    private val db = DatabaseRef("content://test/demo.kdbx", "demo.kdbx")

    @Test
    fun `a vault we never saw unlocked requires verification`() {
        assertTrue(freshness.requiresVerification())
        assertFalse(freshness.hasObservedUnlock())
    }

    @Test
    fun `a fresh unlock counts as verification`() {
        freshness.onState(VaultState.Unlocked(db, "demo.kdbx"))

        assertFalse(freshness.requiresVerification())
        now += 59_999L
        assertFalse(freshness.requiresVerification())
    }

    @Test
    fun `an unlock older than sixty seconds requires verification`() {
        freshness.onState(VaultState.Unlocked(db, "demo.kdbx"))
        now += 60_000L

        assertTrue(freshness.requiresVerification())
    }

    @Test
    fun `marking unlocked refreshes the window`() {
        freshness.onState(VaultState.Unlocked(db, "demo.kdbx"))
        now += 120_000L
        assertTrue(freshness.requiresVerification())

        freshness.markUnlocked()
        assertFalse(freshness.requiresVerification())
    }

    @Test
    fun `locking clears the observed unlock`() {
        freshness.onState(VaultState.Unlocked(db, "demo.kdbx"))
        freshness.onState(VaultState.Locked(db))

        assertTrue(freshness.requiresVerification())
        assertFalse(freshness.hasObservedUnlock())
    }
}

package org.friendlypass.android

import kotlinx.coroutines.test.runTest
import org.friendlypass.android.vault.FakeVaultRepository
import org.friendlypass.android.vault.model.VaultState
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AutoLockControllerTest {

    private var now = 1_000_000L
    private val timeout = 5 * 60_000L

    private suspend fun unlockedVault(): FakeVaultRepository = FakeVaultRepository().apply {
        selectDatabase(FakeVaultRepository.DEMO_DATABASE)
        unlock("test".toCharArray(), null)
    }

    private fun controller(vault: FakeVaultRepository, timeoutMillis: Long = timeout) =
        AutoLockController(vault, now = { now }, timeoutMillis = { timeoutMillis })

    @Test
    fun `does not lock before the timeout`() = runTest {
        val vault = unlockedVault()
        val controller = controller(vault)

        now += timeout - 1
        assertFalse(controller.checkIdle())
        assertTrue(vault.state.value is VaultState.Unlocked)
    }

    @Test
    fun `locks once the timeout elapses`() = runTest {
        val vault = unlockedVault()
        val controller = controller(vault)

        now += timeout
        assertTrue(controller.checkIdle())
        assertTrue(vault.state.value is VaultState.Locked)
    }

    @Test
    fun `user interaction resets the idle timer`() = runTest {
        val vault = unlockedVault()
        val controller = controller(vault)

        now += timeout - 1_000
        controller.touch()
        now += timeout - 1
        assertFalse(controller.checkIdle())
        assertTrue(vault.state.value is VaultState.Unlocked)

        now += 1
        assertTrue(controller.checkIdle())
    }

    @Test
    fun `screen off locks immediately`() = runTest {
        val vault = unlockedVault()
        val controller = controller(vault)

        controller.onScreenOff()

        assertTrue(vault.state.value is VaultState.Locked)
        assertFalse(controller.checkIdle())
    }

    @Test
    fun `a zero timeout disables the idle lock`() = runTest {
        val vault = unlockedVault()
        val controller = controller(vault, timeoutMillis = 0L)

        now += 24 * 60 * 60_000L
        assertFalse(controller.checkIdle())
        assertTrue(vault.state.value is VaultState.Unlocked)
    }

    @Test
    fun `locked vaults are left alone and a fresh unlock gets a full timeout`() = runTest {
        val vault = FakeVaultRepository()
        val controller = controller(vault)

        now += timeout * 4
        assertFalse(controller.checkIdle())

        vault.selectDatabase(FakeVaultRepository.DEMO_DATABASE)
        vault.unlock("test".toCharArray(), null)
        now += 1_000
        assertFalse("the timer restarts when a database unlocks", controller.checkIdle())
        assertTrue(vault.state.value is VaultState.Unlocked)
    }
}

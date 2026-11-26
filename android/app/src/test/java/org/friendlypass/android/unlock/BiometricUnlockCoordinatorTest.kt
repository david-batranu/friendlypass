package org.friendlypass.android.unlock

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.MutableStateFlow
import org.friendlypass.android.vault.FakeVaultRepository
import org.friendlypass.android.vault.model.VaultState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Regression tests for the biometric unlock hand-back: the `BiometricPrompt` callback can arrive after the
 * unlock screen was recreated (rotation while the prompt is up), so the credential must be unlocked on a
 * process-wide scope and the failure must surface in a state flow the live screen renders.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class BiometricUnlockCoordinatorTest {

    private val error = MutableStateFlow<String?>(null)

    private fun lockedVault(): FakeVaultRepository = FakeVaultRepository().apply {
        selectDatabase(FakeVaultRepository.DEMO_DATABASE)
    }

    private fun coordinator(vault: FakeVaultRepository) =
        BiometricUnlockCoordinator(CoroutineScope(Dispatchers.Unconfined + SupervisorJob()), vault, error)

    @Test
    fun `unlock still runs when the callback arrives from a cancelled composition scope`() {
        val vault = lockedVault()
        val appScope = CoroutineScope(Dispatchers.Unconfined + SupervisorJob())
        val coordinator = BiometricUnlockCoordinator(appScope, vault, error)

        // The screen that started the prompt is gone: its scope is cancelled, exactly like after an
        // activity recreation mid-prompt. A launch on that scope never runs — this documents the bug.
        val compositionScope = CoroutineScope(Dispatchers.Unconfined + Job())
        compositionScope.cancel()
        var lateRan = false
        compositionScope.launch { lateRan = true }
        assertFalse("sanity: an already-cancelled scope drops launches (the old bug)", lateRan)

        // The prompt now delivers the credentials; the coordinator must not care that the caller's
        // composition died.
        coordinator.onCredentials(FakeVaultRepository.DEMO_PASSWORD.toCharArray(), null)

        assertTrue("vault.unlock must have run on the app scope", vault.state.value is VaultState.Unlocked)
        assertNull(error.value)
    }

    @Test
    fun `wrong stored credentials produce a visible error and stay locked`() {
        val vault = lockedVault()
        coordinator(vault).onCredentials("not-the-password".toCharArray(), null)

        assertTrue(vault.state.value is VaultState.Locked)
        assertEquals("Wrong password or key file", error.value)
    }

    @Test
    fun `prompt errors are published for the visible unlock screen`() {
        coordinator(lockedVault()).onError("Biometric unlock is no longer available. Enter your password.")

        assertEquals("Biometric unlock is no longer available. Enter your password.", error.value)
    }

    @Test
    fun `begin clears the previous failure`() {
        val coordinator = coordinator(lockedVault())
        coordinator.onError("something")
        coordinator.begin()

        assertNull(error.value)
    }

    @Test
    fun `a keyfile-only credential set is delivered unchanged`() {
        val vault = lockedVault()
        // The fake accepts any non-empty key file together with the demo password; an empty one must fail
        // with a visible error rather than silently.
        coordinator(vault).onCredentials(FakeVaultRepository.DEMO_PASSWORD.toCharArray(), ByteArray(0))

        assertTrue(vault.state.value is VaultState.Locked)
        assertEquals("Wrong password or key file", error.value)
    }
}

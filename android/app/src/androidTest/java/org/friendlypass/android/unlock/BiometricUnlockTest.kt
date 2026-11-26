package org.friendlypass.android.unlock

import android.app.Activity
import android.content.Intent
import android.content.pm.ActivityInfo
import android.app.KeyguardManager
import android.content.Context
import android.os.ParcelFileDescriptor
import android.service.autofill.FillResponse
import android.view.View
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import androidx.biometric.BiometricManager
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import org.friendlypass.android.FriendlypassApp
import org.friendlypass.android.MainActivity
import org.friendlypass.android.autofill.AutofillAuthActivity
import org.friendlypass.android.autofill.AutofillExtras
import org.friendlypass.android.autofill.AutofillTarget
import org.friendlypass.android.autofill.FieldIds
import org.friendlypass.android.debug.DebugVaultFile
import org.friendlypass.android.vault.model.DatabaseRef
import org.friendlypass.android.vault.model.VaultState
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * End-to-end biometric unlock against the real keystore and the real KDBX (`sample4.kdbx`, password
 * **testpassword**): enable after a password unlock, lock, and unlock again with the biometric.
 *
 * A fingerprint cannot be presented from inside a test — `adb emu finger touch 1` is an emulator console
 * command, not a shell command, and `UiDevice.executeShellCommand` only reaches the device shell. The test
 * therefore waits for a *host trigger*: run `adb -s emulator-<port> emu finger touch 1` while a prompt is
 * up (the app logs `friendlypass.biometric: prompt: starting` on logcat for each one). A prompt that
 * nobody satisfies times out and the test fails with a visible-error assertion, never a silent pass.
 *
 * When the device has no enrolled class-3 biometric (a fresh emulator boot with `-read-only` wipes the
 * enrolment), the whole class is skipped with an assumption — enable requires a real prompt.
 *
 * The second test is the regression test for the fixed bug: the activity is recreated (rotation) while
 * the prompt is up. Before the fix the success callback landed on the dead composition's scope,
 * `vault.unlock` was silently dropped, and the database stayed locked without any error. The third test
 * covers the same unlock through [org.friendlypass.android.autofill.AutofillAuthActivity], the activity
 * behind the autofill "Unlock friendlypass" chip, which hosts the very same UnlockGate.
 */
@RunWith(AndroidJUnit4::class)
class BiometricUnlockTest {

    @get:Rule
    val composeRule = createAndroidComposeRule<MainActivity>()

    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val app: FriendlypassApp get() = context.applicationContext as FriendlypassApp
    private val device: UiDevice get() = UiDevice.getInstance(instrumentation)

    private val enrolled: Boolean
        get() =
            BiometricManager.from(context)
                .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
                BiometricManager.BIOMETRIC_SUCCESS &&
                (context.getSystemService(KeyguardManager::class.java)?.isDeviceSecure == true)

    @Before
    fun setUp() {
        assumeTrue(
            "no class-3 biometric + screen lock enrolled: enable requires the real prompt and a host-" +
                "triggered `adb -s emulator-<port> emu finger touch 1`; skipping",
            enrolled,
        )
        val ref = DebugVaultFile.install(
            context,
            instrumentation.context.assets.open(ASSET).use { it.readBytes() },
            FIXTURE,
        )
        app.biometric.disable(ref)
        app.vault.lock()
        app.vault.selectDatabase(ref)
        // The host watcher only feeds the finger while this marker exists, so no other test class can
        // be affected by it.
        shell("touch $TOUCH_MARKER")
    }

    @After
    fun tearDown() {
        shell("rm -f $TOUCH_MARKER")
        runCatching {
            composeRule.activityRule.scenario.onActivity {
                it.requestedOrientation = ActivityInfo.SCREEN_ORIENTATION_UNSPECIFIED
            }
        }
        runCatching { app.biometric.disable(currentRef()) }
        runCatching { app.vault.lock() }
        DebugVaultFile.delete(context, FIXTURE)
    }

    private fun shell(command: String): String =
        instrumentation.uiAutomation.executeShellCommand(command).use { pfd ->
            ParcelFileDescriptor.AutoCloseInputStream(pfd).bufferedReader().readText()
        }

    @Test
    fun enableThenUnlockWithBiometricsEndToEnd() {
        enableBiometricViaUi()

        app.vault.lock()
        unlockWithBiometricsViaUi()
        assertNull("a successful biometric unlock must not show an error", visibleError())
        assertTrue("the blob must survive a successful unlock", app.biometric.isEnabled(currentRef()))
        composeRule.onNodeWithTag("search").assertExists()
    }

    @Test
    fun biometricUnlockSurvivesActivityRecreationDuringPrompt() {
        enableBiometricViaUi()

        app.vault.lock()
        composeRule.waitUntil(TIMEOUT_UI) {
            composeRule.onAllNodesWithTag("biometric-unlock").fetchSemanticsNodes().isNotEmpty()
        }
        composeRule.onNodeWithTag("biometric-unlock").performClick()
        composeRule.waitForIdle()

        // Recreate the activity while the system prompt is in front, like a rotation while the user
        // lifts the phone to the face sensor.
        composeRule.activityRule.scenario.onActivity {
            it.requestedOrientation = ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE
        }
        Thread.sleep(2_000)

        awaitUnlockedAfterBiometric()
        assertNull("recreation must not swallow the unlock result", visibleError())
        assertEquals(
            "unlock must finish even though the starting composition died",
            VaultState.Unlocked::class.java.simpleName,
            app.vault.state.value::class.java.simpleName,
        )
    }

    @Test
    fun biometricUnlockCompletesTheAutofillAuthenticationGate() {
        enableBiometricViaUi()
        app.vault.lock()

        val intent = Intent(context, AutofillAuthActivity::class.java).apply {
            AutofillExtras.putFieldIds(
                this,
                FieldIds(
                    usernameIds = listOf(AutofillId.create(View(context), 1)),
                    passwordIds = listOf(AutofillId.create(View(context), 2)),
                ),
            )
            AutofillExtras.putTarget(
                this,
                AutofillTarget.App("org.friendlypass.testapp"),
                "org.friendlypass.testapp",
            )
        }
        val scenario = ActivityScenario.launchActivityForResult<AutofillAuthActivity>(intent)
        try {
            val button = device.wait(Until.findObject(By.text("Unlock with biometrics")), TIMEOUT_UI)
            assertNotNull("the autofill gate did not show the biometric button", button)

            // This is the activity that the autofill "Unlock friendlypass" chip opens: the UnlockGate
            // must complete the fill request after a biometric unlock, wherever the gate is hosted.
            button!!.click()
            val unlocked = pollUntil(TIMEOUT_TOUCH + TIMEOUT_ARGON2) {
                app.vault.state.value is VaultState.Unlocked
            }
            assertTrue("biometric unlock through the autofill gate did not complete", unlocked)
            val delivered = pollUntil(20_000) { runCatching { scenario.result }.isSuccess }
            assertTrue("the auth activity never finished with a result after the unlock", delivered)
            val result = scenario.result
            assertEquals(
                "the autofill gate did not deliver a response after the biometric unlock",
                Activity.RESULT_OK,
                result.resultCode,
            )
            assertNotNull(
                result.resultData?.getParcelableExtra(
                    AutofillManager.EXTRA_AUTHENTICATION_RESULT,
                    FillResponse::class.java,
                ),
            )
        } finally {
            runCatching { scenario.close() }
        }
    }

    // ------------------------------------------------------------------ steps

    private fun currentRef(): DatabaseRef =
        (app.vault.state.value as? VaultState.Locked)?.db
            ?: (app.vault.state.value as VaultState.Unlocked).db

    /**
     * Drives "password unlock -> Enable biometric unlock -> prompt". Retries the whole dance up to
     * three times: on this shared emulator the biometric availability check is occasionally
     * [BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE] for a moment right after a fingerprint session
     * teardown, which makes the offer (or a later prompt) skip; that is a harness condition, not the
     * behaviour under test. Every path still ends with the blob really stored, or a failure.
     */
    private fun enableBiometricViaUi() {
        val ref = currentRef()
        var diagnosis = ""
        repeat(3) { attempt ->
            unlockWithPassword()
            when {
                visibleError() != null -> {
                    diagnosis = "attempt ${attempt + 1}: password unlock failed: ${visibleError()}"
                }
                offerVisible() -> {
                    composeRule.onNodeWithText("Enable").performClick()
                    val stored = pollUntil(TIMEOUT_TOUCH + 30_000) { app.biometric.isEnabled(ref) }
                    if (stored) return
                    diagnosis = "attempt ${attempt + 1}: enable prompt never satisfied " +
                        "(no `adb emu finger touch 1`? last prompt error see logcat)"
                }
                else -> {
                    // The gate navigated without offering: transient canAuthenticate() failure.
                    diagnosis = if (app.vault.state.value is VaultState.Unlocked) {
                        "attempt ${attempt + 1}: offer skipped although enrolled (transient " +
                            "canAuthenticate failure?)"
                    } else {
                        "attempt ${attempt + 1}: unlock click produced neither offer nor error " +
                            "(password field length ${passwordLength()})"
                    }
                }
            }
            runCatching { app.vault.lock() }
            composeRule.waitUntil(TIMEOUT_UI) {
                composeRule.onAllNodesWithTag("password").fetchSemanticsNodes().isNotEmpty()
            }
        }
        org.junit.Assert.fail("could not enable biometric unlock in three attempts: $diagnosis")
    }

    private fun offerVisible(): Boolean =
        composeRule.onAllNodes(hasText("Enable biometric unlock")).fetchSemanticsNodes().isNotEmpty()

    private fun unlockWithPassword() {
        composeRule.waitUntil(TIMEOUT_UI) {
            composeRule.onAllNodesWithTag("password").fetchSemanticsNodes().isNotEmpty()
        }
        composeRule.onNodeWithTag("password").performTextInput(DebugVaultFile.PASSWORD)
        composeRule.onNodeWithTag("unlock").performClick()
        // KDBX4 Argon2 unlock is slow on the emulator.
        pollUntil(TIMEOUT_ARGON2) { offerVisible() || visibleError() != null || app.vault.state.value is VaultState.Unlocked }
    }

    /** Length of what landed in the password field; never its content. */
    private fun passwordLength(): Int {
        val nodes = composeRule.onAllNodesWithTag("password").fetchSemanticsNodes()
        if (nodes.isEmpty()) return -1
        val config = nodes.first().config
        if (!config.contains(androidx.compose.ui.semantics.SemanticsProperties.Text)) return 0
        return config[androidx.compose.ui.semantics.SemanticsProperties.Text].joinToString("") { it.text }.length
    }

    private fun unlockWithBiometricsViaUi() {
        composeRule.waitUntil(TIMEOUT_UI) {
            composeRule.onAllNodesWithTag("biometric-unlock").fetchSemanticsNodes().isNotEmpty()
        }
        composeRule.onNodeWithTag("biometric-unlock").performClick()
        awaitUnlockedAfterBiometric()
    }

    private fun awaitUnlockedAfterBiometric() {
        // The prompt needs the host-triggered finger touch, then the Rust unlock takes seconds.
        val unlocked = pollUntil(TIMEOUT_TOUCH + TIMEOUT_ARGON2) {
            app.vault.state.value is VaultState.Unlocked || visibleError() != null
        }
        val failure = visibleError()
        assertNull("biometric unlock failed: $failure (was the finger touched from the host?)", failure)
        assertTrue("biometric unlock did not complete within ${TIMEOUT_TOUCH + TIMEOUT_ARGON2} ms", unlocked)
        assertTrue(app.vault.state.value is VaultState.Unlocked)
    }

    private fun visibleError(): String? {
        val nodes = composeRule.onAllNodesWithTag("unlock-error").fetchSemanticsNodes()
        if (nodes.isEmpty()) return null
        val config = nodes.first().config
        if (!config.contains(androidx.compose.ui.semantics.SemanticsProperties.Text)) return null
        return config[androidx.compose.ui.semantics.SemanticsProperties.Text].joinToString(" ") { it.text }
    }

    private inline fun pollUntil(timeoutMillis: Long, condition: () -> Boolean): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMillis
        while (System.currentTimeMillis() < deadline) {
            if (condition()) return true
            Thread.sleep(200)
        }
        return condition()
    }

    private companion object {
        const val ASSET = "sample4.kdbx"
        const val FIXTURE = "sample4-biometric-test.kdbx"
        const val TOUCH_MARKER = "/data/local/tmp/fp-biometric-test-active"
        const val TIMEOUT_UI = 10_000L
        const val TIMEOUT_ARGON2 = 90_000L
        const val TIMEOUT_TOUCH = 240_000L
    }
}

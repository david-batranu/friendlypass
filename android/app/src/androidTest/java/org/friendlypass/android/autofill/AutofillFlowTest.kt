package org.friendlypass.android.autofill

import android.os.ParcelFileDescriptor
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.BySelector
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.StaleObjectException
import androidx.test.uiautomator.Until
import kotlinx.coroutines.runBlocking
import org.friendlypass.android.FriendlypassApp
import org.friendlypass.android.vault.FakeVaultRepository
import org.friendlypass.android.vault.model.NewLogin
import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * End-to-end autofill test on the emulator: lock the vault, focus the test app's username field and
 * check that the framework received the locked response with the inline unlock chip, then unlock and
 * check that a fill response with the matching dataset reaches the framework.
 *
 * Gboard's inline chip strip lives in the IME window, which UiAutomator does not expose on this image,
 * so the response itself is asserted through `dumpsys autofill` (verbose). When the chip *is* visible to
 * UiAutomator the test also taps it and asserts the credentials were filled.
 */
@RunWith(AndroidJUnit4::class)
class AutofillFlowTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val device: UiDevice = UiDevice.getInstance(instrumentation)
    private val context get() = instrumentation.targetContext
    private val app: FriendlypassApp get() = context.applicationContext as FriendlypassApp

    private val serviceComponent = "org.friendlypass.android/.autofill.FriendlypassAutofillService"

    @Before
    fun setUp() {
        shell("settings put secure autofill_service $serviceComponent")
        shell("cmd autofill set log_level verbose")
        shell("am force-stop org.friendlypass.testapp")

        runBlocking {
            app.store.remember(FakeVaultRepository.DEMO_DATABASE)
            app.vault.selectDatabase(FakeVaultRepository.DEMO_DATABASE)
            app.vault.unlock(FakeVaultRepository.DEMO_PASSWORD.toCharArray(), null)
            app.vault.addLogin(
                NewLogin(
                    title = "Test App",
                    username = "demo@example.app",
                    password = "android-demo-password",
                    url = null,
                    androidApp = "org.friendlypass.testapp",
                ),
            )
        }
        app.vault.lock()

        shell("am start -n org.friendlypass.testapp/.LoginActivity")
        assertNotNull(
            "test app login form did not appear",
            device.wait(Until.findObject(By.res(TEST_APP, "username")), 10_000),
        )
    }

    @Test
    fun lockedResponseCarriesInlineUnlockChipAndUnlockedResponseHasDatasets() {
        assertEquals(
            "friendlypass is not the selected autofill service",
            serviceComponent,
            shell("settings get secure autofill_service").trim(),
        )

        device.findObject(By.res(TEST_APP, "username")).click()
        device.waitForIdle()

        val lockedDump = waitForDump { it.contains("hasAuthentication") && it.contains(serviceComponent) }
        assertTrue("locked fill response was not delivered to the framework", lockedDump.contains("hasAuthentication"))
        assertTrue(
            "locked fill response did not include the inline keyboard chip",
            lockedDump.contains("hasInlinePresentation"),
        )
        assertTrue(
            "AutofillManager does not report an enabled autofill service",
            AutofillStatus.isAutofillEnabled(context),
        )

        // If the IME exposes its chip strip to accessibility, drive the real unlock + fill flow.
        val chipVisible = device.wait(Until.hasObject(By.textContains("Unlock friendlypass")), 3_000)
        if (chipVisible) {
            assertTrue("unlock chip disappeared before it could be tapped", click(By.textContains("Unlock friendlypass")))
            val passwordField = device.wait(Until.findObject(By.clazz("android.widget.EditText")), 10_000)
            assertNotNull("unlock screen did not appear", passwordField)
            passwordField.click()
            device.executeShellCommand("input text ${FakeVaultRepository.DEMO_PASSWORD}")
            assertTrue("unlock button not found", click(By.text("Unlock"), 10_000))

            // After authentication the framework shows the returned datasets as chips; pick the entry.
            // The keyboard may be hidden after the auth activity finishes, so refocus the field once.
            device.wait(Until.hasObject(By.pkg(TEST_APP)), 10_000)
            device.waitForIdle()
            var entryChipVisible = device.wait(Until.hasObject(By.textContains("Test App")), 5_000)
            if (!entryChipVisible) {
                device.pressBack()
                device.waitForIdle()
                device.findObject(By.res(TEST_APP, "username")).click()
                entryChipVisible = device.wait(Until.hasObject(By.textContains("Test App")), 10_000)
            }
            assertTrue("authenticated datasets did not appear after unlocking", entryChipVisible)
            assertTrue("could not tap the entry chip", click(By.textContains("Test App")))

            val username = device.wait(
                Until.findObject(By.res(TEST_APP, "username").text("demo@example.app")),
                15_000,
            )
            assertNotNull(
                "username was not filled by the autofill dataset (text='" +
                    (device.findObject(By.res(TEST_APP, "username"))?.text ?: "") + "')",
                username,
            )
        }

        // Unlock and ask for a new fill: the framework must receive the matching dataset and the
        // pinned "Search friendlypass…" dataset.
        if (app.vault.state.value !is org.friendlypass.android.vault.model.VaultState.Unlocked) {
            runBlocking { app.vault.unlock(FakeVaultRepository.DEMO_PASSWORD.toCharArray(), null) }
        }
        shell("am start -n org.friendlypass.testapp/.LoginActivity")
        val passwordForUnlockedCheck = device.wait(Until.findObject(By.res(TEST_APP, "password")), 10_000)
        assertNotNull("test app form is not visible for the unlocked fill check", passwordForUnlockedCheck)
        passwordForUnlockedCheck.click()
        val unlockedDump = waitForDump { it.contains("datasets=[Dataset") && !it.contains("datasets=[]") }
        assertFalse("no fill response was delivered after unlocking", unlockedDump.isEmpty())
        assertTrue(
            "unlocked fill response did not contain the matching entry plus the search dataset",
            Regex("Dataset\\[id=").findAll(unlockedDump).count() >= 2,
        )
    }

    /** Clicks [selector], retrying when the accessibility node is replaced while the UI updates. */
    private fun click(selector: BySelector, timeoutMs: Long = 5_000): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            val node = device.wait(Until.findObject(selector), 1_000)
            if (node != null) {
                try {
                    node.click()
                    return true
                } catch (e: StaleObjectException) {
                    // Node was replaced mid-click; find it again.
                }
            }
        }
        return false
    }

    private fun waitForDump(timeoutMs: Long = 10_000, predicate: (String) -> Boolean): String {
        val deadline = System.currentTimeMillis() + timeoutMs
        var last = ""
        while (System.currentTimeMillis() < deadline) {
            last = shell("dumpsys autofill")
            if (predicate(last)) return last
            Thread.sleep(400)
        }
        return last
    }

    private fun shell(command: String): String =
        instrumentation.uiAutomation.executeShellCommand(command).use { pfd ->
            ParcelFileDescriptor.AutoCloseInputStream(pfd).bufferedReader().readText()
        }

    companion object {
        private const val TEST_APP = "org.friendlypass.testapp"
    }
}

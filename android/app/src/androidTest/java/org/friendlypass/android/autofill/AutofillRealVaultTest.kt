package org.friendlypass.android.autofill

import android.os.ParcelFileDescriptor
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.BySelector
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import kotlinx.coroutines.runBlocking
import org.friendlypass.android.FriendlypassApp
import org.friendlypass.android.debug.DebugVaultFile
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.friendlypass_mobile.openVault

/**
 * Autofill save against a real KDBX file: fill both fields of `:testapp`, commit the form, accept the save
 * sheet, then re-open the written bytes with the Rust vault and check the stored `AndroidApp` field.
 */
@RunWith(AndroidJUnit4::class)
class AutofillRealVaultTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val device: UiDevice = UiDevice.getInstance(instrumentation)
    private val context get() = instrumentation.targetContext
    private val app: FriendlypassApp get() = context.applicationContext as FriendlypassApp

    @Before
    fun setUp() {
        shell("settings put secure autofill_service $SERVICE")
        shell("cmd autofill set log_level verbose")
        shell("cmd autofill reset")
        val ref = DebugVaultFile.install(
            context,
            instrumentation.context.assets.open(ASSET).use { it.readBytes() },
            FIXTURE,
        )
        runBlocking {
            app.store.remember(ref)
            app.vault.selectDatabase(ref)
            app.vault.unlock(DebugVaultFile.PASSWORD.toCharArray(), null)
        }
        shell("am force-stop $TEST_APP")
    }

    @After
    fun tearDown() {
        app.vault.lock()
        shell("am force-stop $TEST_APP")
    }

    @Test
    fun savedLoginPersistsWithTheAndroidAppField() {
        shell("am start -W -n $TEST_APP/.LoginActivity")
        val username = device.wait(Until.findObject(By.res(TEST_APP, "username")), 10_000)
        assertNotNull("test app did not start", username)
        // Focus each field before typing so the framework starts an autofill session and sees the values
        // change; a save request is only sent for fields changed during the session.
        username!!.click()
        username.setText(USERNAME)
        val password = device.wait(Until.findObject(By.res(TEST_APP, "password")), 5_000)
        assertNotNull("test app has no password field", password)
        password!!.click()
        password.setText(PASSWORD)
        device.waitForIdle()

        click(By.res(TEST_APP, "sign_in"))

        // The framework first shows its own SaveInfo dialog; accepting it calls onSaveRequest, whose
        // IntentSender opens our confirmation sheet.
        if (device.wait(Until.hasObject(By.textContains("Save username and password to friendlypass")), 15_000)) {
            click(By.text("Save"))
        }
        device.waitForIdle()
        val sheet = device.wait(Until.findObject(By.text("Save login?")), 30_000)
        if (sheet == null) screenshot("w3-debug-autofill-save")
        assertNotNull("the autofill save sheet did not appear", sheet)
        screenshot("w3-autofill-save")
        click(By.text("Save"))
        device.wait(Until.gone(By.text("Save login?")), 10_000)

        val opened = openVault(DebugVaultFile.read(context, FIXTURE)!!, DebugVaultFile.PASSWORD, null)
        try {
            val saved = opened.allEntries().filter { it.username == USERNAME }
            assertEquals("the saved login must be in the written KDBX", 1, saved.size)
            val detail = opened.entry(saved.single().uuid)
            assertEquals(PASSWORD, detail.password)
            assertTrue(
                "AndroidApp was not persisted (androidApps=${detail.androidApps})",
                detail.androidApps.contains(TEST_APP),
            )
            assertTrue(
                "the custom AndroidApp field is missing",
                detail.customFields.any { it.name == "AndroidApp" && it.value == TEST_APP },
            )
            assertTrue(
                "the saved login must match :testapp",
                opened.matchApp(TEST_APP).any { it.uuid == saved.single().uuid },
            )
        } finally {
            opened.destroy()
        }
    }

    private fun click(selector: BySelector) {
        val node = device.wait(Until.findObject(selector), 10_000)
        assertNotNull("could not find $selector", node)
        node!!.click()
        device.waitForIdle()
    }

    private fun screenshot(name: String) {
        shell("screencap -p /sdcard/$name.png")
    }

    private fun shell(command: String): String =
        instrumentation.uiAutomation.executeShellCommand(command).use { pfd ->
            ParcelFileDescriptor.AutoCloseInputStream(pfd).bufferedReader().readText()
        }

    companion object {
        private const val TEST_APP = "org.friendlypass.testapp"
        private const val SERVICE = "org.friendlypass.android/.autofill.FriendlypassAutofillService"
        private const val ASSET = "sample4.kdbx"
        private const val FIXTURE = "sample4-autofill.kdbx"
        private const val USERNAME = "real-autofill-user"
        private const val PASSWORD = "real-autofill-password"
    }
}

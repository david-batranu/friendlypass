package org.friendlypass.android.autofill

import android.os.ParcelFileDescriptor
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.BySelector
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.UiObject2
import androidx.test.uiautomator.Until
import kotlinx.coroutines.runBlocking
import org.friendlypass.android.FriendlypassApp
import org.friendlypass.android.debug.DebugVaultFile
import org.friendlypass.android.vault.model.VaultState
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * End-to-end one-time-code autofill against a real KDBX fixture with a TOTP entry that matches
 * `:testapp` both by URL (`https://appassets.androidplatform.net`, the WebView assets origin) and by
 * `AndroidApp=org.friendlypass.testapp`.
 *
 * The keyboard's inline chips are part of Gboard's window, which UiAutomator does not expose on this
 * image, so a chip is tapped at the top of the IME surface (its inset comes from `dumpsys window`). Every
 * assertion about the code itself reads the filled field.
 */
@RunWith(AndroidJUnit4::class)
class OtpAutofillTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val device: UiDevice = UiDevice.getInstance(instrumentation)
    private val context get() = instrumentation.targetContext
    private val app: FriendlypassApp get() = context.applicationContext as FriendlypassApp

    private lateinit var entryUuid: String

    @Before
    fun setUp() {
        shell("settings put secure autofill_service $SERVICE")
        shell("cmd autofill set log_level verbose")
        shell("cmd autofill reset")
        shell("am force-stop $TEST_APP")
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
        entryUuid = app.vault.search(ENTRY_TITLE).single().uuid
    }

    @After
    fun tearDown() {
        app.vault.lock()
        shell("am force-stop $TEST_APP")
    }

    @Test
    fun nativeTwoStepLoginFillsTheOneTimeCode() {
        shell("am start -W -n $TEST_APP/.LoginActivity")
        val username = device.wait(Until.findObject(By.res(TEST_APP, "username")), 10_000)
        assertNotNull("test app login form did not appear", username)

        // Step 1: the login dataset fills username + password.
        assertTrue(
            "the login dataset did not fill the username",
            fillWithInlineChip(
                By.res(TEST_APP, "username"),
                chipShot = "otp-native-login-chip",
                datasetLabel = ENTRY_TITLE,
                relaunch = { shell("am start -W -n $TEST_APP/.LoginActivity") },
            ) {
                device.findObject(By.res(TEST_APP, "username"))?.text == USERNAME
            },
        )
        val password = device.findObject(By.res(TEST_APP, "password"))
        assertNotNull("password field disappeared", password)
        assertTrue(
            "the login dataset did not fill the password (text='${password!!.text}')",
            password.text.orEmpty().length == PASSWORD.length,
        )

        screenshot("otp-native-login-filled")

        // Step 2: sign in with the two-step user, which opens the native OTP page.
        click(By.res(TEST_APP, "sign_in"))
        assertNotNull(
            "the one-time-code page did not open after sign in",
            device.wait(Until.findObject(By.res(TEST_APP, "otp")), 10_000),
        )

        assertTrue(
            "the one-time-code chip did not fill the OTP field",
            fillWithInlineChip(
                By.res(TEST_APP, "otp"),
                chipShot = "otp-native-chip",
                datasetLabel = OTP_LABEL,
                relaunch = { shell("am start -W -n $TEST_APP/.OtpActivity") },
            ) {
                isSixDigitCode(device.findObject(By.res(TEST_APP, "otp"))?.text)
            },
        )
        val filled = device.findObject(By.res(TEST_APP, "otp"))?.text.orEmpty()
        assertRecentCode(filled, "native OTP field")
        screenshot("otp-native-filled")
    }

    @Test
    fun webOtpPageFillsTheSingleCodeField() {
        shell("am start -W -n $TEST_APP/.WebLoginActivity -e $PAGE_EXTRA otp")
        val input = device.wait(Until.findObject(By.res("otp")), 15_000)
        assertNotNull("the web one-time-code input did not appear", input)

        assertTrue(
            "the one-time-code chip did not fill the web input",
            fillWithInlineChip(
                By.res("otp"),
                chipShot = "otp-web-chip",
                datasetLabel = OTP_LABEL,
                relaunch = { shell("am start -W -n $TEST_APP/.WebLoginActivity -e $PAGE_EXTRA otp") },
            ) {
                isSixDigitCode(device.findObject(By.res("otp"))?.text)
            },
        )
        val filled = device.findObject(By.res("otp"))?.text.orEmpty()
        assertRecentCode(filled, "web OTP input")
        screenshot("otp-web-filled")
    }

    @Test
    fun webCombinedPageFillsUsernamePasswordAndOneTimeCode() {
        shell("am start -W -n $TEST_APP/.WebLoginActivity -e $PAGE_EXTRA otp-combined")
        val username = device.wait(Until.findObject(By.res("username")), 15_000)
        assertNotNull("the combined web login form did not appear", username)

        assertTrue(
            "the one-time-code dataset did not fill the combined form",
            fillWithInlineChip(
                By.res("username"),
                chipShot = "otp-combined-chip",
                datasetLabel = OTP_LABEL,
                relaunch = { shell("am start -W -n $TEST_APP/.WebLoginActivity -e $PAGE_EXTRA otp-combined") },
            ) {
                device.findObject(By.res("username"))?.text == USERNAME &&
                    isSixDigitCode(device.findObject(By.res("otp"))?.text)
            },
        )
        val password = device.findObject(By.res("password"))
        assertNotNull("the combined page has no password field", password)
        assertEquals(
            "the combined dataset must fill the password too",
            PASSWORD.length,
            password!!.text.orEmpty().length,
        )
        val code = device.findObject(By.res("otp"))?.text.orEmpty()
        assertRecentCode(code, "combined web form")
        screenshot("otp-combined-filled")
    }

    @Test
    fun webSegmentedOtpFillsOneDigitPerBox() {        shell("am start -W -n $TEST_APP/.WebLoginActivity -e $PAGE_EXTRA otp-split")
        val firstBox = device.wait(Until.findObject(By.res("otp-1")), 15_000)
        assertNotNull("the segmented one-time-code form did not appear", firstBox)

        assertTrue(
            "the one-time-code chip did not fill the segmented web form",
            fillWithInlineChip(
                By.res("otp-1"),
                chipShot = "otp-split-chip",
                datasetLabel = OTP_LABEL,
                relaunch = { shell("am start -W -n $TEST_APP/.WebLoginActivity -e $PAGE_EXTRA otp-split") },
            ) {
                (1..6).all { index ->
                    device.findObject(By.res("otp-$index"))?.text?.length == 1
                }
            },
        )
        val digits = (1..6).map { index ->
            device.findObject(By.res("otp-$index"))?.text.orEmpty()
        }
        assertEquals("each box must contain exactly one digit ($digits)", 6, digits.size)
        digits.forEach { digit ->
            assertTrue("box contained '$digit', not one digit", digit.length == 1 && digit[0].isDigit())
        }
        assertRecentCode(digits.joinToString(""), "segmented web form")
        screenshot("otp-split-filled")
    }

    @Test
    fun lockedVaultUnlocksThenFillsTheOtp() {
        app.vault.lock()
        assertTrue(app.vault.state.value is VaultState.Locked)
        shell("am start -W -n $TEST_APP/.OtpActivity")
        val input = device.wait(Until.findObject(By.res(TEST_APP, "otp")), 10_000)
        assertNotNull("the native OTP page did not appear", input)

        // Locked: the first chip is our authentication chip, not an OTP dataset.
        assertTrue("could not focus the OTP field", click(By.res(TEST_APP, "otp")))
        device.waitForIdle()
        Thread.sleep(1_500)
        screenshot("otp-locked-chip")
        assertTrue(
            "the unlock chip did not open friendlypass's unlock screen",
            openUnlockFromInlineChip(),
        )
        screenshot("otp-locked-unlock")
        val password = device.wait(Until.findObject(By.clazz("android.widget.EditText")), 10_000)
        assertNotNull("the unlock screen did not appear", password)
        password!!.click()
        shell("input text ${DebugVaultFile.PASSWORD}")
        assertTrue("could not press Unlock", click(By.text("Unlock")))
        Thread.sleep(1_000)
        screenshot("otp-locked-unlocking")

        val unlocked = waitUntil(15_000) { app.vault.state.value is VaultState.Unlocked }
        assertTrue("the vault was not unlocked from the autofill chip", unlocked)

        // The framework applies the response returned by the authentication activity; either way, a
        // fresh fill now offers the OTP dataset and fills the field.
        device.wait(Until.hasObject(By.res(TEST_APP, "otp")), 10_000)
        assertTrue(
            "the one-time-code chip did not fill the OTP field after unlocking",
            fillWithInlineChip(
                By.res(TEST_APP, "otp"),
                chipShot = "otp-unlocked-chip",
                datasetLabel = OTP_LABEL,
                relaunch = { shell("am start -W -n $TEST_APP/.OtpActivity") },
            ) {
                isSixDigitCode(device.findObject(By.res(TEST_APP, "otp"))?.text)
            },
        )
        val filled = device.findObject(By.res(TEST_APP, "otp"))?.text.orEmpty()
        assertRecentCode(filled, "locked-then-unlocked OTP field")
        screenshot("otp-unlocked-filled")
    }

    // ------------------------------------------------------------------ helpers

    /**
     * Fills through the first offered dataset. The framework's dropdown is used when it is in the
     * accessibility tree (it is right after an unlock); otherwise the first keyboard chip is tapped.
     * Retries once when nothing was filled.
     */
    private fun fillWithInlineChip(
        field: BySelector,
        chipShot: String? = null,
        datasetLabel: String? = null,
        relaunch: (() -> Unit)? = null,
        filled: () -> Boolean,
    ): Boolean {
        repeat(4) { attempt ->
            if (attempt > 0 && !device.hasObject(field)) {
                relaunch?.invoke()
                device.wait(Until.hasObject(field), 8_000)
            }
            // The dropdown may already be open (for example as the result of the unlock authentication).
            if (datasetLabel != null && clickDropdownItem(datasetLabel, filled)) return true
            if (click(field)) {
                device.waitForIdle()
                // Let the framework deliver a fresh FillResponse to the IME before tapping.
                Thread.sleep(1_500)
                if (attempt == 0) chipShot?.let { screenshot(it) }
                if (datasetLabel != null && clickDropdownItem(datasetLabel, filled)) return true
                tapFirstInlineChip()
                if (waitUntil(5_000, filled)) return true
            }
            // A Gboard toolbar panel or education bubble may have swallowed the tap. Only press Back
            // while the IME is visible: otherwise it would finish the page under test.
            dismissImeIfVisible()
        }
        return false
    }

    private fun dismissImeIfVisible() {
        val imeShown = shell("dumpsys input_method").contains("mInputShown=true")
        if (!imeShown) return
        device.pressBack()
        device.waitForIdle()
        Thread.sleep(400)
    }

    private fun clickDropdownItem(label: String, filled: () -> Boolean): Boolean {
        val item = device.findObject(By.textContains(label)) ?: return false
        item.click()
        return waitUntil(6_000, filled)
    }

    /**
     * Focuses the OTP field and taps the locked "Unlock friendlypass" chip until our authentication
     * activity is on screen.
     */
    private fun openUnlockFromInlineChip(): Boolean {
        repeat(3) {
            if (!device.hasObject(By.res(TEST_APP, "otp"))) {
                shell("am start -W -n $TEST_APP/.OtpActivity")
                device.wait(Until.hasObject(By.res(TEST_APP, "otp")), 6_000)
            }
            if (click(By.res(TEST_APP, "otp"))) {
                device.waitForIdle()
                Thread.sleep(1_500)
                tapFirstInlineChip()
                if (waitUntil(5_000) { device.hasObject(By.pkg(APP_PACKAGE)) }) return true
            }
            dismissImeIfVisible()
        }
        return false
    }

    /**
     * Taps the first inline chip. Chips live in the IME window (not in the accessibility tree); the IME
     * inset from `dumpsys window` gives the top of the keyboard, and the chip strip is right below it.
     */
    private fun tapFirstInlineChip() {
        val dump = shell("dumpsys window")
        val imeLine = dump.lineSequence().firstOrNull { it.contains("mType=ime") }
        val bottom = imeLine
            ?.let { Regex("bottom=(\\d+)").find(it)?.groupValues?.get(1)?.toIntOrNull() }
            ?: 883
        val x = device.displayWidth * 35 / 100
        val y = device.displayHeight - bottom + 40
        device.click(x, y)
        device.waitForIdle()
    }

    /** The code the vault generates for the entry now, one step either way. */
    private fun acceptableCodes(): Set<String> {
        val now = System.currentTimeMillis() / 1000
        return setOf(-30L, 0L, 30L).mapNotNull { offset ->
            app.vault.totp(entryUuid, now + offset)?.code
        }.toSet()
    }

    private fun assertRecentCode(code: String, where: String) {
        val expected = acceptableCodes()
        assertTrue(
            "$where contains '$code', which is not the vault's TOTP for this moment " +
                "(expected one of $expected)",
            code in expected,
        )
    }

    private fun isSixDigitCode(text: String?): Boolean =
        text != null && Regex("""\d{6}""").matches(text)

    private fun waitUntil(timeoutMs: Long, predicate: () -> Boolean): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (predicate()) return true
            Thread.sleep(150)
        }
        return predicate()
    }

    private fun click(selector: BySelector, timeoutMs: Long = 10_000): Boolean {
        val node: UiObject2 = device.wait(Until.findObject(selector), timeoutMs) ?: return false
        node.click()
        device.waitForIdle()
        return true
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
        private const val APP_PACKAGE = "org.friendlypass.android"
        private const val SERVICE = "org.friendlypass.android/.autofill.FriendlypassAutofillService"
        private const val PAGE_EXTRA = "org.friendlypass.testapp.PAGE"
        private const val ASSET = "otp-autofill.kdbx"
        private const val FIXTURE = "otp-autofill-test.kdbx"
        private const val ENTRY_TITLE = "OTP Account"
        private const val USERNAME = "otp-user"
        private const val PASSWORD = "otp-password"
        private const val OTP_LABEL = "· one-time code"
    }
}

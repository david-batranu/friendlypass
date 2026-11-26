package org.friendlypass.android.autofill

import android.os.ParcelFileDescriptor
import android.view.KeyEvent
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
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Clear-and-refill: after the user clears a field that an autofill chip filled, the chip must come
 * back and the next fill must be computed again (a one-time code must be the *current* step's code).
 *
 * Reproduction of the real-device bug: the chip fills once, and after clearing the field nothing is
 * offered until the page is reloaded. The dataset that [AutofillOtpActivity] returns replaces the
 * authenticated dataset in the framework's cached FillResponse for the session; the replacement must
 * carry the inline presentation and its own authentication again, or the cleared field shows no chip
 * (or fills a stale, literal code). These tests never relaunch the page between fill and refill: the
 * refill must come out of the framework's session cache, exactly like on the phone.
 */
@RunWith(AndroidJUnit4::class)
class AutofillRefillTest {

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
        AutofillRecents.clear()
    }

    @After
    fun tearDown() {
        app.vault.lock()
        shell("am force-stop $TEST_APP")
    }

    @Test
    fun nativeOtpChipComesBackAfterClearingAndFillsAFreshCode() {
        shell("am start -W -n $TEST_APP/.OtpActivity")
        val otp = By.res(TEST_APP, "otp")
        assertNotNull("the native one-time-code page did not appear", device.wait(Until.findObject(otp), 10_000))

        val first = fillOtpChip(otp)
        assertRecentCode(first, "native OTP field after the first fill")

        clearField(otp, "native")
        refocus(otp, "native")
        val second = refillOtpChip(otp)
        assertRecentCode(second, "native OTP field after clearing and refilling")
    }

    @Test
    fun webOtpChipComesBackAfterClearingAndFillsAFreshCode() {
        shell("am start -W -n $TEST_APP/.WebLoginActivity -e $PAGE_EXTRA otp")
        val otp = By.res("otp")
        assertNotNull("the web one-time-code input did not appear", device.wait(Until.findObject(otp), 15_000))

        val first = fillOtpChip(otp)
        assertRecentCode(first, "web OTP input after the first fill")

        clearField(otp, "web")
        refocus(otp, "web")
        val second = refillOtpChip(otp)
        assertRecentCode(second, "web OTP input after clearing and refilling")
    }

    /**
     * Step 4: the username dataset (a plain value dataset from the service response) must survive a
     * clear-and-refill too. No recomputation is expected here — filling the same username again is
     * correct — so this only asserts the chip returns and the field is filled again.
     */
    @Test
    fun webLoginUsernameRefillAfterClearing() {
        shell("am start -W -n $TEST_APP/.WebLoginActivity -e $PAGE_EXTRA login")
        val username = By.res("username")
        assertNotNull("the web login form did not appear", device.wait(Until.findObject(username), 15_000))

        assertTrue(
            "the entry dataset did not fill the username",
            fillWithChip(username) { device.findObject(username)?.text == USERNAME },
        )
        assertEquals(USERNAME, device.findObject(username)?.text)

        clearField(username, "login")
        refocus(username, "login")
        assertTrue(
            "the username chip did not come back after clearing (text='" +
                (device.findObject(username)?.text ?: "") + "')",
            fillWithChip(username) { device.findObject(username)?.text == USERNAME },
        )
    }

    // ------------------------------------------------------------------ helpers

    /** First fill of the OTP field through the keyboard chip. */
    private fun fillOtpChip(field: BySelector): String {
        val before = otpAuthRuns()
        val filled = fillWithChip(field) { isSixDigitCode(device.findObject(field)?.text) }
        assertTrue("the one-time-code chip did not fill the field", filled)
        assertTrue(
            "tapping the chip did not run the OTP authentication activity " +
                "(log lines before=$before after=${otpAuthRuns()})",
            otpAuthRuns() > before,
        )
        return device.findObject(field)?.text.orEmpty()
    }

    /** Refill after clearing: the chip must come back, and the code must be computed again. */
    private fun refillOtpChip(field: BySelector): String {
        val before = otpAuthRuns()
        val filled = fillWithChip(field) { isSixDigitCode(device.findObject(field)?.text) }
        val text = device.findObject(field)?.text.orEmpty()
        assertTrue(
            "after clearing the field, tapping the first keyboard chip did not fill it " +
                "(field text='$text', chip fill retries exhausted)",
            filled,
        )
        assertTrue(
            "the refill did not compute a fresh code: the OTP authentication activity ran " +
                "0 more times since the first fill (before=$before after=${otpAuthRuns()})",
            otpAuthRuns() > before,
        )
        return text
    }

    /**
     * Focuses [field], lets the framework deliver its cached suggestions to the keyboard, taps the
     * first inline chip and waits for [filled]. Retries the focus+tap up to 3 times but never
     * relaunches the page: the refill must come from the framework's session cache.
     */
    private fun fillWithChip(field: BySelector, filled: () -> Boolean): Boolean {
        repeat(3) {
            if (click(field)) {
                device.waitForIdle()
                Thread.sleep(1_500)
                tapFirstInlineChip()
                if (waitUntil(5_000, filled)) return true
            }
            dismissImeIfVisible()
            Thread.sleep(500)
        }
        return filled()
    }

    /** Selects the whole text and deletes it with the keyboard, like a user clearing the field. */
    private fun clearField(field: BySelector, tag: String) {
        val node = device.findObject(field)
        assertNotNull("field gone before clearing", node)
        node!!.click()
        device.waitForIdle()
        Thread.sleep(400)
        shell("input keyevent ${KeyEvent.KEYCODE_MOVE_END}")
        repeat(12) { device.pressKeyCode(KeyEvent.KEYCODE_DEL) }
        device.waitForIdle()
        // A cleared native EditText reports its hint through accessibility (e.g. "One-time code", 0 digits);
        // a cleared web input reports empty. Either way the six-digit code must be gone.
        assertTrue(
            "could not clear the field (text='${device.findObject(field)?.text ?: ""}')",
            waitUntil(4_000) { (device.findObject(field)?.text ?: "").count { it.isDigit() } < 6 },
        )
        screenshot("refill-$tag-cleared")
    }

    /** Hides the keyboard and taps the field again — the user looking for the chip a second time. */
    private fun refocus(field: BySelector, tag: String) {
        dismissImeIfVisible()
        Thread.sleep(800)
        assertTrue("could not re-focus the field", click(field))
        device.waitForIdle()
        Thread.sleep(1_500)
        screenshot("refill-$tag-refocused")
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

    private fun dismissImeIfVisible() {
        if (!shell("dumpsys input_method").contains("mInputShown=true")) return
        device.pressBack()
        device.waitForIdle()
        Thread.sleep(400)
    }

    /** Number of OTP authentication runs the service logged so far (freshness evidence). */
    private fun otpAuthRuns(): Int =
        Regex("otp activity: code generated=true")
            .findAll(shell("logcat -d -s FriendlypassAutofill:D"))
            .count()

    private fun assertRecentCode(code: String, where: String) {
        val now = System.currentTimeMillis() / 1000
        val expected = setOf(-30L, 0L, 30L).mapNotNull { offset ->
            app.vault.totp(entryUuid, now + offset)?.code
        }.toSet()
        assertTrue(
            "$where contains '$code', which is not the vault's TOTP for this moment (expected one of $expected)",
            code in expected,
        )
    }

    private fun isSixDigitCode(text: String?): Boolean = text != null && Regex("""\d{6}""").matches(text)

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
        private const val SERVICE = "org.friendlypass.android/.autofill.FriendlypassAutofillService"
        private const val PAGE_EXTRA = "org.friendlypass.testapp.PAGE"
        private const val ASSET = "otp-autofill.kdbx"
        private const val FIXTURE = "otp-autofill-refill-test.kdbx"
        private const val ENTRY_TITLE = "OTP Account"
        private const val USERNAME = "otp-user"
    }
}

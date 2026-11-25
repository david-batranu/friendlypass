package org.friendlypass.android.credentials

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
import org.friendlypass.android.vault.model.NewLogin
import org.friendlypass.android.vault.model.VaultState
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.friendlypass_mobile.openVault

/**
 * End-to-end Credential Manager tests on a real KDBX fixture copied into debug app storage.
 *
 * `:credtest` is the calling app, the GMS credential chooser is the system sheet, and every assertion about the
 * saved database re-opens the bytes with the Rust vault instead of trusting the Kotlin repository.
 */
@RunWith(AndroidJUnit4::class)
class CredentialsFlowTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val device: UiDevice = UiDevice.getInstance(instrumentation)
    private val context get() = instrumentation.targetContext
    private val app: FriendlypassApp get() = context.applicationContext as FriendlypassApp

    private var previousService: String? = null
    private var previousPrimary: String? = null

    @Before
    fun setUp() {
        previousService = secureSetting(CREDENTIAL_SERVICE)
        previousPrimary = secureSetting(CREDENTIAL_SERVICE_PRIMARY)
        shell("settings put secure $CREDENTIAL_SERVICE $PROVIDER_COMPONENT")
        shell("settings put secure $CREDENTIAL_SERVICE_PRIMARY $PROVIDER_COMPONENT")
        shell("am force-stop $CREDTEST")

        val ref = DebugVaultFile.install(context, fixture(), FIXTURE)
        runBlocking {
            app.store.remember(ref)
            app.vault.selectDatabase(ref)
            app.vault.unlock(DebugVaultFile.PASSWORD.toCharArray(), null)
        }
    }

    @After
    fun tearDown() {
        app.vault.lock()
        restore(CREDENTIAL_SERVICE, previousService)
        restore(CREDENTIAL_SERVICE_PRIMARY, previousPrimary)
        shell("am force-stop $CREDTEST")
    }

    @Test
    fun savePasswordAndCreateThenUsePasskeyPersistInTheKdbx() {
        launchCredtest()

        // ---------------------------------------------------------------- password save
        click(By.text("SAVE PASSWORD"))
        assertNotNull(
            "the system sheet did not ask to save the password",
            device.wait(Until.findObject(By.textContains("Save password to sign in")), 15_000),
        )
        click(By.text("Continue"))
        // The status line sits under the system status bar and can be pruned from the accessibility tree;
        // the result body is the reliable, visible proof that credtest got the response.
        assertTrue(
            "credtest did not report a successful password save",
            waitForUiText("password saved"),
        )

        val afterPassword = reopen()
        try {
            val saved = afterPassword.allEntries().filter { it.title == "org.friendlypass.credtest" }
            assertEquals("saved password entry must exist in the KDBX", 1, saved.size)
            val detail = afterPassword.entry(saved.single().uuid)
            assertEquals("credtest-user", detail.summary.username)
            assertTrue(
                "the saved password was not the one credtest sent",
                detail.password.startsWith("credtest-password-"),
            )
        } finally {
            afterPassword.destroy()
        }

        // ---------------------------------------------------------------- passkey create
        click(By.text("CREATE PASSKEY"))
        assertNotNull(
            "the system sheet did not ask to create a passkey",
            device.wait(Until.findObject(By.textContains("Create passkey to sign in")), 15_000),
        )
        // The chooser may prefer another provider; pick friendlypass explicitly when it offers a choice.
        if (device.wait(Until.hasObject(By.text("Save another way")), 3_000)) {
            click(By.text("Save another way"))
            assertNotNull(
                "the provider picker did not list friendlypass",
                device.wait(Until.findObject(By.text("friendlypass")), 10_000),
            )
            click(By.text("friendlypass"))
            device.waitForIdle()
        }
        screenshot("w3-passkey-create-sheet")
        click(By.text("Continue"))
        assertTrue(
            "credtest did not report a successful passkey registration",
            waitForUiText("\"publicKey\"", timeoutMs = 30_000),
        )

        val afterPasskey = reopen()
        try {
            val passkeyEntries = afterPasskey.allEntries().filter { it.hasPasskey }
            assertEquals("exactly one passkey entry must be stored", 1, passkeyEntries.size)
            val detail = afterPasskey.entry(passkeyEntries.single().uuid)
            assertEquals("credtest.friendlypass.test", detail.summary.title)
            val fields = detail.customFields.associate { it.name to it.value }
            for (name in PASSKEY_FIELDS) {
                assertTrue("stored KDBX is missing $name", fields.containsKey(name))
            }
            assertEquals("credtest.friendlypass.test", fields["KPEX_PASSKEY_RELYING_PARTY"])
            assertEquals("1", fields["KPEX_PASSKEY_FLAG_BE"])
            assertEquals("1", fields["KPEX_PASSKEY_FLAG_BS"])
        } finally {
            afterPasskey.destroy()
        }

        // ---------------------------------------------------------------- passkey sign-in
        click(By.text("SIGN IN WITH PASSKEY"))
        assertNotNull(
            "the system sheet did not offer the stored passkey",
            device.wait(Until.findObject(By.text("credtest.friendlypass.test")), 15_000),
        )
        screenshot("w3-passkey-signin-sheet")
        click(By.text("credtest.friendlypass.test"))
        if (device.wait(Until.hasObject(By.text("Continue")), 2_000)) {
            click(By.text("Continue"))
        }
        assertTrue(
            "credtest could not verify the ES256 assertion",
            waitForUiText("signature: VALID (SHA256withECDSA)", timeoutMs = 30_000),
        )
        screenshot("w3-credtest-verified")
    }

    @Test
    fun lockedSheetShowsUnlockAndUnlockingContinuesTheFlow() {
        runBlocking {
            app.vault.addLogin(
                NewLogin(
                    title = "Credtest Login",
                    username = "credtest-user",
                    password = "credtest-secret",
                    url = null,
                    androidApp = CREDTEST,
                ),
            )
        }
        app.vault.lock()
        assertTrue(app.vault.state.value is VaultState.Locked)

        launchCredtest()
        click(By.text("GET PASSWORD"))

        val unlockAction = device.wait(Until.findObject(By.textContains("Unlock friendlypass")), 15_000)
        assertNotNull("locked system sheet did not show 'Unlock friendlypass'", unlockAction)
        screenshot("w3-locked-sheet")
        unlockAction!!.click()
        device.waitForIdle()

        val passwordField = device.wait(Until.findObject(By.clazz("android.widget.EditText")), 15_000)
        assertNotNull("the friendlypass unlock screen did not appear", passwordField)
        passwordField!!.click()
        shell("input text ${DebugVaultFile.PASSWORD}")
        click(By.text("Unlock"))

        assertNotNull(
            "the unlocked sheet did not list the real vault's entry",
            device.wait(Until.findObject(By.text("Credtest Login")), 20_000),
        )
        click(By.text("Credtest Login"))
        assertTrue(
            "credtest did not receive the password after unlocking",
            waitForUiText("password=credtest-secret"),
        )
    }

    // ------------------------------------------------------------------ helpers

    private fun fixture(): ByteArray =
        instrumentation.context.assets.open(ASSET).use { it.readBytes() }

    private fun reopen() = openVault(DebugVaultFile.read(context, FIXTURE)!!, DebugVaultFile.PASSWORD, null)

    private fun launchCredtest() {
        shell("am start -W -n $CREDTEST/.MainActivity")
        assertNotNull(
            "credtest did not start",
            device.wait(Until.findObject(By.text("GET PASSWORD")), 10_000),
        )
    }

    private fun click(selector: BySelector) {
        val node = device.wait(Until.findObject(selector), 10_000)
        assertNotNull("could not find $selector", node)
        node!!.click()
        device.waitForIdle()
    }

    private fun secureSetting(name: String): String? =
        shell("settings get secure $name").trim().takeUnless { it.isEmpty() || it == "null" }

    private fun restore(name: String, value: String?) {
        if (value == null) {
            shell("settings delete secure $name")
        } else {
            shell("settings put secure $name $value")
        }
    }

    private fun screenshot(name: String) {
        shell("screencap -p /sdcard/$name.png")
    }

    /**
     * Polls a fresh window hierarchy for [text]. `UiDevice.wait` can keep seeing the credential chooser's
     * window after it has closed, while a fresh dump always describes what is on screen; used for the result
     * text credtest shows after a system-sheet round trip.
     */
    private fun waitForUiText(text: String, timeoutMs: Long = 15_000): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            val hierarchy = runCatching {
                val out = java.io.ByteArrayOutputStream()
                device.dumpWindowHierarchy(out)
                out.toString(Charsets.UTF_8.name())
            }.getOrDefault("")
            if (hierarchy.contains(text)) return true
            Thread.sleep(400)
        }
        return false
    }

    private fun shell(command: String): String =
        instrumentation.uiAutomation.executeShellCommand(command).use { pfd ->
            ParcelFileDescriptor.AutoCloseInputStream(pfd).bufferedReader().readText()
        }

    companion object {
        private const val CREDTEST = "org.friendlypass.credtest"
        private const val ASSET = "sample4.kdbx"
        private const val FIXTURE = "sample4-credentials.kdbx"
        private const val PROVIDER_COMPONENT =
            "org.friendlypass.android/.credentials.FriendlypassCredentialProviderService"
        private const val CREDENTIAL_SERVICE = "credential_service"
        private const val CREDENTIAL_SERVICE_PRIMARY = "credential_service_primary"

        private val PASSKEY_FIELDS = listOf(
            "KPEX_PASSKEY_USERNAME",
            "KPEX_PASSKEY_CREDENTIAL_ID",
            "KPEX_PASSKEY_PRIVATE_KEY_PEM",
            "KPEX_PASSKEY_RELYING_PARTY",
            "KPEX_PASSKEY_USER_HANDLE",
            "KPEX_PASSKEY_FLAG_BE",
            "KPEX_PASSKEY_FLAG_BS",
        )
    }
}

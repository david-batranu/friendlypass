package org.friendlypass.android

import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.friendlypass.android.vault.FakeVaultRepository
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * End-to-end smoke test for the skeleton: unlock the built-in sample database with "test", browse to the
 * Fastmail entry and check that a live TOTP code is rendered.
 */
@RunWith(AndroidJUnit4::class)
class UnlockAndBrowseTest {

    @get:Rule
    val composeRule = createAndroidComposeRule<MainActivity>()

    @Test
    fun unlockBrowseAndShowTotp() {
        // The app starts on the database picker (no database selected yet).
        composeRule.onNodeWithTag("open-database").assertExists()

        composeRule.activityRule.scenario.onActivity { activity ->
            (activity.application as FriendlypassApp)
                .vault
                .selectDatabase(FakeVaultRepository.DEMO_DATABASE)
        }

        composeRule.waitUntil(timeoutMillis = 5_000) {
            composeRule.onAllNodesWithTag("password").fetchSemanticsNodes().isNotEmpty()
        }

        composeRule.onNodeWithTag("password").performTextInput("test")
        composeRule.onNodeWithTag("unlock").performClick()

        composeRule.waitUntil(timeoutMillis = 10_000) {
            composeRule.onAllNodesWithTag("search").fetchSemanticsNodes().isNotEmpty()
        }

        composeRule.onNodeWithTag("search").performTextInput("fastmail")
        composeRule.onNodeWithTag("entry-f1a2b3c4d5e60718293a4b5c6d7e8f01").performClick()

        composeRule.waitUntil(timeoutMillis = 5_000) {
            composeRule.onAllNodesWithTag("totp-code").fetchSemanticsNodes().isNotEmpty()
        }

        val code = composeRule.onNodeWithTag("totp-code")
            .fetchSemanticsNode()
            .config[SemanticsProperties.Text]
            .joinToString(separator = "") { it.text }
        assertTrue("expected a 6-digit TOTP code, got '$code'", Regex("""\d{6}""").matches(code))
    }
}

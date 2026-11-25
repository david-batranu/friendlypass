package org.friendlypass.android.autofill

import android.text.InputType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Parser tests use the Android-free [AutofillNode] model (no `ViewStructure` required), covering native
 * forms, web forms, email-as-username, password-only forms and forms without credential fields.
 */
class AutofillParserTest {

    private fun textNode(
        index: Int,
        resourceId: String? = null,
        hint: String? = null,
        inputType: Int = InputType.TYPE_CLASS_TEXT,
        autofillHints: List<String>? = null,
        html: HtmlAttributes? = null,
        webDomain: String? = null,
        webScheme: String? = null,
    ) = AutofillNode(
        index = index,
        className = "android.widget.EditText",
        resourceId = resourceId,
        hint = hint,
        inputType = inputType,
        autofillHints = autofillHints,
        htmlInfo = html,
        webDomain = webDomain,
        webScheme = webScheme,
    )

    @Test
    fun nativeFormClassifiesUsernameAndPasswordHints() {
        val form = AutofillParser.parse(
            AutofillNode(
                index = 0,
                children = listOf(
                    textNode(1, resourceId = "com.example.app:id/username", autofillHints = listOf("username")),
                    textNode(2, resourceId = "com.example.app:id/password", inputType = InputType.TYPE_TEXT_VARIATION_PASSWORD),
                ),
            ),
        )

        assertEquals(listOf(1), form.usernameFieldIndices)
        assertEquals(listOf(2), form.passwordFieldIndices)
        assertTrue(form.hasCredentials)
        assertTrue(form.hasPassword)
    }

    @Test
    fun passwordInputTypeWinsOverLoginLikeName() {
        val form = AutofillParser.parse(
            textNode(
                1,
                resourceId = "com.example.app:id/loginPassword",
                hint = "Login",
                inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD,
            ),
        )

        assertEquals(listOf(1), form.passwordFieldIndices)
        assertTrue(form.usernameFieldIndices.isEmpty())
    }

    @Test
    fun emailInputTypeIsClassifiedAsUsername() {
        val form = AutofillParser.parse(
            textNode(
                1,
                resourceId = "com.example.app:id/field1",
                inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS,
            ),
        )

        assertEquals(listOf(1), form.usernameFieldIndices)
        assertTrue(form.passwordFieldIndices.isEmpty())
    }

    @Test
    fun resourceIdAndHintHeuristicsFindFields() {
        val form = AutofillParser.parse(
            AutofillNode(
                index = 0,
                children = listOf(
                    textNode(1, resourceId = "com.example.app:id/user_name_input"),
                    textNode(2, hint = "Enter your pass phrase"),
                ),
            ),
        )

        assertEquals(listOf(1), form.usernameFieldIndices)
        assertEquals(listOf(2), form.passwordFieldIndices)
    }

    @Test
    fun passwordOnlyFormIsStillUseful() {
        val form = AutofillParser.parse(
            textNode(7, hint = "Password", inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD),
        )

        assertTrue(form.usernameFieldIndices.isEmpty())
        assertEquals(listOf(7), form.passwordFieldIndices)
        assertTrue(form.hasCredentials)
    }

    @Test
    fun formWithoutEditableCredentialFieldsIsEmpty() {
        val form = AutofillParser.parse(
            AutofillNode(
                index = 0,
                className = "android.widget.LinearLayout",
                children = listOf(
                    AutofillNode(index = 1, className = "android.widget.TextView", hint = "Email address"),
                    AutofillNode(index = 2, className = "android.widget.Button", hint = "Password"),
                ),
            ),
        )

        assertFalse(form.hasCredentials)
        assertNull(form.webDomain)
    }

    @Test
    fun webFormUsesHtmlAttributesAndWebOrigin() {
        val form = AutofillParser.parse(
            AutofillNode(
                index = 0,
                children = listOf(
                    textNode(
                        1,
                        html = HtmlAttributes(
                            tag = "input",
                            type = "text",
                            name = "user",
                            id = "login-user",
                            autocomplete = "username",
                        ),
                        webDomain = "appassets.androidplatform.net",
                        webScheme = "https",
                    ),
                    textNode(
                        2,
                        html = HtmlAttributes(
                            tag = "input",
                            type = "password",
                            name = "secret",
                            id = "login-pass",
                            autocomplete = "current-password",
                        ),
                        webDomain = "appassets.androidplatform.net",
                        webScheme = "https",
                    ),
                ),
            ),
        )

        assertEquals(listOf(1), form.usernameFieldIndices)
        assertEquals(listOf(2), form.passwordFieldIndices)
        assertEquals("appassets.androidplatform.net", form.webDomain)
        assertEquals("https", form.webScheme)
        assertTrue(form.hasHtmlFields)
    }

    @Test
    fun webTargetIsResolvedForKnownBrowser() {
        val form = ParsedForm(webDomain = "example.com", webScheme = "https", hasHtmlFields = false)

        val target = AutofillTargets.resolve(form, "com.android.chrome")

        assertEquals(AutofillTarget.Web("https://example.com", "example.com"), target)
    }

    @Test
    fun webTargetIsResolvedForWebViewInOtherApps() {
        val form = ParsedForm(webDomain = "appassets.androidplatform.net", webScheme = "https", hasHtmlFields = true)

        val target = AutofillTargets.resolve(form, "org.friendlypass.testapp")

        assertEquals(
            AutofillTarget.Web("https://appassets.androidplatform.net", "appassets.androidplatform.net"),
            target,
        )
    }

    @Test
    fun webOriginFromUnverifiedAppIsIgnored() {
        val form = ParsedForm(webDomain = "example.com", hasHtmlFields = false)

        assertNull(AutofillTargets.resolve(form, "com.example.notabrowser"))
    }

    @Test
    fun nativeAppTargetIsTheCallingPackage() {
        val form = ParsedForm(usernameFieldIndices = listOf(1), passwordFieldIndices = listOf(2))

        assertEquals(AutofillTarget.App("com.example.app"), AutofillTargets.resolve(form, "com.example.app"))
    }

    @Test
    fun ownPackageIsIgnored() {
        val form = ParsedForm(usernameFieldIndices = listOf(1), passwordFieldIndices = listOf(2))

        assertNull(AutofillTargets.resolve(form, "org.friendlypass.android"))
        assertNull(AutofillTargets.resolve(form, "org.friendlypass.android", ownPackage = "org.friendlypass.android"))
    }
}

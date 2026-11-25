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
        maxLength: Int = -1,
    ) = AutofillNode(
        index = index,
        className = "android.widget.EditText",
        resourceId = resourceId,
        hint = hint,
        inputType = inputType,
        maxLength = maxLength,
        autofillHints = autofillHints,
        htmlInfo = html,
        webDomain = webDomain,
        webScheme = webScheme,
    )

    /** A WebView `<input>` with the attributes Android exposes through `HtmlInfo`. */
    private fun htmlNode(
        index: Int,
        type: String? = "text",
        id: String? = null,
        name: String? = null,
        autocomplete: String? = null,
        placeholder: String? = null,
        maxLength: Int? = null,
        extra: Map<String, String> = emptyMap(),
    ): AutofillNode {
        val attributes = buildMap {
            type?.let { put("type", it) }
            id?.let { put("id", it) }
            name?.let { put("name", it) }
            autocomplete?.let { put("autocomplete", it) }
            placeholder?.let { put("placeholder", it) }
            maxLength?.let { put("maxlength", it.toString()) }
            putAll(extra)
        }
        return textNode(
            index,
            inputType = 0,
            html = HtmlAttributes(
                tag = "input",
                type = type,
                id = id,
                name = name,
                autocomplete = autocomplete,
                attributes = attributes,
            ),
            webDomain = "appassets.androidplatform.net",
            webScheme = "https",
            maxLength = maxLength ?: -1,
        )
    }

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

    // ------------------------------------------------------------------ one-time codes (TOTP)

    @Test
    fun oneTimeCodeAutocompleteIsOtp() {
        val form = AutofillParser.parse(
            htmlNode(1, type = "text", name = "field-7", autocomplete = "one-time-code", maxLength = 6),
        )

        assertEquals(listOf(1), form.otpFieldIndices)
        assertEquals(listOf(listOf(1)), form.otpGroups)
        assertTrue(form.hasOtp)
        assertTrue(form.hasCredentials)
    }

    @Test
    fun oneTimeCodeAutocompleteWinsOverPasswordType() {
        val form = AutofillParser.parse(
            htmlNode(1, type = "password", name = "secret", autocomplete = "one-time-code"),
        )

        assertEquals(listOf(1), form.otpFieldIndices)
        assertTrue(form.passwordFieldIndices.isEmpty())
    }

    @Test
    fun passwordTypeWithOtpNameIsAnOtpField() {
        val form = AutofillParser.parse(
            htmlNode(1, type = "password", name = "otp", id = "otp-input", maxLength = 6),
        )

        assertEquals(listOf(1), form.otpFieldIndices)
        assertTrue(form.passwordFieldIndices.isEmpty())
    }

    @Test
    fun otpWordsAreFoundInIdNamePlaceholderAndHint() {
        val form = AutofillParser.parse(
            AutofillNode(
                index = 0,
                children = listOf(
                    htmlNode(1, id = "otp-input"),
                    htmlNode(2, name = "verification_code"),
                    htmlNode(3, placeholder = "Enter token"),
                    textNode(4, hint = "Two-factor code"),
                ),
            ),
        )

        assertEquals(listOf(1, 2, 3, 4), form.otpFieldIndices)
    }

    @Test
    fun androidOtpAutofillHintsAreRecognized() {
        for (hint in listOf("smsOTPCode", "2faAppOTPCode", "emailOTPCode", "otpCode", "one-time-code")) {
            val form = AutofillParser.parse(textNode(1, autofillHints = listOf(hint)))

            assertEquals("$hint must be an OTP hint", listOf(1), form.otpFieldIndices)
        }
    }

    @Test
    fun nativeResourceIdAndHintWordsAreOtp() {
        val form = AutofillParser.parse(
            AutofillNode(
                index = 0,
                children = listOf(
                    textNode(1, resourceId = "com.example.app:id/otp_field"),
                    textNode(2, hint = "One-time code"),
                    textNode(3, resourceId = "com.example.app:id/verification_code", inputType = InputType.TYPE_CLASS_NUMBER),
                ),
            ),
        )

        assertEquals(listOf(1, 2, 3), form.otpFieldIndices)
    }

    @Test
    fun falsePositiveCodeFieldsAreNotOtp() {
        val form = AutofillParser.parse(
            AutofillNode(
                index = 0,
                children = listOf(
                    htmlNode(1, name = "postcode"),
                    htmlNode(2, name = "coupon_code"),
                    htmlNode(3, name = "promo code"),
                    htmlNode(4, name = "zip_code"),
                    htmlNode(5, name = "author"),
                    htmlNode(6, name = "comment"),
                    htmlNode(7, name = "error_code"),
                ),
            ),
        )

        assertTrue("false positives: ${form.otpFieldIndices}", form.otpFieldIndices.isEmpty())
        assertFalse(form.hasCredentials)
    }

    @Test
    fun emailAndUsernameFieldsAreNeverOtp() {
        val form = AutofillParser.parse(
            AutofillNode(
                index = 0,
                children = listOf(
                    htmlNode(1, type = "email", name = "otp"),
                    htmlNode(2, name = "email_otp"),
                    htmlNode(3, name = "username_otp"),
                ),
            ),
        )

        assertTrue(form.otpFieldIndices.isEmpty())
        assertEquals(listOf(1, 2, 3), form.usernameFieldIndices)
    }

    @Test
    fun onlyNumberPasswordTelAndTextInputTypesAreOtp() {
        for (type in listOf("number", "password", "tel", "text")) {
            val form = AutofillParser.parse(htmlNode(1, type = type, name = "otp", maxLength = 6))

            assertEquals("type=$type must be OTP", listOf(1), form.otpFieldIndices)
        }
        val checkbox = AutofillParser.parse(htmlNode(1, type = "checkbox", name = "otp"))

        assertTrue(checkbox.otpFieldIndices.isEmpty())
    }

    @Test
    fun maxLengthOutsideSixToTenIsNotAStandaloneOtp() {
        for (length in listOf(5, 11, 12, 2)) {
            val form = AutofillParser.parse(htmlNode(1, name = "otp", maxLength = length))

            assertTrue("maxlength=$length must be rejected", form.otpFieldIndices.isEmpty())
        }
        for (length in listOf(6, 8, 10)) {
            val form = AutofillParser.parse(htmlNode(1, name = "otp", maxLength = length))

            assertEquals("maxlength=$length must be accepted", listOf(1), form.otpFieldIndices)
        }
    }

    @Test
    fun readonlyAndTinyOtpInputsAreRejected() {
        val readonly = AutofillParser.parse(
            htmlNode(1, name = "otp", maxLength = 6, extra = mapOf("readonly" to "")),
        )
        val tiny = AutofillParser.parse(
            htmlNode(1, name = "otp", maxLength = 6, extra = mapOf("size" to "1")),
        )
        val emailMode = AutofillParser.parse(
            htmlNode(1, name = "otp", maxLength = 6, extra = mapOf("inputmode" to "email")),
        )

        assertTrue(readonly.otpFieldIndices.isEmpty())
        assertTrue(tiny.otpFieldIndices.isEmpty())
        assertTrue(emailMode.otpFieldIndices.isEmpty())
    }

    @Test
    fun sixSingleCharacterBoxesAreOneSegmentedGroup() {
        val form = AutofillParser.parse(
            AutofillNode(
                index = 0,
                children = (1..6).map { htmlNode(it, name = "otp-$it", maxLength = 1) },
            ),
        )

        assertEquals(listOf(1, 2, 3, 4, 5, 6), form.otpFieldIndices)
        assertEquals(listOf(listOf(1, 2, 3, 4, 5, 6)), form.otpGroups)
    }

    @Test
    fun segmentedGroupSurvivesMissingMaxLengthFromTheWebView() {
        val form = AutofillParser.parse(
            AutofillNode(
                index = 0,
                children = (1..6).map { htmlNode(it, name = "otp-$it") },
            ),
        )

        assertEquals(listOf(listOf(1, 2, 3, 4, 5, 6)), form.otpGroups)
    }

    @Test
    fun fourAndEightSingleCharacterBoxesAreGroupsButThreeAndNineAreNot() {
        val four = AutofillParser.parse(
            AutofillNode(index = 0, children = (1..4).map { htmlNode(it, name = "code-$it", maxLength = 1) }),
        )
        val eight = AutofillParser.parse(
            AutofillNode(index = 0, children = (1..8).map { htmlNode(it, name = "code-$it", maxLength = 1) }),
        )
        val three = AutofillParser.parse(
            AutofillNode(index = 0, children = (1..3).map { htmlNode(it, name = "code-$it", maxLength = 1) }),
        )
        val nine = AutofillParser.parse(
            AutofillNode(index = 0, children = (1..9).map { htmlNode(it, name = "code-$it", maxLength = 1) }),
        )

        assertEquals(1, four.otpGroups.size)
        assertEquals(1, eight.otpGroups.size)
        assertTrue(three.otpGroups.isEmpty())
        assertTrue(nine.otpGroups.isEmpty())
    }

    @Test
    fun combinedPageHasUsernamePasswordAndOtpTogether() {
        val form = AutofillParser.parse(
            AutofillNode(
                index = 0,
                children = listOf(
                    htmlNode(1, name = "username", autocomplete = "username"),
                    htmlNode(2, type = "password", name = "password", autocomplete = "current-password"),
                    htmlNode(3, name = "otp", autocomplete = "one-time-code"),
                ),
            ),
        )

        assertEquals(listOf(1), form.usernameFieldIndices)
        assertEquals(listOf(2), form.passwordFieldIndices)
        assertEquals(listOf(3), form.otpFieldIndices)
        assertEquals(listOf(listOf(3)), form.otpGroups)
    }

    @Test
    fun aRealPasswordFieldIsStillAPassword() {
        val form = AutofillParser.parse(
            htmlNode(1, type = "password", name = "password", id = "password", autocomplete = "current-password"),
        )

        assertEquals(listOf(1), form.passwordFieldIndices)
        assertTrue(form.otpFieldIndices.isEmpty())
    }
}

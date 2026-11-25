package org.friendlypass.android.autofill

import android.text.InputType

/**
 * Pure heuristics that turn a view tree into username/password/one-time-code fields.
 *
 * Precedence, strongest first:
 * 1. `autofillHints` (`username`, `emailAddress`, `password`, `smsOTPCode`, `2faAppOTPCode`, …),
 * 2. `HtmlInfo` attributes from a `WebView` (`type`, `name`, `id`, `placeholder`, `autocomplete`,
 *    `maxlength`), using the extension's TOTP rules (`extension/src/content/totp-field.ts`),
 * 3. `inputType` variations (password, email),
 * 4. resource id / hint text heuristics ("user", "email", "login", "pass", "otp", "code", …).
 *
 * One-time-code fields intentionally win over passwords for `type=password name=otp` style inputs, as the
 * browser extension does. A run of 4–8 consecutive single-character OTP-ish inputs is treated as one
 * segmented code and filled one digit per box.
 *
 * A node is only considered when it looks editable (has an input type, autofill hints, or is an HTML
 * `<input>`), so buttons, labels and containers are skipped.
 */
object AutofillParser {

    private val PASSWORD_VARIATIONS = setOf(
        InputType.TYPE_TEXT_VARIATION_PASSWORD,
        InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD,
        InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD,
        InputType.TYPE_NUMBER_VARIATION_PASSWORD,
    )

    private val EMAIL_VARIATIONS = setOf(
        InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS,
        InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS,
    )

    private val PASSWORD_WORDS = listOf("password", "passwd", "passcode", "pwd", "pass")
    private val USERNAME_WORDS = listOf("username", "user", "email", "login", "logon", "account", "identifier", "handle")

    // ------------------------------------------------------------------ one-time codes (extension port)

    /** Words that make an input look like a one-time-code entry (`ACCEPTED_OTP_FIELDS`). */
    internal val ACCEPTED_OTP_FIELDS = listOf(
        "2fa",
        "2fpin",
        "auth",
        "challenge",
        "code",
        "idvpin",
        "mfa",
        "one_time_password",
        "one-time password",
        "otc-confirmation-input",
        "otp",
        "otppw",
        "token",
        "twofa",
        "two-factor",
        "twofactor",
        "verification_pin",
        "mfacode",
    )

    /** False positives: coupon/postcode/encoding fields that contain "code" (the extension's regex). */
    internal val OTP_IGNORE_REGEX =
        Regex("(bank|bar|coupon|post(al)?|user|zip|promo).*code|(en|de)code(d|r)*|comment|author|error", RegexOption.IGNORE_CASE)

    private val OTP_IGNORED_TYPES = listOf("email", "username")
    private val OTP_ALLOWED_INPUT_TYPES = listOf("number", "password", "tel", "text")

    /** Android/AndroidX one-time-code autofill hints, plus the generic HTML hint. */
    private val OTP_HINTS = setOf(
        "smsotpcode",
        "2faappotpcode",
        "emailotpcode",
        "otpcode",
        "one-time-code",
        "onetimecode",
    )

    internal const val MIN_OTP_LENGTH = 6
    internal const val MAX_OTP_LENGTH = 10
    internal const val MIN_SEGMENTED_FIELDS = 4
    internal const val MAX_SEGMENTED_FIELDS = 8

    fun parse(root: AutofillNode): ParsedForm {
        val nodes = root.depthFirst().toList()
        val usernameFields = mutableListOf<Int>()
        val passwordFields = mutableListOf<Int>()
        var webDomain: String? = null
        var webScheme: String? = null
        var hasHtmlFields = false

        nodes.forEach { node ->
            if (webDomain == null) {
                node.webDomain?.trim()?.takeIf { it.isNotEmpty() }?.let { webDomain = it }
            }
            if (webScheme == null) {
                node.webScheme?.trim()?.takeIf { it.isNotEmpty() }?.let { webScheme = it }
            }
            if (node.htmlInfo != null && looksEditable(node)) hasHtmlFields = true
        }

        // Segmented codes are detected first so their single-character boxes are not also offered as
        // independent OTP datasets.
        val segmented = segmentedGroups(nodes)
        val segmentedIndices = segmented.flatten().toSet()
        val otpGroups = mutableListOf<List<Int>>()
        val seenGroups = mutableSetOf<Int>()
        nodes.forEach { node ->
            val group = segmented.firstOrNull { it.firstOrNull() == node.index }
            if (group != null) {
                if (seenGroups.add(node.index)) otpGroups += group
                return@forEach
            }
            if (node.index in segmentedIndices) return@forEach
            when (val role = classify(node)) {
                FieldRole.PASSWORD -> if (node.index !in passwordFields) passwordFields += node.index
                FieldRole.USERNAME -> if (node.index !in usernameFields) usernameFields += node.index
                FieldRole.OTP -> otpGroups += listOf(node.index)
                null -> Unit
            }
        }

        return ParsedForm(
            usernameFieldIndices = usernameFields,
            passwordFieldIndices = passwordFields,
            otpFieldIndices = otpGroups.flatten(),
            otpGroups = otpGroups,
            webDomain = webDomain,
            webScheme = webScheme,
            hasHtmlFields = hasHtmlFields,
        )
    }

    /** Returns the role of [node], or null when it is not a credential field. */
    fun classify(node: AutofillNode): FieldRole? {
        if (!node.isEnabled) return null
        if (!looksEditable(node)) return null

        // One-time codes beat every other role, including `type=password name=otp`.
        if (isOtpField(node)) return FieldRole.OTP

        // 1. Explicit autofill hints from the platform.
        val hints = node.autofillHints.orEmpty().map { it.lowercase() }
        if (hints.any { it == "password" || it == "newpassword" || it == "currentpassword" || it.contains("password") }) {
            return FieldRole.PASSWORD
        }
        if (hints.any { it == "username" || it == "emailaddress" || it == "email" || it == "login" || it == "account" }) {
            return FieldRole.USERNAME
        }

        // 2. HTML attributes from a WebView.
        val html = node.htmlInfo
        if (html != null) {
            val type = html.type?.lowercase().orEmpty()
            val autocomplete = html.autocomplete?.lowercase().orEmpty()
            val names = listOfNotNull(html.name, html.id).joinToString(" ").lowercase()
            if (type == "password" || autocomplete.contains("password")) return FieldRole.PASSWORD
            if (type == "email" || autocomplete.contains("username") || autocomplete.contains("email")) {
                return FieldRole.USERNAME
            }
            if (PASSWORD_WORDS.any { autocomplete.contains(it) || names.contains(it) }) return FieldRole.PASSWORD
            if (USERNAME_WORDS.any { autocomplete.contains(it) || names.contains(it) }) return FieldRole.USERNAME
        }

        // 3. Input type variations.
        val variation = node.inputType and InputType.TYPE_MASK_VARIATION
        if (node.inputType != 0) {
            if (variation in PASSWORD_VARIATIONS) return FieldRole.PASSWORD
            if (variation in EMAIL_VARIATIONS) return FieldRole.USERNAME
            val inputClass = node.inputType and InputType.TYPE_MASK_CLASS
            val textLike = inputClass == InputType.TYPE_CLASS_TEXT ||
                inputClass == InputType.TYPE_CLASS_NUMBER ||
                inputClass == InputType.TYPE_CLASS_PHONE
            if (!textLike) return null
            // Otherwise fall through to the naming heuristics below.
        }

        // 4. Resource id / hint text heuristics.
        val words = listOfNotNull(
            node.resourceId?.substringAfterLast('/'),
            node.hint,
            node.className,
        ).joinToString(" ").lowercase()
        if (words.isNotBlank()) {
            if (PASSWORD_WORDS.any { words.contains(it) }) return FieldRole.PASSWORD
            if (USERNAME_WORDS.any { words.contains(it) }) return FieldRole.USERNAME
        }
        return null
    }

    // ------------------------------------------------------------------ OTP predicates

    private fun isOtpField(node: AutofillNode): Boolean {
        val hints = node.autofillHints.orEmpty().map { it.lowercase() }
        if (hints.any { it in OTP_HINTS }) return true

        val html = node.htmlInfo
        // The extension lets autocomplete="one-time-code" win over every other heuristic.
        if (html?.autocomplete?.trim()?.lowercase() == "one-time-code") return true

        if (!otpLike(node)) return false
        if (!otpInputTypeAllowed(node)) return false

        if (html != null && html.attributes.containsKey("readonly")) return false
        if (html != null) {
            val size = html.attributes["size"]?.trim()?.toIntOrNull()
            if (size != null && size < 2) return false
            if (html.attributes["inputmode"]?.trim()?.lowercase() == "email") return false
        }

        val maxLength = otpMaxLength(node)
        // A single-character box only makes sense as one cell of a segmented code.
        if (maxLength == 1) return false
        if (maxLength > 1 && (maxLength < MIN_OTP_LENGTH || maxLength > MAX_OTP_LENGTH)) return false
        return true
    }

    /** Word/type checks shared by single inputs and the cells of a segmented code. */
    private fun otpLike(node: AutofillNode): Boolean {
        val hint = node.hint.orEmpty()
        val resource = node.resourceId?.substringAfterLast('/').orEmpty()
        val htmlId = node.htmlInfo?.id.orEmpty()
        val htmlName = node.htmlInfo?.name.orEmpty()
        val placeholder = node.htmlInfo?.attributes?.get("placeholder").orEmpty()
        val autocomplete = node.htmlInfo?.autocomplete.orEmpty()
        val words = listOf(htmlId, htmlName, placeholder, hint, resource).joinToString(" ").lowercase()

        val accepted = ACCEPTED_OTP_FIELDS.any { words.contains(it) } ||
            autocomplete.contains("one-time-code")
        if (!accepted) return false

        // `user`/`email` fields are never one-time codes, as in the extension.
        if (OTP_IGNORED_TYPES.any { words.contains(it) }) return false
        if (autocomplete.trim().lowercase() in OTP_IGNORED_TYPES) return false
        if (OTP_IGNORE_REGEX.containsMatchIn(words)) return false
        return true
    }

    private fun otpInputTypeAllowed(node: AutofillNode): Boolean {
        val htmlType = node.htmlInfo?.type?.trim()?.lowercase()
        if (htmlType != null) {
            if (htmlType in OTP_IGNORED_TYPES) return false
            if (htmlType.isNotEmpty() && htmlType !in OTP_ALLOWED_INPUT_TYPES) return false
        }
        if (node.inputType != 0) {
            val variation = node.inputType and InputType.TYPE_MASK_VARIATION
            if (variation in EMAIL_VARIATIONS) return false
            val inputClass = node.inputType and InputType.TYPE_MASK_CLASS
            val allowed = inputClass == InputType.TYPE_CLASS_TEXT ||
                inputClass == InputType.TYPE_CLASS_NUMBER ||
                inputClass == InputType.TYPE_CLASS_PHONE
            if (!allowed && variation !in PASSWORD_VARIATIONS) return false
        }
        return true
    }

    private fun otpMaxLength(node: AutofillNode): Int {
        val attr = node.htmlInfo?.attributes?.get("maxlength")?.trim()?.toIntOrNull()
        if (attr != null) return attr
        return node.maxLength
    }

    private fun isSegmentedCandidate(node: AutofillNode): Boolean {
        if (!node.isEnabled) return false
        val hints = node.autofillHints.orEmpty().map { it.lowercase() }
        val hintOtp = hints.any { it in OTP_HINTS } ||
            node.htmlInfo?.autocomplete?.trim()?.lowercase() == "one-time-code"
        if (!hintOtp && !otpLike(node)) return false
        if (!otpInputTypeAllowed(node)) return false
        val maxLength = otpMaxLength(node)
        // Unknown length is tolerated: some WebView versions do not expose `maxlength`, and a run of
        // 4–8 back-to-back OTP-ish inputs is a segmented code either way.
        return maxLength <= 1
    }

    /**
     * Runs of 4–8 consecutive single-character OTP-ish editable fields. Non-editable nodes (labels,
     * containers) do not break a run; any other editable field does.
     */
    internal fun segmentedGroups(nodes: List<AutofillNode>): List<List<Int>> {
        val groups = mutableListOf<List<Int>>()
        var run = mutableListOf<Int>()
        fun flush() {
            if (run.size in MIN_SEGMENTED_FIELDS..MAX_SEGMENTED_FIELDS) groups += run.toList()
            run = mutableListOf()
        }
        nodes.forEach { node ->
            if (!looksEditable(node)) return@forEach
            if (isSegmentedCandidate(node)) {
                run += node.index
            } else {
                flush()
            }
        }
        flush()
        return groups
    }

    private fun looksEditable(node: AutofillNode): Boolean {
        if (node.inputType != 0) return true
        if (!node.autofillHints.isNullOrEmpty()) return true
        val tag = node.htmlInfo?.tag?.lowercase()
        if (tag == "input" || tag == "textarea") return true
        val className = node.className.orEmpty()
        return className.contains("EditText") || className.contains("TextField")
    }

    private fun AutofillNode.depthFirst(): Sequence<AutofillNode> = sequence {
        yield(this@depthFirst)
        children.forEach { yieldAll(it.depthFirst()) }
    }
}

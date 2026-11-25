package org.friendlypass.android.autofill

import android.text.InputType

/**
 * Pure heuristics that turn a view tree into username/password fields.
 *
 * Precedence, strongest first:
 * 1. `autofillHints` (`username`, `emailAddress`, `password`, …),
 * 2. `HtmlInfo` attributes from a `WebView` (`type`, `name`, `id`, `autocomplete`),
 * 3. `inputType` variations (password, email),
 * 4. resource id / hint text heuristics ("user", "email", "login", "pass", …).
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

    fun parse(root: AutofillNode): ParsedForm {
        val usernameFields = mutableListOf<Int>()
        val passwordFields = mutableListOf<Int>()
        var webDomain: String? = null
        var webScheme: String? = null
        var hasHtmlFields = false

        root.depthFirst().forEach { node ->
            if (webDomain == null) {
                node.webDomain?.trim()?.takeIf { it.isNotEmpty() }?.let { webDomain = it }
            }
            if (webScheme == null) {
                node.webScheme?.trim()?.takeIf { it.isNotEmpty() }?.let { webScheme = it }
            }
            val role = classify(node) ?: return@forEach
            if (node.htmlInfo != null) hasHtmlFields = true
            when (role) {
                FieldRole.PASSWORD -> if (node.index !in passwordFields) passwordFields += node.index
                FieldRole.USERNAME -> if (node.index !in usernameFields) usernameFields += node.index
            }
        }

        return ParsedForm(
            usernameFieldIndices = usernameFields,
            passwordFieldIndices = passwordFields,
            webDomain = webDomain,
            webScheme = webScheme,
            hasHtmlFields = hasHtmlFields,
        )
    }

    /** Returns the role of [node], or null when it is not a credential field. */
    fun classify(node: AutofillNode): FieldRole? {
        if (!node.isEnabled) return null
        if (!looksEditable(node)) return null

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

package org.friendlypass.android.autofill

import android.view.autofill.AutofillId

/**
 * Android-free mirror of one `ViewStructure` node.
 *
 * The autofill parser works on this model only, so it can be unit tested on the JVM without a real
 * `ViewStructure` (which cannot be instantiated outside the framework). [index] is a stable per-request id
 * assigned while reading the structure; [AndroidStructureReader] keeps the matching `AutofillId` per index.
 */
data class AutofillNode(
    val index: Int,
    val className: String? = null,
    /** Fully qualified resource id, e.g. `com.example.app:id/username`. */
    val resourceId: String? = null,
    val hint: String? = null,
    val text: String? = null,
    val inputType: Int = 0,
    /** `ViewStructure.ViewNode.maxTextLength`; -1 when the field does not limit its length. */
    val maxLength: Int = -1,
    val autofillHints: List<String>? = null,
    val htmlInfo: HtmlAttributes? = null,
    val webDomain: String? = null,
    val webScheme: String? = null,
    val isFocused: Boolean = false,
    val isEnabled: Boolean = true,
    val children: List<AutofillNode> = emptyList(),
)

/** The HTML attributes a `WebView` exposes through `ViewStructure.HtmlInfo`. */
data class HtmlAttributes(
    val tag: String? = null,
    val type: String? = null,
    val name: String? = null,
    val id: String? = null,
    val autocomplete: String? = null,
    val attributes: Map<String, String> = emptyMap(),
)

enum class FieldRole { USERNAME, PASSWORD, OTP }

/** Result of [AutofillParser.parse]: which node indexes are credential fields, plus the page's web origin. */
data class ParsedForm(
    val usernameFieldIndices: List<Int> = emptyList(),
    val passwordFieldIndices: List<Int> = emptyList(),
    /**
     * One-time-code fields in document order. Segmented inputs (six single-digit boxes) are listed
     * individually; [otpGroups] says which of them belong together.
     */
    val otpFieldIndices: List<Int> = emptyList(),
    /** Every group of OTP fields: a one-field group for a normal input, N fields for a segmented one. */
    val otpGroups: List<List<Int>> = emptyList(),
    val webDomain: String? = null,
    val webScheme: String? = null,
    val hasHtmlFields: Boolean = false,
) {
    val hasUsername: Boolean get() = usernameFieldIndices.isNotEmpty()
    val hasPassword: Boolean get() = passwordFieldIndices.isNotEmpty()
    val hasOtp: Boolean get() = otpFieldIndices.isNotEmpty()
    val hasCredentials: Boolean get() = hasUsername || hasPassword || hasOtp
}

/**
 * Where a fill/save request belongs: a web origin (from a `WebView` or a browser) or an Android app package.
 */
sealed interface AutofillTarget {
    /** Web page; [url] is a full `https://host` style URL, [domain] the host. */
    data class Web(val url: String, val domain: String) : AutofillTarget

    data class App(val packageName: String) : AutofillTarget
}

/** The password/username/one-time-code field ids of one fill request, in the order the service received them. */
data class FieldIds(
    val usernameIds: List<AutofillId>,
    val passwordIds: List<AutofillId>,
    val otpIds: List<AutofillId> = emptyList(),
    /**
     * Grouping of [otpIds], one size per group: `[1]` for a single input, `[6]` for six single-digit
     * boxes. Empty is treated as one group covering every OTP id.
     */
    val otpGroupSizes: List<Int> = emptyList(),
) {
    val all: List<AutofillId> get() = usernameIds + passwordIds + otpIds
    val isEmpty: Boolean get() = usernameIds.isEmpty() && passwordIds.isEmpty() && otpIds.isEmpty()
    val hasOtp: Boolean get() = otpIds.isNotEmpty()

    /** Group sizes with the "one group for every id" fallback applied. */
    fun otpGroups(): List<Int> = when {
        otpIds.isEmpty() -> emptyList()
        otpGroupSizes.isEmpty() -> listOf(otpIds.size)
        else -> otpGroupSizes
    }

    companion object {
        val EMPTY = FieldIds(emptyList(), emptyList())
    }
}

/** One entry that can be filled, with the secret kept out of any presentation. */
data class FillCandidate(
    val entryUuid: String,
    /** Rendered as the suggestion title. */
    val title: String,
    /** Rendered as the suggestion subtitle. Never contains the password. */
    val username: String,
    /** Only written into `AutofillValue`s, never into a presentation. */
    val password: String,
    /** True when the entry has an `otpauth://` secret the OTP flow can use. */
    val hasTotp: Boolean = false,
)

/** Presentation-only description of one dataset: deliberately carries no secret. */
data class DatasetPlan(
    val id: String,
    val title: String,
    val subtitle: String,
    val entryUuid: String? = null,
    val isSearch: Boolean = false,
)

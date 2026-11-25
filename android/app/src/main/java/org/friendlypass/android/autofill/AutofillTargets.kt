package org.friendlypass.android.autofill

/**
 * Decides whether a request is for a web origin or an app, and refuses pages we cannot vouch for.
 *
 * `ViewStructure.webDomain` is only populated by a `WebView` (which also exposes `HtmlInfo`) or by a
 * browser's autofill implementation. A native app could set the field by hand, so a web origin is only
 * trusted when either
 * - the calling package is a known browser, or
 * - the structure carries `HtmlInfo` attributes, which a real `WebView` provides.
 *
 * Everything else is matched against the calling package as an Android app.
 */
object AutofillTargets {

    /** Browsers whose autofill implementation reports a web origin we can trust. */
    val KNOWN_BROWSERS = setOf(
        "com.android.chrome",
        "com.chrome.beta",
        "com.chrome.dev",
        "com.chrome.canary",
        "com.brave.browser",
        "com.microsoft.emmx",
        "com.microsoft.emmx.beta",
        "com.sec.android.app.sbrowser",
        "org.mozilla.firefox",
        "org.mozilla.firefox_beta",
        "org.mozilla.fenix",
        "com.duckduckgo.mobile.android",
        "com.opera.browser",
        "com.opera.mini.native",
        "com.ecosia.android",
        "com.vivaldi.browser",
        "com.kiwibrowser.browser",
        "org.chromium.webview_shell",
        "com.android.webview",
    )

    /**
     * Returns the target for [form] as seen from [callingPackage], or null when the request must be
     * ignored (our own package, an untrusted web origin, or no package at all).
     */
    fun resolve(
        form: ParsedForm,
        callingPackage: String?,
        ownPackage: String = org.friendlypass.android.BuildConfig.APPLICATION_ID,
    ): AutofillTarget? {
        if (callingPackage.isNullOrBlank()) return null
        if (callingPackage == ownPackage) return null

        val domain = form.webDomain
        if (domain != null) {
            val trusted = callingPackage in KNOWN_BROWSERS || form.hasHtmlFields
            if (!trusted) return null
            val scheme = form.webScheme?.lowercase()?.takeIf { it == "http" || it == "https" } ?: "https"
            return AutofillTarget.Web(url = "$scheme://$domain", domain = domain)
        }
        return AutofillTarget.App(callingPackage)
    }

    fun isKnownBrowser(packageName: String): Boolean = packageName in KNOWN_BROWSERS

    /** Host part of [url], for save-sheet titles and display. */
    fun hostOf(url: String): String? {
        val withoutScheme = url.substringAfter("://", missingDelimiterValue = url)
        val authority = withoutScheme.substringBefore('/').substringBefore('?').substringBefore('#')
        val host = authority.substringAfterLast('@').substringBefore(':')
        return host.ifBlank { null }?.lowercase()
    }
}

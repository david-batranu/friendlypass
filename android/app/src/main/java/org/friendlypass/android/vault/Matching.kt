package org.friendlypass.android.vault

/**
 * Deliberately small stand-in for `friendlypass::matching`: same shape (lower is better, null = no match)
 * but only the rules the fake vault needs. Wave 2 routes this through the shared Rust module.
 */
object Matching {
    data class Target(val webUrl: String? = null, val androidPackage: String? = null)

    /** Returns 0 for an exact host, 1 for a subdomain of the entry host, null otherwise. */
    fun webScore(entryUrl: String, target: Target): Int? {
        val targetHost = hostOf(target.webUrl ?: return null) ?: return null
        if (!entryUrl.startsWith("http://") && !entryUrl.startsWith("https://")) return null
        val entryHost = hostOf(entryUrl) ?: return null
        if (entryHost.equals(targetHost, ignoreCase = true)) return 0
        val suffix = ".$entryHost"
        return if (targetHost.endsWith(suffix, ignoreCase = true)) 1 else null
    }

    /** Exact Android package match against the `androidapp://` URIs or AndroidApp fields. */
    fun androidScore(entryUrls: List<String>, androidApps: List<String>, target: Target): Int? {
        val packageName = target.androidPackage ?: return null
        if (androidApps.any { it.equals(packageName, ignoreCase = true) }) return 0
        return if (entryUrls.any { it == "androidapp://$packageName" || it == "androidapp://$packageName/" }) 0 else null
    }

    fun hostOf(url: String): String? {
        val withoutScheme = url.substringAfter("://", missingDelimiterValue = url)
        val authority = withoutScheme.substringBefore('/').substringBefore('?').substringBefore('#')
        val host = authority.substringAfterLast('@').substringBefore(':')
        return host.ifBlank { null }?.lowercase()
    }
}

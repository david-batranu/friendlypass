package org.friendlypass.android.credentials

/**
 * Origin / relying-party rules for the provider.
 *
 * A privileged browser (Chrome & friends) is allowed to state its web origin; the platform verifies its signature
 * against the downloaded allowlist. Any other app is identified by the WebAuthn Android origin
 * `android:apk-key-hash:<base64url sha256 of the signing certificate>`.
 *
 * There is no INTERNET permission, so Digital Asset Links cannot be fetched at runtime. For unprivileged apps we
 * therefore only accept an rpId that is already recorded on an entry as an Android app package, or when the caller
 * is our own debug credential test app.
 */
internal object OriginPolicy {

    const val CREDTEST_PACKAGE = "org.friendlypass.credtest"

    fun apkKeyHashOrigin(signingCertSha256: ByteArray): String =
        "android:apk-key-hash:${B64Url.encode(signingCertSha256)}"

    fun isWebOrigin(origin: String?): Boolean =
        origin?.startsWith("https://") == true || origin?.startsWith("http://") == true

    fun hostOf(url: String): String? {
        if (!url.contains("://")) return null
        val withoutScheme = url.substringAfter("://")
        val authority = withoutScheme.substringBefore('/').substringBefore('?').substringBefore('#')
        val host = authority.substringAfterLast('@').substringBefore(':')
        return host.ifBlank { null }?.lowercase()
    }

    /** WebAuthn allows an rpId that equals the origin host or is a registrable suffix of it. */
    fun rpIdMatchesOrigin(rpId: String, origin: String): Boolean {
        val host = hostOf(origin) ?: return false
        val normalized = rpId.lowercase()
        return host == normalized || host.endsWith(".$normalized")
    }

    fun isDebugCredtest(packageName: String, isDebugBuild: Boolean): Boolean =
        isDebugBuild && packageName == CREDTEST_PACKAGE

    /**
     * @param origin verified web origin for privileged callers, otherwise the apk-key-hash origin.
     * @param entryHasAndroidApp true when some entry already records [rpId] as an Android app package.
     */
    fun isPasskeyRpAllowed(
        rpId: String,
        origin: String?,
        privileged: Boolean,
        callingPackage: String,
        isDebugBuild: Boolean,
        entryHasAndroidApp: Boolean,
    ): Boolean {
        if (rpId.isBlank()) return false
        if (privileged && isWebOrigin(origin) && rpIdMatchesOrigin(rpId, origin!!)) return true
        if (isDebugCredtest(callingPackage, isDebugBuild)) return true
        return entryHasAndroidApp
    }
}

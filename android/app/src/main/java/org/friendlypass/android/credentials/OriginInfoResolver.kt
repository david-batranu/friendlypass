package org.friendlypass.android.credentials

import android.content.Context
import androidx.credentials.provider.CallingAppInfo
import org.friendlypass.android.BuildConfig
import java.security.MessageDigest

/** What the provider knows about the calling app: package name plus the origin it may speak for. */
internal data class RequestOrigin(
    val packageName: String,
    /** Verified web origin for a privileged browser, otherwise the apk-key-hash Android origin. */
    val origin: String?,
    val isPrivileged: Boolean,
    val isDebugBuild: Boolean,
) {
    val isDebugCredtest: Boolean
        get() = OriginPolicy.isDebugCredtest(packageName, isDebugBuild)
}

/**
 * Resolves [CallingAppInfo] into a [RequestOrigin] using the bundled Google privileged-apps allowlist.
 *
 * [CallingAppInfo.getOrigin] throws when the caller is not on the allowlist; in that case the origin is derived
 * from the caller's signing certificate, as WebAuthn requires for Android apps.
 */
internal object OriginInfoResolver {

    const val PRIVILEGED_BROWSERS_ASSET = "privileged_browsers.json"

    @Volatile
    private var cachedAllowlist: String? = null

    fun privilegedAllowlist(context: Context): String {
        cachedAllowlist?.let { return it }
        val text = context.assets.open(PRIVILEGED_BROWSERS_ASSET)
            .bufferedReader(Charsets.UTF_8)
            .use { it.readText() }
        cachedAllowlist = text
        return text
    }

    fun resolve(context: Context, callingAppInfo: CallingAppInfo, isDebugBuild: Boolean = BuildConfig.DEBUG): RequestOrigin {
        val packageName = callingAppInfo.packageName
        val privilegedOrigin = runCatching {
            callingAppInfo.getOrigin(privilegedAllowlist(context))
        }.getOrNull()

        if (!privilegedOrigin.isNullOrBlank()) {
            return RequestOrigin(
                packageName = packageName,
                origin = privilegedOrigin,
                isPrivileged = true,
                isDebugBuild = isDebugBuild,
            )
        }

        return RequestOrigin(
            packageName = packageName,
            origin = unprivilegedFallback(callingAppInfo),
            isPrivileged = false,
            isDebugBuild = isDebugBuild,
        )
    }

    /** `android:apk-key-hash:<b64url sha256(signing cert)>`, or null when the system gave us no certificate. */
    private fun unprivilegedFallback(callingAppInfo: CallingAppInfo): String? {
        val certificates = runCatching {
            callingAppInfo.signingInfo?.apkContentsSigners?.toList()
        }.getOrNull().orEmpty()
        val certificate = certificates.firstOrNull() ?: return null
        val digest = MessageDigest.getInstance("SHA-256").digest(certificate.toByteArray())
        return OriginPolicy.apkKeyHashOrigin(digest)
    }
}

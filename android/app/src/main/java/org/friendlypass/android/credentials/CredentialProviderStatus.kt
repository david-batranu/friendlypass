package org.friendlypass.android.credentials

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import org.friendlypass.android.R

/**
 * Whether the Credential Manager provider is available to the system and whether the user selected friendlypass
 * as their credential service. The service only exists from API 34 (see `values-v34/credentials_bools.xml`).
 */
object CredentialProviderStatus {

    fun component(context: Context): ComponentName =
        ComponentName(context, FriendlypassCredentialProviderService::class.java)

    fun isSupported(): Boolean = Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE

    /** True when the provider service is declared and enabled in this build/on this device. */
    @Suppress("DEPRECATION")
    fun isEnabled(context: Context): Boolean {
        if (!isSupported()) return false
        return runCatching {
            context.packageManager.getServiceInfo(component(context), 0).enabled
        }.getOrDefault(false)
    }

    /**
     * True when the secure setting names our provider as the credential service. The key is hidden on
     * Android 16, so apps cannot read it; returning false there is expected and only hides the extra
     * "selected" wording in Settings.
     */
    fun isSelected(context: Context): Boolean {
        val setting = runCatching {
            Settings.Secure.getString(context.contentResolver, CREDENTIAL_SERVICE)
        }.getOrNull().orEmpty()
        val selected = ComponentName.unflattenFromString(setting) ?: return false
        return selected.packageName == context.packageName &&
            selected.className == FriendlypassCredentialProviderService::class.java.name
    }

    fun statusText(context: Context): String = when {
        !isSupported() -> context.getString(R.string.credentials_provider_status_unsupported)
        !isEnabled(context) -> context.getString(R.string.credentials_provider_status_disabled)
        isSelected(context) -> context.getString(R.string.credentials_provider_status_selected)
        else -> context.getString(R.string.credentials_provider_status_enabled)
    }

    private const val CREDENTIAL_SERVICE = "credential_service"
}

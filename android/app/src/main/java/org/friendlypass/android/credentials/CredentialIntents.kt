package org.friendlypass.android.credentials

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri

/** Extras/modes shared between the provider service and its activities. */
internal object CredentialIntents {

    const val EXTRA_MODE = "org.friendlypass.android.credentials.EXTRA_MODE"
    const val MODE_UNLOCK = "unlock"
    const val MODE_GET = "get"
    const val MODE_CREATE = "create"

    const val EXTRA_ENTRY_UUID = "org.friendlypass.android.credentials.EXTRA_ENTRY_UUID"
    const val EXTRA_CREDENTIAL_TYPE = "org.friendlypass.android.credentials.EXTRA_CREDENTIAL_TYPE"

    const val TYPE_PASSWORD = "password"
    const val TYPE_PUBLIC_KEY = "public-key"

    private const val SCHEME = "friendlypass-credentials"
    private const val REQUEST_CODE = 42

    fun unlock(context: Context): PendingIntent = pendingIntent(
        context = context,
        target = CredentialsGetActivity::class.java,
        uri = "$SCHEME://unlock",
        configure = {
            putExtra(EXTRA_MODE, MODE_UNLOCK)
        },
    )

    fun getEntry(context: Context, entryUuid: String, credentialType: String): PendingIntent = pendingIntent(
        context = context,
        target = CredentialsGetActivity::class.java,
        uri = "$SCHEME://get/$credentialType/$entryUuid",
        configure = {
            putExtra(EXTRA_MODE, MODE_GET)
            putExtra(EXTRA_ENTRY_UUID, entryUuid)
            putExtra(EXTRA_CREDENTIAL_TYPE, credentialType)
        },
    )

    fun create(context: Context): PendingIntent = pendingIntent(
        context = context,
        target = CredentialsCreateActivity::class.java,
        uri = "$SCHEME://create",
        configure = {
            putExtra(EXTRA_MODE, MODE_CREATE)
        },
    )

    private fun pendingIntent(
        context: Context,
        target: Class<*>,
        uri: String,
        configure: Intent.() -> Unit,
    ): PendingIntent {
        val intent = Intent(context, target).apply {
            data = Uri.parse(uri)
            configure()
        }
        // Credential Manager adds the original request to the launch intent, so the PendingIntent must be mutable.
        return PendingIntent.getActivity(
            context,
            REQUEST_CODE,
            intent,
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
    }
}

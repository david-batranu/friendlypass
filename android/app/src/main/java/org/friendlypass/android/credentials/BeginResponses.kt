package org.friendlypass.android.credentials

import android.content.Context
import androidx.credentials.PasswordCredential
import androidx.credentials.PublicKeyCredential
import androidx.credentials.provider.AuthenticationAction
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPasswordOption
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.PasswordCredentialEntry
import androidx.credentials.provider.PublicKeyCredentialEntry
import org.friendlypass.android.BuildConfig
import org.friendlypass.android.R
import org.friendlypass.android.vault.VaultRepository
import org.friendlypass.android.vault.model.VaultState

/**
 * Builds the query-phase responses. Shared by the provider service (already unlocked) and the unlock activity
 * (which builds the full response after the user unlocks so the system can replace the authentication action).
 */
internal object BeginResponses {

    fun get(
        context: Context,
        request: BeginGetCredentialRequest,
        vault: VaultRepository,
        isDebugBuild: Boolean = BuildConfig.DEBUG,
    ): BeginGetCredentialResponse {
        val response = BeginGetCredentialResponse.Builder()
        val state = vault.state.value
        if (state !is VaultState.Unlocked) {
            if (state is VaultState.Locked) {
                response.addAuthenticationAction(
                    AuthenticationAction.Builder(
                        context.getString(R.string.credentials_unlock_action),
                        CredentialIntents.unlock(context),
                    ).build(),
                )
            }
            return response.build()
        }

        val callingAppInfo = request.callingAppInfo ?: return response.build()
        val origin = OriginInfoResolver.resolve(context, callingAppInfo, isDebugBuild)
        val listings = CredentialListingBuilder(vault)

        for (option in request.beginGetCredentialOptions) {
            when (option) {
                is BeginGetPasswordOption -> {
                    val listing = listings.build(
                        ListingRequest(
                            passwordRequested = true,
                            publicKeyRequested = false,
                            allowedUserIds = option.allowedUserIds,
                            origin = origin.origin,
                            callingPackage = origin.packageName,
                            isDebugBuild = origin.isDebugBuild,
                            privileged = origin.isPrivileged,
                        ),
                    )
                    for (entry in listing.passwordEntries) {
                        response.addCredentialEntry(
                            PasswordCredentialEntry.Builder(
                                context,
                                entry.username.ifBlank { entry.displayName },
                                CredentialIntents.getEntry(context, entry.uuid, CredentialIntents.TYPE_PASSWORD),
                                option,
                            )
                                .setDisplayName(entry.displayName)
                                .build(),
                        )
                    }
                }

                is BeginGetPublicKeyCredentialOption -> {
                    val options = runCatching { RequestJson.parseGet(option.requestJson) }.getOrNull()
                        ?: continue
                    val rpId = options.rpId ?: continue
                    val listing = listings.build(
                        ListingRequest(
                            passwordRequested = false,
                            publicKeyRequested = true,
                            rpId = rpId,
                            allowCredentialIds = options.allowCredentialIds,
                            origin = origin.origin,
                            callingPackage = origin.packageName,
                            isDebugBuild = origin.isDebugBuild,
                            privileged = origin.isPrivileged,
                        ),
                    )
                    for (entry in listing.passkeyEntries) {
                        response.addCredentialEntry(
                            PublicKeyCredentialEntry.Builder(
                                context,
                                entry.username.ifBlank { entry.displayName },
                                CredentialIntents.getEntry(context, entry.uuid, CredentialIntents.TYPE_PUBLIC_KEY),
                                option,
                            )
                                .setDisplayName(entry.displayName)
                                .build(),
                        )
                    }
                }
            }
        }
        return response.build()
    }

    fun create(
        context: Context,
        request: BeginCreateCredentialRequest,
        vault: VaultRepository,
    ): BeginCreateCredentialResponse {
        val response = BeginCreateCredentialResponse.Builder()
        val databaseName = when (val state = vault.state.value) {
            is VaultState.Unlocked -> state.databaseName
            is VaultState.Locked -> state.db.displayName
            VaultState.NoDatabase -> return response.build()
        }

        val type = request.type
        val password = type == PasswordCredential.TYPE_PASSWORD_CREDENTIAL ||
            type == "android.credentials.TYPE_PASSWORD_CREDENTIAL"
        val passkey = type == PublicKeyCredential.TYPE_PUBLIC_KEY_CREDENTIAL ||
            type == "android.credentials.TYPE_PUBLIC_KEY_CREDENTIAL"
        if (!password && !passkey) return response.build()

        val total = (if (password) 1 else 0) + (if (passkey) 1 else 0)
        response.addCreateEntry(
            CreateEntry.Builder(
                context.getString(R.string.credentials_create_account, databaseName),
                CredentialIntents.create(context),
            )
                .setPasswordCredentialCount(if (password) 1 else 0)
                .setPublicKeyCredentialCount(if (passkey) 1 else 0)
                .setTotalCredentialCount(total)
                .build(),
        )
        return response.build()
    }
}

package org.friendlypass.android.credentials

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.credentials.CreatePasswordRequest
import androidx.credentials.CreatePasswordResponse
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.provider.ProviderCreateCredentialRequest
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import org.friendlypass.android.BuildConfig
import org.friendlypass.android.FriendlypassApp
import org.friendlypass.android.ui.theme.FriendlypassTheme
import org.friendlypass.android.unlock.UnlockGate
import org.friendlypass.android.vault.model.NewLogin
import org.friendlypass.android.vault.model.PasskeyCreateRequest

/**
 * Finishes a create-credential request: saves a password as a new login, or registers a passkey in the vault.
 */
class CredentialsCreateActivity : FragmentActivity() {

    private val app: FriendlypassApp get() = application as FriendlypassApp
    private var handled = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!BuildConfig.DEBUG) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
        CredentialSession.ensureStarted(app.vault)

        setContent {
            FriendlypassTheme {
                CredentialGate(onUnlocked = { CredentialSession.markUnlocked() }) {
                    if (!handled) {
                        handled = true
                        handle()
                    }
                }
            }
        }
    }

    private fun handle() {
        val request = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
            ?: return CredentialResults.cancelCreate(this)

        when (val calling = request.callingRequest) {
            is CreatePasswordRequest -> createPassword(request, calling)
            is CreatePublicKeyCredentialRequest -> createPasskey(request, calling)
            else -> CredentialResults.cancelCreate(this)
        }
    }

    private fun createPassword(
        request: ProviderCreateCredentialRequest,
        calling: CreatePasswordRequest,
    ) {
        val origin = OriginInfoResolver.resolve(this, request.callingAppInfo)
        val web = OriginPolicy.isWebOrigin(origin.origin)
        val title = if (web) {
            OriginPolicy.hostOf(origin.origin!!) ?: origin.packageName
        } else {
            origin.packageName
        }
        lifecycleScope.launch {
            try {
                app.vault.addLogin(
                    NewLogin(
                        title = title,
                        username = calling.id,
                        password = calling.password,
                        url = origin.origin.takeIf { web },
                        androidApp = origin.packageName.takeIf { !web },
                    ),
                )
                CredentialResults.finishWithCreateResponse(this@CredentialsCreateActivity, CreatePasswordResponse())
            } catch (_: Exception) {
                CredentialResults.finishWithCreateException(
                    this@CredentialsCreateActivity,
                    CreateCredentialUnknownException("could not save the password"),
                )
            }
        }
    }

    private fun createPasskey(
        request: ProviderCreateCredentialRequest,
        calling: CreatePublicKeyCredentialRequest,
    ) {
        val options = runCatching { RequestJson.parseCreate(calling.requestJson) }.getOrNull()
            ?: return CredentialResults.finishWithCreateException(
                this,
                CreateCredentialUnknownException("invalid passkey request"),
            )
        val origin = OriginInfoResolver.resolve(this, request.callingAppInfo)
        val allowed = OriginPolicy.isPasskeyRpAllowed(
            rpId = options.rpId,
            origin = origin.origin,
            privileged = origin.isPrivileged,
            callingPackage = origin.packageName,
            isDebugBuild = origin.isDebugBuild,
            entryHasAndroidApp = runCatching { app.vault.matchApp(options.rpId).isNotEmpty() }.getOrDefault(false),
        )
        if (!allowed) {
            return CredentialResults.finishWithCreateException(
                this,
                CreateCredentialCancellationException("origin is not allowed for this relying party"),
            )
        }

        lifecycleScope.launch {
            try {
                if (options.excludeCredentialIds.isNotEmpty() &&
                    app.vault.passkeysForRp(options.rpId, options.excludeCredentialIds).isNotEmpty()
                ) {
                    CredentialResults.finishWithCreateException(
                        this@CredentialsCreateActivity,
                        CreateCredentialCancellationException("a passkey for this account already exists"),
                    )
                    return@launch
                }
                val registration = app.vault.registerPasskey(
                    PasskeyCreateRequest(
                        rpId = options.rpId,
                        rpName = options.rpName,
                        userName = options.userName,
                        userDisplayName = options.userDisplayName,
                        userHandle = options.userId,
                        algorithms = options.algorithms,
                        excludeCredentialIds = options.excludeCredentialIds,
                    ),
                )
                val clientDataJson = if (calling.clientDataHash == null) {
                    CredentialJson.clientDataJson(
                        type = CredentialJson.TYPE_CREATE,
                        challenge = options.challenge,
                        origin = origin.origin ?: "",
                        androidPackageName = origin.packageName
                            .takeIf { !OriginPolicy.isWebOrigin(origin.origin) },
                    ).toByteArray(Charsets.UTF_8)
                } else {
                    null
                }
                CredentialResults.finishWithCreateResponse(
                    this@CredentialsCreateActivity,
                    CreatePublicKeyCredentialResponse(
                        CredentialJson.registration(
                            credentialId = registration.credentialId,
                            clientDataJson = clientDataJson,
                            attestationObject = registration.attestationObject,
                            authenticatorData = registration.authenticatorData,
                            publicKeySpkiDer = registration.publicKeySpkiDer,
                            publicKeyAlgorithm = registration.algorithm,
                        ),
                    ),
                )
            } catch (_: Exception) {
                CredentialResults.finishWithCreateException(
                    this@CredentialsCreateActivity,
                    CreateCredentialUnknownException("could not register the passkey"),
                )
            }
        }
    }
}

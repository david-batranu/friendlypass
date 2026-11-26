package org.friendlypass.android.credentials

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PasswordCredential
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.exceptions.NoCredentialException
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.provider.ProviderGetCredentialRequest
import androidx.fragment.app.FragmentActivity
import org.friendlypass.android.BuildConfig
import org.friendlypass.android.FriendlypassApp
import org.friendlypass.android.R
import org.friendlypass.android.ui.theme.FriendlypassTheme
import org.friendlypass.android.unlock.UnlockGate
import java.security.MessageDigest

/**
 * Hosts the user-facing half of a get-credential request: unlocking the vault (both for an authentication action
 * and for a selected entry) and producing the [PasswordCredential] or [PublicKeyCredential].
 */
class CredentialsGetActivity : FragmentActivity() {

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
                CredentialGate(
                    onUnlocked = { CredentialSession.markUnlocked() },
                    onReady = {
                        if (!handled) {
                            handled = true
                            handle()
                        }
                    },
                )
            }
        }
    }

    private fun handle() {
        when (intent.getStringExtra(CredentialIntents.EXTRA_MODE)) {
            CredentialIntents.MODE_UNLOCK -> completeBeginRequest()
            CredentialIntents.MODE_GET -> completeGetRequest()
            else -> CredentialResults.cancelGet(this)
        }
    }

    /** Authentication-action flow: the vault is unlocked, so replace the action with the real entries. */
    private fun completeBeginRequest() {
        val request = PendingIntentHandler.retrieveBeginGetCredentialRequest(intent)
            ?: return CredentialResults.cancelGet(this)
        val response = BeginResponses.get(this, request, app.vault)
        val result = android.content.Intent()
        PendingIntentHandler.setBeginGetCredentialResponse(result, response)
        setResult(RESULT_OK, result)
        finish()
    }

    private fun completeGetRequest() {
        val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
            ?: return CredentialResults.finishWithGetException(
                this,
                GetCredentialUnknownException("missing request"),
            )
        when (intent.getStringExtra(CredentialIntents.EXTRA_CREDENTIAL_TYPE)) {
            CredentialIntents.TYPE_PASSWORD -> completePassword(request)
            CredentialIntents.TYPE_PUBLIC_KEY -> completePasskey(request)
            else -> CredentialResults.cancelGet(this)
        }
    }

    private fun completePassword(request: ProviderGetCredentialRequest) {
        val uuid = intent.getStringExtra(CredentialIntents.EXTRA_ENTRY_UUID)
            ?: return CredentialResults.cancelGet(this)
        val detail = try {
            app.vault.entry(uuid)
        } catch (_: Exception) {
            return CredentialResults.finishWithGetException(
                this,
                NoCredentialException("entry is no longer available"),
            )
        }
        CredentialResults.finishWithCredential(
            this,
            PasswordCredential(
                detail.summary.username.ifBlank { detail.summary.title },
                detail.password,
            ),
        )
    }

    private fun completePasskey(request: ProviderGetCredentialRequest) {
        val uuid = intent.getStringExtra(CredentialIntents.EXTRA_ENTRY_UUID)
            ?: return CredentialResults.cancelGet(this)
        val option = request.credentialOptions
            .filterIsInstance<GetPublicKeyCredentialOption>()
            .firstOrNull()
            ?: return CredentialResults.finishWithGetException(
                this,
                GetCredentialUnknownException("missing public key option"),
            )
        val options = runCatching { RequestJson.parseGet(option.requestJson) }
            .onFailure { CredentialLog.failure("parse-get-options", it) }
            .getOrNull()
            ?: return CredentialResults.finishWithGetException(
                this,
                GetCredentialUnknownException("invalid public key request"),
            )
        CredentialLog.optionsShape("get", option.requestJson)
        val rpId = options.rpId
            ?: return CredentialResults.finishWithGetException(
                this,
                GetCredentialUnknownException("missing rpId"),
            )
        val origin = OriginInfoResolver.resolve(this, request.callingAppInfo)
        val allowed = OriginPolicy.isPasskeyRpAllowed(
            rpId = rpId,
            origin = origin.origin,
            privileged = origin.isPrivileged,
            callingPackage = origin.packageName,
            isDebugBuild = origin.isDebugBuild,
            entryHasAndroidApp = runCatching { app.vault.matchApp(rpId).isNotEmpty() }.getOrDefault(false),
        )
        if (!allowed) {
            return CredentialResults.finishWithGetException(
                this,
                NoCredentialException("origin is not allowed for this relying party"),
            )
        }
        val passkey = try {
            app.vault.passkeysForRp(rpId, options.allowCredentialIds)
                .firstOrNull { it.entryUuid == uuid }
        } catch (error: Exception) {
            CredentialLog.failure("passkeys-for-rp", error)
            null
        } ?: return CredentialResults.finishWithGetException(
            this,
            NoCredentialException("passkey is no longer available"),
        )

        val proceed = {
            val clientDataHash = option.clientDataHash
            val clientDataJson = if (clientDataHash == null) {
                CredentialJson.clientDataJson(
                    type = CredentialJson.TYPE_GET,
                    challenge = options.challenge,
                    origin = origin.origin ?: "",
                    androidPackageName = origin.packageName
                        .takeIf { !OriginPolicy.isWebOrigin(origin.origin) },
                ).toByteArray(Charsets.UTF_8)
            } else {
                null
            }
            val hash = clientDataHash
                ?: MessageDigest.getInstance("SHA-256")
                    .digest(requireNotNull(clientDataJson) { "client data missing" })
            try {
                val assertion = app.vault.assertPasskey(uuid, rpId, hash)
                CredentialResults.finishWithCredential(
                    this,
                    PublicKeyCredential(
                        CredentialJson.assertion(
                            credentialId = assertion.credentialId.takeIf { it.isNotEmpty() } ?: passkey.credentialId,
                            clientDataJson = clientDataJson,
                            authenticatorData = assertion.authenticatorData,
                            signature = assertion.signature,
                            userHandle = assertion.userHandle,
                        ),
                    ),
                )
            } catch (error: Exception) {
                CredentialLog.failure("assert-passkey", error)
                CredentialResults.finishWithGetException(
                    this,
                    NoCredentialException("passkey assertion failed"),
                )
            }
        }

        if (CredentialSession.requiresUserVerification()) {
            requestUserVerification(proceed)
        } else {
            proceed()
        }
    }

    /** BiometricPrompt with the device-credential fallback; the unlock itself counts when it is fresh. */
    private fun requestUserVerification(onVerified: () -> Unit) {
        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    onVerified()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    CredentialResults.cancelGet(this@CredentialsGetActivity)
                }
            },
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(getString(R.string.credentials_verify_title))
            .setSubtitle(getString(R.string.credentials_verify_subtitle))
            .setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_WEAK or
                    BiometricManager.Authenticators.DEVICE_CREDENTIAL,
            )
            .build()
        runCatching { prompt.authenticate(info) }
            .onFailure { CredentialResults.cancelGet(this) }
    }
}

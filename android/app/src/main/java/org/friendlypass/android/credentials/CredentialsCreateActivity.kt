package org.friendlypass.android.credentials

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.credentials.CreatePasswordRequest
import androidx.credentials.CreatePasswordResponse
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.provider.ProviderCreateCredentialRequest
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.delay
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

    /** Non-null while the UI should show progress or a final error instead of a blank screen. */
    private var status by mutableStateOf<String?>(null)
    private var failed by mutableStateOf(false)

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
                ) {
                    CredentialStatus(status, failed)
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
        status = "Saving password…"
        lifecycleScope.launch {
            try {
                val origin = OriginInfoResolver.resolve(this@CredentialsCreateActivity, request.callingAppInfo)
                val web = OriginPolicy.isWebOrigin(origin.origin)
                val title = if (web) {
                    OriginPolicy.hostOf(origin.origin!!) ?: origin.packageName
                } else {
                    origin.packageName
                }
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
            } catch (error: Exception) {
                CredentialLog.failure("save-password", error)
                finishWithError(CreateCredentialUnknownException("could not save the password"), error)
            }
        }
    }

    private fun createPasskey(
        request: ProviderCreateCredentialRequest,
        calling: CreatePublicKeyCredentialRequest,
    ) {
        status = "Registering passkey…"
        CredentialLog.optionsShape("create", calling.requestJson)
        lifecycleScope.launch {
            var step = "parse-create-options"
            try {
                val options = RequestJson.parseCreate(calling.requestJson)
                step = "resolve-origin"
                val origin = OriginInfoResolver.resolve(this@CredentialsCreateActivity, request.callingAppInfo)
                step = "origin-check"
                val allowed = OriginPolicy.isPasskeyRpAllowed(
                    rpId = options.rpId,
                    origin = origin.origin,
                    privileged = origin.isPrivileged,
                    callingPackage = origin.packageName,
                    isDebugBuild = origin.isDebugBuild,
                    entryHasAndroidApp = runCatching { app.vault.matchApp(options.rpId).isNotEmpty() }
                        .getOrDefault(false),
                )
                if (!allowed) {
                    CredentialLog.warning(
                        "origin-check",
                        "rpId=\"${options.rpId}\" rejected for package=\"${origin.packageName}\" " +
                            "privileged=${origin.isPrivileged} webOrigin=${OriginPolicy.isWebOrigin(origin.origin)}",
                    )
                    return@launch CredentialResults.finishWithCreateException(
                        this@CredentialsCreateActivity,
                        CreateCredentialCancellationException("origin is not allowed for this relying party"),
                    )
                }

                step = "exclude-credentials"
                if (options.excludeCredentialIds.isNotEmpty() &&
                    app.vault.passkeysForRp(options.rpId, options.excludeCredentialIds).isNotEmpty()
                ) {
                    return@launch CredentialResults.finishWithCreateException(
                        this@CredentialsCreateActivity,
                        CreateCredentialCancellationException("a passkey for this account already exists"),
                    )
                }

                step = "register-passkey"
                status = "Registering passkey for ${options.rpId}…"
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

                step = "client-data-json"
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

                step = "build-response"
                val response = CreatePublicKeyCredentialResponse(
                    CredentialJson.registration(
                        credentialId = registration.credentialId,
                        clientDataJson = clientDataJson,
                        attestationObject = registration.attestationObject,
                        authenticatorData = registration.authenticatorData,
                        publicKeySpkiDer = registration.publicKeySpkiDer,
                        publicKeyAlgorithm = registration.algorithm,
                    ),
                )

                step = "deliver-response"
                CredentialResults.finishWithCreateResponse(this@CredentialsCreateActivity, response)
            } catch (error: Exception) {
                CredentialLog.failure(step, error)
                finishWithError(CreateCredentialUnknownException("could not register the passkey"), error)
            }
        }
    }

    /** Shows a short, useful error before answering the caller with [exception]. */
    private fun finishWithError(exception: CreateCredentialException, cause: Throwable? = null) {
        // VaultException messages are contract-defined and secret-free (for example "Could not save X: …").
        val detail = (cause as? org.friendlypass.android.vault.model.VaultException)
            ?.message
            ?.takeIf { it.isNotBlank() }
        val headline = exception.errorMessage?.toString().orEmpty().ifBlank {
            "Could not complete the request"
        }
        failed = true
        status = if (detail == null) headline else "$headline\n$detail"
        lifecycleScope.launch {
            delay(ERROR_VISIBLE_MS)
            CredentialResults.finishWithCreateException(this@CredentialsCreateActivity, exception)
        }
    }

    companion object {
        private const val ERROR_VISIBLE_MS = 1_200L
    }
}

/** Progress/error surface: never leave the credential sheet showing a blank white activity. */
@Composable
private fun CredentialStatus(status: String?, failed: Boolean) {
    val text = status ?: return
    Surface(modifier = Modifier.fillMaxSize()) {
        Box(modifier = Modifier.fillMaxSize().padding(32.dp), contentAlignment = Alignment.Center) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(20.dp),
            ) {
                if (!failed) {
                    CircularProgressIndicator()
                }
                Text(
                    text = text,
                    style = MaterialTheme.typography.bodyLarge,
                    color = if (failed) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface,
                    textAlign = TextAlign.Center,
                )
            }
        }
    }
}

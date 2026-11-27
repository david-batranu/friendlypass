package org.friendlypass.android.credentials

import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import org.friendlypass.android.FriendlypassApp
import org.friendlypass.android.vault.model.VaultState

/**
 * Credential Manager provider: offers friendlypass passwords and passkeys to the system credential sheet.
 *
 * Nothing here logs credentials or entry contents; failures become generic credential exceptions.
 */
class FriendlypassCredentialProviderService : CredentialProviderService() {

    private val app: FriendlypassApp get() = application as FriendlypassApp
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onCreate() {
        super.onCreate()
        CredentialSession.ensureStarted(app.vault)
    }

    override fun onDestroy() {
        super.onDestroy()
        serviceScope.cancel()
    }

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        try {
            if (cancellationSignal.isCanceled) return
            CredentialSession.ensureStarted(app.vault)
            if (app.vault.state.value is VaultState.Unlocked) {
                val job = serviceScope.launch {
                    try {
                        withTimeoutOrNull(SYNC_TIMEOUT_MS) { app.vault.syncIfChanged() }
                        if (!cancellationSignal.isCanceled) {
                            callback.onResult(BeginResponses.get(this@FriendlypassCredentialProviderService, request, app.vault))
                        }
                    } catch (_: Exception) {
                        if (!cancellationSignal.isCanceled) {
                            callback.onError(GetCredentialUnknownException())
                        }
                    }
                }
                cancellationSignal.setOnCancelListener { job.cancel() }
            } else {
                callback.onResult(BeginResponses.get(this, request, app.vault))
            }
        } catch (_: Exception) {
            callback.onError(GetCredentialUnknownException())
        }
    }

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        try {
            if (cancellationSignal.isCanceled) return
            CredentialSession.ensureStarted(app.vault)
            callback.onResult(BeginResponses.create(this, request, app.vault))
        } catch (_: Exception) {
            callback.onError(CreateCredentialUnknownException())
        }
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>,
    ) {
        // Nothing is cached outside the (already locked) vault.
        callback.onResult(null)
    }

    companion object {
        private const val SYNC_TIMEOUT_MS = 1_500L
    }
}

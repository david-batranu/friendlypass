package org.friendlypass.android.autofill

import android.app.assist.AssistStructure
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.util.Log
import android.view.autofill.AutofillId
import android.widget.inline.InlinePresentationSpec
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import org.friendlypass.android.FriendlypassApp
import org.friendlypass.android.R
import org.friendlypass.android.vault.model.VaultState

/**
 * friendlypass autofill service.
 *
 * - **Locked** (`Locked`/`NoDatabase`): one `FillResponse` authentication chip ("Unlock friendlypass"),
 *   also offered as an inline keyboard suggestion when the IME supports it. Its `IntentSender` opens
 *   [AutofillAuthActivity], which unlocks and returns datasets through
 *   `AutofillManager.EXTRA_AUTHENTICATION_RESULT`.
 * - **Unlocked**: one dataset per matching entry plus a pinned "Search friendlypass…" dataset that opens
 *   [AutofillPickActivity]. When the request has a one-time-code field, only entries with a TOTP secret are
 *   offered, each as an authenticated dataset whose chip reads "<title> · one-time code" and which computes
 *   the code at tap time in [AutofillOtpActivity].
 * - **Save**: the request is handed to [AutofillSaveActivity] via `SaveCallback.onSuccess(IntentSender)`.
 *
 * Requests from our own app, requests without a username/password/one-time-code field, and web origins we
 * cannot attribute (see [AutofillTargets]) are ignored.
 */
class FriendlypassAutofillService : AutofillService() {

    private val app: FriendlypassApp get() = application as FriendlypassApp
    private val ui: AutofillUi get() = AutofillUi(this)
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onDestroy() {
        super.onDestroy()
        serviceScope.cancel()
    }

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback,
    ) {
        val structure = request.fillContexts.lastOrNull()?.structure
        if (structure == null) {
            callback.onFailure(getString(R.string.autofill_error_no_fields))
            return
        }
        val reading = AndroidStructureReader.read(structure)
        if (reading == null) {
            callback.onFailure(getString(R.string.autofill_error_no_fields))
            return
        }
        val parsed = AutofillParser.parse(reading.root)
        if (!parsed.hasCredentials) {
            callback.onFailure(getString(R.string.autofill_error_no_fields))
            return
        }
        val target = AutofillTargets.resolve(parsed, reading.activityPackage) ?: run {
            // Own package or an unattributable web origin: silently ignore.
            callback.onFailure(null)
            return
        }
        val fields = FieldIds(
            usernameIds = parsed.usernameFieldIndices.mapNotNull { reading[it] },
            passwordIds = parsed.passwordFieldIndices.mapNotNull { reading[it] },
            otpIds = parsed.otpFieldIndices.mapNotNull { reading[it] },
            otpGroupSizes = parsed.otpGroups.map { it.size },
        )
        if (fields.isEmpty) {
            callback.onFailure(getString(R.string.autofill_error_no_fields))
            return
        }

        // A dataset chosen during the previous fill session is the entry the user just used; remember it
        // for the OTP ordering. The client state names the target the selection belonged to.
        recordHistorySelection()

        val inline = request.inlineSuggestionsRequest
        val spec = inline?.inlinePresentationSpecs?.firstOrNull()
        val maxSuggestions = inline?.maxSuggestionCount ?: UNLIMITED
        Log.d(
            TAG,
            "fill request: pkg=${reading.activityPackage} target=$target " +
                "usernameFields=${fields.usernameIds.size} passwordFields=${fields.passwordIds.size} " +
                "otpFields=${fields.otpIds.size} otpGroups=${fields.otpGroups()} " +
                "inlineSpec=${spec != null} max=$maxSuggestions " +
                "locked=${app.vault.state.value !is VaultState.Unlocked}",
        )

        if (app.vault.state.value is VaultState.Unlocked) {
            val job = serviceScope.launch {
                withTimeoutOrNull(SYNC_TIMEOUT_MS) { app.vault.syncIfChanged() }
                if (cancellationSignal.isCanceled) return@launch
                val response = if (app.vault.state.value is VaultState.Unlocked) {
                    buildUnlockedResponse(reading.activityPackage, target, fields, maxSuggestions, spec)
                } else {
                    ui.lockedResponse(fields, target, maxSuggestions, spec)
                }
                if (!cancellationSignal.isCanceled) {
                    callback.onSuccess(response)
                }
            }
            cancellationSignal.setOnCancelListener { job.cancel() }
        } else {
            callback.onSuccess(ui.lockedResponse(fields, target, maxSuggestions, spec))
        }
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        Log.d(TAG, "save request received (${request.fillContexts.size} contexts)")
        val structure = request.fillContexts.lastOrNull()?.structure
        if (structure == null) {
            callback.onFailure(getString(R.string.autofill_error_no_fields))
            return
        }
        val reading = AndroidStructureReader.read(structure)
        if (reading == null) {
            callback.onFailure(getString(R.string.autofill_error_no_fields))
            return
        }
        val parsed = AutofillParser.parse(reading.root)
        if (!parsed.hasPassword) {
            callback.onFailure(getString(R.string.autofill_error_no_fields))
            return
        }
        val target = AutofillTargets.resolve(parsed, reading.activityPackage) ?: run {
            callback.onFailure(null)
            return
        }
        val username = parsed.usernameFieldIndices.firstOrNull()
            ?.let { reading[it] }
            ?.let { id -> structureValue(structure, id) }
            .orEmpty()
        val password = parsed.passwordFieldIndices.firstOrNull()
            ?.let { reading[it] }
            ?.let { id -> structureValue(structure, id) }
            .orEmpty()
        if (password.isEmpty()) {
            // Nothing worth saving (the framework may fire a save request for a cleared field).
            callback.onFailure(getString(R.string.autofill_error_no_fields))
            return
        }

        val intent = AutofillSaveActivity.newIntent(
            context = this,
            target = target,
            callingPackage = reading.activityPackage,
            username = username,
            password = password,
        )
        val pendingIntent = AutofillPendingIntents.forIntent(this, intent)
        Log.d(TAG, "save request: target=$target username=${username.length} chars, handing to activity")
        // API 28+ semantics: the activity shows our confirmation UI, the framework does not draw a dialog.
        callback.onSuccess(pendingIntent.intentSender)
    }

    /** Matches the target and builds a response with one dataset per entry plus the pinned search dataset. */
    private fun buildUnlockedResponse(
        callingPackage: String?,
        target: AutofillTarget,
        fields: FieldIds,
        maxSuggestions: Int,
        spec: InlinePresentationSpec?,
    ): FillResponse {
        var candidates = AutofillMatching.candidates(app.vault, target)
        if (fields.hasOtp) {
            // An OTP request only offers entries that can actually produce a code; the entry used most
            // recently for this same target comes first, the rest stay in match-score order.
            candidates = AutofillRecents.prioritize(target, candidates.filter { it.hasTotp })
        }
        return if (candidates.isEmpty()) {
            ui.searchOnlyResponse(fields, target, callingPackage, maxSuggestions, spec)
        } else {
            ui.unlockedResponse(fields, target, callingPackage, candidates, maxSuggestions, spec)
        }
    }

    /** Records the dataset the user chose in the previous session, if the framework kept its history. */
    @Suppress("DEPRECATION")
    private fun recordHistorySelection() {
        val history = try {
            fillEventHistory
        } catch (e: Exception) {
            null
        } ?: return
        val targetKey = history.clientState?.getString(AutofillExtras.STATE_TARGET_KEY) ?: return
        val event = history.events.orEmpty().lastOrNull { event ->
            event.type == android.service.autofill.FillEventHistory.Event.TYPE_DATASET_SELECTED ||
                event.type == android.service.autofill.FillEventHistory.Event.TYPE_DATASET_AUTHENTICATION_SELECTED
        } ?: return
        val datasetId = event.datasetId ?: return
        if (datasetId == AutofillDatasetPlanner.SEARCH_ID) return
        AutofillRecents.recordKey(targetKey, datasetId)
        Log.d(TAG, "recent fill recorded for $targetKey (type=${event.type})")
    }

    /**
     * Reads the current text of one field from the saved structure. `AutofillValue` is only available for
     * text fields; anything else yields an empty string.
     */
    private fun structureValue(structure: AssistStructure, id: AutofillId): String? {
        for (w in 0 until structure.windowNodeCount) {
            val node = structure.getWindowNodeAt(w).rootViewNode ?: continue
            findValue(node, id)?.let { return it }
        }
        return null
    }

    private fun findValue(node: AssistStructure.ViewNode, id: AutofillId): String? {
        if (node.autofillId == id) {
            return node.autofillValue?.takeIf { it.isText }?.textValue?.toString()
        }
        for (i in 0 until node.childCount) {
            val child = node.getChildAt(i) ?: continue
            findValue(child, id)?.let { return it }
        }
        return null
    }

    companion object {
        private const val TAG = "FriendlypassAutofill"
        private const val SYNC_TIMEOUT_MS = 1_500L

        /** Same as `InlineSuggestionsRequest.SUGGESTION_COUNT_UNLIMITED`; the planner treats it as unlimited. */
        const val UNLIMITED = -1
    }
}

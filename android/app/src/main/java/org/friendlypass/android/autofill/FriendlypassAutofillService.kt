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
 *   [AutofillPickActivity].
 * - **Save**: the request is handed to [AutofillSaveActivity] via `SaveCallback.onSuccess(IntentSender)`.
 *
 * Requests from our own app, requests without a username/password field, and web origins we cannot
 * attribute (see [AutofillTargets]) are ignored.
 */
class FriendlypassAutofillService : AutofillService() {

    private val app: FriendlypassApp get() = application as FriendlypassApp
    private val ui: AutofillUi get() = AutofillUi(this)

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
        )
        if (fields.isEmpty) {
            callback.onFailure(getString(R.string.autofill_error_no_fields))
            return
        }

        val inline = request.inlineSuggestionsRequest
        val spec = inline?.inlinePresentationSpecs?.firstOrNull()
        val maxSuggestions = inline?.maxSuggestionCount ?: UNLIMITED
        Log.d(
            TAG,
            "fill request: pkg=${reading.activityPackage} target=$target " +
                "usernameFields=${fields.usernameIds.size} passwordFields=${fields.passwordIds.size} " +
                "inlineSpec=${spec != null} max=$maxSuggestions " +
                "locked=${app.vault.state.value !is VaultState.Unlocked}",
        )

        val response = if (app.vault.state.value is VaultState.Unlocked) {
            buildUnlockedResponse(reading.activityPackage, target, fields, maxSuggestions, spec)
        } else {
            ui.lockedResponse(fields, target, maxSuggestions, spec)
        }
        callback.onSuccess(response)
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
        val candidates = AutofillMatching.candidates(app.vault, target)
        return if (candidates.isEmpty()) {
            ui.searchOnlyResponse(fields, target, callingPackage, maxSuggestions, spec)
        } else {
            ui.unlockedResponse(fields, target, callingPackage, candidates, maxSuggestions, spec)
        }
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

        /** Same as `InlineSuggestionsRequest.SUGGESTION_COUNT_UNLIMITED`; the planner treats it as unlimited. */
        const val UNLIMITED = -1
    }
}

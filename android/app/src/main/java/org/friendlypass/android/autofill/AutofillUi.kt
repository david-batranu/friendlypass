package org.friendlypass.android.autofill

import android.content.Context
import android.content.Intent
import android.graphics.drawable.Icon
import android.service.autofill.Dataset
import android.service.autofill.FillResponse
import android.service.autofill.InlinePresentation
import android.service.autofill.SaveInfo
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import android.widget.inline.InlinePresentationSpec
import androidx.autofill.inline.v1.InlineSuggestionUi
import org.friendlypass.android.R

/**
 * Builds the autofill UI: dropdown RemoteViews, inline keyboard chips and datasets.
 *
 * Passwords are only ever written into `AutofillValue`s. The dropdown and chip presentations are built
 * exclusively from [DatasetPlan.title]/[DatasetPlan.subtitle] (entry title + username).
 */
@Suppress("DEPRECATION")
class AutofillUi(private val context: Context) {

    fun datasetPresentation(title: CharSequence, subtitle: CharSequence?): RemoteViews =
        RemoteViews(context.packageName, R.layout.autofill_dataset).apply {
            setTextViewText(R.id.autofill_title, title)
            if (subtitle.isNullOrBlank()) {
                setViewVisibility(R.id.autofill_subtitle, android.view.View.GONE)
            } else {
                setTextViewText(R.id.autofill_subtitle, subtitle)
                setViewVisibility(R.id.autofill_subtitle, android.view.View.VISIBLE)
            }
        }

    fun authPresentation(label: CharSequence): RemoteViews =
        datasetPresentation(label, context.getString(R.string.autofill_unlock_chip_subtitle))

    /**
     * Builds the keyboard chip for [spec]. Returns null when the keyboard did not request inline
     * suggestions, in which case only the dropdown presentation is shown.
     */
    fun inlineChip(
        spec: InlinePresentationSpec?,
        title: CharSequence,
        subtitle: CharSequence?,
        pendingIntent: android.app.PendingIntent,
    ): InlinePresentation? {
        if (spec == null) return null
        val content = InlineSuggestionUi.newContentBuilder(pendingIntent)
            .setTitle(title)
            .setSubtitle(subtitle ?: "")
            .setContentDescription(if (subtitle.isNullOrBlank()) title else "$title, $subtitle")
            .setStartIcon(Icon.createWithResource(context, R.drawable.autofill_logo))
            .build()
        return InlinePresentation(content.slice, spec, /* pinned = */ false)
    }

    /** One dataset for a matched entry: presentation from the plan, values from the candidate. */
    fun entryDataset(
        fields: FieldIds,
        plan: DatasetPlan,
        candidate: FillCandidate,
        spec: InlinePresentationSpec?,
    ): Dataset {
        val builder = Dataset.Builder(datasetPresentation(plan.title, plan.subtitle))
            .setId(plan.id)
        inlineChip(spec, plan.title, plan.subtitle, attributionIntent())?.let(builder::setInlinePresentation)
        fields.usernameIds.forEach { id ->
            builder.setValue(id, AutofillValue.forText(candidate.username))
        }
        fields.passwordIds.forEach { id ->
            builder.setValue(id, AutofillValue.forText(candidate.password))
        }
        return builder.build()
    }

    /** The pinned "Search friendlypass…" dataset: its authentication opens the picker for the real values. */
    fun searchDataset(
        fields: FieldIds,
        target: AutofillTarget,
        callingPackage: String?,
        maxSuggestions: Int,
        spec: InlinePresentationSpec?,
    ): Dataset {
        val title = context.getString(R.string.autofill_search)
        val subtitle = context.getString(R.string.autofill_search_subtitle)
        val intent = AutofillPickActivity.newIntent(
            context,
            fields,
            target,
            callingPackage,
            maxSuggestions,
            spec,
            onlyWithTotp = fields.hasOtp,
        )
        val pendingIntent = AutofillPendingIntents.forIntent(context, intent)
        val builder = Dataset.Builder(datasetPresentation(title, subtitle))
            .setId(AutofillDatasetPlanner.SEARCH_ID)
            .setAuthentication(pendingIntent.intentSender)
        // A dataset must carry at least one field value, even when it authenticates: the picker activity
        // returns the real Dataset (with the chosen password/code) through EXTRA_AUTHENTICATION_RESULT.
        fields.all.forEach { id -> builder.setValue(id, AutofillValue.forText("")) }
        // The keyboard chip has room for one line only; the title is enough there.
        inlineChip(spec, title, null, pendingIntent)?.let(builder::setInlinePresentation)
        return builder.build()
    }

    /**
     * One-time-code suggestion: only a presentation and an authentication intent. The code is computed by
     * [AutofillOtpActivity] when the user taps, so it is always fresh and never shown in the UI.
     */
    fun otpDataset(
        fields: FieldIds,
        plan: DatasetPlan,
        target: AutofillTarget,
        callingPackage: String?,
        spec: InlinePresentationSpec?,
    ): Dataset {
        val title = otpTitle(plan.title)
        val intent =
            AutofillOtpActivity.newIntent(context, fields, target, callingPackage, plan.entryUuid, spec)
        val pendingIntent = AutofillPendingIntents.forIntent(context, intent)
        val builder = Dataset.Builder(datasetPresentation(title, plan.subtitle))
            .setId(plan.id)
            .setAuthentication(pendingIntent.intentSender)
        fields.all.forEach { id -> builder.setValue(id, AutofillValue.forText("")) }
        inlineChip(spec, title, null, pendingIntent)?.let(builder::setInlinePresentation)
        return builder.build()
    }

    /**
     * A complete OTP dataset, built at tap time by [AutofillOtpActivity] or the picker.
     *
     * The dataset is returned as an *ephemeral* authentication result (see
     * [AutofillManager.EXTRA_AUTHENTICATION_RESULT_EPHEMERAL_DATASET]): it fills the fields once and does
     * not replace the authenticated dataset in the framework's cached `FillResponse`, so clearing the
     * field re-offers the original chip and every later tap computes a fresh code again. On API 30,
     * where the extra is ignored and the result replaces the original dataset, this dataset must still
     * carry the inline presentation, or no chip would survive the clear. It must not carry an
     * authentication IntentSender: the framework would run it as the next authentication step of this
     * same selection, in a loop.
     */
    fun otpFilledDataset(
        fields: FieldIds,
        title: CharSequence,
        subtitle: CharSequence?,
        entryUuid: String,
        candidate: FillCandidate,
        code: String,
        spec: InlinePresentationSpec?,
    ): Dataset {
        val presentationTitle = otpTitle(title)
        val builder = Dataset.Builder(datasetPresentation(presentationTitle, subtitle))
            .setId(entryUuid)
        inlineChip(spec, presentationTitle, null, attributionIntent())?.let(builder::setInlinePresentation)
        fields.usernameIds.forEach { id -> builder.setValue(id, AutofillValue.forText(candidate.username)) }
        fields.passwordIds.forEach { id -> builder.setValue(id, AutofillValue.forText(candidate.password)) }
        val values = AutofillOtp.values(code, fields.otpGroups())
        fields.otpIds.forEachIndexed { index, id ->
            builder.setValue(id, AutofillValue.forText(values.getOrElse(index) { "" }))
        }
        return builder.build()
    }

    /**
     * The authentication result [Intent]: the filled dataset, flagged ephemeral (API 31+) so the
     * framework does not replace the session's authenticated chip dataset with this value snapshot.
     */
    fun authenticationResultIntent(dataset: Dataset): Intent =
        Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset).apply {
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
                putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT_EPHEMERAL_DATASET, true)
            }
        }

    /** "<title> · one-time code": the only OTP text ever shown in a presentation. */
    fun otpTitle(title: CharSequence): CharSequence = context.getString(R.string.autofill_otp_title, title)

    /** A dataset built after the user picked an entry in [AutofillPickActivity]. */
    fun pickedDataset(
        fields: FieldIds,
        candidate: FillCandidate,
        spec: InlinePresentationSpec?,
    ): Dataset {
        val plan = DatasetPlan(
            id = candidate.entryUuid,
            title = candidate.title,
            subtitle = candidate.username,
            entryUuid = candidate.entryUuid,
        )
        return entryDataset(fields, plan, candidate, spec)
    }

    /**
     * A FillResponse for an unlocked vault: one dataset per match plus the pinned search dataset.
     *
     * With an OTP field present, matches are authenticated OTP datasets (the code is computed at tap
     * time), and for combined pages the same dataset also carries username/password.
     */
    fun unlockedResponse(
        fields: FieldIds,
        target: AutofillTarget,
        callingPackage: String?,
        candidates: List<FillCandidate>,
        maxSuggestions: Int,
        spec: InlinePresentationSpec?,
    ): FillResponse {
        val plans = AutofillDatasetPlanner.plan(candidates, maxSuggestions, includeSearch = true)
        android.util.Log.d(
            "FriendlypassAutofill",
            "unlocked response: plans=${plans.size} matches=${candidates.size} inline=${spec != null} otp=${fields.hasOtp}",
        )
        val byUuid = candidates.associateBy { it.entryUuid }
        val builder = FillResponse.Builder()
        builder.setClientState(clientState(target))
        plans.forEach { plan ->
            if (plan.isSearch) {
                builder.addDataset(searchDataset(fields, target, callingPackage, maxSuggestions, spec))
            } else if (fields.hasOtp) {
                builder.addDataset(otpDataset(fields, plan, target, callingPackage, spec))
            } else {
                val candidate = byUuid[plan.entryUuid] ?: return@forEach
                builder.addDataset(entryDataset(fields, plan, candidate, spec))
            }
        }
        saveInfo(fields)?.let(builder::setSaveInfo)
        return builder.build()
    }

    /** FillResponse returned by the unlock activity when nothing matches: only the search dataset. */
    fun searchOnlyResponse(
        fields: FieldIds,
        target: AutofillTarget,
        callingPackage: String?,
        maxSuggestions: Int,
        spec: InlinePresentationSpec?,
    ): FillResponse {
        val builder = FillResponse.Builder()
        builder.setClientState(clientState(target))
        builder.addDataset(searchDataset(fields, target, callingPackage, maxSuggestions, spec))
        saveInfo(fields)?.let { builder.setSaveInfo(it) }
        return builder.build()
    }

    /** Locked: a single authentication chip and dropdown entry, no datasets. */
    fun lockedResponse(fields: FieldIds, target: AutofillTarget, maxSuggestions: Int, spec: InlinePresentationSpec?): FillResponse {
        val intent = AutofillAuthActivity.newIntent(context, fields, target, maxSuggestions, spec)
        val pendingIntent = AutofillPendingIntents.forIntent(context, intent)
        val label = context.getString(R.string.autofill_unlock_chip)
        val builder = FillResponse.Builder()
        builder.setClientState(clientState(target))
        val ids: Array<AutofillId> = fields.all.toTypedArray()
        val auth = authPresentation(label)
        // Chip text is one line in most keyboards; the dropdown keeps the longer explanation.
        val inline = inlineChip(spec, label, null, pendingIntent)
        android.util.Log.d(
            "FriendlypassAutofill",
            "locked response: inline=${inline != null} ids=${ids.size} otp=${fields.otpIds.size}",
        )
        if (inline != null) {
            builder.setAuthentication(ids, pendingIntent.intentSender, auth, inline)
        } else {
            builder.setAuthentication(ids, pendingIntent.intentSender, auth)
        }
        saveInfo(fields)?.let(builder::setSaveInfo)
        return builder.build()
    }

    /** Client state lets [FriendlypassAutofillService] attribute a later dataset selection to its target. */
    private fun clientState(target: AutofillTarget): android.os.Bundle =
        android.os.Bundle().apply {
            putString(AutofillExtras.STATE_TARGET_KEY, AutofillRecents.targetKey(target))
        }

    /**
     * SaveInfo when a password field exists: the password is required, the username optional. Requests
     * without a password field never get SaveInfo.
     */
    fun saveInfo(fields: FieldIds): SaveInfo? {
        if (fields.passwordIds.isEmpty()) return null
        val type = SaveInfo.SAVE_DATA_TYPE_USERNAME or SaveInfo.SAVE_DATA_TYPE_PASSWORD
        val builder = SaveInfo.Builder(type, fields.passwordIds.toTypedArray())
        if (fields.usernameIds.isNotEmpty()) {
            builder.setOptionalIds(fields.usernameIds.toTypedArray())
        }
        return builder.build()
    }

    /** Immutable attribution intent for keyboard chips (IME "manage" affordance). */
    private fun attributionIntent(): android.app.PendingIntent {
        val intent = Intent(context, AutofillSettingsActivity::class.java)
        return AutofillPendingIntents.forIntent(context, intent, mutable = false)
    }
}

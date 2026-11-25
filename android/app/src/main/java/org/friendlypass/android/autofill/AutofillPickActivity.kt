package org.friendlypass.android.autofill

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.service.autofill.Dataset
import android.view.autofill.AutofillManager
import android.widget.inline.InlinePresentationSpec
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.friendlypass.android.FriendlypassApp
import org.friendlypass.android.ui.EntryPicker
import org.friendlypass.android.ui.theme.FriendlypassTheme
import org.friendlypass.android.unlock.UnlockGate
import org.friendlypass.android.vault.model.EntrySummary
import org.friendlypass.android.vault.model.VaultException
import org.friendlypass.android.vault.model.VaultState

/**
 * Dataset authentication for the pinned "Search friendlypass…" suggestion: shows [EntryPicker] (unlocking
 * first when needed) and returns the picked entry as a [Dataset] through
 * [AutofillManager.EXTRA_AUTHENTICATION_RESULT].
 */
class AutofillPickActivity : FragmentActivity() {

    private lateinit var fields: FieldIds
    private var spec: InlinePresentationSpec? = null
    private var delivered = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        fields = AutofillExtras.fieldIds(intent)
        spec = AutofillExtras.inlineSpec(intent)
        if (!org.friendlypass.android.BuildConfig.DEBUG) {
            // Unlock screen (auth) / entry titles and usernames (picker): keep them out of screenshots.
            window.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        }
        if (fields.isEmpty) {
            finishCancelled()
            return
        }

        setContent {
            FriendlypassTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    val app = application as FriendlypassApp
                    val state by app.vault.state.collectAsStateWithLifecycle()
                    if (state is VaultState.Unlocked) {
                        Box(Modifier.fillMaxSize()) {
                            EntryPicker(
                                onEntrySelected = { entry -> deliver(entry) },
                                onDismiss = { finishCancelled() },
                            )
                        }
                    } else {
                        UnlockGate(onUnlocked = { /* recomposition shows the picker */ }, onCancel = { finishCancelled() })
                    }
                }
            }
        }
    }

    private fun deliver(entry: EntrySummary) {
        if (delivered) return
        delivered = true
        val app = application as FriendlypassApp
        try {
            val detail = app.vault.entry(entry.uuid)
            val candidate = FillCandidate(
                entryUuid = entry.uuid,
                title = entry.title,
                username = entry.username.ifBlank { entry.url },
                password = detail.password,
            )
            val dataset = AutofillUi(this).pickedDataset(fields, candidate, spec)
            setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset))
        } catch (e: VaultException) {
            finishCancelled()
            return
        }
        finish()
    }

    private fun finishCancelled() {
        if (delivered) return
        delivered = true
        setResult(RESULT_CANCELED)
        finish()
    }

    companion object {
        fun newIntent(
            context: Context,
            fields: FieldIds,
            target: AutofillTarget,
            callingPackage: String?,
            maxSuggestions: Int,
            spec: InlinePresentationSpec?,
        ): Intent = Intent(context, AutofillPickActivity::class.java).apply {
            AutofillExtras.putFieldIds(this, fields)
            AutofillExtras.putTarget(this, target, callingPackage)
            putExtra(AutofillExtras.EXTRA_MAX_SUGGESTIONS, maxSuggestions)
            AutofillExtras.putInlineSpec(this, spec)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
    }
}

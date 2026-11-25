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
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
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
    private var target: AutofillTarget? = null
    private var onlyWithTotp: Boolean = false
    private var spec: InlinePresentationSpec? = null
    private var delivered = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        fields = AutofillExtras.fieldIds(intent)
        target = AutofillExtras.target(intent)
        onlyWithTotp = fields.hasOtp || intent.getBooleanExtra(AutofillExtras.EXTRA_ONLY_TOTP, false)
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
                                onlyWithTotp = onlyWithTotp,
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
        if (fields.hasOtp && !entry.hasTotp) {
            // The picker is filtered, but re-check: an OTP dataset needs a secret.
            return
        }
        delivered = true
        val app = application as FriendlypassApp
        val resolvedTarget = target ?: return finishCancelled()
        lifecycleScope.launch {
            try {
                val detail = app.vault.entry(entry.uuid)
                val candidate = FillCandidate(
                    entryUuid = entry.uuid,
                    title = entry.title,
                    username = entry.username.ifBlank { entry.url },
                    password = detail.password,
                    hasTotp = entry.hasTotp,
                )
                val ui = AutofillUi(this@AutofillPickActivity)
                val dataset = if (fields.hasOtp) {
                    val code = AutofillOtp.freshCode(app.vault, entry.uuid) ?: run {
                        finishCancelled()
                        return@launch
                    }
                    AutofillRecents.record(resolvedTarget, entry.uuid)
                    ui.otpFilledDataset(
                        fields = fields,
                        title = entry.title,
                        subtitle = candidate.username,
                        entryUuid = entry.uuid,
                        candidate = candidate,
                        code = code.code,
                        spec = spec,
                    )
                } else {
                    AutofillRecents.record(resolvedTarget, entry.uuid)
                    ui.pickedDataset(fields, candidate, spec)
                }
                setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset))
                finish()
            } catch (e: VaultException) {
                finishCancelled()
            }
        }
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
            onlyWithTotp: Boolean = false,
        ): Intent = Intent(context, AutofillPickActivity::class.java).apply {
            AutofillExtras.putFieldIds(this, fields)
            AutofillExtras.putTarget(this, target, callingPackage)
            putExtra(AutofillExtras.EXTRA_MAX_SUGGESTIONS, maxSuggestions)
            putExtra(AutofillExtras.EXTRA_ONLY_TOTP, onlyWithTotp)
            AutofillExtras.putInlineSpec(this, spec)
        }
    }
}

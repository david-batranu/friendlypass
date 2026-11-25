package org.friendlypass.android.autofill

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.service.autofill.FillResponse
import android.view.autofill.AutofillManager
import android.widget.inline.InlinePresentationSpec
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import androidx.fragment.app.FragmentActivity
import org.friendlypass.android.FriendlypassApp
import org.friendlypass.android.ui.theme.FriendlypassTheme
import org.friendlypass.android.unlock.UnlockGate

/**
 * Authentication activity for the locked "Unlock friendlypass" chip.
 *
 * Hosts [UnlockGate]; once the vault is unlocked it matches the remembered target, builds a
 * [FillResponse] with one dataset per match (or only the "Search friendlypass…" dataset) and returns it
 * through [AutofillManager.EXTRA_AUTHENTICATION_RESULT].
 */
class AutofillAuthActivity : FragmentActivity() {

    private lateinit var fields: FieldIds
    private var target: AutofillTarget? = null
    private var callingPackage: String? = null
    private var maxSuggestions: Int = -1
    private var spec: InlinePresentationSpec? = null
    private var resultDelivered = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        fields = AutofillExtras.fieldIds(intent)
        target = AutofillExtras.target(intent)
        callingPackage = intent.getStringExtra(AutofillExtras.EXTRA_TARGET_PACKAGE)
        maxSuggestions = intent.getIntExtra(AutofillExtras.EXTRA_MAX_SUGGESTIONS, -1)
        spec = AutofillExtras.inlineSpec(intent)

        if (!org.friendlypass.android.BuildConfig.DEBUG) {
            // Unlock screen (auth) / entry titles and usernames (picker): keep them out of screenshots.
            window.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        }
        if (fields.isEmpty || target == null) {
            finishCancelled()
            return
        }

        setContent {
            FriendlypassTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    UnlockGate(
                        onUnlocked = { deliverResult() },
                        onCancel = { finishCancelled() },
                    )
                }
            }
        }
    }

    private fun deliverResult() {
        if (resultDelivered) return
        resultDelivered = true
        val resolvedTarget = target ?: return finishCancelled()
        val app = application as FriendlypassApp
        val candidates = AutofillMatching.candidates(app.vault, resolvedTarget)
        val ui = AutofillUi(this)
        val response = if (candidates.isEmpty()) {
            ui.searchOnlyResponse(fields, resolvedTarget, callingPackage, maxSuggestions, spec)
        } else {
            ui.unlockedResponse(fields, resolvedTarget, callingPackage, candidates, maxSuggestions, spec)
        }
        setResult(
            RESULT_OK,
            Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, response),
        )
        finish()
    }

    private fun finishCancelled() {
        if (resultDelivered) return
        resultDelivered = true
        setResult(RESULT_CANCELED)
        finish()
    }

    companion object {
        fun newIntent(
            context: Context,
            fields: FieldIds,
            target: AutofillTarget,
            maxSuggestions: Int,
            spec: InlinePresentationSpec?,
        ): Intent = Intent(context, AutofillAuthActivity::class.java).apply {
            AutofillExtras.putFieldIds(this, fields)
            AutofillExtras.putTarget(this, target, null)
            putExtra(AutofillExtras.EXTRA_MAX_SUGGESTIONS, maxSuggestions)
            AutofillExtras.putInlineSpec(this, spec)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
    }
}

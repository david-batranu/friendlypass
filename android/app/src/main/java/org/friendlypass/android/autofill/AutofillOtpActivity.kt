package org.friendlypass.android.autofill

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.autofill.AutofillManager
import android.widget.inline.InlinePresentationSpec
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import org.friendlypass.android.FriendlypassApp
import org.friendlypass.android.vault.model.VaultException

/**
 * Dataset authentication for a one-time-code suggestion. Deliberately has no UI: it runs
 * with a translucent window for as long as it takes to generate a fresh code and returns the filled
 * [android.service.autofill.Dataset] through [AutofillManager.EXTRA_AUTHENTICATION_RESULT].
 *
 * The code is generated at tap time, not when the [android.service.autofill.FillResponse] was built, and
 * the activity waits for the next step when the current one has less than
 * [AutofillOtp.MIN_REMAINING_SECS] seconds left.
 */
class AutofillOtpActivity : FragmentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val fields = AutofillExtras.fieldIds(intent)
        val target = AutofillExtras.target(intent)
        val entryUuid = intent.getStringExtra(AutofillExtras.EXTRA_ENTRY_UUID)
        val spec = AutofillExtras.inlineSpec(intent)
        android.util.Log.d(TAG, "otp activity: fields=${fields.otpIds.size} groups=${fields.otpGroups()} target=$target entry=${entryUuid != null}")
        if (fields.isEmpty || target == null) {
            finishCancelled()
            return
        }

        val app = application as FriendlypassApp
        lifecycleScope.launch {
            val candidates = AutofillMatching.candidates(app.vault, target).filter { it.hasTotp }
            android.util.Log.d(TAG, "otp activity: totp candidates=${candidates.size}")
            if (candidates.isEmpty()) {
                finishCancelled()
                return@launch
            }
            val candidate = candidates.firstOrNull { it.entryUuid == entryUuid } ?: candidates.first()
            val code = try {
                AutofillOtp.freshCode(app.vault, candidate.entryUuid)
            } catch (e: VaultException) {
                null
            }
            android.util.Log.d(TAG, "otp activity: code generated=${code != null}")
            if (code == null) {
                finishCancelled()
                return@launch
            }
            val dataset = AutofillUi(this@AutofillOtpActivity).otpFilledDataset(
                fields = fields,
                title = candidate.title,
                subtitle = candidate.username,
                entryUuid = candidate.entryUuid,
                candidate = candidate,
                code = code.code,
                spec = spec,
            )
            AutofillRecents.record(target, candidate.entryUuid)
            setResult(
                RESULT_OK,
                Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset),
            )
            finish()
        }
    }

    private fun finishCancelled() {
        setResult(RESULT_CANCELED)
        finish()
    }

    companion object {
        private const val TAG = "FriendlypassAutofill"

        fun newIntent(
            context: Context,
            fields: FieldIds,
            target: AutofillTarget,
            callingPackage: String?,
            entryUuid: String?,
        ): Intent = Intent(context, AutofillOtpActivity::class.java).apply {
            AutofillExtras.putFieldIds(this, fields)
            AutofillExtras.putTarget(this, target, callingPackage)
            if (!entryUuid.isNullOrBlank()) putExtra(AutofillExtras.EXTRA_ENTRY_UUID, entryUuid)
        }
    }
}

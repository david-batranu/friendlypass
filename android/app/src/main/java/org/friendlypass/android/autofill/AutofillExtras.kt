package org.friendlypass.android.autofill

import android.content.Context
import android.content.Intent
import android.view.autofill.AutofillId
import android.widget.inline.InlinePresentationSpec
import androidx.core.content.IntentCompat
import java.util.concurrent.atomic.AtomicInteger

/**
 * Intent plumbing between the autofill service and its activities (unlock, picker, save).
 *
 * Field ids and the web/app target travel as intent extras so the activity can rebuild exactly the same
 * `FillResponse`/`Dataset` after authentication. Extras never go to a log.
 */
object AutofillExtras {
    const val EXTRA_USERNAME_IDS = "org.friendlypass.android.autofill.USERNAME_IDS"
    const val EXTRA_PASSWORD_IDS = "org.friendlypass.android.autofill.PASSWORD_IDS"
    const val EXTRA_WEB_URL = "org.friendlypass.android.autofill.WEB_URL"
    const val EXTRA_WEB_DOMAIN = "org.friendlypass.android.autofill.WEB_DOMAIN"
    const val EXTRA_ANDROID_PACKAGE = "org.friendlypass.android.autofill.ANDROID_PACKAGE"
    const val EXTRA_TARGET_PACKAGE = "org.friendlypass.android.autofill.TARGET_PACKAGE"
    const val EXTRA_MAX_SUGGESTIONS = "org.friendlypass.android.autofill.MAX_SUGGESTIONS"
    const val EXTRA_INLINE_SPEC = "org.friendlypass.android.autofill.INLINE_SPEC"
    const val EXTRA_SAVE_USERNAME = "org.friendlypass.android.autofill.SAVE_USERNAME"
    const val EXTRA_SAVE_PASSWORD = "org.friendlypass.android.autofill.SAVE_PASSWORD"

    private val requestCode = AtomicInteger(1_000)

    fun nextRequestCode(): Int = requestCode.incrementAndGet()

    @Suppress("DEPRECATION")
    fun putInlineSpec(intent: Intent, spec: InlinePresentationSpec?) {
        if (spec != null) intent.putExtra(EXTRA_INLINE_SPEC, spec)
    }

    fun inlineSpec(intent: Intent): InlinePresentationSpec? =
        IntentCompat.getParcelableExtra(intent, EXTRA_INLINE_SPEC, InlinePresentationSpec::class.java)

    fun putFieldIds(intent: Intent, fields: FieldIds): Intent = intent.apply {
        intent.putParcelableArrayListExtra(EXTRA_USERNAME_IDS, ArrayList(fields.usernameIds))
        intent.putParcelableArrayListExtra(EXTRA_PASSWORD_IDS, ArrayList(fields.passwordIds))
    }

    fun fieldIds(intent: Intent): FieldIds = FieldIds(
        usernameIds = IntentCompat.getParcelableArrayListExtra(intent, EXTRA_USERNAME_IDS, AutofillId::class.java)
            .orEmpty(),
        passwordIds = IntentCompat.getParcelableArrayListExtra(intent, EXTRA_PASSWORD_IDS, AutofillId::class.java)
            .orEmpty(),
    )

    fun putTarget(intent: Intent, target: AutofillTarget, callingPackage: String?): Intent = intent.apply {
        when (target) {
            is AutofillTarget.Web -> {
                intent.putExtra(EXTRA_WEB_URL, target.url)
                intent.putExtra(EXTRA_WEB_DOMAIN, target.domain)
            }
            is AutofillTarget.App -> intent.putExtra(EXTRA_ANDROID_PACKAGE, target.packageName)
        }
        if (callingPackage != null) intent.putExtra(EXTRA_TARGET_PACKAGE, callingPackage)
    }

    /** Rebuilds the target; null when the extras are incomplete. */
    fun target(intent: Intent): AutofillTarget? {
        val webUrl = intent.getStringExtra(EXTRA_WEB_URL)
        if (webUrl != null) {
            val domain = intent.getStringExtra(EXTRA_WEB_DOMAIN) ?: AutofillTargets.hostOf(webUrl)
            return AutofillTarget.Web(webUrl, domain ?: return null)
        }
        val packageName = intent.getStringExtra(EXTRA_ANDROID_PACKAGE) ?: return null
        return AutofillTarget.App(packageName)
    }
}

/** Unique, correctly flag-geared [android.app.PendingIntent]s for autofill authentication intents. */
object AutofillPendingIntents {
    fun forIntent(context: Context, intent: Intent, mutable: Boolean = true): android.app.PendingIntent {
        val flags = (if (mutable) android.app.PendingIntent.FLAG_MUTABLE else android.app.PendingIntent.FLAG_IMMUTABLE) or
            android.app.PendingIntent.FLAG_UPDATE_CURRENT
        return android.app.PendingIntent.getActivity(context, AutofillExtras.nextRequestCode(), intent, flags)
    }
}

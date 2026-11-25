package org.friendlypass.android.autofill

import android.content.ComponentName
import android.content.Context
import android.view.autofill.AutofillManager
import org.friendlypass.android.R

/** Whether friendlypass is the active autofill service, for the settings screen. */
object AutofillStatus {

    fun manager(context: Context): AutofillManager? =
        context.getSystemService(AutofillManager::class.java)

    /** True when *any* autofill service is enabled on the device. */
    fun isAutofillEnabled(context: Context): Boolean =
        manager(context)?.hasEnabledAutofillServices() == true

    /** True when the enabled autofill service is this app's. */
    fun isActiveService(context: Context): Boolean {
        val manager = manager(context) ?: return false
        if (!manager.hasEnabledAutofillServices()) return false
        return manager.autofillServiceComponentName ==
            ComponentName(context, FriendlypassAutofillService::class.java)
    }

    fun statusText(context: Context): String = when {
        isActiveService(context) -> context.getString(R.string.autofill_status_active)
        isAutofillEnabled(context) -> context.getString(R.string.autofill_status_other)
        else -> context.getString(R.string.autofill_status_off)
    }
}

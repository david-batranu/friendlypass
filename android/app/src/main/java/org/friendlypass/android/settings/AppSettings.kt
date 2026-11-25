package org.friendlypass.android.settings

import android.content.Context

/** User-visible preferences (currently just auto-lock). Stored in a private SharedPreferences file. */
class AppSettings(context: Context) {

    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    /** Minutes of inactivity before the vault locks; 0 disables the idle timer (screen off still locks). */
    var lockTimeoutMinutes: Int
        get() = prefs.getInt(KEY_LOCK_TIMEOUT, DEFAULT_LOCK_TIMEOUT_MINUTES)
        set(value) {
            require(value >= 0) { "timeout must not be negative" }
            prefs.edit().putInt(KEY_LOCK_TIMEOUT, value).apply()
        }

    val lockTimeoutMillis: Long
        get() = lockTimeoutMinutes * 60_000L

    companion object {
        private const val PREFS_NAME = "friendlypass.settings"
        private const val KEY_LOCK_TIMEOUT = "lock_timeout_minutes"

        const val DEFAULT_LOCK_TIMEOUT_MINUTES = 5

        /** Offered in Settings; 1 is the shortest, 30 the longest automated choice. */
        val LOCK_TIMEOUT_CHOICES = listOf(1, 5, 15, 30)
    }
}

package org.friendlypass.android.ui

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle

/**
 * Copies secrets to the clipboard marked as sensitive (so they are not shown in the clipboard preview and are
 * excluded from Android 13+ clipboard auto-sync), and clears the clipboard again after 30 seconds.
 */
object SecureClipboard {

    const val AUTO_CLEAR_MS = 30_000L

    fun copySecret(context: Context, label: String, value: String) = copy(context, label, value, AUTO_CLEAR_MS)

    fun copy(context: Context, label: String, value: String, clearAfterMs: Long) {
        val manager = context.getSystemService(ClipboardManager::class.java) ?: return
        val clip = ClipData.newPlainText(label, value)
        clip.description.extras = PersistableBundle().apply {
            // ClipDescription.EXTRA_IS_SENSITIVE is API 33; the key is stable on older releases.
            putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
        }
        manager.setPrimaryClip(clip)
        if (clearAfterMs > 0) {
            Handler(Looper.getMainLooper()).postDelayed({
                val current = manager.primaryClipDescription
                if (current != null && current.label == label) {
                    manager.clearPrimaryClip()
                }
            }, clearAfterMs)
        }
    }
}

package org.friendlypass.android.autofill

/**
 * In-memory memory of which entry was filled last for a target, used to put the entry the user just used
 * first in the OTP suggestions. The window is short (5 minutes) and the whole map is dropped when the
 * vault locks.
 *
 * Nothing here contains a secret: only the target key, an entry UUID and a timestamp.
 */
object AutofillRecents {

    const val WINDOW_MS = 5 * 60_000L

    private data class Recent(val targetKey: String, val entryUuid: String, val atMillis: Long)

    private val lock = Any()
    private val recents = mutableMapOf<String, Recent>()

    /** Stable key for "the same target": a web host or an Android package. */
    fun targetKey(target: AutofillTarget): String = when (target) {
        is AutofillTarget.Web -> "web:${target.domain.lowercase()}"
        is AutofillTarget.App -> "app:${target.packageName}"
    }

    fun record(target: AutofillTarget, entryUuid: String, nowMillis: Long = System.currentTimeMillis()) =
        recordKey(targetKey(target), entryUuid, nowMillis)

    fun recordKey(targetKey: String, entryUuid: String, nowMillis: Long = System.currentTimeMillis()) {
        synchronized(lock) {
            recents[targetKey] = Recent(targetKey, entryUuid, nowMillis)
        }
    }

    /** The entry filled for [target] within the last five minutes, or null. */
    fun recentFor(target: AutofillTarget, nowMillis: Long = System.currentTimeMillis()): String? =
        recentKeyFor(targetKey(target), nowMillis)

    fun recentKeyFor(targetKey: String, nowMillis: Long = System.currentTimeMillis()): String? {
        val recent = synchronized(lock) { recents[targetKey] } ?: return null
        return recent.entryUuid.takeIf { nowMillis - recent.atMillis <= WINDOW_MS }
    }

    /**
     * Moves the entry most recently filled for [target] to the front and leaves the rest in match-score
     * order. A recent entry that is no longer a candidate is ignored.
     */
    fun prioritize(
        target: AutofillTarget,
        candidates: List<FillCandidate>,
        nowMillis: Long = System.currentTimeMillis(),
    ): List<FillCandidate> {
        val recentUuid = recentFor(target, nowMillis) ?: return candidates
        val recent = candidates.firstOrNull { it.entryUuid == recentUuid } ?: return candidates
        return listOf(recent) + candidates.filterNot { it.entryUuid == recentUuid }
    }

    fun clear() {
        synchronized(lock) { recents.clear() }
    }
}

package org.friendlypass.android.autofill

import android.util.Log
import org.friendlypass.android.vault.VaultRepository
import org.friendlypass.android.vault.model.EntrySummary
import org.friendlypass.android.vault.model.VaultException

/**
 * Turns a match target into fillable candidates. Shared by the service and the unlock activity so both
 * produce identical datasets.
 */
object AutofillMatching {

    private const val TAG = "FriendlypassAutofill"

    fun candidates(vault: VaultRepository, target: AutofillTarget): List<FillCandidate> {
        val summaries: List<EntrySummary> = try {
            when (target) {
                is AutofillTarget.Web -> vault.matchWeb(target.url)
                is AutofillTarget.App -> vault.matchApp(target.packageName)
            }
        } catch (e: VaultException) {
            Log.d(TAG, "vault not readable while matching: ${e.javaClass.simpleName}")
            return emptyList()
        }
        return summaries.mapNotNull { summary ->
            val detail = try {
                vault.entry(summary.uuid)
            } catch (e: VaultException) {
                return@mapNotNull null
            }
            FillCandidate(
                entryUuid = summary.uuid,
                title = summary.title,
                username = summary.username.ifBlank { summary.url },
                password = detail.password,
                hasTotp = summary.hasTotp,
            )
        }
    }
}

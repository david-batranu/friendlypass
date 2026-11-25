package org.friendlypass.android.autofill

/**
 * Builds the presentation-only dataset plans. Kept free of Android types so the limit rules and the
 * "no secrets in a presentation" property are unit tested directly.
 *
 * Presentation rules:
 * - title = entry title, subtitle = username (never the password),
 * - the "Search friendlypass…" dataset is always planned last (it is the pinned dataset),
 * - when the keyboard limits the suggestion count, matches are trimmed first; the search dataset is kept
 *   whenever there is room for it, and a single-suggestion budget shows the best match instead of only search.
 */
object AutofillDatasetPlanner {

    const val SEARCH_ID = "org.friendlypass.android.autofill.SEARCH"

    /** `InlineSuggestionsRequest.SUGGESTION_COUNT_UNLIMITED` is -1; treat any non-positive value as unlimited. */
    fun plan(candidates: List<FillCandidate>, maxCount: Int, includeSearch: Boolean = true): List<DatasetPlan> {
        val unique = candidates.distinctBy { it.entryUuid }
        val matchPlans = unique.map { candidate ->
            DatasetPlan(
                id = candidate.entryUuid,
                title = candidate.title,
                subtitle = candidate.username,
                entryUuid = candidate.entryUuid,
            )
        }
        val searchPlans = if (includeSearch) listOf(searchPlan()) else emptyList()

        if (maxCount <= 0) return matchPlans + searchPlans

        return when {
            matchPlans.isEmpty() -> searchPlans.take(maxCount)
            maxCount == 1 -> matchPlans.take(1)
            else -> {
                val budgetForMatches = if (includeSearch) (maxCount - 1).coerceAtLeast(1) else maxCount
                matchPlans.take(budgetForMatches) + searchPlans.take(if (includeSearch) 1 else 0)
            }
        }
    }

    /** The locked "Unlock friendlypass" chip is a single suggestion, not a dataset. */
    fun searchPlan(): DatasetPlan = DatasetPlan(
        id = SEARCH_ID,
        title = SEARCH_TITLE,
        subtitle = SEARCH_SUBTITLE,
        isSearch = true,
    )

    // Kept as constants instead of string resources so the plans stay Android-free; the Android layer
    // replaces them with localised resources when it builds the actual views.
    const val SEARCH_TITLE = "Search friendlypass…"
    const val SEARCH_SUBTITLE = "Choose an entry"
}

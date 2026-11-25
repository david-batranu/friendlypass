package org.friendlypass.android.autofill

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Dataset planning rules: per-match plans plus a pinned search plan, honouring the keyboard's
 * `maxSuggestionCount`, and never exposing a password through a presentation.
 */
class AutofillDatasetPlannerTest {

    private val candidates = listOf(
        FillCandidate("uuid-1", "Fastmail", "david@example.com", "fastmail-demo-password"),
        FillCandidate("uuid-2", "Gmail", "david@gmail.example", "gmail-demo-password"),
        FillCandidate("uuid-3", "GitHub", "david", "github-demo-password"),
    )

    @Test
    fun unlimitedPlanHasEveryMatchAndPinnedSearchLast() {
        val plans = AutofillDatasetPlanner.plan(candidates, maxCount = -1)

        assertEquals(listOf("uuid-1", "uuid-2", "uuid-3", AutofillDatasetPlanner.SEARCH_ID), plans.map { it.id })
        assertTrue(plans.last().isSearch)
    }

    @Test
    fun limitedPlanTrimsMatchesButKeepsPinnedSearch() {
        val plans = AutofillDatasetPlanner.plan(candidates, maxCount = 3)

        assertEquals(listOf("uuid-1", "uuid-2", AutofillDatasetPlanner.SEARCH_ID), plans.map { it.id })
        assertEquals(3, plans.size)
        assertTrue(plans.last().isSearch)
    }

    @Test
    fun singleSuggestionBudgetShowsTheBestMatch() {
        val plans = AutofillDatasetPlanner.plan(candidates, maxCount = 1)

        assertEquals(listOf("uuid-1"), plans.map { it.id })
        assertFalse(plans.any { it.isSearch })
    }

    @Test
    fun noMatchesYieldsOnlyTheSearchDataset() {
        val plans = AutofillDatasetPlanner.plan(emptyList(), maxCount = 3)

        assertEquals(1, plans.size)
        assertTrue(plans.single().isSearch)
    }

    @Test
    fun zeroMatchesAndNoSearchIsEmpty() {
        assertTrue(AutofillDatasetPlanner.plan(emptyList(), maxCount = 3, includeSearch = false).isEmpty())
    }

    @Test
    fun planNeverContainsSecretsAndTitlesAreEntryTitleAndUsername() {
        val plans = AutofillDatasetPlanner.plan(candidates, maxCount = -1)

        val texts = plans.flatMap { listOf(it.title, it.subtitle) }
        candidates.forEach { candidate ->
            assertFalse(
                "password leaked into a presentation: ${candidate.password}",
                texts.any { it.contains(candidate.password) },
            )
        }
        val first = plans.first()
        assertEquals("Fastmail", first.title)
        assertEquals("david@example.com", first.subtitle)
    }

    @Test
    fun duplicateEntriesArePlannedOnce() {
        val duplicated = candidates + candidates.first()

        assertEquals(
            listOf("uuid-1", "uuid-2", "uuid-3", AutofillDatasetPlanner.SEARCH_ID),
            AutofillDatasetPlanner.plan(duplicated, maxCount = -1).map { it.id },
        )
    }
}

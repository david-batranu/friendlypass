package org.friendlypass.android.autofill

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Digit splitting across OTP fields and the "most recently used entry" ordering. */
class AutofillOtpTest {

    private val web = AutofillTarget.Web("https://appassets.androidplatform.net", "appassets.androidplatform.net")
    private val app = AutofillTarget.App("org.friendlypass.testapp")

    private val candidates = listOf(
        FillCandidate("uuid-a", "Alpha", "alpha-user", "alpha-password", hasTotp = true),
        FillCandidate("uuid-b", "Beta", "beta-user", "beta-password", hasTotp = true),
        FillCandidate("uuid-c", "Gamma", "gamma-user", "gamma-password", hasTotp = true),
    )

    @Test
    fun aSingleOtpFieldGetsTheWholeCode() {
        assertEquals(listOf("287082"), AutofillOtp.values("287082", listOf(1)))
        assertEquals(listOf("287082"), AutofillOtp.values("287082", emptyList()))
    }

    @Test
    fun aSegmentedCodeGetsOneDigitPerBox() {
        assertEquals(
            listOf("2", "8", "7", "0", "8", "2"),
            AutofillOtp.values("287082", listOf(6)),
        )
    }

    @Test
    fun aShortCodeLeavesTheRemainingBoxesEmpty() {
        assertEquals(
            listOf("1", "2", "3", "4", "", ""),
            AutofillOtp.values("1234", listOf(6)),
        )
    }

    @Test
    fun severalGroupsKeepFieldOrder() {
        assertEquals(
            listOf("287082", "2", "8", "7", "0", "8", "2"),
            AutofillOtp.values("287082", listOf(1, 6)),
        )
    }

    @Test
    fun theMostRecentEntryForATargetComesFirst() {
        AutofillRecents.clear()
        AutofillRecents.record(web, "uuid-c", nowMillis = 1_000)

        val ordered = AutofillRecents.prioritize(web, candidates, nowMillis = 2_000)

        assertEquals(listOf("uuid-c", "uuid-a", "uuid-b"), ordered.map { it.entryUuid })
    }

    @Test
    fun aRecentFillForAnotherTargetDoesNotReorder() {
        AutofillRecents.clear()
        AutofillRecents.record(app, "uuid-c", nowMillis = 1_000)

        assertEquals(
            listOf("uuid-a", "uuid-b", "uuid-c"),
            AutofillRecents.prioritize(web, candidates, nowMillis = 2_000).map { it.entryUuid },
        )
    }

    @Test
    fun aFillOlderThanFiveMinutesIsIgnored() {
        AutofillRecents.clear()
        AutofillRecents.record(web, "uuid-c", nowMillis = 1_000)

        assertNull(AutofillRecents.recentFor(web, nowMillis = 1_000 + AutofillRecents.WINDOW_MS + 1))
        assertEquals(
            listOf("uuid-a", "uuid-b", "uuid-c"),
            AutofillRecents.prioritize(web, candidates, nowMillis = 1_000 + AutofillRecents.WINDOW_MS + 1)
                .map { it.entryUuid },
        )
    }

    @Test
    fun clearingTheMemoryRestoresMatchOrder() {
        AutofillRecents.clear()
        AutofillRecents.record(web, "uuid-b", nowMillis = 1_000)
        AutofillRecents.clear()

        assertEquals(
            listOf("uuid-a", "uuid-b", "uuid-c"),
            AutofillRecents.prioritize(web, candidates, nowMillis = 2_000).map { it.entryUuid },
        )
    }

    @Test
    fun aRecentEntryThatIsNoLongerACandidateIsIgnored() {
        AutofillRecents.clear()
        AutofillRecents.record(web, "deleted-uuid", nowMillis = 1_000)

        assertEquals(
            listOf("uuid-a", "uuid-b", "uuid-c"),
            AutofillRecents.prioritize(web, candidates, nowMillis = 2_000).map { it.entryUuid },
        )
        assertTrue(AutofillRecents.recentFor(web, nowMillis = 2_000) == "deleted-uuid")
    }

    @Test
    fun webAndAppTargetsUseStableKeys() {
        assertEquals("web:appassets.androidplatform.net", AutofillRecents.targetKey(web))
        assertEquals("app:org.friendlypass.testapp", AutofillRecents.targetKey(app))
    }
}

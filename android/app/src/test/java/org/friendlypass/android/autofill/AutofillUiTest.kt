package org.friendlypass.android.autofill

import android.content.Context
import android.view.View
import android.widget.FrameLayout
import android.widget.TextView
import androidx.test.core.app.ApplicationProvider
import org.friendlypass.android.R
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * The dropdown presentation is rendered from [DatasetPlan] only. This test inflates the real
 * `autofill_dataset` RemoteViews and asserts the visible text: title + username, never a password.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class AutofillUiTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun dropdownShowsTitleAndUsernameOnly() {
        val ui = AutofillUi(context)

        val view = ui.datasetPresentation("Fastmail", "david@example.com")
            .apply(context, FrameLayout(context))

        assertEquals("Fastmail", view.findViewById<TextView>(R.id.autofill_title).text.toString())
        val subtitle = view.findViewById<TextView>(R.id.autofill_subtitle)
        assertEquals("david@example.com", subtitle.text.toString())
        assertEquals(View.VISIBLE, subtitle.visibility)
    }

    @Test
    fun iconOnlyPresentationHidesTheSubtitle() {
        val ui = AutofillUi(context)

        val view = ui.datasetPresentation("Unlock friendlypass", null)
            .apply(context, FrameLayout(context))

        assertEquals("Unlock friendlypass", view.findViewById<TextView>(R.id.autofill_title).text.toString())
        assertEquals(View.GONE, view.findViewById<TextView>(R.id.autofill_subtitle).visibility)
    }

    @Test
    fun otpTitleSaysOneTimeCodeAndCarriesNoCode() {
        val title = AutofillUi(context).otpTitle("OTP Account").toString()

        assertEquals("OTP Account · one-time code", title)
        assertEquals(false, title.contains("287082"))
    }

    @Test
    fun presentationTextNeverContainsASecret() {
        // The plan carries no password field at all; this pins the pipeline by building the plan from a
        // candidate and checking the rendered view text.
        val candidate = FillCandidate("uuid", "Fastmail", "david@example.com", "fastmail-demo-password")
        val plan = AutofillDatasetPlanner.plan(listOf(candidate), maxCount = 1).first()
        val view = AutofillUi(context).datasetPresentation(plan.title, plan.subtitle)
            .apply(context, FrameLayout(context))

        val rendered = listOf(
            view.findViewById<TextView>(R.id.autofill_title).text.toString(),
            view.findViewById<TextView>(R.id.autofill_subtitle).text.toString(),
        )
        assertEquals(false, rendered.any { it.contains(candidate.password) })
    }
}

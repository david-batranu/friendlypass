package org.friendlypass.android.credentials

import android.app.Activity
import android.content.Intent
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.CreateCredentialResponse
import androidx.credentials.Credential
import androidx.credentials.GetCredentialResponse
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.provider.PendingIntentHandler

/** Small helpers so both credential activities answer Credential Manager the same way. */
internal object CredentialResults {

    fun finishWithCredential(activity: Activity, credential: Credential) {
        val result = Intent()
        PendingIntentHandler.setGetCredentialResponse(result, GetCredentialResponse(credential))
        activity.setResult(Activity.RESULT_OK, result)
        activity.finish()
    }

    fun finishWithGetException(activity: Activity, exception: GetCredentialException) {
        val result = Intent()
        PendingIntentHandler.setGetCredentialException(result, exception)
        activity.setResult(Activity.RESULT_OK, result)
        activity.finish()
    }

    fun finishWithCreateResponse(activity: Activity, response: CreateCredentialResponse) {
        val result = Intent()
        PendingIntentHandler.setCreateCredentialResponse(result, response)
        activity.setResult(Activity.RESULT_OK, result)
        activity.finish()
    }

    fun finishWithCreateException(activity: Activity, exception: CreateCredentialException) {
        val result = Intent()
        PendingIntentHandler.setCreateCredentialException(result, exception)
        activity.setResult(Activity.RESULT_OK, result)
        activity.finish()
    }

    fun cancelGet(activity: Activity) =
        finishWithGetException(activity, GetCredentialCancellationException())

    fun cancelCreate(activity: Activity) =
        finishWithCreateException(activity, CreateCredentialCancellationException())
}

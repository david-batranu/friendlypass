package org.friendlypass.testapp

import android.app.Activity
import android.os.Bundle

/**
 * Second step of the two-step login: a single one-time-code field with the `smsOTPCode` autofill hint,
 * used to exercise friendlypass OTP autofill on a native form.
 */
class OtpActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_otp)
    }
}
